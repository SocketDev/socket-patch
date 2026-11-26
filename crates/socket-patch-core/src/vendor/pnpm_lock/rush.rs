//! Rush layout of the pnpm v9 vendor backend.
//!
//! A Rush monorepo has no root `package.json` / `pnpm-lock.yaml` pair. Its
//! lock lives at `common/config/rush/pnpm-lock.yaml` (one per subspace under
//! `common/config/subspaces/<name>/`), and `rush install` copies it into
//! `common/temp[/<subspace>]` and runs pnpm THERE, with a `package.json` and
//! `pnpm-workspace.yaml` it generates from `pnpm-config.json`. So every path
//! in the lock is relative to that temp directory, and the override surface
//! is `pnpm-config.json`'s `globalOverrides`.
//!
//! The lock gets the same fragments as a plain pnpm project
//! ([`super`]): the `packages:` / `snapshots:` entries rekeyed to
//! `name@file:<tgz>`, dependents' refs and importer entries moved to it. The
//! lines are edited as pnpm would spell them from the repository root
//! (`file:.socket/vendor/…`) and written back relative to the temp
//! directory (`file:../../.socket/vendor/…`), which is what lets the plain
//! backend's splices and reverts run unchanged.
//!
//! Two things differ, both forced by Rush's own stale-lock check
//! (`rush install` compares each project's `package.json` with its lock
//! importer and looks overrides up by bare dependency name):
//!
//! * a project that depends on the package DIRECTLY gets its `package.json`
//!   spec moved to `file:<path relative to the project>`. A versioned
//!   override would rewrite the importer's `specifier` under a
//!   `package.json` that still names the registry version, and
//!   `rush install` then fails on every run, `rush update` included;
//! * TRANSITIVE dependents get one parent-scoped override each
//!   (`<parent>@<version>><name>@<version>`). It never matches a workspace
//!   project, so it cannot trip that check, and it moves exactly the edges
//!   the lock resolves to this version: pnpm matches a plain
//!   `name@version` selector against every dependent whose declared range
//!   merely includes the version, wherever that dependent is locked.
//!
//! Every shape here is what Rush 5.182.1 itself writes for the same
//! `globalOverrides` and `package.json` specs (pnpm 9.15.9, 10.34.9,
//! 11.28.12 and 12.21.0), byte for byte; the unit tests quote those locks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::constants::npm_family::{PNPM_LOCK, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR};
use crate::formats::pnpm::lines::{
    next_block, parse_key_line, section_bounds, split_lines, unquote_value, yaml_key,
};
use crate::formats::pnpm::{sniff_lock_grammar, vendored_npm_uuids, PnpmLockGrammar};
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::line_endings::LineEndings;
use crate::vendor::common::refused;
use crate::vendor::jsonc;
use crate::vendor::lock_inventory::pnpm::{is_rush, rush_lock_rels};
use crate::vendor::lock_inventory::ProjectView;
use crate::vendor::npm_common::{
    guard_coordinates, guard_revert_uuid_dir, refusal_code, tgz_leaf_version, tgz_rel_leaf,
    vendor_npm_family, NpmCommit, NpmCoords, NpmLockBackend, NpmStagedPack, NpmVendorRequest,
    WireCx,
};
use crate::vendor::npm_dir::{dependency_token, replace_dependency_token};
use crate::vendor::parse_memo::ParseMemo;
use crate::vendor::path::{parse_vendor_path, parse_vendor_path_from};
use crate::vendor::pnpm_build_approvals::VENDOR_PNPM_BUILD_APPROVAL_LOST;
use crate::vendor::revert::{self, KeepPolicy};
use crate::vendor::source::PackageSource;
use crate::vendor::state::{PnpmMeta, VendorEntry, WiringAction, WiringRecord};
use crate::vendor::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};

use super::{
    check_hosted_dependents, check_rewritable_refs_with, dep_entries, drifted, edit_packages,
    edit_snapshot_refs, edit_snapshot_rekey, is_mixed_line_endings, lock_has_target_package,
    matching_blocks, override_key_name, overrides_record, read_pnpm_text, restore_dep_map_refs,
    revert_lock_record, split_v9_lock, EditCtx, PnpmDialect, RefBlocks, KIND_LOCK_IMPORTER_DEP,
    KIND_LOCK_PACKAGE, KIND_LOCK_SNAPSHOT, VENDOR_CONFIG_DEPENDENCY_UNPATCHED,
    VENDOR_PNPM_LOCK_MULTI_DOCUMENT,
};

/// The ledger flavor of a Rush-wired entry.
pub(crate) const FLAVOR: &str = "rush-pnpm";

/// Refusal: a Rush repository shape vendored mode does not wire.
pub(crate) const VENDOR_RUSH_UNSUPPORTED: &str = "vendor_rush_unsupported";
/// Refusal: a directly-depending project's `package.json` cannot take the
/// `file:` spec.
pub(crate) const VENDOR_RUSH_PROJECT_MANIFEST: &str = "vendor_rush_project_manifest";
/// Refusal: the `file:` specs would fail Rush's consistent-versions policy.
pub(crate) const VENDOR_RUSH_INCONSISTENT_VERSIONS: &str = "vendor_rush_inconsistent_versions";
/// Warning: project `package.json` files were edited.
pub(crate) const VENDOR_RUSH_PACKAGE_JSON_EDITED: &str = "vendor_rush_package_json_edited";
/// Warning: `repo-state.json` holds a lock hash the edit made stale.
pub(crate) const VENDOR_RUSH_REPO_STATE_STALE: &str = "vendor_rush_repo_state_stale";

/// Wiring kinds this layout adds to the plain backend's lock kinds.
pub(crate) const KIND_GLOBAL_OVERRIDE: &str = "rush_global_override";
pub(crate) const KIND_PROJECT_DEP: &str = "rush_project_dep";

const RUSH_JSON: &str = "rush.json";
const RUSH_CONFIG_DIR: &str = "common/config/rush";
const RUSH_TEMP_DIR: &str = "common/temp";
const PNPM_CONFIG: &str = "pnpm-config.json";
const GLOBAL_OVERRIDES: &str = "globalOverrides";
const PACKAGE_JSON: &str = "package.json";
/// How a vendored path is spelled from the repository root.
const ROOT_PREFIX: &str = "file:.socket/vendor/";
/// The dependency fields of a lock importer that name a `package.json` field.
const DEP_FIELDS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];

/// A refusal's `(code, detail)`.
type Refusal = (&'static str, String);

/// One Rush pnpm lock and the directories Rush installs it from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Layout {
    /// `common/config/rush/pnpm-lock.yaml`, or a subspace's.
    lock_rel: String,
    /// Where `rush install` copies the lock and runs pnpm: the directory
    /// every path in the lock is relative to.
    temp_rel: String,
    /// The directory holding the lock and the subspace's own config files.
    config_dir: String,
}

impl Layout {
    /// The layout of a lock [`rush_lock_rels`] lists.
    fn of(lock_rel: &str) -> Option<Self> {
        if lock_rel == RUSH_COMMON_LOCK_REL {
            return Some(Self {
                lock_rel: lock_rel.to_string(),
                temp_rel: RUSH_TEMP_DIR.to_string(),
                config_dir: RUSH_CONFIG_DIR.to_string(),
            });
        }
        let name = lock_rel
            .strip_prefix(RUSH_SUBSPACES_DIR)?
            .strip_prefix('/')?
            .strip_suffix(PNPM_LOCK)?
            .strip_suffix('/')?;
        if !crate::patch::path_safety::is_safe_multi_segment(name) || name.contains('/') {
            return None;
        }
        Some(Self {
            lock_rel: lock_rel.to_string(),
            temp_rel: format!("{RUSH_TEMP_DIR}/{name}"),
            config_dir: format!("{RUSH_SUBSPACES_DIR}/{name}"),
        })
    }

    /// How the lock spells a vendored path: relative to the temp directory.
    fn temp_prefix(&self) -> String {
        format!(
            "file:{}.socket/vendor/",
            "../".repeat(self.temp_rel.split('/').count())
        )
    }

    /// The config file of this lock's subspace named `leaf`, in lookup
    /// order: the subspace's own, then the repository-wide one.
    fn config_candidates(&self, leaf: &str) -> Vec<String> {
        let own = format!("{}/{leaf}", self.config_dir);
        let shared = format!("{RUSH_CONFIG_DIR}/{leaf}");
        match own == shared {
            true => vec![own],
            false => vec![own, shared],
        }
    }

    /// The lock's lines as pnpm would spell them from the repository root.
    /// An importer's `specifier:` is relative to the importing project, not
    /// to the lock, and stays as written. `Err` names a line this cannot
    /// round-trip.
    fn to_root_relative(&self, lines: &mut [String]) -> Result<(), String> {
        let temp = self.temp_prefix();
        for line in lines.iter_mut().filter(|l| !is_specifier_line(l)) {
            if line.contains(ROOT_PREFIX) {
                return Err(format!(
                    "{} names `{}`, a vendored path under {} that no vendoring writes",
                    self.lock_rel,
                    line.trim(),
                    self.temp_rel
                ));
            }
            if line.contains(&temp) {
                *line = line.replace(&temp, ROOT_PREFIX);
            }
        }
        Ok(())
    }

    /// The inverse of [`Self::to_root_relative`].
    fn to_temp_relative(&self, lines: &[String]) -> Vec<String> {
        let temp = self.temp_prefix();
        lines
            .iter()
            .map(
                |line| match is_specifier_line(line) || !line.contains(ROOT_PREFIX) {
                    true => line.clone(),
                    false => line.replace(ROOT_PREFIX, &temp),
                },
            )
            .collect()
    }
}

fn is_specifier_line(line: &str) -> bool {
    line.starts_with("        specifier: ")
}

/// The text of the Rush lock at `lock_rel` with its vendored paths rebased
/// from Rush's temp directory, which the lock is installed from, to the
/// repository root, where every reader of a vendored reference expects
/// them ([`crate::origin::vendor_ref`]): `file:../../.socket/vendor/…`
/// reads as this repository's `file:.socket/vendor/…`, and a path the lock
/// spells `file:.socket/vendor/…` as the `common/temp/.socket/vendor/…` it
/// names, which is no artifact of ours. Any other file's text comes back
/// as it is.
pub(crate) fn root_relative_lock_text(lock_rel: &str, text: String) -> String {
    let Some(layout) = Layout::of(lock_rel) else {
        return text;
    };
    let temp = layout.temp_prefix();
    if !text.contains(&temp) && !text.contains(ROOT_PREFIX) {
        return text;
    }
    let under_temp = format!("file:{}/.socket/vendor/", layout.temp_rel);
    text.split('\n')
        .map(|line| match is_specifier_line(line) {
            true => line.to_string(),
            false => line
                .replace(ROOT_PREFIX, &under_temp)
                .replace(&temp, ROOT_PREFIX),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The first line of the Rush lock at `lock_rel` that spells a vendored
/// path from the repository root, as written: pnpm resolves it against
/// Rush's temp directory, so it names no artifact of this repository.
pub(crate) fn misplaced_vendored_path<'t>(lock_rel: &str, text: &'t str) -> Option<&'t str> {
    Layout::of(lock_rel)?;
    text.split('\n')
        .find(|line| !is_specifier_line(line) && line.contains(ROOT_PREFIX))
        .map(str::trim)
}

/// The repository-relative folder a lock importer key names: the key is
/// relative to the temp directory. `None` for a key that is not a plain
/// relative path, leaves the repository, or names the repository root or a
/// folder vendoring must never write into.
fn importer_project_rel(temp_rel: &str, importer: &str) -> Option<String> {
    if importer.contains('\\') || importer.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = temp_rel.split('/').collect();
    for segment in importer.split('/') {
        match segment {
            "" => return None,
            "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    let rel = parts.join("/");
    let reserved = parts
        .iter()
        .any(|p| matches!(*p, "node_modules" | ".socket" | ".git"));
    let under_temp = rel == RUSH_TEMP_DIR || rel.starts_with(&format!("{RUSH_TEMP_DIR}/"));
    (!parts.is_empty()
        && !reserved
        && !under_temp
        && crate::patch::path_safety::is_safe_multi_segment(&rel))
    .then_some(rel)
}

/// The split, rebased project document of each Rush lock this process read
/// last, by the lock's bytes and install folder (see [`ParseMemo`]).
static LOCK_MEMO: ParseMemo<Vec<String>, 4> = ParseMemo::new();

/// One Rush lock as read: its project document, root-relative.
#[derive(Debug, Clone)]
struct LockDoc {
    layout: Layout,
    eol: LineEndings,
    /// An env document ahead of the project document, kept verbatim.
    prefix: String,
    /// Shared with the next read of the same bytes ([`LOCK_MEMO`]): a run
    /// reads every Rush lock once per patched package.
    lines: Arc<Vec<String>>,
    /// The whole lock as read (LF).
    text: String,
}

impl LockDoc {
    /// The lock's bytes with `lines` as its project document.
    fn render(&self, lines: &[String]) -> Vec<u8> {
        let body = self.layout.to_temp_relative(lines).join("\n");
        self.eol
            .restore(&format!("{}{body}", self.prefix))
            .into_owned()
            .into_bytes()
    }
}

/// The Rush repository as the wiring reads it, gated before any write.
#[derive(Debug)]
pub(crate) struct RushProject {
    /// pnpm >= 11 gets its overrides through a key-sorted
    /// `pnpm-workspace.yaml` Rush generates, older pnpm through
    /// `package.json` in `globalOverrides`' own order; the lock's
    /// `overrides:` follows.
    sorted_overrides: bool,
    /// `ensureConsistentVersions` in rush.json.
    consistent_versions: bool,
    /// Folders of the projects rush.json publishes.
    published: BTreeSet<String>,
    locks: Vec<LockDoc>,
}

/// Whether the vendor router sends this project here: a Rush repository
/// with at least one pnpm lock of its own. `Err` is the refusal for a Rush
/// repository vendored mode does not wire.
pub(crate) async fn routes(project_root: &Path) -> Result<(), Refusal> {
    let view = ProjectView::Disk(project_root);
    let mut any = false;
    if is_rush(view).await {
        for rel in rush_lock_rels(view).await {
            any |= view.is_file(&rel);
        }
    }
    match any {
        true => Ok(()),
        false => Err(no_lock_refusal()),
    }
}

fn no_lock_refusal() -> Refusal {
    (
        VENDOR_RUSH_UNSUPPORTED,
        format!(
            "found {RUSH_JSON} but no Rush pnpm lockfile ({RUSH_COMMON_LOCK_REL}, or \
             {RUSH_SUBSPACES_DIR}/<name>/{PNPM_LOCK}): run `rush update` first. Vendored mode \
             wires Rush repositories that install with pnpm; one that installs with npm or \
             yarn is not wired"
        ),
    )
}

/// Read and gate the repository (refuse before any write).
async fn read_project(project_root: &Path) -> Result<RushProject, Refusal> {
    let unsupported = |detail: String| (VENDOR_RUSH_UNSUPPORTED, detail);
    let rush = read_regular_to_string(&project_root.join(RUSH_JSON))
        .await
        .ok()
        .and_then(|text| crate::formats::package_json::parse(&text))
        .ok_or_else(|| unsupported(format!("cannot read {RUSH_JSON} as JSON with comments")))?;
    let major = rush
        .get("pnpmVersion")
        .and_then(Value::as_str)
        .and_then(|v| v.split('.').next()?.parse::<u32>().ok())
        .ok_or_else(|| {
            unsupported(format!(
                "{RUSH_JSON} names no `pnpmVersion`: this Rush repository installs with npm or \
                 yarn, which vendored mode does not wire — use `socket-patch scan --mode hosted`"
            ))
        })?;
    let published = rush
        .get("projects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            p.get("shouldPublish").and_then(Value::as_bool) == Some(true)
                || p.get("versionPolicyName").is_some_and(|v| !v.is_null())
        })
        .filter_map(|p| Some(p.get("projectFolder")?.as_str()?.replace('\\', "/")))
        .collect();

    let view = ProjectView::Disk(project_root);
    let mut locks = Vec::new();
    for rel in rush_lock_rels(view).await {
        let Some(layout) = Layout::of(&rel) else {
            continue;
        };
        let (text, eol) = match read_pnpm_text(project_root, &rel).await {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) if is_mixed_line_endings(&e) => {
                return Err(("vendor_lockfile_crlf_unsupported", format!("{rel}: {e}")))
            }
            Err(e) => return Err(("vendor_lockfile_missing", format!("cannot read {rel}: {e}"))),
        };
        match sniff_lock_grammar(&text) {
            Ok(PnpmLockGrammar::V9) => {}
            Ok(other) => {
                return Err((
                    "vendor_lockfile_version_unsupported",
                    format!(
                        "{rel} is a {} lock: vendored mode wires a Rush repository on \
                         lockfileVersion 9.0 only (pnpm 9 and newer) — upgrade `pnpmVersion` in \
                         {RUSH_JSON} and run `rush update`, or use `socket-patch scan --mode \
                         hosted`",
                        other.describe()
                    ),
                ))
            }
            Err(detail) => {
                return Err((
                    "vendor_lockfile_version_unsupported",
                    detail.replace(PNPM_LOCK, &rel),
                ))
            }
        }
        let (prefix, project) = split_v9_lock(&text).map_err(|why| {
            (
                VENDOR_PNPM_LOCK_MULTI_DOCUMENT,
                format!("{rel}: {why} — use `--mode hosted`; nothing was written"),
            )
        })?;
        // The split and rebase are a function of the bytes and of where
        // Rush installs them from.
        let mut memo_key = text.as_bytes().to_vec();
        memo_key.push(0);
        memo_key.extend_from_slice(layout.temp_rel.as_bytes());
        let lines = LOCK_MEMO
            .parse(&memo_key, || {
                let mut lines = split_lines(project);
                layout.to_root_relative(&mut lines).map(|()| lines)
            })
            .map_err(unsupported)?;
        if lines.iter().any(|l| l.contains("@rush-temp/")) {
            return Err(unsupported(format!(
                "{rel} was installed without pnpm workspaces (`useWorkspaces` is off in \
                 {PNPM_CONFIG}): vendored mode wires Rush's workspace installs only — use \
                 `socket-patch scan --mode hosted`"
            )));
        }
        locks.push(LockDoc {
            layout,
            eol,
            prefix: prefix.to_string(),
            lines,
            text: text.clone(),
        });
    }
    if locks.is_empty() {
        return Err(no_lock_refusal());
    }
    Ok(RushProject {
        sorted_overrides: major >= 11,
        consistent_versions: rush
            .get("ensureConsistentVersions")
            .and_then(Value::as_bool)
            == Some(true),
        published,
        locks,
    })
}

/// Files of the repository, read once per run.
struct Files<'r> {
    root: &'r Path,
    texts: BTreeMap<String, Option<String>>,
}

impl<'r> Files<'r> {
    fn new(root: &'r Path) -> Self {
        Self {
            root,
            texts: BTreeMap::new(),
        }
    }

    /// The text of `rel`; `Ok(None)` when it does not exist. A path that
    /// passes through a symlink is never read: the edit that follows must
    /// stay inside the repository.
    async fn text(&mut self, rel: &str) -> Result<Option<String>, String> {
        if let Some(known) = self.texts.get(rel) {
            return Ok(known.clone());
        }
        let path = self.root.join(rel);
        if let Some(link) = crate::utils::containment::linked_level(self.root, &path) {
            return Err(format!(
                "{rel} is reached through the symlink {}",
                link.display()
            ));
        }
        let read = match read_regular_to_string(&path).await {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("cannot read {rel}: {e}")),
        };
        self.texts.insert(rel.to_string(), read.clone());
        Ok(read)
    }
}

/// One file the wiring rewrites.
#[derive(Debug)]
struct FileWrite {
    rel: String,
    new: Vec<u8>,
    original: Vec<u8>,
}

/// The whole wiring of one package, computed in memory.
#[derive(Debug, Default)]
struct Plan {
    /// In write order: project manifests, config files, locks.
    writes: Vec<FileWrite>,
    wiring: Vec<WiringRecord>,
    created_overrides_table: bool,
    warnings: Vec<VendorWarning>,
}

/// A dependency entry of a lock importer.
#[derive(Debug, Clone)]
struct ImporterDep {
    importer: String,
    /// The `package.json` field the entry sits under.
    field: &'static str,
    spec_line: usize,
    ver_line: usize,
    specifier: String,
    version: String,
}

/// Every importer's entry for dependency `name`, in lock order.
fn importer_deps(lines: &[String], name: &str) -> Vec<ImporterDep> {
    let mut out = Vec::new();
    let Some((start, end)) = section_bounds(lines, "importers") else {
        return out;
    };
    let mut i = start + 1;
    while let Some(importer) = next_block(lines, i, end) {
        i = importer.end;
        // The 4-space field headers of the block, each running to the next.
        let headers: Vec<(usize, &'static str)> = (importer.header + 1..importer.end)
            .filter_map(|k| {
                let (key, _, rest) = parse_key_line(&lines[k], 4)?;
                let field = DEP_FIELDS.into_iter().find(|f| *f == key)?;
                rest.is_empty().then_some((k, field))
            })
            .collect();
        for (header, field) in &headers {
            let field_end = (header + 1..importer.end)
                .find(|k| parse_key_line(&lines[*k], 4).is_some())
                .unwrap_or(importer.end);
            for entry in dep_entries(lines, header + 1, field_end, 6).filter(|e| e.dep == name) {
                if let Some((spec_line, specifier, ver_line, version)) = entry.pair() {
                    out.push(ImporterDep {
                        importer: importer.key.clone(),
                        field,
                        spec_line,
                        ver_line,
                        specifier,
                        version,
                    });
                }
            }
        }
    }
    out
}

/// The 2-space-keyed blocks of `section`, as `(key, header, end)`.
fn section_blocks(lines: &[String], section: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    if let Some((start, end)) = section_bounds(lines, section) {
        let mut i = start + 1;
        while let Some(block) = next_block(lines, i, end) {
            i = block.end;
            out.push((block.key, block.header, block.end));
        }
    }
    out
}

/// Move the block keyed `key` to where pnpm's serializer keeps it: the
/// section's keys in code-unit order, compared as the lock spells them
/// (relative to the layout's temp directory). The other blocks are left in
/// the order they are in.
fn resort_block(lines: &mut Vec<String>, section: &str, key: &str, layout: &Layout) {
    let temp = layout.temp_prefix();
    let spelled = |key: &str| -> std::borrow::Cow<'_, str> {
        match key.contains(ROOT_PREFIX) {
            true => key.replace(ROOT_PREFIX, &temp).into(),
            false => key.to_string().into(),
        }
    };
    let blocks = section_blocks(lines, section);
    let Some(&(_, header, end)) = blocks.iter().find(|(k, _, _)| k == key) else {
        return;
    };
    let target = spelled(key).into_owned();
    let after = |other: &str| match other.contains(ROOT_PREFIX) {
        true => *spelled(other) > *target,
        false => other > target.as_str(),
    };
    let next = blocks
        .iter()
        .filter(|(k, _, _)| k != key)
        .find(|(k, _, _)| after(k))
        .map(|(_, h, _)| *h);
    let in_place = match next {
        Some(h) => blocks
            .iter()
            .skip_while(|(_, bh, _)| *bh != header)
            .nth(1)
            .is_some_and(|(_, bh, _)| *bh == h),
        None => blocks.last().is_some_and(|(_, bh, _)| *bh == header),
    };
    if in_place {
        return;
    }
    let mut chunk: Vec<String> = lines.drain(header..end).collect();
    // The blank line that separated it goes along.
    if lines.get(header).is_some_and(String::is_empty) {
        lines.remove(header);
    }
    chunk.push(String::new());
    let blocks = section_blocks(lines, section);
    let at = match blocks.iter().find(|(k, _, _)| after(k)) {
        Some((_, h, _)) => *h,
        None => match blocks.last() {
            // After the last block and the blank line that follows it.
            Some((_, _, e)) => {
                (*e + usize::from(lines.get(*e).is_some_and(String::is_empty))).min(lines.len())
            }
            None => header,
        },
    };
    lines.splice(at..at, chunk);
}

/// A later resolve can bring the registry entry back beside the vendored
/// one (a new dependent on the same version). Once every edge has moved to
/// the vendored entry nothing references the registry one, and pnpm drops
/// it: so does this. Returns whether a block went.
fn drop_registry_twin(lines: &mut Vec<String>, section: &str, name: &str, version: &str) -> bool {
    let Some((start, end)) = section_bounds(lines, section) else {
        return false;
    };
    let matches = matching_blocks(lines, section, start, end, name, version);
    if !matches.iter().any(|(_, rekeyed)| *rekeyed) {
        return false;
    }
    let Some((twin, _)) = matches.into_iter().find(|(_, rekeyed)| !rekeyed) else {
        return false;
    };
    lines.drain(twin.header..twin.end);
    if lines.get(twin.header).is_some_and(String::is_empty) {
        lines.remove(twin.header);
    }
    true
}

/// Reduce the blocks keyed `key` in `section` to one: the block whose lines
/// are `keep` (a wiring record's original fragment) when one is, else the
/// first. Returns whether a block went.
fn drop_duplicate_block(
    lines: &mut Vec<String>,
    section: &str,
    key: &str,
    keep: Option<&Value>,
) -> bool {
    let twins: Vec<(usize, usize)> = section_blocks(lines, section)
        .into_iter()
        .filter(|(k, _, _)| k == key)
        .map(|(_, header, end)| (header, end))
        .collect();
    if twins.len() < 2 {
        return false;
    }
    let is_kept = |&(header, end): &(usize, usize)| {
        keep.and_then(Value::as_array).is_some_and(|want| {
            want.len() == end - header
                && want
                    .iter()
                    .zip(&lines[header..end])
                    .all(|(w, line)| w.as_str() == Some(line))
        })
    };
    let kept = twins.iter().position(is_kept).unwrap_or(0);
    // From the last block back, so the earlier offsets stay valid.
    for (at, (header, end)) in twins.iter().enumerate().rev() {
        if at == kept {
            continue;
        }
        lines.drain(*header..*end);
        if lines.get(*header).is_some_and(String::is_empty) {
            lines.remove(*header);
        }
    }
    true
}

/// How an override selects the package of snapshot `key`:
/// `<name>@<version>`. `None` when the lock does not say its version.
fn override_parent(
    lines: &[String],
    packages: &[(String, usize, usize)],
    key: &str,
) -> Option<String> {
    // A peer or patch suffix is not part of the package's identity.
    let bare = key.split_once('(').map_or(key, |(k, _)| k);
    // Past the first character: a scope's `@` is not the separator.
    let at = bare
        .char_indices()
        .skip(1)
        .find_map(|(i, c)| (c == '@').then_some(i))?;
    let (parent, locator) = (&bare[..at], &bare[at + 1..]);
    if locator.starts_with(|c: char| c.is_ascii_digit()) {
        return Some(format!("{parent}@{locator}"));
    }
    // A `file:`, git or url entry spells its version in the entry.
    let (_, header, end) = packages.iter().find(|(k, _, _)| k == bare)?;
    lines[header + 1..*end].iter().find_map(|line| {
        let (field, _, rest) = parse_key_line(line, 4)?;
        (field == "version").then(|| format!("{parent}@{}", unquote_value(rest)))
    })
}

/// What each snapshot that depends on `name` resolves it to:
/// `(snapshot key, resolved value)`.
fn snapshot_edges(lines: &[String], name: &str) -> Vec<(String, String)> {
    section_blocks(lines, "snapshots")
        .into_iter()
        .filter_map(|(key, header, end)| {
            let rest = lines[header + 1..end].iter().find_map(|line| {
                parse_key_line(line, 6)
                    .filter(|(dep, _, _)| *dep == name)
                    .map(|(_, _, rest)| rest.to_string())
            })?;
            Some((key, rest))
        })
        .collect()
}

/// The override key of every registry package whose snapshot resolves the
/// vendored package: `<parent>@<version>><name>@<version>`, sorted.
fn parent_override_keys(lines: &[String], ctx: &EditCtx<'_>) -> Result<Vec<String>, String> {
    let mut keys = BTreeSet::new();
    let packages = section_blocks(lines, "packages");
    for (key, rest) in snapshot_edges(lines, ctx.name) {
        if rest != ctx.spec {
            continue;
        }
        let parent = override_parent(lines, &packages, &key).ok_or_else(|| {
            format!(
                "`{key}` depends on {}@{} but its own version cannot be read, so no override \
                 can select it",
                ctx.name, ctx.version
            )
        })?;
        keys.insert(format!("{parent}>{}@{}", ctx.name, ctx.version));
    }
    Ok(keys.into_iter().collect())
}

/// The first dependent in `lines` that one of `keys` selects but that
/// resolves `name` to something other than `spec`: `(override key, snapshot
/// key, what it resolves to)`. pnpm applies an override to every lock that
/// reads the config, so that dependent would move to the vendored release
/// the next time pnpm resolves it.
fn other_resolution(
    lines: &[String],
    keys: &[String],
    name: &str,
    spec: &str,
) -> Option<(String, String, String)> {
    let packages = section_blocks(lines, "packages");
    snapshot_edges(lines, name)
        .into_iter()
        .filter(|(_, rest)| rest != spec)
        .find_map(|(snapshot, rest)| {
            let parent = override_parent(lines, &packages, &snapshot)?;
            let key = keys
                .iter()
                .find(|key| key.split_once('>').is_some_and(|(p, _)| p == parent))?;
            Some((key.clone(), snapshot, rest))
        })
}

/// The `overrides:` entries of a lock, as `(line, key, value)`.
fn lock_overrides(lines: &[String]) -> Vec<(usize, String, String)> {
    let Some((start, end)) = section_bounds(lines, "overrides") else {
        return Vec::new();
    };
    (start + 1..end)
        .filter_map(|i| {
            let (key, _, rest) = parse_key_line(&lines[i], 2)?;
            Some((i, key.to_string(), rest.to_string()))
        })
        .collect()
}

/// Put `keys` (each to `spec`) into the lock's `overrides:` section, where
/// pnpm keeps them: in key order when Rush hands pnpm a sorted map, else
/// after the entries already there (the config file's order, which the
/// config edit appends to as well).
fn edit_overrides(
    lines: &mut Vec<String>,
    keys: &[String],
    spec: &str,
    sorted: bool,
    wiring: &mut Vec<WiringRecord>,
) -> bool {
    let mut changed = false;
    for key in keys {
        let entry = format!("  {}: {spec}", yaml_key(key));
        let live = lock_overrides(lines);
        if let Some((at, _, value)) = live.iter().find(|(_, k, _)| k == key) {
            if value != spec {
                lines[*at] = entry;
                wiring.push(overrides_record(key, spec, WiringAction::Rewritten, None));
                changed = true;
            }
            continue;
        }
        match section_bounds(lines, "overrides") {
            Some((start, _)) => {
                let at = match sorted {
                    true => live.iter().find(|(_, k, _)| k > key).map(|(i, _, _)| *i),
                    false => None,
                }
                .unwrap_or_else(|| live.last().map_or(start + 1, |(i, _, _)| i + 1));
                lines.insert(at, entry);
            }
            None => {
                // pnpm's root key order: after `settings` / `catalogs`,
                // ahead of the checksums, `patchedDependencies` and
                // `importers`.
                let at = lines
                    .iter()
                    .position(|line| {
                        !line.is_empty()
                            && !line.starts_with(' ')
                            && !["lockfileVersion", "settings", "catalogs"]
                                .contains(&line.split(':').next().unwrap_or(""))
                    })
                    .unwrap_or(lines.len());
                lines.splice(at..at, ["overrides:".to_string(), entry, String::new()]);
            }
        }
        wiring.push(overrides_record(key, spec, WiringAction::Added, None));
        changed = true;
    }
    changed
}

/// Whether an override entry is one this layout writes for package `name`:
/// a parent-scoped key that pins the dependency to the very version its
/// vendored tarball holds. A sibling version's entry is one too, and
/// reaches none of this version's edges (a parent resolves the package to
/// one version).
fn is_own_override(key: &str, value: &str, name: &str) -> bool {
    parse_vendor_path(value)
        .filter(|parts| parts.eco == "npm")
        // The whole leaf: a scoped package's is `@scope/name-<version>.tgz`.
        .and_then(|parts| tgz_leaf_version(name, &parts.leaf).map(str::to_string))
        .is_some_and(|vendored| key.ends_with(&format!(">{name}@{vendored}")))
}

/// The refusal for an override on `name` that is not this vendoring's own:
/// pnpm would apply it to the edges the wiring moves.
fn override_conflict(
    file: &str,
    entries: impl Iterator<Item = (String, String)>,
    name: &str,
    version: &str,
) -> Result<(), Refusal> {
    for (key, value) in entries {
        if override_key_name(&key) == name && !is_own_override(&key, &value, name) {
            return Err((
                "vendor_override_conflict",
                format!(
                    "{file} already overrides {name} (`{key}: {value}`): pnpm would apply it to \
                     the dependents vendoring rewires — remove that override (and run `rush \
                     update`) before vendoring {name}@{version}"
                ),
            ));
        }
    }
    Ok(())
}

/// Compute the wiring of `name@version` (artifact `rel_tgz`, sha512
/// `integrity`) over every Rush lock that installs it. Nothing is written.
async fn plan(
    project: &RushProject,
    files: &mut Files<'_>,
    name: &str,
    version: &str,
    rel_tgz: &str,
    integrity: &str,
) -> Result<Plan, Refusal> {
    let spec = format!("file:{rel_tgz}");
    let ctx = EditCtx {
        name,
        version,
        rel_tgz,
        spec: &spec,
        integrity,
        override_key: "",
    };
    let mut out = Plan::default();
    // file -> (text as read, text after the edits so far).
    let mut manifests: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut configs: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut edited_manifests: Vec<String> = Vec::new();
    // Per lock: the lines this run edits, once it edits them.
    let mut edits: Vec<Option<LockEdit>> = project.locks.iter().map(|_| None).collect();
    // Per lock: the pnpm-config.json Rush reads for it.
    let mut lock_configs: Vec<Option<String>> = Vec::with_capacity(project.locks.len());
    // Per config file: the overrides this run needs in it, in the order it
    // gets them, and how the locks that read it spell a vendored path.
    let mut config_keys: Vec<ConfigKeys> = Vec::new();

    for (at, doc) in project.locks.iter().enumerate() {
        let lock_rel = doc.layout.lock_rel.as_str();
        let config_rel = config_file(files, &doc.layout).await?;
        lock_configs.push(config_rel.clone());
        if !lock_has_target_package(&*doc.lines, name, version) {
            continue;
        }
        let unsupported = |detail: String| {
            (
                "vendor_lock_entry_unsupported",
                detail.replace(PNPM_LOCK, lock_rel),
            )
        };
        check_rewritable_refs_with(&doc.lines, name, version, None).map_err(unsupported)?;
        check_hosted_dependents(&doc.lines, name, version, None).map_err(unsupported)?;
        override_conflict(
            lock_rel,
            lock_overrides(&doc.lines)
                .into_iter()
                .map(|(_, key, value)| (key, value)),
            name,
            version,
        )?;

        let mut lines = (*doc.lines).clone();
        let mut records: Vec<WiringRecord> = Vec::new();
        let specifiers_before = distinct_specifiers(&lines, name);
        let mut injected_hash_inputs = false;

        // Direct edges: the importer entry and the project's package.json.
        for dep in importer_deps(&lines, name) {
            let ours = ctx.is_ours(&dep.version);
            if dep.version != version && !ours {
                continue;
            }
            let project_rel = importer_project_rel(&doc.layout.temp_rel, &dep.importer)
                .ok_or_else(|| {
                    (
                        VENDOR_RUSH_UNSUPPORTED,
                        format!(
                            "{lock_rel} importer `{}` does not name a project folder inside the \
                             repository",
                            dep.importer
                        ),
                    )
                })?;
            let importer_spec = format!(
                "file:{}{rel_tgz}",
                "../".repeat(project_rel.split('/').count())
            );
            let manifest_rel = format!("{project_rel}/{PACKAGE_JSON}");
            let edited = edit_manifest(
                files,
                &mut manifests,
                &manifest_rel,
                &project_rel,
                &dep,
                (name, version),
                &importer_spec,
                lock_rel,
                &mut out.wiring,
            )
            .await?;
            if edited {
                injected_hash_inputs |= dep.field != "devDependencies";
                edited_manifests.push(manifest_rel);
            }
            if dep.version == spec && dep.specifier == importer_spec {
                continue;
            }
            records.push(WiringRecord {
                file: PNPM_LOCK.to_string(),
                kind: KIND_LOCK_IMPORTER_DEP.to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{}|{name}", dep.importer)),
                original: (!ours).then(
                    || serde_json::json!({ "specifier": dep.specifier, "version": dep.version }),
                ),
                new: Some(serde_json::json!({ "specifier": importer_spec, "version": spec })),
            });
            lines[dep.spec_line] = format!("        specifier: {importer_spec}");
            lines[dep.ver_line] = format!("        version: {spec}");
        }

        // Transitive edges, then the entry itself.
        edit_snapshot_refs(&mut lines, &ctx, &mut records).map_err(unsupported)?;
        for section in ["packages", "snapshots"] {
            drop_registry_twin(&mut lines, section, name, version);
        }
        edit_packages(&mut lines, &ctx, &mut records).map_err(unsupported)?;
        edit_snapshot_rekey(&mut lines, &ctx, &mut records).map_err(unsupported)?;
        for section in ["packages", "snapshots"] {
            resort_block(&mut lines, section, &ctx.new_key(), &doc.layout);
        }

        // The overrides that keep the transitive edges where the lock has
        // them go into the config Rush generates pnpm's from. Rush and pnpm
        // then expect them in EVERY lock that reads that config, so the
        // locks get them below, once every lock has named its own.
        let keys = parent_override_keys(&lines, &ctx).map_err(unsupported)?;
        match &config_rel {
            Some(config_rel) => {
                let temp = doc.layout.temp_prefix();
                let at = match config_keys.iter().position(|c| &c.file == config_rel) {
                    Some(at) => at,
                    None => {
                        config_keys.push(ConfigKeys {
                            file: config_rel.clone(),
                            temp_prefix: temp.clone(),
                            keys: Vec::new(),
                        });
                        config_keys.len() - 1
                    }
                };
                let shared = &mut config_keys[at];
                if shared.temp_prefix != temp {
                    return Err((
                        VENDOR_RUSH_UNSUPPORTED,
                        format!(
                            "{lock_rel} and a lockfile Rush installs from another folder both \
                             read {config_rel}: an override there cannot name the vendored \
                             tarball for both. Remove the lockfile Rush no longer uses"
                        ),
                    ));
                }
                for key in keys {
                    if !shared.keys.contains(&key) {
                        shared.keys.push(key);
                    }
                }
            }
            None if keys.is_empty() => {}
            None => {
                return Err((
                    VENDOR_RUSH_UNSUPPORTED,
                    format!(
                        "{RUSH_CONFIG_DIR}/{PNPM_CONFIG} does not exist: vendoring declares \
                         its overrides in `{GLOBAL_OVERRIDES}` there, which Rush copies into \
                         the install it runs — create it with `rush init`, or use `socket-patch \
                         scan --mode hosted`"
                    ),
                ))
            }
        }
        // The env document ahead of the project lock is never edited.
        if lock_has_target_package(&split_lines(&doc.prefix), name, version) {
            out.warnings.push(VendorWarning::new(
                VENDOR_CONFIG_DEPENDENCY_UNPATCHED,
                format!(
                    "{name}@{version} is also a pnpm config dependency (the first document of \
                     {lock_rel}); vendoring wires the projects' copy only, and the copy pnpm \
                     installs under node_modules/.pnpm-config stays unpatched — use `--mode \
                     hosted` to patch both"
                ),
            ));
        }
        edits[at] = Some(LockEdit {
            lines,
            records,
            specifiers_before: Some(specifiers_before),
            injected_hash_inputs,
        });
    }
    if edits.iter().all(Option::is_none) {
        return Err((
            "vendor_lock_entry_not_found",
            format!(
                "no Rush pnpm lockfile has a packages entry for {name}@{version} — make sure \
                 the package is installed and locked (`rush update`) before vendoring"
            ),
        ));
    }

    for shared in &config_keys {
        edit_config(
            files,
            &mut configs,
            shared,
            (name, version),
            &spec,
            &mut out,
        )
        .await?;
    }
    // Every lock that reads a config carries that config's overrides,
    // whether or not it installs the package.
    for (at, doc) in project.locks.iter().enumerate() {
        let Some(shared) = lock_configs[at]
            .as_ref()
            .and_then(|rel| config_keys.iter().find(|c| &c.file == rel))
        else {
            continue;
        };
        // A lock Rush installs from another depth cannot carry the config's
        // path (a leftover of a layout the repository moved off): it does
        // not install the package, so it is left as it is.
        if shared.keys.is_empty() || shared.temp_prefix != doc.layout.temp_prefix() {
            continue;
        }
        let keys = shared.keys.as_slice();
        let current = edits[at].as_ref().map_or(&**doc.lines, |e| &e.lines[..]);
        if let Some((key, dependent, other)) = other_resolution(current, keys, name, &spec) {
            return Err((
                VENDOR_RUSH_UNSUPPORTED,
                format!(
                    "{} reads {} too, and there `{dependent}` resolves {name} to `{other}`, \
                     not {version}: the override `{key}` that vendoring {name}@{version} needs \
                     in that config would move it to the vendored release the next time pnpm \
                     resolves that lockfile. Give one of the subspaces its own {PNPM_CONFIG}, \
                     or use `socket-patch scan --mode hosted`; nothing was written",
                    doc.layout.lock_rel, shared.file
                ),
            ));
        }
        let edit = edits[at].get_or_insert_with(|| LockEdit {
            lines: (*doc.lines).clone(),
            records: Vec::new(),
            specifiers_before: None,
            injected_hash_inputs: false,
        });
        edit_overrides(
            &mut edit.lines,
            keys,
            &spec,
            project.sorted_overrides,
            &mut edit.records,
        );
    }

    let mut lock_writes = Vec::new();
    let mut stale_repo_state: Vec<String> = Vec::new();
    let mut stale_injected_hash: Vec<String> = Vec::new();
    for (doc, edit) in project.locks.iter().zip(edits) {
        let Some(LockEdit {
            lines,
            mut records,
            specifiers_before,
            injected_hash_inputs,
        }) = edit
        else {
            continue;
        };
        let lock_rel = doc.layout.lock_rel.as_str();
        if let Some(before) = specifiers_before {
            let policy = version_policy(files, &doc.layout, name).await?;
            if project.consistent_versions || policy.consistent_versions {
                let mut after = distinct_specifiers(&lines, name);
                let mut before = before;
                if let Some(preferred) = &policy.preferred_version {
                    after.insert(preferred.clone());
                    before.insert(preferred.clone());
                }
                let disallowed = |set: &BTreeSet<String>| {
                    set.iter()
                        .filter(|s| !policy.allowed_alternatives.contains(*s))
                        .count()
                };
                if disallowed(&after) > 1 && disallowed(&before) <= 1 {
                    return Err((
                        VENDOR_RUSH_INCONSISTENT_VERSIONS,
                        format!(
                            "vendoring {name}@{version} gives the projects that depend on it \
                             directly different `package.json` specs ({}), because a `file:` \
                             spec is relative to each project's folder, and this repository \
                             enforces `ensureConsistentVersions`: `rush install` would fail. \
                             List those specs under `allowedAlternativeVersions` for `{name}` \
                             in common-versions.json and re-run, or use `socket-patch scan \
                             --mode hosted`; nothing was written",
                            after.into_iter().collect::<Vec<_>>().join(", ")
                        ),
                    ));
                }
            }
        }
        // Rush records two hashes beside the lock, and `rush install`
        // refuses a repository whose files no longer match them.
        let repo_state = format!("{}/repo-state.json", doc.layout.config_dir);
        let recorded = files
            .text(&repo_state)
            .await
            .ok()
            .flatten()
            .and_then(|text| crate::formats::package_json::parse(&text));
        let records_hash = |field: &str| recorded.as_ref().is_some_and(|v| v.get(field).is_some());
        if injected_hash_inputs && records_hash("packageJsonInjectedDependenciesHash") {
            stale_injected_hash.push(repo_state.clone());
        }
        if lines == *doc.lines {
            continue;
        }
        for record in &mut records {
            record.file = lock_rel.to_string();
        }
        out.wiring.extend(records);
        lock_writes.push(FileWrite {
            rel: lock_rel.to_string(),
            new: doc.render(&lines),
            original: doc.eol.restore(&doc.text).into_owned().into_bytes(),
        });
        // `preventManualShrinkwrapChanges` records the lock's hash.
        if records_hash("pnpmShrinkwrapHash") {
            stale_repo_state.push(repo_state);
        }
    }

    let changed = |(rel, (was, now)): (String, (String, String))| {
        (was != now).then(|| FileWrite {
            rel,
            new: now.into_bytes(),
            original: was.into_bytes(),
        })
    };
    out.writes.extend(manifests.into_iter().filter_map(changed));
    out.writes.extend(configs.into_iter().filter_map(changed));
    out.writes.extend(lock_writes);

    if !edited_manifests.is_empty() {
        let published: Vec<&str> = edited_manifests
            .iter()
            .filter_map(|m| m.strip_suffix(PACKAGE_JSON)?.strip_suffix('/'))
            .filter(|folder| project.published.contains(*folder))
            .collect();
        let published = match published.is_empty() {
            true => String::new(),
            false => format!(
                " {} published from this repository: a package published with a `file:` \
                 dependency cannot be installed by its consumers, so depend on a fixed \
                 release of {name} there instead.",
                match published.as_slice() {
                    [one] => format!("{one} is"),
                    many => format!("{} are", many.join(", ")),
                }
            ),
        };
        out.warnings.push(VendorWarning::new(
            VENDOR_RUSH_PACKAGE_JSON_EDITED,
            format!(
                "{name}@{version} is a direct dependency of {}: its spec there now points at \
                 the vendored tarball. `rush install` compares each project's package.json \
                 with the lockfile, so a direct dependency cannot be redirected by an \
                 override alone; `vendor --revert` puts the registry version back.{published}",
                edited_manifests.join(", ")
            ),
        ));
    }
    if !stale_repo_state.is_empty() {
        out.warnings.push(VendorWarning::new(
            VENDOR_RUSH_REPO_STATE_STALE,
            format!(
                "{} records a hash of the lockfile (`preventManualShrinkwrapChanges`), which \
                 this edit made stale: `rush install` fails until `rush update` refreshes it. \
                 `rush update` keeps the vendored wiring and changes only that hash",
                stale_repo_state.join(", ")
            ),
        ));
    }
    if !stale_injected_hash.is_empty() {
        out.warnings.push(VendorWarning::new(
            VENDOR_RUSH_REPO_STATE_STALE,
            format!(
                "{} records a hash of the package.json files behind injected workspace \
                 dependencies (`packageJsonInjectedDependenciesHash`), and this run changed \
                 {name}'s spec in {}: if one of those projects is among them, `rush install` \
                 fails until `rush update` refreshes the hash. `rush update` keeps the vendored \
                 wiring",
                stale_injected_hash.join(", "),
                edited_manifests.join(", ")
            ),
        ));
    }
    Ok(out)
}

/// One lock's lines as this run edits them.
struct LockEdit {
    lines: Vec<String>,
    /// Lock records, `file` still to be set.
    records: Vec<WiringRecord>,
    /// The importers' specifiers for the package before the edit; `None`
    /// for a lock that only mirrors a shared config's overrides.
    specifiers_before: Option<BTreeSet<String>>,
    /// Whether this run edited a project manifest field that Rush hashes
    /// for injected workspace dependencies (every field but
    /// `devDependencies`).
    injected_hash_inputs: bool,
}

/// The overrides one `pnpm-config.json` gets from this run.
struct ConfigKeys {
    file: String,
    /// How the locks that read this config spell a vendored path.
    temp_prefix: String,
    /// In the order the config gets them.
    keys: Vec<String>,
}

/// Every distinct `specifier` the lock's importers give dependency `name`.
fn distinct_specifiers(lines: &[String], name: &str) -> BTreeSet<String> {
    importer_deps(lines, name)
        .into_iter()
        .map(|dep| unquote_value(&dep.specifier).to_string())
        .collect()
}

/// Move a project's `package.json` spec for the dependency to
/// `importer_spec`. Returns whether the manifest changed.
#[allow(clippy::too_many_arguments)]
async fn edit_manifest(
    files: &mut Files<'_>,
    manifests: &mut BTreeMap<String, (String, String)>,
    manifest_rel: &str,
    project_rel: &str,
    dep: &ImporterDep,
    (name, version): (&str, &str),
    importer_spec: &str,
    lock_rel: &str,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, Refusal> {
    let refuse = |detail: String| (VENDOR_RUSH_PROJECT_MANIFEST, detail);
    if !manifests.contains_key(manifest_rel) {
        let text = files
            .text(manifest_rel)
            .await
            .map_err(&refuse)?
            .ok_or_else(|| {
                refuse(format!(
                    "{lock_rel} lists the project `{}`, but {manifest_rel} does not exist",
                    dep.importer
                ))
            })?;
        manifests.insert(manifest_rel.to_string(), (text.clone(), text));
    }
    let (_, text) = manifests.get_mut(manifest_rel).expect("just inserted");
    let stale = || {
        refuse(format!(
            "{manifest_rel} and {lock_rel} disagree on `{name}` under `{}` (the lockfile has \
             `{}`): run `rush update` so they match, then vendor again; nothing was written",
            dep.field, dep.specifier
        ))
    };
    let token = match dependency_token(text, dep.field, name) {
        Ok(token) => token,
        // pnpm installs a workspace project's own peer dependency for it and
        // locks it under `dependencies`, beside a `devDependencies` spec or
        // without one. Rush moves the entry to `devDependencies` once that
        // spec is a `file:` one, an edit this layout does not make.
        Err(_) if dependency_token(text, "peerDependencies", name).is_ok() => {
            return Err(refuse(format!(
                "{manifest_rel} lists `{name}` under peerDependencies. pnpm locks a workspace \
                 project's own peer dependency under `dependencies` in {lock_rel}, where the \
                 project has no spec that vendoring can move to the tarball. Vendored mode \
                 does not wire this shape: use `socket-patch scan --mode hosted`; nothing was \
                 written"
            )))
        }
        Err(_) => return Err(stale()),
    };
    let current: String = serde_json::from_str(&token).map_err(|_| stale())?;
    if current == importer_spec {
        return Ok(false);
    }
    // The registry spec the lock was resolved from, or an earlier
    // vendoring's spec for the same release. The lock quotes a spec YAML
    // would misread (`'*'`, `'1'`).
    let ours = parse_vendor_path_from(project_rel, &current)
        .is_some_and(|p| p.eco == "npm" && p.leaf == tgz_rel_leaf(name, version));
    if current != unquote_value(&dep.specifier) && !ours {
        return Err(stale());
    }
    let raw = Value::String(importer_spec.to_string()).to_string();
    *text = replace_dependency_token(text, dep.field, name, &raw).map_err(|_| stale())?;
    wiring.push(WiringRecord {
        file: manifest_rel.to_string(),
        kind: KIND_PROJECT_DEP.to_string(),
        action: WiringAction::Rewritten,
        key: Some(format!("{}|{name}", dep.field)),
        original: (!ours).then(|| Value::String(current)),
        new: Some(Value::String(importer_spec.to_string())),
    });
    Ok(true)
}

/// What a subspace's config files say about version consistency.
#[derive(Debug, Default)]
struct ConfigFacts {
    /// `ensureConsistentVersions` in common-versions.json.
    consistent_versions: bool,
    /// `allowedAlternativeVersions` for the package.
    allowed_alternatives: Vec<String>,
    /// `preferredVersions` for the package: Rush's consistency check counts
    /// it beside the projects' own specs.
    preferred_version: Option<String>,
}

/// The version policy of the lock's subspace for package `name`: its own
/// common-versions.json (Rush reads no shared one for a subspace).
async fn version_policy(
    files: &mut Files<'_>,
    layout: &Layout,
    name: &str,
) -> Result<ConfigFacts, Refusal> {
    let mut facts = ConfigFacts::default();
    let rel = format!("{}/common-versions.json", layout.config_dir);
    let text = files
        .text(&rel)
        .await
        .map_err(|detail| (VENDOR_RUSH_UNSUPPORTED, detail))?;
    if let Some(doc) = text.and_then(|text| crate::formats::package_json::parse(&text)) {
        facts.consistent_versions =
            doc.get("ensureConsistentVersions").and_then(Value::as_bool) == Some(true);
        facts.allowed_alternatives = doc
            .get("allowedAlternativeVersions")
            .and_then(|table| table.get(name))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        facts.preferred_version = doc
            .get("preferredVersions")
            .and_then(|table| table.get(name))
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    Ok(facts)
}

/// The `pnpm-config.json` Rush reads for this lock: the subspace's own,
/// else the repository-wide one. `None` when neither exists.
async fn config_file(files: &mut Files<'_>, layout: &Layout) -> Result<Option<String>, Refusal> {
    for rel in layout.config_candidates(PNPM_CONFIG) {
        let found = files
            .text(&rel)
            .await
            .map_err(|detail| (VENDOR_RUSH_UNSUPPORTED, detail))?;
        if found.is_some() {
            return Ok(Some(rel));
        }
    }
    Ok(None)
}

/// The Rush settings that decide whether a package may run its build
/// scripts.
const BUILD_SETTINGS: [&str; 3] = [
    "globalOnlyBuiltDependencies",
    "globalNeverBuiltDependencies",
    "globalAllowBuilds",
];

/// Put this run's parent-scoped overrides into a `pnpm-config.json`'s
/// `globalOverrides`, refusing an override of the user's on the package.
async fn edit_config(
    files: &mut Files<'_>,
    configs: &mut BTreeMap<String, (String, String)>,
    shared: &ConfigKeys,
    (name, version): (&str, &str),
    spec: &str,
    out: &mut Plan,
) -> Result<(), Refusal> {
    let unreadable = |detail: String| (VENDOR_RUSH_UNSUPPORTED, detail);
    let (config_rel, temp) = (shared.file.as_str(), shared.temp_prefix.as_str());
    if !configs.contains_key(config_rel) {
        let text = files
            .text(config_rel)
            .await
            .map_err(unreadable)?
            .ok_or_else(|| unreadable(format!("{config_rel} does not exist")))?;
        configs.insert(config_rel.to_string(), (text.clone(), text));
    }
    let (_, text) = configs.get_mut(config_rel).expect("just inserted");
    let live = jsonc::string_members(text, GLOBAL_OVERRIDES).ok_or_else(|| {
        unreadable(format!(
            "cannot read `{GLOBAL_OVERRIDES}` in {config_rel} as an object of strings"
        ))
    })?;
    override_conflict(
        config_rel,
        live.iter()
            .map(|(key, value)| (key.clone(), value.replace(temp, ROOT_PREFIX))),
        name,
        version,
    )?;
    let written = spec.replace(ROOT_PREFIX, temp);
    // pnpm 10.34.2+ / 11.5.3+ match a build decision against the id a
    // package installs under, which is now the vendored one (see
    // `super::build_approvals`). A decision that names the registry package
    // is not carried over here: say so.
    if let Some(doc) = crate::formats::package_json::parse(text) {
        let named = |key: &str| key == name || key.starts_with(&format!("{name}@"));
        let vendored_id = format!("{name}@{written}");
        for setting in BUILD_SETTINGS {
            let keys: Vec<&str> = match doc.get(setting) {
                Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
                Some(Value::Object(map)) => map.keys().map(String::as_str).collect(),
                _ => continue,
            };
            if keys.iter().any(|key| named(key)) && !keys.contains(&vendored_id.as_str()) {
                out.warnings.push(VendorWarning::new(
                    VENDOR_PNPM_BUILD_APPROVAL_LOST,
                    format!(
                        "{config_rel} decides {name}'s build scripts under `{setting}` by the \
                         registry package's name. pnpm 10.34.2+ and 11.5.3+ match that decision \
                         against the id a package installs under, which is now \
                         `{vendored_id}`: pnpm 10 no longer applies the decision and pnpm 11 \
                         and newer fail the install (ERR_PNPM_IGNORED_BUILDS). Add the same \
                         decision for that id to `{setting}`"
                    ),
                ));
            }
        }
    }
    if shared.keys.is_empty() {
        return Ok(());
    }
    // Rush merges a config into the one it `extends` property by property:
    // a `globalOverrides` table here replaces the inherited one whole.
    let inherits = crate::formats::package_json::parse(text)
        .is_some_and(|doc| doc.get("extends").is_some() && doc.get(GLOBAL_OVERRIDES).is_none());
    if inherits {
        return Err(unreadable(format!(
            "{config_rel} takes its `{GLOBAL_OVERRIDES}` from the file it `extends`, and a \
             table written here would replace the inherited one whole. Add a \
             `{GLOBAL_OVERRIDES}` table to {config_rel} holding the entries it inherits (an \
             empty one when there are none) and run `rush update`, then vendor again; \
             nothing was written"
        )));
    }
    let entries: Vec<(String, String)> = shared
        .keys
        .iter()
        .map(|key| (key.clone(), written.clone()))
        .collect();
    let edited = jsonc::upsert_strings(text, GLOBAL_OVERRIDES, &entries)
        .map_err(|why| unreadable(format!("cannot edit {config_rel}: {why}")))?;
    let Some((new_text, created)) = edited else {
        return Ok(());
    };
    for key in &shared.keys {
        let prior = live.iter().find(|(k, _)| k == key);
        if prior.is_some_and(|(_, value)| value == &written) {
            continue;
        }
        out.wiring.push(WiringRecord {
            file: config_rel.to_string(),
            kind: KIND_GLOBAL_OVERRIDE.to_string(),
            action: match prior {
                Some(_) => WiringAction::Rewritten,
                None => WiringAction::Added,
            },
            key: Some(key.clone()),
            original: None,
            new: Some(Value::String(written.clone())),
        });
    }
    out.created_overrides_table |= created;
    *text = new_text;
    Ok(())
}

// ───────────────────────────── vendor backend ─────────────────────────────

/// Vendor one npm package into a Rush repository (see the module doc).
/// Same contract as [`super::vendor_pnpm`].
#[allow(clippy::too_many_arguments)]
pub async fn vendor_rush_pnpm<'a>(
    purl: &str,
    _installed_dir: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    _sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    _force: bool,
    service: Option<&crate::vendor::VendorServiceConfig>,
) -> VendorOutcome {
    vendor_npm_family(
        &RushBackend,
        NpmVendorRequest {
            purl,
            project_root,
            record,
            vendored_at,
            dry_run,
            service,
        },
    )
    .await
}

struct RushBackend;

/// A sha512 SRI of the right shape for the pre-flight's dry edit, which
/// only has to prove the edit can be made.
const PREFLIGHT_INTEGRITY: &str = "sha512-preflight";

fn artifact_rel(coords: &NpmCoords) -> String {
    format!(
        "{}/{}",
        coords.uuid_dir_rel,
        tgz_rel_leaf(&coords.name, &coords.version)
    )
}

impl NpmLockBackend for RushBackend {
    type Plan = RushProject;

    fn flavor(&self) -> Option<&'static str> {
        Some(FLAVOR)
    }

    async fn preflight(
        &self,
        project_root: &Path,
        coords: &NpmCoords,
        _warnings: &mut Vec<VendorWarning>,
    ) -> Result<RushProject, Box<VendorOutcome>> {
        let refuse = |(code, detail): Refusal| Box::new(refused(code, detail));
        let project = read_project(project_root).await.map_err(refuse)?;
        // The whole edit, with a stand-in digest: every refusal fires here,
        // before anything is fetched, packed or written.
        plan(
            &project,
            &mut Files::new(project_root),
            &coords.name,
            &coords.version,
            &artifact_rel(coords),
            PREFLIGHT_INTEGRITY,
        )
        .await
        .map_err(refuse)?;
        Ok(project)
    }

    async fn wire(
        &self,
        project: RushProject,
        cx: &WireCx<'_>,
        staged: &mut NpmStagedPack,
        warnings: &mut Vec<VendorWarning>,
    ) -> Result<Option<NpmCommit>, String> {
        let plan = plan(
            &project,
            &mut Files::new(cx.project_root),
            &cx.coords.name,
            &cx.coords.version,
            &staged.rel_tgz,
            &staged.packed.integrity,
        )
        .await
        .map_err(|(_, detail)| detail)?;
        if plan.writes.is_empty() {
            return Ok(None);
        }
        commit(cx.project_root, &plan.writes).await?;
        warnings.extend(plan.warnings);
        Ok(Some(NpmCommit {
            wiring: plan.wiring,
            pnpm: Some(PnpmMeta {
                created_overrides_table: plan.created_overrides_table,
                ..PnpmMeta::default()
            }),
            ..NpmCommit::default()
        }))
    }

    fn manifest_warning(&self, name: &str, version: &str) -> VendorWarning {
        VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; the lockfile's dependency \
                 mirrors were preserved verbatim — if the patch changed dependency ranges, run \
                 `rush update` to re-resolve them"
            ),
        )
    }
}

/// Write the plan's files in order (project manifests and config first, the
/// locks last). A failed write puts every file already written back, so a
/// `package.json` or override is never left without the lock entry it
/// names.
async fn commit(project_root: &Path, writes: &[FileWrite]) -> Result<(), String> {
    for (at, write) in writes.iter().enumerate() {
        let path = project_root.join(&write.rel);
        if let Err(e) = atomic_write_bytes_preserving_mode(&path, &write.new).await {
            for done in writes[..at].iter().rev() {
                let _ = atomic_write_bytes_preserving_mode(
                    &project_root.join(&done.rel),
                    &done.original,
                )
                .await;
            }
            return Err(format!(
                "cannot write {}: {e} (the files already written were restored)",
                write.rel
            ));
        }
    }
    Ok(())
}

/// Which of `packages` [`vendor_rush_pnpm`] refuses before its first
/// service call; see [`crate::vendor::npm_flavor::preflight_packages`].
pub(crate) async fn preflight_packages(
    project_root: &Path,
    packages: &[(&str, &PatchRecord)],
) -> Vec<Result<(), &'static str>> {
    let project = read_project(project_root).await.map_err(|(code, _)| code);
    let mut verdicts = Vec::with_capacity(packages.len());
    for (purl, record) in packages {
        // The coordinate guard first, as every flavor runs it.
        let coords = match guard_coordinates(purl, record) {
            Ok(coords) => coords,
            Err(outcome) => {
                verdicts.push(Err(refusal_code(&outcome)));
                continue;
            }
        };
        verdicts.push(match &project {
            Err(code) => Err(*code),
            Ok(project) => plan(
                project,
                &mut Files::new(project_root),
                &coords.name,
                &coords.version,
                &artifact_rel(&coords),
                PREFLIGHT_INTEGRITY,
            )
            .await
            .map(drop)
            .map_err(|(code, _)| code),
        });
    }
    verdicts
}

// ──────────────────────────────── revert ─────────────────────────────────

/// Is this entry's artifact still what a Rush lock installs? `None` when no
/// Rush lock could be read.
pub(crate) async fn entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    let view = ProjectView::Disk(project_root);
    let mut any_read = false;
    for rel in rush_lock_rels(view).await {
        let Some(layout) = Layout::of(&rel) else {
            continue;
        };
        let Ok(text) = read_regular_to_string(&project_root.join(&rel)).await else {
            continue;
        };
        any_read = true;
        let rooted = root_relative_lock_text(&layout.lock_rel, text);
        if vendored_npm_uuids(&rooted).contains(&entry.uuid) {
            return Some(true);
        }
    }
    any_read.then_some(false)
}

/// Every file the Rush layout may wire, project-relative: each pnpm lock,
/// the `pnpm-config.json` files Rush reads for it, and the `package.json`
/// of every project `rush.json` lists. Empty outside a Rush repository;
/// sorted, and entries need not exist.
pub async fn wiring_files(project_root: &Path) -> Vec<String> {
    let view = ProjectView::Disk(project_root);
    if !is_rush(view).await {
        return Vec::new();
    }
    let mut files = BTreeSet::new();
    for rel in rush_lock_rels(view).await {
        if let Some(layout) = Layout::of(&rel) {
            files.extend(layout.config_candidates(PNPM_CONFIG));
        }
        files.insert(rel);
    }
    let rush = read_regular_to_string(&project_root.join(RUSH_JSON))
        .await
        .ok()
        .and_then(|text| crate::formats::package_json::parse(&text));
    let folders = rush
        .iter()
        .filter_map(|rush| rush.get("projects")?.as_array())
        .flatten()
        .filter_map(|project| project.get("projectFolder")?.as_str());
    for folder in folders {
        let folder = folder.replace('\\', "/");
        let manifest = format!("{}/{PACKAGE_JSON}", folder.trim_matches('/'));
        // `rush.json` is the repository's own, and still only a plain
        // folder inside it is read.
        if is_project_manifest(&manifest) {
            files.insert(manifest);
        }
    }
    files.into_iter().collect()
}

/// Whether `rel` is a Rush pnpm lock: the common one or a subspace's.
pub(crate) fn is_lock_rel(rel: &str) -> bool {
    Layout::of(rel).is_some()
}

/// Whether `rel` is a project manifest a wiring record may name: a
/// `package.json` in a plain folder of the repository.
pub(crate) fn is_project_manifest(rel: &str) -> bool {
    rel.strip_suffix(PACKAGE_JSON)
        .and_then(|dir| dir.strip_suffix('/'))
        .is_some_and(|dir| {
            crate::patch::path_safety::is_safe_multi_segment(dir)
                && !dir
                    .split('/')
                    .any(|p| matches!(p, "node_modules" | ".socket" | ".git" | "." | ".."))
        })
}

/// Whether `rel` is a `pnpm-config.json` Rush reads.
pub(crate) fn is_pnpm_config(rel: &str) -> bool {
    rel == format!("{RUSH_CONFIG_DIR}/{PNPM_CONFIG}")
        || rel
            .strip_suffix(PNPM_CONFIG)
            .and_then(|dir| dir.strip_suffix('/'))
            .and_then(|dir| dir.strip_prefix(RUSH_SUBSPACES_DIR)?.strip_prefix('/'))
            .is_some_and(|name| {
                !name.contains('/') && crate::patch::path_safety::is_safe_multi_segment(name)
            })
}

/// Undo one Rush-vendored package: restore the lock fragments, take the
/// overrides back out of `pnpm-config.json`, put each project's
/// `package.json` spec back, and remove the artifact. Per-record ownership
/// is re-checked against the live file (drift is a warning, left alone).
pub async fn revert_rush_pnpm_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    // SECURITY: `entry.uuid` and every record's `file` come from the
    // committed, tamper-able state.json.
    let uuid_dir_rel = match guard_revert_uuid_dir(&entry.uuid) {
        Ok(dir) => dir,
        Err(outcome) => return outcome,
    };
    if !opts.keep_artifact && entry.wiring.is_empty() {
        if let Some(blocked) = unwired_guard(entry, project_root, &uuid_dir_rel).await {
            return blocked;
        }
    }

    let mut outcome = RevertOutcome::ok();
    let mut lock_records: BTreeMap<String, Vec<&WiringRecord>> = BTreeMap::new();
    let mut config_records: BTreeMap<String, Vec<&WiringRecord>> = BTreeMap::new();
    let mut manifest_records: BTreeMap<String, Vec<&WiringRecord>> = BTreeMap::new();
    for rec in &entry.wiring {
        let group = match rec.kind.as_str() {
            KIND_GLOBAL_OVERRIDE if is_pnpm_config(&rec.file) => &mut config_records,
            KIND_PROJECT_DEP if is_project_manifest(&rec.file) => &mut manifest_records,
            KIND_GLOBAL_OVERRIDE | KIND_PROJECT_DEP => {
                outcome.warnings.push(drifted(format!(
                    "ignoring wiring record for non-allowlisted file `{}`",
                    crate::vendor::state::terminal_safe(&rec.file)
                )));
                continue;
            }
            _ if Layout::of(&rec.file).is_some() => &mut lock_records,
            _ => {
                outcome.warnings.push(drifted(format!(
                    "ignoring wiring record for non-allowlisted file `{}`",
                    crate::vendor::state::terminal_safe(&rec.file)
                )));
                continue;
            }
        };
        group.entry(rec.file.clone()).or_default().push(rec);
    }

    // Every surface is computed before the first write.
    let mut writes: Vec<(String, Vec<u8>)> = Vec::new();
    let refs = PnpmDialect::V9.dep_refs();
    for (lock_rel, records) in &lock_records {
        let layout = Layout::of(lock_rel).expect("grouped by layout");
        let (text, eol) = match read_pnpm_text(project_root, lock_rel).await {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{lock_rel} is missing; lock fragments cannot be restored"),
                ));
                continue;
            }
            Err(e) if is_mixed_line_endings(&e) => {
                return RevertOutcome::failed(format!("{lock_rel}: {e}; nothing was reverted"))
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {lock_rel}: {e}")),
        };
        let located = split_v9_lock(&text)
            .map_err(|why| why.to_string())
            .and_then(|(prefix, project)| {
                let mut lines = split_lines(project);
                layout.to_root_relative(&mut lines)?;
                Ok((prefix.to_string(), lines))
            });
        let (prefix, mut lines) = match located {
            Ok(found) => found,
            Err(why) => {
                return RevertOutcome::failed(format!(
                    "{why}, so the vendored wiring of {} cannot be located; nothing was \
                     reverted — restore the vendored {lock_rel} (or run `rush update`) and \
                     re-run the revert",
                    entry.base_purl
                ))
            }
        };
        let mut dirty = false;
        let mut blocks: Option<RefBlocks> = None;
        for rec in records.iter().rev() {
            if rec.kind == refs.kind {
                let cached = blocks.get_or_insert_with(|| RefBlocks::of(&lines, refs.section));
                refs.restore(
                    &mut lines,
                    cached,
                    rec,
                    &entry.uuid,
                    &mut dirty,
                    &mut outcome.warnings,
                );
                continue;
            }
            blocks = None;
            revert_lock_record(
                &mut lines,
                rec,
                &entry.uuid,
                &mut dirty,
                &mut outcome.warnings,
            );
        }
        let target = crate::vendor::npm_common::parse_npm_purl(&entry.base_purl);
        for rec in records.iter() {
            let section = match rec.kind.as_str() {
                KIND_LOCK_PACKAGE => "packages",
                KIND_LOCK_SNAPSHOT => "snapshots",
                _ => continue,
            };
            let Some(key) = rec.key.as_deref() else {
                continue;
            };
            // A later `rush update` may have resolved the registry entry
            // again, for a dependent added since: the restore then put a
            // second block under the same key, which pnpm cannot parse.
            // The restored one is the entry; the other goes.
            dirty |= drop_duplicate_block(&mut lines, section, key, rec.original.as_ref());
            // A restored registry entry goes back where pnpm keeps it.
            resort_block(&mut lines, section, key, &layout);
        }
        // References pnpm itself wrote to the vendored entry since (a new
        // peer variant of a dependent the override already covers) follow
        // the entry back to the registry release.
        if let Some((name, version)) = &target {
            let registry_key = format!("{name}@{version}");
            let restored = section_blocks(&lines, "packages")
                .iter()
                .any(|(key, _, _)| key == &registry_key);
            if restored {
                let ours = |value: &str| {
                    parse_vendor_path(unquote_value(value))
                        .is_some_and(|p| p.eco == "npm" && p.uuid == entry.uuid)
                };
                dirty |= restore_dep_map_refs(&mut lines, "snapshots", name, version, false, &ours);
            }
        }
        // A reference into the artifact that survives the restore names an
        // entry the lock no longer holds, which pnpm rejects. The
        // `overrides:` declaration is not one.
        if !outcome.drift_skipped() && !outcome.lock_entry_removed() {
            let uuid = entry.uuid.to_ascii_lowercase();
            let declared = section_bounds(&lines, "overrides").unwrap_or((0, 0));
            let left = lines.iter().enumerate().find(|(i, line)| {
                !(declared.0..declared.1).contains(i) && line.to_ascii_lowercase().contains(&uuid)
            });
            if let Some((_, line)) = left {
                let detail = format!(
                    "refusing to revert {uuid_dir_rel}: {lock_rel} would still resolve through \
                     it once the recorded wiring is restored (`{}`), and pnpm rejects a lock \
                     whose reference has no entry; nothing was reverted — remove that \
                     reference and run `rush update`, then re-run `vendor --revert`",
                    line.trim()
                );
                outcome.success = false;
                outcome.error = Some(detail.clone());
                outcome
                    .warnings
                    .push(VendorWarning::new(revert::STILL_WIRED_CODE, detail));
                return outcome;
            }
        }
        if dirty {
            let body = layout.to_temp_relative(&lines).join("\n");
            writes.push((
                lock_rel.clone(),
                eol.restore(&format!("{prefix}{body}"))
                    .into_owned()
                    .into_bytes(),
            ));
        }
    }

    // A lock the vendoring never wrote (a subspace added since, reading the
    // same config) can resolve through the artifact too, and no record
    // restores it.
    if !opts.keep_artifact {
        let uuid = entry.uuid.to_ascii_lowercase();
        for lock_rel in rush_lock_rels(ProjectView::Disk(project_root)).await {
            if lock_records.contains_key(&lock_rel) {
                continue;
            }
            let Ok((text, _)) = read_pnpm_text(project_root, &lock_rel).await else {
                continue;
            };
            let lines = split_lines(split_v9_lock(&text).map_or(text.as_str(), |(_, p)| p));
            let declared = section_bounds(&lines, "overrides").unwrap_or((0, 0));
            let left = lines.iter().enumerate().find(|(i, line)| {
                !(declared.0..declared.1).contains(i) && line.to_ascii_lowercase().contains(&uuid)
            });
            if let Some((_, line)) = left {
                let detail = format!(
                    "refusing to revert {uuid_dir_rel}: {lock_rel}, which the vendoring did not \
                     write, resolves through it too (`{}`), and deleting the tarball would \
                     break that install; nothing was reverted — remove what makes it use the \
                     tarball (the entries for it under `{GLOBAL_OVERRIDES}`, or a `file:` spec \
                     in one of that subspace's projects) and run `rush update`, then re-run \
                     `vendor --revert`",
                    line.trim()
                );
                outcome.success = false;
                outcome.error = Some(detail.clone());
                outcome
                    .warnings
                    .push(VendorWarning::new(revert::STILL_WIRED_CODE, detail));
                return outcome;
            }
        }
    }

    let drop_table = entry
        .pnpm
        .as_ref()
        .is_some_and(|meta| meta.created_overrides_table);
    for (config_rel, records) in &config_records {
        let text = match read_regular_to_string(&project_root.join(config_rel)).await {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return RevertOutcome::failed(format!("cannot read {config_rel}: {e}")),
        };
        let entries: Vec<(String, String)> = records
            .iter()
            .filter_map(|rec| Some((rec.key.clone()?, rec.new.as_ref()?.as_str()?.to_string())))
            .collect();
        let (edited, verdicts) =
            match jsonc::remove_strings(&text, GLOBAL_OVERRIDES, &entries, drop_table) {
                Ok(done) => done,
                Err(why) => {
                    return RevertOutcome::failed(format!(
                        "cannot edit {config_rel}: {why}; nothing was reverted"
                    ))
                }
            };
        for ((key, _), verdict) in entries.iter().zip(verdicts) {
            if verdict == jsonc::Removal::Changed {
                outcome.warnings.push(drifted(format!(
                    "{config_rel} `{GLOBAL_OVERRIDES}` entry `{}` was changed since vendoring; \
                     left alone",
                    crate::vendor::state::terminal_safe(key)
                )));
            }
        }
        if edited != text {
            writes.push((config_rel.clone(), edited.into_bytes()));
        }
    }

    for (manifest_rel, records) in &manifest_records {
        let path = project_root.join(manifest_rel);
        if crate::utils::containment::linked_level(project_root, &path).is_some() {
            outcome.warnings.push(drifted(format!(
                "{manifest_rel} is reached through a symlink; left alone"
            )));
            continue;
        }
        let mut text = match read_regular_to_string(&path).await {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return RevertOutcome::failed(format!("cannot read {manifest_rel}: {e}")),
        };
        let before = text.clone();
        for rec in records.iter().rev() {
            let Some((field, dep)) = rec.key.as_deref().and_then(|k| k.split_once('|')) else {
                outcome.warnings.push(drifted(format!(
                    "wiring record in {manifest_rel} has no usable key; left alone"
                )));
                continue;
            };
            if !DEP_FIELDS.contains(&field) {
                continue;
            }
            let live = dependency_token(&text, field, dep)
                .ok()
                .and_then(|token| serde_json::from_str::<String>(&token).ok());
            let (new, original) = (
                rec.new.as_ref().and_then(Value::as_str),
                rec.original.as_ref().and_then(Value::as_str),
            );
            match (live.as_deref(), original) {
                // The dependency is gone, or already back.
                (None, _) => {}
                (Some(live), Some(original)) if live == original => {}
                (Some(live), Some(original)) if Some(live) == new => {
                    let raw = Value::String(original.to_string()).to_string();
                    match replace_dependency_token(&text, field, dep, &raw) {
                        Ok(edited) => text = edited,
                        Err(_) => outcome.warnings.push(drifted(format!(
                            "{manifest_rel} `{field}.{dep}` cannot be edited in place; left alone"
                        ))),
                    }
                }
                (Some(live), _) => outcome.warnings.push(match original {
                    Some(_) => revert::re_resolved(
                        format_args!("{manifest_rel} `{field}.{dep}`"),
                        Some(live),
                    ),
                    None => drifted(format!(
                        "{manifest_rel} `{field}.{dep}` has no recorded pre-vendor spec; left \
                         as-is"
                    )),
                }),
            }
        }
        if text != before {
            writes.push((manifest_rel.clone(), text.into_bytes()));
        }
    }

    if opts.dry_run {
        return RevertOutcome::ok();
    }
    // Reverse of the vendoring order: locks, config, then manifests.
    for (rel, bytes) in &writes {
        if let Err(e) = atomic_write_bytes_preserving_mode(&project_root.join(rel), bytes).await {
            return RevertOutcome::failed(format!("cannot write {rel}: {e}"));
        }
    }
    let touched: Vec<&str> = lock_records
        .keys()
        .chain(config_records.keys())
        .chain(manifest_records.keys())
        .map(String::as_str)
        .collect();
    let policy = KeepPolicy::NpmFamily {
        locks: &touched,
        wired: &[],
        uuid: &entry.uuid,
    };
    revert::finish(outcome, project_root, &uuid_dir_rel, opts, policy).await
}

/// The refusal for an entry with no wiring records (a `repair`
/// reconstruction) whose artifact a Rush lock may still install: deleting
/// it would fail every later install.
async fn unwired_guard(
    entry: &VendorEntry,
    project_root: &Path,
    uuid_dir_rel: &str,
) -> Option<RevertOutcome> {
    let clause = match entry_in_use(entry, project_root).await {
        Some(false) => return None,
        Some(true) => "a Rush lockfile still resolves through it",
        None => "no Rush lockfile could be read to prove it is no longer referenced",
    };
    let detail = format!(
        "refusing to remove {uuid_dir_rel}: the ledger entry records no pre-vendor wiring to \
         replay and {clause} — deleting the artifact would make every subsequent install fail; \
         restore the pre-vendor lockfile, {PNPM_CONFIG} and package.json specs (or remove the \
         override and run `rush update`) before re-running `vendor --revert`"
    );
    Some(RevertOutcome {
        success: false,
        warnings: vec![VendorWarning::new(
            "vendor_wiring_unknown_revert_blocked",
            detail.clone(),
        )],
        error: Some(detail),
        kept_artifact: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::vendor::npm_flavor::{
        detect_npm_lock_flavor, detect_vendorable_npm_flavor, revert_npm_any, NpmLockFlavor,
    };
    use crate::vendor::test_support::{expect_done, tree_snapshot, vendor_npm_any};
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// `(name, version, patch uuid)`: the releases the fixtures vendor.
    type Target = (&'static str, &'static str, &'static str);
    const MINIMIST_008: Target = ("minimist", "0.0.8", "8cccd65b-5a7c-4ec5-8068-ebc66c727d8c");
    const MINIMIST_0010: Target = ("minimist", "0.0.10", "d8533454-f3bf-44d2-a187-7b5a9ec251ce");
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    fn fixture(case: &str, side: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vendor/rush")
            .join(case)
            .join(side)
    }

    /// A lock or config with the vendored tarballs' digests masked: they
    /// are the one thing that depends on how the tarball was packed.
    fn masked(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes)
            .split('\n')
            .map(|line| {
                match (
                    line.find("integrity: sha512-"),
                    line.contains("tarball: file:"),
                ) {
                    (Some(at), true) => {
                        let end = line[at..].find(',').map_or(line.len(), |n| at + n);
                        format!("{}integrity: <sri>{}", &line[..at], &line[end..])
                    }
                    _ => line.to_string(),
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A Rush repository holding one fixture case's `before` files.
    struct Repo {
        tmp: tempfile::TempDir,
    }

    impl Repo {
        fn new(case: &str) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            for (rel, bytes) in tree_snapshot(&fixture(case, "before")) {
                let path = tmp.path().join(&rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Self { tmp }
        }

        fn root(&self) -> &Path {
            self.tmp.path()
        }

        fn write(&self, rel: &str, text: &str) {
            let path = self.root().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn read(&self, rel: &str) -> String {
            std::fs::read_to_string(self.root().join(rel)).unwrap()
        }

        /// Vendor `target` through the npm flavor router, as the CLI does.
        async fn vendor(&self, (name, version, uuid): Target) -> VendorOutcome {
            let installed = self.root().join(format!(
                "common/temp/node_modules/.pnpm/{name}@{version}/node_modules/{name}"
            ));
            std::fs::create_dir_all(&installed).unwrap();
            std::fs::write(
                installed.join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
            std::fs::write(installed.join("index.js"), ORIG_INDEX).unwrap();
            let blobs = self.root().join(".socket/blobs");
            std::fs::create_dir_all(&blobs).unwrap();
            let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
            std::fs::write(blobs.join(&after_hash), PATCHED_INDEX).unwrap();
            let record = PatchRecord {
                uuid: uuid.to_string(),
                exported_at: "2026-11-18T00:00:00Z".to_string(),
                files: HashMap::from([(
                    "package/index.js".to_string(),
                    PatchFileInfo {
                        before_hash: compute_git_sha256_from_bytes(ORIG_INDEX),
                        after_hash,
                    },
                )]),
                vulnerabilities: HashMap::new(),
                description: "test patch".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            };
            vendor_npm_any(
                &format!("pkg:npm/{name}@{version}"),
                installed.as_path(),
                self.root(),
                &record,
                &PatchSources::blobs_only(&blobs),
                "2026-11-18T00:00:00Z",
                false,
                false,
                None,
            )
            .await
        }

        /// Every wiring file of the fixture side, against the repository's.
        fn assert_is(&self, case: &str, side: &str) {
            for (rel, want) in tree_snapshot(&fixture(case, side)) {
                let got = std::fs::read(self.root().join(&rel))
                    .unwrap_or_else(|e| panic!("{case}/{side}: {rel}: {e}"));
                assert_eq!(masked(&got), masked(&want), "{case}/{side}: {rel}");
            }
        }
    }

    /// Vendor `targets` into the case's `before`, expect its `after`, then
    /// revert and expect `before` again, byte for byte.
    async fn round_trip(case: &str, targets: &[Target]) -> Vec<VendorWarning> {
        let repo = Repo::new(case);
        let (mut entries, mut warnings) = (Vec::new(), Vec::new());
        for target in targets {
            let (result, entry, mut warned) = expect_done(repo.vendor(*target).await);
            assert!(result.success, "{case}: {:?}", result.error);
            let entry = entry.expect("a wired run records an entry");
            assert_eq!(entry.flavor.as_deref(), Some(FLAVOR));
            entries.push(entry);
            warnings.append(&mut warned);
        }
        repo.assert_is(case, "after");
        // In sync: a second run changes nothing and records nothing.
        let wired = tree_snapshot(repo.root());
        for target in targets {
            let (result, entry, _) = expect_done(repo.vendor(*target).await);
            assert!(
                result.success && entry.is_none(),
                "{case}: re-run of {target:?}"
            );
        }
        assert_eq!(
            tree_snapshot(repo.root()),
            wired,
            "{case}: the re-run wrote"
        );
        for entry in entries.iter().rev() {
            let outcome = revert_npm_any(entry, repo.root(), false).await;
            assert!(outcome.success, "{case}: {:?}", outcome.error);
            assert!(
                outcome.warnings.is_empty(),
                "{case}: {:?}",
                outcome.warnings
            );
            assert!(
                !repo
                    .root()
                    .join(".socket/vendor/npm")
                    .join(&entry.uuid)
                    .exists(),
                "{case}: the artifact outlived the revert"
            );
        }
        let before = tree_snapshot(&fixture(case, "before"));
        for (rel, want) in &before {
            let got = std::fs::read(repo.root().join(rel)).unwrap();
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(want),
                "{case}: {rel} after the revert"
            );
        }
        warnings
    }

    fn codes(warnings: &[VendorWarning]) -> Vec<&'static str> {
        warnings.iter().map(|w| w.code).collect()
    }

    #[tokio::test]
    async fn direct_and_transitive_dependents_match_rush() {
        let warnings = round_trip("pnpm10", &[MINIMIST_008]).await;
        let edited = warnings
            .iter()
            .find(|w| w.code == VENDOR_RUSH_PACKAGE_JSON_EDITED)
            .expect("the package.json edit is announced");
        assert!(
            edited.detail.contains("libs/util/package.json"),
            "{}",
            edited.detail
        );
        assert!(
            edited.detail.contains("top/package.json"),
            "{}",
            edited.detail
        );
        assert!(!edited.detail.contains("published"), "{}", edited.detail);
        assert!(!codes(&warnings).contains(&VENDOR_RUSH_REPO_STATE_STALE));
    }

    #[tokio::test]
    async fn lock_overrides_keep_the_config_order_on_pnpm_10() {
        round_trip("pnpm10-user-overrides", &[MINIMIST_008]).await;
    }

    #[tokio::test]
    async fn lock_overrides_are_key_sorted_on_pnpm_11() {
        round_trip("pnpm11-user-overrides", &[MINIMIST_008]).await;
    }

    /// Two versions of one package, and a `~0.0.5` dependent locked at
    /// 0.0.10: every edge stays on the version the lock resolves it to.
    #[tokio::test]
    async fn sibling_versions_keep_their_own_dependents() {
        round_trip("sibling-versions", &[MINIMIST_0010, MINIMIST_008]).await;
    }

    #[tokio::test]
    async fn a_rekeyed_entry_moves_behind_a_later_sibling() {
        round_trip("sibling-sorts-after", &[MINIMIST_008]).await;
    }

    #[tokio::test]
    async fn subspace_locks_are_wired_three_levels_up() {
        round_trip("subspaces", &[MINIMIST_008]).await;
    }

    /// A later `rush update` resolved a new direct dependent and a new
    /// parent from the registry: the re-run moves both edges and drops the
    /// registry entry nothing references any more.
    #[tokio::test]
    async fn a_rerun_takes_in_dependents_added_since() {
        let repo = Repo::new("new-dependents");
        let (result, entry, warnings) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success, "{:?}", result.error);
        repo.assert_is("new-dependents", "after");
        let entry = entry.unwrap();
        let recorded: Vec<(&str, &str)> = entry
            .wiring
            .iter()
            .map(|r| (r.file.as_str(), r.kind.as_str()))
            .collect();
        assert!(
            recorded.contains(&("tools/deep/cli/package.json", KIND_PROJECT_DEP)),
            "{recorded:?}"
        );
        assert!(
            entry.wiring.iter().any(|r| r.kind == KIND_GLOBAL_OVERRIDE
                && r.key.as_deref() == Some("mkdirp@0.5.0>minimist@0.0.8")),
            "{recorded:?}"
        );
        let edited = warnings
            .iter()
            .find(|w| w.code == VENDOR_RUSH_PACKAGE_JSON_EDITED)
            .unwrap();
        assert!(edited.detail.contains("tools/deep/cli/package.json"));
        assert!(!edited.detail.contains("libs/util"), "{}", edited.detail);
    }

    /// Two subspaces that read one `pnpm-config.json`: Rush and pnpm expect
    /// every override of that config in both locks, so the lock with no
    /// dependent to redirect gets the entry too.
    #[tokio::test]
    async fn a_config_two_subspaces_share_reaches_both_locks() {
        round_trip("subspaces-shared-config", &[MINIMIST_008]).await;
    }

    /// The wired files of the repository, replaced by another fixture
    /// side's: what a later `rush update` left behind.
    fn overlay(repo: &Repo, case: &str, side: &str) {
        for (rel, bytes) in tree_snapshot(&fixture(case, side)) {
            std::fs::write(repo.root().join(&rel), bytes).unwrap();
        }
    }

    /// `rush update` brought the registry entry back beside the vendored
    /// one (new dependents), and the revert runs before any re-vendor: the
    /// restore must leave ONE registry entry, not two under the same key.
    #[tokio::test]
    async fn revert_with_the_registry_entry_back_leaves_one_entry() {
        let repo = Repo::new("pnpm10");
        let (_, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        let entry = entry.unwrap();
        overlay(&repo, "new-dependents", "before");
        let outcome = revert_npm_any(&entry, repo.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let lock = repo.read(RUSH_COMMON_LOCK_REL);
        let (packages, snapshots) = lock.split_once("\nsnapshots:\n").unwrap();
        assert_eq!(packages.matches("\n  minimist@0.0.8:").count(), 1, "{lock}");
        assert_eq!(
            snapshots.matches("\n  minimist@0.0.8:").count(),
            1,
            "{lock}"
        );
        for rel in [
            RUSH_COMMON_LOCK_REL,
            "common/config/rush/pnpm-config.json",
            "libs/util/package.json",
            "top/package.json",
        ] {
            assert!(!repo.read(rel).contains(".socket/vendor"), "{rel}");
        }
        // The dependents added since keep their registry edges.
        assert!(
            lock.contains("  mkdirp@0.5.0:\n    dependencies:\n      minimist: 0.0.8\n"),
            "{lock}"
        );
    }

    /// pnpm wrote a reference of its own to the vendored entry after
    /// vendoring (another peer variant of a dependent the override
    /// covers). No record names it; it follows the entry back.
    #[tokio::test]
    async fn revert_restores_references_added_since() {
        let repo = Repo::new("pnpm10");
        let (_, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        let entry = entry.unwrap();
        let lock = repo.read(RUSH_COMMON_LOCK_REL);
        let vendored_ref = lock
            .lines()
            .find(|l| l.starts_with("      minimist: file:"))
            .expect("mkdirp's ref is vendored")
            .to_string();
        let variant = format!("\n  mkdirp@0.5.1(peer@1.0.0):\n    dependencies:\n{vendored_ref}\n");
        repo.write(
            RUSH_COMMON_LOCK_REL,
            &format!("{}\n{variant}", lock.trim_end_matches('\n')),
        );
        let outcome = revert_npm_any(&entry, repo.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let lock = repo.read(RUSH_COMMON_LOCK_REL);
        assert!(!lock.contains(".socket/vendor"), "{lock}");
        assert!(
            lock.contains("  mkdirp@0.5.1(peer@1.0.0):\n    dependencies:\n      minimist: 0.0.8"),
            "{lock}"
        );
    }

    /// A build decision that names the registry package stops matching the
    /// vendored id: it is not carried over, so it is named.
    #[tokio::test]
    async fn a_build_decision_on_the_package_is_named() {
        let repo = Repo::new("pnpm10");
        let config_rel = format!("{RUSH_CONFIG_DIR}/{PNPM_CONFIG}");
        let config = repo.read(&config_rel).replace(
            "\"globalOverrides\": {",
            "\"globalOnlyBuiltDependencies\": [\"minimist\"],\n  \"globalOverrides\": {",
        );
        repo.write(&config_rel, &config);
        let (result, _, warnings) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success, "{:?}", result.error);
        let lost = warnings
            .iter()
            .find(|w| w.code == VENDOR_PNPM_BUILD_APPROVAL_LOST)
            .expect("the lost build decision is announced");
        assert!(
            lost.detail.contains("globalOnlyBuiltDependencies"),
            "{}",
            lost.detail
        );
        assert!(
            lost.detail.contains(&format!(
                "minimist@file:../../.socket/vendor/npm/{}/minimist-0.0.8.tgz",
                MINIMIST_008.2
            )),
            "{}",
            lost.detail
        );
    }

    // ── routing ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_vendor_router_takes_a_rush_repository() {
        let repo = Repo::new("pnpm10");
        // The lock probe still finds no root lock to route.
        let (code, _) = detect_npm_lock_flavor(repo.root()).await.unwrap_err();
        assert_eq!(code, VENDOR_RUSH_UNSUPPORTED);
        let (flavor, warnings) = detect_vendorable_npm_flavor(repo.root()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::RushPnpm);
        assert!(warnings.is_empty());
    }

    #[tokio::test]
    async fn a_rush_repository_without_a_pnpm_lock_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("rush.json"), r#"{"rushVersion":"5.0.0"}"#).unwrap();
        let (code, detail) = detect_vendorable_npm_flavor(tmp.path()).await.unwrap_err();
        assert_eq!(code, VENDOR_RUSH_UNSUPPORTED);
        assert!(detail.contains("rush update"), "{detail}");
        assert!(detail.contains(RUSH_COMMON_LOCK_REL), "{detail}");
    }

    // ── refusals: nothing is written ───────────────────────────────────

    async fn refused(repo: &Repo, target: Target) -> (&'static str, String) {
        let before = tree_snapshot(repo.root());
        let outcome = repo.vendor(target).await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected a refusal");
        };
        // The fixture's own installed copy and blob aside, nothing changed.
        for (rel, bytes) in before {
            assert_eq!(
                std::fs::read(repo.root().join(&rel)).unwrap(),
                bytes,
                "{rel}"
            );
        }
        assert!(!repo.root().join(".socket/vendor").exists());
        (code, detail)
    }

    #[tokio::test]
    async fn a_repository_that_installs_with_npm_is_refused() {
        let repo = Repo::new("pnpm10");
        let rush = repo.read(RUSH_JSON).replace("pnpmVersion", "npmVersion");
        repo.write(RUSH_JSON, &rush);
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, VENDOR_RUSH_UNSUPPORTED);
        assert!(detail.contains("npm or yarn"), "{detail}");
    }

    #[tokio::test]
    async fn a_pre_v9_lock_is_refused() {
        let repo = Repo::new("pnpm10");
        let lock = repo
            .read(RUSH_COMMON_LOCK_REL)
            .replace("lockfileVersion: '9.0'", "lockfileVersion: '6.0'");
        repo.write(RUSH_COMMON_LOCK_REL, &lock);
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, "vendor_lockfile_version_unsupported");
        assert!(detail.contains(RUSH_COMMON_LOCK_REL), "{detail}");
    }

    #[tokio::test]
    async fn a_package_no_lock_installs_is_refused() {
        let repo = Repo::new("pnpm10");
        let (code, _) = refused(&repo, ("minimist", "1.2.8", MINIMIST_008.2)).await;
        assert_eq!(code, "vendor_lock_entry_not_found");
    }

    /// A dependent that a hosted patch pins (#2263): pnpm 12.23 refuses a
    /// lock in which it depends on a local file, so its dependency is not
    /// vendored under it. The refusal names Rush's lock.
    #[tokio::test]
    async fn a_dependency_of_a_hosted_package_is_refused() {
        const MKDIRP: &str = "  mkdirp@0.5.1:\n    resolution: {integrity: sha512-SknJC52obPfGQPnjIkXbmA6+5H15E+fR+E4iR2oQ3zzCLbd7/ONua69R/Gw7AgkTLsRG+r5fzksYwWe1AgTyWA==}\n";
        let repo = Repo::new("pnpm10");
        let lock = repo.read(RUSH_COMMON_LOCK_REL);
        assert!(lock.contains(MKDIRP), "{lock}");
        let hosted = "  mkdirp@0.5.1:\n    resolution: {integrity: sha512-PATCHED==, tarball: https://patch.socket.dev/patch/npm/mkdirp/0.5.1/9ee29ee2-9ee2-49ee-829e-e29ee29ee29e/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/mkdirp-0.5.1.tgz}\n";
        repo.write(RUSH_COMMON_LOCK_REL, &lock.replace(MKDIRP, hosted));
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, "vendor_lock_entry_unsupported");
        assert!(
            detail.contains(&format!(
                "{RUSH_COMMON_LOCK_REL} installs mkdirp@0.5.1 from a hosted patch"
            )) && detail.contains("depends on minimist@0.0.8")
                && detail.contains("ERR_PNPM_LOCAL_SUBDEP_NOT_ALLOWED"),
            "{detail}"
        );
    }

    /// The lock and a project's `package.json` disagree: `rush update` has
    /// not run since the manifest changed.
    #[tokio::test]
    async fn a_project_manifest_the_lock_does_not_match_is_refused() {
        let repo = Repo::new("pnpm10");
        let manifest = repo
            .read("libs/util/package.json")
            .replace("0.0.8", "^0.0.8");
        repo.write("libs/util/package.json", &manifest);
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, VENDOR_RUSH_PROJECT_MANIFEST);
        assert!(detail.contains("libs/util/package.json"), "{detail}");
        assert!(detail.contains("rush update"), "{detail}");
    }

    /// The lock quotes a spec YAML would misread (`'*'`); the manifest
    /// spells the same spec bare, and the two still agree.
    #[tokio::test]
    async fn a_spec_the_lock_quotes_matches_the_manifest() {
        let repo = Repo::new("pnpm10");
        let manifest = repo
            .read("libs/util/package.json")
            .replace("\"0.0.8\"", "\"*\"");
        repo.write("libs/util/package.json", &manifest);
        let importer =
            "  ../../libs/util:\n    dependencies:\n      minimist:\n        specifier: ";
        let lock = repo.read(RUSH_COMMON_LOCK_REL);
        assert!(lock.contains(&format!("{importer}0.0.8")));
        let lock = lock.replace(&format!("{importer}0.0.8"), &format!("{importer}'*'"));
        repo.write(RUSH_COMMON_LOCK_REL, &lock);

        let (result, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success, "{:?}", result.error);
        assert!(repo
            .read("libs/util/package.json")
            .contains("file:../../.socket/vendor/"));
        let outcome = revert_npm_any(&entry.unwrap(), repo.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(repo.read("libs/util/package.json"), manifest);
        assert_eq!(repo.read(RUSH_COMMON_LOCK_REL), lock);
    }

    /// pnpm installs a project's own peer dependency for it and locks it
    /// under `dependencies`, with or without a `devDependencies` spec
    /// beside it: `rush update` is not what is missing.
    #[tokio::test]
    async fn a_projects_own_peer_dependency_is_refused_by_name() {
        let own = "\"dependencies\": {\n    \"minimist\": \"0.0.8\"\n  }";
        for manifest in [
            "\"peerDependencies\": {\n    \"minimist\": \"0.0.8\"\n  }".to_string(),
            "\"peerDependencies\": {\n    \"minimist\": \"0.0.8\"\n  },\n  \"devDependencies\": {\n    \"minimist\": \"0.0.8\"\n  }".to_string(),
        ] {
            let repo = Repo::new("pnpm10");
            let before = repo.read("libs/util/package.json");
            assert!(before.contains(own), "{before}");
            repo.write("libs/util/package.json", &before.replace(own, &manifest));
            let (code, detail) = refused(&repo, MINIMIST_008).await;
            assert_eq!(code, VENDOR_RUSH_PROJECT_MANIFEST);
            assert!(detail.contains("peerDependencies"), "{detail}");
            assert!(detail.contains("--mode hosted"), "{detail}");
            assert!(!detail.contains("  "), "{detail}");
        }
    }

    /// Rush replaces an inherited `globalOverrides` table with the one the
    /// extending config declares: writing a first table there would drop
    /// every inherited override.
    #[tokio::test]
    async fn a_config_that_inherits_its_overrides_is_refused() {
        let repo = Repo::new("pnpm10");
        let config_rel = format!("{RUSH_CONFIG_DIR}/{PNPM_CONFIG}");
        repo.write(
            &config_rel,
            "{\n  \"extends\": \"../shared/pnpm-config.json\",\n  \"useWorkspaces\": true\n}\n",
        );
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, VENDOR_RUSH_UNSUPPORTED);
        assert!(detail.contains("extends"), "{detail}");

        // Its own table is the one Rush uses: the overrides go there.
        repo.write(
            &config_rel,
            "{\n  \"extends\": \"../shared/pnpm-config.json\",\n  \"useWorkspaces\": true,\n  \"globalOverrides\": {}\n}\n",
        );
        let (result, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success && entry.is_some(), "{:?}", result.error);
        assert!(repo
            .read(&config_rel)
            .contains("mkdirp@0.5.1>minimist@0.0.8"));
    }

    /// Two subspaces read one config, and the same dependent resolves the
    /// package to another release in the second: the override the first
    /// needs would move the second's the next time pnpm resolves it.
    #[tokio::test]
    async fn a_shared_override_that_would_move_another_lock_is_refused() {
        let repo = Repo::new("subspaces-shared-config");
        let other = format!("{RUSH_SUBSPACES_DIR}/team-b/{PNPM_LOCK}");
        let lock = repo.read(&other);
        repo.write(
            &other,
            &format!("{lock}\n  mkdirp@0.5.1:\n    dependencies:\n      minimist: 0.0.10\n"),
        );
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, VENDOR_RUSH_UNSUPPORTED);
        assert!(detail.contains(&other), "{detail}");
        assert!(detail.contains("mkdirp@0.5.1>minimist@0.0.8"), "{detail}");
        assert!(detail.contains("its own pnpm-config.json"), "{detail}");
    }

    /// A lock Rush installs from another depth reads the same config but
    /// cannot spell its path, and does not install the package: it is a
    /// leftover, and stays as it is.
    #[tokio::test]
    async fn a_leftover_lock_at_another_depth_is_left_alone() {
        let repo = Repo::new("pnpm10");
        let leftover = format!("{RUSH_SUBSPACES_DIR}/old/{PNPM_LOCK}");
        let text = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n";
        repo.write(&leftover, text);
        let (result, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(repo.read(&leftover), text);
        let entry = entry.unwrap();
        assert!(entry.wiring.iter().all(|rec| rec.file != leftover));
    }

    #[test]
    fn only_parent_scoped_vendored_overrides_are_this_layouts_own() {
        let tgz = |v: &str| {
            format!(
                "file:.socket/vendor/npm/{}/minimist-{v}.tgz",
                MINIMIST_008.2
            )
        };
        assert!(is_own_override(
            "mkdirp@0.5.1>minimist@0.0.8",
            &tgz("0.0.8"),
            "minimist"
        ));
        // A sibling version's entry is this layout's too.
        assert!(is_own_override(
            "optimist@0.6.1>minimist@0.0.10",
            &tgz("0.0.10"),
            "minimist"
        ));
        // A scoped package's tarball sits under its scope's folder.
        let scoped = format!(
            "file:.socket/vendor/npm/{}/@types/node-18.0.0.tgz",
            MINIMIST_008.2
        );
        let node = "@types/node";
        assert!(is_own_override(
            "@scope/parent@1.0.0>@types/node@18.0.0",
            &scoped,
            node
        ));
        assert!(!is_own_override(
            "@scope/parent@1.0.0>@types/node@18.0.1",
            &scoped,
            node
        ));
        assert!(!is_own_override("@types/node@18.0.0", &scoped, node));
        for (key, value) in [
            // What the plain pnpm backend writes: under Rush it would
            // rewrite project importers.
            ("minimist@0.0.8", tgz("0.0.8")),
            ("minimist", tgz("0.0.8")),
            ("mkdirp@0.5.1>minimist@0.0.8", "0.0.10".to_string()),
            ("mkdirp@0.5.1>minimist@0.0.8", tgz("0.0.10")),
            (
                "mkdirp@0.5.1>minimist@0.0.8",
                "file:../elsewhere/minimist-0.0.8.tgz".to_string(),
            ),
        ] {
            assert!(!is_own_override(key, &value, "minimist"), "{key}: {value}");
        }
    }

    #[tokio::test]
    async fn a_users_override_on_the_package_is_refused() {
        let repo = Repo::new("pnpm10");
        let config_rel = format!("{RUSH_CONFIG_DIR}/{PNPM_CONFIG}");
        let config = repo.read(&config_rel).replace(
            "\"globalOverrides\": {",
            "\"globalOverrides\": {\n    \"mkdirp>minimist\": \"0.0.10\",",
        );
        repo.write(&config_rel, &config);
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, "vendor_override_conflict");
        assert!(detail.contains("mkdirp>minimist"), "{detail}");
    }

    /// `util` (depth 2) and `top` (depth 1) both depend on the package, so
    /// their `file:` specs differ, which `ensureConsistentVersions` fails —
    /// unless the repository lists them as allowed alternatives.
    #[tokio::test]
    async fn specs_the_consistency_policy_would_fail_are_refused() {
        let repo = Repo::new("pnpm10");
        let rush = repo.read(RUSH_JSON).replace(
            "\"projects\":",
            "\"ensureConsistentVersions\": true,\n  \"projects\":",
        );
        repo.write(RUSH_JSON, &rush);
        let (code, detail) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, VENDOR_RUSH_INCONSISTENT_VERSIONS);
        assert!(detail.contains("allowedAlternativeVersions"), "{detail}");

        let versions_rel = format!("{RUSH_CONFIG_DIR}/common-versions.json");
        let rel_tgz = format!(".socket/vendor/npm/{}/minimist-0.0.8.tgz", MINIMIST_008.2);
        let versions = repo.read(&versions_rel).replace(
            "\"allowedAlternativeVersions\": {",
            &format!(
                "\"allowedAlternativeVersions\": {{\n    \"minimist\": [\"file:../../{rel_tgz}\", \"file:../{rel_tgz}\"],"
            ),
        );
        repo.write(&versions_rel, &versions);
        let (result, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success && entry.is_some(), "{:?}", result.error);
    }

    /// Rush's consistency check counts `preferredVersions` beside the
    /// projects' own specs: a preferred registry version and one `file:`
    /// spec are two versions.
    #[tokio::test]
    async fn a_preferred_version_counts_in_the_consistency_policy() {
        let repo = Repo::new("pnpm10");
        let rush = repo.read(RUSH_JSON).replace(
            "\"projects\":",
            "\"ensureConsistentVersions\": true,\n  \"projects\":",
        );
        repo.write(RUSH_JSON, &rush);
        let versions_rel = format!("{RUSH_CONFIG_DIR}/common-versions.json");
        let rel_tgz = format!(".socket/vendor/npm/{}/minimist-0.0.8.tgz", MINIMIST_008.2);
        // One of the two `file:` specs is allowed: one version is left.
        let allowed = repo.read(&versions_rel).replace(
            "\"allowedAlternativeVersions\": {",
            &format!(
                "\"allowedAlternativeVersions\": {{\n    \"minimist\": [\"file:../../{rel_tgz}\"],"
            ),
        );
        let preferred = allowed.replace(
            "\"preferredVersions\": {",
            "\"preferredVersions\": {\n    \"minimist\": \"0.0.8\",",
        );
        assert_ne!(preferred, allowed);
        repo.write(&versions_rel, &preferred);
        let (code, _) = refused(&repo, MINIMIST_008).await;
        assert_eq!(code, VENDOR_RUSH_INCONSISTENT_VERSIONS);

        repo.write(&versions_rel, &allowed);
        let (result, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success && entry.is_some(), "{:?}", result.error);
    }

    // ── warnings ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_published_project_and_a_hashed_lock_are_named() {
        let repo = Repo::new("pnpm10");
        let rush = repo.read(RUSH_JSON).replace(
            "\"projectFolder\": \"libs/util\"",
            "\"projectFolder\": \"libs/util\",\n      \"shouldPublish\": true",
        );
        repo.write(RUSH_JSON, &rush);
        repo.write(
            &format!("{RUSH_CONFIG_DIR}/repo-state.json"),
            "// DO NOT MODIFY THIS FILE MANUALLY BUT DO COMMIT IT.\n{\n  \"pnpmShrinkwrapHash\": \"9514ab4e\",\n  \"packageJsonInjectedDependenciesHash\": \"0c1f\"\n}\n",
        );
        let (result, _, warnings) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success, "{:?}", result.error);
        let edited = warnings
            .iter()
            .find(|w| w.code == VENDOR_RUSH_PACKAGE_JSON_EDITED)
            .unwrap();
        assert!(
            edited.detail.contains("libs/util is published"),
            "{}",
            edited.detail
        );
        let stale = warnings
            .iter()
            .find(|w| w.code == VENDOR_RUSH_REPO_STATE_STALE)
            .expect("the stale lock hash is announced");
        assert!(stale.detail.contains("repo-state.json"), "{}", stale.detail);
        // The other hash covers `dependencies`, which libs/util's edit is.
        let injected = warnings
            .iter()
            .find(|w| w.detail.contains("packageJsonInjectedDependenciesHash"))
            .expect("the stale injected-dependencies hash is announced");
        assert_eq!(injected.code, VENDOR_RUSH_REPO_STATE_STALE);
        assert!(
            injected.detail.contains("libs/util/package.json"),
            "{}",
            injected.detail
        );
    }

    // ── revert ─────────────────────────────────────────────────────────

    /// A subspace added since the vendoring resolves through the tarball
    /// in a lock no record names: the revert must not delete it.
    #[tokio::test]
    async fn revert_keeps_an_artifact_an_unrecorded_lock_installs() {
        let repo = Repo::new("pnpm10");
        let (result, entry, _) = expect_done(repo.vendor(MINIMIST_008).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        let added = format!("{RUSH_SUBSPACES_DIR}/added/{PNPM_LOCK}");
        repo.write(&added, &repo.read(RUSH_COMMON_LOCK_REL));
        let wired = tree_snapshot(repo.root());

        let outcome = revert_npm_any(&entry, repo.root(), false).await;
        assert!(!outcome.success);
        assert!(codes(&outcome.warnings).contains(&revert::STILL_WIRED_CODE));
        assert!(outcome.error.unwrap().contains(&added));
        assert_eq!(tree_snapshot(repo.root()), wired, "a refused revert wrote");

        std::fs::remove_file(repo.root().join(&added)).unwrap();
        let outcome = revert_npm_any(&entry, repo.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        repo.assert_is("pnpm10", "before");
    }

    /// The cleanup commands ask which files may still name an artifact.
    #[tokio::test]
    async fn the_wiring_files_are_the_locks_configs_and_project_manifests() {
        let repo = Repo::new("subspaces-shared-config");
        let rush = repo.read(RUSH_JSON).replace(
            "\"projectFolder\": \"top\"",
            "\"projectFolder\": \"../outside\"",
        );
        repo.write(RUSH_JSON, &rush);
        let files = wiring_files(repo.root()).await;
        for rel in [
            "common/config/rush/pnpm-config.json",
            "common/config/rush/pnpm-lock.yaml",
            "common/config/subspaces/default/pnpm-config.json",
            "common/config/subspaces/default/pnpm-lock.yaml",
            "common/config/subspaces/team-b/pnpm-lock.yaml",
            "apps/app/package.json",
            "libs/util/package.json",
            "tools/deep/cli/package.json",
        ] {
            assert!(files.iter().any(|f| f == rel), "{rel}: {files:?}");
        }
        assert!(files.iter().all(|f| !f.contains("..")), "{files:?}");
        // Not a Rush repository: nothing.
        let plain = tempfile::tempdir().unwrap();
        assert!(wiring_files(plain.path()).await.is_empty());
    }

    // ── helpers ────────────────────────────────────────────────────────

    #[test]
    fn layouts_name_where_rush_installs_each_lock() {
        let common = Layout::of(RUSH_COMMON_LOCK_REL).unwrap();
        assert_eq!(common.temp_rel, "common/temp");
        assert_eq!(common.temp_prefix(), "file:../../.socket/vendor/");
        let subspace = Layout::of("common/config/subspaces/team-b/pnpm-lock.yaml").unwrap();
        assert_eq!(subspace.temp_rel, "common/temp/team-b");
        assert_eq!(subspace.temp_prefix(), "file:../../../.socket/vendor/");
        assert_eq!(
            subspace.config_candidates(PNPM_CONFIG),
            [
                "common/config/subspaces/team-b/pnpm-config.json",
                "common/config/rush/pnpm-config.json"
            ]
        );
        for not_a_rush_lock in [
            "pnpm-lock.yaml",
            "common/config/rush/pnpm-lock.yaml.bak",
            "common/config/subspaces/pnpm-lock.yaml",
            "common/config/subspaces/a/b/pnpm-lock.yaml",
            "common/config/subspaces/../pnpm-lock.yaml",
            "x/common/config/rush/pnpm-lock.yaml",
        ] {
            assert!(Layout::of(not_a_rush_lock).is_none(), "{not_a_rush_lock}");
        }
    }

    #[test]
    fn importer_keys_resolve_inside_the_repository_only() {
        for (importer, want) in [
            ("../../apps/app", Some("apps/app")),
            ("../../top", Some("top")),
            ("../../tools/deep/cli", Some("tools/deep/cli")),
            ("../templates/app", Some("common/templates/app")),
            ("./nested", None),
            // The temp directory itself, the repository root, and beyond.
            (".", None),
            ("../..", None),
            ("../../..", None),
            ("../../../elsewhere/app", None),
            ("../../apps/../../escape", None),
            ("../../node_modules/x", None),
            ("../../.socket/x", None),
            ("/abs/app", None),
            ("..\\..\\apps\\app", None),
        ] {
            assert_eq!(
                importer_project_rel("common/temp", importer).as_deref(),
                want,
                "{importer}"
            );
        }
        assert_eq!(
            importer_project_rel("common/temp/team-b", "../../../top").as_deref(),
            Some("top")
        );
    }

    /// The lock's paths go to root-relative and back unchanged, importer
    /// specifiers are never touched, and a path that would not survive the
    /// trip is refused.
    #[test]
    fn the_rebase_round_trips_or_refuses() {
        let layout = Layout::of(RUSH_COMMON_LOCK_REL).unwrap();
        let lock: Vec<String> = [
            "        specifier: file:../../.socket/vendor/npm/u/x.tgz",
            "        version: file:../../.socket/vendor/npm/u/x.tgz",
            "  x@file:../../.socket/vendor/npm/u/x.tgz:",
            "    resolution: {integrity: sha512-a, tarball: file:../../.socket/vendor/npm/u/x.tgz}",
            "  y@file:../../libs/y:",
        ]
        .map(String::from)
        .to_vec();
        let mut rooted = lock.clone();
        layout.to_root_relative(&mut rooted).unwrap();
        assert_eq!(rooted[0], lock[0]);
        assert_eq!(
            rooted[1],
            "        version: file:.socket/vendor/npm/u/x.tgz"
        );
        assert_eq!(rooted[2], "  x@file:.socket/vendor/npm/u/x.tgz:");
        assert_eq!(rooted[4], lock[4]);
        assert_eq!(layout.to_temp_relative(&rooted), lock);

        let mut under_temp = vec!["  x@file:.socket/vendor/npm/u/x.tgz:".to_string()];
        assert!(layout.to_root_relative(&mut under_temp).is_err());
        // Discovery reads such a path as what it names: nothing of ours.
        let text = root_relative_lock_text(RUSH_COMMON_LOCK_REL, under_temp[0].clone());
        assert_eq!(text, "  x@file:common/temp/.socket/vendor/npm/u/x.tgz:");
        assert_eq!(
            root_relative_lock_text("pnpm-lock.yaml", lock[2].clone()),
            lock[2],
            "only a Rush lock is rebased"
        );
    }

    /// pnpm single-quotes a key that starts with `@` (pnpm 10.34.9 under
    /// Rush wrote `'@babel/code-frame@7.0.0>@babel/highlight': 7.0.0`) and
    /// leaves a `>` inside a plain key alone.
    #[test]
    fn override_keys_are_spelled_as_pnpm_spells_them() {
        let mut lines: Vec<String> = [
            "lockfileVersion: '9.0'",
            "",
            "settings:",
            "  autoInstallPeers: false",
            "",
            "pnpmfileChecksum: sha256-x",
            "",
            "importers:",
            "",
        ]
        .map(String::from)
        .to_vec();
        let keys = [
            "@babel/code-frame@7.0.0>@babel/highlight@7.0.0".to_string(),
            "mkdirp@0.5.1>minimist@0.0.8".to_string(),
        ];
        let mut wiring = Vec::new();
        assert!(edit_overrides(
            &mut lines,
            &keys,
            "file:x.tgz",
            true,
            &mut wiring
        ));
        assert_eq!(
            lines[4..9],
            [
                "",
                "overrides:",
                "  '@babel/code-frame@7.0.0>@babel/highlight@7.0.0': file:x.tgz",
                "  mkdirp@0.5.1>minimist@0.0.8: file:x.tgz",
                "",
            ]
        );
        assert_eq!(lines[9], "pnpmfileChecksum: sha256-x");
        assert_eq!(wiring.len(), 2);
        // In sync: nothing to do, nothing recorded.
        assert!(!edit_overrides(
            &mut lines,
            &keys,
            "file:x.tgz",
            true,
            &mut wiring
        ));
        assert_eq!(wiring.len(), 2);
        // A scoped parent's own version is read past its scope's `@`.
        let snapshot: Vec<String> = [
            "packages:",
            "",
            "snapshots:",
            "",
            "  '@scope/parent@2.1.0(react@18.0.0)':",
            "    dependencies:",
            "      minimist: file:x.tgz",
            "",
        ]
        .map(String::from)
        .to_vec();
        let ctx = EditCtx {
            name: "minimist",
            version: "0.0.8",
            rel_tgz: "x.tgz",
            spec: "file:x.tgz",
            integrity: "sha512-x",
            override_key: "",
        };
        assert_eq!(
            parent_override_keys(&snapshot, &ctx).unwrap(),
            ["@scope/parent@2.1.0>minimist@0.0.8"]
        );
        // The same dependent resolving another release is what a shared
        // override would move.
        let keys = ["@scope/parent@2.1.0>minimist@0.0.8".to_string()];
        assert_eq!(
            other_resolution(&snapshot, &keys, "minimist", "file:x.tgz"),
            None
        );
        assert_eq!(
            other_resolution(&snapshot, &keys, "minimist", "file:y.tgz"),
            Some((
                keys[0].clone(),
                "@scope/parent@2.1.0(react@18.0.0)".to_string(),
                "file:x.tgz".to_string()
            ))
        );
        // A key that names no version is an error, never a panic.
        for key in ["é", "@scope/parent", "parent"] {
            assert_eq!(override_parent(&snapshot, &[], key), None, "{key}");
        }
        let odd: Vec<String> = [
            "snapshots:",
            "",
            "  é:",
            "    dependencies:",
            "      minimist: file:x.tgz",
            "",
        ]
        .map(String::from)
        .to_vec();
        assert!(parent_override_keys(&odd, &ctx).is_err());
    }

    #[test]
    fn revert_edits_only_rush_files() {
        assert!(is_pnpm_config("common/config/rush/pnpm-config.json"));
        assert!(is_pnpm_config(
            "common/config/subspaces/team-b/pnpm-config.json"
        ));
        for no in [
            "pnpm-config.json",
            "common/config/subspaces/a/b/pnpm-config.json",
            "common/config/rush/../../../pnpm-config.json",
        ] {
            assert!(!is_pnpm_config(no), "{no}");
        }
        assert!(is_project_manifest("apps/app/package.json"));
        for no in [
            "package.json",
            "../outside/package.json",
            "apps/app/node_modules/x/package.json",
            ".git/package.json",
            "apps/app/package.json5",
            "/abs/package.json",
        ] {
            assert!(!is_project_manifest(no), "{no}");
        }
    }
}
