//! pnpm build approvals for a vendored `file:` tarball (#1597).
//!
//! Vendoring wires a pnpm project to `name@file:.socket/vendor/npm/<uuid>/…`,
//! and pnpm installs the package under that id. pnpm 10.34.2+ / 11.5.3+ match a
//! build decision (`allowBuilds`, `onlyBuiltDependencies`) against the id,
//! so a key spelling the registry package (`name`, `name@1.2.3`,
//! `name@1.2.3 || 1.2.4`) stops matching the vendored copy: pnpm 10 skips
//! the approved install script and pnpm 11/12 (`strictDepBuilds` on by
//! default) fail every install with `ERR_PNPM_IGNORED_BUILDS`. Only a key
//! spelling the whole `name@file:<spec>` matches.
//!
//! So when the project already decides the package's build, the same
//! decision is added under the vendored key, next to the user's own entry,
//! on the surface that holds it: `pnpm-workspace.yaml` (`allowBuilds:`
//! block mapping, `onlyBuiltDependencies:` block sequence) or
//! `package.json#pnpm` (the same two fields, read by pnpm <= 10). A key a
//! superseded patch left for the same `name@version` is replaced, and its
//! decision carried when it is the only one; an added key follows the
//! user's decision when it changes. Each added key is a ledger record that
//! `vendor --revert` / `rollback` / `remove` take out again. The user's own
//! entries are never edited.
//!
//! The key is written only when the project's pnpm pins say it runs
//! 10.34.2+ (11.5.3+ on pnpm 11): older releases still match the name, and
//! refuse a `file:` key outright (ERR_PNPM_INVALID_VERSION_UNION). Without a usable
//! pin, or for a decision the line surgery cannot extend (a flow-style
//! value, a non-boolean one), nothing is written and the
//! `vendor_pnpm_build_approval_lost` warning names the key to add.

use serde_json::Value;

use super::path::{parse_vendor_path, VendorPathParts};
use super::state::{WiringAction, WiringRecord};
use super::VendorWarning;
use crate::formats::pnpm::lines::{
    indent_of, parse_key_line, split_lines, unquote_value, yaml_key,
};
use crate::formats::pnpm::workspace::{block_section_bounds, strip_comment, top_level_key};
use crate::utils::pnpm_workspace::PNPM_WORKSPACE;

const PACKAGE_JSON: &str = "package.json";

/// The two pnpm settings that hold per-package build decisions.
const ALLOW_BUILDS: &str = "allowBuilds";
const ONLY_BUILT: &str = "onlyBuiltDependencies";

/// Wiring kinds: one vendored-key approval added to a surface.
pub(super) const KIND_WS_ALLOW_BUILD: &str = "pnpm_ws_allow_build";
pub(super) const KIND_WS_ONLY_BUILT: &str = "pnpm_ws_only_built";
pub(super) const KIND_PKG_ALLOW_BUILD: &str = "pnpm_pkg_allow_build";
pub(super) const KIND_PKG_ONLY_BUILT: &str = "pnpm_pkg_only_built";

/// Warning code: the project decides the package's build in a way this
/// rewriter does not carry to the vendored key, so pnpm 10.34.2+ / 11.5.3+ stop
/// applying that decision.
pub(crate) const VENDOR_PNPM_BUILD_APPROVAL_LOST: &str = "vendor_pnpm_build_approval_lost";

/// Whether `kind` is one of this module's `pnpm-workspace.yaml` records.
pub(super) fn is_ws_kind(kind: &str) -> bool {
    matches!(kind, KIND_WS_ALLOW_BUILD | KIND_WS_ONLY_BUILT)
}

/// Whether `kind` is one of this module's `package.json` records.
pub(super) fn is_pkg_kind(kind: &str) -> bool {
    matches!(kind, KIND_PKG_ALLOW_BUILD | KIND_PKG_ONLY_BUILT)
}

/// The package being vendored and the key pnpm matches its copy by.
pub(super) struct Target<'a> {
    name: &'a str,
    version: &'a str,
    /// `name@file:<rel-tgz>`, the id pnpm installs the vendored copy as.
    key: String,
    /// The vendored tarball's path, parsed.
    ours: Option<VendorPathParts>,
}

impl<'a> Target<'a> {
    /// `rel_tgz` is the vendored tarball's root-relative path.
    pub(super) fn new(name: &'a str, version: &'a str, rel_tgz: &str) -> Self {
        Target {
            name,
            version,
            key: format!("{name}@file:{rel_tgz}"),
            ours: parse_vendor_path(rel_tgz),
        }
    }

    /// How strongly `key` decides this package's build: a version-pinned
    /// key beats a name-only one, and both beat a vendored key a superseded
    /// patch left for the same `name@version`. `None` for any other key,
    /// including the vendored key itself.
    fn rank(&self, key: &str) -> Option<Rank> {
        if key == self.name {
            return Some(Rank::Name);
        }
        let rest = key.strip_prefix(self.name)?.strip_prefix('@')?;
        if let Some(path) = rest.strip_prefix("file:") {
            let ours = self.ours.as_ref()?;
            return parse_vendor_path(path)
                .filter(|p| p.eco == "npm" && p.leaf == ours.leaf && p.uuid != ours.uuid)
                .map(|_| Rank::Stale);
        }
        // pnpm's version specs: exact versions joined by `||`.
        rest.split("||")
            .any(|v| v.trim() == self.version)
            .then_some(Rank::Pinned)
    }

    /// Where the decision for this package sits among `keys`, `None` when
    /// none decides it.
    fn select<'k>(&self, keys: impl Iterator<Item = &'k str>) -> Option<Selection> {
        let mut sel = Selection::default();
        let mut best = None;
        for (i, key) in keys.enumerate() {
            if key == self.key {
                sel.ours = Some(i);
                continue;
            }
            let Some(rank) = self.rank(key) else {
                continue;
            };
            if best.is_none_or(|b| rank > b) {
                sel.source = i;
                best = Some(rank);
            }
            if rank == Rank::Stale {
                sel.stale.push(i);
            }
            sel.anchor = i;
        }
        best.map(|_| sel)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Stale,
    Name,
    Pinned,
}

/// [`Target::select`]'s answer, as indices into the keys it was given.
#[derive(Default)]
struct Selection {
    /// The entry whose decision is carried.
    source: usize,
    /// The vendored key's own entry.
    ours: Option<usize>,
    /// Keys a superseded patch left, ascending.
    stale: Vec<usize>,
    /// The last deciding entry: the vendored key goes right after it.
    anchor: usize,
}

/// What [`carry`] changed.
#[derive(Default)]
pub(super) struct Carried {
    /// `package.json` (the `pkg` value passed in) was edited.
    pub pkg_changed: bool,
    /// The new `pnpm-workspace.yaml` text, when it was edited.
    pub ws_text: Option<String>,
}

/// Add the vendored key beside every build decision the project holds for
/// `target` (see the module doc), pushing one record per added key.
/// `ws_text` is the workspace file as the override wiring left it.
/// `file_keys` is whether the project's pnpm matches build decisions
/// against a `file:` id ([`crate::formats::pnpm::matches_file_id_build_keys`]).
pub(super) fn carry(
    target: &Target<'_>,
    ws_text: Option<&str>,
    pkg: &mut Value,
    file_keys: Option<bool>,
    wiring: &mut Vec<WiringRecord>,
    warnings: &mut Vec<VendorWarning>,
) -> Carried {
    if file_keys == Some(false) {
        // Older pnpm matches the name, which the vendored copy keeps.
        return Carried::default();
    }
    let mut trial = pkg.clone();
    let mut added = Vec::new();
    let mut lost = Vec::new();
    let carried = carry_all(target, ws_text, &mut trial, &mut added, &mut lost);
    for surface in &lost {
        warnings.push(lost_warning(target, surface, LostWhy::Shape));
    }
    if file_keys == Some(true) {
        *pkg = trial;
        wiring.extend(added);
        return carried;
    }
    if let Some(rec) = added.first() {
        warnings.push(lost_warning(target, &rec.file, LostWhy::UnknownPnpm));
    }
    Carried::default()
}

fn carry_all(
    target: &Target<'_>,
    ws_text: Option<&str>,
    pkg: &mut Value,
    wiring: &mut Vec<WiringRecord>,
    lost: &mut Vec<String>,
) -> Carried {
    let mut carried = Carried::default();
    if let Some(text) = ws_text {
        let mut lines = split_lines(text);
        let mut changed = false;
        for (field, kind) in [
            (ALLOW_BUILDS, KIND_WS_ALLOW_BUILD),
            (ONLY_BUILT, KIND_WS_ONLY_BUILT),
        ] {
            match carry_ws(&mut lines, field, target) {
                WsCarry::Unchanged => {}
                WsCarry::Edited(added) => {
                    changed = true;
                    if let Some(value) = added {
                        wiring.push(record(PNPM_WORKSPACE, kind, target, value));
                    }
                }
                WsCarry::Unsupported => lost.push(format!("{PNPM_WORKSPACE} `{field}`")),
            }
        }
        if changed {
            carried.ws_text = Some(lines.join("\n"));
        }
    }
    if let Some(table) = pkg.get_mut("pnpm").and_then(Value::as_object_mut) {
        if let Some(map) = table.get_mut(ALLOW_BUILDS).and_then(Value::as_object_mut) {
            match carry_pkg_map(map, target) {
                Some((changed, added)) => {
                    carried.pkg_changed |= changed;
                    if let Some(value) = added {
                        wiring.push(record(PACKAGE_JSON, KIND_PKG_ALLOW_BUILD, target, value));
                    }
                }
                None => lost.push(format!("{PACKAGE_JSON} `pnpm.{ALLOW_BUILDS}`")),
            }
        }
        if let Some(list) = table.get_mut(ONLY_BUILT).and_then(Value::as_array_mut) {
            let (changed, added) = carry_pkg_list(list, target);
            carried.pkg_changed |= changed;
            if let Some(value) = added {
                wiring.push(record(PACKAGE_JSON, KIND_PKG_ONLY_BUILT, target, value));
            }
        }
    }
    carried
}

fn record(file: &str, kind: &str, target: &Target<'_>, value: Value) -> WiringRecord {
    WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action: WiringAction::Added,
        key: Some(target.key.clone()),
        original: None,
        new: Some(value),
    }
}

/// Why a decision was not carried.
enum LostWhy {
    /// The value is not one the line surgery can extend.
    Shape,
    /// No pnpm pin says whether the key would be accepted.
    UnknownPnpm,
}

fn lost_warning(target: &Target<'_>, surface: &str, why: LostWhy) -> VendorWarning {
    let (name, version, key) = (target.name, target.version, &target.key);
    let reason = match why {
        LostWhy::Shape => format!(
            "its value is not a block mapping/sequence of true/false this rewriter can \
             extend; add `{key}` there with the same decision"
        ),
        LostWhy::UnknownPnpm => format!(
            "no pnpm pin (package.json `packageManager`, `devEngines`, `engines.pnpm`, or \
             node_modules/.modules.yaml) says which pnpm installs, and pnpm 10.20–10.34.1 and \
             11.0–11.5.2 refuse that key (ERR_PNPM_INVALID_VERSION_UNION); on pnpm 10.34.2+ / \
             11.5.3+ add \
             `{key}` there with the same decision, or pin pnpm and re-run to have it added"
        ),
    };
    VendorWarning::new(
        VENDOR_PNPM_BUILD_APPROVAL_LOST,
        format!(
            "{surface} decides {name}@{version}'s install script by a key pnpm 10.34.2+ / 11.5.3+ \
             no longer match once the package is vendored, so pnpm 10 skips the script \
             and pnpm 11+ fail every install with ERR_PNPM_IGNORED_BUILDS; {reason}"
        ),
    )
}

/// The outcome of one `pnpm-workspace.yaml` field.
enum WsCarry {
    Unchanged,
    /// Lines were edited; `Some` carries the decision of a key added.
    Edited(Option<Value>),
    /// The field decides the package in a form not carried.
    Unsupported,
}

/// One entry of a block mapping or sequence: its line, key and value.
struct WsEntry {
    line: usize,
    key: String,
    value: String,
}

/// The entries of the top-level block `field`, with the indent its entries
/// use. A sequence's items may sit at column 0 (YAML allows that under a
/// mapping key), which ends [`block_section_bounds`]'s section, so items
/// are read here line by line.
fn ws_entries(lines: &[String], field: &str) -> Option<(usize, Vec<WsEntry>)> {
    let (start, end) = block_section_bounds(lines, field)?;
    let body = |l: &str| {
        let t = l.trim_start_matches(' ');
        !(t.is_empty() || t == "\r" || t.starts_with('#'))
    };
    let first = lines[start + 1..].iter().position(|l| body(l))? + start + 1;
    let indent = indent_of(&lines[first]);
    let mut entries = Vec::new();
    if field == ONLY_BUILT {
        for (i, line) in lines.iter().enumerate().skip(first) {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if !body(line) {
                continue;
            }
            let Some(item) = line
                .strip_prefix(&" ".repeat(indent))
                .and_then(|s| s.strip_prefix('-'))
                .filter(|s| s.is_empty() || s.starts_with(' '))
            else {
                break;
            };
            entries.push(WsEntry {
                line: i,
                key: unquote_value(strip_comment(item).trim()).to_string(),
                value: String::new(),
            });
        }
    } else {
        for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some((key, _repr, rest)) = parse_key_line(line, indent) {
                entries.push(WsEntry {
                    line: i,
                    key: key.to_string(),
                    value: strip_comment(rest).trim().to_string(),
                });
            }
        }
    }
    Some((indent, entries))
}

/// Whether a top-level `field` with a flow (inline) value decides the
/// package: the value runs from the key's line until its brackets close.
fn flow_value_decides(lines: &[String], field: &str, target: &Target<'_>) -> bool {
    let Some(start) = lines.iter().position(|l| {
        top_level_key(l).is_some_and(|(key, value)| key == field && !value.is_empty())
    }) else {
        return false;
    };
    let mut text = String::new();
    for (n, line) in lines[start..].iter().enumerate() {
        if n == 0 {
            text.push_str(top_level_key(line).map_or("", |(_, value)| value));
        } else {
            text.push(' ');
            text.push_str(strip_comment(line));
        }
        let depth: i32 = text
            .chars()
            .map(|c| match c {
                '[' | '{' => 1,
                ']' | '}' => -1,
                _ => 0,
            })
            .sum();
        if depth <= 0 {
            break;
        }
    }
    text.split([',', '[', ']', '{', '}'])
        .map(|item| {
            let item = item.trim();
            // A mapping item's key ends at the first `: `.
            let key = item.find(": ").map_or(item, |at| &item[..at]);
            unquote_value(key.trim())
        })
        .any(|key| target.rank(key).is_some())
}

fn carry_ws(lines: &mut Vec<String>, field: &str, target: &Target<'_>) -> WsCarry {
    let Some((indent, entries)) = ws_entries(lines, field) else {
        return if flow_value_decides(lines, field, target) {
            WsCarry::Unsupported
        } else {
            WsCarry::Unchanged
        };
    };
    let Some(sel) = target.select(entries.iter().map(|e| e.key.as_str())) else {
        return WsCarry::Unchanged;
    };
    let source = &entries[sel.source];
    let map = field == ALLOW_BUILDS;
    if map && !matches!(source.value.as_str(), "true" | "false") {
        return WsCarry::Unsupported;
    }
    let pad = " ".repeat(indent);
    let eol = if lines[source.line].ends_with('\r') {
        "\r"
    } else {
        ""
    };
    let new_line = if map {
        format!("{pad}{}: {}{eol}", yaml_key(&target.key), source.value)
    } else {
        format!("{pad}- '{}'{eol}", target.key)
    };
    let mut edited = !sel.stale.is_empty();
    let mut added = None;
    match sel.ours.map(|i| &entries[i]) {
        // The added key follows the user's decision when it changes.
        Some(ours) if map && ours.value != source.value => {
            lines[ours.line] = new_line;
            edited = true;
        }
        Some(_) => {}
        None => {
            lines.insert(entries[sel.anchor].line + 1, new_line);
            added = Some(Value::String(if map {
                source.value.clone()
            } else {
                target.key.clone()
            }));
            edited = true;
        }
    }
    // Stale lines all sit at or before the anchor, so the insert leaves
    // their indices alone; drop them last-first.
    for &i in sel.stale.iter().rev() {
        lines.remove(entries[i].line);
    }
    if edited {
        WsCarry::Edited(added)
    } else {
        WsCarry::Unchanged
    }
}

/// `package.json#pnpm.allowBuilds`: `(changed, the decision of a key
/// added)`, `None` when the deciding value is not a boolean.
fn carry_pkg_map(
    map: &mut serde_json::Map<String, Value>,
    target: &Target<'_>,
) -> Option<(bool, Option<Value>)> {
    let keys: Vec<String> = map.keys().cloned().collect();
    let Some(sel) = target.select(keys.iter().map(String::as_str)) else {
        return Some((false, None));
    };
    let value = map[&keys[sel.source]].clone();
    if !value.is_boolean() {
        return None;
    }
    let changed = sel.ours.is_none_or(|i| map[&keys[i]] != value) || !sel.stale.is_empty();
    // Rebuild in order: the vendored key goes right after the last
    // deciding entry (or stays where it is), stale keys go.
    let old = std::mem::take(map);
    for (i, (key, v)) in old.into_iter().enumerate() {
        if Some(i) == sel.ours {
            map.insert(key, value.clone());
        } else if !sel.stale.contains(&i) {
            map.insert(key, v);
        }
        if i == sel.anchor && sel.ours.is_none() {
            map.insert(target.key.clone(), value.clone());
        }
    }
    Some((changed, sel.ours.is_none().then_some(value)))
}

/// `package.json#pnpm.onlyBuiltDependencies`.
fn carry_pkg_list(list: &mut Vec<Value>, target: &Target<'_>) -> (bool, Option<Value>) {
    let keys: Vec<&str> = list.iter().map(|v| v.as_str().unwrap_or("")).collect();
    let Some(sel) = target.select(keys.into_iter()) else {
        return (false, None);
    };
    let ours = sel.ours.is_some();
    if !ours {
        list.insert(sel.anchor + 1, Value::String(target.key.clone()));
    }
    // The insert sits after every stale index.
    for &i in sel.stale.iter().rev() {
        list.remove(i);
    }
    if ours {
        (!sel.stale.is_empty(), None)
    } else {
        (true, Some(Value::String(target.key.clone())))
    }
}

/// Take the keys `records` added out of `pnpm-workspace.yaml`'s lines. A
/// key already gone is converged. The key names this patch's own artifact,
/// which the revert removes, so a decision the user flipped since goes too.
pub(super) fn revert_ws(lines: &mut Vec<String>, records: &[&WiringRecord]) -> bool {
    let mut dirty = false;
    for rec in records {
        let Some(key) = rec.key.as_deref() else {
            continue;
        };
        let field = if rec.kind == KIND_WS_ALLOW_BUILD {
            ALLOW_BUILDS
        } else {
            ONLY_BUILT
        };
        let Some((_, entries)) = ws_entries(lines, field) else {
            continue;
        };
        if let Some(entry) = entries.iter().rev().find(|e| e.key == key) {
            lines.remove(entry.line);
            dirty = true;
        }
    }
    dirty
}

/// Take the key `rec` added out of `package.json#pnpm`; `true` when the
/// document changed.
pub(super) fn revert_pkg(doc: &mut Value, rec: &WiringRecord) -> bool {
    let Some(key) = rec.key.as_deref() else {
        return false;
    };
    let Some(table) = doc.get_mut("pnpm").and_then(Value::as_object_mut) else {
        return false;
    };
    if rec.kind == KIND_PKG_ALLOW_BUILD {
        table
            .get_mut(ALLOW_BUILDS)
            .and_then(Value::as_object_mut)
            .is_some_and(|map| map.shift_remove(key).is_some())
    } else {
        table
            .get_mut(ONLY_BUILT)
            .and_then(Value::as_array_mut)
            .is_some_and(|list| {
                let before = list.len();
                list.retain(|v| v.as_str() != Some(key));
                list.len() != before
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const OLD: &str = "11111111-2222-4333-8444-555555555555";

    fn vendored_rel(uuid: &str) -> String {
        format!(".socket/vendor/npm/{uuid}/sp-build-1.0.0.tgz")
    }

    fn target() -> Target<'static> {
        Target::new("sp-build", "1.0.0", &vendored_rel(UUID))
    }

    fn key(uuid: &str) -> String {
        format!("sp-build@file:{}", vendored_rel(uuid))
    }

    fn run_ws_with(
        text: &str,
        file_keys: Option<bool>,
    ) -> (Option<String>, Vec<WiringRecord>, Vec<VendorWarning>) {
        let (mut wiring, mut warnings) = (Vec::new(), Vec::new());
        let mut pkg = serde_json::json!({});
        let out = carry(
            &target(),
            Some(text),
            &mut pkg,
            file_keys,
            &mut wiring,
            &mut warnings,
        );
        assert!(!out.pkg_changed);
        (out.ws_text, wiring, warnings)
    }

    fn run_ws(text: &str) -> (Option<String>, Vec<WiringRecord>, Vec<VendorWarning>) {
        run_ws_with(text, Some(true))
    }

    #[test]
    fn rank_reads_pnpm_version_specs() {
        let t = target();
        assert!(t.rank("sp-build") == Some(Rank::Name));
        assert!(t.rank("sp-build@1.0.0") == Some(Rank::Pinned));
        assert!(t.rank("sp-build@0.9.0 || 1.0.0") == Some(Rank::Pinned));
        assert!(t.rank("sp-build@2.0.0").is_none());
        assert!(t.rank("sp-build-native").is_none());
        assert!(t.rank(&key(OLD)) == Some(Rank::Stale));
        assert!(t.rank(&key(UUID)).is_none());
        assert!(t
            .rank("sp-build@file:.socket/vendor/npm/x/other-1.0.0.tgz")
            .is_none());
    }

    #[test]
    fn allow_builds_true_and_false_are_carried_after_the_users_entry() {
        for value in ["true", "false"] {
            let text = format!("packages:\n  - '.'\nallowBuilds:\n  esbuild: true\n  sp-build: {value} # native\n  zz: false\n");
            let (ws, wiring, warnings) = run_ws(&text);
            let key = key(UUID);
            assert_eq!(
                ws.unwrap(),
                text.replace(
                    &format!("  sp-build: {value} # native\n"),
                    &format!("  sp-build: {value} # native\n  {key}: {value}\n")
                )
            );
            assert!(warnings.is_empty());
            assert_eq!(wiring.len(), 1);
            assert_eq!(wiring[0].kind, KIND_WS_ALLOW_BUILD);
            assert_eq!(wiring[0].key.as_deref(), Some(key.as_str()));
        }
    }

    #[test]
    fn pinned_decision_beats_name_only() {
        let text = "allowBuilds:\n  sp-build@1.0.0: false\n  sp-build: true\n";
        let (ws, _, _) = run_ws(text);
        assert_eq!(ws.unwrap(), format!("{text}  {}: false\n", key(UUID)));
    }

    #[test]
    fn only_built_list_gets_a_quoted_item_even_at_column_zero() {
        let key = key(UUID);
        for text in [
            "onlyBuiltDependencies:\n  - esbuild\n  - sp-build\npackages:\n  - '.'\n",
            "onlyBuiltDependencies:\n- 'sp-build'\npackages:\n- '.'\n",
        ] {
            let (ws, wiring, _) = run_ws(text);
            let pad = if text.contains("\n  - esbuild") {
                "  "
            } else {
                ""
            };
            let item = if pad.is_empty() {
                "- 'sp-build'\n"
            } else {
                "  - sp-build\n"
            };
            assert_eq!(
                ws.unwrap(),
                text.replacen(item, &format!("{item}{pad}- '{key}'\n"), 1)
            );
            assert_eq!(wiring[0].kind, KIND_WS_ONLY_BUILT);
        }
    }

    #[test]
    fn no_decision_for_the_package_leaves_the_file_alone() {
        let text = "allowBuilds:\n  esbuild: true\nonlyBuiltDependencies:\n  - sharp\n";
        let (ws, wiring, warnings) = run_ws(text);
        assert!(ws.is_none() && wiring.is_empty() && warnings.is_empty());
    }

    #[test]
    fn rerun_is_in_sync_and_a_superseded_key_is_replaced() {
        let key = key(UUID);
        let synced = format!("allowBuilds:\n  sp-build: true\n  {key}: true\n");
        let (ws, wiring, _) = run_ws(&synced);
        assert!(ws.is_none() && wiring.is_empty());

        // Only the superseded patch's key decides: its decision carries.
        let old = self::key(OLD);
        let (ws, wiring, _) = run_ws(&format!("allowBuilds:\n  {old}: true\n"));
        assert_eq!(ws.unwrap(), format!("allowBuilds:\n  {key}: true\n"));
        assert_eq!(wiring.len(), 1);
        let (ws, _, _) = run_ws(&format!(
            "onlyBuiltDependencies:\n  - sp-build\n  - '{old}'\n"
        ));
        assert_eq!(
            ws.unwrap(),
            format!("onlyBuiltDependencies:\n  - sp-build\n  - '{key}'\n")
        );
    }

    /// The user flips their decision after vendoring: the re-run brings
    /// the added key along, without a new record (the first one still
    /// takes the key out on revert).
    #[test]
    fn added_key_follows_a_flipped_decision() {
        let key = key(UUID);
        let (ws, wiring, _) = run_ws(&format!("allowBuilds:\n  sp-build: false\n  {key}: true\n"));
        assert_eq!(
            ws.unwrap(),
            format!("allowBuilds:\n  sp-build: false\n  {key}: false\n")
        );
        assert!(wiring.is_empty());

        let mut pkg = serde_json::json!({"pnpm": {"allowBuilds": {"sp-build": false, &key: true}}});
        let (mut wiring, mut warnings) = (Vec::new(), Vec::new());
        let out = carry(
            &target(),
            None,
            &mut pkg,
            Some(true),
            &mut wiring,
            &mut warnings,
        );
        assert!(out.pkg_changed && wiring.is_empty());
        assert_eq!(pkg["pnpm"]["allowBuilds"][&key], Value::Bool(false));
    }

    #[test]
    fn flow_or_non_boolean_values_warn_and_write_nothing() {
        for text in [
            "onlyBuiltDependencies: [sp-build]\n",
            "onlyBuiltDependencies: [\n  esbuild,\n  'sp-build', # native\n]\npackages: ['.']\n",
            "allowBuilds: {sp-build: true}\n",
            "allowBuilds:\n  sp-build: &yes true\n",
            "allowBuilds:\n  sp-build:\n",
        ] {
            let (ws, wiring, warnings) = run_ws(text);
            assert!(ws.is_none() && wiring.is_empty(), "{text}");
            assert_eq!(warnings.len(), 1, "{text}");
            assert_eq!(warnings[0].code, VENDOR_PNPM_BUILD_APPROVAL_LOST);
            assert!(
                warnings[0].detail.contains(&key(UUID)),
                "{}",
                warnings[0].detail
            );
        }
        // Other packages whose names contain the target's decide nothing.
        for text in [
            "onlyBuiltDependencies: [sp-build-native, '@x/sp-build']\n",
            "allowBuilds: {sp-builder: true}\n",
        ] {
            let (_, _, warnings) = run_ws(text);
            assert!(warnings.is_empty(), "{text}: {warnings:?}");
        }
    }

    /// pnpm 10.20–10.34.1 refuse a `file:` key, older pnpm still matches
    /// the name: only a pin admitting nothing but 10.34.2+ / 11.5.3+ gets the key.
    #[test]
    fn the_key_is_written_only_for_a_pnpm_that_reads_it() {
        let text = "allowBuilds:\n  sp-build: true\n";
        let (ws, wiring, warnings) = run_ws_with(text, Some(false));
        assert!(ws.is_none() && wiring.is_empty() && warnings.is_empty());

        let (ws, wiring, warnings) = run_ws_with(text, None);
        assert!(ws.is_none() && wiring.is_empty());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, VENDOR_PNPM_BUILD_APPROVAL_LOST);
        assert!(
            warnings[0]
                .detail
                .contains("ERR_PNPM_INVALID_VERSION_UNION"),
            "{}",
            warnings[0].detail
        );

        // Nothing to carry: silent whatever the pnpm.
        let (_, _, warnings) = run_ws_with("allowBuilds:\n  esbuild: true\n", None);
        assert!(warnings.is_empty());
    }

    #[test]
    fn package_json_fields_are_carried_and_reverted() {
        let t = target();
        let key = key(UUID);
        let before = serde_json::json!({
            "pnpm": {
                "onlyBuiltDependencies": ["sp-build", "esbuild"],
                "allowBuilds": {"sp-build@1.0.0": false, "esbuild": true}
            }
        });
        let mut pkg = before.clone();
        let (mut wiring, mut warnings) = (Vec::new(), Vec::new());
        let out = carry(&t, None, &mut pkg, Some(true), &mut wiring, &mut warnings);
        assert!(out.pkg_changed && out.ws_text.is_none());
        assert_eq!(
            pkg["pnpm"]["onlyBuiltDependencies"],
            serde_json::json!(["sp-build", key, "esbuild"])
        );
        let order: Vec<&String> = pkg["pnpm"]["allowBuilds"]
            .as_object()
            .unwrap()
            .keys()
            .collect();
        assert_eq!(
            order,
            ["sp-build@1.0.0", &key, "esbuild"],
            "next to the decision"
        );
        assert_eq!(pkg["pnpm"]["allowBuilds"][&key], Value::Bool(false));
        assert_eq!(wiring.len(), 2);

        // In sync on a re-run.
        let mut again = Vec::new();
        assert!(!carry(&t, None, &mut pkg, Some(true), &mut again, &mut warnings).pkg_changed);
        assert!(again.is_empty());

        for rec in &wiring {
            assert!(is_pkg_kind(&rec.kind));
            assert!(revert_pkg(&mut pkg, rec));
        }
        assert_eq!(pkg, before);
    }

    #[test]
    fn revert_ws_removes_only_the_added_keys() {
        let text = "packages:\n  - '.'\nallowBuilds:\n  sp-build: true\nonlyBuiltDependencies:\n  - sp-build\n";
        let (ws, wiring, _) = run_ws(text);
        assert_eq!(wiring.len(), 2);
        let mut lines = split_lines(&ws.unwrap());
        let refs: Vec<&WiringRecord> = wiring.iter().collect();
        assert!(refs.iter().all(|r| is_ws_kind(&r.kind)));
        assert!(revert_ws(&mut lines, &refs));
        assert_eq!(lines.join("\n"), text);
        // Converged on a second pass.
        assert!(!revert_ws(&mut lines, &refs));
    }

    #[test]
    fn scoped_package_keys_are_quoted() {
        let rel = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/@sp/pad-1.0.0.tgz";
        let t = Target::new("@sp/pad", "1.0.0", rel);
        let mut lines = split_lines("allowBuilds:\n  '@sp/pad': false\n");
        assert!(matches!(
            carry_ws(&mut lines, ALLOW_BUILDS, &t),
            WsCarry::Edited(Some(_))
        ));
        assert_eq!(
            lines.join("\n"),
            format!("allowBuilds:\n  '@sp/pad': false\n  '@sp/pad@file:{rel}': false\n")
        );
    }
}
