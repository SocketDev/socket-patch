//! pnpm build approvals for a vendored `file:` tarball (#1597).
//!
//! Vendoring wires a pnpm project to `name@file:.socket/vendor/npm/<uuid>/…`,
//! and pnpm installs the package under that id. pnpm >= 10.34.2 matches a
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
//! decision carried when it is the only one. Each added key is a ledger
//! record that `vendor --revert` / `rollback` / `remove` take out again.
//! The user's own entries are never edited. A decision this line surgery
//! cannot extend (a flow-style value) is left alone and reported with the
//! key to add by hand.

use serde_json::Value;

use super::path::parse_vendor_path;
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

/// Warning code: the project decides the package's build in a form the
/// carry-over cannot extend, so pnpm stops applying that decision.
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
    pub name: &'a str,
    pub version: &'a str,
    /// The vendored tarball's root-relative path (`.socket/vendor/npm/…`).
    pub rel_tgz: &'a str,
}

impl Target<'_> {
    /// `name@file:<rel-tgz>`, the id pnpm installs the vendored copy as.
    fn key(&self) -> String {
        format!("{}@file:{}", self.name, self.rel_tgz)
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
            let ours = parse_vendor_path(self.rel_tgz)?;
            return parse_vendor_path(path)
                .filter(|p| p.eco == "npm" && p.leaf == ours.leaf && p.uuid != ours.uuid)
                .map(|_| Rank::Stale);
        }
        // pnpm's version specs: exact versions joined by `||`.
        rest.split("||")
            .any(|v| v.trim() == self.version)
            .then_some(Rank::Pinned)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Stale,
    Name,
    Pinned,
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
pub(super) fn carry(
    target: &Target<'_>,
    ws_text: Option<&str>,
    pkg: &mut Value,
    wiring: &mut Vec<WiringRecord>,
    warnings: &mut Vec<VendorWarning>,
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
                WsCarry::Inline => {
                    warnings.push(lost_warning(target, &format!("{PNPM_WORKSPACE} `{field}`")))
                }
            }
        }
        if changed {
            carried.ws_text = Some(lines.join("\n"));
        }
    }
    if let Some(table) = pkg.get_mut("pnpm").and_then(Value::as_object_mut) {
        if let Some(map) = table.get_mut(ALLOW_BUILDS).and_then(Value::as_object_mut) {
            let (changed, added) = carry_pkg_map(map, target);
            carried.pkg_changed |= changed;
            if let Some(value) = added {
                wiring.push(record(PACKAGE_JSON, KIND_PKG_ALLOW_BUILD, target, value));
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
        key: Some(target.key()),
        original: None,
        new: Some(value),
    }
}

fn lost_warning(target: &Target<'_>, surface: &str) -> VendorWarning {
    VendorWarning::new(
        VENDOR_PNPM_BUILD_APPROVAL_LOST,
        format!(
            "{surface} decides {}@{}'s install script by a key pnpm >= 10.34.2 no longer \
             matches once the package is vendored, and the value is not a block \
             mapping/sequence this rewriter can extend; add `{}` there with the same \
             decision, or pnpm skips the script (pnpm 10) or fails every install with \
             ERR_PNPM_IGNORED_BUILDS (pnpm 11+)",
            target.name,
            target.version,
            target.key(),
        ),
    )
}

/// The outcome of one `pnpm-workspace.yaml` field.
enum WsCarry {
    Unchanged,
    /// Lines were edited; `Some` carries the decision of a key added.
    Edited(Option<Value>),
    /// The field holds an inline (flow) value naming the package.
    Inline,
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
        let mut i = first;
        while i < lines.len() {
            let line = lines[i].strip_suffix('\r').unwrap_or(&lines[i]);
            if body(line) {
                let Some(item) = line
                    .strip_prefix(&" ".repeat(indent))
                    .and_then(|s| s.strip_prefix('-'))
                    .filter(|s| s.is_empty() || s.starts_with(' '))
                else {
                    break;
                };
                let item = strip_comment(item).trim();
                entries.push(WsEntry {
                    line: i,
                    key: unquote_value(item).to_string(),
                    value: String::new(),
                });
            }
            i += 1;
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

fn carry_ws(lines: &mut Vec<String>, field: &str, target: &Target<'_>) -> WsCarry {
    let Some((indent, entries)) = ws_entries(lines, field) else {
        let inline = lines.iter().any(|l| {
            top_level_key(l).is_some_and(|(key, value)| {
                key == field && !value.is_empty() && value.contains(target.name)
            })
        });
        return if inline {
            WsCarry::Inline
        } else {
            WsCarry::Unchanged
        };
    };
    let our_key = target.key();
    let ours = entries.iter().any(|e| e.key == our_key);
    let mut best: Option<(Rank, &WsEntry)> = None;
    let mut stale = Vec::new();
    for entry in &entries {
        let Some(rank) = target.rank(&entry.key) else {
            continue;
        };
        if rank == Rank::Stale {
            stale.push(entry.line);
        }
        if best.is_none_or(|(r, _)| rank > r) {
            best = Some((rank, entry));
        }
    }
    let Some((_, source)) = best else {
        return WsCarry::Unchanged;
    };
    let pad = " ".repeat(indent);
    let eol = if lines[source.line].ends_with('\r') {
        "\r"
    } else {
        ""
    };
    let (new_line, value) = if field == ONLY_BUILT {
        (
            format!("{pad}- '{our_key}'{eol}"),
            Value::String(our_key.clone()),
        )
    } else {
        (
            format!("{pad}{}: {}{eol}", yaml_key(&our_key), source.value),
            Value::String(source.value.clone()),
        )
    };
    let anchor = entries
        .iter()
        .filter(|e| target.rank(&e.key).is_some())
        .map(|e| e.line)
        .max()
        .unwrap_or(source.line);
    if !ours {
        lines.insert(anchor + 1, new_line);
    }
    // Stale lines all sit at or before the anchor, so the insert leaves
    // their indices alone; drop them last-first.
    for &i in stale.iter().rev() {
        lines.remove(i);
    }
    if ours {
        if stale.is_empty() {
            WsCarry::Unchanged
        } else {
            WsCarry::Edited(None)
        }
    } else {
        WsCarry::Edited(Some(value))
    }
}

fn carry_pkg_map(
    map: &mut serde_json::Map<String, Value>,
    target: &Target<'_>,
) -> (bool, Option<Value>) {
    let our_key = target.key();
    let mut best: Option<(Rank, Value)> = None;
    let mut stale = Vec::new();
    for (key, value) in map.iter() {
        let Some(rank) = target.rank(key) else {
            continue;
        };
        if rank == Rank::Stale {
            stale.push(key.clone());
        }
        if best.as_ref().is_none_or(|(r, _)| rank > *r) {
            best = Some((rank, value.clone()));
        }
    }
    let Some((_, value)) = best else {
        return (false, None);
    };
    for key in &stale {
        map.shift_remove(key);
    }
    if map.contains_key(&our_key) {
        return (!stale.is_empty(), None);
    }
    map.insert(our_key, value.clone());
    (true, Some(value))
}

fn carry_pkg_list(list: &mut Vec<Value>, target: &Target<'_>) -> (bool, Option<Value>) {
    let our_key = target.key();
    let ranked = |v: &Value| v.as_str().and_then(|s| target.rank(s));
    let Some(anchor) = list.iter().rposition(|v| ranked(v).is_some()) else {
        return (false, None);
    };
    let ours = list.iter().any(|v| v.as_str() == Some(our_key.as_str()));
    if !ours {
        list.insert(anchor + 1, Value::String(our_key.clone()));
    }
    let before = list.len();
    list.retain(|v| ranked(v) != Some(Rank::Stale));
    let removed = list.len() != before;
    if ours {
        (removed, None)
    } else {
        (true, Some(Value::String(our_key)))
    }
}

/// Take the keys `records` added out of `pnpm-workspace.yaml`'s lines. A
/// key already gone is converged. The key names this patch's own artifact,
/// which the revert removes, so a decision the user flipped since goes too.
pub(super) fn revert_ws(lines: &mut Vec<String>, records: &[&super::state::WiringRecord]) -> bool {
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

    fn target(rel: &str) -> Target<'_> {
        Target {
            name: "sp-build",
            version: "1.0.0",
            rel_tgz: rel,
        }
    }

    fn vendored_rel(uuid: &str) -> String {
        format!(".socket/vendor/npm/{uuid}/sp-build-1.0.0.tgz")
    }

    fn run_ws(text: &str) -> (Option<String>, Vec<WiringRecord>, Vec<VendorWarning>) {
        let rel = vendored_rel(UUID);
        let (mut wiring, mut warnings) = (Vec::new(), Vec::new());
        let mut pkg = serde_json::json!({});
        let out = carry(
            &target(&rel),
            Some(text),
            &mut pkg,
            &mut wiring,
            &mut warnings,
        );
        assert!(!out.pkg_changed);
        (out.ws_text, wiring, warnings)
    }

    #[test]
    fn rank_reads_pnpm_version_specs() {
        let rel = vendored_rel(UUID);
        let t = target(&rel);
        assert!(t.rank("sp-build") == Some(Rank::Name));
        assert!(t.rank("sp-build@1.0.0") == Some(Rank::Pinned));
        assert!(t.rank("sp-build@0.9.0 || 1.0.0") == Some(Rank::Pinned));
        assert!(t.rank("sp-build@2.0.0").is_none());
        assert!(t.rank("sp-build-native").is_none());
        assert!(t.rank(&format!("sp-build@file:{}", vendored_rel(OLD))) == Some(Rank::Stale));
        assert!(t.rank(&t.key()).is_none());
        assert!(t
            .rank("sp-build@file:.socket/vendor/npm/x/other-1.0.0.tgz")
            .is_none());
    }

    #[test]
    fn allow_builds_true_and_false_are_carried_after_the_users_entry() {
        for value in ["true", "false"] {
            let text = format!("packages:\n  - '.'\nallowBuilds:\n  esbuild: true\n  sp-build: {value} # native\n  zz: false\n");
            let (ws, wiring, warnings) = run_ws(&text);
            let key = format!("sp-build@file:{}", vendored_rel(UUID));
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
        let key = format!("sp-build@file:{}", vendored_rel(UUID));
        assert_eq!(ws.unwrap(), format!("{text}  {key}: false\n"));
    }

    #[test]
    fn only_built_list_gets_a_quoted_item_even_at_column_zero() {
        let key = format!("sp-build@file:{}", vendored_rel(UUID));
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
        let key = format!("sp-build@file:{}", vendored_rel(UUID));
        let synced = format!("allowBuilds:\n  sp-build: true\n  {key}: true\n");
        let (ws, wiring, _) = run_ws(&synced);
        assert!(ws.is_none() && wiring.is_empty());

        // Only the superseded patch's key decides: its decision carries.
        let old = format!("sp-build@file:{}", vendored_rel(OLD));
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

    #[test]
    fn inline_value_naming_the_package_warns_and_writes_nothing() {
        let (ws, wiring, warnings) = run_ws("onlyBuiltDependencies: [sp-build]\n");
        assert!(ws.is_none() && wiring.is_empty());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, VENDOR_PNPM_BUILD_APPROVAL_LOST);
        let (_, _, warnings) = run_ws("onlyBuiltDependencies: [esbuild]\n");
        assert!(warnings.is_empty());
    }

    #[test]
    fn package_json_fields_are_carried_and_reverted() {
        let rel = vendored_rel(UUID);
        let t = target(&rel);
        let key = t.key();
        let before = serde_json::json!({
            "pnpm": {
                "onlyBuiltDependencies": ["sp-build", "esbuild"],
                "allowBuilds": {"sp-build@1.0.0": false}
            }
        });
        let mut pkg = before.clone();
        let (mut wiring, mut warnings) = (Vec::new(), Vec::new());
        let out = carry(&t, None, &mut pkg, &mut wiring, &mut warnings);
        assert!(out.pkg_changed && out.ws_text.is_none());
        assert_eq!(
            pkg["pnpm"]["onlyBuiltDependencies"],
            serde_json::json!(["sp-build", key, "esbuild"])
        );
        assert_eq!(pkg["pnpm"]["allowBuilds"][&key], Value::Bool(false));
        assert_eq!(wiring.len(), 2);

        // In sync on a re-run.
        let mut again = Vec::new();
        assert!(!carry(&t, None, &mut pkg, &mut again, &mut warnings).pkg_changed);
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
        let t = Target {
            name: "@sp/pad",
            version: "1.0.0",
            rel_tgz: rel,
        };
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
