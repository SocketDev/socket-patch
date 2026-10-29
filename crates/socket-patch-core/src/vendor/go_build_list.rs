//! Offline answer to "does the build list select `module@version`?".
//!
//! Go keys a `replace` by module path **and version**, so a replace pinned
//! to a version the build list does not select is silently inert: the build
//! links the unpatched module and nothing warns. Every Go path that writes,
//! audits or attests such a replace (agent `apply`, `apply --check`, `vex`,
//! the hosted rewriter, vex lockfile discovery) asks this one question here
//! instead of keeping its own go.mod/go.sum heuristic (#391, #392, #509).
//!
//! The answer comes from the project's `go.mod` and `go.sum` only (no
//! toolchain, no network), so it works on a fresh clone in CI. In workspace
//! mode it is MVS over the module graph instead, which also needs the
//! dependencies' go.mod files from the module cache (see
//! [`super::go_workspace`]). In module mode:
//!
//! * **go ≥ 1.17** (pruned graph): `require` lists the selected version of
//!   every module that provides a package to the build, so it is
//!   authoritative. A module absent from `require` is built only if go.sum
//!   carries its zip line at that version.
//! * **go < 1.17** (or no `go` directive): `require` holds lower bounds and
//!   omits transitive modules. MVS selects the highest version the graph
//!   asks for, and go.sum records a zip (`h1:`) line for each version whose
//!   packages are built. A `/go.mod`-only line means MVS *read* that
//!   version's requirements, not that it selected it (#509). So the highest
//!   of the required version and the zip-line versions is the selected one.
//!   With no evidence at or above the patched version, the answer is
//!   [`Selection::Unknown`]: a directory `replace` makes `go mod tidy` drop
//!   the original's go.sum lines, so absence proves nothing.
//!
//! Either way, a zip line is no evidence when go.mod names that
//! module@version as the target of a module-to-module `replace`
//! (`replace other.com/fork v1.0.0 => example.com/upstream v1.0.0`): go
//! records the target's go.sum lines under the target's own path, but the
//! build list holds only the replaced module, and go doesn't apply a
//! replace to a replacement. go also refuses a build that uses one
//! module@version under two module paths, so the zip can't be from the
//! target being built in its own right. Such a module is
//! [`Selection::ReplaceTarget`] (#1823).
//!
//! Whether that replace is in effect turns on the version of the replaced
//! module the build selects. A pruned go.mod lists it. An unpruned one
//! omits a module only a dependency requires, yet its replace still
//! applies there (#1840), so that answer comes from the module graph read
//! from the module cache ([`module_graph`]).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::utils::fs::read_regular_to_string;

use super::go_mod_edit::{
    parse_replace_entries, parse_required_versions, prunes_module_graph, ReplaceEntry,
};
use super::go_sum_edit::{go_semver_cmp, go_sum_lines};

/// Whether the build list selects the patched version of a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The build selects exactly the patched version.
    Selected,
    /// The build selects this other version, so a replace pinned to the
    /// patched version is inert.
    Other(String),
    /// The module is not in the build at all (pruned graph only).
    NotInGraph,
    /// go.mod and go.sum hold no evidence either way.
    Unknown,
    /// The build compiles the patched version only as the replacement of
    /// this other module (go.mod's `replace <this> => <module> <version>`).
    /// go doesn't chain replaces, so a replace of the module itself is
    /// inert and the build links the unpatched code (#1823).
    ReplaceTarget(String),
}

impl Selection {
    /// The version the build selects instead of the patched one, when the
    /// files prove a replace pinned to the patched version is inert.
    pub fn other_version(&self) -> Option<&str> {
        match self {
            Selection::Other(v) => Some(v),
            _ => None,
        }
    }
}

/// What MVS selects over a module-mode project's whole module graph,
/// read from the module cache ([`module_graph`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraph {
    /// The selected version of each module the graph requires.
    pub selected: BTreeMap<String, String>,
    /// Every go.mod the graph needed was read, so a module missing from
    /// `selected` is not in the build.
    pub complete: bool,
}

/// [`Selection`] for `module@version` from the text of `go.mod` and (when
/// present) `go.sum`.
pub fn selection(go_mod: &str, go_sum: Option<&str>, module: &str, version: &str) -> Selection {
    selection_in(go_mod, go_sum, None, module, version)
}

/// [`selection`] with the project's [`ModuleGraph`], when read.
pub fn selection_in(
    go_mod: &str,
    go_sum: Option<&str>,
    graph: Option<&ModuleGraph>,
    module: &str,
    version: &str,
) -> Selection {
    let required = parse_required_versions(go_mod).remove(module);
    let zips: Vec<&str> = go_sum
        .map(|text| {
            go_sum_lines(text)
                .filter_map(|l| l.zip_version_of(module))
                .collect()
        })
        .unwrap_or_default();
    select_in(go_mod, graph, module, required.as_deref(), &zips, version)
}

/// [`selection`] from already-parsed parts: the root go.mod's text (whether
/// the graph is pruned, and its replaces), the module's `require` version,
/// and the versions go.sum holds a zip line for.
pub fn select(
    go_mod: &str,
    module: &str,
    required: Option<&str>,
    zips: &[&str],
    version: &str,
) -> Selection {
    select_in(go_mod, None, module, required, zips, version)
}

/// [`select`] with the project's [`ModuleGraph`], when read.
pub fn select_in(
    go_mod: &str,
    graph: Option<&ModuleGraph>,
    module: &str,
    required: Option<&str>,
    zips: &[&str],
    version: &str,
) -> Selection {
    // A zip line at the version a module-to-module replace targets is the
    // replacement's, not the module's own (see the module docs).
    let replaced = replaced_module(go_mod, graph, module, version);
    let zips: Vec<&str> = zips
        .iter()
        .copied()
        .filter(|z| replaced.is_none() || *z != version)
        .collect();
    let zips = zips.as_slice();
    let no_evidence = |fallback| match &replaced {
        Some(via) => Selection::ReplaceTarget(via.clone()),
        None => fallback,
    };
    if prunes_module_graph(go_mod) {
        return match required {
            Some(r) if r == version => Selection::Selected,
            Some(r) => Selection::Other(r.to_string()),
            None if zips.contains(&version) => Selection::Selected,
            None => no_evidence(Selection::NotInGraph),
        };
    }
    let highest = required
        .into_iter()
        .chain(zips.iter().copied())
        .max_by(|a, b| go_semver_cmp(a, b));
    match highest {
        Some(h) if h == version => Selection::Selected,
        Some(h) if go_semver_cmp(h, version) == Ordering::Greater => {
            Selection::Other(h.to_string())
        }
        // Everything is below the patched version. A zip line there shows
        // that lower version is the one built (go records no zip line for
        // the patched version only once a directory replace covers it).
        Some(h) if zips.contains(&h) => Selection::Other(h.to_string()),
        _ => no_evidence(Selection::Unknown),
    }
}

/// The module-to-module replaces in `go_mod` whose target is exactly
/// `module@version`.
fn replaces_targeting<'a>(
    entries: &'a [ReplaceEntry],
    module: &'a str,
    version: &'a str,
) -> impl Iterator<Item = &'a ReplaceEntry> {
    entries.iter().filter(move |e| {
        e.module != module
            && e.rhs_module.as_deref() == Some(module)
            && e.rhs_version.as_deref() == Some(version)
    })
}

/// Whether [`select`]'s answer for `module@version` can turn on the
/// [`ModuleGraph`]: an unpruned go.mod with a module-to-module replace
/// targeting it. Only then is the graph worth reading.
pub fn needs_module_graph(go_mod: &str, module: &str, version: &str) -> bool {
    !prunes_module_graph(go_mod)
        && replaces_targeting(&parse_replace_entries(go_mod), module, version)
            .next()
            .is_some()
}

/// Whether any answer of [`select`] over `go_mod` can turn on the
/// [`ModuleGraph`] ([`needs_module_graph`] for every module).
pub fn may_need_module_graph(go_mod: &str) -> bool {
    !prunes_module_graph(go_mod)
        && parse_replace_entries(go_mod)
            .iter()
            .any(|e| e.rhs_module.is_some() && e.rhs_version.is_some())
}

/// The module whose module-to-module `replace` in `go_mod` targets exactly
/// `module@version`, if that replace is the one in effect: the build
/// selects the replaced module, and no replace pinned to its selected
/// version shadows a version-less one (go prefers the versioned replace).
/// `go mod tidy` keeps unused replaces, so one of a module the build
/// doesn't use, or pinned to a version it doesn't select, explains nothing.
///
/// A pruned go.mod's `require` holds the selected version. An unpruned
/// one's holds only lower bounds and omits modules only a dependency
/// requires, so `graph` answers there (#1840). Without a complete graph a
/// replace of a module go.mod doesn't list counts as in effect (the safe
/// side: no patch is reported built that isn't), unless go.mod requires
/// `module@version` itself: that puts it in the build under its own path,
/// and go refuses one module@version under two.
fn replaced_module(
    go_mod: &str,
    graph: Option<&ModuleGraph>,
    module: &str,
    version: &str,
) -> Option<String> {
    let pruned = prunes_module_graph(go_mod);
    let required = parse_required_versions(go_mod);
    let entries = parse_replace_entries(go_mod);
    // The version of `fork` the build selects: `Some(None)` when it isn't
    // in the build, `None` when the files can't tell.
    let selected = |fork: &str| -> Option<Option<String>> {
        if pruned {
            return Some(required.get(fork).cloned());
        }
        if let Some(graph) = graph {
            if let Some(v) = graph.selected.get(fork) {
                return Some(Some(v.clone()));
            }
            if graph.complete {
                return Some(None);
            }
        }
        required.get(fork).map(|v| Some(v.clone()))
    };
    let in_effect = replaces_targeting(&entries, module, version)
        .find(|e| match selected(&e.module) {
            Some(Some(sel)) => match e.version.as_deref() {
                Some(v) => v == sel,
                None => !entries
                    .iter()
                    .any(|o| o.module == e.module && o.version.as_deref() == Some(sel.as_str())),
            },
            Some(None) => false,
            None => required.get(module).map(String::as_str) != Some(version),
        })
        .map(|e| e.module.clone());
    in_effect
}

/// The [`ModuleGraph`] of the module-mode project at `project_root`, read
/// from the module cache, when [`needs_module_graph`] says the answer for
/// `module@version` can turn on it.
pub async fn module_graph_for(
    project_root: &Path,
    go_mod: &str,
    module: &str,
    version: &str,
) -> Option<ModuleGraph> {
    if !needs_module_graph(go_mod, module, version) {
        return None;
    }
    let cache = crate::crawlers::go_crawler::GoCrawler::get_gomodcache();
    Some(super::go_workspace::module_graph(project_root, go_mod, cache.as_deref()).await)
}

/// [`selection`] for a project directory. In workspace mode the build
/// list spans every `use` member's module graph, so the answer is the
/// workspace's ([`super::go_workspace::GoWorkspace::selection`] after
/// [`super::go_workspace::GoWorkspace::read_graph`]), unknown when go
/// refuses the workspace. Otherwise it reads `<project_root>/go.mod`
/// and `go.sum` (`None` when there is no readable go.mod).
pub async fn project_selection(
    project_root: &Path,
    module: &str,
    version: &str,
) -> Option<Selection> {
    match super::go_workspace::load(project_root).await {
        super::go_workspace::Loaded::Workspace(mut ws) => {
            ws.read_graph().await;
            return Some(ws.selection(module, version));
        }
        super::go_workspace::Loaded::Invalid(_) => return Some(Selection::Unknown),
        super::go_workspace::Loaded::None => {}
    }
    let go_mod = read_regular_to_string(&project_root.join("go.mod"))
        .await
        .ok()?;
    let go_sum = read_regular_to_string(&project_root.join("go.sum"))
        .await
        .ok();
    let graph = module_graph_for(project_root, &go_mod, module, version).await;
    Some(selection_in(
        &go_mod,
        go_sum.as_deref(),
        graph.as_ref(),
        module,
        version,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UP: &str = "example.com/upstream";

    fn sum(lines: &[&str]) -> String {
        lines.iter().map(|l| format!("{l} h1:x=\n")).collect()
    }

    #[test]
    fn pruned_graph_trusts_require() {
        let m = format!("module c\n\ngo 1.21\n\nrequire {UP} v1.0.1 // indirect\n");
        assert_eq!(
            selection(&m, None, UP, "v1.0.0"),
            Selection::Other("v1.0.1".into())
        );
        assert_eq!(selection(&m, None, UP, "v1.0.1"), Selection::Selected);
    }

    #[test]
    fn pruned_graph_without_require_is_not_in_graph() {
        let m = "module c\n\ngo 1.21\n";
        assert_eq!(selection(m, None, UP, "v1.0.0"), Selection::NotInGraph);
        let s = sum(&[&format!("{UP} v1.0.0/go.mod")]);
        assert_eq!(selection(m, Some(&s), UP, "v1.0.0"), Selection::NotInGraph);
        let s = sum(&[&format!("{UP} v1.0.0"), &format!("{UP} v1.0.0/go.mod")]);
        assert_eq!(selection(m, Some(&s), UP, "v1.0.0"), Selection::Selected);
    }

    /// #509 / #392: in a go 1.16 graph a losing version keeps only its
    /// `/go.mod` line, and the selected version has the zip line.
    #[test]
    fn unpruned_graph_reads_the_selected_version_from_zip_lines() {
        let m = "module c\n\ngo 1.16\n\nrequire (\n\texample.com/mida v1.0.0\n\texample.com/midb v1.0.0\n)\n";
        let s = sum(&[
            &format!("{UP} v1.0.0/go.mod"),
            &format!("{UP} v1.0.1"),
            &format!("{UP} v1.0.1/go.mod"),
        ]);
        assert_eq!(
            selection(m, Some(&s), UP, "v1.0.0"),
            Selection::Other("v1.0.1".into())
        );
        assert_eq!(selection(m, Some(&s), UP, "v1.0.1"), Selection::Selected);
    }

    #[test]
    fn unpruned_require_is_a_lower_bound() {
        let m = format!("module c\n\ngo 1.16\n\nrequire {UP} v1.0.0\n");
        let s = sum(&[&format!("{UP} v1.0.1")]);
        assert_eq!(
            selection(&m, Some(&s), UP, "v1.0.0"),
            Selection::Other("v1.0.1".into())
        );
        // A tidied directory replace drops the original's go.sum lines.
        assert_eq!(selection(&m, Some(""), UP, "v1.0.0"), Selection::Selected);
        // Only a lower bound below the patched version: can't tell.
        assert_eq!(selection(&m, None, UP, "v1.2.0"), Selection::Unknown);
        // A zip line below it shows the lower version is built.
        let s = sum(&[&format!("{UP} v1.0.0")]);
        assert_eq!(
            selection(&m, Some(&s), UP, "v1.2.0"),
            Selection::Other("v1.0.0".into())
        );
    }

    #[test]
    fn missing_go_directive_is_unpruned() {
        let m = "module c\n";
        assert_eq!(selection(m, None, UP, "v1.0.0"), Selection::Unknown);
        let s = sum(&[&format!("{UP} v1.0.1")]);
        assert_eq!(
            selection(m, Some(&s), UP, "v1.0.0"),
            Selection::Other("v1.0.1".into())
        );
    }

    #[test]
    fn go_directive_versions() {
        for (d, pruned) in [
            ("go 1.16", false),
            ("go 1.17", true),
            ("go 1.21.0", true),
            ("go 1.9", false),
            ("go 1.22rc1", true),
            ("go 2.0", true),
            ("go \t1.24 // pinned", true),
        ] {
            assert_eq!(
                prunes_module_graph(&format!("module c\n\n{d}\n")),
                pruned,
                "{d}"
            );
        }
        assert!(!prunes_module_graph("module c\ngodebug default=go1.21\n"));
    }

    /// #1823: go records a module-to-module replace target's go.sum lines
    /// under the target's path, but the build list holds only the replaced
    /// module, so the zip line is no evidence the target itself is built.
    #[test]
    fn replace_target_zip_is_not_the_module_built() {
        let s = sum(&[&format!("{UP} v1.0.0"), &format!("{UP} v1.0.0/go.mod")]);
        let via = Selection::ReplaceTarget("other.com/fork".into());
        for go in ["go 1.21", "go 1.16", ""] {
            for replace in [
                format!("replace other.com/fork v1.0.0 => {UP} v1.0.0"),
                format!("replace other.com/fork => {UP} v1.0.0"),
                format!("replace (\n\tother.com/fork => {UP} v1.0.0\n)"),
            ] {
                let m = format!("module c\n\n{go}\n\nrequire other.com/fork v1.0.0\n\n{replace}\n");
                assert_eq!(
                    selection(&m, Some(&s), UP, "v1.0.0"),
                    via,
                    "{go} / {replace}"
                );
            }
        }
    }

    /// `go mod tidy` keeps unused replaces: one of a module go.mod doesn't
    /// require, one pinned to another version than the required one, or a
    /// version-less one a versioned replace shadows doesn't explain the zip.
    #[test]
    fn inactive_replace_target_keeps_the_zip_as_evidence() {
        let s = sum(&[&format!("{UP} v1.0.0")]);
        for go in ["go 1.21", "go 1.16"] {
            // A pruned graph lists every module it builds, so a fork the
            // root go.mod doesn't require is not in the build.
            let unrequired =
                (go == "go 1.21").then(|| ("", format!("replace other.com/fork => {UP} v1.0.0")));
            for (require, replace) in unrequired.into_iter().chain([
                (
                    "require other.com/fork v1.0.0\n",
                    format!("replace other.com/fork v0.5.0 => {UP} v1.0.0"),
                ),
                (
                    "require other.com/fork v1.0.0\n",
                    format!(
                        "replace other.com/fork => {UP} v1.0.0\n\
                         replace other.com/fork v1.0.0 => ../fork"
                    ),
                ),
            ]) {
                let m = format!("module c\n\n{go}\n\n{require}\n{replace}\n");
                assert_eq!(
                    selection(&m, Some(&s), UP, "v1.0.0"),
                    Selection::Selected,
                    "{go} / {replace}"
                );
            }
        }
    }

    /// #1840: an unpruned graph (go 1.16, or no `go` directive) omits from
    /// the root go.mod a fork only a dependency requires, but the root's
    /// replace still applies to it, so the zip line is the fork's.
    #[test]
    fn unpruned_replace_of_a_transitive_fork_is_a_replace_target() {
        let s = sum(&[&format!("{UP} v1.0.0"), &format!("{UP} v1.0.0/go.mod")]);
        let via = Selection::ReplaceTarget("other.com/fork".into());
        for go in ["go 1.16", ""] {
            for replace in [
                format!("replace other.com/fork => {UP} v1.0.0"),
                format!("replace other.com/fork v1.0.0 => {UP} v1.0.0"),
                format!("replace (\n\tother.com/fork => {UP} v1.0.0\n)"),
            ] {
                let m =
                    format!("module c\n\n{go}\n\nrequire example.com/mid v1.0.0\n\n{replace}\n");
                assert_eq!(
                    selection(&m, Some(&s), UP, "v1.0.0"),
                    via,
                    "{go} / {replace}"
                );
                // No zip line at all: still built only as the replacement.
                assert_eq!(selection(&m, None, UP, "v1.0.0"), via, "{go} / {replace}");
            }
        }
    }

    fn graph(selected: &[(&str, &str)], complete: bool) -> ModuleGraph {
        ModuleGraph {
            selected: selected
                .iter()
                .map(|(m, v)| (m.to_string(), v.to_string()))
                .collect(),
            complete,
        }
    }

    /// With the module graph read, the replaced module's selected version
    /// settles a go 1.16 fork replace either way: one `go mod tidy` kept
    /// though nothing requires the fork explains nothing (the module is
    /// built in its own right), and one a dependency raised the fork to
    /// applies although go.mod requires a lower version.
    #[test]
    fn unpruned_module_graph_settles_the_fork_replace() {
        let s = sum(&[&format!("{UP} v1.0.0")]);
        let via = Selection::ReplaceTarget("other.com/fork".into());
        let m = format!(
            "module c\n\ngo 1.16\n\nrequire example.com/mid v1.0.0\n\n\
             replace other.com/fork => {UP} v1.0.0\n"
        );
        let stale = graph(&[("example.com/mid", "v1.0.0"), (UP, "v1.0.0")], true);
        assert_eq!(
            selection_in(&m, Some(&s), Some(&stale), UP, "v1.0.0"),
            Selection::Selected
        );
        let forked = graph(
            &[("example.com/mid", "v1.0.0"), ("other.com/fork", "v1.0.0")],
            true,
        );
        assert_eq!(selection_in(&m, Some(&s), Some(&forked), UP, "v1.0.0"), via);
        // A graph missing go.mod files can't show the fork is absent.
        let partial = graph(&[("example.com/mid", "v1.0.0")], false);
        assert_eq!(
            selection_in(&m, Some(&s), Some(&partial), UP, "v1.0.0"),
            via
        );

        // go.mod requires fork v0.9.0, a dependency raises it to v1.0.0,
        // where the versioned replace applies.
        let m = format!(
            "module c\n\ngo 1.16\n\nrequire other.com/fork v0.9.0\n\n\
             replace other.com/fork v1.0.0 => {UP} v1.0.0\n"
        );
        assert_eq!(selection(&m, Some(&s), UP, "v1.0.0"), Selection::Selected);
        let raised = graph(&[("other.com/fork", "v1.0.0")], true);
        assert_eq!(selection_in(&m, Some(&s), Some(&raised), UP, "v1.0.0"), via);
        // At another version, a versioned replace pinned there wins over the
        // version-less one.
        let m = format!(
            "module c\n\ngo 1.16\n\nrequire example.com/mid v1.0.0\n\n\
             replace other.com/fork => {UP} v1.0.0\n\
             replace other.com/fork v1.1.0 => ../fork\n"
        );
        let shadowed = graph(&[("other.com/fork", "v1.1.0")], true);
        assert_eq!(
            selection_in(&m, Some(&s), Some(&shadowed), UP, "v1.0.0"),
            Selection::Selected
        );
        // A pruned go.mod lists what it builds: the graph isn't consulted.
        let m = format!("module c\n\ngo 1.21\n\nreplace other.com/fork => {UP} v1.0.0\n");
        assert_eq!(
            selection_in(&m, Some(&s), Some(&forked), UP, "v1.0.0"),
            Selection::Selected
        );
    }

    #[test]
    fn module_graph_is_needed_only_for_an_unpruned_fork_replace() {
        let fork = format!("replace other.com/fork => {UP} v1.0.0\n");
        for (go, replace, needed) in [
            ("go 1.16", fork.as_str(), true),
            ("", fork.as_str(), true),
            ("go 1.21", fork.as_str(), false),
            ("go 1.16", "replace other.com/fork => ../fork\n", false),
            ("go 1.16", "", false),
        ] {
            let m = format!("module c\n\n{go}\n\n{replace}");
            assert_eq!(needs_module_graph(&m, UP, "v1.0.0"), needed, "{m}");
            assert_eq!(may_need_module_graph(&m), needed, "{m}");
        }
        let m = format!("module c\n\ngo 1.16\n\n{fork}");
        assert!(!needs_module_graph(&m, UP, "v1.1.0"));
    }

    /// Without the graph, go.mod's require of a lower version of the
    /// module doesn't put `module@version` itself in the build: go builds
    /// v0.9.0 under its own path and v1.0.0 only as the fork.
    #[test]
    fn unpruned_root_require_of_another_version_keeps_the_fork_replace() {
        let m = format!(
            "module c\n\ngo 1.16\n\nrequire (\n\t{UP} v0.9.0\n\texample.com/mid v1.0.0\n)\n\n\
             replace other.com/fork => {UP} v1.0.0\n"
        );
        let s = sum(&[&format!("{UP} v1.0.0")]);
        assert_eq!(
            selection(&m, Some(&s), UP, "v1.0.0"),
            Selection::ReplaceTarget("other.com/fork".into())
        );
    }

    /// A root require of the module puts it in the build under its own
    /// path, and go refuses one module@version under two paths, so a
    /// replace of an unrequired fork can't explain its zip line.
    #[test]
    fn unpruned_root_require_of_the_module_keeps_its_zip() {
        let m = format!(
            "module c\n\ngo 1.16\n\nrequire {UP} v1.0.0\n\n\
             replace other.com/fork => {UP} v1.0.0\n"
        );
        let s = sum(&[&format!("{UP} v1.0.0")]);
        assert_eq!(selection(&m, Some(&s), UP, "v1.0.0"), Selection::Selected);
    }

    #[test]
    fn replace_target_at_another_version_keeps_its_own_evidence() {
        // The fork targets v1.0.0; a zip line at v1.1.0 is the module's own.
        let m = format!(
            "module c\n\ngo 1.21\n\nrequire other.com/fork v1.0.0\n\n\
             replace other.com/fork => {UP} v1.0.0\n"
        );
        let s = sum(&[&format!("{UP} v1.0.0"), &format!("{UP} v1.1.0")]);
        assert_eq!(selection(&m, Some(&s), UP, "v1.1.0"), Selection::Selected);
        // A require of the module still decides in a pruned graph.
        let m = format!(
            "module c\n\ngo 1.21\n\nrequire {UP} v1.2.0\n\n\
             replace other.com/fork => {UP} v1.0.0\n"
        );
        assert_eq!(
            selection(&m, Some(&s), UP, "v1.0.0"),
            Selection::Other("v1.2.0".into())
        );
        // A directory replace of the fork, or a replace of the module
        // itself, is not a module-to-module target.
        for replace in [
            "replace other.com/fork => ../fork".to_string(),
            format!("replace {UP} v1.0.0 => ./.socket/go-patches/{UP}@v1.0.0"),
        ] {
            let m = format!("module c\n\ngo 1.21\n\n{replace}\n");
            let s = sum(&[&format!("{UP} v1.0.0")]);
            assert_eq!(selection(&m, Some(&s), UP, "v1.0.0"), Selection::Selected);
        }
    }

    #[test]
    fn incompatible_versions_compare_exactly() {
        let m = format!("module c\n\ngo 1.21\n\nrequire {UP} v2.0.0+incompatible\n");
        assert_eq!(
            selection(&m, None, UP, "v2.0.0+incompatible"),
            Selection::Selected
        );
    }
}
