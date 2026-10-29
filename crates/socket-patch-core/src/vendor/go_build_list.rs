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

use std::cmp::Ordering;
use std::path::Path;

use crate::utils::fs::read_regular_to_string;

use super::go_mod_edit::{parse_replace_entries, parse_required_versions, prunes_module_graph};
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

/// [`Selection`] for `module@version` from the text of `go.mod` and (when
/// present) `go.sum`.
pub fn selection(go_mod: &str, go_sum: Option<&str>, module: &str, version: &str) -> Selection {
    let required = parse_required_versions(go_mod).remove(module);
    let zips: Vec<&str> = go_sum
        .map(|text| {
            go_sum_lines(text)
                .filter_map(|l| l.zip_version_of(module))
                .collect()
        })
        .unwrap_or_default();
    select(go_mod, module, required.as_deref(), &zips, version)
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
    // A zip line at the version a module-to-module replace targets is the
    // replacement's, not the module's own (see the module docs).
    let replaced = replaced_module(go_mod, module, version);
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

/// The module whose module-to-module `replace` in `go_mod` targets exactly
/// `module@version`, if any.
fn replaced_module(go_mod: &str, module: &str, version: &str) -> Option<String> {
    parse_replace_entries(go_mod)
        .into_iter()
        .find(|e| {
            e.module != module
                && e.rhs_module.as_deref() == Some(module)
                && e.rhs_version.as_deref() == Some(version)
        })
        .map(|e| e.module)
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
    Some(selection(&go_mod, go_sum.as_deref(), module, version))
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
