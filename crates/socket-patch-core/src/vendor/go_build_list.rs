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
//! toolchain, no network), so it works on a fresh clone in CI:
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

use std::cmp::Ordering;
use std::path::Path;

use crate::utils::fs::read_regular_to_string;

use super::go_mod_edit::{parse_required_versions, prunes_module_graph};
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
                .filter(|l| !l.go_mod && l.module == module)
                .map(|l| l.version)
                .collect()
        })
        .unwrap_or_default();
    select(
        prunes_module_graph(go_mod),
        required.as_deref(),
        &zips,
        version,
    )
}

/// [`selection`] from already-parsed parts: whether the graph is pruned,
/// the module's `require` version, and the versions go.sum holds a zip line
/// for.
pub fn select(pruned: bool, required: Option<&str>, zips: &[&str], version: &str) -> Selection {
    if pruned {
        return match required {
            Some(r) if r == version => Selection::Selected,
            Some(r) => Selection::Other(r.to_string()),
            None if zips.contains(&version) => Selection::Selected,
            None => Selection::NotInGraph,
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
        _ => Selection::Unknown,
    }
}

/// [`selection`] for a project directory: reads `<project_root>/go.mod` and
/// `go.sum` (`None` when there is no readable go.mod). In workspace mode the
/// build list also takes other members' requirements, so a module absent
/// from this go.mod may still be built: [`Selection::NotInGraph`] becomes
/// [`Selection::Unknown`] there.
pub async fn project_selection(
    project_root: &Path,
    module: &str,
    version: &str,
) -> Option<Selection> {
    let go_mod = read_regular_to_string(&project_root.join("go.mod"))
        .await
        .ok()?;
    let go_sum = read_regular_to_string(&project_root.join("go.sum"))
        .await
        .ok();
    let sel = selection(&go_mod, go_sum.as_deref(), module, version);
    if sel == Selection::NotInGraph && super::go_consumer_sync::workspace_in_effect(project_root) {
        return Some(Selection::Unknown);
    }
    Some(sel)
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

    #[test]
    fn incompatible_versions_compare_exactly() {
        let m = format!("module c\n\ngo 1.21\n\nrequire {UP} v2.0.0+incompatible\n");
        assert_eq!(
            selection(&m, None, UP, "v2.0.0+incompatible"),
            Selection::Selected
        );
    }
}
