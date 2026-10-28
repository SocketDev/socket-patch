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
use std::collections::HashMap;
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
                .filter_map(|l| l.zip_version_of(module))
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
        // Everything is below the patched version. A zip line there shows
        // that lower version is the one built (go records no zip line for
        // the patched version only once a directory replace covers it).
        Some(h) if zips.contains(&h) => Selection::Other(h.to_string()),
        _ => Selection::Unknown,
    }
}

/// [`selection`] for a project directory: reads `<project_root>/go.mod` and
/// `go.sum` (`None` when there is no readable go.mod).
///
/// In workspace mode the build list also takes every `use` member's
/// requirements, so their go.mod/go.sum are weighed too
/// ([`workspace_selection`]).
pub async fn project_selection(
    project_root: &Path,
    module: &str,
    version: &str,
) -> Option<Selection> {
    let own = dir_selection(project_root, module, version).await?;
    let Some(dirs) = super::go_consumer_sync::workspace_member_dirs(project_root).await else {
        return Some(own);
    };
    let mut members = Vec::new();
    for dir in dirs {
        members.extend(dir_selection(&dir, module, version).await);
    }
    Some(workspace_selection(own, members, version))
}

/// What one go.work member's `go.mod` and `go.sum` prove about the
/// versions it builds, parsed once for every module asked about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleEvidence {
    pruned: bool,
    required: HashMap<String, String>,
    zips: HashMap<String, Vec<String>>,
}

impl ModuleEvidence {
    pub fn from_files(go_mod: &str, go_sum: Option<&str>) -> Self {
        let mut zips: HashMap<String, Vec<String>> = HashMap::new();
        for line in go_sum.into_iter().flat_map(go_sum_lines) {
            if !line.go_mod {
                let versions = zips.entry(line.module.to_string()).or_default();
                versions.push(line.version.to_string());
            }
        }
        Self {
            pruned: prunes_module_graph(go_mod),
            required: parse_required_versions(go_mod),
            zips,
        }
    }

    /// [`selection`] for `module@version` from these files.
    pub fn selection(&self, module: &str, version: &str) -> Selection {
        let zips: Vec<&str> = self
            .zips
            .get(module)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        select(
            self.pruned,
            self.required.get(module).map(String::as_str),
            &zips,
            version,
        )
    }
}

/// The evidence of every other `use` member of the go.work in effect for
/// `project_root` (empty outside a workspace), read on the calling thread.
/// A member whose go.mod can't be read is left out, as
/// [`project_selection`] skips it.
pub fn other_workspace_members(project_root: &Path) -> Vec<ModuleEvidence> {
    use super::go_consumer_sync::{same_dir_key, workspace_member_dirs_sync};
    use crate::utils::fs::read_regular_to_string_sync;
    let Some(dirs) = workspace_member_dirs_sync(project_root) else {
        return Vec::new();
    };
    let root = same_dir_key(project_root);
    dirs.into_iter()
        .filter(|dir| same_dir_key(dir) != root)
        .filter_map(|dir| {
            let go_mod = read_regular_to_string_sync(&dir.join("go.mod")).ok()?;
            let go_sum = read_regular_to_string_sync(&dir.join("go.sum")).ok();
            Some(ModuleEvidence::from_files(&go_mod, go_sum.as_deref()))
        })
        .collect()
}

/// The selection for the whole workspace, from this module's own
/// [`Selection`] (`own`) and each other member's.
///
/// MVS selects the highest version any member asks for (#1751). So a
/// version another member proves is weighed with this one's, and a module
/// absent from this go.mod may still be built: [`Selection::NotInGraph`]
/// becomes [`Selection::Unknown`] unless a member proves the version.
pub fn workspace_selection(
    own: Selection,
    members: impl IntoIterator<Item = Selection>,
    version: &str,
) -> Selection {
    let mut highest = evidence(&own, version);
    // A member whose files can't tell may build a higher version than the
    // highest one proven, so then only a proof at or above ours decides.
    let mut unknown = own == Selection::Unknown;
    for member in members {
        unknown |= member == Selection::Unknown;
        if let Some(v) = evidence(&member, version) {
            if highest
                .as_deref()
                .is_none_or(|h| go_semver_cmp(&v, h) == Ordering::Greater)
            {
                highest = Some(v);
            }
        }
    }
    match highest {
        Some(h) if h == version => Selection::Selected,
        Some(h) if !unknown || go_semver_cmp(&h, version) == Ordering::Greater => {
            Selection::Other(h)
        }
        _ if own == Selection::NotInGraph => Selection::Unknown,
        _ => own,
    }
}

/// [`selection`] from `<dir>/go.mod` and `go.sum`, ignoring any workspace.
async fn dir_selection(dir: &Path, module: &str, version: &str) -> Option<Selection> {
    let go_mod = read_regular_to_string(&dir.join("go.mod")).await.ok()?;
    let go_sum = read_regular_to_string(&dir.join("go.sum")).await.ok();
    Some(selection(&go_mod, go_sum.as_deref(), module, version))
}

/// The version a module's own go.mod and go.sum prove it builds, if any.
fn evidence(sel: &Selection, version: &str) -> Option<String> {
    match sel {
        Selection::Selected => Some(version.to_string()),
        Selection::Other(v) => Some(v.clone()),
        Selection::NotInGraph | Selection::Unknown => None,
    }
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

    fn module(dir: &Path, name: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let m = format!("module example.com/{name}\n\ngo 1.21\n\nrequire {UP} {version}\n");
        std::fs::write(dir.join("go.mod"), m).unwrap();
        let s = sum(&[
            &format!("{UP} {version}"),
            &format!("{UP} {version}/go.mod"),
        ]);
        std::fs::write(dir.join("go.sum"), s).unwrap();
    }

    /// #1751: a go.work build list takes every `use` member's requirements,
    /// so another member's higher version is the one built, and a replace
    /// pinned to this member's lower version is inert.
    #[tokio::test]
    async fn workspace_member_requiring_a_higher_version_wins() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (a, b) = (ws.join("a"), ws.join("b"));
        module(&a, "a", "v1.0.0");
        module(&b, "b", "v1.1.0");
        assert_eq!(
            project_selection(&a, UP, "v1.0.0").await,
            Some(Selection::Selected),
            "outside a workspace only a's go.mod counts"
        );
        std::fs::write(ws.join("go.work"), "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n").unwrap();
        assert_eq!(
            project_selection(&a, UP, "v1.0.0").await,
            Some(Selection::Other("v1.1.0".into()))
        );
        // b's own version is the workspace's.
        assert_eq!(
            project_selection(&b, UP, "v1.1.0").await,
            Some(Selection::Selected)
        );
        // A member that doesn't require the module is built at the version
        // another member selects.
        std::fs::write(a.join("go.mod"), "module example.com/a\n\ngo 1.21\n").unwrap();
        assert_eq!(
            project_selection(&a, UP, "v1.0.0").await,
            Some(Selection::Other("v1.1.0".into()))
        );
        assert_eq!(
            project_selection(&a, UP, "v1.1.0").await,
            Some(Selection::Selected)
        );
    }

    /// #1753: the hosted rewriter gets every member but the scanned one; a
    /// member without a go.mod is left out, and outside a workspace there
    /// are none.
    #[test]
    fn other_workspace_members_reads_every_member_but_this_one() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (a, b, c) = (ws.join("a"), ws.join("b"), ws.join("c"));
        module(&a, "a", "v1.0.0");
        module(&b, "b", "v1.1.0");
        std::fs::create_dir_all(&c).unwrap();
        assert!(other_workspace_members(&a).is_empty());
        std::fs::write(
            ws.join("go.work"),
            "go 1.21\n\nuse (\n\t./a\n\t./b/\n\t./c\n)\n",
        )
        .unwrap();
        let members = other_workspace_members(&a);
        assert_eq!(members.len(), 1, "{members:?}");
        assert_eq!(
            members[0].selection(UP, "v1.0.0"),
            Selection::Other("v1.1.0".into())
        );
        let members = other_workspace_members(&b);
        assert_eq!(members.len(), 1, "{members:?}");
        assert_eq!(members[0].selection(UP, "v1.0.0"), Selection::Selected);
    }

    /// A version below the patched one counts when it is the highest any
    /// member proves, unless a member's files can't tell.
    #[tokio::test]
    async fn workspace_lower_versions_decide_only_without_unknown_members() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (a, b, c) = (ws.join("a"), ws.join("b"), ws.join("c"));
        module(&a, "a", "v1.0.0");
        module(&b, "b", "v1.0.5");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(c.join("go.mod"), "module example.com/c\n\ngo 1.21\n").unwrap();
        std::fs::write(
            ws.join("go.work"),
            "go 1.21\n\nuse (\n\t./a\n\t./b\n\t./c\n)\n",
        )
        .unwrap();
        for project in [&a, &c] {
            assert_eq!(
                project_selection(project, UP, "v1.1.0").await,
                Some(Selection::Other("v1.0.5".into()))
            );
        }
        // An old-style member with only a lower bound may build anything.
        std::fs::write(
            b.join("go.mod"),
            format!("module example.com/b\n\ngo 1.16\n\nrequire {UP} v1.0.5\n"),
        )
        .unwrap();
        std::fs::write(b.join("go.sum"), "").unwrap();
        assert_eq!(
            project_selection(&c, UP, "v1.1.0").await,
            Some(Selection::Unknown)
        );
        assert_eq!(
            project_selection(&a, UP, "v1.1.0").await,
            Some(Selection::Other("v1.0.0".into()))
        );
    }

    /// A member requiring a lower version doesn't move the workspace off
    /// this member's higher one, and a member go.work doesn't `use` counts
    /// for nothing.
    #[tokio::test]
    async fn workspace_lower_or_unused_members_do_not_change_the_selection() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (a, b, c) = (ws.join("a"), ws.join("b"), ws.join("c"));
        module(&a, "a", "v1.1.0");
        module(&b, "b", "v1.0.0");
        module(&c, "c", "v1.2.0");
        std::fs::write(ws.join("go.work"), "go 1.21\n\nuse ./a\nuse ./b\n").unwrap();
        assert_eq!(
            project_selection(&a, UP, "v1.1.0").await,
            Some(Selection::Selected)
        );
        assert_eq!(
            project_selection(&b, UP, "v1.0.0").await,
            Some(Selection::Other("v1.1.0".into()))
        );
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
