//! Where pnpm keeps a project's install: its modules dirs.
//!
//! pnpm installs into `node_modules` unless `modulesDir` says otherwise
//! (`modulesDir:` in `pnpm-workspace.yaml`, `modules-dir` in `.npmrc` up to
//! pnpm 10), and from pnpm 10.12 its virtual store follows
//! (`<modulesDir>/.pnpm`). The npm crawler (crawl roots), the layout
//! detector ([`super::pkg_managers`]) and the vendored router all ask this
//! one module, so they agree on where a pnpm install lives (#1129).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::utils::fs::read_dir_entries_sync;
use crate::vendor::lock_inventory::ProjectView;

/// The install record pnpm writes into whatever modules dir it used.
pub(crate) const MODULES_YAML: &str = ".modules.yaml";

/// The project's pnpm `modulesDir` install roots, other than
/// `node_modules` itself, without repeats:
/// - the configured setting ([`modules_dir_setting`]), resolved against
///   the project like pnpm does, and honored only strictly inside it (the
///   value comes from the scanned project and names a tree apply WRITES
///   into; see [`super::npm_crawler::resolve_modules_folder`]);
/// - any direct child dir holding pnpm's [`MODULES_YAML`] install record.
///   That finds an install whose `modulesDir` came from pnpm's global
///   config or the environment, which the project's files do not show.
pub(crate) fn configured_modules_dirs(project: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = modules_dir_setting(project)
        .and_then(|raw| super::npm_crawler::resolve_modules_folder(&[], &raw))
    {
        dirs.push(project.join(dir));
    }
    let Some((entries, _)) = read_dir_entries_sync(project) else {
        return dirs;
    };
    for entry in entries {
        let name = entry.file_name();
        if name == OsStr::new("node_modules") || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = project.join(name);
        if !dirs.contains(&dir)
            && std::fs::symlink_metadata(dir.join(MODULES_YAML)).is_ok_and(|m| m.is_file())
        {
            dirs.push(dir);
        }
    }
    dirs
}

/// Whether the project holds an installed pnpm store: a [`MODULES_YAML`]
/// record or a `.pnpm` virtual store in `node_modules` or in one of its
/// [`configured_modules_dirs`]. The configured dirs are read only when
/// `node_modules` holds neither.
pub(crate) fn installed_store_in(view: &ProjectView<'_>) -> bool {
    let holds_store = |dir: &str| {
        view.is_file(&format!("{dir}/{MODULES_YAML}")) || view.is_dir(&format!("{dir}/.pnpm"))
    };
    holds_store("node_modules")
        || configured_modules_dirs_in(view)
            .iter()
            .any(|d| holds_store(d))
}

/// [`installed_store_in`] over the disk.
pub(crate) fn installed_store(project: &Path) -> bool {
    installed_store_in(&ProjectView::Disk(project))
}

/// [`configured_modules_dirs`] for a view, as `/`-separated paths
/// relative to the project. On disk (and in a snapshot, whose recording
/// this read opts out of, like
/// [`ProjectView::yarn_node_linker`]) it is the disk answer, which also
/// reads the settings files above the project. A memory view is the
/// repository alone: only the project's own `pnpm-workspace.yaml` and
/// `.npmrc` count, plus the children holding an install record.
fn configured_modules_dirs_in(view: &ProjectView<'_>) -> Vec<String> {
    let root = match view {
        ProjectView::Disk(root) => *root,
        ProjectView::Snapshot(snap) => snap.root(),
        ProjectView::Memory(project) => {
            let mut dirs: Vec<String> =
                setting_from(project.text("pnpm-workspace.yaml"), project.text(".npmrc"))
                    .and_then(|raw| super::npm_crawler::resolve_modules_folder(&[], &raw))
                    .into_iter()
                    .collect();
            for (name, is_dir) in project.children("") {
                if is_dir
                    && name != "node_modules"
                    && !dirs.contains(&name)
                    && view.is_file(&format!("{name}/{MODULES_YAML}"))
                {
                    dirs.push(name);
                }
            }
            return dirs;
        }
    };
    configured_modules_dirs(root)
        .iter()
        .filter_map(|dir| {
            let rel = dir.strip_prefix(root).ok()?;
            let parts = rel
                .components()
                .map(|c| c.as_os_str().to_str())
                .collect::<Option<Vec<_>>>()?;
            Some(parts.join("/"))
        })
        .collect()
}

/// The raw pnpm `modulesDir` setting that applies to the project:
/// `modulesDir:` in the nearest `pnpm-workspace.yaml` at or above it (the
/// workspace's settings file on pnpm 10+, which wins over `.npmrc`), else
/// `modules-dir` from the nearest `.npmrc` at or above it that sets it
/// (pnpm up to 10). Read with
/// [`crate::utils::fs::read_regular_to_string_sync`]: the files belong to
/// the (untrusted) project.
fn modules_dir_setting(project: &Path) -> Option<String> {
    let read = |path: PathBuf| crate::utils::fs::read_regular_to_string_sync(&path).ok();
    project
        .ancestors()
        .find_map(|dir| read(dir.join("pnpm-workspace.yaml")))
        .and_then(|yaml| workspace_modules_dir(&yaml))
        .or_else(|| {
            project.ancestors().find_map(|dir| {
                let npmrc = read(dir.join(".npmrc"))?;
                npmrc_modules_dir(&npmrc)
            })
        })
        .filter(|value| !value.is_empty())
}

/// [`modules_dir_setting`] from one `pnpm-workspace.yaml` and one
/// `.npmrc` text.
fn setting_from(workspace_yaml: Option<&str>, npmrc: Option<&str>) -> Option<String> {
    workspace_yaml
        .and_then(workspace_modules_dir)
        .or_else(|| npmrc.and_then(npmrc_modules_dir))
        .filter(|value| !value.is_empty())
}

/// The last top-level `modulesDir:` of a `pnpm-workspace.yaml`.
fn workspace_modules_dir(yaml: &str) -> Option<String> {
    crate::formats::text::strip_bom(yaml)
        .lines()
        .filter_map(crate::formats::pnpm::workspace::top_level_key)
        .rfind(|(key, _)| key == "modulesDir")
        .map(|(_, value)| unquote_yaml_scalar(value))
}

/// The top-level `modules-dir` of an `.npmrc`.
fn npmrc_modules_dir(npmrc: &str) -> Option<String> {
    crate::patch::redirect::npmrc::npmrc_top_level_value(npmrc, "modules-dir")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawlers::pkg_managers::{
        detect_npm_pkg_manager, pnpm_pnp_layout, pnpm_pnp_layout_in, NpmPkgManager, YarnPnpLoader,
    };
    use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

    /// The ways a project tells pnpm to install into `deps/`, with the
    /// store each leaves there: the `.npmrc` and `pnpm-workspace.yaml`
    /// settings (a `.pnpm` store), and an unconfigured project whose
    /// `deps/` holds pnpm's install record (a global-config setting).
    const LAYOUTS: [(&str, &str, &str); 4] = [
        (
            ".npmrc",
            "node-linker=pnp\nmodules-dir=deps\n",
            "deps/.pnpm/x",
        ),
        ("pnpm-workspace.yaml", "modulesDir: deps\n", "deps/.pnpm/x"),
        (
            "pnpm-workspace.yaml",
            "modulesDir: './deps'\n",
            "deps/.pnpm/x",
        ),
        ("package.json", "{}", "deps/.modules.yaml"),
    ];

    /// Stage a pnpm `node-linker=pnp` install into `deps/` (the files a
    /// real pnpm 10.28 install writes, #1129) in `root`, and the same
    /// files in memory.
    fn stage(root: &Path, (file, text, store): (&str, &str, &str)) -> MemoryProject {
        let mut memory = MemoryProject::new();
        for (rel, text) in [
            (file, text),
            (".pnp.cjs", "/* pnp */"),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            (store, ""),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
            memory.insert(rel, MemoryEntry::Text(text.into()));
        }
        memory
    }

    /// Every former reader of the pnpm install location answers through
    /// this module: the crawler's roots, the layout detector, the PnP
    /// carve-out over disk and memory, VEX's loader probe and the
    /// vendored router all find the `deps/` store (#1129). Before, all
    /// but the crawler probed only `node_modules/`, so the tree read as
    /// yarn berry.
    #[tokio::test]
    async fn every_reader_finds_a_store_in_the_configured_modules_dir() {
        for layout in LAYOUTS {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let memory = stage(root, layout);

            assert_eq!(
                configured_modules_dirs(root),
                vec![root.join("deps")],
                "{layout:?}"
            );
            assert_eq!(
                super::super::npm_crawler::configured_install_roots(root),
                vec![root.join("deps")],
                "{layout:?}"
            );
            assert!(installed_store(root), "{layout:?}");
            assert!(pnpm_pnp_layout(root), "{layout:?}");
            assert!(
                pnpm_pnp_layout_in(&ProjectView::Memory(&memory)),
                "memory: {layout:?}"
            );
            let snapshot = crate::vendor::lock_inventory::DiskSnapshot::new(root);
            assert!(
                pnpm_pnp_layout_in(&ProjectView::Snapshot(&snapshot)),
                "snapshot: {layout:?}"
            );
            assert_eq!(
                detect_npm_pkg_manager(root),
                NpmPkgManager::Pnpm,
                "{layout:?}"
            );
            assert!(YarnPnpLoader::detect(root).is_none(), "{layout:?}");
            let (code, _) = crate::vendor::npm_flavor::detect_npm_lock_flavor(root)
                .await
                .unwrap_err();
            assert_eq!(code, "vendor_pnpm_pnp_unsupported", "{layout:?}");

            // Without the loader it is a plain pnpm install in deps/.
            std::fs::remove_file(root.join(".pnp.cjs")).unwrap();
            assert_eq!(
                detect_npm_pkg_manager(root),
                NpmPkgManager::Pnpm,
                "{layout:?}"
            );
        }
    }

    /// The carve-out stays fail-closed with a configured modules dir: no
    /// store there, or a `yarn.lock` beside the loader, keeps the yarn
    /// berry reading.
    #[test]
    fn a_configured_modules_dir_without_a_store_is_not_pnpm() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        stage(
            root,
            (".npmrc", "modules-dir=deps\n", "deps/x/package.json"),
        );
        assert!(!installed_store(root));
        assert_eq!(detect_npm_pkg_manager(root), NpmPkgManager::YarnBerryPnP);

        std::fs::create_dir_all(root.join("deps/.pnpm")).unwrap();
        assert_eq!(detect_npm_pkg_manager(root), NpmPkgManager::Pnpm);
        std::fs::write(root.join("yarn.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(root), NpmPkgManager::YarnBerryPnP);
    }

    /// A modules dir both configured and holding an install record is
    /// listed once.
    #[test]
    fn a_configured_dir_holding_the_record_is_listed_once() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let memory = stage(root, (".npmrc", "modules-dir=deps\n", "deps/.modules.yaml"));
        assert_eq!(configured_modules_dirs(root), vec![root.join("deps")]);
        assert_eq!(
            configured_modules_dirs_in(&ProjectView::Memory(&memory)),
            vec!["deps"]
        );
        assert_eq!(
            configured_modules_dirs_in(&ProjectView::Disk(root)),
            vec!["deps"]
        );
    }

    /// The setting: `pnpm-workspace.yaml` wins over `.npmrc` (even when
    /// it is empty), quotes are removed, and the last key wins.
    #[test]
    fn setting_precedence_and_quoting() {
        assert_eq!(
            setting_from(Some("modulesDir: a\n"), Some("modules-dir=b\n")).as_deref(),
            Some("a")
        );
        assert_eq!(
            setting_from(None, Some("modules-dir=b\n")).as_deref(),
            Some("b")
        );
        assert_eq!(
            setting_from(Some("modulesDir: ''\n"), Some("modules-dir=b\n")),
            None
        );
        assert_eq!(
            setting_from(Some("packages: []\n"), Some("modules-dir=b\n")).as_deref(),
            Some("b")
        );
        assert_eq!(
            setting_from(Some("modulesDir: a\nmodulesDir: \"it's\"\n"), None).as_deref(),
            Some("it's")
        );
        assert_eq!(
            setting_from(Some("modulesDir: 'it''s'\n"), None).as_deref(),
            Some("it's")
        );
    }
}
