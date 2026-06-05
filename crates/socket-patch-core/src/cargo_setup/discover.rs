//! Discover a Cargo project's root + member `Cargo.toml`s so `setup` can add
//! the guard dependency to each member (so any member's build runs the guard)
//! and write `[env] SOCKET_PATCH_ROOT` once at the workspace root.
//!
//! There is no existing Cargo workspace reader in the crate (the npm/pnpm
//! workspace logic in `package_json::find` is JS-specific), so this is a
//! minimal `[workspace] members` reader built on `toml_edit`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tokio::fs;
use toml_edit::{DocumentMut, Item};

/// A discovered Cargo project.
#[derive(Debug, Clone)]
pub struct CargoProject {
    /// Directory containing the workspace (or single-crate) `Cargo.toml`. The
    /// `.cargo/config.toml` + `[env] SOCKET_PATCH_ROOT` live here.
    pub root: PathBuf,
    /// Every member's `Cargo.toml` path (the guard dep is added to each).
    pub members: Vec<PathBuf>,
}

/// Find the Cargo project that `cwd` belongs to, resolving the workspace root
/// and its members. Returns `None` if there is no `Cargo.toml` at or above
/// `cwd`.
pub async fn discover_cargo_project(cwd: &Path) -> Option<CargoProject> {
    let nearest = find_cargo_toml_upwards(cwd).await?;
    // The workspace root is the nearest ancestor `Cargo.toml` (including
    // `nearest`) that declares `[workspace]`; otherwise `nearest` is a
    // standalone crate that is its own root.
    let ws_manifest = find_workspace_root(&nearest).await.unwrap_or(nearest);
    let root = ws_manifest.parent()?.to_path_buf();

    let content = fs::read_to_string(&ws_manifest).await.ok()?;
    let doc = content.parse::<DocumentMut>().ok()?;

    let mut members: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    // The root manifest is itself a member when it has a `[package]`.
    if doc.get("package").is_some() {
        push_unique(&mut members, &mut seen, ws_manifest.clone());
    }

    // `[workspace] members = [...]` (with single-trailing-`*` glob support).
    if let Some(arr) = doc
        .get("workspace")
        .and_then(Item::as_table)
        .and_then(|w| w.get("members"))
        .and_then(Item::as_array)
    {
        for pattern in arr.iter().filter_map(|v| v.as_str()) {
            for manifest in expand_member(&root, pattern).await {
                push_unique(&mut members, &mut seen, manifest);
            }
        }
    }

    // Neither a `[package]` nor any resolvable members → treat the manifest
    // itself as the sole member (e.g. a virtual manifest with globbed members
    // that matched nothing — fall back so setup still has something to edit).
    if members.is_empty() {
        push_unique(&mut members, &mut seen, ws_manifest);
    }

    Some(CargoProject { root, members })
}

fn push_unique(members: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, path: PathBuf) {
    if seen.insert(path.clone()) {
        members.push(path);
    }
}

/// Walk up from `start` looking for a `Cargo.toml`.
async fn find_cargo_toml_upwards(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("Cargo.toml");
        if fs::metadata(&candidate).await.is_ok() {
            return Some(candidate);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Walk up from `start_manifest`'s directory looking for a `Cargo.toml` that
/// declares `[workspace]`. Returns that manifest, or `None` if none exists.
async fn find_workspace_root(start_manifest: &Path) -> Option<PathBuf> {
    let mut dir = start_manifest.parent()?.to_path_buf();
    loop {
        let candidate = dir.join("Cargo.toml");
        if let Ok(content) = fs::read_to_string(&candidate).await {
            if content
                .parse::<DocumentMut>()
                .ok()
                .map(|d| d.get("workspace").is_some())
                .unwrap_or(false)
            {
                return Some(candidate);
            }
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Expand one `[workspace] members` pattern (relative to `root`) into member
/// `Cargo.toml` paths. Supports a bare path (`crate-a`), a single-level glob
/// (`crates/*` / `*`), and the recursive glob (`crates/**` / `**`), which Cargo
/// accepts and which `setup` must honor so a deeply-nested member is configured
/// (property 9). `/**` is checked before `/*` (a `crates/**` pattern ends in
/// `**`, not `/*`, but the explicit order keeps intent clear).
async fn expand_member(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let pattern = pattern.replace('\\', "/");
    if let Some(prefix) = pattern.strip_suffix("/**") {
        glob_dir_recursive(&root.join(prefix)).await
    } else if pattern == "**" {
        glob_dir_recursive(root).await
    } else if let Some(prefix) = pattern.strip_suffix("/*") {
        glob_dir(&root.join(prefix)).await
    } else if pattern == "*" {
        glob_dir(root).await
    } else {
        let manifest = root.join(&pattern).join("Cargo.toml");
        if fs::metadata(&manifest).await.is_ok() {
            vec![manifest]
        } else {
            Vec::new()
        }
    }
}

/// Every immediate subdirectory of `base` that contains a `Cargo.toml`.
async fn glob_dir(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut rd = match fs::read_dir(base).await {
        Ok(rd) => rd,
        Err(_) => return out,
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        // `entry.file_type()` reflects the dir entry itself, which for a
        // symlink reports `is_dir() == false` — so a symlinked member
        // directory (which Cargo accepts and expands) would be silently
        // skipped. Stat the path instead so symlinks are followed.
        let path = entry.path();
        if fs::metadata(&path).await.map(|m| m.is_dir()).unwrap_or(false) {
            let manifest = path.join("Cargo.toml");
            if fs::metadata(&manifest).await.is_ok() {
                out.push(manifest);
            }
        }
    }
    out
}

/// Recursive-glob (`**`) expansion: every subdirectory of `base`, at any depth,
/// that contains a `Cargo.toml`. Skips hidden dirs and `target/` so a build
/// tree is never walked. Bounded depth as a loop backstop.
async fn glob_dir_recursive(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_manifests_recursive(base, 0, &mut out).await;
    out
}

async fn collect_manifests_recursive(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 20 {
        return;
    }
    let mut rd = match fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        let path = entry.path();
        // Stat (not `file_type`) so symlinked dirs are followed, mirroring `glob_dir`.
        if !fs::metadata(&path).await.map(|m| m.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        let manifest = path.join("Cargo.toml");
        if fs::metadata(&manifest).await.is_ok() {
            out.push(manifest);
        }
        Box::pin(collect_manifests_recursive(&path, depth + 1, out)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write(path: &Path, body: &str) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).await.unwrap();
        }
        fs::write(path, body).await.unwrap();
    }

    #[tokio::test]
    async fn test_single_crate() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .await;

        let proj = discover_cargo_project(root).await.unwrap();
        assert_eq!(proj.root, root);
        assert_eq!(proj.members, vec![root.join("Cargo.toml")]);
    }

    #[tokio::test]
    async fn test_workspace_with_glob_and_root_package() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\n[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .await;
        write(
            &root.join("crates/a/Cargo.toml"),
            "[package]\nname=\"a\"\nversion=\"0.1.0\"\n",
        )
        .await;
        write(
            &root.join("crates/b/Cargo.toml"),
            "[package]\nname=\"b\"\nversion=\"0.1.0\"\n",
        )
        .await;
        // A non-crate dir under crates/ is ignored.
        fs::create_dir_all(root.join("crates/notacrate"))
            .await
            .unwrap();

        let proj = discover_cargo_project(root).await.unwrap();
        assert_eq!(proj.root, root);
        // Root package + the two globbed members.
        assert!(proj.members.contains(&root.join("Cargo.toml")));
        assert!(proj.members.contains(&root.join("crates/a/Cargo.toml")));
        assert!(proj.members.contains(&root.join("crates/b/Cargo.toml")));
        assert_eq!(proj.members.len(), 3);
    }

    #[tokio::test]
    async fn test_workspace_recursive_double_glob() {
        // Property 9: `members = ["crates/**"]` must reach a member nested
        // several directories deep (`crates/group/leaf`), which the single-level
        // `crates/*` expansion would miss.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/**\"]\n",
        )
        .await;
        write(
            &root.join("crates/group/leaf/Cargo.toml"),
            "[package]\nname=\"leaf\"\nversion=\"0.1.0\"\n",
        )
        .await;
        // A sibling at a different depth is also matched by `**`.
        write(
            &root.join("crates/top/Cargo.toml"),
            "[package]\nname=\"top\"\nversion=\"0.1.0\"\n",
        )
        .await;
        // A `target/` build dir must NOT be walked even if it holds a Cargo.toml.
        write(
            &root.join("crates/group/target/junk/Cargo.toml"),
            "[package]\nname=\"junk\"\nversion=\"0.1.0\"\n",
        )
        .await;

        let proj = discover_cargo_project(root).await.unwrap();
        assert!(
            proj.members.contains(&root.join("crates/group/leaf/Cargo.toml")),
            "deeply-nested member must be discovered via `crates/**`, got {:?}",
            proj.members
        );
        assert!(proj.members.contains(&root.join("crates/top/Cargo.toml")));
        assert!(
            !proj.members.iter().any(|m| m.to_string_lossy().contains("target")),
            "target/ build dir must not be walked, got {:?}",
            proj.members
        );
        assert_eq!(proj.members.len(), 2, "exactly leaf + top: {:?}", proj.members);
    }

    #[tokio::test]
    async fn test_virtual_manifest_explicit_members() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // No [package] — a virtual workspace manifest.
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"lib\"]\n",
        )
        .await;
        write(
            &root.join("app/Cargo.toml"),
            "[package]\nname=\"app\"\nversion=\"0.1.0\"\n",
        )
        .await;
        write(
            &root.join("lib/Cargo.toml"),
            "[package]\nname=\"lib\"\nversion=\"0.1.0\"\n",
        )
        .await;

        let proj = discover_cargo_project(root).await.unwrap();
        assert!(
            !proj.members.contains(&root.join("Cargo.toml")),
            "virtual manifest is not a member"
        );
        assert!(proj.members.contains(&root.join("app/Cargo.toml")));
        assert!(proj.members.contains(&root.join("lib/Cargo.toml")));
        assert_eq!(proj.members.len(), 2);
    }

    #[tokio::test]
    async fn test_discovers_workspace_root_from_member_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/a\"]\n",
        )
        .await;
        let member = root.join("crates/a");
        write(
            &member.join("Cargo.toml"),
            "[package]\nname=\"a\"\nversion=\"0.1.0\"\n",
        )
        .await;

        // Run discovery from inside the member dir.
        let proj = discover_cargo_project(&member).await.unwrap();
        assert_eq!(proj.root, root, "should resolve up to the workspace root");
        assert_eq!(proj.members, vec![root.join("crates/a/Cargo.toml")]);
    }

    // A member directory reached through a symlink (Cargo follows symlinked
    // members when expanding a `crates/*` glob) must still be discovered. The
    // old `DirEntry::file_type()` gate reported the symlink as a non-directory
    // and silently dropped it, leaving that member unconfigured by `setup`.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_globbed_member_through_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .await;
        // The real crate lives outside `crates/`; `crates/a` is a symlink to it.
        write(
            &root.join("real/Cargo.toml"),
            "[package]\nname=\"a\"\nversion=\"0.1.0\"\n",
        )
        .await;
        fs::create_dir_all(root.join("crates")).await.unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("crates/a")).unwrap();

        let proj = discover_cargo_project(root).await.unwrap();
        assert!(
            proj.members.contains(&root.join("crates/a/Cargo.toml")),
            "symlinked workspace member must be discovered, got {:?}",
            proj.members
        );
        // It must be the real member, not the virtual-manifest fallback.
        assert!(!proj.members.contains(&root.join("Cargo.toml")));
        assert_eq!(proj.members.len(), 1);
    }

    #[tokio::test]
    async fn test_no_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        assert!(discover_cargo_project(dir.path()).await.is_none());
    }
}
