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
    // Read via `as_table_like` so the equally-valid inline form
    // `workspace = { members = [...] }` is honored too — otherwise its members
    // are silently dropped even though `find_workspace_root` (which only checks
    // `.is_some()`) still treats it as the workspace root. Mirrors the
    // inline-aware `[dependencies]` handling in `update::is_guard_dep_present`.
    if let Some(arr) = doc
        .get("workspace")
        .and_then(Item::as_table_like)
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
        // Use the dir-entry's own type (does NOT follow symlinks): a `**` walk
        // must not traverse a symlinked dir — it could loop back to an ancestor
        // (so the workspace root's own `Cargo.toml` reappears as a duplicate
        // member) or escape the repo entirely (so `setup` would edit an
        // out-of-tree `Cargo.toml`, breaking the in-repo-only contract). The
        // `glob` crate's `**` likewise does not follow symlinks. (The
        // single-level `glob_dir` still follows a symlinked direct member.)
        let ft = match entry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        let path = entry.path();
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

    // A recursive `crates/**` glob must NOT follow symlinked directories: a
    // loop symlink back to the root would re-add the workspace manifest as a
    // duplicate member, and an escaping symlink would let `setup` edit an
    // out-of-tree `Cargo.toml`. (Contrast the single-level `crates/*` case,
    // which intentionally follows a symlinked direct member.)
    #[cfg(unix)]
    #[tokio::test]
    async fn test_recursive_glob_does_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/**\"]\n",
        )
        .await;
        write(
            &root.join("crates/real/Cargo.toml"),
            "[package]\nname=\"real\"\nversion=\"0.1.0\"\n",
        )
        .await;
        fs::create_dir_all(root.join("crates")).await.unwrap();
        // Loop: crates/loop -> the workspace root (would re-discover root Cargo.toml).
        std::os::unix::fs::symlink(root, root.join("crates/loop")).unwrap();
        // Escape: crates/escape -> an unrelated dir OUTSIDE the repo.
        let outside = tempfile::tempdir().unwrap();
        write(
            &outside.path().join("Cargo.toml"),
            "[package]\nname=\"outside\"\nversion=\"0.1.0\"\n",
        )
        .await;
        std::os::unix::fs::symlink(outside.path(), root.join("crates/escape")).unwrap();

        let proj = discover_cargo_project(root).await.unwrap();
        assert_eq!(
            proj.members,
            vec![root.join("crates/real/Cargo.toml")],
            "recursive `**` must find only the real nested member — never the root \
             via the loop symlink, never the out-of-tree crate via the escape symlink; got {:?}",
            proj.members
        );
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

    // A bare-path member that does not resolve to a `Cargo.toml` must be
    // silently skipped without aborting discovery of the valid siblings.
    #[tokio::test]
    async fn test_nonexistent_bare_member_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"ghost\", \"lib\"]\n",
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
        // `ghost` is listed but the directory has no Cargo.toml (it doesn't even
        // exist) — Cargo would error, but `setup` must just skip it.

        let proj = discover_cargo_project(root).await.unwrap();
        assert!(proj.members.contains(&root.join("app/Cargo.toml")));
        assert!(proj.members.contains(&root.join("lib/Cargo.toml")));
        assert!(
            !proj.members.iter().any(|m| m.to_string_lossy().contains("ghost")),
            "unresolved member must not be added, got {:?}",
            proj.members
        );
        assert_eq!(proj.members.len(), 2);
    }

    // Root `[package]` + recursive `crates/**`: the root manifest is a member
    // (via `[package]`) and every nested crate is discovered, with no path
    // appearing twice.
    #[tokio::test]
    async fn test_recursive_glob_with_root_package_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname=\"root\"\nversion=\"0.1.0\"\n\n[workspace]\nmembers = [\"crates/**\"]\n",
        )
        .await;
        write(
            &root.join("crates/a/Cargo.toml"),
            "[package]\nname=\"a\"\nversion=\"0.1.0\"\n",
        )
        .await;
        write(
            &root.join("crates/group/deep/Cargo.toml"),
            "[package]\nname=\"deep\"\nversion=\"0.1.0\"\n",
        )
        .await;

        let proj = discover_cargo_project(root).await.unwrap();
        assert!(proj.members.contains(&root.join("Cargo.toml")));
        assert!(proj.members.contains(&root.join("crates/a/Cargo.toml")));
        assert!(proj.members.contains(&root.join("crates/group/deep/Cargo.toml")));
        assert_eq!(proj.members.len(), 3, "no duplicates: {:?}", proj.members);

        // No path appears twice.
        let mut sorted = proj.members.clone();
        sorted.sort();
        let deduped_len = {
            let mut s = sorted.clone();
            s.dedup();
            s.len()
        };
        assert_eq!(sorted.len(), deduped_len, "members contain a duplicate: {:?}", proj.members);
    }

    // Single-level `*` at the workspace root finds direct crate dirs and ignores
    // an immediate subdir that has no `Cargo.toml`.
    #[tokio::test]
    async fn test_single_level_star_at_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("Cargo.toml"), "[workspace]\nmembers = [\"*\"]\n").await;
        write(
            &root.join("alpha/Cargo.toml"),
            "[package]\nname=\"alpha\"\nversion=\"0.1.0\"\n",
        )
        .await;
        write(
            &root.join("beta/Cargo.toml"),
            "[package]\nname=\"beta\"\nversion=\"0.1.0\"\n",
        )
        .await;
        // A non-crate dir at the same level is ignored.
        fs::create_dir_all(root.join("docs")).await.unwrap();

        let proj = discover_cargo_project(root).await.unwrap();
        assert!(proj.members.contains(&root.join("alpha/Cargo.toml")));
        assert!(proj.members.contains(&root.join("beta/Cargo.toml")));
        assert_eq!(proj.members.len(), 2, "only the two crate dirs: {:?}", proj.members);
    }

    // The `[workspace]`/`members` tables may be written as an inline table —
    // `workspace = { members = [...] }` is valid TOML that Cargo (serde)
    // accepts exactly like a `[workspace]` section. The reader must see through
    // it via `as_table_like`, just as `is_guard_dep_present` does for inline
    // `[dependencies]`. The old `as_table` gate returned None for the inline
    // form, so every member was silently dropped (only the virtual-manifest
    // fallback survived) — leaving the members unconfigured by `setup`, even
    // though `find_workspace_root` still treats it as the workspace root.
    #[tokio::test]
    async fn test_inline_workspace_members_are_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Inline workspace table — NO `[package]`, so the only way to get real
        // members is to read the inline `members` array.
        write(
            &root.join("Cargo.toml"),
            "workspace = { members = [\"crates/*\"] }\n",
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

        let proj = discover_cargo_project(root).await.unwrap();
        assert_eq!(proj.root, root);
        assert!(
            proj.members.contains(&root.join("crates/a/Cargo.toml")),
            "inline-workspace member `a` must be discovered, got {:?}",
            proj.members
        );
        assert!(
            proj.members.contains(&root.join("crates/b/Cargo.toml")),
            "inline-workspace member `b` must be discovered, got {:?}",
            proj.members
        );
        // Exactly the two real members — NOT the virtual-manifest fallback
        // (which would wrongly list the root `Cargo.toml` alone).
        assert_eq!(
            proj.members.len(),
            2,
            "must be the two inline members, not the virtual fallback: {:?}",
            proj.members
        );
        assert!(!proj.members.contains(&root.join("Cargo.toml")));
    }

    // An inline workspace table with an explicit (non-glob) member list must
    // also resolve through the same `as_table_like` path.
    #[tokio::test]
    async fn test_inline_workspace_explicit_members() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("Cargo.toml"),
            "workspace = { members = [\"app\", \"lib\"] }\n",
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
        assert!(proj.members.contains(&root.join("app/Cargo.toml")));
        assert!(proj.members.contains(&root.join("lib/Cargo.toml")));
        assert_eq!(proj.members.len(), 2, "{:?}", proj.members);
    }
}
