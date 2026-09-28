//! Test-only scaffolding for the randomized crawler sweeps: generators build
//! fixture trees with these helpers, and the crawl output is pinned by a
//! golden snapshot (see [`crate::golden`]).

use std::path::{Path, PathBuf};

use super::types::CrawledPackage;

/// Restores permissions a generator stripped before the tempdir is removed
/// (declare it AFTER the tempdir so it drops first). Only Unix strips
/// permissions; everywhere else the plan is recorded and ignored.
#[derive(Default)]
pub(crate) struct PermGuard(Vec<(PathBuf, u32)>, Vec<PathBuf>);

impl PermGuard {
    /// Queue `dir` to get `mode` once the tree is complete (a stripped dir
    /// must not block the rest of the generation).
    pub(crate) fn plan(&mut self, dir: &Path, mode: u32) {
        self.0.push((dir.to_path_buf(), mode));
    }

    /// The queued `(path relative to base, mode)` pairs, for a sweep's input.
    pub(crate) fn planned(&self, base: &Path) -> Vec<(String, u32)> {
        self.0.iter().map(|(p, m)| (rel(base, p), *m)).collect()
    }

    /// Apply every queued mode, deepest paths first.
    pub(crate) fn apply(&mut self) {
        let mut plan = std::mem::take(&mut self.0);
        plan.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        for (dir, _mode) in plan {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(_mode)).is_ok() {
                    self.1.push(dir);
                }
            }
            #[cfg(not(unix))]
            let _ = dir;
        }
    }
}

impl Drop for PermGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        for p in self.1.iter().rev() {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
        }
    }
}

/// Create a symlink (Unix only; a no-op elsewhere).
pub(crate) fn symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = link.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::os::unix::fs::symlink(target, link);
    }
    #[cfg(not(unix))]
    let _ = (target, link);
}

/// Create a FIFO (Unix only; a no-op elsewhere). Only for paths the crawler
/// under test reads through the FIFO-safe opener — a plain read would wedge
/// both implementations.
pub(crate) fn fifo(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        let _ = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Write `content` to `path`, creating parents. Best effort: a random
/// generator may already have put a directory (or a file) in the way.
pub(crate) fn write(path: &Path, content: &str) {
    write_bytes(path, content.as_bytes());
}

/// [`write`] for raw bytes.
pub(crate) fn write_bytes(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Never open anything but a regular file (or nothing): writing into a
    // FIFO planted earlier in the tree would block the generator.
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) {
        return;
    }
    let _ = std::fs::write(path, content);
}

/// `create_dir_all`, best effort (see [`write`]).
pub(crate) fn mkdir(path: &Path) {
    let _ = std::fs::create_dir_all(path);
}

/// A crawled package as a comparable row (every field, in order).
pub(crate) type Row = (String, String, Option<String>, String, PathBuf);

pub(crate) fn rows(pkgs: &[CrawledPackage]) -> Vec<Row> {
    pkgs.iter()
        .map(|p| {
            (
                p.name.clone(),
                p.version.clone(),
                p.namespace.clone(),
                p.purl.clone(),
                p.path.clone(),
            )
        })
        .collect()
}

/// A crawled package as a row with its path relative to `base` (the sweep's
/// tempdir), so the row is the same on every run.
pub(crate) type RelRow = (String, String, Option<String>, String, String);

pub(crate) fn rel(base: &Path, path: &Path) -> String {
    match path.strip_prefix(base) {
        Ok(rest) => rest.to_string_lossy().replace('\\', "/"),
        Err(_) => format!("<abs>{}", path.display()),
    }
}

pub(crate) fn rel_rows(base: &Path, pkgs: &[CrawledPackage]) -> Vec<RelRow> {
    pkgs.iter().map(|p| rel_row(base, p)).collect()
}

fn rel_row(base: &Path, p: &CrawledPackage) -> RelRow {
    (
        p.name.clone(),
        p.version.clone(),
        p.namespace.clone(),
        p.purl.clone(),
        rel(base, &p.path),
    )
}

/// A `find_by_purls` map as sorted [`RelRow`]s.
pub(crate) fn rel_map_rows(
    base: &Path,
    map: &std::collections::HashMap<String, CrawledPackage>,
) -> std::collections::BTreeMap<String, RelRow> {
    map.iter()
        .map(|(k, p)| (k.clone(), rel_row(base, p)))
        .collect()
}

/// Every entry under `root` — path, kind, mode, file bytes, link target —
/// as the input a sweep case records, so generator drift shows up as such.
pub(crate) fn tree_listing(root: &Path) -> Vec<(String, String)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt as _;
                meta.permissions().mode() & 0o7777
            };
            #[cfg(not(unix))]
            let mode = 0;
            let what = if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap_or_default();
                format!("link {mode:o} {}", rel(base, &target))
            } else if meta.is_dir() {
                format!("dir {mode:o}")
            } else if meta.is_file() {
                // Generators may write the tempdir's own path into a file.
                let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default())
                    .replace(&*base.to_string_lossy(), "<base>");
                format!("file {mode:o} {}", crate::golden::digest(&text))
            } else {
                format!("other {mode:o}")
            };
            out.push((rel(base, &path), what));
            if meta.is_dir() && !meta.file_type().is_symlink() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// Whether this run can replay a crawler golden: they were blessed on Linux
/// (case-sensitive, symlinks), and a sweep that strips permissions as a
/// non-root user, where the stripped modes are honored.
pub(crate) fn crawl_goldens_apply(strips_permissions: bool) -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions.
        !strips_permissions || unsafe { libc::geteuid() != 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = strips_permissions;
        false
    }
}
