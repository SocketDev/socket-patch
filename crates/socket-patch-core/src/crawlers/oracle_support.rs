//! Test-only scaffolding shared by the crawler equivalence tests: each
//! crawler whose async walk moved onto the blocking pool keeps its previous
//! implementation as a `#[cfg(test)]` oracle, and randomized fixture trees
//! built with these helpers assert both produce identical output.

use std::path::{Path, PathBuf};

use super::types::CrawledPackage;

/// Deterministic xorshift64* generator (no `rand` dependency).
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub(crate) fn chance(&mut self, pct: usize) -> bool {
        self.below(100) < pct
    }

    pub(crate) fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

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

/// A `find_by_purls` map as sorted comparable rows.
pub(crate) fn map_rows(
    map: &std::collections::HashMap<String, CrawledPackage>,
) -> std::collections::BTreeMap<String, Row> {
    map.iter()
        .map(|(k, p)| {
            (
                k.clone(),
                (
                    p.name.clone(),
                    p.version.clone(),
                    p.namespace.clone(),
                    p.purl.clone(),
                    p.path.clone(),
                ),
            )
        })
        .collect()
}
