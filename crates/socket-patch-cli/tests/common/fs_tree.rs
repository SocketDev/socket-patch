//! Recursive directory copy for test fixtures. `common/mod.rs` re-exports
//! it; shared modules whose includers don't all declare `mod common` pull
//! this file in on its own with `#[path = "../common/fs_tree.rs"] mod
//! fs_tree;`.

#![allow(dead_code)]

use std::path::Path;

/// Copy `src` into `dst`, creating `dst`. Symlinks are followed: a link to
/// a directory is copied as a directory, a link to a file as the file.
/// Panics if `src` is not a readable directory.
pub fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}
