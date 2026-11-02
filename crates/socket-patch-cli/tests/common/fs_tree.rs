//! Recursive directory copy for test fixtures, reached as
//! `common::fs_tree::copy_tree`. Shared modules whose includers don't all
//! declare `mod common` pull this file in on its own with
//! `#[path = "../common/fs_tree.rs"] mod fs_tree;`.

#![allow(dead_code)]

use std::path::Path;

/// Copy `src` into `dst`, creating `dst`. A symlink to a file is copied as
/// the file; a symlink to a directory panics rather than being followed,
/// so a link cycle in an installed tree can't recurse forever. Panics if
/// `src` is not a readable directory.
pub fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}
