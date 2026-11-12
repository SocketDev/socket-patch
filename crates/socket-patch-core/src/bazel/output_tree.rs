//! Output-tree classifier over injected `stat` and `read_link` (design
//! 2.11). It tests a path by marker and never by name, because
//! `--symlink_prefix` moves the convenience links. Used to refuse and to
//! prune, never to write or to crawl.
//!
//! Stub until `wp-output-tree` (wave 1) replaces this file.

/// What kind of Bazel-owned tree a path is in. Everything but `Plain` is
/// never written and never crawled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    Plain,
    OutputBase,
    RepoContentsCache,
    RepositoryCache,
    VendorDir,
    Link,
}
