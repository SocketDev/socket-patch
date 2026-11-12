//! `.socket/bazel/index.json`, the one file socket-patch owns in a Bazel
//! repository (design 5.2): the pins whose undo cannot be re-derived from
//! upstream, and the ignore lines it added. Rows hold digests, versions and
//! paths, never a URL.
//!
//! Stub until `wp-ignore-index` (wave 1) replaces this file.

/// One `pins` row: what a lane's offline restore undoes. No value exists
/// until the index does.
#[derive(Debug, Clone, PartialEq)]
pub enum IndexRow {}
