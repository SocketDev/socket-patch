//! The stat-only upward root probe (design 2.2): from the project up to the
//! read boundary, recording every directory that holds a Bazel boundary
//! file. In a project with none it costs four `symlink_metadata` calls per
//! ancestor and nothing else: no read, no warning, no request.
//!
//! Stub until `wp-root-probe` (wave 1) replaces this file. It looks at
//! nothing, so it answers the one value that refuses every write and
//! withholds every attestation: an unread root may hold hubs, and
//! unreadable is not absent. The facade `bazel::probe` re-exports this
//! function, so the name stays.

use std::path::Path;

use crate::bazel::model::Probe;

/// The Bazel roots that govern `project_dir`.
pub fn probe(project_dir: &Path) -> Probe {
    Probe::RootOutsideBoundary {
        marker: project_dir.to_path_buf(),
        confirmed: true,
    }
}
