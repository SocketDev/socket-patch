pub mod apply;
pub mod apply_lock;
// Ungated: the vendor backends (npm/pypi/gem are unconditional) stage their
// patched copies with `fresh_copy`/`remove_tree`, not just the golang redirect.
pub mod copy_tree;
pub mod cow;
pub mod diff;
pub(crate) mod file_hash;
pub mod package;
pub(crate) mod path_safety;
pub mod redirect;
pub mod rollback;
pub mod sidecars;

// Moved modules — these re-exports keep the old `patch::*` paths compiling
// for external consumers of the published crate. Internal code must import
// the new canonical paths (`crate::vendor::*`, `redirect::golang_local`);
// CI greps reject new uses of the old ones. Drop these aliases at 4.0.
pub use crate::vendor;
pub use crate::vendor::go_mod_edit;
pub use redirect::golang_local as go_redirect;
