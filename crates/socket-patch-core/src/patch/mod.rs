pub mod apply;
pub mod apply_lock;
pub(crate) mod bun_lock_text;
// Ungated: the vendor backends (npm/pypi/gem are unconditional) stage their
// patched copies with `fresh_copy`/`remove_tree`, not just the golang redirect.
pub mod copy_tree;
pub mod cow;
pub mod diff;
pub mod file_hash;
pub mod go_mod_edit;
pub mod go_redirect;
pub mod package;
pub(crate) mod path_safety;
pub mod redirect;
pub mod rollback;
pub mod sidecars;
pub mod vendor;
