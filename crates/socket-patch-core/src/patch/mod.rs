pub mod apply;
pub mod apply_lock;
// `fresh_copy`/`remove_tree` are shared by the Go redirect and the vendor backends.
pub mod copy_tree;
pub mod diff;
pub(crate) mod file_hash;
pub mod package;
pub(crate) mod path_safety;
pub mod redirect;
pub mod rollback;
pub mod sidecars;
