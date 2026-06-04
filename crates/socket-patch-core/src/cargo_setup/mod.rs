//! Cargo `setup` support: add/remove the `socket-patch-guard` build-time
//! dependency and discover a project's member `Cargo.toml`s. Analogous to
//! [`crate::package_json`] for npm and [`crate::pth_hook`] for Python.
//!
//! The `[env] SOCKET_PATCH_ROOT` part of setup is written via
//! [`crate::patch::cargo_config`] (shared with the apply-time redirect writer).

pub mod discover;
pub mod update;

pub use discover::{discover_cargo_project, CargoProject};
pub use update::{
    add_guard_dep, is_guard_dep_present, remove_guard_dep, CargoEditResult, CargoSetupStatus,
    GUARD_CRATE,
};
