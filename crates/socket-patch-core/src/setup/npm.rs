//! The npm setup backend, by alias.
//!
//! npm's hook wiring lives in [`crate::package_json`] — that module stays
//! top-level because it is also the crate-wide shared npm-manifest library
//! (crawlers and vendor parse package.json through it). This alias exists so
//! `setup::*` enumerates every ecosystem backend in one place.

pub use crate::package_json::detect::{is_setup_configured_str, PackageManager};
pub use crate::package_json::find::{detect_package_manager, find_package_json_files};
pub use crate::package_json::update::{remove_package_json, update_package_json};
