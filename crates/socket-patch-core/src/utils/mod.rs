pub mod cargo_workspace;
pub mod concurrent;
pub(crate) mod digest;
pub mod env_compat;
pub mod fs;
pub mod notice;
pub(crate) mod http;
pub(crate) mod line_endings;
pub mod pdm_lock;
pub mod pipenv;
pub mod poetry_lock;
pub mod process;
pub mod purl;
pub mod python_lock;
pub mod python_script;
pub(crate) mod requirements;
pub(crate) mod serde;
pub mod socket_cli_config;
pub mod socket_dir;
pub(crate) mod toml_edit_ext;
pub mod uri;

// Moved modules — these re-exports keep the old `utils::*` paths compiling
// for external consumers of the published crate. Internal code must import
// the new canonical paths; CI greps reject new uses of the old ones. Drop
// these aliases at 4.0.
pub use crate::api::date;
pub use crate::crawlers::fuzzy_match;
pub use crate::manifest::cleanup_blobs;
pub use crate::telemetry;

pub mod hatch;
