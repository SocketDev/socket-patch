pub mod env_compat;
pub mod fs;
pub(crate) mod http;
pub mod pipenv;
pub mod process;
pub mod purl;
pub mod python_lock;
pub mod python_script;
pub(crate) mod serde;
pub mod socket_cli_config;
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
