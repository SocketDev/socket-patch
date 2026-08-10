pub mod api;
pub mod constants;
pub mod crawlers;
pub mod hash;
pub mod manifest;
pub mod package_json;
pub mod patch;
pub mod setup;
pub mod telemetry;
pub mod update;
pub mod utils;
pub mod vendor;
pub mod vex;

// Moved modules — these aliases keep the old top-level paths compiling for
// external consumers of the published crate. Internal code must import the
// canonical `setup::*` paths; CI greps reject new uses of the old ones.
// Drop these aliases at 4.0.
pub use setup::composer as composer_setup;
pub use setup::gem as gem_setup;
pub use setup::pypi as pth_hook;
