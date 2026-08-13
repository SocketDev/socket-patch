//! Per-ecosystem `setup` backends: the code that wires (and unwires) each
//! ecosystem's auto-re-apply hook into a user's project, consumed by the
//! CLI's `setup` command.
//!
//! One concept, one home — these previously lived as four top-level modules
//! under four naming schemes (`gem_setup`, `composer_setup`, `pth_hook`,
//! plus `package_json`'s setup surface):
//!
//! * [`gem`] — Bundler plugin directive in the Gemfile + generated plugin
//!   gem, re-applying gem patches on `bundle install`.
//! * [`composer`] — post-install hook in `composer.json`.
//! * [`pypi`] — the `socket-patch[hook]` dependency whose `.pth` wheel
//!   re-applies pypi patches at interpreter startup.
//! * [`npm`] — a thin alias: the npm backend's real home is
//!   [`crate::package_json`], which stays top-level because it doubles as
//!   the crate-wide shared npm-manifest library (crawlers and vendor read
//!   package.json through it too).

pub mod composer;
pub mod gem;
pub mod npm;
pub mod pypi;
