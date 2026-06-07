//! Python `.pth` post-install hook setup.
//!
//! Where npm-family ecosystems get an automatic post-install patch hook via a
//! `package.json` `postinstall` script ([`crate::package_json`]), Python has no
//! universal installer hook. Instead, `socket-patch setup` declares a committed
//! dependency on the `socket-patch-hook` wheel (via the `socket-patch[hook]`
//! extra); installing that wheel lays a startup `.pth` into site-packages that
//! re-applies patches after any install — package-manager-agnostic, because it
//! rides on the interpreter's startup hook rather than any one installer.
//!
//! This module is the Rust side: detecting the project's dependency manager
//! ([`detect`]) and editing its manifest(s) to add/remove the hook dependency
//! ([`edit`]). All actual patching stays in `socket-patch apply`.
//!
//! The committed dependency line is the single source of truth that the hook is
//! active — there is no separate marker/audit file (git history is the audit
//! trail), so nothing can drift out of sync with the manifest.

pub mod detect;
pub mod edit;

pub use detect::{deps_contain_hook, detect_python_pm, PythonPackageManager, HOOK_DEP};
pub use edit::{
    add_hook_dependency, pyproject_contains_hook, remove_hook_dependency, ManifestKind,
    PthEditResult, PthStatus,
};
