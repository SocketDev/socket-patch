//! The `vendor` backend: committable vendoring of patched dependencies.
//!
//! Where `apply` patches installed packages in place (machine-local state),
//! `vendor` ejects each patched package into a committed
//! `.socket/vendor/<eco>/<patch-uuid>/<artifact>` and rewires the ecosystem's
//! lockfile/config so the project consumes the vendored copy. After
//! committing `.socket/vendor/` + the lockfile edits, a fresh checkout builds
//! with the patched dependency on machines with no socket-patch installed and
//! no Socket API access (spike-proven per ecosystem against real package
//! managers — see `spikes/PHASE0-FINDINGS.txt`).
//!
//! ## Per-ecosystem wiring
//!
//! | eco      | artifact            | wiring                                         |
//! |----------|---------------------|------------------------------------------------|
//! | npm      | deterministic tgz   | package-lock.json `resolved`+`integrity` only  |
//! | cargo    | crate dir           | `.cargo/config.toml` `[patch.crates-io]` + Cargo.lock surgery |
//! | golang   | module dir          | `go.mod` `replace` ([`ReplaceOwner::Vendor`])  |
//! | composer | package dir         | composer.lock `dist` → `{type: path}`          |
//! | gem      | gem dir (+gemspec)  | Gemfile `path:` + Gemfile.lock PATH pair       |
//! | pypi     | rebuilt wheel       | uv: pyproject+uv.lock pair; pip: requirements  |
//!
//! npm requests route through [`npm_flavor`], which content-sniffs the
//! project's lockfile (package-lock / yarn / pnpm / bun) and dispatches to
//! the matching backend — today only the package-lock backend exists and
//! the other flavors refuse with stable reason codes.
//!
//! ## Ownership & reversal
//!
//! `.socket/vendor/state.json` (committed) records the verbatim original
//! lockfile fragments every wire replaced; `vendor --revert` restores them
//! and removes the artifacts. `rollback`/`remove` stay vendoring-unaware by
//! design. The path-level UUID makes "is this Socket-vendored, by which
//! patch" recoverable from the lockfile string alone ([`path`]).
//!
//! [`ReplaceOwner::Vendor`]: crate::patch::go_mod_edit::ReplaceOwner

pub mod path;
pub mod state;

mod berry_zip;
pub mod bun_lock;
#[cfg(feature = "cargo")]
pub mod cargo;
#[cfg(feature = "cargo")]
pub mod cargo_config;
#[cfg(feature = "cargo")]
pub mod cargo_lock;
#[cfg(feature = "composer")]
pub mod composer_lock;
pub mod gem;
#[cfg(feature = "golang")]
pub mod golang;
mod npm_common;
pub mod npm_flavor;
pub mod npm_lock;
pub mod npm_pack;
pub mod pnpm_lock;
pub mod pypi;
pub mod pypi_pdm;
pub mod pypi_pipenv;
pub mod pypi_poetry;
pub mod pypi_requirements;
pub mod pypi_uv;
pub mod pypi_wheel;
mod toml_surgery;
pub mod verify;
pub mod yarn_berry_lock;
pub mod yarn_classic_lock;

pub use path::{ecosystem_dir_for_purl, parse_vendor_path, VendorPathParts, VENDOR_DIR};
pub use state::{load_state, save_state, VendorEntry, VendorState, VENDOR_STATE_REL};

use crate::patch::apply::ApplyResult;

/// A non-fatal advisory surfaced as a warning event (`code` is a stable
/// reason tag from the CLI contract; `detail` is human text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorWarning {
    pub code: &'static str,
    pub detail: String,
}

impl VendorWarning {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// The result of one backend `vendor_*` call.
//
// `large_enum_variant`: `Done` is much bigger than `Refused` because it carries
// the full `ApplyResult` plus an `Option<VendorEntry>` (which itself holds the
// per-ecosystem `*Meta` records). That asymmetry is harmless here — a
// `VendorOutcome` is a one-shot return value, built once per backend call and
// consumed immediately by the router; it is never stored in a collection or a
// hot loop. Boxing both large fields (what the lint asks for) would only spray
// deref churn across every backend, router, and the CLI for no runtime benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VendorOutcome {
    /// Refused before any write (wrong package manager, unsupported lockfile
    /// flavor, unsafe coordinates, …). `code` is the stable reason tag.
    Refused { code: &'static str, detail: String },
    /// The backend ran. `result` carries the per-file verify/patch outcome
    /// (the same [`ApplyResult`] contract as apply); `entry` is the state
    /// record to persist — present iff `result.success` and not a dry run.
    Done {
        result: ApplyResult,
        entry: Option<VendorEntry>,
        warnings: Vec<VendorWarning>,
    },
}

/// The result of one backend `revert_*` call.
#[derive(Debug)]
pub struct RevertOutcome {
    pub success: bool,
    pub warnings: Vec<VendorWarning>,
    pub error: Option<String>,
}

impl RevertOutcome {
    pub fn ok() -> Self {
        Self {
            success: true,
            warnings: Vec::new(),
            error: None,
        }
    }

    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            success: false,
            warnings: Vec::new(),
            error: Some(error.into()),
        }
    }
}

/// True iff this build can vendor this PURL's ecosystem.
pub fn is_vendorable(purl: &str) -> bool {
    ecosystem_dir_for_purl(purl).is_some()
}

/// Cheap probe used by `apply` to respect vendor ownership: is `purl`
/// recorded as vendored in the committed ledger?
pub async fn is_purl_vendored(project_root: &std::path::Path, purl: &str) -> bool {
    match load_state(project_root).await {
        Ok(state) => {
            state.entries.contains_key(purl) || state.entries.values().any(|e| e.base_purl == purl)
        }
        Err(_) => false,
    }
}
