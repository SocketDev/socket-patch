//! OpenVEX 0.2.0 document generation from a Socket Patch manifest.
//!
//! Self-contained so it can be lifted into its own crate later. The
//! module is organized as:
//!
//! * [`schema`] — hand-rolled OpenVEX 0.2.0 serde structs.
//! * [`build`] — manifest + applied-set → [`schema::Document`].
//! * [`product`] — auto-detect the top-level product PURL from the
//!   filesystem (package.json / pyproject.toml / Cargo.toml).
//! * [`verify`] — partition manifest entries by on-disk hash check.
//! * [`time`] — minimal RFC 3339 timestamp formatter (no chrono).
//!
//! Cross-references against the Go reference implementation
//! (<https://github.com/openvex/go-vex>) live next to the affected
//! struct in [`schema`].

pub mod build;
pub mod product;
pub mod schema;
pub mod time;
pub mod verify;

pub use build::{build_document, BuildOptions};
pub use product::{detect_product, DetectResult};
pub use schema::{
    Document, Justification, Product, Statement, Status, Subcomponent, Vulnerability,
    OPENVEX_CONTEXT_V0_2_0,
};
pub use verify::{applied_patches, FailedPatch, VerifyOutcome};
