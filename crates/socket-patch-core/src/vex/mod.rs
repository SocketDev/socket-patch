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
pub use verify::{
    applied_patches, applied_patches_with_vendor, FailedPatch, VendorContext, VerifyOutcome,
};

#[cfg(test)]
mod conformance_tests;

#[cfg(test)]
mod reexport_tests {
    //! Compile-only smoke tests for the public surface. If a future
    //! refactor drops a `pub use` line, this module will fail to
    //! compile — the visible symptom we want.

    use super::*;

    #[test]
    fn every_reexport_is_usable_from_vex_namespace() {
        // Names — just touching each one keeps the linker honest.
        let _: &str = OPENVEX_CONTEXT_V0_2_0;

        // Types instantiable via Default or struct literal.
        let _ = DetectResult::default();
        let _ = VerifyOutcome::default();
        let _ = FailedPatch {
            purl: String::new(),
            reason: String::new(),
        };
        let _ = BuildOptions {
            product_id: String::new(),
            doc_id: String::new(),
            author: String::new(),
            tooling: None,
        };
        let _ = Vulnerability {
            name: "GHSA-x".to_string(),
            aliases: Vec::new(),
        };
        let _ = Subcomponent {
            id: "pkg:npm/x@1".to_string(),
            identifiers: None,
            hashes: None,
        };
        let _ = Product {
            id: "pkg:npm/app@1.0".to_string(),
            identifiers: None,
            hashes: None,
            subcomponents: Vec::new(),
        };
        let _ = Statement {
            id: None,
            vulnerability: Vulnerability {
                name: "GHSA-x".to_string(),
                aliases: Vec::new(),
            },
            timestamp: None,
            last_updated: None,
            products: Vec::new(),
            status: Status::NotAffected,
            supplier: None,
            justification: Some(Justification::InlineMitigationsAlreadyExist),
            impact_statement: None,
            action_statement: None,
        };
        let _ = Document {
            context: OPENVEX_CONTEXT_V0_2_0.to_string(),
            id: String::new(),
            author: String::new(),
            role: None,
            timestamp: String::new(),
            last_updated: None,
            version: 1,
            tooling: None,
            statements: Vec::new(),
        };

        // Functions — reference them so an accidental rename
        // surfaces here. We can't easily type async fns with
        // reference parameters as `fn(_)` pointers (the lifetime
        // bound goes through the returned future), so just take
        // their address and discard it; the resolver will error if
        // the symbol disappears.
        let _ = build_document as *const ();
        let _ = detect_product as *const ();
        let _ = applied_patches as *const ();
    }
}
