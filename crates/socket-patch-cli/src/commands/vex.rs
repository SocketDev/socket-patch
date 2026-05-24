//! `socket-patch vex` — generate an OpenVEX 0.2.0 document.
//!
//! Reads the local manifest, optionally verifies each patch's on-disk
//! state, and emits a VEX document describing the vulnerabilities that
//! have been mitigated. Designed to be piped into vexctl, Grype, Trivy,
//! and the like.
//!
//! Output channels:
//! * Default (`--output` unset, `--json` unset): VEX JSON to stdout,
//!   human-readable status to stderr.
//! * `--output <path>` (no `--json`): VEX JSON to file, one-line
//!   summary to stdout.
//! * `--json` (requires `--output`): VEX JSON to file, envelope JSON
//!   to stdout. This is the CI integration shape.

use std::collections::HashMap;
use std::path::PathBuf;

use clap::Args;
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::vex::{
    build_document, detect_product, BuildOptions, FailedPatch, VerifyOutcome,
};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent,
};

#[derive(Args)]
pub struct VexArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Write the VEX document to this path instead of stdout.
    #[arg(long = "output", short = 'O', env = "SOCKET_VEX_OUTPUT")]
    pub output: Option<PathBuf>,

    /// Override the auto-detected top-level product PURL/identifier.
    #[arg(long = "product", env = "SOCKET_VEX_PRODUCT")]
    pub product: Option<String>,

    /// Skip the on-disk file-hash check and trust the manifest.
    /// By default every manifest entry is verified before being
    /// emitted; this flag flips that off — useful when generating a
    /// VEX doc on a build machine that doesn't have the patched files
    /// laid out yet.
    #[arg(long = "no-verify", env = "SOCKET_VEX_NO_VERIFY", default_value_t = false)]
    pub no_verify: bool,

    /// Override the document `@id`. Default is `urn:uuid:<random v4>`,
    /// regenerated on every invocation. Pin this to get a reproducible
    /// doc identifier across runs.
    #[arg(long = "doc-id", env = "SOCKET_VEX_DOC_ID")]
    pub doc_id: Option<String>,

    /// Emit compact JSON instead of pretty-printed.
    #[arg(long = "compact", env = "SOCKET_VEX_COMPACT", default_value_t = false)]
    pub compact: bool,
}

pub async fn run(args: VexArgs) -> i32 {
    apply_env_toggles(&args.common);

    // --json without --output would race the envelope and the VEX doc
    // on the same stdout stream. Bail out with a clear error before
    // doing any work.
    if args.common.json && args.output.is_none() {
        emit_envelope_error(
            &args,
            "json_requires_output",
            "--json requires --output (the VEX document is itself JSON; \
             route it to a file so the envelope can use stdout)",
        );
        return 2;
    }

    let manifest_path = args.common.resolved_manifest_path();

    let manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            emit_envelope_error(
                &args,
                "manifest_not_found",
                &format!("Manifest not found at {}", manifest_path.display()),
            );
            return 2;
        }
        Err(e) => {
            emit_envelope_error(&args, "manifest_unreadable", &e.to_string());
            return 2;
        }
    };

    if manifest.patches.is_empty() {
        emit_envelope_error(
            &args,
            "no_patches",
            "Manifest is empty — nothing to attest. Run `socket-patch get` \
             or `socket-patch scan --sync` first.",
        );
        return 1;
    }

    // Resolve product.
    let product_id = match resolve_product_id(&args).await {
        Ok(id) => id,
        Err(reason) => {
            emit_envelope_error(&args, "product_undetected", &reason);
            return 2;
        }
    };

    // Partition manifest into applied / failed.
    let outcome = if args.no_verify {
        VerifyOutcome {
            applied: manifest.patches.keys().cloned().collect(),
            failed: Vec::new(),
        }
    } else {
        let package_paths = resolve_package_paths(&args, &manifest).await;
        socket_patch_core::vex::applied_patches(&manifest, &package_paths).await
    };

    if !outcome.failed.is_empty() && !args.common.silent && !args.common.json {
        for f in &outcome.failed {
            eprintln!(
                "Warning: omitting patch for {} from VEX ({})",
                f.purl, f.reason
            );
        }
    }

    // Build the document.
    let opts = BuildOptions {
        product_id,
        doc_id: args
            .doc_id
            .clone()
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
        author: "Socket".to_string(),
        tooling: Some(format!("socket-patch {}", env!("CARGO_PKG_VERSION"))),
    };

    let doc = match build_document(&manifest, &outcome.applied, &opts) {
        Some(doc) => doc,
        None => {
            emit_envelope_error_with_failures(
                &args,
                "no_applicable_patches",
                "No applied patches with vulnerability metadata to attest.",
                &outcome.failed,
            );
            return 1;
        }
    };

    // Serialize.
    let serialized = if args.compact {
        match serde_json::to_string(&doc) {
            Ok(s) => s,
            Err(e) => {
                emit_envelope_error(&args, "serialize_failed", &e.to_string());
                return 2;
            }
        }
    } else {
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => s,
            Err(e) => {
                emit_envelope_error(&args, "serialize_failed", &e.to_string());
                return 2;
            }
        }
    };

    // Write.
    let wrote_to_file = match &args.output {
        Some(path) => {
            if let Err(e) = tokio::fs::write(path, &serialized).await {
                emit_envelope_error(&args, "write_failed", &e.to_string());
                return 2;
            }
            true
        }
        None => {
            println!("{serialized}");
            false
        }
    };

    // Status reporting.
    if args.common.json {
        emit_envelope_success(&args, &doc, &outcome.failed);
    } else if wrote_to_file {
        let path = args.output.as_ref().unwrap().display();
        let stmt_count = doc.statements.len();
        if !args.common.silent {
            println!(
                "Wrote OpenVEX document with {stmt_count} statement(s) to {path}"
            );
        }
    } else if !args.common.silent && !args.common.json {
        let stmt_count = doc.statements.len();
        eprintln!("Emitted {stmt_count} VEX statement(s)");
    }

    0
}

/// Pick the product PURL from `--product` or by filesystem auto-detect.
async fn resolve_product_id(args: &VexArgs) -> Result<String, String> {
    if let Some(p) = &args.product {
        return Ok(p.clone());
    }
    let detect = detect_product(&args.common.cwd).await;
    for w in &detect.warnings {
        if !args.common.silent && !args.common.json {
            eprintln!("Warning: {w}");
        }
    }
    detect.purl.ok_or_else(|| {
        format!(
            "Could not auto-detect a top-level product PURL in {}. \
             Provide one with --product <purl> (e.g. pkg:npm/my-app@1.0.0).",
            args.common.cwd.display()
        )
    })
}

/// Walk the ecosystem dispatch to build the PURL -> on-disk-path map
/// used by `vex::verify::applied_patches`.
async fn resolve_package_paths(
    args: &VexArgs,
    manifest: &PatchManifest,
) -> HashMap<String, PathBuf> {
    let purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned = partition_purls(&purls, args.common.ecosystems.as_deref());
    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        batch_size: 0, // unused for find_packages_for_purls
    };
    find_packages_for_purls(&partitioned, &crawler_options, args.common.silent).await
}

fn emit_envelope_error(args: &VexArgs, code: &str, message: &str) {
    if args.common.json {
        let mut env = Envelope::new(Command::Vex);
        env.mark_error(EnvelopeError::new(code, message.to_string()));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
    }
}

fn emit_envelope_error_with_failures(
    args: &VexArgs,
    code: &str,
    message: &str,
    failures: &[FailedPatch],
) {
    if args.common.json {
        let mut env = Envelope::new(Command::Vex);
        for f in failures {
            env.record(
                PatchEvent::new(PatchAction::Skipped, f.purl.clone())
                    .with_reason(f.reason.clone(), "patch omitted from VEX"),
            );
        }
        env.mark_error(EnvelopeError::new(code, message.to_string()));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
        for f in failures {
            eprintln!("  omitted: {} ({})", f.purl, f.reason);
        }
    }
}

fn emit_envelope_success(
    _args: &VexArgs,
    doc: &socket_patch_core::vex::Document,
    failures: &[FailedPatch],
) {
    let mut env = Envelope::new(Command::Vex);
    for st in &doc.statements {
        for prod in &st.products {
            for sub in &prod.subcomponents {
                env.record(
                    PatchEvent::new(PatchAction::Verified, sub.id.clone())
                        .with_details(serde_json::json!({
                            "vulnerability": st.vulnerability.name,
                            "aliases": st.vulnerability.aliases,
                            "status": "not_affected",
                        })),
                );
            }
        }
    }
    for f in failures {
        env.record(
            PatchEvent::new(PatchAction::Skipped, f.purl.clone())
                .with_reason(f.reason.clone(), "patch omitted from VEX"),
        );
    }
    if !failures.is_empty() {
        env.mark_partial_failure();
    }
    println!("{}", env.to_pretty_json());
}

#[cfg(test)]
mod tests {
    //! Lightweight tests at the args/wiring layer. End-to-end behavior
    //! lives in `tests/e2e_vex*.rs`.
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(subcommand)]
        cmd: Sub,
    }

    #[derive(clap::Subcommand)]
    enum Sub {
        Vex(VexArgs),
    }

    #[test]
    fn parses_with_defaults() {
        let w = Wrap::parse_from(["test", "vex"]);
        match w.cmd {
            Sub::Vex(args) => {
                assert!(args.output.is_none());
                assert!(args.product.is_none());
                assert!(!args.no_verify);
                assert!(args.doc_id.is_none());
                assert!(!args.compact);
            }
        }
    }

    #[test]
    fn parses_all_flags() {
        let w = Wrap::parse_from([
            "test",
            "vex",
            "--output",
            "out.vex.json",
            "--product",
            "pkg:npm/app@1.0.0",
            "--no-verify",
            "--doc-id",
            "urn:uuid:fixed",
            "--compact",
        ]);
        match w.cmd {
            Sub::Vex(args) => {
                assert_eq!(args.output.unwrap().to_str(), Some("out.vex.json"));
                assert_eq!(args.product.as_deref(), Some("pkg:npm/app@1.0.0"));
                assert!(args.no_verify);
                assert_eq!(args.doc_id.as_deref(), Some("urn:uuid:fixed"));
                assert!(args.compact);
            }
        }
    }
}
