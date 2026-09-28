//! `socket-patch hosted-bundle` (hidden, internal): run the in-memory
//! hosted engine over a JSON bundle read from stdin and print its result.
//! A parity/debugging harness for [`crate::hosted_memory`]: the patch API
//! is the authenticated org API built from the global `--api-url` /
//! `--api-token` / `--org` arguments, which (like every command's) fall back
//! to `SOCKET_API_URL` / `SOCKET_API_TOKEN` / `SOCKET_ORG_SLUG` — so an
//! exported production token is used, reference grants included. It never
//! uses the public proxy, and the engine itself reads no environment.
//!
//! Stdin: `{"files": {path: text}, "binaryFiles"?: {path: base64},
//! "presentOnly"?: [path], "symlinks"?: [path], "projectRoots"?: [dir],
//! "pipenvMajor"?: n, "batchSize"?: n, "maxNewPatches"?: n | "none",
//! "maxNewPatchesCap"?: n, "inFlightPatches"?: [purl]}`. Stdout: the engine result
//! (`HostedScanResult`, binary contents base64), or
//! `{"status":"error","error":{"code","message"}}` with exit 2 for bad
//! credentials/bundle input, or exit 1 for an engine failure.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use base64::Engine;
use clap::Args;
use serde::Deserialize;
use socket_patch_core::api::client::{ApiClient, ApiClientOptions};
use socket_patch_core::constants::DEFAULT_SOCKET_API_URL;
use tokio_util::sync::CancellationToken;

use crate::args::GlobalArgs;
use crate::hosted_memory::{
    run_in_memory, EngineError, HostedScanOptions, MarkKind, PresentKind, SessionBuilder,
};

#[derive(Args)]
pub struct HostedBundleArgs {
    #[command(flatten)]
    pub common: GlobalArgs,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    #[serde(default)]
    files: BTreeMap<String, String>,
    #[serde(default)]
    binary_files: BTreeMap<String, String>,
    #[serde(default)]
    present_only: Vec<String>,
    #[serde(default)]
    symlinks: Vec<String>,
    #[serde(default)]
    project_roots: Option<Vec<String>>,
    #[serde(default)]
    pipenv_major: Option<u32>,
    #[serde(default)]
    batch_size: Option<u32>,
    #[serde(default)]
    max_new_patches: Option<crate::hosted_memory::MaxNewPatchesOption>,
    #[serde(default)]
    max_new_patches_cap: Option<u32>,
    #[serde(default)]
    in_flight_patches: Option<Vec<String>>,
}

fn print_error(code: &str, message: &str) {
    println!(
        "{}",
        serde_json::json!({ "status": "error", "error": { "code": code, "message": message } })
    );
}

fn build_input(
    bundle: Bundle,
    options: HostedScanOptions,
) -> Result<crate::hosted_memory::HostedScanInput, EngineError> {
    let mut builder = SessionBuilder::new(options)?;
    for (path, text) in &bundle.files {
        builder.add_text(path, text)?;
    }
    for (path, encoded) in &bundle.binary_files {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| EngineError::InvalidInput {
                code: "invalid_base64",
                message: format!("binaryFiles[{path}]: {e}"),
            })?;
        builder.add_binary(path, &bytes)?;
    }
    for path in &bundle.present_only {
        builder.mark_present(path, MarkKind::Present(PresentKind::Present))?;
    }
    for path in &bundle.symlinks {
        builder.mark_present(path, MarkKind::Symlink)?;
    }
    builder.finish()
}

pub async fn run(args: HostedBundleArgs) -> i32 {
    let common = &args.common;
    let (Some(token), Some(org)) = (
        common.api_token.clone().filter(|t| !t.is_empty()),
        common.org.clone().filter(|o| !o.is_empty()),
    ) else {
        print_error(
            "missing_credentials",
            "hosted-bundle requires --api-token and --org",
        );
        return 2;
    };
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        print_error("invalid_bundle", &format!("cannot read stdin: {e}"));
        return 2;
    }
    let bundle: Bundle = match serde_json::from_str(&raw) {
        Ok(bundle) => bundle,
        Err(e) => {
            print_error("invalid_bundle", &e.to_string());
            return 2;
        }
    };
    let options = HostedScanOptions {
        org_slug: org.clone(),
        ecosystems: common.ecosystems.clone(),
        batch_size: bundle.batch_size,
        dry_run: common.dry_run,
        pipenv_major: bundle.pipenv_major,
        trust_lockfile_config: Some(!common.no_trust_lockfile_config),
        npm_allow_remote_config: Some(!common.no_npm_allow_remote_config),
        project_roots: bundle.project_roots.clone(),
        max_new_patches: bundle.max_new_patches,
        max_new_patches_cap: bundle.max_new_patches_cap,
        in_flight_patches: bundle.in_flight_patches.clone(),
        ..HostedScanOptions::default()
    };
    let input = match build_input(bundle, options) {
        Ok(input) => input,
        Err(e) => {
            print_error(e.code(), &e.to_string());
            return 2;
        }
    };
    let client = ApiClient::new(ApiClientOptions {
        api_url: common
            .api_url
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_SOCKET_API_URL.to_string()),
        api_token: Some(token),
        use_public_proxy: false,
        org_slug: Some(org),
    });
    match run_in_memory(input, Arc::new(client), CancellationToken::new()).await {
        Ok(output) => match serde_json::to_string_pretty(&output) {
            Ok(text) => {
                println!("{text}");
                0
            }
            Err(e) => {
                print_error("engine_internal", &e.to_string());
                1
            }
        },
        Err(e) => {
            print_error(e.code(), &e.to_string());
            1
        }
    }
}
