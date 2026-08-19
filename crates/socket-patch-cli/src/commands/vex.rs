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
use std::path::{Path, PathBuf};

use clap::Args;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{track_vex_failed, track_vex_generated};
use socket_patch_core::vex::{
    build_document, detect_product, BuildOptions, Document, FailedPatch, VendorContext,
    VerifyOutcome,
};

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::ecosystem_dispatch::find_manifest_package_paths;
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent, RunWarning};

/// Routing tag for a patch omitted from VEX by the property-7 ecosystem
/// filter alone: the patch IS applied (byte-verified, or trusted under
/// `--no-verify`) and carries vulnerability metadata, but its ecosystem has
/// no install hook set up and is not declared `manual`. Distinct from the
/// verification tags (`hash_mismatch`, `package_not_found`, …) so a JSON
/// consumer can tell "not patched" from "patched but not persisted by any
/// hook" — before this tag existed the drop was machine-invisible.
const ECOSYSTEM_NOT_SETUP: &str = "ecosystem_not_setup";

#[derive(Args)]
pub struct VexArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Write the VEX document to this path instead of stdout.
    #[arg(long = "output", short = 'O', env = "SOCKET_VEX_OUTPUT")]
    pub output: Option<PathBuf>,

    /// Override the auto-detected top-level product PURL/identifier.
    /// Auto-detection probes (in order):
    /// 1. `.git/config` `[remote "origin"]` — converted to
    ///    `pkg:github/<owner>/<repo>` for github.com, similar for
    ///    gitlab.com/bitbucket.org, raw URL otherwise.
    /// 2. `package.json` → `pkg:npm/<name>@<version>`
    /// 3. `pyproject.toml` → `pkg:pypi/<name>@<version>`
    /// 4. `Cargo.toml` → `pkg:cargo/<name>@<version>`
    #[arg(long = "product", env = "SOCKET_VEX_PRODUCT")]
    pub product: Option<String>,

    /// Skip the on-disk file-hash check and trust the manifest.
    /// By default every manifest entry is verified before being
    /// emitted; this flag flips that off — useful when generating a
    /// VEX doc on a build machine that doesn't have the patched files
    /// laid out yet.
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    /// clap's default bool parser accepts only the literal strings
    /// `true`/`false` from the env binding, so `SOCKET_VEX_NO_VERIFY=1` (or
    /// an exported-but-empty `SOCKET_VEX_NO_VERIFY=`) aborted the parse.
    /// This var is also outside `GLOBAL_ARG_ENV_VARS`, so `main`'s empty-var
    /// scrub never rescues it.
    #[arg(
        long = "no-verify",
        env = "SOCKET_VEX_NO_VERIFY",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub no_verify: bool,

    /// Override the document `@id`. Default is `urn:uuid:<random v4>`,
    /// regenerated on every invocation. Pin this to get a reproducible
    /// doc identifier across runs.
    #[arg(long = "doc-id", env = "SOCKET_VEX_DOC_ID")]
    pub doc_id: Option<String>,

    /// Emit compact JSON instead of pretty-printed.
    #[arg(
        long = "compact",
        env = "SOCKET_VEX_COMPACT",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub compact: bool,
}

/// VEX-generation knobs embedded into `apply` and `scan` via `--vex`.
///
/// `--vex <path>` is the trigger: when set, the host command generates an
/// OpenVEX document at that path after a successful run. The remaining
/// `--vex-*` flags mirror the standalone `vex` command's knobs but are
/// namespaced so they don't collide with the host command's own
/// vocabulary (e.g. apply's `--force`). They are inert unless `--vex` is
/// set.
#[derive(Args, Default, Clone)]
pub struct VexEmbedArgs {
    /// Generate an OpenVEX 0.2.0 document at this path after a successful
    /// run. The document is always written to the file (never stdout), so
    /// it never races the command's own `--json` output.
    #[arg(long = "vex", env = "SOCKET_VEX")]
    pub vex: Option<PathBuf>,

    /// Override the auto-detected top-level product PURL for the VEX
    /// document. See `socket-patch vex --product`.
    #[arg(long = "vex-product", env = "SOCKET_VEX_PRODUCT")]
    pub vex_product: Option<String>,

    /// Skip the on-disk file-hash check when building the VEX document and
    /// trust the manifest. See `socket-patch vex --no-verify`.
    ///
    /// `value_parser = parse_bool_flag`: these embedded flags share their
    /// env vars with the standalone `vex` flags, so without it an ambient
    /// `SOCKET_VEX_NO_VERIFY=1` (or `=`) aborted every host command parse —
    /// including `apply` running from a postinstall hook.
    #[arg(
        long = "vex-no-verify",
        env = "SOCKET_VEX_NO_VERIFY",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub vex_no_verify: bool,

    /// Pin the VEX document `@id`. See `socket-patch vex --doc-id`.
    #[arg(long = "vex-doc-id", env = "SOCKET_VEX_DOC_ID")]
    pub vex_doc_id: Option<String>,

    /// Emit compact (non-pretty) JSON for the VEX document.
    #[arg(
        long = "vex-compact",
        env = "SOCKET_VEX_COMPACT",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub vex_compact: bool,
}

impl VexEmbedArgs {
    /// Build the core [`VexBuildParams`] from the embedded flags. The
    /// output is always the `--vex` path (embedded VEX never writes to
    /// stdout). Caller must have checked `self.vex.is_some()`.
    pub(crate) fn to_build_params(&self) -> VexBuildParams {
        VexBuildParams {
            output: self.vex.clone(),
            product: self.vex_product.clone(),
            no_verify: self.vex_no_verify,
            doc_id: self.vex_doc_id.clone(),
            compact: self.vex_compact,
            assume_applied: Vec::new(),
        }
    }
}

/// Plain (non-clap) inputs to [`generate_vex`] so the standalone `vex`
/// command and the embedded `apply`/`scan` paths feed one code path.
pub(crate) struct VexBuildParams {
    /// Where to write the document. `None` => stdout (standalone `vex`
    /// only); embedded callers always pass `Some(path)`.
    pub output: Option<PathBuf>,
    pub product: Option<String>,
    pub no_verify: bool,
    pub doc_id: Option<String>,
    pub compact: bool,
    /// In-run `scan --redirect --vex` only: the PURLs whose lockfile rewrite
    /// THIS RUN confirmed (their hosted-patch URL landed in a project file).
    /// These are exempt from on-disk verification — their bytes are remote
    /// until the next install; the lockfile integrity pins are the evidence —
    /// while every other manifest/vendored patch (and any stale ledger record
    /// this run did NOT confirm) still verifies normally. The post-install
    /// standalone `vex` passes an empty list so redirected patches are then
    /// hash-verified against the installed tree like any applied patch.
    pub assume_applied: Vec<String>,
}

/// Successful result of [`generate_vex`].
pub(crate) struct VexWriteSummary {
    pub statements: usize,
    pub failed: Vec<FailedPatch>,
    /// The built document — returned so the standalone `vex` command can
    /// emit its per-subcomponent envelope without rebuilding.
    pub doc: Document,
    /// Run-level advisories (non-IRI product override, vendored artifacts
    /// whose live installed tree is out of sync). Already printed to stderr
    /// in human mode by [`generate_vex`]; the standalone `vex --json` path
    /// folds them into the envelope's `warnings[]` (which is the only
    /// channel `--json` has — it silences stderr).
    pub warnings: Vec<RunWarning>,
}

/// Failure from [`generate_vex`], carrying a stable code + message the
/// caller surfaces in its own output channel.
pub(crate) struct VexGenError {
    pub code: &'static str,
    pub message: String,
    /// Patches omitted by verification, populated only for the
    /// `no_applicable_patches` case (so callers can list them).
    pub failed: Vec<FailedPatch>,
}

pub async fn run(args: VexArgs) -> i32 {
    apply_env_toggles(&args.common);

    // --json without --output would race the envelope and the VEX doc
    // on the same stdout stream. Bail out with a clear error before
    // doing any work.
    if args.common.json && args.output.is_none() {
        let e = fail(
            &args.common,
            "json_requires_output",
            "--json requires --output (the VEX document is itself JSON; \
             route it to a file so the envelope can use stdout)"
                .to_string(),
        )
        .await;
        emit_envelope_error(&args, e.code, &e.message, &[]);
        return 2;
    }

    let params = VexBuildParams {
        output: args.output.clone(),
        product: args.product.clone(),
        no_verify: args.no_verify,
        doc_id: args.doc_id.clone(),
        compact: args.compact,
        assume_applied: Vec::new(),
    };

    let manifest_path = args.common.resolved_manifest_path();
    match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
        Ok(summary) => {
            if args.common.json {
                emit_envelope_success(&summary);
            } else if let Some(path) = &args.output {
                if !args.common.silent {
                    println!(
                        "Wrote OpenVEX document with {} statement(s) to {}",
                        summary.statements,
                        path.display()
                    );
                }
            } else if !args.common.silent {
                eprintln!("Emitted {} VEX statement(s)", summary.statements);
            }
            0
        }
        // `no_applicable_patches` and `no_patches` are soft "nothing to
        // attest" cases (exit 1); every other error is a hard failure
        // (exit 2). `generate_vex_from_manifest_path` already fired
        // telemetry, so these emit-only sinks must not re-track.
        Err(e) if e.code == "no_applicable_patches" => {
            emit_envelope_error(&args, e.code, &e.message, &e.failed);
            1
        }
        // Standalone-only remediation hint: after an embedded `apply --vex`
        // / `scan --vex` run the advice would be circular, so the shared
        // path keeps the bare message and it is appended here.
        Err(e) if e.code == "no_patches" => {
            emit_envelope_error(
                &args,
                e.code,
                "Manifest is empty — nothing to attest. Run `socket-patch get` \
                 or `socket-patch scan --sync` first.",
                &[],
            );
            1
        }
        Err(e) => {
            emit_envelope_error(&args, e.code, &e.message, &[]);
            2
        }
    }
}

/// Map a `setup.manual` entry to an `Ecosystem`. Accepts the canonical
/// `cli_name` plus the friendly aliases `setup --exclude`/`--ecosystems` accept
/// (`go`/`golang`, `python`/`pypi`, `ruby`/`gem`, `php`/`composer`).
/// Unrecognized names yield `None` and are ignored.
fn ecosystem_from_manual_name(name: &str) -> Option<Ecosystem> {
    match name.to_ascii_lowercase().as_str() {
        "npm" | "yarn" | "pnpm" | "bun" => Some(Ecosystem::Npm),
        "pypi" | "python" => Some(Ecosystem::Pypi),
        "gem" | "ruby" => Some(Ecosystem::Gem),
        "cargo" | "rust" => Some(Ecosystem::Cargo),
        "golang" | "go" => Some(Ecosystem::Golang),
        "composer" | "php" => Some(Ecosystem::Composer),
        // The apply-only ecosystems are the primary use of `manual` (hand-applied
        // patches with no auto-install hook); they must map too.
        "maven" | "java" => Some(Ecosystem::Maven),
        "nuget" | "dotnet" => Some(Ecosystem::Nuget),
        "deno" | "jsr" => Some(Ecosystem::Deno),
        _ => None,
    }
}

/// Core VEX pipeline shared by the standalone `vex` command and the
/// embedded `apply`/`scan` `--vex` paths: resolve the product, verify the
/// manifest against disk (unless `no_verify`), build the OpenVEX document,
/// serialize, write (or print to stdout when `output` is `None`), and fire
/// telemetry. Returns a [`VexWriteSummary`] on success or a structured
/// [`VexGenError`] (with a stable code) on failure. All `track_vex_*`
/// telemetry is fired here so every caller reports consistently.
async fn generate_vex(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest: &PatchManifest,
    redirected: &[String],
) -> Result<VexWriteSummary, VexGenError> {
    // Resolve product.
    let product_id = match resolve_product_id(common, params.product.as_deref()).await {
        Ok(id) => id,
        Err(reason) => return Err(fail(common, "product_undetected", reason).await),
    };

    let mut warnings: Vec<RunWarning> = Vec::new();

    // The help text promises "PURL/identifier", so an arbitrary string is
    // accepted — but the OpenVEX spec types the product `@id` as an IRI, and
    // strict consumers (vexctl et al.) may reject or mis-key a bare name.
    // Warn (never hard-reject) when the EXPLICIT override carries no scheme;
    // auto-detected products are always `pkg:` PURLs and need no check.
    if let Some(p) = params
        .product
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        if !has_iri_scheme(p) {
            note_warning(
                &mut warnings,
                common,
                "product_not_iri",
                format!(
                    "product override {p:?} (--product / --vex-product) is neither a PURL \
                     (pkg:...) nor an absolute IRI; it is emitted verbatim as the OpenVEX \
                     product @id, which the spec requires to be an IRI — strict consumers may \
                     reject the document. Prefer pkg:<type>/<name>@<version>."
                ),
            );
        }
    }

    // Partition manifest into applied / failed.
    let mut outcome = if params.no_verify {
        // Trust-the-manifest mode still needs the vendored classification:
        // the property-7 exemption and the "(vendored)" phrasing key off
        // `outcome.vendored`, and both are about how the patch persists,
        // not whether this run hashed it. The committed ledger is as
        // trustworthy as the manifest beside it, and reading it hashes
        // nothing. An unreadable ledger degrades to "nothing vendored".
        let entries = socket_patch_core::vendor::load_state(&common.cwd)
            .await
            .map(|state| state.entries)
            .unwrap_or_default();
        let vendored = manifest
            .patches
            .keys()
            .filter(|purl| socket_patch_core::vendor::lookup_entry(&entries, purl).is_some())
            .cloned()
            .collect();
        VerifyOutcome {
            applied: manifest.patches.keys().cloned().collect(),
            vendored,
            ..Default::default()
        }
    } else {
        // stdout belongs to machine output here: the envelope in `--json`
        // mode, or the VEX document itself when `output` is None. Silence
        // the dispatch's human chrome ("Using <X> at: ...") in both,
        // mirroring apply/rollback's `silent || json` gating.
        let quiet = common.silent || common.json || params.output.is_none();
        let purls: Vec<String> = manifest.patches.keys().cloned().collect();
        let package_paths = find_manifest_package_paths(&purls, common, quiet).await;
        let vendor = load_vendor_context(common, manifest).await;
        socket_patch_core::vex::applied_patches_with_vendor(
            manifest,
            &package_paths,
            vendor.as_ref(),
        )
        .await
    };

    // In-run `scan --redirect --vex`: the bytes of deps THAT RUN confirmed
    // redirected live on the patch server until the next install, so their
    // verification against the local tree would spuriously fail
    // (package_not_found / not_applied). Exempt exactly those PURLs —
    // everything else above verified normally, including any stale ledger
    // record the run did not re-confirm (a reverted lockfile or a withdrawn
    // patch must not keep attesting).
    if !params.assume_applied.is_empty() {
        let exempt: std::collections::HashSet<&str> =
            params.assume_applied.iter().map(|s| s.as_str()).collect();
        outcome.failed.retain(|f| !exempt.contains(f.purl.as_str()));
        for purl in &params.assume_applied {
            if manifest.patches.contains_key(purl) && !outcome.applied.iter().any(|p| p == purl) {
                outcome.applied.push(purl.clone());
            }
        }
    }

    // Vendored disclosure: the committed artifact verified (the attestation
    // stands — the committables are what the lockfile consumes) but the LIVE
    // installed tree is present and running different bytes. Say so — a
    // build that bypasses the vendor wiring is unpatched until the next
    // package-manager install.
    for purl in &outcome.vendored_out_of_sync {
        note_warning(
            &mut warnings,
            common,
            "vendored_tree_out_of_sync",
            format!(
                "{purl}: the installed tree does not match its vendored artifact; the \
                 attestation is based on the committed .socket/vendor artifact (the lockfile \
                 consumes it), but the live tree carries different bytes — re-run your \
                 package manager's install to resync it."
            ),
        );
    }

    // Property 7: attest a patch only for an ecosystem that is actually set up —
    // or explicitly declared `manual` in the manifest. Patches for an ecosystem
    // that is neither are dropped regardless of verification mode (so even
    // `--no-verify` won't attest an un-set-up ecosystem's patches).
    // Exemption: VENDORED patches bypass the filter — the committed
    // `.socket/vendor/` artifact + lockfile wiring IS the persistence
    // mechanism, so no install hook exists (or is needed) by construction.
    let vendored_set: std::collections::HashSet<String> =
        outcome.vendored.iter().cloned().collect();
    // Redirected patches (from `scan --redirect`) bypass the property-7
    // ecosystem filter for the same reason vendored ones do: the committed
    // lockfile rewrite IS the persistence mechanism, so no install hook exists
    // (or is needed) by construction.
    let redirected_set: std::collections::HashSet<&str> =
        redirected.iter().map(|s| s.as_str()).collect();
    let mut allowed = crate::commands::setup::configured_ecosystems(common).await;
    if let Some(s) = &manifest.setup {
        for name in &s.manual {
            if let Some(e) = ecosystem_from_manual_name(name) {
                allowed.insert(e);
            }
        }
    }
    let mut setup_filtered: Vec<String> = Vec::new();
    outcome.applied.retain(|purl| {
        let keep = vendored_set.contains(purl)
            || redirected_set.contains(purl.as_str())
            || Ecosystem::from_purl(purl)
                .map(|e| allowed.contains(&e))
                .unwrap_or(false);
        if !keep {
            setup_filtered.push(purl.clone());
        }
        keep
    });
    if !setup_filtered.is_empty() && !common.silent && !common.json {
        eprintln!(
            "Note: omitting patches for ecosystems that are not set up (and not declared `manual` \
             in .socket/manifest.json's `setup.manual`) from VEX."
        );
    }
    // The filter drops join the omission channel (`failed`) with their own
    // routing tag so they surface as per-purl `skipped` events in the
    // envelope — success and error paths alike. Before this they existed
    // only as the human-mode note above, leaving `--json` consumers unable
    // to distinguish "patched but no persistence hook" from "not patched".
    outcome
        .failed
        .extend(setup_filtered.into_iter().map(|purl| FailedPatch {
            purl,
            reason: ECOSYSTEM_NOT_SETUP.to_string(),
        }));

    if !outcome.failed.is_empty() && !common.silent && !common.json {
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
        // Same "empty means unset" rule as the product override above: the
        // document `@id` is a required field with no `skip_serializing_if`,
        // so `--doc-id "$UNSET_VAR"` emitted a literal `"@id": ""`.
        doc_id: params
            .doc_id
            .clone()
            .filter(|d| !d.trim().is_empty())
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
        author: "Socket".to_string(),
        tooling: Some(format!("socket-patch {}", env!("CARGO_PKG_VERSION"))),
    };

    let doc = match build_document(
        manifest,
        &outcome.applied,
        &outcome.vendored,
        redirected,
        &opts,
    ) {
        Some(doc) => doc,
        None => {
            let (token, org) = crate::commands::list::telemetry_credentials(common);
            track_vex_failed("no_applicable_patches", token.as_deref(), org.as_deref()).await;
            // When nothing attested and EVERY omission was the property-7
            // filter, say so: those patches ARE applied with vulnerability
            // metadata, and the generic message below would read as "not
            // patched" to a human. The code stays `no_applicable_patches` —
            // it is the documented exit-1 routing tag consumers already
            // branch on; the per-event `ecosystem_not_setup` errorCode is
            // the machine-readable discriminator.
            let all_setup_drops = outcome.applied.is_empty()
                && !outcome.failed.is_empty()
                && outcome
                    .failed
                    .iter()
                    .all(|f| f.reason == ECOSYSTEM_NOT_SETUP);
            let message = if all_setup_drops {
                format!(
                    "{} applied patch(es) with vulnerability metadata were omitted from VEX \
                     because their ecosystems are not set up (no install hook) and not declared \
                     `manual` in .socket/manifest.json's `setup.manual`. Run `socket-patch \
                     setup`, or add the ecosystem to `setup.manual`, then re-run.",
                    outcome.failed.len()
                )
            } else {
                "No applied patches with vulnerability metadata to attest.".to_string()
            };
            return Err(VexGenError {
                code: "no_applicable_patches",
                message,
                failed: outcome.failed,
            });
        }
    };

    // Serialize.
    let serialized = match if params.compact {
        serde_json::to_string(&doc)
    } else {
        serde_json::to_string_pretty(&doc)
    } {
        Ok(s) => s,
        Err(e) => return Err(fail(common, "serialize_failed", e.to_string()).await),
    };

    // Write.
    let wrote_to_file = match &params.output {
        Some(path) => {
            if let Err(e) = tokio::fs::write(path, &serialized).await {
                // The raw io::Error ("No such file or directory (os error
                // 2)") names neither the file nor the operation — useless
                // in a CI log. Say what was being written and where.
                return Err(fail(
                    common,
                    "write_failed",
                    format!("failed to write VEX document to {}: {e}", path.display()),
                )
                .await);
            }
            true
        }
        None => {
            println!("{serialized}");
            false
        }
    };

    let (token, org) = crate::commands::list::telemetry_credentials(common);
    track_vex_generated(
        doc.statements.len(),
        "openvex-0.2.0",
        if wrote_to_file { "file" } else { "stdout" },
        token.as_deref(),
        org.as_deref(),
    )
    .await;

    Ok(VexWriteSummary {
        statements: doc.statements.len(),
        failed: outcome.failed,
        doc,
        warnings,
    })
}

/// Record a run-level advisory the way `update`/`vendor` do: stderr
/// (`Warning: <detail>`) in human mode, and into `warnings` so the `--json`
/// envelope — which silences stderr — carries it in `warnings[]` instead.
/// Under `--silent` only the envelope copy survives (warnings are not
/// errors).
fn note_warning(warnings: &mut Vec<RunWarning>, common: &GlobalArgs, code: &str, detail: String) {
    if !common.silent && !common.json {
        eprintln!("Warning: {detail}");
    }
    warnings.push(RunWarning {
        code: code.to_string(),
        detail,
    });
}

/// True when `s` opens with an RFC 3986/3987 scheme
/// (`ALPHA *(ALPHA / DIGIT / "+" / "-" / ".") ":"`). A purl passes the same
/// test (`pkg:` is a scheme), so one check covers both halves of the help
/// text's "PURL/identifier" promise. Deliberately shallow — the goal is to
/// catch bare names like `my-app`, not to validate full IRIs.
fn has_iri_scheme(s: &str) -> bool {
    let Some((scheme, _)) = s.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Read the manifest at `manifest_path`, then [`generate_vex`]. Manifest
/// read failures are wrapped as [`VexGenError`] so embedded callers
/// (`apply`/`scan`) get a single error channel. Used by the embedded
/// `--vex` paths, which always write to a file.
///
/// Failure contract: a run that ends in error leaves NO OpenVEX document at
/// the output path — including a stale one from a previous run. Attestation
/// semantics demand it: a pipeline reusing one `--output`/`--vex` path must
/// not ship yesterday's `not_affected` document for a tree this run could
/// no longer attest. See [`remove_stale_vex_doc`] for the deletion guard.
pub(crate) async fn generate_vex_from_manifest_path(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest_path: &Path,
) -> Result<VexWriteSummary, VexGenError> {
    let result = generate_vex_from_manifest_path_inner(common, params, manifest_path).await;
    if result.is_err() {
        remove_stale_vex_doc(params.output.as_deref()).await;
    }
    result
}

/// Delete a PRIOR run's OpenVEX document at `output` after a failed run.
/// Only a file that is recognizably OpenVEX (JSON whose `@context` names
/// openvex.dev) is removed — the guard keeps a mistyped `--output` pointing
/// at an unrelated file from being destroyed by an unrelated failure.
/// Removal errors are swallowed: the non-zero exit is the contract, the
/// deletion is hygiene.
async fn remove_stale_vex_doc(output: Option<&Path>) {
    let Some(path) = output else { return };
    let Ok(bytes) = tokio::fs::read(path).await else {
        return;
    };
    let is_openvex = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("@context")
                .and_then(|c| c.as_str())
                .map(|c| c.contains("openvex.dev"))
        })
        .unwrap_or(false);
    if is_openvex {
        let _ = tokio::fs::remove_file(path).await;
    }
}

/// [`generate_vex_from_manifest_path`] without the failure-cleanup wrapper.
async fn generate_vex_from_manifest_path_inner(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest_path: &Path,
) -> Result<VexWriteSummary, VexGenError> {
    let manifest_file = match read_manifest(manifest_path).await {
        Ok(m) => m,
        Err(e) => return Err(fail(common, "manifest_unreadable", e.to_string()).await),
    };
    let had_manifest_file = manifest_file.is_some();
    // Detached vendored patches (`scan --vendor --detached`) and redirected
    // patches (`scan --redirect`) have no manifest record; the vendor and
    // redirect ledgers' embedded copies must still attest.
    let manifest =
        augment_with_detached(common, manifest_file.unwrap_or_else(PatchManifest::new)).await;
    let (manifest, redirected) = match augment_with_redirect(common, manifest).await {
        Ok(augmented) => augmented,
        Err(corrupt) => {
            return Err(fail(common, "redirect_ledger_corrupt", corrupt.to_string()).await);
        }
    };
    if manifest.patches.is_empty() {
        if !had_manifest_file {
            return Err(fail(
                common,
                "manifest_not_found",
                format!("Manifest not found at {}", manifest_path.display()),
            )
            .await);
        }
        return Err(fail(
            common,
            "no_patches",
            "Manifest is empty — nothing to attest.".to_string(),
        )
        .await);
    }
    generate_vex(common, params, &manifest, &redirected).await
}

/// Fold detached vendor entries' embedded records into a manifest view so
/// verification and document building see them — `scan --vendor
/// --detached` patches have no manifest record by design. Keyed by the
/// ledger key; an existing manifest entry wins a collision (that purl is
/// manifest-owned and verifies against the manifest's record). An
/// unreadable ledger leaves the manifest unchanged here — verification
/// still fails closed per-entry downstream, and `load_vendor_context`
/// already warns about the unreadable state.
async fn augment_with_detached(common: &GlobalArgs, mut manifest: PatchManifest) -> PatchManifest {
    if let Ok(state) = socket_patch_core::vendor::load_state(&common.cwd).await {
        for (key, entry) in state.entries {
            if !entry.detached {
                continue;
            }
            let Some(record) = entry.record else { continue };
            manifest.patches.entry(key).or_insert(record);
        }
    }
    manifest
}

/// Fold the `scan --redirect` ledger's embedded records into a manifest view
/// and return the set of redirected PURLs (so the builder can mark them
/// `(redirected)`). Redirected patches have no `.socket/manifest.json` record
/// by design — the lockfile rewrite + this ledger IS the persistence — so,
/// like detached vendored patches, they must still be attestable. An existing
/// manifest entry wins a collision (that PURL is manifest-owned). A missing
/// ledger leaves the manifest unchanged and returns no redirected PURLs; a
/// MALFORMED ledger is a hard error — attesting with its records silently
/// dropped would produce a false document.
async fn augment_with_redirect(
    common: &GlobalArgs,
    mut manifest: PatchManifest,
) -> Result<(PatchManifest, Vec<String>), socket_patch_core::patch::redirect::CorruptRedirectState>
{
    let mut redirected = Vec::new();
    if let Some(state) =
        socket_patch_core::patch::redirect::load_redirect_state(&common.cwd).await?
    {
        for (purl, record) in state.records {
            redirected.push(purl.clone());
            manifest.patches.entry(purl).or_insert(record);
        }
    }
    Ok((manifest, redirected))
}

/// Fire `vex_failed` telemetry and build the matching [`VexGenError`].
/// Centralizes the "track then return error" pattern in [`generate_vex`].
/// Attribution goes through the same layered credential chain as
/// `list`/`setup` (flag / env / socket-cli `config.json`), not the raw
/// flags — a `socket login`-only user must not report anonymously.
async fn fail(common: &GlobalArgs, code: &'static str, message: String) -> VexGenError {
    let (token, org) = crate::commands::list::telemetry_credentials(common);
    track_vex_failed(code, token.as_deref(), org.as_deref()).await;
    VexGenError {
        code,
        message,
        failed: Vec::new(),
    }
}

/// Pick the product PURL from an explicit override or by filesystem
/// auto-detect.
async fn resolve_product_id(common: &GlobalArgs, product: Option<&str>) -> Result<String, String> {
    // An empty (or whitespace-only) override means "unset" — the semantics
    // `scrub_empty_env_vars` already gives the `SOCKET_VEX_PRODUCT=` twin and
    // `api_client_overrides` gives `--api-url ""`. Without the filter,
    // `--product "$UNSET_VAR"` sailed through to `BuildOptions::product_id`,
    // and `Product::id` is `skip_serializing_if = "String::is_empty"` — so the
    // run wrote a spec-invalid document whose statements claim `not_affected`
    // about a product carrying NO identifier at all, and exited 0.
    if let Some(p) = product.filter(|p| !p.trim().is_empty()) {
        return Ok(p.to_string());
    }
    let detect = detect_product(&common.cwd).await;
    for w in &detect.warnings {
        if !common.silent && !common.json {
            eprintln!("Warning: {w}");
        }
    }
    detect.purl.ok_or_else(|| {
        format!(
            "Could not auto-detect a top-level product PURL in {}. \
             Provide one with --product <purl> (e.g. pkg:npm/my-app@1.0.0).",
            common.cwd.display()
        )
    })
}

/// Build the [`VendorContext`] for verification: the committed
/// `.socket/vendor/state.json` ledger plus synthesized entries for the
/// legacy `.socket/go-patches/` redirect backend. Shared by `vex` and
/// `setup --check`'s patch-consistency pass — both must judge a vendored
/// patch by the committed artifact, never the installed tree.
///
/// The go-patches synthesis fixes a latent bug: an apply-redirected Go
/// patch leaves the module cache pristine (the `replace` directive routes
/// the build at the copy dir), so verifying against the crawler-resolved
/// cache path reported `not_applied`/`package_not_found` and the patch was
/// silently omitted from the VEX document. The redirect copy dir holds the
/// bytes the build actually consumes, so it is what verification must hash.
///
/// An unreadable/corrupt vendor ledger degrades to "no vendor entries"
/// (with a stderr warning): vendored PURLs then fall through to the
/// installed tree, fail verification there, and are omitted — fail-closed,
/// never falsely attested. Returns `None` when there is nothing vendored
/// and no redirect to synthesize (the common case).
pub(crate) async fn load_vendor_context(
    common: &GlobalArgs,
    manifest: &PatchManifest,
) -> Option<VendorContext> {
    let entries = match socket_patch_core::vendor::load_state(&common.cwd).await {
        Ok(state) => state.entries,
        Err(e) => {
            if !common.silent {
                eprintln!(
                    "Warning: unreadable vendor state ({e}); vendored patches cannot be \
                     verified from the committed artifact"
                );
            }
            HashMap::new()
        }
    };

    let go_patches = synthesize_go_patches(common, manifest, &entries).await;

    if entries.is_empty() && go_patches.is_empty() {
        return None;
    }
    Some(VendorContext {
        project_root: common.cwd.clone(),
        entries,
        go_patches,
    })
}

/// Synthesize go-patches redirect targets for [`load_vendor_context`]: for
/// every socket-owned (`.socket/go-patches/`) `replace` in `go.mod` whose
/// module+version maps to a manifest golang PURL with no explicit vendor
/// entry, record the absolute redirect copy dir for dir-hash verification.
async fn synthesize_go_patches(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    entries: &HashMap<String, socket_patch_core::vendor::VendorEntry>,
) -> HashMap<String, PathBuf> {
    use socket_patch_core::patch::redirect::golang_local::{
        are_safe_redirect_coords, copy_dir_for,
    };
    use socket_patch_core::utils::purl::build_golang_purl;
    use socket_patch_core::vendor::go_mod_edit::{
        read_replace_entries, ReplaceOwner, GO_PATCHES_DIR,
    };

    let mut go_patches = HashMap::new();
    for entry in read_replace_entries(&common.cwd).await {
        if entry.owner != Some(ReplaceOwner::GoPatches) {
            continue;
        }
        let Some(version) = entry.version.as_deref() else {
            continue;
        };
        let purl = build_golang_purl(&entry.module, version);
        if !manifest.patches.contains_key(&purl) {
            continue;
        }
        // Explicit vendor entries take precedence over the synthesis
        // (vendor may have taken over an apply redirect).
        if socket_patch_core::vendor::lookup_entry(entries, &purl).is_some() {
            continue;
        }
        // SECURITY: module/version come from a committed (tamper-able)
        // go.mod and are about to key a path we hash. Apply the same
        // fail-closed coordinate guard `go_redirect` itself uses before
        // building the copy-dir path.
        if !are_safe_redirect_coords(&entry.module, version) {
            continue;
        }
        go_patches.insert(
            purl,
            copy_dir_for(&common.cwd, GO_PATCHES_DIR, &entry.module, version),
        );
    }
    go_patches
}

/// Emit a `vex` error to the active output channel: an error envelope on
/// stdout in `--json` mode, a stderr message otherwise. `failures` lists
/// patches omitted by verification (populated for `no_applicable_patches`,
/// empty everywhere else).
fn emit_envelope_error(args: &VexArgs, code: &str, message: &str, failures: &[FailedPatch]) {
    if args.common.json {
        let mut env = Envelope::new(Command::Vex);
        for f in failures {
            env.record(
                PatchEvent::new(PatchAction::Skipped, f.purl.clone())
                    .with_reason(f.reason.clone(), omission_reason_message(&f.reason)),
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

/// Human `reason` string for an omission event; the routing tag rides
/// `errorCode`. The property-7 drop gets its own phrasing — that patch IS
/// applied and verified, which the generic "omitted" alone doesn't convey.
fn omission_reason_message(reason: &str) -> &'static str {
    if reason == ECOSYSTEM_NOT_SETUP {
        "applied patch omitted from VEX: its ecosystem has no install hook set up and is not \
         declared `manual` in setup.manual"
    } else {
        "patch omitted from VEX"
    }
}

fn emit_envelope_success(summary: &VexWriteSummary) {
    let mut env = Envelope::new(Command::Vex);
    for st in &summary.doc.statements {
        for prod in &st.products {
            for sub in &prod.subcomponents {
                env.record(
                    PatchEvent::new(PatchAction::Verified, sub.id.clone()).with_details(
                        serde_json::json!({
                            "vulnerability": st.vulnerability.name,
                            "aliases": st.vulnerability.aliases,
                            "status": "not_affected",
                        }),
                    ),
                );
            }
        }
    }
    for f in &summary.failed {
        env.record(
            PatchEvent::new(PatchAction::Skipped, f.purl.clone())
                .with_reason(f.reason.clone(), omission_reason_message(&f.reason)),
        );
    }
    if !summary.failed.is_empty() {
        env.mark_partial_failure();
    }
    env.warnings = summary.warnings.clone();
    println!("{}", env.to_pretty_json());
}

#[cfg(test)]
mod tests {
    //! Lightweight tests at the args/wiring layer. End-to-end behavior
    //! lives in `tests/e2e_vex*.rs`.
    use super::*;
    use clap::Parser;

    // Property 7: every ecosystem a PURL can classify to must also be
    // declarable `manual`. Apply-only maven/nuget/deno are the *primary* use of
    // `manual`; they were missing originally, silently dropping their patches.
    #[test]
    fn ecosystem_from_manual_name_maps_every_ecosystem() {
        assert_eq!(ecosystem_from_manual_name("npm"), Some(Ecosystem::Npm));
        assert_eq!(ecosystem_from_manual_name("PyPI"), Some(Ecosystem::Pypi)); // case-insensitive
        assert_eq!(ecosystem_from_manual_name("python"), Some(Ecosystem::Pypi));
        assert_eq!(ecosystem_from_manual_name("ruby"), Some(Ecosystem::Gem));
        assert_eq!(ecosystem_from_manual_name("nonsense"), None);
        assert_eq!(ecosystem_from_manual_name("cargo"), Some(Ecosystem::Cargo));
        assert_eq!(ecosystem_from_manual_name("go"), Some(Ecosystem::Golang));
        assert_eq!(
            ecosystem_from_manual_name("composer"),
            Some(Ecosystem::Composer)
        );
        assert_eq!(ecosystem_from_manual_name("maven"), Some(Ecosystem::Maven));
        assert_eq!(ecosystem_from_manual_name("nuget"), Some(Ecosystem::Nuget));
        assert_eq!(ecosystem_from_manual_name("deno"), Some(Ecosystem::Deno));
    }

    // Property 7 completeness, the reverse direction of the test above and
    // future-proof: every ecosystem the build can classify a PURL for (i.e.
    // every `Ecosystem::all()` variant) MUST round-trip through its canonical
    // `cli_name` back to itself via `ecosystem_from_manual_name`. Otherwise a
    // `manual`-declared patch for that ecosystem would be silently dropped from
    // the VEX doc by the `retain` in `generate_vex`. Iterating `all()` (rather
    // than hard-coding names) means adding a new ecosystem without wiring up its
    // `manual` alias fails this test instead of shipping a silent drop.
    #[test]
    fn every_compiled_ecosystem_is_declarable_manual_via_cli_name() {
        for &e in Ecosystem::all() {
            assert_eq!(
                ecosystem_from_manual_name(e.cli_name()),
                Some(e),
                "ecosystem {:?} (cli_name {:?}) is not reachable via ecosystem_from_manual_name — \
                 its `manual`-declared patches would be silently dropped from VEX",
                e,
                e.cli_name(),
            );
        }
    }

    /// The go-patches synthesis guards its copy-dir keys with core's
    /// `are_safe_redirect_coords`; pin the accept/reject set from the CLI
    /// side — a regression here would let a tampered go.mod `replace` key
    /// an out-of-tree path into the go-patches verification map.
    #[test]
    fn go_redirect_coord_guard_matches_core_rules() {
        use socket_patch_core::patch::redirect::golang_local::are_safe_redirect_coords;

        assert!(are_safe_redirect_coords("github.com/foo/bar", "v1.4.2"));
        assert!(are_safe_redirect_coords("gopkg.in/inf.v0", "v0.9.1"));
        assert!(are_safe_redirect_coords(
            "github.com/foo/bar/v2",
            "v2.0.0-20210101000000-abcdef123456"
        ));
        assert!(!are_safe_redirect_coords("../../../etc", "v1.0.0"));
        assert!(!are_safe_redirect_coords(
            "github.com/../../../etc",
            "v1.0.0"
        ));
        assert!(!are_safe_redirect_coords("/abs/path", "v1.0.0"));
        assert!(!are_safe_redirect_coords("github.com//bar", "v1.0.0"));
        assert!(!are_safe_redirect_coords("foo/./bar", "v1.0.0"));
        assert!(!are_safe_redirect_coords("foo\\bar", "v1.0.0"));
        assert!(!are_safe_redirect_coords("", "v1.0.0"));
        assert!(!are_safe_redirect_coords(
            "github.com/foo/bar",
            "../../../evil"
        ));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", "v1/0/0"));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", ".."));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", ""));
    }

    /// The `--product` advisory keys off [`has_iri_scheme`]: PURLs and
    /// anything scheme-shaped sail through silently; bare names (what the
    /// probe fed in) warn. Pin the accept/reject sets so the check can't
    /// drift into rejecting legal identifiers (a hard reject is explicitly
    /// out of contract — help text says "PURL/identifier").
    #[test]
    fn iri_scheme_check_accepts_purls_and_iris_rejects_bare_names() {
        // Accepted (no warning): PURLs, URLs, URNs, exotic-but-legal schemes.
        assert!(has_iri_scheme("pkg:npm/my-app@1.0.0"));
        assert!(has_iri_scheme("pkg:golang/github.com/foo/bar@v1.2.3"));
        assert!(has_iri_scheme("https://example.com/products/app"));
        assert!(has_iri_scheme(
            "urn:uuid:0f9be22a-4a56-4b74-8c9d-6d70c67a4b32"
        ));
        assert!(has_iri_scheme("git+ssh://git@github.com/foo/bar"));
        // Rejected (warn): bare names, empty scheme, non-alpha scheme start,
        // spaces before the colon.
        assert!(!has_iri_scheme("my-app"));
        assert!(!has_iri_scheme("my app 1.0"));
        assert!(!has_iri_scheme(""));
        assert!(!has_iri_scheme(":no-scheme"));
        assert!(!has_iri_scheme("1pkg:starts-with-digit"));
        assert!(!has_iri_scheme("bad scheme:rest"));
    }

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
