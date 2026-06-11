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
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::telemetry::{track_vex_failed, track_vex_generated};
use socket_patch_core::vex::{
    build_document_with_vendored, detect_product, BuildOptions, Document, FailedPatch,
    VendorContext, VerifyOutcome,
};

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::ecosystem_dispatch::{find_packages_for_rollback, partition_purls};
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent};

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
}

/// Successful result of [`generate_vex`].
pub(crate) struct VexWriteSummary {
    pub statements: usize,
    pub failed: Vec<FailedPatch>,
    pub wrote_to_file: bool,
    /// The built document — returned so the standalone `vex` command can
    /// emit its per-subcomponent envelope without rebuilding.
    pub doc: Document,
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
        emit_envelope_error_and_track(
            &args,
            "json_requires_output",
            "--json requires --output (the VEX document is itself JSON; \
             route it to a file so the envelope can use stdout)",
        )
        .await;
        return 2;
    }

    let manifest_path = args.common.resolved_manifest_path();

    // `None` ⇒ no manifest file. That is no longer terminal by itself:
    // a `scan --vendor --detached` project carries its patch records in
    // the vendor ledger instead, and those must still be attestable.
    let manifest_file = match read_manifest(&manifest_path).await {
        Ok(m) => m,
        Err(e) => {
            emit_envelope_error_and_track(&args, "manifest_unreadable", &e.to_string()).await;
            return 2;
        }
    };
    let had_manifest_file = manifest_file.is_some();
    let manifest = augment_with_detached(
        &args.common,
        manifest_file.unwrap_or_else(PatchManifest::new),
    )
    .await;

    if manifest.patches.is_empty() {
        if !had_manifest_file {
            // No manifest AND nothing detached — the original contract.
            emit_envelope_error_and_track(
                &args,
                "manifest_not_found",
                &format!("Manifest not found at {}", manifest_path.display()),
            )
            .await;
            return 2;
        }
        emit_envelope_error_and_track(
            &args,
            "no_patches",
            "Manifest is empty — nothing to attest. Run `socket-patch get` \
             or `socket-patch scan --sync` first.",
        )
        .await;
        return 1;
    }

    let params = VexBuildParams {
        output: args.output.clone(),
        product: args.product.clone(),
        no_verify: args.no_verify,
        doc_id: args.doc_id.clone(),
        compact: args.compact,
    };

    match generate_vex(&args.common, &params, &manifest).await {
        Ok(summary) => {
            if args.common.json {
                emit_envelope_success(&summary.doc, &summary.failed);
            } else if summary.wrote_to_file {
                if !args.common.silent {
                    let path = args.output.as_ref().unwrap().display();
                    println!(
                        "Wrote OpenVEX document with {} statement(s) to {path}",
                        summary.statements
                    );
                }
            } else if !args.common.silent {
                eprintln!("Emitted {} VEX statement(s)", summary.statements);
            }
            0
        }
        // `no_applicable_patches` is a soft "nothing to attest" (exit 1)
        // and lists the omitted patches; every other error is a hard
        // failure (exit 2). `generate_vex` already fired telemetry, so
        // these emit-only sinks must not re-track.
        Err(e) if e.code == "no_applicable_patches" => {
            emit_envelope_error_with_failures(&args, e.code, &e.message, &e.failed);
            1
        }
        Err(e) => {
            emit_envelope_error(&args, e.code, &e.message);
            2
        }
    }
}

/// Map a `setup.manual` entry to an `Ecosystem`. Accepts the canonical
/// `cli_name` plus the friendly aliases `setup --exclude`/`--ecosystems` accept
/// (`go`/`golang`, `python`/`pypi`, `ruby`/`gem`, `php`/`composer`). Names for
/// ecosystems not compiled into this build (or unrecognized) yield `None` and
/// are ignored.
fn ecosystem_from_manual_name(name: &str) -> Option<Ecosystem> {
    match name.to_ascii_lowercase().as_str() {
        "npm" | "yarn" | "pnpm" | "bun" => Some(Ecosystem::Npm),
        "pypi" | "python" => Some(Ecosystem::Pypi),
        "gem" | "ruby" => Some(Ecosystem::Gem),
        #[cfg(feature = "cargo")]
        "cargo" | "rust" => Some(Ecosystem::Cargo),
        #[cfg(feature = "golang")]
        "golang" | "go" => Some(Ecosystem::Golang),
        #[cfg(feature = "composer")]
        "composer" | "php" => Some(Ecosystem::Composer),
        // The apply-only ecosystems are the primary use of `manual` (hand-applied
        // patches with no auto-install hook); they must map too, feature-gated to
        // match the compiled-in `Ecosystem` variants `from_purl` can return.
        #[cfg(feature = "maven")]
        "maven" | "java" => Some(Ecosystem::Maven),
        #[cfg(feature = "nuget")]
        "nuget" | "dotnet" => Some(Ecosystem::Nuget),
        #[cfg(feature = "deno")]
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
pub(crate) async fn generate_vex(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest: &PatchManifest,
) -> Result<VexWriteSummary, VexGenError> {
    // Resolve product.
    let product_id = match resolve_product_id(common, params.product.as_deref()).await {
        Ok(id) => id,
        Err(reason) => return Err(fail(common, "product_undetected", reason).await),
    };

    // Partition manifest into applied / failed.
    let mut outcome = if params.no_verify {
        VerifyOutcome {
            applied: manifest.patches.keys().cloned().collect(),
            ..Default::default()
        }
    } else {
        // stdout belongs to machine output here: the envelope in `--json`
        // mode, or the VEX document itself when `output` is None. Silence
        // the dispatch's human chrome ("Using <X> at: ...") in both,
        // mirroring apply/rollback's `silent || json` gating.
        let quiet = common.silent || common.json || params.output.is_none();
        let package_paths = resolve_package_paths(common, manifest, quiet).await;
        let vendor = load_vendor_context(common, manifest).await;
        socket_patch_core::vex::applied_patches_with_vendor(
            manifest,
            &package_paths,
            vendor.as_ref(),
        )
        .await
    };

    // Property 7: attest a patch only for an ecosystem that is actually set up —
    // or explicitly declared `manual` in the manifest. Patches for an ecosystem
    // that is neither are dropped regardless of verification mode (so even
    // `--no-verify` won't attest an un-set-up ecosystem's patches).
    // Exemption: VENDORED patches bypass the filter — the committed
    // `.socket/vendor/` artifact + lockfile wiring IS the persistence
    // mechanism, so no install hook exists (or is needed) by construction.
    let vendored_set: std::collections::HashSet<String> =
        outcome.vendored.iter().cloned().collect();
    let mut allowed = crate::commands::setup::configured_ecosystems(common).await;
    if let Some(s) = &manifest.setup {
        for name in &s.manual {
            if let Some(e) = ecosystem_from_manual_name(name) {
                allowed.insert(e);
            }
        }
    }
    let before = outcome.applied.len();
    outcome.applied.retain(|purl| {
        vendored_set.contains(purl)
            || Ecosystem::from_purl(purl)
                .map(|e| allowed.contains(&e))
                .unwrap_or(false)
    });
    if outcome.applied.len() != before && !common.silent && !common.json {
        eprintln!(
            "Note: omitting patches for ecosystems that are not set up (and not declared `manual` \
             in .socket/manifest.json's `setup.manual`) from VEX."
        );
    }

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
        doc_id: params
            .doc_id
            .clone()
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
        author: "Socket".to_string(),
        tooling: Some(format!("socket-patch {}", env!("CARGO_PKG_VERSION"))),
    };

    let doc =
        match build_document_with_vendored(manifest, &outcome.applied, &outcome.vendored, &opts) {
            Some(doc) => doc,
            None => {
                track_vex_failed(
                    "no_applicable_patches",
                    common.api_token.as_deref(),
                    common.org.as_deref(),
                )
                .await;
                return Err(VexGenError {
                    code: "no_applicable_patches",
                    message: "No applied patches with vulnerability metadata to attest."
                        .to_string(),
                    failed: outcome.failed,
                });
            }
        };

    // Serialize.
    let serialized = if params.compact {
        match serde_json::to_string(&doc) {
            Ok(s) => s,
            Err(e) => return Err(fail(common, "serialize_failed", e.to_string()).await),
        }
    } else {
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => s,
            Err(e) => return Err(fail(common, "serialize_failed", e.to_string()).await),
        }
    };

    // Write.
    let wrote_to_file = match &params.output {
        Some(path) => {
            if let Err(e) = tokio::fs::write(path, &serialized).await {
                return Err(fail(common, "write_failed", e.to_string()).await);
            }
            true
        }
        None => {
            println!("{serialized}");
            false
        }
    };

    track_vex_generated(
        doc.statements.len(),
        "openvex-0.2.0",
        if wrote_to_file { "file" } else { "stdout" },
        common.api_token.as_deref(),
        common.org.as_deref(),
    )
    .await;

    Ok(VexWriteSummary {
        statements: doc.statements.len(),
        failed: outcome.failed,
        wrote_to_file,
        doc,
    })
}

/// Read the manifest at `manifest_path`, then [`generate_vex`]. Manifest
/// read failures are wrapped as [`VexGenError`] so embedded callers
/// (`apply`/`scan`) get a single error channel. Used by the embedded
/// `--vex` paths, which always write to a file.
pub(crate) async fn generate_vex_from_manifest_path(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest_path: &Path,
) -> Result<VexWriteSummary, VexGenError> {
    let manifest_file = match read_manifest(manifest_path).await {
        Ok(m) => m,
        Err(e) => return Err(fail(common, "manifest_unreadable", e.to_string()).await),
    };
    let had_manifest_file = manifest_file.is_some();
    // Detached vendored patches (`scan --vendor --detached`) have no
    // manifest record; the ledger's embedded copies must still attest.
    let manifest =
        augment_with_detached(common, manifest_file.unwrap_or_else(PatchManifest::new)).await;
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
    generate_vex(common, params, &manifest).await
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
    if let Ok(state) = socket_patch_core::patch::vendor::load_state(&common.cwd).await {
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

/// Fire `vex_failed` telemetry and build the matching [`VexGenError`].
/// Centralizes the "track then return error" pattern in [`generate_vex`].
async fn fail(common: &GlobalArgs, code: &'static str, message: String) -> VexGenError {
    track_vex_failed(code, common.api_token.as_deref(), common.org.as_deref()).await;
    VexGenError {
        code,
        message,
        failed: Vec::new(),
    }
}

/// Pick the product PURL from an explicit override or by filesystem
/// auto-detect.
async fn resolve_product_id(common: &GlobalArgs, product: Option<&str>) -> Result<String, String> {
    if let Some(p) = product {
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
/// legacy `.socket/go-patches/` redirect backend.
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
async fn load_vendor_context(
    common: &GlobalArgs,
    manifest: &PatchManifest,
) -> Option<VendorContext> {
    let entries = match socket_patch_core::patch::vendor::load_state(&common.cwd).await {
        Ok(state) => state.entries,
        Err(e) => {
            if !common.silent {
                eprintln!(
                    "Warning: unreadable vendor state ({e}); vendored patches will be \
                     omitted from VEX"
                );
            }
            HashMap::new()
        }
    };

    let go_patches = {
        #[cfg(feature = "golang")]
        {
            synthesize_go_patches(common, manifest, &entries).await
        }
        #[cfg(not(feature = "golang"))]
        {
            let _ = manifest;
            HashMap::new()
        }
    };

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
#[cfg(feature = "golang")]
async fn synthesize_go_patches(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    entries: &HashMap<String, socket_patch_core::patch::vendor::VendorEntry>,
) -> HashMap<String, PathBuf> {
    use socket_patch_core::patch::go_mod_edit::{
        read_replace_entries, ReplaceOwner, GO_PATCHES_DIR,
    };
    use socket_patch_core::utils::purl::build_golang_purl;

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
        if entries.contains_key(&purl) || entries.values().any(|e| e.base_purl == purl) {
            continue;
        }
        // SECURITY: module/version come from a committed (tamper-able)
        // go.mod and are about to key a path we hash. Validate with the
        // same per-segment rules `go_redirect::are_safe_redirect_coords`
        // applies (it is crate-private to core) before building the
        // copy-dir path.
        if !are_safe_go_redirect_coords(&entry.module, version) {
            continue;
        }
        go_patches.insert(
            purl,
            common
                .cwd
                .join(GO_PATCHES_DIR)
                .join(format!("{}@{version}", entry.module)),
        );
    }
    go_patches
}

/// Local mirror of core's `go_redirect::are_safe_redirect_coords` (which is
/// `pub(crate)` there): a module path is `/`-separated segments, each
/// non-empty and not `.`/`..`, no leading `/`, no backslash/NUL; a version
/// is a single such segment. Fail-closed before any disk access.
#[cfg(feature = "golang")]
fn are_safe_go_redirect_coords(module: &str, version: &str) -> bool {
    fn safe_segment(seg: &str) -> bool {
        !seg.is_empty() && seg != "." && seg != ".."
    }
    let module_ok = !module.is_empty()
        && !module.starts_with('/')
        && !module.contains('\\')
        && !module.contains('\0')
        && module.split('/').all(safe_segment);
    let version_ok = safe_segment(version)
        && !version.contains('/')
        && !version.contains('\\')
        && !version.contains('\0');
    module_ok && version_ok
}

/// Walk the ecosystem dispatch to build the PURL -> on-disk-path map
/// used by `vex::verify::applied_patches`.
async fn resolve_package_paths(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    quiet: bool,
) -> HashMap<String, PathBuf> {
    let purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned = partition_purls(&purls, common.ecosystems.as_deref());
    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
        batch_size: 0, // unused for find_packages_for_rollback
    };
    // Use the rollback (qualified-aware) resolver, NOT
    // `find_packages_for_purls`. Release-variant ecosystems
    // (PyPI / RubyGems / Maven) key the manifest by *qualified* PURLs
    // (`?artifact_id=`, `?platform=`, `?classifier=&ext=`), but the
    // crawler only knows the *base* PURL. `find_packages_for_purls`
    // would key the result map by the base PURL, so the qualified
    // lookups in `vex::applied_patches` would all miss and every
    // PyPI/Gem/Maven patch would be silently dropped from the VEX doc
    // as `package_not_found`. The rollback variant fans each base path
    // back out to every qualified manifest PURL — the same mapping the
    // manifest was written with (`get` uses the same resolver).
    find_packages_for_rollback(&partitioned, &crawler_options, quiet).await
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

/// Async error sink that mirrors `emit_envelope_error` and also fires
/// the `vex_failed` telemetry event. Centralizes both side effects so
/// each `return` site in `run` only needs one call.
async fn emit_envelope_error_and_track(args: &VexArgs, code: &str, message: &str) {
    track_vex_failed(
        code,
        args.common.api_token.as_deref(),
        args.common.org.as_deref(),
    )
    .await;
    emit_envelope_error(args, code, message);
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

fn emit_envelope_success(doc: &Document, failures: &[FailedPatch]) {
    let mut env = Envelope::new(Command::Vex);
    for st in &doc.statements {
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

    // Property 7: every ecosystem the build can classify a PURL for must also be
    // declarable `manual`. Apply-only maven/nuget/deno are the *primary* use of
    // `manual`; they were missing originally, silently dropping their patches.
    #[test]
    fn ecosystem_from_manual_name_maps_compiled_in_ecosystems() {
        assert_eq!(ecosystem_from_manual_name("npm"), Some(Ecosystem::Npm));
        assert_eq!(ecosystem_from_manual_name("PyPI"), Some(Ecosystem::Pypi)); // case-insensitive
        assert_eq!(ecosystem_from_manual_name("python"), Some(Ecosystem::Pypi));
        assert_eq!(ecosystem_from_manual_name("ruby"), Some(Ecosystem::Gem));
        assert_eq!(ecosystem_from_manual_name("nonsense"), None);
        #[cfg(feature = "cargo")]
        assert_eq!(ecosystem_from_manual_name("cargo"), Some(Ecosystem::Cargo));
        #[cfg(feature = "golang")]
        assert_eq!(ecosystem_from_manual_name("go"), Some(Ecosystem::Golang));
        #[cfg(feature = "composer")]
        assert_eq!(
            ecosystem_from_manual_name("composer"),
            Some(Ecosystem::Composer)
        );
        #[cfg(feature = "maven")]
        assert_eq!(ecosystem_from_manual_name("maven"), Some(Ecosystem::Maven));
        #[cfg(feature = "nuget")]
        assert_eq!(ecosystem_from_manual_name("nuget"), Some(Ecosystem::Nuget));
        #[cfg(feature = "deno")]
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

    /// The local mirror of core's `are_safe_redirect_coords` must enforce
    /// the same accept/reject set (cases lifted from core's pinned tests) —
    /// a divergence would let a tampered go.mod `replace` key an
    /// out-of-tree path into the go-patches verification map.
    #[cfg(feature = "golang")]
    #[test]
    fn go_redirect_coord_guard_matches_core_rules() {
        assert!(are_safe_go_redirect_coords("github.com/foo/bar", "v1.4.2"));
        assert!(are_safe_go_redirect_coords("gopkg.in/inf.v0", "v0.9.1"));
        assert!(are_safe_go_redirect_coords(
            "github.com/foo/bar/v2",
            "v2.0.0-20210101000000-abcdef123456"
        ));
        assert!(!are_safe_go_redirect_coords("../../../etc", "v1.0.0"));
        assert!(!are_safe_go_redirect_coords(
            "github.com/../../../etc",
            "v1.0.0"
        ));
        assert!(!are_safe_go_redirect_coords("/abs/path", "v1.0.0"));
        assert!(!are_safe_go_redirect_coords("github.com//bar", "v1.0.0"));
        assert!(!are_safe_go_redirect_coords("foo/./bar", "v1.0.0"));
        assert!(!are_safe_go_redirect_coords("foo\\bar", "v1.0.0"));
        assert!(!are_safe_go_redirect_coords("", "v1.0.0"));
        assert!(!are_safe_go_redirect_coords(
            "github.com/foo/bar",
            "../../../evil"
        ));
        assert!(!are_safe_go_redirect_coords("github.com/foo/bar", "v1/0/0"));
        assert!(!are_safe_go_redirect_coords("github.com/foo/bar", ".."));
        assert!(!are_safe_go_redirect_coords("github.com/foo/bar", ""));
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
