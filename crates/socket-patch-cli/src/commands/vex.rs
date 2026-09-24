//! `socket-patch vex` — generate an OpenVEX 0.2.0 document.
//!
//! Gathers every patch the project can prove — the local manifest, the
//! `.socket/vendor` ledgers, and (manifest-less VEX) the hosted / vendored
//! patch references its lockfiles wire (see [`crate::commands::vex_sources`]
//! for the merge, record-resolution and wiring-liveness rules) — optionally
//! verifies each patch's on-disk state, and emits a VEX document describing
//! the vulnerabilities that have been mitigated. Designed to be piped into
//! vexctl, Grype, Trivy, and the like.
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
use socket_patch_core::vendor::state::VendorState;
use socket_patch_core::vex::{
    build_document, detect_product, BuildOptions, Document, FailedPatch, VendorContext,
    VerifyOutcome,
};

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::vex_sources::{
    self, Plan, Sources, RECORD_MISMATCH, RECORD_UNAVAILABLE, REDIRECT_UNWIRED, VENDOR_UNWIRED,
    WIRING_CONFLICT,
};
use crate::ecosystem_dispatch::{collapse_to_first, find_manifest_package_copies};
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent, RunWarning};
use crate::ui::plural;

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

    /// Write the VEX document to this path instead of stdout (`-` means
    /// stdout). A relative path resolves against the current directory, not
    /// `--cwd`.
    #[arg(long = "output", short = 'O', env = "SOCKET_VEX_OUTPUT")]
    pub output: Option<PathBuf>,

    /// Override the auto-detected top-level product PURL/identifier
    ///
    /// Auto-detection tries, in order:
    ///   1. the git `origin` remote: pkg:github/<owner>/<repo> for github.com
    ///      (likewise gitlab.com and bitbucket.org), the raw URL otherwise
    ///   2. package.json:   pkg:npm/<name>@<version>
    ///   3. pyproject.toml: pkg:pypi/<name>@<version>
    ///   4. Cargo.toml:     pkg:cargo/<name>@<version>
    ///   5. go.mod:         pkg:golang/<module>
    ///   6. composer.json:  pkg:composer/<vendor>/<name>[@<version>]
    ///   7. pom.xml:        pkg:maven/<groupId>/<artifactId>[@<version>]
    ///   8. *.csproj:       pkg:nuget/<id>[@<version>] (a single one at the root)
    ///   9. *.gemspec:      pkg:gem/<name>[@<version>] (a single one at the root)
    // `verbatim_doc_comment`: clap otherwise joins the numbered list into
    // one run-on line.
    #[arg(long = "product", env = "SOCKET_VEX_PRODUCT", verbatim_doc_comment)]
    pub product: Option<String>,

    /// Skip the on-disk file-hash check and trust the patch records.
    /// By default every patch is verified before being emitted; this flag
    /// flips that off — useful when generating a VEX doc on a build machine
    /// that doesn't have the patched files laid out yet. The wiring checks
    /// still apply: a hosted or vendored ledger record the lockfile no
    /// longer wires, or a lockfile reference whose record is unavailable or
    /// names another package, is omitted either way.
    //
    // `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    // clap's default bool parser accepts only the literal strings
    // `true`/`false` from the env binding, so `SOCKET_VEX_NO_VERIFY=1` (or
    // an exported-but-empty `SOCKET_VEX_NO_VERIFY=`) aborted the parse.
    // This var is also outside `GLOBAL_ARG_ENV_VARS`, so `main`'s empty-var
    // scrub never rescues it.
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
    /// trust the patch records (the lockfile wiring checks still apply). See
    /// `socket-patch vex --no-verify`.
    //
    // `value_parser = parse_bool_flag`: these embedded flags share their
    // env vars with the standalone `vex` flags, so without it an ambient
    // `SOCKET_VEX_NO_VERIFY=1` (or `=`) aborted every host command parse —
    // including `apply` running from a postinstall hook.
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
            known_stale: Vec::new(),
            // Embedded callers skip VEX entirely under `--dry-run`.
            dry_run: false,
            product_flag: "--vex-product",
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
    /// Hosted probes positively identified unpatched installed bytes. These
    /// PURLs cannot be attested by another interpreter or --no-verify.
    pub known_stale: Vec<String>,
    /// `vex --dry-run`: build and verify, but write nothing to `output` and
    /// leave any previous document there alone. Printing to stdout is not a
    /// mutation, so it still happens.
    pub dry_run: bool,
    /// The flag that carried `product`, named in the non-IRI advisory
    /// (`--product` standalone, `--vex-product` embedded).
    pub product_flag: &'static str,
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
    /// Whether the document was written to `output` (false under
    /// `--dry-run`, and when it went to stdout).
    pub wrote_file: bool,
}

/// Failure from [`generate_vex`], carrying a stable code + message the
/// caller surfaces in its own output channel.
pub(crate) struct VexGenError {
    pub code: &'static str,
    pub message: String,
    /// Patches omitted by verification, populated only for the
    /// `no_applicable_patches` case (so callers can list them).
    pub failed: Vec<FailedPatch>,
    /// Advisories raised before the failure (already printed in human
    /// mode) — for `no_applicable_patches` often the only explanation of a
    /// `vendor_unwired` / `redirect_unwired` omission (the lockfile-discovery
    /// diagnostics say why a lockfile's mention is not live wiring). The
    /// `--json` error envelopes carry them.
    pub warnings: Vec<RunWarning>,
}

impl VexGenError {
    /// What an EMBEDDED `--vex` failure folds into its host command's
    /// `warnings[]` (`apply`, `vendor`, `scan`): the run's advisories, then
    /// one `vex_omitted` per omitted patch (`<purl>: <why> (<errorCode>)`).
    /// The standalone `vex` envelope lists those omissions as `skipped`
    /// events; a host envelope's events are its own command's, so the
    /// omissions ride `warnings[]` there — otherwise `--json` would say only
    /// `no_applicable_patches`, never which patch the gates refused or why.
    pub(crate) fn embedded_warnings(&self) -> Vec<RunWarning> {
        let mut out = self.warnings.clone();
        out.extend(self.failed.iter().map(|f| RunWarning {
            code: "vex_omitted".to_string(),
            detail: format!(
                "{}: {} ({})",
                f.purl,
                omission_reason_message(&f.reason),
                f.reason
            ),
        }));
        out
    }

    /// Human stderr for an embedded `--vex` failure: the error line — even
    /// under `--silent` ("errors only", never "nothing": exit 1 with no
    /// message would be undiagnosable) — and, under `--silent`, each omitted
    /// patch, as standalone `vex --silent` lists them (a louder run already
    /// printed a `Warning: omitting …` line per omission).
    pub(crate) fn print_embedded(&self, common: &GlobalArgs) {
        eprintln!("Error: VEX generation failed: {}", self.message);
        if common.silent {
            for f in &self.failed {
                eprintln!("  omitted: {} ({})", f.purl, f.reason);
            }
        }
    }
}

pub async fn run(args: VexArgs) -> i32 {
    apply_env_toggles(&args.common);

    // `-O -` is the conventional spelling of stdout, not a file named `-`.
    let output = args.output.clone().filter(|p| p.as_os_str() != "-");

    // --json without --output would race the envelope and the VEX doc
    // on the same stdout stream. Bail out with a clear error before
    // doing any work.
    if args.common.json && output.is_none() {
        // A usage error, not a generation failure: no telemetry POST and no
        // config read (argument errors never report), just the envelope.
        emit_envelope_error(
            &args,
            "json_requires_output",
            "--json requires --output (the VEX document is itself JSON; \
             route it to a file so the envelope can use stdout)",
            &[],
            &[],
        );
        return 2;
    }

    // `-o` is `--org`, `-O` is `--output`: a file-shaped org slug is almost
    // certainly a mistyped `-O` (the document then silently went to stdout).
    let mut run_warnings: Vec<RunWarning> = Vec::new();
    if let Some(detail) = org_looks_like_path(args.common.org.as_deref()) {
        note_warning(
            &mut run_warnings,
            &args.common,
            "org_looks_like_path",
            detail,
        );
    }

    let params = VexBuildParams {
        output: output.clone(),
        product: args.product.clone(),
        no_verify: args.no_verify,
        doc_id: args.doc_id.clone(),
        compact: args.compact,
        assume_applied: Vec::new(),
        known_stale: Vec::new(),
        dry_run: args.common.dry_run,
        product_flag: "--product",
    };

    let manifest_path = args.common.resolved_manifest_path();
    match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
        Ok(mut summary) => {
            run_warnings.append(&mut summary.warnings);
            summary.warnings = run_warnings;
            if args.common.json {
                emit_envelope_success(&summary, params.dry_run);
            } else if !args.common.silent {
                match &output {
                    Some(path) if summary.wrote_file => {
                        println!("{}", format_vex_written(summary.statements, path));
                    }
                    Some(path) => {
                        println!("{}", format_vex_dry_run(summary.statements, path));
                    }
                    None => eprintln!("{}", format_vex_emitted(summary.statements)),
                }
            }
            0
        }
        // `no_applicable_patches` and `no_patches` are soft "nothing to
        // attest" cases (exit 1); every other error is a hard failure
        // (exit 2). `generate_vex_from_manifest_path` already fired
        // telemetry, so these emit-only sinks must not re-track.
        Err(mut e) => {
            run_warnings.append(&mut e.warnings);
            let (message, exit) = match e.code {
                "no_applicable_patches" => (e.message, 1),
                // Standalone-only remediation hints: after an embedded
                // `apply --vex` / `scan --vex` run the advice would be
                // circular, so the shared path keeps the bare message and
                // it is appended here.
                "no_patches" => (
                    "Manifest is empty, and no hosted or vendored patch references were found \
                     in the lockfiles or .socket/vendor ledgers — nothing to attest. Run \
                     `socket-patch get` or `socket-patch scan` (agent, hosted or vendored mode) \
                     first."
                        .to_string(),
                    1,
                ),
                "manifest_not_found" => (
                    format_manifest_not_found_hint(&e.message, &args.common.manifest_path),
                    2,
                ),
                _ => (e.message, 2),
            };
            emit_envelope_error(&args, e.code, &message, &e.failed, &run_warnings);
            exit
        }
    }
}

/// `Manifest not found at <path>. Run ... first[, or pass --manifest-path].`
/// The `--manifest-path` hint only makes sense while the default path is in
/// use; a user who already pointed elsewhere gets just the next step.
fn format_manifest_not_found_hint(message: &str, manifest_path: &str) -> String {
    let base = message.trim_end().trim_end_matches('.');
    if manifest_path == socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH {
        format!(
            "{base}. Run `socket-patch scan` or `socket-patch get` first, or pass \
             --manifest-path."
        )
    } else {
        format!("{base}. Run `socket-patch scan` or `socket-patch get` first.")
    }
}

/// `Wrote OpenVEX document with 1 statement to out.json` — the one-line
/// summary after writing a document to a file.
pub(crate) fn format_vex_written(statements: usize, path: &Path) -> String {
    format!(
        "Wrote OpenVEX document with {} to {}",
        plural(statements, "statement", "statements"),
        path.display()
    )
}

/// The note an embedded `--vex` prints under `--dry-run`, where no
/// document is built: `done` is what the dry run did not do ("applied",
/// "redirected", "vendored").
pub(crate) fn format_vex_dry_run_skip(done: &str) -> String {
    format!("Skipping VEX generation (--dry-run: nothing was {done}).")
}

/// The note an embedded `--vex` on a manifest-less command prints when
/// nothing anywhere references a patch
/// ([`ManifestlessVex::NothingToAttest`]): the requested document was not
/// written (the command still exits 0).
pub(crate) fn format_vex_nothing_to_attest() -> String {
    "No VEX document written: no manifest, .socket/vendor ledger record or lockfile \
     references a patch."
        .to_string()
}

/// The `--dry-run` twin of [`format_vex_written`]: nothing was written.
pub(crate) fn format_vex_dry_run(statements: usize, path: &Path) -> String {
    format!(
        "[dry-run] Would write OpenVEX document with {} to {}",
        plural(statements, "statement", "statements"),
        path.display()
    )
}

/// The stderr summary after the document went to stdout.
pub(crate) fn format_vex_emitted(statements: usize) -> String {
    format!(
        "Emitted {}",
        plural(statements, "VEX statement", "VEX statements")
    )
}

/// A warning when the `--org` slug looks like a file path, i.e. a `-o`
/// typed for `-O`/`--output`. Slugs never contain slashes or end in
/// `.json`.
fn org_looks_like_path(org: Option<&str>) -> Option<String> {
    let org = org?.trim();
    let pathy =
        org.contains('/') || org.contains('\\') || org.to_ascii_lowercase().ends_with(".json");
    pathy.then(|| {
        format!("--org {org:?} looks like a file path; did you mean -O/--output? (-o is --org)")
    })
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
/// plan's record view against disk (unless `no_verify`), build the OpenVEX
/// document, serialize, write (or print to stdout when `output` is `None`),
/// and fire telemetry. Returns a [`VexWriteSummary`] on success or a
/// structured [`VexGenError`] (with a stable code) on failure. All
/// `track_vex_*` telemetry is fired here so every caller reports
/// consistently. Run advisories join `warnings` (the caller already added
/// the lockfile-discovery diagnostics).
async fn generate_vex(
    common: &GlobalArgs,
    params: &VexBuildParams,
    plan: Plan,
    warnings: &mut Vec<RunWarning>,
) -> Result<VexWriteSummary, VexGenError> {
    let manifest = &plan.view;
    let redirected: &[String] = &plan.redirected;
    // Resolve product.
    let product_id = match resolve_product_id(common, params.product.as_deref(), warnings).await {
        Ok(id) => id,
        Err(reason) => return Err(fail(common, "product_undetected", reason).await),
    };

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
                warnings,
                common,
                "product_not_iri",
                format!(
                    "Product override {p:?} ({}) is neither a PURL \
                     (pkg:...) nor an absolute IRI; it is emitted verbatim as the OpenVEX \
                     product @id, which the spec requires to be an IRI — strict consumers may \
                     reject the document. Prefer pkg:<type>/<name>@<version>.",
                    params.product_flag
                ),
            );
        }
    }

    // The plan's advisories (fetch failures, wiring conflicts, superseded
    // or dead records) are run warnings like any other: human mode prints
    // them, and the `--json` envelopes — standalone and embedded, success
    // and failure — carry them in `warnings[]`, the only place their detail
    // survives (a skip carries just its code). Some are gathered in
    // patch-fetch completion order: sorted.
    let mut notes: Vec<&crate::commands::vex_sources::PlanNote> = plan.notes.iter().collect();
    notes.sort();
    notes.dedup();
    for note in notes {
        note_warning(warnings, common, note.code, note.detail.clone());
    }

    // Partition the record view into applied / failed. The plan already
    // applied every gate hashing cannot stand in for (wiring liveness, the
    // wired-uuid rule, record match), so `--no-verify` skips ONLY the
    // hashing below — a stale ledger no lockfile wires stays omitted.
    let mut outcome = if params.no_verify {
        // Trust-the-records mode still needs the vendored classification:
        // the property-7 exemption and the "(vendored)" phrasing key off
        // `outcome.vendored`, and both are about how the patch persists (a
        // LIVE vendor wiring, per the plan), not whether this run hashed it.
        let mut vendored: Vec<String> = plan
            .vendor_entries
            .keys()
            .filter(|purl| manifest.patches.contains_key(*purl))
            .cloned()
            .collect();
        vendored.sort();
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
        // ONE installed-tree lookup: the first copy of every purl for the
        // record check, every copy of the hosted ones below.
        let copies = find_manifest_package_copies(&purls, common, quiet).await;
        let package_paths = collapse_to_first(copies.clone());
        let go_patches = synthesize_go_patches(common, manifest, &plan.vendor_entries).await;
        // Hosted-basis purls are judged by the copies their build CONSUMES
        // (the Go replacement module, the Socket registry's cargo src dir,
        // maven's suffixed version; every copy where hosted and registry
        // bytes share a location) — never by a pristine sibling the
        // crawler's first match may be. See `vex_consumed`.
        let hosted =
            crate::commands::vex_consumed::hosted_consumed_copies(common, &plan.hosted, &copies)
                .await;
        let vendor = VendorContext {
            project_root: common.cwd.clone(),
            entries: plan.vendor_entries.clone(),
            go_patches,
            hosted,
        };
        let mut outcome = socket_patch_core::vex::applied_patches_with_vendor(
            manifest,
            &package_paths,
            Some(&vendor),
        )
        .await;
        // Hosted lockfile basis: a DISCOVERED Socket-host reference whose
        // lock pins the artifact attests from that wiring when no installed
        // tree exists yet (a lockfile-only CI checkout) — the evidence the
        // in-run `scan --mode hosted --vex` uses. An installed tree that
        // does not verify still wins (hash_mismatch / not_applied stay
        // failures): only the absence of any installed copy is excused.
        //
        // "Absent" must mean the crawler LOOKED: `--ecosystems` /
        // `SOCKET_ECOSYSTEMS` keeps out-of-scope purls from being crawled at
        // all, and they come back `package_not_found` too. Excusing those
        // would attest a lockfile-basis patch over an installed tree that
        // was never inspected (and may be unpatched), so they stay omitted
        // like every other out-of-scope purl.
        let crawled = |purl: &str| {
            !crate::ecosystem_dispatch::partition_purls(
                std::slice::from_ref(&purl.to_string()),
                common.ecosystems.as_deref(),
            )
            .is_empty()
        };
        let mut lockfile_attested = Vec::new();
        outcome.failed.retain(|f| {
            let excused = f.reason == "package_not_found"
                && plan.lockfile_basis.contains(&f.purl)
                && crawled(&f.purl);
            if excused {
                lockfile_attested.push(f.purl.clone());
            }
            !excused
        });
        outcome.applied.extend(lockfile_attested);
        outcome
    };

    // In-run `scan --redirect --vex`: the bytes of deps THAT RUN confirmed
    // redirected live on the patch server until the next install, so their
    // verification against the local tree would spuriously fail
    // (package_not_found / not_applied). Exempt exactly those PURLs —
    // everything else above verified normally, including any stale ledger
    // record the run did not re-confirm (a reverted lockfile or a withdrawn
    // patch must not keep attesting).
    if !params.assume_applied.is_empty() {
        use socket_patch_core::utils::purl::strip_purl_qualifiers;
        // The confirmed purls come from the grant reference (unqualified —
        // `pkg:pypi/urllib3@1.26.18`) while the ledger records the API's
        // artifact-qualified purl (`…?artifact_id=py2-py3-none-any-whl`), so
        // match on the qualifier-stripped form: a lock-only pypi redirect used
        // to attest nothing and fail the same-run `--vex` with
        // `no_applicable_patches`.
        let exempt: std::collections::HashSet<&str> = params
            .assume_applied
            .iter()
            .map(|s| strip_purl_qualifiers(s))
            .collect();
        let is_exempt = |purl: &str| exempt.contains(strip_purl_qualifiers(purl));
        outcome.failed.retain(|f| !is_exempt(&f.purl));
        for key in manifest.patches.keys() {
            if is_exempt(key) && !outcome.applied.iter().any(|p| p == key) {
                outcome.applied.push(key.clone());
            }
        }
    }

    // Positive evidence from a hosted probe takes precedence over an
    // assumed redirect or a healthy copy found in a different interpreter.
    if !params.known_stale.is_empty() {
        use socket_patch_core::utils::purl::strip_purl_qualifiers;
        let stale: std::collections::HashSet<&str> = params
            .known_stale
            .iter()
            .map(|purl| strip_purl_qualifiers(purl))
            .collect();
        let is_stale = |purl: &str| stale.contains(strip_purl_qualifiers(purl));
        outcome.applied.retain(|purl| !is_stale(purl));
        outcome.failed.retain(|failure| !is_stale(&failure.purl));
        outcome.failed.extend(
            manifest
                .patches
                .keys()
                .filter(|purl| is_stale(purl))
                .map(|purl| FailedPatch {
                    purl: purl.clone(),
                    reason: "stale_install".to_string(),
                }),
        );
    }

    // The plan's gate omissions (record_unavailable / record_mismatch /
    // vendor_unwired / redirect_unwired / wiring_conflict) join the omission
    // channel so they surface as per-purl `skipped` events like any
    // verification failure.
    outcome.failed.extend(plan.gated.iter().cloned());

    // Vendored disclosure: the committed artifact verified (the attestation
    // stands — the committables are what the lockfile consumes) but the LIVE
    // installed tree is present and running different bytes. Say so — a
    // build that bypasses the vendor wiring is unpatched until the next
    // package-manager install.
    for purl in &outcome.vendored_out_of_sync {
        note_warning(
            warnings,
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
    let any_setup_filtered = !setup_filtered.is_empty();
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
    // `failed` is built by iterating the record view's HashMap: without a
    // sort the omission order (stderr, the error list and the JSON
    // `skipped` events) changes run to run.
    outcome
        .failed
        .sort_by(|a, b| (&a.purl, &a.reason).cmp(&(&b.purl, &b.reason)));

    // When nothing attests and EVERY omission was the property-7 filter,
    // the run fails with a message that explains the setup cause itself
    // (see below), so the generic note would only repeat it.
    let all_setup_drops = outcome.applied.is_empty()
        && !outcome.failed.is_empty()
        && outcome
            .failed
            .iter()
            .all(|f| f.reason == ECOSYSTEM_NOT_SETUP);
    if !common.silent && !common.json {
        if any_setup_filtered && !all_setup_drops {
            eprintln!(
                "Note: patches for ecosystems that are not set up (and not declared `manual` \
                 in .socket/manifest.json's `setup.manual`) are omitted from VEX."
            );
        }
        for f in &outcome.failed {
            eprintln!("{}", format_omission_warning(&f.purl, &f.reason));
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
            let (token, org) = common.telemetry_credentials();
            track_vex_failed("no_applicable_patches", token.as_deref(), org.as_deref()).await;
            // When nothing attested and EVERY omission was the property-7
            // filter, say so: those patches ARE applied with vulnerability
            // metadata, and the generic message below would read as "not
            // patched" to a human. The code stays `no_applicable_patches` —
            // it is the documented exit-1 routing tag consumers already
            // branch on; the per-event `ecosystem_not_setup` errorCode is
            // the machine-readable discriminator.
            let message = if all_setup_drops {
                format_setup_drops_message(outcome.failed.len())
            } else {
                "No applied patches with vulnerability metadata to attest.".to_string()
            };
            return Err(VexGenError {
                code: "no_applicable_patches",
                message,
                failed: outcome.failed,
                warnings: Vec::new(),
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

    // Write. The file gets the same trailing newline `println!` gives the
    // stdout form, so `cat out.json` does not glue the prompt to the `}`.
    let wrote_to_file = match &params.output {
        Some(_) if params.dry_run => false,
        Some(path) => {
            if let Err(e) = tokio::fs::write(path, format!("{serialized}\n")).await {
                // The raw io::Error ("No such file or directory (os error
                // 2)") names neither the file nor the operation — useless
                // in a CI log. Say what was being written and where.
                return Err(fail(
                    common,
                    "write_failed",
                    format!("Failed to write VEX document to {}: {e}", path.display()),
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

    let (token, org) = common.telemetry_credentials();
    track_vex_generated(
        doc.statements.len(),
        "openvex-0.2.0",
        if params.output.is_some() {
            "file"
        } else {
            "stdout"
        },
        token.as_deref(),
        org.as_deref(),
    )
    .await;

    Ok(VexWriteSummary {
        statements: doc.statements.len(),
        failed: outcome.failed,
        doc,
        warnings: Vec::new(),
        wrote_file: wrote_to_file,
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
    generate_vex_with_cleanup(common, params, manifest_path, false).await
}

/// Outcome of [`generate_vex_without_manifest`].
pub(crate) enum ManifestlessVex {
    /// Nothing references a patch anywhere (no manifest, no ledger record,
    /// no lockfile reference): the caller keeps its historical calm
    /// no-manifest exit 0. Carries the run's advisories (the lockfile-
    /// discovery diagnostics — an unparseable lock may be WHY nothing was
    /// found — and a removed stale document) for the `--json` envelope's
    /// `warnings[]`; human mode already printed them.
    NothingToAttest(Vec<RunWarning>),
    /// The document was written.
    Written(VexWriteSummary),
    /// Generation failed: the caller fails the command.
    Failed(VexGenError),
}

/// Embedded `--vex` for a command that found NO manifest (`apply`,
/// `vendor`): hosted and vendored patches are wired by the lockfiles and
/// the `.socket/vendor` ledgers, not the manifest, so a manifest-less
/// checkout can still have patches to attest and a requested document must
/// be written (or the command must fail). "Nothing to attest anywhere" is
/// [`ManifestlessVex::NothingToAttest`], not a failure: an ambient
/// `SOCKET_VEX` on a project that never used socket-patch must not start
/// failing installs, so it sends no failure telemetry. A stale document at
/// the output path is removed in that case too (same contract as
/// [`generate_vex_from_manifest_path`]: this run attested nothing, so
/// yesterday's `not_affected` must not survive at the path).
pub(crate) async fn generate_vex_without_manifest(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest_path: &Path,
) -> ManifestlessVex {
    match generate_vex_with_cleanup(common, params, manifest_path, true).await {
        Ok(summary) => ManifestlessVex::Written(summary),
        Err(e) if e.code == "manifest_not_found" => ManifestlessVex::NothingToAttest(e.warnings),
        Err(e) => ManifestlessVex::Failed(e),
    }
}

/// [`generate_vex_from_manifest_path`]'s failure-cleanup wrapper, shared
/// with [`generate_vex_without_manifest`] (`calm_when_nothing`: see
/// [`generate_vex_from_manifest_path_inner`]). The run's advisories land on
/// the summary or the error either way.
async fn generate_vex_with_cleanup(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest_path: &Path,
    calm_when_nothing: bool,
) -> Result<VexWriteSummary, VexGenError> {
    let mut warnings = Vec::new();
    let result = generate_vex_from_manifest_path_inner(
        common,
        params,
        manifest_path,
        calm_when_nothing,
        &mut warnings,
    )
    .await;
    match result {
        Ok(mut summary) => {
            summary.warnings = warnings;
            Ok(summary)
        }
        Err(mut e) => {
            // A dry run mutates nothing, a stale document included.
            if !params.dry_run {
                if let Some(path) = params.output.as_deref() {
                    if remove_stale_vex_doc(path).await {
                        note_warning(
                            &mut warnings,
                            common,
                            "vex_stale_doc_removed",
                            format!(
                                "Removed the previous VEX document at {} (this run could not \
                                 attest it).",
                                path.display()
                            ),
                        );
                    }
                }
            }
            e.warnings = warnings;
            Err(e)
        }
    }
}

/// Delete a PRIOR run's OpenVEX document at `output` after a failed run.
/// Only a file that is recognizably OpenVEX (JSON whose `@context` names
/// openvex.dev) is removed — the guard keeps a mistyped `--output` pointing
/// at an unrelated file from being destroyed by an unrelated failure.
/// Removal errors are swallowed: the non-zero exit is the contract, the
/// deletion is hygiene. Returns whether a document was actually removed.
async fn remove_stale_vex_doc(path: &Path) -> bool {
    let Ok(bytes) = tokio::fs::read(path).await else {
        return false;
    };
    let is_openvex = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("@context")
                .and_then(|c| c.as_str())
                .map(|c| c.contains("openvex.dev"))
        })
        .unwrap_or(false);
    is_openvex && tokio::fs::remove_file(path).await.is_ok()
}

/// [`generate_vex_from_manifest_path`] without the failure-cleanup wrapper.
///
/// Loads every attestation source — the manifest (a missing file is fine),
/// both `.socket/vendor` ledgers, and the project's lockfile references —
/// merges them into a [`Plan`] ([`vex_sources::plan`]), and hands that to
/// [`generate_vex`].
async fn generate_vex_from_manifest_path_inner(
    common: &GlobalArgs,
    params: &VexBuildParams,
    manifest_path: &Path,
    // `manifest_not_found` is the caller's calm no-op, not a failure: skip
    // the failure telemetry for it (see [`generate_vex_without_manifest`]).
    calm_when_nothing: bool,
    warnings: &mut Vec<RunWarning>,
) -> Result<VexWriteSummary, VexGenError> {
    let manifest_file = match read_manifest(manifest_path).await {
        Ok(m) => m,
        Err(e) => {
            // Core's text ("Failed to parse manifest JSON: ...") does not
            // say which file; in a workspace that matters.
            let message = format!("{e} (in {})", manifest_path.display());
            return Err(fail(common, "manifest_unreadable", message).await);
        }
    };
    let had_manifest_file = manifest_file.is_some();
    // Both ledgers are attestation inputs (records, and the entries whose
    // wiring liveness gates them), so a MALFORMED one is a hard error:
    // attesting with its contents silently dropped would produce a false —
    // or silently partial — document. A missing ledger is simply empty.
    let redirect = match socket_patch_core::patch::redirect::load_redirect_state(&common.cwd).await
    {
        Ok(state) => state,
        Err(corrupt) => {
            // Not core's Display: that text ("... so it will not be
            // overwritten") is written for the `scan --redirect` writer, and
            // `vex` only reads the ledger.
            let message = format!(
                "The redirect ledger {} is malformed ({}); cannot attest redirected patches. \
                 Repair its JSON or restore it from version control, then re-run.",
                corrupt.path.display(),
                corrupt.detail
            );
            return Err(fail(common, "redirect_ledger_corrupt", message).await);
        }
    };
    let vendor = match socket_patch_core::vendor::load_state(&common.cwd).await {
        Ok(state) => state,
        Err(e) => {
            let message = format!(
                "The vendor ledger {} is unreadable ({e}); refusing to attest from a partial \
                 view. Restore it from version control or re-run `socket-patch vendor`.",
                socket_patch_core::vendor::VENDOR_STATE_REL
            );
            return Err(fail(common, "vendor_ledger_corrupt", message).await);
        }
    };
    // Rooted where the ledgers are (`--cwd`). It runs under `--global` /
    // `--global-prefix` too: the redirect and vendor ledgers are still read
    // from `--cwd`, and discovery is what gates them (core discover rule
    // 11). Skipping it handed every ledger claim to the raw-text fallbacks,
    // which must never decide a uuid a lockfile mentions — so a
    // commented-out or rejected pin attested again under `--global`.
    let discovery = crate::commands::discover_wiring(common, &common.cwd).await;
    for diag in &discovery.diagnostics {
        note_warning(warnings, common, diag.code, diag.detail.clone());
    }
    let sources = Sources {
        manifest: manifest_file.unwrap_or_else(PatchManifest::new),
        vendor,
        redirect,
        discovery,
    };
    if sources.is_empty() {
        // A discovery diagnostic (an unparseable lock, a rejected reference)
        // may be the only clue why nothing was found: the wrapper keeps the
        // run's warnings on the error.
        if !had_manifest_file {
            let message = format!(
                "Manifest not found at {}, and no hosted or vendored patch references were \
                 found in the project's lockfiles or .socket/vendor ledgers — nothing to \
                 attest.",
                manifest_path.display()
            );
            return Err(if calm_when_nothing {
                VexGenError {
                    code: "manifest_not_found",
                    message,
                    failed: Vec::new(),
                    warnings: Vec::new(),
                }
            } else {
                fail(common, "manifest_not_found", message).await
            });
        }
        return Err(fail(
            common,
            "no_patches",
            "Manifest is empty — nothing to attest.".to_string(),
        )
        .await);
    }
    let plan = vex_sources::plan(common, sources, &params.assume_applied).await;
    generate_vex(common, params, plan, warnings).await
}

/// Fire `vex_failed` telemetry and build the matching [`VexGenError`].
/// Centralizes the "track then return error" pattern in [`generate_vex`].
/// Attribution goes through the same layered credential chain as
/// `list`/`setup` (flag / env / socket-cli `config.json`), not the raw
/// flags — a `socket login`-only user must not report anonymously.
async fn fail(common: &GlobalArgs, code: &'static str, message: String) -> VexGenError {
    let (token, org) = common.telemetry_credentials();
    track_vex_failed(code, token.as_deref(), org.as_deref()).await;
    VexGenError {
        code,
        message,
        failed: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Pick the product PURL from an explicit override or by filesystem
/// auto-detect. Auto-detect advisories (several project manifests) join
/// `warnings`.
async fn resolve_product_id(
    common: &GlobalArgs,
    product: Option<&str>,
    warnings: &mut Vec<RunWarning>,
) -> Result<String, String> {
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
    for w in detect.warnings {
        note_warning(warnings, common, "product_multiple_manifests", w);
    }
    if let Some(purl) = detect.purl {
        return Ok(purl);
    }
    let mut found = Vec::new();
    for name in PRODUCT_MANIFESTS {
        if tokio::fs::metadata(common.cwd.join(name)).await.is_ok() {
            found.push(*name);
        }
    }
    Err(format_product_undetected(&common.cwd, &found))
}

/// The project manifests product auto-detection reads (after the git
/// remote), in its probe order.
const PRODUCT_MANIFESTS: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "composer.json",
    "pom.xml",
];

/// The `product_undetected` message. `found` names the manifests that exist
/// but yielded no PURL (no name/version), so the user knows which file to
/// fix instead of guessing.
fn format_product_undetected(cwd: &Path, found: &[&str]) -> String {
    let why = match found {
        [] => String::new(),
        [one] => format!(" ({one} was found but has no usable name and version)"),
        many => format!(
            " ({} were found but have no usable name and version)",
            join_and(many)
        ),
    };
    format!(
        "Could not auto-detect a top-level product PURL in {}{why}. \
         Provide one with --product <purl> (e.g. pkg:npm/my-app@1.0.0).",
        cwd.display()
    )
}

/// `a`, `a and b`, `a, b and c`.
fn join_and(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The one `unreadable vendor state` advisory (contract: `setup --check`
/// surfaces a ledger it cannot read or parse as this line, muted by
/// `--silent`): a read-only consumer degrades to "nothing vendored" and says
/// so, on stderr, so the operator learns why nothing verifies. (`vex` itself
/// refuses an unreadable ledger outright — `vendor_ledger_corrupt` — since
/// the ledger's entries gate what attests.)
pub(crate) fn warn_unreadable_vendor_state(common: &GlobalArgs, e: &std::io::Error) {
    if !common.silent {
        eprintln!(
            "Warning: {}",
            vendor_state_unreadable_message(&e.to_string())
        );
    }
}

/// Build the [`VendorContext`] for `setup --check`'s patch-consistency pass
/// from `ledger` — the caller's ONE `load_state` of
/// `.socket/vendor/state.json` (it also fed the vendor-record fold) — plus
/// synthesized entries for the legacy `.socket/go-patches/` redirect
/// backend: a vendored patch is judged by the committed artifact, never the
/// installed tree. (`vex` itself builds its context from the gated plan
/// instead, so a ledger entry no lockfile wires never routes its
/// verification.)
///
/// The go-patches synthesis fixes a latent bug: an apply-redirected Go
/// patch leaves the module cache pristine (the `replace` directive routes
/// the build at the copy dir), so verifying against the crawler-resolved
/// cache path reported `not_applied`/`package_not_found` and the patch was
/// silently omitted from the VEX document. The redirect copy dir holds the
/// bytes the build actually consumes, so it is what verification must hash.
///
/// An unreadable/corrupt vendor ledger degrades to "no vendor entries":
/// vendored PURLs then fall through to the installed tree, fail
/// verification there, and are omitted — fail-closed, never falsely
/// attested. The degrade is returned as a warning detail for the caller to
/// report in its own channel. The context is `None` when there is nothing
/// vendored and no redirect to synthesize (the common case).
pub(crate) async fn vendor_context_from(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    ledger: std::io::Result<VendorState>,
) -> (Option<VendorContext>, Option<String>) {
    let (entries, warning) = match ledger {
        Ok(state) => (state.entries, None),
        Err(e) => (
            HashMap::new(),
            Some(vendor_state_unreadable_message(&e.to_string())),
        ),
    };

    let go_patches = synthesize_go_patches(common, manifest, &entries).await;

    if entries.is_empty() && go_patches.is_empty() {
        return (None, warning);
    }
    let context = VendorContext {
        project_root: common.cwd.clone(),
        entries,
        go_patches,
        hosted: HashMap::new(),
    };
    (Some(context), warning)
}

/// The unreadable-`.socket/vendor/state.json` advisory (`cause` is
/// `load_state`'s error, which names the file).
pub(crate) fn vendor_state_unreadable_message(cause: &str) -> String {
    format!(
        "Unreadable vendor state ({cause}); vendored patches cannot be verified from the \
         committed artifact"
    )
}

/// Synthesize go-patches redirect targets for [`vendor_context_from`] and
/// `vex`: for every socket-owned (`.socket/go-patches/`) `replace` in
/// `go.mod` whose module+version maps to a golang PURL of the record view
/// (`manifest` — for `vex` the merged manifest + ledger + lockfile view, so
/// a manifest-less project's ledger-recorded Go patch verifies too) with no
/// explicit vendor entry, record the absolute redirect copy dir for
/// dir-hash verification.
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
/// empty everywhere else); `warnings` are the run's advisories, already on
/// stderr in human mode, folded into the envelope's `warnings[]` here.
fn emit_envelope_error(
    args: &VexArgs,
    code: &str,
    message: &str,
    failures: &[FailedPatch],
    warnings: &[RunWarning],
) {
    if args.common.json {
        let mut env = Envelope::new(Command::Vex);
        env.dry_run = args.common.dry_run;
        for f in failures {
            env.record(
                PatchEvent::new(PatchAction::Skipped, f.purl.clone())
                    .with_reason(f.reason.clone(), omission_reason_message(&f.reason)),
            );
        }
        env.mark_error(EnvelopeError::new(code, message.to_string()));
        env.warnings = warnings.to_vec();
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
        // The per-patch "Warning: omitting ..." lines already named each
        // omission; `--silent` muted them, so list them with the error.
        if args.common.silent {
            for f in failures {
                eprintln!("  omitted: {} ({})", f.purl, f.reason);
            }
        }
    }
}

/// What an omission routing tag means, in words (the tag itself stays the
/// machine-readable `errorCode`).
fn omission_phrase(reason: &str) -> &'static str {
    match reason {
        ECOSYSTEM_NOT_SETUP => {
            "applied, but its ecosystem has no install hook set up and is not declared \
             `manual` in setup.manual"
        }
        "package_not_found" => "the package is not installed",
        "not_applied" => "the patched files still hold the original content",
        "hash_mismatch" => "a patched file matches neither the original nor the patched content",
        "file_not_found" => "a patched file is missing",
        "no_files" => "the patch record lists no files",
        "vendor_hash_mismatch" => "the vendored artifact does not match the patch",
        "vendor_artifact_missing" => "the vendored artifact is missing",
        "vendor_artifact_unreadable" => "the vendored artifact cannot be read",
        "vendor_path_unsafe" => "the vendored artifact path is unsafe",
        "vendor_uuid_mismatch" => "the vendored artifact belongs to a different patch",
        "vendor_inventory_mismatch" => {
            "the vendored artifact's contents do not match its ledger inventory"
        }
        "stale_install" => "the installed copy is not patched",
        RECORD_UNAVAILABLE => {
            "a lockfile wires the patch, but no local record exists and the patch API could not \
             supply one (offline, a network error, not found, or a paid patch without an API \
             token)"
        }
        RECORD_MISMATCH => {
            "the patch record names a different package or patch than the lockfile wires"
        }
        VENDOR_UNWIRED => {
            "the vendor ledger records its artifact, but no lockfile or config wires it to this \
             package any more"
        }
        REDIRECT_UNWIRED => {
            "the redirect ledger records it, but no lockfile wires its hosted patch to this \
             package any more"
        }
        WIRING_CONFLICT => {
            "the lockfiles wire this package to different patches, so which one the build \
             installs cannot be determined"
        }
        _ => "the patch could not be verified",
    }
}

/// The per-patch stderr line: the readable phrase, then the tag in
/// parentheses (what `--json` reports as `errorCode`).
fn format_omission_warning(purl: &str, reason: &str) -> String {
    format!(
        "Warning: omitting {purl} from VEX: {} ({reason})",
        omission_phrase(reason)
    )
}

/// Human `reason` string for an omission event; the routing tag rides
/// `errorCode`.
fn omission_reason_message(reason: &str) -> String {
    if reason == ECOSYSTEM_NOT_SETUP {
        "applied patch omitted from VEX: its ecosystem has no install hook set up and is not \
         declared `manual` in setup.manual"
            .to_string()
    } else {
        format!("patch omitted from VEX: {}", omission_phrase(reason))
    }
}

/// The `no_applicable_patches` message when every omission was the
/// property-7 setup filter.
fn format_setup_drops_message(n: usize) -> String {
    let (subject, verb, their, ecosystems) = if n == 1 {
        ("applied patch", "was", "its", "ecosystem is")
    } else {
        ("applied patches", "were", "their", "ecosystems are")
    };
    format!(
        "{n} {subject} with vulnerability metadata {verb} omitted from VEX because {their} \
         {ecosystems} not set up (no install hook) and not declared `manual` in \
         .socket/manifest.json's `setup.manual`. Run `socket-patch setup`, or add the \
         ecosystem to `setup.manual`, then re-run."
    )
}

fn emit_envelope_success(summary: &VexWriteSummary, dry_run: bool) {
    let mut env = Envelope::new(Command::Vex);
    env.dry_run = dry_run;
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

    #[test]
    fn vex_summary_lines_pluralize() {
        let p = Path::new("out.json");
        assert_eq!(
            format_vex_written(1, p),
            "Wrote OpenVEX document with 1 statement to out.json"
        );
        assert_eq!(
            format_vex_dry_run_skip("applied"),
            "Skipping VEX generation (--dry-run: nothing was applied)."
        );
        assert_eq!(
            format_vex_written(0, p),
            "Wrote OpenVEX document with 0 statements to out.json"
        );
        assert_eq!(
            format_vex_written(3, Path::new("dir/é.json")),
            "Wrote OpenVEX document with 3 statements to dir/é.json"
        );
        assert_eq!(
            format_vex_dry_run(1, p),
            "[dry-run] Would write OpenVEX document with 1 statement to out.json"
        );
        assert_eq!(
            format_vex_dry_run(2, p),
            "[dry-run] Would write OpenVEX document with 2 statements to out.json"
        );
        assert_eq!(format_vex_emitted(1), "Emitted 1 VEX statement");
        assert_eq!(format_vex_emitted(12), "Emitted 12 VEX statements");
    }

    #[test]
    fn setup_drops_message_agrees_in_number() {
        let one = format_setup_drops_message(1);
        assert!(
            one.starts_with(
                "1 applied patch with vulnerability metadata was omitted from VEX because its \
                 ecosystem is not set up (no install hook)"
            ),
            "{one}"
        );
        let two = format_setup_drops_message(2);
        assert!(
            two.starts_with(
                "2 applied patches with vulnerability metadata were omitted from VEX because \
                 their ecosystems are not set up (no install hook)"
            ),
            "{two}"
        );
        for m in [&one, &two] {
            assert!(!m.contains("(s)"), "{m}");
            assert!(m.ends_with("then re-run."), "{m}");
        }
    }

    #[test]
    fn omission_warning_names_phrase_and_tag() {
        assert_eq!(
            format_omission_warning("pkg:npm/a@1.0.0", "not_applied"),
            "Warning: omitting pkg:npm/a@1.0.0 from VEX: the patched files still hold the \
             original content (not_applied)"
        );
        assert_eq!(
            format_omission_warning("pkg:npm/b@2.0.0", "package_not_found"),
            "Warning: omitting pkg:npm/b@2.0.0 from VEX: the package is not installed \
             (package_not_found)"
        );
        // Unknown tags still read as a sentence and keep the raw tag.
        assert_eq!(
            format_omission_warning("pkg:npm/c@3.0.0", "brand_new_tag"),
            "Warning: omitting pkg:npm/c@3.0.0 from VEX: the patch could not be verified \
             (brand_new_tag)"
        );
        for tag in [
            ECOSYSTEM_NOT_SETUP,
            "package_not_found",
            "not_applied",
            "hash_mismatch",
            "file_not_found",
            "no_files",
            "vendor_hash_mismatch",
            "vendor_artifact_missing",
            "stale_install",
            RECORD_UNAVAILABLE,
            RECORD_MISMATCH,
            VENDOR_UNWIRED,
            REDIRECT_UNWIRED,
            WIRING_CONFLICT,
        ] {
            assert_ne!(
                omission_phrase(tag),
                omission_phrase("brand_new_tag"),
                "{tag} has no phrase of its own"
            );
            let reason = omission_reason_message(tag);
            assert!(reason.contains("omitted from VEX"), "{reason}");
        }
        assert_eq!(
            omission_reason_message("hash_mismatch"),
            "patch omitted from VEX: a patched file matches neither the original nor the \
             patched content"
        );
    }

    #[test]
    fn product_undetected_names_unusable_manifests() {
        let cwd = Path::new("proj");
        assert_eq!(
            format_product_undetected(cwd, &[]),
            "Could not auto-detect a top-level product PURL in proj. Provide one with \
             --product <purl> (e.g. pkg:npm/my-app@1.0.0)."
        );
        assert_eq!(
            format_product_undetected(cwd, &["package.json"]),
            "Could not auto-detect a top-level product PURL in proj (package.json was found \
             but has no usable name and version). Provide one with --product <purl> (e.g. \
             pkg:npm/my-app@1.0.0)."
        );
        let many =
            format_product_undetected(cwd, &["package.json", "pyproject.toml", "Cargo.toml"]);
        assert!(
            many.contains(
                "(package.json, pyproject.toml and Cargo.toml were found but have no usable \
                 name and version)"
            ),
            "{many}"
        );
        assert_eq!(join_and(&["a", "b"]), "a and b");
        assert_eq!(join_and(&[]), "");
    }

    #[test]
    fn org_path_heuristic() {
        assert_eq!(org_looks_like_path(None), None);
        assert_eq!(org_looks_like_path(Some("socketdev")), None);
        assert_eq!(org_looks_like_path(Some("my-org_2")), None);
        assert_eq!(
            org_looks_like_path(Some("out.json")).as_deref(),
            Some("--org \"out.json\" looks like a file path; did you mean -O/--output? (-o is --org)")
        );
        assert!(org_looks_like_path(Some("reports/vex")).is_some());
        assert!(org_looks_like_path(Some("C:\\vex")).is_some());
        assert!(org_looks_like_path(Some("OUT.JSON")).is_some());
    }

    #[test]
    fn vendor_state_message_is_capitalized_and_keeps_cause() {
        assert_eq!(
            vendor_state_unreadable_message("corrupt x/state.json: eof"),
            "Unreadable vendor state (corrupt x/state.json: eof); vendored patches cannot be \
             verified from the committed artifact"
        );
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
