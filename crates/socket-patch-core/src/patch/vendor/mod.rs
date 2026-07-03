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
//! | npm      | deterministic tgz   | per lockfile flavor: package-lock `resolved`+`integrity`, yarn classic, yarn berry, pnpm, bun ([`npm_flavor`] routes) |
//! | cargo    | crate dir           | `.cargo/config.toml` `[patch.crates-io]` + Cargo.lock surgery |
//! | golang   | module dir          | `go.mod` `replace` ([`ReplaceOwner::Vendor`])  |
//! | composer | package dir         | composer.lock `dist` → `{type: path}`          |
//! | gem      | gem dir (+gemspec)  | Gemfile `path:` + Gemfile.lock PATH pair       |
//! | pypi     | rebuilt wheel       | per manifest flavor: uv, poetry, pdm, pipenv, requirements ([`pypi`] routes) |
//! | maven    | rebuilt jar         | committed `file://` maven2 repo + pom `<repository>` ([`maven_repo`]) |
//! | nuget    | rebuilt nupkg       | folder feed + `nuget.config` + `packages.lock.json` pin ([`nuget_feed`]) |
//!
//! npm requests route through [`npm_flavor`], which content-sniffs the
//! project's lockfile (not just file presence) and dispatches to the
//! matching backend — all five flavors have real backends; a lockfile the
//! probe can't classify (or a berry PnP layout) refuses with a stable
//! reason code.
//!
//! ## Ownership & reversal
//!
//! `.socket/vendor/state.json` (committed) records the verbatim original
//! lockfile fragments every wire replaced; `vendor --revert` restores them
//! and removes the artifacts. The rest of the CLI yields ownership of
//! ledger-recorded purls (`apply`/`rollback` skip them, `scan --prune`
//! exempts them) and `remove` reverts vendoring as part of removing a
//! patch. Detached entries (`scan --vendor --detached`) carry an embedded
//! patch record instead of a manifest entry. The path-level UUID makes "is
//! this Socket-vendored, by which patch" recoverable from the lockfile
//! string alone ([`path`]).
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
pub(crate) mod cargo_lock;
pub(crate) mod common;
#[cfg(feature = "composer")]
pub mod composer_lock;
pub mod gem;
#[cfg(feature = "golang")]
pub mod golang;
pub mod lock_inventory;
#[cfg(feature = "maven")]
pub mod maven_repo;
mod npm_common;
pub mod npm_flavor;
pub mod npm_lock;
pub mod npm_pack;
#[cfg(feature = "nuget")]
pub mod nuget_feed;
pub mod pnpm_lock;
pub mod pypi;
pub mod pypi_pdm;
pub mod pypi_pipenv;
pub mod pypi_poetry;
pub mod pypi_requirements;
pub mod pypi_uv;
pub mod pypi_wheel;
pub mod registry_fetch;
pub(crate) mod service_fetch;
mod toml_surgery;
pub mod verify;
pub mod yarn_berry_lock;
pub mod yarn_classic_lock;

pub use path::{ecosystem_dir_for_purl, parse_vendor_path, VendorPathParts, VENDOR_DIR};
pub use state::{load_state, lookup_entry, save_state, VendorEntry, VendorState, VENDOR_STATE_REL};
pub use verify::{check_vendored_artifact, file_sha256_hex, ArtifactHealth};

use std::collections::HashMap;
use std::path::Path;

use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::{
    apply_package_patch, is_safe_relative_subpath, normalize_file_path, ApplyResult, PatchSources,
    VerifyStatus,
};

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

/// Where `vendor` acquires the installable patched artifact for a package.
///
/// * `Auto` (default) — try the patch.socket.dev vendoring service first and
///   silently fall back to a local build on any non-fatal miss (offline,
///   pending build, not found, network error). The downloaded bytes are always
///   integrity-verified before use.
/// * `Service` — require the vendoring service; fail closed on a miss. Useful
///   for CI / exercising the service path exclusively.
/// * `Build` — always build the artifact locally (the pre-service behavior;
///   never contacts the vendoring service).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VendorSource {
    #[default]
    Auto,
    Service,
    Build,
}

impl VendorSource {
    /// Short lowercase tag, suitable for JSON output and `--vendor-source`
    /// flag values.
    pub fn as_tag(&self) -> &'static str {
        match self {
            VendorSource::Auto => "auto",
            VendorSource::Service => "service",
            VendorSource::Build => "build",
        }
    }

    /// Parse a `--vendor-source` / `SOCKET_VENDOR_SOURCE` token (case-insensitive,
    /// surrounding whitespace trimmed).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(VendorSource::Auto),
            "service" => Ok(VendorSource::Service),
            "build" => Ok(VendorSource::Build),
            other => Err(format!(
                "unknown vendor source '{other}'. Expected auto, service, or build."
            )),
        }
    }

    /// Whether this mode may contact the vendoring service at all.
    pub fn may_use_service(&self) -> bool {
        matches!(self, VendorSource::Auto | VendorSource::Service)
    }

    /// Whether a service miss must fail closed (no local-build fallback).
    pub fn requires_service(&self) -> bool {
        matches!(self, VendorSource::Service)
    }
}

/// Everything the vendor backends need to (optionally) download a prebuilt
/// patched archive from the patch.socket.dev vendoring service.
///
/// Built once per `vendor` run in the CLI and threaded as
/// `Option<&VendorServiceConfig>` through the dispatch chain — `None` means
/// "build-only" (the pre-service behavior), which keeps every caller that
/// doesn't opt in (and every existing test) unchanged.
#[derive(Debug, Clone)]
pub struct VendorServiceConfig {
    /// The `auto` / `service` / `build` policy.
    pub source: VendorSource,
    /// The run-level API client (reused from the CLI). `None` disables the
    /// service path even under `auto`/`service` (treated as a miss / refusal).
    pub client: Option<crate::api::client::ApiClient>,
    /// True when the client targets the public proxy (tokenless) — drives
    /// `freeOnly` on the package-reference request.
    pub use_public_proxy: bool,
    /// Optional override for the step-1 package-reference base host.
    pub vendor_url: Option<String>,
    /// Optional override for the step-2 download host (rewrites the host of the
    /// server-returned absolute URL).
    pub patch_server_url: Option<String>,
    /// Strict airgap — never contact the network.
    pub offline: bool,
}

impl VendorServiceConfig {
    /// Whether this run may actually attempt a service download right now:
    /// the mode permits it, we're online, and a client is configured.
    pub fn service_enabled(&self) -> bool {
        self.source.may_use_service() && !self.offline && self.client.is_some()
    }
}

/// One warning per staged file whose pre-patch content matched NEITHER
/// `beforeHash` nor `afterHash` and was overwritten with the verified
/// patched content (vendor staging always force-applies — the stage is a
/// private copy, and every apply write path is hash-gated to exactly
/// `afterHash`).
///
/// Detection rides the verify signature `apply_package_patch` leaves
/// behind: a force-promoted file keeps `status: Ready` WITH
/// `expected_hash: Some(..)` and a differing `current_hash`, whereas a
/// cleanly-verified file carries `expected_hash: None` (see
/// `verify_file_patch`).
pub(crate) fn mismatch_overwrite_warnings(
    result: &ApplyResult,
    name: &str,
    version: &str,
) -> Vec<VendorWarning> {
    let mut warnings: Vec<VendorWarning> = result
        .files_verified
        .iter()
        .filter(|v| {
            v.status == VerifyStatus::Ready
                && v.expected_hash.is_some()
                && v.current_hash != v.expected_hash
        })
        .map(|v| {
            VendorWarning::new(
                "vendor_content_mismatch_overwritten",
                format!(
                    "installed {name}@{version} does not match this patch's expected original \
                     ({}); vendored the patched content anyway",
                    v.file
                ),
            )
        })
        .collect();
    // HashMap-driven verify order is randomized; keep warning order stable.
    warnings.sort_by(|a, b| a.detail.cmp(&b.detail));
    warnings
}

/// Patch-target files (non-empty `beforeHash`) absent from the staged
/// copy. Vendor staging force-applies (see [`force_apply_staged`]), and
/// force silently SKIPS missing files — which would pack an artifact
/// without the fix. This pre-check restores the strict apply's
/// fail-closed behavior for the non-`--force` path. Unsafe keys are
/// skipped here: the apply pipeline itself rejects them fail-closed.
pub(crate) async fn missing_existing_patch_files(
    staged_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    for (file_name, info) in files {
        if info.before_hash.is_empty() {
            continue; // a new file is expected to not exist yet
        }
        let normalized = normalize_file_path(file_name);
        if !is_safe_relative_subpath(normalized) {
            continue;
        }
        if tokio::fs::metadata(staged_dir.join(normalized))
            .await
            .is_err()
        {
            missing.push(file_name.clone());
        }
    }
    missing.sort();
    missing
}

/// A failed synthesized [`ApplyResult`] in the shape the strict apply
/// pipeline would have produced (success=false, `error` set, no files).
pub(crate) fn failed_apply_result(purl: &str, error: String) -> ApplyResult {
    ApplyResult {
        package_key: purl.to_string(),
        package_path: String::new(),
        success: false,
        files_verified: Vec::new(),
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error: Some(error),
        sidecar: None,
    }
}

/// Patched-content blobs harvested from the committed vendor artifacts:
/// for every manifest record whose patch uuid matches its ledger entry,
/// hash the artifact's files (git-sha256, the manifest hash) and keep the
/// ones matching the record's `afterHash`es.
///
/// This is what lets vendor RE-RUNS (in-sync verification, re-vendor) run
/// with no network and no `.socket/blobs` — the committed artifact IS the
/// patched content. Artifact shapes: npm/pypi tarball-or-wheel files and
/// the dir-shaped ecosystems (cargo/golang/composer/gem copies). Fail-soft
/// per entry; tampered/oversized artifacts contribute nothing (the apply
/// pipeline's afterHash gate decides correctness either way).
pub async fn harvest_artifact_blobs(
    project_root: &Path,
    manifest_patches: &HashMap<String, crate::manifest::schema::PatchRecord>,
) -> HashMap<String, Vec<u8>> {
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    let Ok(state) = load_state(project_root).await else {
        return out;
    };
    if state.entries.is_empty() {
        return out;
    }

    for (purl, record) in manifest_patches {
        let needed: std::collections::HashSet<&str> = record
            .files
            .values()
            .map(|f| f.after_hash.as_str())
            .filter(|h| !h.is_empty() && !out.contains_key(*h))
            .collect();
        if needed.is_empty() {
            continue;
        }
        let Some(entry) = state.entries.get(purl).or_else(|| {
            state
                .entries
                .values()
                .find(|e| e.base_purl == crate::utils::purl::strip_purl_qualifiers(purl))
        }) else {
            continue;
        };
        if entry.uuid != record.uuid {
            continue; // stale artifact: a re-vendor is pending, don't trust it
        }
        // SECURITY: the artifact path comes from the committed, tamperable
        // ledger and is joined onto the project root for READING only —
        // still, never follow an escaping path.
        if !crate::patch::apply::is_safe_relative_subpath(&entry.artifact.path) {
            continue;
        }
        let artifact = project_root.join(&entry.artifact.path);

        // Tarball/wheel artifacts: read entries in memory.
        let lower = entry.artifact.path.to_ascii_lowercase();
        if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
            if let Ok(map) = crate::patch::package::read_archive_to_map(&artifact) {
                for bytes in map.into_values() {
                    let h = compute_git_sha256_from_bytes(&bytes);
                    if needed.contains(h.as_str()) {
                        out.insert(h, bytes);
                    }
                }
            }
            continue;
        }
        // `.nupkg` is a plain OPC zip (NuGet) and `.jar` is a plain zip (Maven)
        // — both vendored artifacts read their entries the same way as
        // wheels/zips to recover afterHash blobs.
        if lower.ends_with(".whl")
            || lower.ends_with(".zip")
            || lower.ends_with(".nupkg")
            || lower.ends_with(".jar")
        {
            let Ok(bytes) = tokio::fs::read(&artifact).await else {
                continue;
            };
            if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
                continue;
            }
            let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
                continue;
            };
            for i in 0..archive.len() {
                use std::io::Read as _;
                let Ok(mut file) = archive.by_index(i) else {
                    continue;
                };
                if file.is_dir() || file.size() > MAX_FILE_BYTES {
                    continue;
                }
                let mut content = Vec::with_capacity(file.size() as usize);
                if file.read_to_end(&mut content).is_err() {
                    continue;
                }
                let h = compute_git_sha256_from_bytes(&content);
                if needed.contains(h.as_str()) {
                    out.insert(h, content);
                }
            }
            continue;
        }
        // Dir-shaped artifacts (cargo/golang/composer/gem copies): the
        // record keys are package-relative, so resolve each needed file
        // directly instead of walking the whole tree.
        if tokio::fs::metadata(&artifact)
            .await
            .is_ok_and(|m| m.is_dir())
        {
            for (file_name, info) in &record.files {
                if !needed.contains(info.after_hash.as_str()) {
                    continue;
                }
                let rel = crate::patch::apply::normalize_file_path(file_name);
                if !crate::patch::apply::is_safe_relative_subpath(rel) {
                    continue;
                }
                if let Ok(content) = tokio::fs::read(artifact.join(rel)).await {
                    if content.len() as u64 > MAX_FILE_BYTES {
                        continue;
                    }
                    let h = compute_git_sha256_from_bytes(&content);
                    if h == info.after_hash {
                        out.insert(h, content);
                    }
                }
            }
        }
    }
    out
}

/// Run the hardened apply pipeline against a vendor stage/copy with the
/// vendor auto-force policy:
///
/// * Missing patch-target files fail closed unless the caller's own
///   `--force` asked for that skip tolerance.
/// * The apply itself ALWAYS forces: the stage is a private copy (never
///   the user's tree), and every apply write path is hash-gated to
///   exactly `afterHash` (the archive and blob paths verify content
///   BEFORE writing; the diff path self-disables on a base mismatch) —
///   forcing can only produce the verified patched content or fail
///   closed. This is what lets vendor succeed on a package already
///   patched in place by `apply`, or on a patch whose `beforeHash` was
///   built against different bytes than the installed artifact.
/// * Every force-overwritten file (content matched NEITHER hash) emits a
///   `vendor_content_mismatch_overwritten` warning — including on dry
///   runs, so previews predict the real outcome.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn force_apply_staged(
    purl: &str,
    staged_dir: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> ApplyResult {
    if !force {
        let missing = missing_existing_patch_files(staged_dir, &record.files).await;
        if let Some(first) = missing.first() {
            return failed_apply_result(
                purl,
                format!("Cannot apply patch: {first} - File not found"),
            );
        }
    }
    let result = apply_package_patch(
        purl,
        staged_dir,
        &record.files,
        sources,
        Some(&record.uuid),
        dry_run,
        // The stage is private and every write path is afterHash-gated;
        // Force additionally covers the caller's --force NotFound-skip
        // (the missing-file pre-check above handles the default case).
        crate::patch::apply::MismatchPolicy::Force,
    )
    .await;
    if result.success {
        warnings.extend(mismatch_overwrite_warnings(&result, name, version));
    }
    result
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
        Ok(state) => lookup_entry(&state.entries, purl).is_some(),
        Err(_) => false,
    }
}

/// Every purl spelling under which the ledger's entries are addressable:
/// each entry's map key (the manifest purl, possibly qualified), its
/// resolved base purl, and the qualifier-stripped key. The one-load,
/// many-lookups companion to [`is_purl_vendored`] for callers that match
/// whole purl sets against vendor ownership (apply / rollback / scan
/// prune). An unreadable ledger degrades to the empty set — the same
/// fail-open contract as `is_purl_vendored`; mutating callers that need
/// fail-closed semantics use [`load_state`] directly.
pub async fn vendored_purl_keys(
    project_root: &std::path::Path,
) -> std::collections::HashSet<String> {
    match load_state(project_root).await {
        Ok(state) => state
            .entries
            .iter()
            .flat_map(|(key, entry)| {
                [
                    key.clone(),
                    entry.base_purl.clone(),
                    crate::utils::purl::strip_purl_qualifiers(key).to_string(),
                ]
            })
            .collect(),
        Err(_) => std::collections::HashSet::new(),
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::patch::apply::VerifyResult;

    fn verify(status: VerifyStatus, expected: Option<&str>, current: Option<&str>) -> VerifyResult {
        VerifyResult {
            file: "package/index.js".to_string(),
            status,
            message: None,
            current_hash: current.map(str::to_string),
            expected_hash: expected.map(str::to_string),
            target_hash: None,
        }
    }

    fn result_with(files_verified: Vec<VerifyResult>) -> ApplyResult {
        ApplyResult {
            package_key: "pkg:npm/x@1.0.0".to_string(),
            package_path: String::new(),
            success: true,
            files_verified,
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: None,
            sidecar: None,
        }
    }

    /// Only the force-promoted signature (`Ready` + `expected_hash: Some` +
    /// differing `current_hash`) flags an overwrite; clean verifies and
    /// AlreadyPatched files never do.
    #[test]
    fn mismatch_overwrite_warnings_detects_promoted_ready() {
        // Force-promoted mismatch: flagged.
        let r = result_with(vec![verify(VerifyStatus::Ready, Some("aa"), Some("bb"))]);
        let w = mismatch_overwrite_warnings(&r, "left-pad", "1.3.0");
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].code, "vendor_content_mismatch_overwritten");
        assert!(w[0].detail.contains("left-pad@1.3.0"));
        assert!(w[0].detail.contains("package/index.js"));

        // Clean Ready (verify matched beforeHash): expected_hash is None.
        let r = result_with(vec![verify(VerifyStatus::Ready, None, Some("aa"))]);
        assert!(mismatch_overwrite_warnings(&r, "x", "1").is_empty());

        // AlreadyPatched (afterHash content): not a mismatch.
        let r = result_with(vec![verify(
            VerifyStatus::AlreadyPatched,
            None,
            Some("after"),
        )]);
        assert!(mismatch_overwrite_warnings(&r, "x", "1").is_empty());

        // NotFound (force-skipped): not an overwrite.
        let r = result_with(vec![verify(VerifyStatus::NotFound, None, None)]);
        assert!(mismatch_overwrite_warnings(&r, "x", "1").is_empty());
    }
}

#[cfg(test)]
mod vendor_source_tests {
    use super::*;

    #[test]
    fn parse_accepts_known_tokens_case_insensitively() {
        assert_eq!(VendorSource::parse("auto").unwrap(), VendorSource::Auto);
        assert_eq!(VendorSource::parse("AUTO").unwrap(), VendorSource::Auto);
        assert_eq!(
            VendorSource::parse(" service ").unwrap(),
            VendorSource::Service
        );
        assert_eq!(VendorSource::parse("Build").unwrap(), VendorSource::Build);
    }

    #[test]
    fn parse_rejects_unknown_tokens() {
        let err = VendorSource::parse("download").unwrap_err();
        assert!(err.contains("download"), "echoes the bad token: {err}");
        assert!(
            err.contains("auto, service, or build"),
            "lists the set: {err}"
        );
        assert!(VendorSource::parse("").is_err());
    }

    #[test]
    fn as_tag_round_trips_through_parse() {
        for s in [
            VendorSource::Auto,
            VendorSource::Service,
            VendorSource::Build,
        ] {
            assert_eq!(VendorSource::parse(s.as_tag()).unwrap(), s);
        }
    }

    #[test]
    fn default_is_auto_and_mode_predicates_hold() {
        assert_eq!(VendorSource::default(), VendorSource::Auto);
        assert!(VendorSource::Auto.may_use_service());
        assert!(VendorSource::Service.may_use_service());
        assert!(!VendorSource::Build.may_use_service());
        assert!(VendorSource::Service.requires_service());
        assert!(!VendorSource::Auto.requires_service());
        assert!(!VendorSource::Build.requires_service());
    }
}

#[cfg(test)]
mod harvest_tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord};
    use std::collections::HashMap;
    use std::io::Write as _;

    const UUID: &str = "11111111-2222-4333-8444-555555555555";
    const PATCHED: &[u8] = b"module.exports = patched;\n";

    fn record(purl: &str, uuid: &str, file: &str, after: &[u8]) -> (String, PatchRecord) {
        let mut files = HashMap::new();
        files.insert(
            file.to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"original"),
                after_hash: compute_git_sha256_from_bytes(after),
            },
        );
        (
            purl.to_string(),
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        )
    }

    fn write_ledger(root: &Path, purl: &str, uuid: &str, artifact_path: &str) {
        let vendor_dir = root.join(".socket/vendor");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        let state = serde_json::json!({
            "version": 1,
            "entries": {
                purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": uuid,
                    "artifact": { "path": artifact_path },
                    "wiring": [],
                }
            }
        });
        std::fs::write(
            vendor_dir.join("state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
    }

    fn write_tgz(path: &Path, entry_name: &str, content: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(path).unwrap(),
            flate2::Compression::default(),
        );
        let mut tar = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, entry_name, content).unwrap();
        tar.into_inner().unwrap().finish().unwrap().flush().unwrap();
    }

    #[tokio::test]
    async fn harvests_after_blobs_from_committed_tgz() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/left-pad@1.3.0";
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        write_tgz(&tmp.path().join(&rel), "package/index.js", PATCHED);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "tgz artifact must yield its afterHash blob"
        );
    }

    #[tokio::test]
    async fn stale_uuid_artifact_contributes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/left-pad@1.3.0";
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        write_tgz(&tmp.path().join(&rel), "package/index.js", PATCHED);
        // Ledger still points at an OLD patch uuid: a re-vendor is pending
        // and the artifact's content must not be trusted for the new record.
        write_ledger(
            tmp.path(),
            purl,
            "99999999-aaaa-4bbb-8ccc-dddddddddddd",
            &rel,
        );

        let (k, r) = record(purl, UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        assert!(harvest_artifact_blobs(tmp.path(), &patches)
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn escaping_artifact_path_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/left-pad@1.3.0";
        // The artifact CONTENT would match — only the committed, tamperable
        // ledger path escapes the project. Must contribute nothing.
        let project = tmp.path().join("project");
        write_tgz(&tmp.path().join("outside.tgz"), "package/index.js", PATCHED);
        write_ledger(&project, purl, UUID, "../outside.tgz");

        let (k, r) = record(purl, UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        assert!(harvest_artifact_blobs(&project, &patches).await.is_empty());
    }

    #[tokio::test]
    async fn dir_shaped_artifact_resolves_record_relative_files() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{UUID}/serde-1.0.0");
        let file_dir = tmp.path().join(&rel).join("src");
        std::fs::create_dir_all(&file_dir).unwrap();
        std::fs::write(file_dir.join("lib.rs"), PATCHED).unwrap();
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "src/lib.rs", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "dir-shaped artifact must yield its afterHash blob"
        );
    }
}
