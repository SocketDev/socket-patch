//! The `vendor` backend: committable vendoring of patched dependencies.
//!
//! Where `apply` patches installed packages in place (machine-local state),
//! `vendor` ejects each patched package into a committed
//! `.socket/vendor/<eco>/<patch-uuid>/<artifact>` and rewires the ecosystem's
//! lockfile/config so the project consumes the vendored copy. After
//! committing `.socket/vendor/` + the lockfile edits, a fresh checkout builds
//! with the patched dependency on machines with no socket-patch installed and
//! no Socket API access (spike-proven per ecosystem against real package
//! managers).
//!
//! ## Per-ecosystem wiring
//!
//! | eco      | artifact            | wiring                                         |
//! |----------|---------------------|------------------------------------------------|
//! | npm      | deterministic tgz (vlt: package dir) | per lockfile flavor: package-lock `resolved`+`integrity`, yarn classic, yarn berry, pnpm, bun, vlt ([`npm_flavor`] routes) |
//! | cargo    | crate dir           | root `Cargo.toml` `[patch.crates-io]` + Cargo.lock surgery ([`cargo_manifest`]) |
//! | golang   | module dir          | `go.mod` `replace` ([`ReplaceOwner::Vendor`])  |
//! | composer | package dir         | composer.lock `dist` → `{type: path}`          |
//! | gem      | gem dir (+gemspec)  | Gemfile `path:` + Gemfile.lock PATH pair       |
//! | pypi     | rebuilt wheel       | per manifest flavor: uv, poetry, pdm, pipenv, requirements ([`pypi`] routes) |
//! | maven    | patched jar         | suffixed `<version>-socket.<hex8>` tree under `.socket/vendor/maven2` + pom pin, `.mvn/maven.config` (or Gradle / sbt / scala-cli wiring) ([`maven_repo`] routes to [`jvm`]) |
//! | nuget    | rebuilt nupkg       | folder feed + `nuget.config` + `packages.lock.json` pin ([`nuget_feed`]) |
//!
//! npm requests route through [`npm_flavor`], which content-sniffs the
//! project's lockfile (not just file presence) and dispatches to the
//! matching backend — every flavor (package-lock, yarn classic/berry, pnpm
//! v9 and legacy, bun, vlt) has a real backend; a lockfile the
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
//! patch. Every `scan --mode vendored` / `get --mode vendored` entry is
//! detached: it embeds the patch `record` (the verification source —
//! vendored runs never write `.socket/manifest.json`), while the standalone
//! `vendor` command records `detached: false` entries that point at the
//! manifest. The path-level UUID makes "is this Socket-vendored, by which
//! patch" recoverable from the lockfile string alone ([`path`]).
//!
//! [`ReplaceOwner::Vendor`]: crate::vendor::go_mod_edit::ReplaceOwner

pub mod path;
pub mod state;

#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) mod berry_zip;
mod bun_binary;
pub mod bun_lock;
pub(crate) mod bun_lock_text;
pub(crate) mod bun_lockb;
mod bun_workspace;
pub mod cargo;
pub mod cargo_config;
pub mod cargo_lock;
pub mod cargo_manifest;
pub mod cargo_tag;
pub(crate) mod common;
pub mod composer_lock;
pub mod gem;
pub mod go_mod_edit;
pub mod go_sum_edit;
pub mod golang;
pub mod jvm;
pub(crate) mod ledger_snapshots;
pub mod lock_inventory;
pub mod maven_repo;
pub(crate) mod npm_common;
pub(crate) mod npm_dir;
pub mod npm_flavor;
pub mod npm_lock;
pub(crate) mod npm_origin;
mod npm_pack;
pub(crate) mod nuget_config;
pub mod nuget_feed;
pub(crate) mod parse_memo;
pub mod pnpm_lock;
pub mod pnpm_lock_legacy;
pub mod prestage;
pub mod pypi;
pub(crate) mod pypi_distribution;
mod pypi_hatch;
mod pypi_lock;
pub mod pypi_pdm;
pub mod pypi_pipenv;
pub mod pypi_poetry;
pub(crate) mod pypi_requirements;
mod pypi_uv;
mod pypi_wheel;
pub mod redownload;
pub mod registry_fetch;
pub(crate) mod reuse;
pub(crate) mod service_fetch;
pub mod source;
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
#[allow(dead_code, unused_imports)]
pub mod test_support;
mod toml_surgery;
pub(crate) mod verify;
pub mod vlt_bundled;
pub mod vlt_lock;
pub(crate) mod vlt_lock_text;
pub(crate) mod yarn_berry_lock;
pub(crate) mod yarn_classic_lock;
#[cfg(test)]
mod yarn_layering_tests;

pub use path::{ecosystem_dir_for_purl, parse_vendor_path};
#[cfg(test)]
pub(crate) use pypi_lock::restore_document as restore_python_document;
pub use source::PackageSource;
// `vex::discover` validates lockfile-recorded npm names with the same rule the
// npm backends apply to their own coordinates.
pub(crate) use npm_common::is_safe_npm_name;
pub use pypi_requirements::requirements_include_names;
pub use state::{
    carry_forward_wiring, load_state, lookup_entry, lookup_entry_kv, purl_keys_cover, save_state,
    save_state_shared, VendorEntry, VendorState, VENDOR_STATE_REL,
};
pub use verify::{
    artifact_is_file_shaped, check_vendored_artifact, compute_dir_inventory,
    compute_package_dir_inventory, file_sha256_hex, ArtifactHealth,
};
// The hosted→vendored takeover refuses a berry project the backend would
// refuse BEFORE it reverts the hosted redirect.
pub use npm_lock::npm_lock_vendor_preflight;
pub use npm_common::npm_tarball_gitignore_preflight;
pub use yarn_berry_lock::{yarn_berry_vendor_preflight, yarn_berry_vendor_target_preflight};

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{is_safe_relative_subpath, normalize_file_path, ApplyResult};
use crate::utils::fs::read_regular_to_string_sync;

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

/// Advisory probe: is this project one `yarn install` away from silently
/// losing its vendored patches?
///
/// Yarn 2+ (berry) migrates a classic (v1) `yarn.lock` to its own format on
/// install and re-resolves every entry from the registry — the vendored
/// `file:./.socket/vendor/…` resolutions are dropped with no warning and the
/// packages install unpatched (observed end-to-end on a real monorepo).
/// Returns the warning when ALL of:
///
/// * `yarn.lock` exists and is classic (`# yarn lockfile v1` marker), AND
/// * it carries vendored wiring (`.socket/vendor/` resolutions), AND
/// * `package.json` does NOT pin yarn classic via `packageManager: yarn@1…`
///   (a corepack pin makes stray berry installs refuse instead of migrate).
///
/// State-based (reads the wired lockfile, not the current run's events), so
/// callers can invoke it unconditionally at envelope-finalize time: it stays
/// silent on unwired projects and after a full revert.
pub fn yarn_classic_berry_migration_risk(project_root: &Path) -> Option<VendorWarning> {
    // The guarded sync reader (`O_NONBLOCK` open + fstat regular-file check):
    // this probe runs at envelope-finalize time on every vendor / scan
    // --mode vendored run, and a plain `open(2)` of a FIFO planted at `yarn.lock` or
    // `package.json` would wedge the whole run after the real work is done.
    let lock = read_regular_to_string_sync(&project_root.join("yarn.lock")).ok()?;
    if !lock.contains("# yarn lockfile v1") || !lock.contains(".socket/vendor/") {
        return None;
    }
    let manifest = read_regular_to_string_sync(&project_root.join("package.json")).ok();
    if manifest_pins_yarn_classic(manifest.as_deref()) {
        return None;
    }
    Some(VendorWarning::new(
        "yarn_classic_berry_migration_risk",
        "yarn.lock is yarn-classic (v1) with vendored resolutions: installing with yarn 2+ \
         (berry) migrates the lockfile and silently drops them — packages install unpatched \
         from the registry. Pin yarn classic (e.g. \"packageManager\": \"yarn@1.22.22\" in \
         package.json) so every install uses yarn 1.",
    ))
}

/// Whether a root `package.json` text pins yarn classic through corepack's
/// `packageManager: yarn@1…`, which makes a stray yarn 2+ (berry) install
/// refuse instead of migrating a classic `yarn.lock` and dropping its
/// pins. A missing, unreadable or malformed manifest vouches for nothing
/// (`false`), so callers fail toward warning. Shared by the vendored probe
/// above and the hosted yarn classic rewriter, so both modes warn alike.
pub(crate) fn manifest_pins_yarn_classic(manifest: Option<&str>) -> bool {
    let Some(pm) = manifest
        .and_then(|pkg| serde_json::from_str::<serde_json::Value>(pkg).ok())
        .and_then(|v| {
            v.get("packageManager")
                .and_then(|p| p.as_str().map(String::from))
        })
    else {
        return false;
    };
    let major = crate::utils::package_manager::pinned_version(&pm, "yarn").map(|rest| {
        rest.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
    });
    major.as_deref() == Some("1")
}

/// Vendoring acquires immutable artifacts from the patch service.
/// `auto` remains a command-line compatibility alias for `service`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VendorSource {
    #[default]
    Service,
}

impl VendorSource {
    pub fn as_tag(&self) -> &'static str {
        "service"
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "service" => Ok(Self::Service),
            "build" => Err("local artifact construction was removed; vendoring downloads prebuilt artifacts from the patch service".into()),
            other => Err(format!("unknown vendor source '{other}'. Expected service (or the compatibility alias auto).")),
        }
    }

    pub fn may_use_service(&self) -> bool {
        true
    }
    pub fn requires_service(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct VendorServiceConfig {
    /// Override Maven config wiring; None preserves the recorded choice (auto for new projects).
    pub maven_config: Option<bool>,
    /// Server artifact acquisition policy.
    pub source: VendorSource,
    /// The run-level API client (reused from the CLI). `None` disables the
    /// service path (reported as a refusal).
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

/// Most fetched prebuilt archive bytes the vendor prefetch keeps waiting
/// for the loop. An archive is a whole tarball in memory where the serial
/// loop held exactly one; the download window (the API's own in-flight
/// cap) already keeps at most that many archives ahead of the loop, and
/// this bounds what they may add up to when a few are large: past it, only
/// the download the loop is waiting on may start. It bounds NEW downloads:
/// the ones already in flight when it is reached still land, so the held
/// bytes can exceed it by what they carry; and the trees pre-staged from
/// those archives live on disk, uncounted (see
/// [`crate::api::vendor_prefetch`]'s memory notes).
const ARCHIVE_PREFETCH_BYTES: usize = 128 * 1024 * 1024;

impl VendorServiceConfig {
    /// Whether this run may actually attempt a service download right now:
    /// the mode permits it, we're online, and a client is configured.
    pub fn service_enabled(&self) -> bool {
        self.source.may_use_service() && !self.offline && self.client.is_some()
    }

    /// Whether a run through this config would prefetch service downloads
    /// at all — false when the service is not enabled, and false whenever
    /// the in-flight cap is one, which is
    /// [`crate::utils::concurrent::API_CONCURRENCY_ENV`]'s documented
    /// promise (and what a tight descriptor limit forces): one request at
    /// a time, the strictly serial loop, nothing fetched ahead. Callers
    /// ask before doing the work of naming the plan.
    pub fn wants_prefetch(&self) -> bool {
        self.service_enabled()
            && crate::utils::concurrent::api_concurrency(self.use_public_proxy) > 1
    }

    /// Attach a download plan to this config's client: `downloads` are the
    /// records the vendor loop is expected to download from the service,
    /// in loop order, each with the secondary artifact its backend fetches
    /// right after the archive (see
    /// [`crate::api::client::ApiClient::prefetch_vendor_downloads`]). As
    /// many downloads run at once as the API's in-flight cap allows, and at
    /// most [`ARCHIVE_PREFETCH_BYTES`] of fetched archives wait for the loop.
    /// `None` — nothing attached — when [`Self::wants_prefetch`] is false,
    /// or when fewer than two downloads are planned (nothing to overlap).
    pub fn prefetch_archives(
        &self,
        downloads: Vec<crate::api::client::PlannedDownload>,
    ) -> Option<crate::api::client::VendorPrefetchGuard> {
        if !self.wants_prefetch() || downloads.len() < 2 {
            return None;
        }
        let client = self.client.as_ref()?;
        Some(client.prefetch_vendor_downloads(
            downloads,
            self.use_public_proxy,
            self.vendor_url.as_deref(),
            self.patch_server_url.as_deref(),
            crate::utils::concurrent::api_concurrency(self.use_public_proxy),
            ARCHIVE_PREFETCH_BYTES,
        ))
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
    manifest_patches: &HashMap<String, PatchRecord>,
) -> HashMap<String, Vec<u8>> {
    let Ok(state) = load_state(project_root).await else {
        return HashMap::new();
    };
    harvest_artifact_blobs_from(project_root, &state.entries, manifest_patches).await
}

/// Hard cap on a committed artifact's own bytes, and on any one member
/// harvested out of it. Shared by [`harvest_artifact_blobs_from`] and the
/// zip reader it hands the work to.
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// [`harvest_artifact_blobs`] over an already-loaded ledger (`entries`),
/// for callers that hold the run's single `load_state` result.
pub async fn harvest_artifact_blobs_from(
    project_root: &Path,
    entries: &HashMap<String, VendorEntry>,
    manifest_patches: &HashMap<String, PatchRecord>,
) -> HashMap<String, Vec<u8>> {
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    if entries.is_empty() {
        return out;
    }

    for (purl, record) in manifest_patches {
        let needed: HashSet<&str> = record
            .files
            .values()
            .map(|f| f.after_hash.as_str())
            .filter(|h| !h.is_empty() && !out.contains_key(*h))
            .collect();
        if needed.is_empty() {
            continue;
        }
        let Some(entry) = entries.get(purl).or_else(|| {
            let key = crate::utils::purl_key::PurlKey::new(purl);
            entries
                .values()
                .find(|e| crate::utils::purl_key::PurlKey::new(&e.base_purl) == key)
        }) else {
            continue;
        };
        if entry.uuid != record.uuid {
            continue; // stale artifact: a re-vendor is pending, don't trust it
        }
        // SECURITY: the artifact path comes from the committed, tamperable
        // ledger and is joined onto the project root for READING only —
        // still, never follow an escaping path.
        if !is_safe_relative_subpath(&entry.artifact.path) {
            continue;
        }
        let artifact = project_root.join(&entry.artifact.path);

        // Tarball/wheel artifacts: read entries in memory.
        let lower = entry.artifact.path.to_ascii_lowercase();
        if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
            // The tarball reader is synchronous (gzip + tar decode): run it
            // off the async thread like `verify` does, so a large committed
            // artifact never stalls the runtime.
            let tgz = artifact.clone();
            let read = tokio::task::spawn_blocking(move || {
                crate::patch::package::read_archive_to_map(&tgz)
            })
            .await;
            if let Ok(Ok(map)) = read {
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
            // Gate on metadata BEFORE reading: opening a non-regular file
            // planted at the artifact path (a FIFO) blocks until a writer
            // appears — wedging the run — and the size cap must bound the
            // read, not audit it after the bytes are already in memory.
            if !tokio::fs::metadata(&artifact)
                .await
                .is_ok_and(|m| m.is_file() && m.len() <= MAX_ARTIFACT_BYTES)
            {
                continue;
            }
            // The record's own keys name the members carrying the
            // afterHashes, so the reader below can seek straight to them.
            let wanted: Vec<(String, String)> = record
                .files
                .iter()
                .filter(|(_, info)| needed.contains(info.after_hash.as_str()))
                .map(|(file_name, info)| (file_name.clone(), info.after_hash.clone()))
                .collect();
            let zip_path = artifact.clone();
            // Read + inflate are synchronous: run them off the async thread
            // like the tarball branch above, so a large committed artifact
            // never stalls the runtime.
            let read =
                tokio::task::spawn_blocking(move || harvest_zip_blobs(&zip_path, &wanted)).await;
            if let Ok(found) = read {
                out.extend(found);
            }
            continue;
        }
        // Dir-shaped artifacts (cargo/golang/composer/gem copies, vlt
        // package dirs): the record keys are package-relative, so resolve
        // each needed file directly instead of walking the whole tree. A vlt
        // dir's package.json is post-transform, never the afterHash blob,
        // and its node_modules holds vlt's links.
        let vlt_dir = entry.ecosystem == "npm" && entry.flavor.as_deref() == Some(vlt_lock::FLAVOR);
        if tokio::fs::metadata(&artifact)
            .await
            .is_ok_and(|m| m.is_dir())
        {
            for (file_name, info) in &record.files {
                if !needed.contains(info.after_hash.as_str()) {
                    continue;
                }
                let rel = normalize_file_path(file_name);
                if !is_safe_relative_subpath(rel)
                    || (vlt_dir && (rel == "package.json" || rel.starts_with("node_modules/")))
                {
                    continue;
                }
                let path = artifact.join(rel);
                // Same gate as the zip-shaped artifacts above: never open a
                // non-regular file (FIFO wedge), bound the read up front.
                if !tokio::fs::metadata(&path)
                    .await
                    .is_ok_and(|m| m.is_file() && m.len() <= MAX_FILE_BYTES)
                {
                    continue;
                }
                if let Ok(content) = tokio::fs::read(&path).await {
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

// Test-only: how many times `harvest_zip_blobs`'s fallback scan ran on THIS
// thread. The name path and the scan return the same blobs by construction,
// so which one produced them is otherwise unobservable — and it is the whole
// point of the item. Thread-local, so the tests that read it call
// `harvest_zip_blobs` directly rather than through the blocking pool.
#[cfg(test)]
thread_local! {
    static FALLBACK_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only: run `f` and report how many fallback scans it took.
#[cfg(test)]
fn fallback_scans_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    FALLBACK_SCANS.with(|n| n.set(0));
    let out = f();
    (out, FALLBACK_SCANS.with(std::cell::Cell::get))
}

/// One zip-shaped committed artifact's contribution to the harvest: the
/// blobs whose git-sha256 is one of the `(record key, afterHash)` pairs in
/// `wanted`. Synchronous — the caller runs it on the blocking pool.
///
/// A zip is addressable by member name and `wanted`'s keys ARE the member
/// names (modulo the `package/` prefix a manifest key may carry), so the
/// common case costs one seek and one inflate per needed hash instead of
/// inflating the whole archive. Everything the name lookup does not settle —
/// a member renamed since the patch was exported, a duplicate name, an
/// entry the caps reject — falls back to an exhaustive index scan, which is
/// what keeps the result identical to reading every entry: the name path only ever admits an entry whose hash IS one of
/// the wanted ones, and the scan then supplies every hash still outstanding.
fn harvest_zip_blobs(path: &Path, wanted: &[(String, String)]) -> HashMap<String, Vec<u8>> {
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    /// The entry's bytes, or `None` when either cap rejects it.
    ///
    /// SECURITY: `size` is only the archive-DECLARED uncompressed size; the
    /// entry reader is bounded solely by the COMPRESSED size, so a zip bomb
    /// can declare a tiny size (past the gate) yet decompress far beyond the
    /// cap. Bound the decompressed read itself and drop any entry that
    /// overflows, before its bytes are all in memory.
    fn capped(size: u64, entry: &mut impl std::io::Read) -> Option<Vec<u8>> {
        use std::io::Read as _;

        if size > MAX_FILE_BYTES {
            return None;
        }
        let mut content = Vec::with_capacity(size as usize);
        entry
            .by_ref()
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut content)
            .ok()?;
        (content.len() as u64 <= MAX_FILE_BYTES).then_some(content)
    }

    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    // The caller's metadata gate already refused a non-regular path; the
    // guarded opener refuses one swapped in since, so a FIFO planted between
    // the two can never wedge the blocking pool in `open(2)`.
    let Ok(bytes) = crate::utils::fs::read_regular_to_bytes_sync(path) else {
        return out;
    };
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return out;
    };

    let mut remaining: HashSet<&str> = wanted.iter().map(|(_, hash)| hash.as_str()).collect();
    for (file_name, hash) in wanted {
        if !remaining.contains(hash.as_str()) {
            continue;
        }
        // The same two spellings `verify_member_map` looks a member up by:
        // the normalized key first, then the raw manifest key.
        let normalized = normalize_file_path(file_name);
        let names = [normalized, file_name.as_str()];
        for (i, name) in names.iter().enumerate() {
            if names[..i].contains(name) {
                continue;
            }
            let Ok(mut entry) = archive.by_name(name) else {
                continue;
            };
            if entry.is_dir() {
                continue;
            }
            let size = entry.size();
            let Some(content) = capped(size, &mut entry) else {
                continue;
            };
            let h = compute_git_sha256_from_bytes(&content);
            if h == *hash {
                remaining.remove(hash.as_str());
                out.insert(h, content);
                break;
            }
        }
    }
    if remaining.is_empty() {
        return out;
    }

    // Fallback: the member names disagree with the record's keys (or an
    // entry was rejected above). Scan every entry.
    #[cfg(test)]
    FALLBACK_SCANS.with(|n| n.set(n.get() + 1));
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let size = entry.size();
        let Some(content) = capped(size, &mut entry) else {
            continue;
        };
        let h = compute_git_sha256_from_bytes(&content);
        if remaining.contains(h.as_str()) {
            out.insert(h, content);
        }
    }
    out
}

/// Warning code on a failed npm-family [`VendorOutcome::Done`]: the patch
/// service is still building the patch's prebuilt artifact. With
/// [`VENDOR_PREBUILT_UNAVAILABLE`], it tells the vendor loop the patch is not
/// served (yet), not broken: a package already vendored at an older patch
/// keeps it and is reported as skipped (#954), the way hosted mode keeps
/// its pin.
pub const VENDOR_PREBUILT_PENDING: &str = "vendor_prebuilt_pending";
/// Warning code on a failed npm-family [`VendorOutcome::Done`]: the patch
/// service has no artifact for the patch (`build_failed`, `not_found`,
/// `withdrawn`, …). See [`VENDOR_PREBUILT_PENDING`].
pub const VENDOR_PREBUILT_UNAVAILABLE: &str = "vendor_prebuilt_unavailable";

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

/// Options for a vendored revert (one backend `revert_*_opts` call).
#[derive(Debug, Clone, Copy)]
pub struct RevertOpts {
    /// Preview only — no file writes, no artifact deletion.
    pub dry_run: bool,
    /// Restore the lockfile wiring but KEEP the artifact directory (and the
    /// caller keeps the ledger entry) — `rollback/remove --preserve-state`.
    /// Never sets [`RevertOutcome::kept_artifact`], which stays reserved for
    /// drift-keeps.
    pub keep_artifact: bool,
}

impl RevertOpts {
    /// The default revert: the artifact directory is deleted on a
    /// successful wet revert.
    pub fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            keep_artifact: false,
        }
    }
}

/// Warning code for a recorded lock entry that no longer exists at revert
/// time (the dependency was removed). See [`RevertOutcome::lock_entry_removed`].
pub const LOCK_ENTRY_REMOVED_CODE: &str = "vendor_lock_entry_removed";

/// The result of one backend `revert_*` call.
#[derive(Debug)]
pub struct RevertOutcome {
    pub success: bool,
    pub warnings: Vec<VendorWarning>,
    pub error: Option<String>,
    /// True when the backend deliberately KEPT the artifact uuid dir
    /// because at least one wiring record was left alone during the
    /// restore (a `vendor_lock_entry_drifted` skip). The
    /// entry's recorded pre-vendor originals and vendored blob may be the
    /// only surviving inputs a later restore needs (the lockfile — or the
    /// hosted redirect ledger's recorded `original` fragments — can still
    /// point at them), so callers must ALSO keep the state.json entry
    /// instead of pruning it, and report the package as skipped rather
    /// than removed. Never set on failure or on dry runs.
    pub kept_artifact: bool,
}

impl RevertOutcome {
    pub fn ok() -> Self {
        Self {
            success: true,
            warnings: Vec::new(),
            error: None,
            kept_artifact: false,
        }
    }

    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            success: false,
            warnings: Vec::new(),
            error: Some(error.into()),
            kept_artifact: false,
        }
    }

    /// True when any wiring record was left alone during the restore —
    /// every left-alone branch (ownership-gate drift, missing pre-vendor
    /// original, unknown kind/key, allowlist skip) warns with the stable
    /// code `vendor_lock_entry_drifted`.
    ///
    /// A recorded lock entry that has VANISHED (the user removed the
    /// dependency) is not drift: it warns `vendor_lock_entry_removed`
    /// instead (see [`Self::lock_entry_removed`]), and the backend keeps
    /// the artifact only while the lock still resolves through it.
    ///
    /// LIVENESS CONTRACT: backends must NOT emit that code for a record
    /// whose live state already equals its reverted state (the fragment
    /// equals `rec.original`, or — for Added records with no original —
    /// the key is absent). A previous partial revert leaves records in
    /// exactly that state; re-classifying them as drift would keep the
    /// artifacts and ledger entry forever, and the CLI's "undo the drift
    /// and re-run `vendor --revert`" remediation could never be satisfied.
    /// Such records are silent no-ops, so this gate fires only on genuine
    /// third-party drift that the user can still undo.
    pub fn drift_skipped(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.code == "vendor_lock_entry_drifted")
    }

    /// True when any recorded lock entry no longer existed at revert time
    /// (`vendor_lock_entry_removed`): the user removed the dependency
    /// (`yarn remove`, `npm uninstall`, ...), so there was nothing to
    /// restore. Unlike drift, nothing of the user's is being protected, so
    /// this alone must not keep the artifact forever (#665). The backend
    /// keeps it only while a lockfile still mentions the uuid dir, see
    /// `npm_flavor::keep_artifact_while_lock_references_it`.
    pub fn lock_entry_removed(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.code == LOCK_ENTRY_REMOVED_CODE)
    }

    /// Mark the artifact dir as deliberately kept after a drift-skip and
    /// surface it honestly. Backends call this INSTEAD of removing the
    /// uuid dir when [`Self::drift_skipped`] is true: deleting it would be
    /// unrecoverable, while keeping it is always recoverable (the orphan
    /// sweep's invariant — never delete what something still references —
    /// applies to the revert too).
    pub fn keep_artifact(&mut self, uuid_dir_rel: &str) {
        self.kept_artifact = true;
        self.warnings.push(VendorWarning::new(
            "vendor_artifact_kept",
            format!(
                "kept {uuid_dir_rel}: some recorded lock entries were left alone (see the \
                 vendor_lock_entry_drifted / vendor_lock_entry_removed warnings) and the vendored artifacts may still be \
                 needed for a later restore; undo the drift (restore the vendored lock entries \
                 or re-vendor) and re-run `vendor --revert` to finish cleaning up"
            ),
        ));
    }
}

/// True iff this build can vendor this PURL's ecosystem.
pub fn is_vendorable(purl: &str) -> bool {
    ecosystem_dir_for_purl(purl).is_some()
}

/// The download the vendor loop's backend call for `purl` — a wet run with
/// the patch service enabled — asks the service for, when it asks at all:
/// past every refusal the backend raises before that call, and answered
/// neither by its in-sync hot path nor by the reuse of a committed
/// artifact. The download carries what rides it: the secondary artifact the
/// backend fetches right after (gem's stub gemspec) and the recipe that
/// stages the archive ahead of the backend ([`prestage`]). Each backend answers with the same functions its `vendor_*`
/// entry point runs first, so a download plan built from this never names a
/// package the loop refuses before asking (a grant can start a server-side
/// build and counts against quota). `source_path` is the package source's
/// [`PackageSource::path`] (the gem backend reads its name and parents);
/// `pipenv_version` and `installed_sites` are the loop's own pypi caches.
/// npm is planned in one batch by [`npm_flavor::preflight_packages`] and
/// answers `None` here, as does anything without a service path.
pub async fn service_preflight(
    purl: &str,
    source_path: &Path,
    project_root: &Path,
    record: &crate::manifest::schema::PatchRecord,
    pipenv_version: &tokio::sync::OnceCell<Option<u32>>,
    installed_sites: &pypi::InstalledSiteListings,
) -> Option<crate::api::client::PlannedDownload> {
    match ecosystem_dir_for_purl(purl) {
        Some("cargo") => cargo::service_preflight(purl, project_root, record).await,
        Some("composer") => composer_lock::service_preflight(purl, project_root, record).await,
        Some("gem") => gem::service_preflight(purl, source_path, project_root, record).await,
        Some("golang") => golang::service_preflight(purl, project_root, record).await,
        Some("maven") => maven_repo::service_preflight(purl, project_root, record).await,
        Some("nuget") => nuget_feed::service_preflight(purl, project_root, record).await,
        Some("pypi") => {
            pypi::service_preflight(purl, project_root, record, pipenv_version, installed_sites)
                .await
        }
        _ => None,
    }
}

/// The lock-text refusals among `candidates` (purls with the uuid of the
/// patch to vendor): each purl its backend refuses on the project's lock
/// and manifest text alone, with the backend's `(code, detail)` — the pnpm,
/// yarn classic and yarn berry gates ([`npm_flavor::lock_text_refusals`])
/// and cargo's locked-version gate ([`cargo::lock_text_refusal`]). None of
/// them reads the patch, so the answer needs no view: a vendored run asks
/// before it fetches views and pristine sources, and a package that will
/// be refused costs no network.
pub async fn lock_text_refusals(
    project_root: &Path,
    candidates: &[(&str, &str)],
) -> HashMap<String, (&'static str, String)> {
    let record = |uuid: &str| crate::manifest::schema::PatchRecord {
        uuid: uuid.to_string(),
        exported_at: String::new(),
        files: HashMap::new(),
        vulnerabilities: HashMap::new(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
    };
    let mut refusals = HashMap::new();
    let npm: Vec<(&str, crate::manifest::schema::PatchRecord)> = candidates
        .iter()
        .filter(|(purl, _)| ecosystem_dir_for_purl(purl) == Some("npm"))
        .map(|(purl, uuid)| (*purl, record(uuid)))
        .collect();
    if !npm.is_empty() {
        let packages: Vec<(&str, &crate::manifest::schema::PatchRecord)> =
            npm.iter().map(|(purl, record)| (*purl, record)).collect();
        for ((purl, _), refusal) in packages
            .iter()
            .zip(npm_flavor::lock_text_refusals(project_root, &packages).await)
        {
            if let Some(refusal) = refusal {
                refusals.insert(purl.to_string(), refusal);
            }
        }
    }
    for (purl, uuid) in candidates {
        if ecosystem_dir_for_purl(purl) == Some("cargo") {
            if let Some(refusal) = cargo::lock_text_refusal(purl, project_root, &record(uuid)).await
            {
                refusals.insert(purl.to_string(), refusal);
            }
        }
    }
    refusals
}

/// [`lock_text_refusals`] for npm `candidates` a HOSTED pin wires, in a
/// pnpm (lockfileVersion 9) project only — the refusals a hosted → vendored
/// takeover of them meets after it restores the registry entry (#853), so
/// a dry-run preview can name them without staging the restore (which
/// needs the registry). Empty for every other flavor.
///
/// Evaluating the gates on the still-hosted lock is exact for pnpm: the
/// hosted restore only splices each entry's `resolution:` value, which no
/// pnpm gate reads (coordinates, CRLF, catalogs, overrides, entry presence
/// and ref rewritability all key on other text). The one difference is a
/// `pnpm-workspace.yaml` scaffold hosted mode created, which the restore
/// deletes; a gate that depended on it would make this under-predict, and
/// the wet run still refuses. Yarn's restores rewrite key and checksum
/// text, and legacy pnpm 7/8 locks (5.4 / 6.0) are not lock-text gated at
/// all, so neither is predicted here: a CRLF legacy lock, an override
/// conflict or an unsupported legacy entry previews `would_vendor` while
/// the wet takeover refuses it (keeping the hosted pin, #963) — a known
/// preview gap the contract names.
pub async fn pnpm_takeover_lock_text_refusals(
    project_root: &Path,
    candidates: &[(&str, &str)],
) -> HashMap<String, (&'static str, String)> {
    if !matches!(
        npm_flavor::detect_npm_lock_flavor(project_root).await,
        Ok((npm_flavor::NpmLockFlavor::Pnpm, _))
    ) {
        return HashMap::new();
    }
    let npm: Vec<(&str, &str)> = candidates
        .iter()
        .filter(|(purl, _)| ecosystem_dir_for_purl(purl) == Some("npm"))
        .copied()
        .collect();
    lock_text_refusals(project_root, &npm).await
}

/// [`VendorState::purl_keys`] over the ledger in `project_root`, loaded
/// once for callers that match whole purl sets against vendor ownership
/// (apply / rollback / scan prune). An unreadable ledger degrades to the
/// empty set (fail-open); mutating callers that need fail-closed semantics
/// use [`load_state`] directly.
pub async fn vendored_purl_keys(project_root: &Path) -> HashSet<crate::utils::purl_key::PurlKey> {
    load_state(project_root)
        .await
        .map(|state| state.purl_keys())
        .unwrap_or_default()
}

#[cfg(test)]
mod vendor_source_tests {
    use super::VendorSource;

    #[test]
    fn service_is_the_only_artifact_source() {
        for token in ["service", " SERVICE ", "auto", "AUTO"] {
            assert_eq!(VendorSource::parse(token).unwrap(), VendorSource::Service);
        }
        assert!(VendorSource::parse("build")
            .unwrap_err()
            .contains("removed"));
        assert!(VendorSource::parse("download").is_err());
        assert_eq!(VendorSource::default().as_tag(), "service");
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

    /// Release a reader wedged in `open(2)` on `fifo` (an unguarded open) so
    /// the tokio blocking pool can shut down; the write side closing
    /// immediately EOFs the read.
    #[cfg(unix)]
    pub(super) fn unblock_fifo_reader(fifo: &Path) {
        let fifo = fifo.to_path_buf();
        std::thread::spawn(move || {
            let _ = std::fs::OpenOptions::new().write(true).open(fifo);
        });
    }

    #[cfg(unix)]
    pub(super) fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

    /// A FIFO planted at a zip-shaped artifact path must be skipped, not
    /// read: `open(2)` on a FIFO blocks until a writer appears, wedging the
    /// whole harvest (and with it the vendor run) forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_zip_artifact_never_wedges_harvest() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:pypi/lib@1.0.0";
        let rel = format!(".socket/vendor/pypi/{UUID}/lib-1.0.0-py3-none-any.whl");
        let fifo = tmp.path().join(&rel);
        std::fs::create_dir_all(fifo.parent().unwrap()).unwrap();
        mkfifo(&fifo);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "lib/__init__.py", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harvest_artifact_blobs(tmp.path(), &patches),
        )
        .await;
        if res.is_err() {
            unblock_fifo_reader(&fifo);
        }
        let map = res.expect("harvest must not hang on a FIFO artifact");
        assert!(map.is_empty(), "a FIFO artifact contributes nothing");
    }

    /// Same wedge through the dir-shaped branch: a FIFO at a record-relative
    /// file inside a directory artifact must be skipped, not read.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_inside_dir_artifact_never_wedges_harvest() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{UUID}/serde-1.0.0");
        let file_dir = tmp.path().join(&rel).join("src");
        std::fs::create_dir_all(&file_dir).unwrap();
        let fifo = file_dir.join("lib.rs");
        mkfifo(&fifo);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "src/lib.rs", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harvest_artifact_blobs(tmp.path(), &patches),
        )
        .await;
        if res.is_err() {
            unblock_fifo_reader(&fifo);
        }
        let map = res.expect("harvest must not hang on a FIFO inside a dir artifact");
        assert!(map.is_empty(), "a FIFO file contributes nothing");
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

    fn write_zip(path: &Path, entry_name: &str, content: &[u8]) {
        use std::io::Write as _;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                entry_name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(content).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        std::fs::write(path, &bytes).unwrap();
    }

    /// Like [`write_zip`], but afterwards forges the entry's DECLARED
    /// uncompressed size (in both the local file header at offset 22 and the
    /// central-directory header's field at +24) down to a small value. The
    /// deflate stream is untouched, so it still decompresses to `content` —
    /// this is the zip-bomb shape: a tiny declared size hiding a large
    /// payload.
    fn write_forged_undersized_zip(path: &Path, entry_name: &str, content: &[u8]) {
        write_zip(path, entry_name, content);
        let mut bytes = std::fs::read(path).unwrap();
        let forged: u32 = 10;
        assert_eq!(&bytes[0..4], b"PK\x03\x04", "local file header");
        bytes[22..26].copy_from_slice(&forged.to_le_bytes());
        let cd = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory header");
        bytes[cd + 24..cd + 28].copy_from_slice(&forged.to_le_bytes());
        std::fs::write(path, &bytes).unwrap();
    }

    #[tokio::test]
    async fn honest_zip_artifact_yields_its_after_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:pypi/lib@1.0.0";
        let rel = format!(".socket/vendor/pypi/{UUID}/lib-1.0.0-py3-none-any.whl");
        write_zip(&tmp.path().join(&rel), "lib/__init__.py", PATCHED);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "lib/__init__.py", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "an in-bounds zip entry must still yield its afterHash blob"
        );
    }

    // ── The name-seeking harvest against an exhaustive-scan oracle ──────
    // `harvest_zip_blobs` returns the same blobs whichever path produced
    // them, which is what makes it safe and also what makes a scenario test
    // blind to the path: every test below still passes with the name lookup
    // deleted. The oracle pins the RESULT against an exhaustive scan, and
    // `fallback_scans_of` pins the PATH.

    /// Reference oracle: a whole-archive scan over the hashes a record
    /// needs, reading every entry.
    fn exhaustive_scan(path: &Path, needed: &HashSet<&str>) -> HashMap<String, Vec<u8>> {
        use std::io::Read as _;

        let mut out: HashMap<String, Vec<u8>> = HashMap::new();
        let Ok(bytes) = std::fs::read(path) else {
            return out;
        };
        let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
            return out;
        };
        for i in 0..archive.len() {
            let Ok(mut file) = archive.by_index(i) else {
                continue;
            };
            if file.is_dir() || file.size() > MAX_FILE_BYTES {
                continue;
            }
            let mut content = Vec::with_capacity(file.size() as usize);
            if file
                .by_ref()
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut content)
                .is_err()
            {
                continue;
            }
            if content.len() as u64 > MAX_FILE_BYTES {
                continue;
            }
            let h = compute_git_sha256_from_bytes(&content);
            if needed.contains(h.as_str()) {
                out.insert(h, content);
            }
        }
        out
    }

    /// A zip holding `entries` in order, member names verbatim.
    fn write_zip_members(path: &Path, entries: &[(&str, &[u8])]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in entries {
            writer.start_file(*name, opts).unwrap();
            writer.write_all(content).unwrap();
        }
        std::fs::write(path, writer.finish().unwrap().into_inner()).unwrap();
    }

    /// A zip carrying the SAME member name twice: written under two
    /// distinct names, then renamed in place (all three names are five
    /// bytes, so every header offset is preserved).
    fn write_duplicate_name_zip(path: &Path, name: &str, first: &[u8], second: &[u8]) {
        write_zip_members(path, &[("x1.py", first), ("x2.py", second)]);
        let mut bytes = std::fs::read(path).unwrap();
        for old in [b"x1.py".as_slice(), b"x2.py".as_slice()] {
            while let Some(at) = bytes.windows(5).position(|w| w == old) {
                bytes[at..at + 5].copy_from_slice(name.as_bytes());
            }
        }
        std::fs::write(path, bytes).unwrap();
    }

    fn wanted_pairs(keys: &[(&str, &[u8])]) -> Vec<(String, String)> {
        keys.iter()
            .map(|(k, c)| (k.to_string(), compute_git_sha256_from_bytes(c)))
            .collect()
    }

    /// Whatever the archive's member names turn out to be, the harvest must
    /// return exactly the blob SET the exhaustive scan returns — that is
    /// the equivalence the by-name seek rests on, and the shapes below are
    /// the ways a name can disagree with a record key.
    #[test]
    fn name_seeking_harvest_matches_the_exhaustive_scan() {
        const A: &[u8] = b"alpha\n";
        const B: &[u8] = b"beta\n";
        const C: &[u8] = b"gamma\n";

        // The zip's members, and the record keys naming the bytes the
        // record claims live behind them.
        type Members<'a> = Vec<(&'a str, &'a [u8])>;
        let cases: Vec<(&str, Members, Members)> = vec![
            (
                "exact-names",
                vec![("a.py", A), ("b.py", B)],
                vec![("a.py", A), ("b.py", B)],
            ),
            ("renamed", vec![("renamed.py", A)], vec![("a.py", A)]),
            (
                "package-prefix",
                vec![("index.js", A)],
                vec![("package/index.js", A)],
            ),
            (
                "reverse-prefix",
                vec![("package/index.js", A)],
                vec![("index.js", A)],
            ),
            // Each key names the other's bytes.
            (
                "swapped",
                vec![("a.py", B), ("b.py", A)],
                vec![("a.py", A), ("b.py", B)],
            ),
            // A key naming a directory-shaped member, beside the real file.
            (
                "dir-entry",
                vec![("d/", b""), ("d/a.py", A)],
                vec![("d", A), ("d/a.py", A)],
            ),
            (
                "same-hash-twice",
                vec![("a.py", A), ("b.py", A)],
                vec![("a.py", A), ("b.py", A)],
            ),
            (
                "absent-member",
                vec![("a.py", A)],
                vec![("a.py", A), ("ghost.py", C)],
            ),
            // A windows-packed archive spells its separators the other way.
            (
                "backslashes",
                vec![("lib\\mod.py", A)],
                vec![("lib/mod.py", A)],
            ),
            (
                "case-skew",
                vec![("Lib/Mod.py", A)],
                vec![("lib/mod.py", A)],
            ),
            (
                "mixed",
                vec![("a.py", A), ("renamed", B), ("c.py", C)],
                vec![("a.py", A), ("b.py", B), ("c.py", C)],
            ),
        ];

        for (label, members, keys) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let zip_path = tmp.path().join("artifact.zip");
            write_zip_members(&zip_path, &members);

            let wanted = wanted_pairs(&keys);
            let needed: HashSet<&str> = wanted.iter().map(|(_, h)| h.as_str()).collect();
            let got = harvest_zip_blobs(&zip_path, &wanted);
            let want = exhaustive_scan(&zip_path, &needed);

            let mut got_keys: Vec<&String> = got.keys().collect();
            let mut want_keys: Vec<&String> = want.keys().collect();
            got_keys.sort();
            want_keys.sort();
            assert_eq!(
                got_keys, want_keys,
                "[{label}] the name-seeking harvest returned a different blob set \
                 than the scan it replaced"
            );
            for k in got_keys {
                assert_eq!(
                    got[k], want[k],
                    "[{label}] blob {k} differs from the scan's"
                );
            }
        }
    }

    /// A zip may carry one member name twice (`by_name` resolves exactly one
    /// of them), and the blob the record wants may be in either. Both ways
    /// round, the harvest must still agree with the scan.
    #[test]
    fn duplicate_member_names_match_the_exhaustive_scan() {
        const A: &[u8] = b"alpha\n";
        const B: &[u8] = b"beta\n";
        for (label, want) in [("wanted-is-first", A), ("wanted-is-second", B)] {
            let tmp = tempfile::tempdir().unwrap();
            let zip_path = tmp.path().join("dup.zip");
            write_duplicate_name_zip(&zip_path, "xx.py", A, B);

            let wanted = wanted_pairs(&[("xx.py", want)]);
            let needed: HashSet<&str> = wanted.iter().map(|(_, h)| h.as_str()).collect();
            let got = harvest_zip_blobs(&zip_path, &wanted);
            let scan = exhaustive_scan(&zip_path, &needed);
            assert_eq!(
                got, scan,
                "[{label}] a duplicate member name must not change what is harvested"
            );
        }
    }

    /// The point of the item: a record whose keys name the archive's members
    /// costs no whole-archive scan, and one whose keys do not still gets its
    /// blob from the scan. This is the only test that can see the
    /// difference — the assertions above pass either way.
    #[test]
    fn the_scan_runs_only_for_what_the_names_do_not_settle() {
        const A: &[u8] = b"alpha\n";
        const B: &[u8] = b"beta\n";
        let tmp = tempfile::tempdir().unwrap();

        let named = tmp.path().join("named.zip");
        write_zip_members(&named, &[("a.py", A), ("index.js", B)]);
        // The bare member under a `package/`-prefixed key: the second
        // spelling the name lookup tries.
        let wanted = wanted_pairs(&[("a.py", A), ("package/index.js", B)]);
        let (got, scans) = fallback_scans_of(|| harvest_zip_blobs(&named, &wanted));
        assert_eq!(got.len(), 2, "both blobs must come back");
        assert_eq!(
            scans, 0,
            "keys that name their members must not fall back to the archive scan"
        );

        let renamed = tmp.path().join("renamed.zip");
        write_zip_members(&renamed, &[("renamed.py", A)]);
        let wanted = wanted_pairs(&[("a.py", A)]);
        let (got, scans) = fallback_scans_of(|| harvest_zip_blobs(&renamed, &wanted));
        assert_eq!(got.len(), 1, "the renamed member's blob must come back");
        assert_eq!(scans, 1, "a name the archive does not carry needs the scan");
    }

    /// The record's key names the member the blob normally lives in, so the
    /// harvest looks it up by name — but the archive is free to spell it
    /// differently (a wheel repacked under a renamed member, a `.nupkg`
    /// whose OPC path was rewritten). The blob is keyed by HASH, not by
    /// name, so a name miss must fall back to the exhaustive scan and still
    /// find it.
    #[tokio::test]
    async fn renamed_zip_member_still_yields_its_after_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:pypi/lib@1.0.0";
        let rel = format!(".socket/vendor/pypi/{UUID}/lib-1.0.0-py3-none-any.whl");
        // Member name ≠ the record key below.
        write_zip(&tmp.path().join(&rel), "lib/renamed.py", PATCHED);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "lib/__init__.py", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "a member the record's key does not name must still be harvested"
        );
    }

    /// A manifest key may carry the npm `package/` prefix while the archive
    /// spells the member without it — the same two spellings the member-map
    /// verify accepts. Both must yield the blob; that the second spelling is
    /// what settled it (rather than the fallback scan) is pinned by
    /// [`the_scan_runs_only_for_what_the_names_do_not_settle`].
    #[tokio::test]
    async fn package_prefixed_key_matches_the_bare_zip_member() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/lib@1.0.0";
        let rel = format!(".socket/vendor/npm/{UUID}/lib-1.0.0.zip");
        write_zip(&tmp.path().join(&rel), "index.js", PATCHED);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "the normalized key must resolve the bare member"
        );
    }

    /// Two record files, one whose key names its member and one whose does
    /// not: BOTH blobs must land, which is the whole-archive scan's result.
    /// (Which path produced each one is pinned by
    /// [`the_scan_runs_only_for_what_the_names_do_not_settle`].)
    #[tokio::test]
    async fn mixed_named_and_renamed_members_yield_every_after_blob() {
        const OTHER: &[u8] = b"module.exports = also_patched;\n";
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:nuget/Lib@1.0.0";
        let rel = format!(".socket/vendor/nuget/{UUID}/lib.1.0.0.nupkg");
        let path = tmp.path().join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("lib/net8.0/Lib.dll", opts).unwrap();
        writer.write_all(PATCHED).unwrap();
        writer.start_file("lib/net8.0/Renamed.xml", opts).unwrap();
        writer.write_all(OTHER).unwrap();
        std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, mut r) = record(purl, UUID, "lib/net8.0/Lib.dll", PATCHED);
        r.files.insert(
            "lib/net8.0/Lib.xml".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"original"),
                after_hash: compute_git_sha256_from_bytes(OTHER),
            },
        );
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        assert_eq!(
            mem.get(&compute_git_sha256_from_bytes(PATCHED))
                .map(|b| b.as_slice()),
            Some(PATCHED),
            "the named member must be harvested"
        );
        assert_eq!(
            mem.get(&compute_git_sha256_from_bytes(OTHER))
                .map(|b| b.as_slice()),
            Some(OTHER),
            "the renamed member must be harvested by the fallback scan"
        );
    }

    /// A zip entry whose header DECLARES a tiny uncompressed size but whose
    /// stream decompresses past the per-file cap (a zip bomb) must contribute
    /// nothing. The metadata gate trusts `file.size()` (the declared value),
    /// but the entry reader is bounded only by the COMPRESSED size, so the
    /// decompressed read itself must enforce the cap — otherwise the bomb is
    /// inflated fully into memory before any cap or CRC check, OOM-killing the
    /// harvest.
    #[tokio::test]
    async fn oversized_zip_entry_declaring_small_size_contributes_nothing() {
        // Mirror of the private per-file cap in `harvest_artifact_blobs`.
        const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:pypi/lib@1.0.0";
        let rel = format!(".socket/vendor/pypi/{UUID}/lib-1.0.0-py3-none-any.whl");
        // Decompresses to just past the cap; a run of one byte compresses to a
        // few KiB, so the artifact itself stays well under the artifact cap.
        let content = vec![0x41u8; MAX_FILE_BYTES + 4096];
        write_forged_undersized_zip(&tmp.path().join(&rel), "lib/__init__.py", &content);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "lib/__init__.py", &content);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        assert!(
            mem.is_empty(),
            "a zip entry decompressing past the per-file cap must be dropped, \
             not harvested — the declared size must not gate an unbounded read"
        );
    }

    /// Like [`write_ledger`], but with full control over each entry's map
    /// key, `basePurl`, uuid, and artifact path — for the multi-entry and
    /// qualified-purl shapes the single-entry helper can't express.
    fn write_ledger_entries(root: &Path, entries: &[(&str, &str, &str, &str)]) {
        let vendor_dir = root.join(".socket/vendor");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        let mut map = serde_json::Map::new();
        for (key, base_purl, uuid, artifact_path) in entries {
            map.insert(
                key.to_string(),
                serde_json::json!({
                    "ecosystem": "npm",
                    "basePurl": base_purl,
                    "uuid": uuid,
                    "artifact": { "path": artifact_path },
                    "wiring": [],
                }),
            );
        }
        let state = serde_json::json!({ "version": 1, "entries": map });
        std::fs::write(
            vendor_dir.join("state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
    }

    /// Like [`write_zip`], but with a directory entry plus multiple file
    /// entries — the shape a real wheel/jar/nupkg has.
    fn write_zip_with_entries(path: &Path, dir_entry: &str, entries: &[(&str, &[u8])]) {
        use std::io::Write as _;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let opts = || {
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
        };
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer.add_directory(dir_entry, opts()).unwrap();
        for (name, content) in entries {
            writer.start_file(*name, opts()).unwrap();
            writer.write_all(content).unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        std::fs::write(path, &bytes).unwrap();
    }

    /// Every zip-shaped suffix (`.whl`/`.zip`/`.jar`/`.nupkg` — pypi, maven,
    /// nuget) harvests its afterHash blob, skipping directory entries and
    /// entries whose content no record needs.
    #[tokio::test]
    async fn zip_shaped_suffixes_harvest_and_skip_dir_and_unneeded_entries() {
        for (suffix, eco, purl) in [
            (".whl", "pypi", "pkg:pypi/lib@1.0.0"),
            (".zip", "pypi", "pkg:pypi/lib@1.0.0"),
            (".jar", "maven", "pkg:maven/g/a@1.0"),
            (".nupkg", "nuget", "pkg:nuget/lib@1.0.0"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let rel = format!(".socket/vendor/{eco}/{UUID}/artifact{suffix}");
            write_zip_with_entries(
                &tmp.path().join(&rel),
                "lib/",
                &[
                    ("lib/__init__.py", PATCHED),
                    ("lib/other.py", b"unrelated content\n"),
                ],
            );
            write_ledger(tmp.path(), purl, UUID, &rel);

            let (k, r) = record(purl, UUID, "lib/__init__.py", PATCHED);
            let patches = HashMap::from([(k, r)]);
            let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
            let hash = compute_git_sha256_from_bytes(PATCHED);
            assert_eq!(
                mem.len(),
                1,
                "{suffix}: only the needed afterHash blob is kept, got {:?}",
                mem.keys().collect::<Vec<_>>()
            );
            assert_eq!(
                mem.get(&hash).map(|b| b.as_slice()),
                Some(PATCHED),
                "{suffix} artifact must yield its afterHash blob"
            );
        }
    }

    /// Garbage bytes at a zip-shaped artifact path (a regular file, so it
    /// passes the metadata gate) must be refused by the zip parser and
    /// contribute nothing — fail-soft, no error.
    #[tokio::test]
    async fn corrupt_zip_shaped_artifact_contributes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:pypi/lib@1.0.0";
        let rel = format!(".socket/vendor/pypi/{UUID}/lib-1.0.0-py3-none-any.whl");
        let path = tmp.path().join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a zip archive").unwrap();
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, r) = record(purl, UUID, "lib/__init__.py", PATCHED);
        let patches = HashMap::from([(k, r)]);
        assert!(
            harvest_artifact_blobs(tmp.path(), &patches)
                .await
                .is_empty(),
            "a corrupt zip-shaped artifact contributes nothing"
        );
    }

    /// A manifest record keyed by a QUALIFIED purl still finds its ledger
    /// entry through the base-purl fallback (the harvest twin of the
    /// find_packages_for_rollback resolver invariant).
    #[tokio::test]
    async fn qualified_record_purl_falls_back_to_ledger_base_purl() {
        let tmp = tempfile::tempdir().unwrap();
        let base = "pkg:npm/left-pad@1.3.0";
        let qualified = "pkg:npm/left-pad@1.3.0?checksum=sha256:aa";
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        write_tgz(&tmp.path().join(&rel), "package/index.js", PATCHED);
        // Ledger keyed (and basePurl'd) by the BASE spelling only.
        write_ledger(tmp.path(), base, UUID, &rel);

        let (k, r) = record(qualified, UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "a qualified record purl must resolve via the ledger's base purl"
        );
    }

    /// A record whose purl matches NO ledger entry (neither the map key nor
    /// any base purl) is skipped fail-soft.
    #[tokio::test]
    async fn record_purl_absent_from_ledger_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let other = "pkg:npm/other@2.0.0";
        let rel = format!(".socket/vendor/npm/{UUID}/other-2.0.0.tgz");
        write_tgz(&tmp.path().join(&rel), "package/index.js", PATCHED);
        write_ledger(tmp.path(), other, UUID, &rel);

        let (k, r) = record("pkg:npm/left-pad@1.3.0", UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        assert!(
            harvest_artifact_blobs(tmp.path(), &patches)
                .await
                .is_empty(),
            "an un-vendored record must not harvest another package's artifact"
        );
    }

    /// The documented "unreadable ledger contributes nothing" contract: a
    /// corrupt state.json degrades the whole harvest to empty even when a
    /// matching artifact is sitting right there.
    #[tokio::test]
    async fn corrupt_ledger_degrades_harvest_to_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/left-pad@1.3.0";
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        write_tgz(&tmp.path().join(&rel), "package/index.js", PATCHED);
        std::fs::write(tmp.path().join(".socket/vendor/state.json"), b"{not json").unwrap();

        let (k, r) = record(purl, UUID, "package/index.js", PATCHED);
        let patches = HashMap::from([(k, r)]);
        assert!(
            harvest_artifact_blobs(tmp.path(), &patches)
                .await
                .is_empty(),
            "an unreadable ledger contributes nothing"
        );
    }

    /// A record needing nothing (its only file is a deletion — empty
    /// afterHash) never consults the ledger or reads the artifact.
    #[tokio::test]
    async fn record_with_only_empty_after_hashes_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/left-pad@1.3.0";
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        write_tgz(&tmp.path().join(&rel), "package/index.js", PATCHED);
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, mut r) = record(purl, UUID, "package/index.js", PATCHED);
        r.files.get_mut("package/index.js").unwrap().after_hash = String::new();
        let patches = HashMap::from([(k, r)]);
        assert!(
            harvest_artifact_blobs(tmp.path(), &patches)
                .await
                .is_empty(),
            "a deletion-only record needs no blobs, even with a readable artifact"
        );
    }

    /// Two records sharing one afterHash harvest the blob exactly once —
    /// whichever record iterates second finds nothing left to need.
    #[tokio::test]
    async fn after_hash_shared_across_records_is_harvested_once() {
        let tmp = tempfile::tempdir().unwrap();
        let purl_a = "pkg:npm/left-pad@1.3.0";
        let purl_b = "pkg:npm/right-pad@2.0.0";
        let uuid_b = "22222222-3333-4444-8555-666666666666";
        let rel_a = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        let rel_b = format!(".socket/vendor/npm/{uuid_b}/right-pad-2.0.0.tgz");
        write_tgz(&tmp.path().join(&rel_a), "package/index.js", PATCHED);
        write_tgz(&tmp.path().join(&rel_b), "package/index.js", PATCHED);
        write_ledger_entries(
            tmp.path(),
            &[
                (purl_a, purl_a, UUID, &rel_a),
                (purl_b, purl_b, uuid_b, &rel_b),
            ],
        );

        let (ka, ra) = record(purl_a, UUID, "package/index.js", PATCHED);
        let (kb, rb) = record(purl_b, uuid_b, "package/index.js", PATCHED);
        let patches = HashMap::from([(ka, ra), (kb, rb)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.len(),
            1,
            "a shared afterHash is harvested once, got {:?}",
            mem.keys().collect::<Vec<_>>()
        );
        assert_eq!(mem.get(&hash).map(|b| b.as_slice()), Some(PATCHED));
    }

    /// Dir-shaped branch: an unsafe record file key must be skipped, never
    /// joined onto the artifact dir for reading. Matching content is planted
    /// at the exact location the key WOULD resolve to, proving the empty
    /// harvest is the guard and not a read miss.
    #[tokio::test]
    async fn unsafe_record_file_key_is_skipped_in_dir_harvest() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{UUID}/serde-1.0.0");
        std::fs::create_dir_all(tmp.path().join(&rel)).unwrap();
        write_ledger(tmp.path(), purl, UUID, &rel);
        // <artifact>/../../outside.rs resolves here:
        std::fs::write(tmp.path().join(".socket/vendor/cargo/outside.rs"), PATCHED).unwrap();

        let (k, r) = record(purl, UUID, "../../outside.rs", PATCHED);
        let patches = HashMap::from([(k, r)]);
        assert!(
            harvest_artifact_blobs(tmp.path(), &patches)
                .await
                .is_empty(),
            "an escaping record key must never be resolved against the artifact dir"
        );
    }

    /// Dir-shaped branch skip matrix in one record: a deletion (empty
    /// afterHash) is never read, a tampered file (content matching neither
    /// hash) contributes nothing — per the doc contract — and the intact
    /// file still harvests.
    #[tokio::test]
    async fn dir_artifact_skips_empty_hash_and_tampered_files() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{UUID}/serde-1.0.0");
        let src = tmp.path().join(&rel).join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), PATCHED).unwrap();
        std::fs::write(src.join("tampered.rs"), b"tampered bytes").unwrap();
        write_ledger(tmp.path(), purl, UUID, &rel);

        let (k, mut r) = record(purl, UUID, "src/lib.rs", PATCHED);
        r.files.insert(
            "src/deleted.rs".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"original"),
                after_hash: String::new(),
            },
        );
        r.files.insert(
            "src/tampered.rs".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"original"),
                after_hash: compute_git_sha256_from_bytes(b"expected patched content"),
            },
        );
        let patches = HashMap::from([(k, r)]);
        let mem = harvest_artifact_blobs(tmp.path(), &patches).await;
        let hash = compute_git_sha256_from_bytes(PATCHED);
        assert_eq!(
            mem.len(),
            1,
            "only the intact file harvests, got {:?}",
            mem.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            mem.get(&hash).map(|b| b.as_slice()),
            Some(PATCHED),
            "the tampered and deleted files must contribute nothing"
        );
    }

    /// Every spelling `vendored_purl_keys` covers: the entry's map key
    /// (possibly qualified), its resolved base purl, and the
    /// qualifier-stripped key — one `PurlKey`.
    #[tokio::test]
    async fn vendored_purl_keys_lists_all_addressable_spellings() {
        let tmp = tempfile::tempdir().unwrap();
        let qualified = "pkg:npm/left-pad@1.3.0?checksum=sha256:aa";
        let base = "pkg:npm/left-pad@1.3.0";
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
        write_ledger_entries(tmp.path(), &[(qualified, base, UUID, &rel)]);

        let keys = vendored_purl_keys(tmp.path()).await;
        assert!(
            purl_keys_cover(&keys, qualified),
            "map key spelling: {keys:?}"
        );
        assert!(
            purl_keys_cover(&keys, base),
            "base purl / stripped spelling: {keys:?}"
        );
        assert_eq!(keys.len(), 1, "every spelling shares one key: {keys:?}");
    }

    /// The documented fail-open degrade: no ledger yields the empty set, and
    /// so does a corrupt one (apply/rollback/scan-prune then treat nothing
    /// as vendor-owned).
    #[tokio::test]
    async fn vendored_purl_keys_degrade_to_empty_on_missing_or_corrupt_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            vendored_purl_keys(tmp.path()).await.is_empty(),
            "no ledger at all: empty set"
        );
        let vendor_dir = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        std::fs::write(vendor_dir.join("state.json"), b"{not json").unwrap();
        assert!(
            vendored_purl_keys(tmp.path()).await.is_empty(),
            "a corrupt ledger degrades fail-open to the empty set"
        );
    }
}

#[cfg(test)]
mod berry_migration_risk_tests {
    use super::*;

    const WIRED_V1: &str = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
        # yarn lockfile v1\n\n\n\
        left-pad@1.3.0:\n  version \"1.3.0\"\n  \
        resolved \"file:./.socket/vendor/npm/11111111-2222-4333-8444-555555555555/left-pad-1.3.0.tgz#abc\"\n  \
        integrity sha512-x==\n";
    const UNWIRED_V1: &str = "# yarn lockfile v1\n\n\n\
        left-pad@1.3.0:\n  version \"1.3.0\"\n  \
        resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc\"\n";

    fn project(lock: Option<&str>, package_json: Option<&str>) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        if let Some(l) = lock {
            std::fs::write(tmp.path().join("yarn.lock"), l).unwrap();
        }
        if let Some(p) = package_json {
            std::fs::write(tmp.path().join("package.json"), p).unwrap();
        }
        tmp
    }

    #[test]
    fn wired_classic_without_pin_warns() {
        let tmp = project(Some(WIRED_V1), Some(r#"{"name":"x"}"#));
        let w = yarn_classic_berry_migration_risk(tmp.path()).expect("must warn");
        assert_eq!(w.code, "yarn_classic_berry_migration_risk");
        assert!(
            w.detail.contains("yarn 2+"),
            "detail names the trap: {}",
            w.detail
        );
    }

    #[test]
    fn yarn1_package_manager_pin_suppresses() {
        let tmp = project(
            Some(WIRED_V1),
            Some(r#"{"name":"x","packageManager":"yarn@1.22.22"}"#),
        );
        assert!(yarn_classic_berry_migration_risk(tmp.path()).is_none());
    }

    #[test]
    fn non_classic_pins_still_warn() {
        // A berry pin does not make a classic lockfile safe — and `yarn@10`
        // must not string-match the `yarn@1` prefix.
        for pm in ["yarn@4.2.0", "yarn@10.0.0", "pnpm@9.0.0"] {
            let pkg = format!(r#"{{"name":"x","packageManager":"{pm}"}}"#);
            let tmp = project(Some(WIRED_V1), Some(&pkg));
            assert!(
                yarn_classic_berry_migration_risk(tmp.path()).is_some(),
                "{pm} must not suppress the warning"
            );
        }
    }

    #[test]
    fn unwired_or_non_classic_locks_stay_silent() {
        // Registry-only classic lock: no vendored wiring at risk.
        let tmp = project(Some(UNWIRED_V1), Some(r#"{"name":"x"}"#));
        assert!(yarn_classic_berry_migration_risk(tmp.path()).is_none());
        // Berry-format lock (no v1 marker) even with a vendor-ish string.
        let berry = "__metadata:\n  version: 8\n\n\"a@npm:1.0.0\":\n  resolution: \"a@npm:1.0.0\"\n# .socket/vendor/ mention\n";
        let tmp = project(Some(berry), Some(r#"{"name":"x"}"#));
        assert!(yarn_classic_berry_migration_risk(tmp.path()).is_none());
        // No lockfile at all.
        let tmp = project(None, Some(r#"{"name":"x"}"#));
        assert!(yarn_classic_berry_migration_risk(tmp.path()).is_none());
    }

    /// Run the sync probe on another thread with a timeout: a FIFO planted
    /// at either probed path would wedge an unguarded `read_to_string` in
    /// `open(2)` forever — and the probe runs unconditionally at
    /// envelope-finalize time on EVERY vendor / scan --mode vendored run.
    #[cfg(unix)]
    fn probe_with_timeout(root: &Path, fifo: &Path) -> Option<VendorWarning> {
        let root = root.to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(yarn_classic_berry_migration_risk(&root));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(res) => res,
            Err(_) => {
                super::harvest_tests::unblock_fifo_reader(fifo);
                panic!("probe must not wedge on a FIFO at {}", fifo.display());
            }
        }
    }

    /// A FIFO planted at `yarn.lock` must be skipped, not read: the probe
    /// stays silent (unreadable lockfile = nothing to vouch for) instead of
    /// wedging every vendor run at finalize.
    #[cfg(unix)]
    #[test]
    fn fifo_yarn_lock_never_wedges_probe() {
        let tmp = project(None, Some(r#"{"name":"x"}"#));
        let fifo = tmp.path().join("yarn.lock");
        super::harvest_tests::mkfifo(&fifo);
        assert!(probe_with_timeout(tmp.path(), &fifo).is_none());
    }

    /// A FIFO planted at `package.json` must not wedge the probe either —
    /// and, like a malformed package.json, an unreadable pin cannot vouch
    /// for the project, so the wired-classic warning still fires.
    #[cfg(unix)]
    #[test]
    fn fifo_package_json_never_wedges_probe() {
        let tmp = project(Some(WIRED_V1), None);
        let fifo = tmp.path().join("package.json");
        super::harvest_tests::mkfifo(&fifo);
        assert!(probe_with_timeout(tmp.path(), &fifo).is_some());
    }

    #[test]
    fn malformed_or_missing_package_json_still_warns() {
        // Fail toward warning: an unreadable pin must not silently vouch
        // for the project.
        let tmp = project(Some(WIRED_V1), Some("{not json"));
        assert!(yarn_classic_berry_migration_risk(tmp.path()).is_some());
        let tmp = project(Some(WIRED_V1), None);
        assert!(yarn_classic_berry_migration_risk(tmp.path()).is_some());
    }
}

#[cfg(test)]
mod pnpm_takeover_lock_text_refusal_tests {
    use super::pnpm_takeover_lock_text_refusals;

    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    const UUID: &str = "11111111-2222-4333-8444-555555555555";
    /// A hosted pin: the entry's tarball is the patch server's.
    const HOSTED_V9: &str = "lockfileVersion: '9.0'\n\n\
        importers:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\n\
        packages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x==, tarball: https://patch.socket.dev/patch/npm/left-pad/1.3.0/a/11111111-2222-4333-8444-555555555555/left-pad-1.3.0.tgz}\n\n\
        snapshots:\n\n  left-pad@1.3.0: {}\n";

    fn project(lock_name: &str, lock: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"c","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
        )
        .unwrap();
        std::fs::write(tmp.path().join(lock_name), lock).unwrap();
        tmp
    }

    #[tokio::test]
    async fn crlf_hosted_pnpm_lock_is_refused() {
        let tmp = project("pnpm-lock.yaml", &HOSTED_V9.replace('\n', "\r\n"));
        let refused = pnpm_takeover_lock_text_refusals(tmp.path(), &[(PURL, UUID)]).await;
        assert_eq!(
            refused.get(PURL).map(|(code, _)| *code),
            Some("vendor_lockfile_crlf_unsupported"),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn plain_hosted_pnpm_pin_is_not_refused() {
        let tmp = project("pnpm-lock.yaml", HOSTED_V9);
        let refused = pnpm_takeover_lock_text_refusals(tmp.path(), &[(PURL, UUID)]).await;
        assert!(refused.is_empty(), "{refused:?}");
    }

    /// Only pnpm is predicted: a CRLF yarn classic lock over the same purl
    /// yields nothing here (its restore rewrites the text the gates read).
    #[tokio::test]
    async fn yarn_classic_project_is_out_of_scope() {
        let lock = "# yarn lockfile v1\r\n\r\n\r\nleft-pad@1.3.0:\r\n  version \"1.3.0\"\r\n  \
            resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc\"\r\n";
        let tmp = project("yarn.lock", lock);
        let refused = pnpm_takeover_lock_text_refusals(tmp.path(), &[(PURL, UUID)]).await;
        assert!(refused.is_empty(), "{refused:?}");
    }

    /// A known preview gap (CLI_CONTRACT, #853): a legacy pnpm 7/8 lock
    /// (5.4 / 6.0) is not lock-text gated, so even a CRLF one the wet
    /// takeover refuses (`vendor_lockfile_crlf_unsupported`) previews
    /// `would_vendor`. The wet run's refusal keeps the hosted pin (#963).
    #[tokio::test]
    async fn legacy_pnpm_project_is_out_of_scope() {
        let lock = "lockfileVersion: '6.0'\r\n\r\ndependencies:\r\n  left-pad:\r\n    \
            specifier: 1.3.0\r\n    version: 1.3.0\r\n\r\npackages:\r\n\r\n  \
            /left-pad@1.3.0:\r\n    resolution: {integrity: sha512-x==, tarball: \
            https://patch.socket.dev/patch/npm/left-pad/1.3.0/a/{UUID}/left-pad-1.3.0.tgz}\r\n";
        let tmp = project("pnpm-lock.yaml", &lock.replace("{UUID}", UUID));
        let refused = pnpm_takeover_lock_text_refusals(tmp.path(), &[(PURL, UUID)]).await;
        assert!(refused.is_empty(), "{refused:?}");
    }
}
