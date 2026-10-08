//! Gem (Bundler) vendor backend: the Gemfile + Gemfile.lock pair edit.
//!
//! Empirically verified mechanism (bundler 2.5):
//! BOTH files must be edited. A lock-only edit is a silent unpatch on the next
//! plain `bundle install` (bundler re-resolves from the Gemfile and rewrites
//! the lock back to a registry GEM source; frozen/CI mode errors with exit 16
//! but dev machines do not). The pair edit is the form bundler itself
//! regenerates BYTE-IDENTICALLY, so the committed lock stays churn-free:
//!
//! ```text
//! PATH
//!   remote: .socket/vendor/gem/<uuid>/<name>-<version>
//!   specs:
//!     <name> (<version>)
//!       <dep> (<constraint>)    # the spec block's dependency sublines move over verbatim
//! ```
//!
//! * the PATH section sits BEFORE the GEM section; `remote:` is the RELATIVE
//!   path — no leading `./`, no trailing slash;
//! * the gem's spec block (its 4-space line plus 6-space dependency sublines)
//!   MOVES from GEM/specs into the PATH specs;
//! * the GEM section is retained with the block removed; when its specs run
//!   empty the empty `specs:` stanza is KEPT (that is what bundler writes);
//! * the DEPENDENCIES entry becomes `<name> (= <version>)!` — exact pin plus
//!   the `!` path-source marker; PLATFORMS / BUNDLED WITH / everything else is
//!   byte-preserved;
//! * bundler ≥ 2.6 with `lockfile_checksums` adds a CHECKSUMS section whose
//!   registry entries read `  <name> (<version>) sha256=<hex>`; a path-sourced
//!   gem keeps a BARE `  <name> (<version>)` entry (verified on bundler
//!   2.7.2). The registry token
//!   MUST be stripped on vendor — bundler never repairs it itself (a stale
//!   token is silently preserved, i.e. permanent lock-vs-regen churn) — and
//!   restored verbatim on revert: a bare entry on a registry-sourced gem
//!   hard-fails `BUNDLE_FROZEN=true bundle install` (exit 16).
//!
//! The Gemfile gains `path:` on the gem's declaration (rewritten in place when
//! it is a statically-parseable single top-level line, quote style and
//! trailing options like `require: false` preserved) or, for a transitive
//! dependency, a managed block appended at EOF. Anything
//! the conservative line grammar cannot prove safe to rewrite is REFUSED —
//! never guessed at. The one exception is OUR OWN previous wiring: a patch
//! update moves the manifest to a new uuid (same purl), and a `path:` that
//! parses as the socket vendor dir for exactly this gem is repointed in
//! place (the older patch uuid is re-vendored automatically, like the
//! npm/cargo/golang backends — no revert-first).
//!
//! The stub gemspec from `<gem_home>/specifications/` is copied into the
//! vendored dir as `<name>.gemspec` (a path source needs one; the spike showed
//! the stub works warning-free). Gems whose gemspec declares native
//! extensions are refused: bundler silently skips extension builds for path
//! sources and the missing `.so` only fails at `require` time with a
//! confusing error — refusing up front is the honest failure.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::constants::SOCKET_DIR;
use crate::formats::gem::gemfile;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::patch::path_safety::is_safe_single_segment;
use crate::patch::redirect::gem_line_tail_blocks_edit;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::purl::{build_gem_purl, parse_gem_purl, purl_qualifier};
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::{
    already_patched_result, copy_matches_after_hashes, done, failed_result, inventory_or_warn,
    prune_empty_vendor_levels, refused, service_offline_conflict, stage_dir_for,
    swap_stage_into_place, synthesized_result,
};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::registry_fetch::{extract_gem_data, extract_on_blocking_pool};
use super::service_fetch::{
    claim_prestaged, fetch_verified_archive, fetch_verified_secondary, SecondaryArtifactResult,
    ServiceAttempt, ServicePolicy, ServiceTerminal,
};
use super::source::PackageSource;
use super::state::{
    write_marker_or_warn, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};
use crate::formats::gem::{is_plain_gem_token, split_checksum_entry, split_entry};

const GEMFILE: &str = "Gemfile";
const GEMFILE_LOCK: &str = "Gemfile.lock";

/// Wiring-record discriminators (`key` is the gem name for all three).
///
/// `gemfile_line`: `original`/`new` are verbatim line/block strings.
///
/// `gemfile_lock_spec`: `original` and `new` are arrays of verbatim lock
/// lines. In `original`, lines indented 4+ spaces are the gem's GEM spec
/// block and the single 2-space line (if any) other than a `  remote: ` line
/// is the pre-vendor DEPENDENCIES entry — its absence means the gem was
/// transitive and revert deletes the added entry. A `  remote: ` line names
/// the GEM section the block came from; it is recorded only when that is not
/// the lock's first GEM section (#779), and revert restores into it. In
/// `new`, the last element is the DEPENDENCIES entry we wrote and the rest
/// is the emitted PATH section.
///
/// `gemfile_lock_checksum`: `original`/`new` are the verbatim CHECKSUMS line
/// strings (the registry `  <name> (<version>) sha256=<hex>` form vs the bare
/// `  <name> (<version>)` path form). A SEPARATE record — never appended into
/// `gemfile_lock_spec`'s arrays, whose revert parses them positionally.
const GEMFILE_WIRING_KIND: &str = "gemfile_line";
const LOCK_WIRING_KIND: &str = "gemfile_lock_spec";
const LOCK_CHECKSUM_WIRING_KIND: &str = "gemfile_lock_checksum";

/// Managed-block fence for transitive (not-Gemfile-declared) gems.
const MANAGED_OPEN: &str = "# >>> socket-patch vendor (managed) >>>";
const MANAGED_CLOSE: &str = "# <<< socket-patch vendor (managed) <<<";

/// Everything [`vendor_gem`] decides before it can first ask the patch
/// service, up to its dry-run branch: the coordinate guards, the no-op of an
/// empty patch, the platform refusals, the Gemfile and Gemfile.lock reads,
/// the local stub gemspec and its native-extension refusal, and the hot
/// path's tests (with the stale-CHECKSUMS refusal). With [`gem_edits`] it is
/// every refusal a wet run raises before its first service call, so the
/// download plan evaluates the same functions ahead of the vendor loop
/// ([`service_preflight`]). `installed_path` is the source's
/// [`PackageSource::path`] — only its name and parents are read.
struct GemPrelude {
    name: String,
    version: String,
    copy_rel: String,
    uuid_dir: PathBuf,
    copy_dir: PathBuf,
    gemfile_path: PathBuf,
    gemfile_text: String,
    lock_path: PathBuf,
    lock_text: String,
    local_stub: Option<(PathBuf, String)>,
    /// Gemfile and Gemfile.lock already wire this uuid's copy.
    lock_wired: bool,
    /// ...and the committed copy is intact (the in-sync hot path, which
    /// never asks the service).
    copy_ok: bool,
}

/// Why vendored mode must not wire this project's Gemfile, if it must not:
/// bundler loads a different manifest. This backend edits the `Gemfile` +
/// `Gemfile.lock` pair, so a project where bundler loads `gems.rb` (it wins
/// over a Gemfile twin) or a `BUNDLE_GEMFILE`-configured manifest is refused
/// before any write: wiring the ignored Gemfile would report success while
/// bundler installs the upstream gem. The CLI's hosted→vendored takeover
/// asks this BEFORE it reverts a live hosted pin, so a refused gem keeps
/// its hosted wiring instead of ending up unpatched in both modes.
pub async fn gem_manifest_refusal(project_root: &Path) -> Option<(&'static str, String)> {
    use crate::formats::gem::manifest::LoadedManifest;
    let loaded = crate::crawlers::ruby_crawler::bundler_loaded_manifest(project_root).await;
    let gems_rb_present = tokio::fs::symlink_metadata(project_root.join("gems.rb"))
        .await
        .is_ok();
    match loaded.pair(gems_rb_present) {
        Some((GEMFILE, GEMFILE_LOCK)) => None,
        // A `gems.rb` twin is refused whatever bundler runs: bundler >= 2
        // loads `gems.rb` (with a "Multiple gemfiles" warning) while 1.x
        // still reads the Gemfile first, so wiring the Gemfile is only
        // right on a bundler this backend cannot see.
        Some((manifest, lock)) if matches!(loaded, LoadedManifest::Default) => Some((
            "gemfile_not_loaded",
            format!(
                "a {manifest} sits beside the Gemfile and bundler >= 2 loads {manifest} + \
                 {lock} instead of the Gemfile + Gemfile.lock pair vendored mode wires (a \
                 gems.rb project cannot vendor yet); use hosted mode, or remove gems.rb / \
                 gems.locked if the Gemfile is the real manifest"
            ),
        )),
        Some((manifest, lock)) => Some((
            "gemfile_not_loaded",
            format!(
                "BUNDLE_GEMFILE makes bundler load {manifest} + {lock}, not the Gemfile + \
                 Gemfile.lock pair vendored mode wires (a gems.rb project cannot vendor yet); \
                 use hosted mode"
            ),
        )),
        None => Some((
            "gemfile_not_loaded",
            loaded.unsupported_detail().unwrap_or_default(),
        )),
    }
}

/// The per-gem twin of [`gem_manifest_refusal`] for the hosted→vendored
/// takeover: the backend's Gemfile declaration gate ([`plan_gemfile_edit`]
/// and [`refuse_append_of_direct_dependency`], refused as
/// `gemfile_declaration_not_editable`) for `purl`. Evaluated on the files
/// as the takeover's restore of `pin` will leave them: a dry-run
/// [`restore_upstream`] supplies the restored `Gemfile` / `Gemfile.lock`
/// text, so the hosted `source … do` block socket-patch itself wrote is
/// never mistaken for the user's declaration. A gem declared inside a
/// `group` block is the common case: hosted mode wires it, vendored mode
/// cannot, and without this gate the takeover un-hosts it first (#775).
/// Returns `(code, detail)`, exactly the refusal the backend would raise
/// after the restore; `None` when it would not refuse, when the restore
/// itself would refuse (the takeover reports that), or when the files are
/// unreadable (which the backend reports itself).
///
/// [`restore_upstream`]: crate::patch::redirect::upstream::restore_upstream
pub async fn gem_vendor_target_preflight(
    project_root: &Path,
    purl: &str,
    pin: &crate::patch::redirect::upstream::HostedPin,
    opts: &crate::patch::redirect::upstream::RestoreOptions,
) -> Option<(&'static str, String)> {
    use crate::patch::redirect::upstream::{restore_upstream, RestoreOptions};
    let (name, version) = parse_gem_purl(purl)?;
    // The copy path only shapes a plan that passes; any refusal is decided
    // by the declaration alone, so an unsafe uuid is left to the backend.
    let copy_rel = format!(
        "{}/{name}-{version}",
        vendor_uuid_dir_rel("gem", &pin.uuid)?
    );
    let dry = RestoreOptions {
        dry_run: true,
        ..opts.clone()
    };
    let restore = restore_upstream(project_root, std::slice::from_ref(pin), &dry).await;
    if restore.refused().next().is_some() {
        return None;
    }
    let restored = |file: &str| restore.staged_text.get(file).cloned();
    let gemfile_text = match restored(GEMFILE) {
        Some(text) => text?,
        None => read_regular_to_string(&project_root.join(GEMFILE))
            .await
            .ok()?,
    };
    let lock_text = match restored(GEMFILE_LOCK) {
        Some(text) => text?,
        None => read_regular_to_string(&project_root.join(GEMFILE_LOCK))
            .await
            .ok()?,
    };
    plan_gemfile_edit(&gemfile_text, &name, &version, &copy_rel)
        .and_then(|plan| refuse_append_of_direct_dependency(plan, &lock_text, &name))
        .err()
        .map(|detail| ("gemfile_declaration_not_editable", detail))
}

async fn gem_prelude(
    purl: &str,
    installed_path: &Path,
    project_root: &Path,
    record: &PatchRecord,
) -> Result<GemPrelude, VendorOutcome> {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some((name, version)) = parse_gem_purl(purl) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("not a gem purl: {purl}"),
        ));
    };
    let (name, version) = (name.to_string(), version.to_string());
    let (name, version) = (name.as_str(), version.as_str());
    // SECURITY: `uuid`, `name` and `version` come from committed, tamper-able
    // manifest data. They key the copy dir vendor creates and `--revert`
    // deletes, and — stricter than the path guard — they are embedded
    // VERBATIM into the user's Gemfile (ruby source executed on every
    // `bundle`) and into Gemfile.lock's line grammar. A quote, space, paren,
    // or newline would be a code/grammar injection, so only the plain gem
    // token charset is accepted. Reject fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("gem", &record.uuid) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        ));
    };
    if !is_safe_single_segment(name)
        || !is_safe_single_segment(version)
        || !is_plain_gem_token(name)
        || !is_plain_gem_token(version)
    {
        return Err(refused(
            "unsafe_coordinates",
            format!("unsafe gem coordinates `{name}` @ `{version}`"),
        ));
    }

    let leaf = format!("{name}-{version}");
    let copy_rel = format!("{uuid_dir_rel}/{leaf}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let copy_dir = project_root.join(&copy_rel);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if record.files.is_empty() {
        return Err(done(
            synthesized_result(purl, &copy_dir, Vec::new(), true, None),
            None,
            Vec::new(),
        ));
    }

    // Platform-specific (precompiled) gem builds ship machine-specific
    // artifacts — committing one would break every other platform — so they
    // are refused, not guessed at. Two independent signals decide this:
    //
    //   1. The purl's own `?platform=` qualifier (the AUTHORITATIVE production
    //      key). RubyGems' default portable platform is `ruby`; a bare purl
    //      (no qualifier) is likewise the portable build. Only a *native*
    //      platform value (`x86_64-linux`, `arm64-darwin`, `java`,
    //      `x64-mingw32`, …) is refused.
    //   2. Defense in depth: the resolved install dir's own name. A
    //      locally-installed native variant is `<name>-<version>-<platform>`
    //      even when the manifest purl looked portable (the crawler strips the
    //      suffix to the base purl, so a `?platform=ruby` lookup can still land
    //      on a native install dir).
    //
    // Gating on the platform (not only the staging dir name) lets
    // `?platform=ruby` and bare purls vendor whatever the staging dir is
    // called, while still refusing true native builds by either signal.
    if let Some(platform) = purl_qualifier(purl, "platform") {
        if !platform.is_empty() && !platform.eq_ignore_ascii_case("ruby") {
            return Err(refused(
                "platform_gem_unsupported",
                format!(
                    "`{name}@{version}` is a platform-specific gem build (`platform={platform}`); precompiled platform gems cannot be vendored portably"
                ),
            ));
        }
    }
    let dir_name = installed_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Fail closed: only two dir names are legitimate here — the gem's own
    // `<name>-<version>` leaf (installed, or staged by
    // a server download), and a literal `gem` staging dir, still
    // admitted for compatibility though fetch_gem no longer produces it.
    // Everything else is refused, including a `<name>-<version>-<platform>`
    // precompiled build; an allowlist (not a suffix match) means an unexpected
    // install dir name can never slip through into a vendored copy.
    if installed_path.is_dir() && dir_name != leaf && dir_name != "gem" {
        return Err(refused(
            "platform_gem_unsupported",
            format!(
                "installed dir `{dir_name}` is not the portable `{leaf}` gem (platform-specific or unexpected gem builds cannot be vendored portably)"
            ),
        ));
    }

    // ── project files ────────────────────────────────────────────────────
    if let Some((code, detail)) = gem_manifest_refusal(project_root).await {
        return Err(refused(code, detail));
    }
    let gemfile_path = project_root.join(GEMFILE);
    let gemfile_text = match read_regular_to_string(&gemfile_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refused(
                "gemfile_missing",
                format!("no Gemfile at {}", gemfile_path.display()),
            ));
        }
        Err(e) => {
            return Err(refused(
                "gemfile_missing",
                format!("unreadable Gemfile: {e}"),
            ));
        }
    };
    let lock_path = project_root.join(GEMFILE_LOCK);
    let lock_text = match read_regular_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refused(
                "vendor_lockfile_missing",
                format!(
                    "no Gemfile.lock at {} (the pair edit needs the lock)",
                    lock_path.display()
                ),
            ));
        }
        Err(e) => {
            return Err(refused(
                "vendor_lockfile_missing",
                format!("unreadable Gemfile.lock: {e}"),
            ));
        }
    };

    let local_stub: Option<(PathBuf, String)> = {
        let spec_src = installed_path
            .parent()
            .filter(|gems| gems.file_name().is_some_and(|n| n == "gems"))
            .and_then(Path::parent)
            .map(|home| home.join("specifications").join(format!("{leaf}.gemspec")));
        match spec_src {
            Some(p) => read_regular_to_string(&p).await.ok().map(|t| (p, t)),
            None => None,
        }
    };
    // Textual heuristic, deliberately fail-closed on a match: bundler skips
    // extension builds for path sources entirely, so a native gem would
    // install fine and then fail at `require` time with a missing `.so`.
    // Only the local stub is checked here (when present); the service stub is
    // re-checked in `gem_service_copy`, and a native gem emits no service stub
    // at all (the converter refuses it), so the service path also misses.
    if let Some((_, text)) = &local_stub {
        if gemspec_declares_extensions(text) {
            return Err(refused(
                "native_extensions_unsupported",
                format!(
                    "{leaf}.gemspec declares native extensions; bundler does not build extensions for path-sourced gems"
                ),
            ));
        }
    }

    // The idempotent hot path's tests (see `vendor_gem`): the pair edit
    // already wires this uuid's copy; the lock's CHECKSUMS entry is in the
    // bare path form (a stale registry line is refused, dry run or not); and
    // the committed copy — gemspec included — is intact.
    let remote_line = format!("  remote: {copy_rel}");
    let lock_wired =
        lock_text.split('\n').any(|l| l == remote_line) && gemfile_text.contains(&copy_rel);
    let mut copy_ok = false;
    if lock_wired {
        if lock_checksum_in_sync(&lock_text, name, version) {
            // Probe the copy only once the lock is known to be wired (the
            // common fresh vendor has no copy to hash). Invalid-stub heal: a
            // project vendored before the stub check carries a defective
            // SERVED stub on disk, so EXISTS is not enough — an
            // on-disk stub that fails the required-attribute bar routes into
            // the artifact rebuild (which re-materialises a valid stub)
            // instead of the silent `already_vendored` no-op. The stub read
            // runs second so a hash mismatch short-circuits it.
            copy_ok = copy_matches_after_hashes(&copy_dir, &record.files).await
                && match read_regular_to_string(&copy_dir.join(format!("{name}.gemspec"))).await {
                    Ok(text) => gemspec_missing_required_attrs(&text).is_empty(),
                    Err(_) => false,
                };
        } else {
            // Wired everywhere EXCEPT the lock's CHECKSUMS entry, which still
            // carries the registry form — a lock wired by a pre-CHECKSUMS-aware
            // socket-patch. Bundler never repairs this itself (spike G4: install,
            // frozen install and `bundle lock` all silently preserve a stale
            // token), and we cannot strip it here: this run records no ledger
            // entry, so a revert would put back everything EXCEPT the token —
            // leaving a bare CHECKSUMS entry on a registry-sourced gem, which
            // hard-fails frozen installs (exit 16). Refuse with the repair path
            // instead of the generic "already carries `path:`" Gemfile refusal.
            return Err(refused(
                "vendor_stale_lock_checksum",
                format!(
                    "Gemfile.lock already wires `{name}` to {copy_rel} but its CHECKSUMS entry is not bundler's bare path-gem form (an earlier socket-patch left the registry line in place); {remedy} to repair {purl}",
                    remedy = super::common::REVERT_ALL_AND_REVENDOR,
                ),
            ));
        }
    }
    Ok(GemPrelude {
        name: name.to_string(),
        version: version.to_string(),
        copy_rel,
        uuid_dir,
        copy_dir,
        gemfile_path,
        gemfile_text,
        lock_path,
        lock_text,
        local_stub,
        lock_wired,
        copy_ok,
    })
}

/// A fresh wet vendor's pure edits, computed before any download or write:
/// the Gemfile declaration plan (refused when not editable) and the
/// Gemfile.lock surgery (a failed `Done` when the lock's shape defeats it).
fn gem_edits(
    purl: &str,
    prelude: &GemPrelude,
) -> Result<(GemfilePlan, LockEdit), Box<VendorOutcome>> {
    let (name, version) = (prelude.name.as_str(), prelude.version.as_str());
    // ── Gemfile edit plan (refusals before any write) ────────────────────
    let plan = match plan_gemfile_edit(&prelude.gemfile_text, name, version, &prelude.copy_rel)
        .and_then(|plan| refuse_append_of_direct_dependency(plan, &prelude.lock_text, name))
    {
        Ok(p) => p,
        Err(detail) => {
            return Err(Box::new(refused(
                "gemfile_declaration_not_editable",
                detail,
            )))
        }
    };
    // ── Gemfile.lock edit (pure text surgery, computed before any write) ──
    // A lock-shape failure therefore costs no download / copy / patch and no
    // Gemfile write.
    let lock_edit = match edit_lock(&prelude.lock_text, name, version, &prelude.copy_rel) {
        Ok(edit) => edit,
        Err(e) => {
            return Err(Box::new(done(
                failed_result(
                    purl,
                    &prelude.copy_dir,
                    format!("failed to edit Gemfile.lock: {e}"),
                ),
                None,
                Vec::new(),
            )));
        }
    };
    Ok((plan, lock_edit))
}

/// Whether [`vendor_gem`] — a wet run with the service enabled — asks the
/// patch service for `record`: past every refusal it raises first
/// ([`gem_prelude`], [`gem_edits`]) and not answered by the in-sync hot
/// path. The vendor loop's download plan consults this; the `.gem`'s
/// `gem-stub-gemspec` secondary rides the same planned download.
pub(crate) async fn service_preflight(
    purl: &str,
    installed_path: &Path,
    project_root: &Path,
    record: &PatchRecord,
) -> Option<crate::api::client::PlannedDownload> {
    let prelude = gem_prelude(purl, installed_path, project_root, record)
        .await
        .ok()?;
    let asks = match prelude.lock_wired {
        true => !prelude.copy_ok,
        false => gem_edits(purl, &prelude).is_ok(),
    };
    // `gem_service_copy` fetches the stub gemspec right after the `.gem`,
    // and extracts the `.gem`'s data.tar.gz into the copy dir's stage.
    asks.then(|| crate::api::client::PlannedDownload {
        secondary: Some(GEM_STUB_ARTIFACT_KIND.to_string()),
        stage: Some(super::prestage::PrestageRecipe::extract(
            project_root,
            &prelude.copy_dir,
            extract_gem_data,
        )),
        ..crate::api::client::PlannedDownload::archive(record.uuid.clone())
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn vendor_gem<'a>(
    purl: &str,
    installed_dir: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    let installed_dir = installed_dir.into();
    let prelude = match gem_prelude(purl, installed_dir.path(), project_root, record).await {
        Ok(prelude) => prelude,
        Err(outcome) => return outcome,
    };
    let GemPrelude {
        name,
        version,
        copy_rel,
        uuid_dir,
        copy_dir,
        gemfile_path,
        gemfile_text,
        lock_path,
        lock_text: _,
        local_stub,
        lock_wired,
        copy_ok,
    } = &prelude;
    let (name, version) = (name.as_str(), version.as_str());
    let (copy_rel, uuid_dir, copy_dir) =
        (copy_rel.as_str(), uuid_dir.as_path(), copy_dir.as_path());
    let (lock_wired, copy_ok) = (*lock_wired, *copy_ok);

    // ── idempotent hot path ──────────────────────────────────────────────
    // Copy (incl. the gemspec) already carries every afterHash and both files
    // already reference the uuid path → touch nothing. `entry` stays `None`:
    // the first run's ledger entry holds the only copy of the pre-vendor
    // originals.
    if lock_wired {
        if copy_ok {
            return done(
                already_patched_result(purl, copy_dir, &record.files),
                None,
                Vec::new(),
            );
        }
        // Wired (Gemfile + lock + CHECKSUMS) but the committed copy is
        // missing/stale: rebuild the ARTIFACT only — the pair edit is
        // already correct and the full path would re-record the live
        // vendored fragments as `original`, breaking a later --revert.
        // Service-preferred like the full path (an auto-fetched gem has no
        // local stub to rebuild from — only the service can). The rebuild
        // is staged: a failure must leave the previous (drifted-but-
        // buildable) copy and the live pair edit exactly as they were,
        // never a deleted uuid dir under a still-pointing `path:`.
        if !dry_run {
            if let Some(refusal) = service_offline_conflict(service) {
                return refusal;
            }
            let mut warnings: Vec<VendorWarning> = Vec::new();
            let result = match materialise_patched_copy(
                purl,
                installed_dir,
                copy_dir,
                uuid_dir,
                name,
                version,
                local_stub.as_ref().map(|(p, t)| (p.as_path(), t.as_str())),
                record,
                sources,
                force,
                false, // live-wired: never unwind the uuid dir on failure
                service,
                &mut warnings,
            )
            .await
            {
                Ok(result) => result,
                Err(outcome) => return *outcome,
            };
            if !result.success {
                return done(result, None, warnings);
            }
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored copy for {name}@{version} was missing or \
                     stale; rebuilt at {copy_rel} (Gemfile and Gemfile.lock untouched)"
                ),
            ));
            // The rebuilt tree may differ from the one the ledger
            // inventoried (a service ↔ local flip swaps the stub gemspec):
            // hand back a refreshed entry. Its wiring is empty ON PURPOSE —
            // the caller's `carry_forward_wiring` (same uuid) re-attaches the
            // first run's records, the only copy of the pre-vendor originals.
            let file_inventory =
                inventory_or_warn(copy_dir, &format!("{name}@{version}"), &mut warnings).await;
            let entry = gem_entry(
                build_gem_purl(name, version),
                record,
                copy_rel.to_string(),
                file_inventory,
                Vec::new(),
            );
            return done(result, Some(entry), warnings);
        }
        // Dry runs fall through to the verify-only preview below.
    }

    if dry_run {
        if let Err(outcome) =
            super::service_fetch::preview_service(service, record, extract_gem_data).await
        {
            return *outcome;
        }
        return done(
            super::common::preview_result(purl, copy_dir, &record.files),
            None,
            Vec::new(),
        );
    }

    // ── Gemfile + Gemfile.lock edits (pure, computed before any write) ────
    let (plan, lock_edit) = match gem_edits(purl, &prelude) {
        Ok(edits) => edits,
        Err(outcome) => return *outcome,
    };

    // ── materialise the patched copy ──────────────────────────────────────
    // Prefer the prebuilt `.gem` + stub gemspec from the patch service
    // (download + extract; no local install or patch-apply needed); else copy
    // the installed gem, drop in the local stub gemspec, and apply the patch.
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some(refusal) = service_offline_conflict(service) {
        return refusal;
    }
    let mut result = match materialise_patched_copy(
        purl,
        installed_dir,
        copy_dir,
        uuid_dir,
        name,
        version,
        local_stub.as_ref().map(|(p, t)| (p.as_path(), t.as_str())),
        record,
        sources,
        force,
        true, // fresh vendor: nothing pre-existing worth keeping
        service,
        &mut warnings,
    )
    .await
    {
        Ok(result) => result,
        Err(outcome) => return *outcome,
    };
    if !result.success {
        // The copy / stub / patch step left the result un-successful (and
        // cleaned up its own partial copy); neither project file was touched.
        return done(result, None, warnings);
    }
    result.package_path = copy_dir.display().to_string();

    // ── Gemfile edit ─────────────────────────────────────────────────────
    // Both project files are user-owned: preserve their permission bits.
    let new_gemfile = apply_gemfile_plan(gemfile_text, &plan);
    if let Err(e) = atomic_write_bytes_preserving_mode(gemfile_path, new_gemfile.as_bytes()).await {
        let _ = remove_tree(uuid_dir).await;
        prune_empty_vendor_levels(uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write Gemfile: {e}"));
        return done(result, None, warnings);
    }

    // ── Gemfile.lock write (a failure here unwinds the Gemfile) ──────────
    if let Err(e) = atomic_write_bytes_preserving_mode(lock_path, lock_edit.text.as_bytes()).await {
        let mut detail = format!("failed to write Gemfile.lock: {e}");
        // Unwind: a Gemfile pointing at a path the lock doesn't agree with
        // is exactly the half-wired state the pair edit exists to prevent —
        // restore the recorded original bytes.
        if let Err(e) =
            atomic_write_bytes_preserving_mode(gemfile_path, gemfile_text.as_bytes()).await
        {
            detail.push_str(&format!(" (Gemfile unwind also failed: {e})"));
        }
        let _ = remove_tree(uuid_dir).await;
        prune_empty_vendor_levels(uuid_dir).await;
        result.success = false;
        result.error = Some(detail);
        return done(result, None, warnings);
    }

    // ── marker + ledger entry ────────────────────────────────────────────
    let base_purl = build_gem_purl(name, version);
    let marker = VendorMarker::new("gem", &base_purl, record, vendored_at);
    write_marker_or_warn(uuid_dir, &marker, &mut warnings).await;

    let gemfile_record = match &plan {
        GemfilePlan::Rewrite {
            original_line,
            new_line,
        } => WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(name.to_string()),
            original: Some(Value::String(original_line.clone())),
            new: Some(Value::String(new_line.clone())),
        },
        GemfilePlan::Append { block } => WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Added,
            key: Some(name.to_string()),
            original: None,
            new: Some(Value::String(block.clone())),
        },
        // Re-vendor over our own wiring (see `GemfilePlan::RewireOurs`):
        // `original: None`, carried forward by the caller. The managed-fence
        // form stays `Added` with the whole updated block so revert deletes
        // the fence too.
        GemfilePlan::RewireOurs {
            new_line,
            managed_block,
            ..
        } => match managed_block {
            Some(block) => WiringRecord {
                file: GEMFILE.to_string(),
                kind: GEMFILE_WIRING_KIND.to_string(),
                action: WiringAction::Added,
                key: Some(name.to_string()),
                original: None,
                new: Some(Value::String(block.clone())),
            },
            None => WiringRecord {
                file: GEMFILE.to_string(),
                kind: GEMFILE_WIRING_KIND.to_string(),
                action: WiringAction::Rewritten,
                key: Some(name.to_string()),
                original: None,
                new: Some(Value::String(new_line.clone())),
            },
        },
    };
    // A rewire lifted OUR OWN previous PATH section, not pre-vendor
    // fragments: record `original: None` — the true originals live in the
    // ledger entry being replaced, which the caller carries forward by
    // wiring identity (`persist_vendor_entry`).
    let (original_lines, new_lines) = lock_record_lines(&lock_edit);
    let to_array =
        |lines: Vec<String>| Value::Array(lines.into_iter().map(Value::String).collect());
    let lock_record = WiringRecord {
        file: GEMFILE_LOCK.to_string(),
        kind: LOCK_WIRING_KIND.to_string(),
        action: WiringAction::Rewritten,
        key: Some(name.to_string()),
        original: (!lock_edit.rewired_ours).then(|| to_array(original_lines)),
        new: Some(to_array(new_lines)),
    };
    let mut wiring = vec![gemfile_record, lock_record];
    // The CHECKSUMS rewrite (when the lock had a registry entry for the gem)
    // rides in its OWN record: revert must restore the registry `sha256=`
    // line verbatim — it is not recomputable offline, and a bare entry on a
    // registry-sourced gem hard-fails frozen installs (spike, exit 16).
    if let Some((orig_line, new_line)) = &lock_edit.checksum_rewrite {
        wiring.push(WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: LOCK_CHECKSUM_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(name.to_string()),
            original: Some(Value::String(orig_line.clone())),
            new: Some(Value::String(new_line.clone())),
        });
    } else if lock_edit.rewired_ours {
        // Re-vendor with the bare path-form line already in place (our
        // previous run stripped the registry token): the record must ride
        // again with `original: None` — dropped, the first run's registry
        // `sha256=` line would vanish from the ledger with the entry being
        // replaced, and a later --revert could no longer restore it (a bare
        // leftover on a registry gem hard-fails frozen installs, exit 16).
        if let Some(bare) = &lock_edit.checksum_bare {
            wiring.push(WiringRecord {
                file: GEMFILE_LOCK.to_string(),
                kind: LOCK_CHECKSUM_WIRING_KIND.to_string(),
                action: WiringAction::Rewritten,
                key: Some(name.to_string()),
                original: None,
                new: Some(Value::String(bare.clone())),
            });
        }
    }

    // The whole tree, stub gemspec included: no lockfile integrity covers a
    // path source's bytes.
    let file_inventory =
        inventory_or_warn(copy_dir, &format!("{name}@{version}"), &mut warnings).await;
    let entry = gem_entry(
        base_purl,
        record,
        copy_rel.to_string(),
        file_inventory,
        wiring,
    );

    done(result, Some(entry), warnings)
}

/// The ledger entry for a vendored gem copy: `wiring` is the Gemfile + lock
/// records on a full vendor, empty on an artifact-only rebuild (see the hot
/// path).
fn gem_entry(
    base_purl: String,
    record: &PatchRecord,
    copy_rel: String,
    file_inventory: Option<std::collections::BTreeMap<String, String>>,
    wiring: Vec<WiringRecord>,
) -> VendorEntry {
    VendorEntry {
        ecosystem: "gem".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            yarn_berry10c0: None,
            path: copy_rel,
            sha256: String::new(), // dir-shaped: whole-tree integrity is the inventory
            size: None,
            platform_locked: None,
            file_inventory,
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    }
}

/// Failure cleanup for a staged (re)build: always remove the stage, then
/// either unwind the whole `<uuid>/` dir (`unwind_uuid_dir` — a fresh vendor
/// with no pre-existing state worth keeping) or leave existing state
/// untouched — a live-wired rebuild must never delete the copy the Gemfile
/// `path:` and the lock's PATH `remote:` still point at; either way prune any
/// empty-husk dirs left behind.
async fn cleanup_failed_stage(stage: &Path, uuid_dir: &Path, unwind_uuid_dir: bool) {
    let _ = remove_tree(stage).await;
    if unwind_uuid_dir {
        let _ = remove_tree(uuid_dir).await;
    }
    prune_empty_vendor_levels(uuid_dir).await;
}

/// The path-source stub gemspec served as the gem's SECOND artifact, alongside
/// the `.gem` (mirrors npm's `yarn-berry-zip`). The converter generates it
/// because a `.gem` only carries the gemspec as YAML in `metadata.gz`, not the
/// eval-able Ruby form a bundler path source loads.
pub(crate) const GEM_STUB_ARTIFACT_KIND: &str = "gem-stub-gemspec";

/// Outcome of attempting to materialise the gem copy from the patch service.
pub(super) enum GemServiceCopy {
    /// The prebuilt `.gem` was extracted into `copy_dir` and the verified stub
    /// gemspec written as `<name>.gemspec`.
    Used,
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
}

/// Download the prebuilt `.gem` + its `gem-stub-gemspec` secondary artifact,
/// integrity-verify both, extract the `.gem`'s `data.tar.gz` into `copy_dir`,
/// and write the stub as `<name>.gemspec`. The extracted `.gem` IS the patched
/// package the converter built, so it needs no local install — the point of
/// the service path. Maps each service outcome onto the `auto` / `service`
/// fallback policy.
///
/// A MISSING stub artifact is a terminal miss (fall back under `auto`, refuse
/// under `service`): it means either a native-extension gem (the converter
/// emits no stub — bundler can't build extensions for a path source) or a gem
/// patch built before the stub rollout (the invalidation migration rebuilds
/// those). The downloaded stub is re-checked for native extensions as defense
/// in depth, and an INVALID stub — one missing the rubygems-required
/// `summary`/`authors` assignments — follows
/// the same miss policy under its own `vendor_prebuilt_stub_invalid` code
/// (always loud, even under `auto`).
pub(super) async fn gem_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    copy_dir: &Path,
    uuid_dir: &Path,
    unwind_uuid_dir: bool,
    warnings: &mut Vec<VendorWarning>,
) -> GemServiceCopy {
    let Some(cfg) = service else {
        return GemServiceCopy::HardFail(Box::new(super::service_fetch::required()));
    };
    if !cfg.service_enabled() {
        return GemServiceCopy::HardFail(Box::new(super::service_fetch::required()));
    }
    fn hard(code: &'static str, detail: String) -> GemServiceCopy {
        GemServiceCopy::HardFail(Box::new(refused(code, detail)))
    }
    // One policy for every service miss: explicit `service` refuses (the
    // `refusal` tuple names the terminal code and an optional remedy sentence
    // for its detail), `auto` warns under `code` and falls back to the local
    // build. `is_stub_defect` marks the misses where the service DID serve a
    // stub that failed validation — the reason then rides the `FallBack`
    // payload (see [`GemServiceCopy::FallBack`]).
    let miss = |_warnings: &mut Vec<VendorWarning>,
                _code: &'static str,
                refusal: (&'static str, &str),
                reason: String,
                _is_stub_defect: bool| {
        let (code, remedy) = refusal;
        hard(
            code,
            if remedy.is_empty() {
                reason
            } else {
                format!("{reason}. {remedy}")
            },
        )
    };

    // Step 1: the prebuilt `.gem` (sha512-verified against the reference).
    let fetched = fetch_verified_archive(cfg, &record.uuid).await;
    let subject = format!(".gem for {name}");
    let policy = ServicePolicy::new(cfg, ServiceTerminal::Refused);
    let mut archive = match policy.settle::<()>(fetched, ".gem", &subject, warnings) {
        Ok(archive) => archive,
        Err(ServiceAttempt::HardFail(outcome)) => return GemServiceCopy::HardFail(outcome),
        Err(ServiceAttempt::Used(())) => {
            return GemServiceCopy::HardFail(Box::new(super::service_fetch::required()));
        }
    };

    // Step 2: the stub gemspec the converter generated alongside the `.gem`.
    let stub = match fetch_verified_secondary(cfg, &archive, GEM_STUB_ARTIFACT_KIND).await {
        SecondaryArtifactResult::Ready(bytes) => bytes,
        SecondaryArtifactResult::Absent => {
            return miss(
                warnings,
                "vendor_prebuilt_stub_missing",
                ("vendor_prebuilt_required", ""),
                "the patch service served no stub gemspec for this gem (a native-extension \
                 gem, or a patch built before the stub rollout)"
                    .to_string(),
                false,
            );
        }
        SecondaryArtifactResult::IntegrityMismatch(reason) => {
            return hard(
                "vendor_prebuilt_integrity_mismatch",
                format!(
                    "prebuilt stub gemspec for {name} failed integrity verification ({reason}); \
                     refusing to fall back to a local build on tampered bytes"
                ),
            );
        }
        SecondaryArtifactResult::Failed(reason) => {
            return miss(
                warnings,
                "vendor_prebuilt_unavailable",
                ("vendor_prebuilt_required", ""),
                format!("could not fetch the stub gemspec ({reason})"),
                false,
            );
        }
    };
    let stub_text = String::from_utf8_lossy(&stub);

    // Defense in depth: the converter does not emit a stub for native gems, but
    // refuse one here too — bundler silently skips extension builds for path
    // sources, so a native gem would install and then fail at `require` time.
    if gemspec_declares_extensions(&stub_text) {
        return hard(
            "native_extensions_unsupported",
            format!(
                "the served stub gemspec for {name} declares native extensions; bundler does \
                 not build extensions for path-sourced gems"
            ),
        );
    }

    // Defense in depth: a served stub may omit the rubygems-required
    // `summary`/`authors`, and every bundler major validates path-source
    // gemspecs — writing such a stub
    // verbatim makes every later `bundle install` exit 1 (`missing value for
    // attribute summary`). An INVALID stub follows the MISSING-stub policy
    // (fall back under `auto`, refuse under `service`) but under its own
    // `vendor_prebuilt_stub_invalid` code, and always loudly — the served
    // artifact is defective, not merely absent. Nothing has been written yet,
    // so the refusal leaves no partial artifacts.
    let missing_attrs = gemspec_missing_required_attrs(&stub_text);
    if !missing_attrs.is_empty() {
        let licenses_note = if gemspec_assigns_attr(&stub_text, &["licenses", "license"]) {
            ""
        } else {
            " (it also omits `licenses`, a rubygems warning)"
        };
        let reason = format!(
            "the served stub gemspec for {name} is invalid: it does not assign the \
             rubygems-required attribute(s) {}{licenses_note}; bundler validates \
             path-source gemspecs, so vendoring it would make every later \
             `bundle install` fail",
            missing_attrs.join(", "),
        );
        return miss(
            warnings,
            "vendor_prebuilt_stub_invalid",
            (
                "vendor_prebuilt_stub_invalid",
                "Retry after the patch service publishes a corrected artifact",
            ),
            reason,
            true,
        );
    }

    // Extract the patched `.gem`'s data.tar.gz into a STAGE sibling, add the
    // stub as `<name>.gemspec` (a `.gem`'s data.tar.gz never carries one —
    // the gemspec lives in metadata.gz), and swap it into the copy dir only
    // once fully verified — a failure then leaves any pre-existing (possibly
    // live-wired) copy untouched and no husk behind.
    let stage = stage_dir_for(copy_dir);
    // A tree the download plan already extracted from these bytes (see
    // `prestage`) is moved into the stage instead; otherwise — or should
    // the move fail — extract here, as always.
    if !claim_prestaged(&mut archive, &stage, copy_dir).await {
        let _ = remove_tree(&stage).await;
        if let Err(e) = tokio::fs::create_dir_all(&stage).await {
            cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
            return hard(
                "vendor_prebuilt_write_failed",
                format!("cannot create {}: {e}", stage.display()),
            );
        }
        let gem_bytes = std::mem::take(&mut archive.bytes);
        if let Err(e) = extract_on_blocking_pool(gem_bytes, &stage, extract_gem_data).await {
            cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
            return hard(
                "vendor_prebuilt_extract_failed",
                format!("cannot extract the prebuilt .gem: {e}"),
            );
        }
    }
    if let Err(e) = tokio::fs::write(stage.join(format!("{name}.gemspec")), &stub).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return hard(
            "vendor_prebuilt_write_failed",
            format!("cannot write the stub gemspec into the vendored dir: {e}"),
        );
    }
    if !copy_matches_after_hashes(&stage, &record.files).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return miss(
            warnings,
            "vendor_prebuilt_layout_mismatch",
            ("vendor_prebuilt_required", ""),
            format!(
                "prebuilt .gem for {name} extracted to an unexpected layout \
                 (patched files absent at their recorded paths)"
            ),
            false,
        );
    }
    if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return hard(
            "vendor_prebuilt_write_failed",
            format!("cannot move the extracted .gem into place: {e}"),
        );
    }
    warnings.push(VendorWarning::new(
        "vendor_prebuilt_downloaded",
        format!(
            "vendored {name} from the patch service ({})",
            archive.source_url
        ),
    ));
    GemServiceCopy::Used
}

/// Materialise the patched copy at `copy_dir` plus its `<name>.gemspec` stub,
/// service-download first (see [`gem_service_copy`]) and local copy+stub+apply
/// as the fallback. Returns the verify [`ApplyResult`] (a synthesized
/// `AlreadyPatched` on the service path), or a terminal [`VendorOutcome`] to
/// bubble. A non-fatal copy/stub/patch failure is surfaced as an UN-successful
/// `ApplyResult` (the caller returns it as a `Done` with no ledger entry).
///
/// Either build is staged (see [`swap_stage_into_place`]) and swapped into
/// `copy_dir` only on success, so a failure never destroys a pre-existing
/// copy: with `unwind_uuid_dir` (a fresh vendor — nothing pre-existing to
/// keep) the whole uuid dir is removed on failure, without it (the wired
/// hot-path rebuild, where the Gemfile `path:` and the lock's PATH `remote:`
/// still point at the copy) the previous copy, marker, and wiring are left
/// exactly as they were.
#[allow(clippy::too_many_arguments)]
async fn materialise_patched_copy(
    purl: &str,
    _installed_dir: PackageSource<'_>,
    copy_dir: &Path,
    uuid_dir: &Path,
    name: &str,
    _version: &str,
    _local_stub: Option<(&Path, &str)>,
    record: &PatchRecord,
    _sources: &PatchSources<'_>,
    _force: bool,
    unwind_uuid_dir: bool,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<ApplyResult, Box<VendorOutcome>> {
    match gem_service_copy(
        service,
        record,
        name,
        copy_dir,
        uuid_dir,
        unwind_uuid_dir,
        warnings,
    )
    .await
    {
        GemServiceCopy::Used => {
            // The service `.gem` is the patched package; trust its verified
            // integrity (every file reads as AlreadyPatched).
            Ok(already_patched_result(purl, copy_dir, &record.files))
        }
        GemServiceCopy::HardFail(outcome) => Err(outcome),
    }
}

/// Revert a gem vendor entry: restore the Gemfile line / delete the managed
/// block, splice the lock's spec block back into GEM specs (sorted), the
/// original DEPENDENCIES entry back in and the registry CHECKSUMS line back
/// over the bare path form, then remove the validated uuid dir.
/// Each fragment that no longer looks like what vendor wrote — a hand edit, a
/// `bundle update`, a newer vendor run — is left alone with a
/// `vendor_lock_entry_drifted` warning.
pub async fn revert_gem(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome {
    revert_gem_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_gem`] with full [`RevertOpts`]: `keep_artifact` skips ONLY the
/// artifact deletion; the wiring restore — and the empty-wiring refusal,
/// which applies under `keep_artifact` too — runs unchanged.
///
/// LOSSINESS GUARD (the [`RevertOutcome`] contract every backend honors): a
/// record left alone as genuine drift keeps the artifact dir (and the caller
/// keeps the ledger entry) — the Gemfile `path:` or the lock's PATH section
/// may still route through it, and the entry holds the only pre-vendor
/// originals. A record whose live state already equals its reverted state
/// is convergence, not drift, and stays silent (LIVENESS CONTRACT), so an
/// earlier partial revert or a `bundle update` regeneration never wedges
/// the entry forever.
pub async fn revert_gem_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid
    // grammar is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("gem", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let mut warnings = Vec::new();

    // Fail-closed guard: an entry with NO wiring records (one an older
    // socket-patch repair re-synthesized from the lockfiles, or a
    // hand-stripped state.json) must not "succeed" by deleting the artifact — the
    // Gemfile `path:` and the lock's PATH section would keep pointing at
    // the removed dir and the next `bundle install` hard-fails. Refuse
    // loudly with the manual cleanup steps instead. (Every entry
    // `vendor_gem` records carries at least the Gemfile + lock records.)
    // NOT skipped under `keep_artifact`: a
    // preserve-state revert that cannot restore the wiring must not report
    // the system restored while the pair edit still wires the vendored dir
    // in — the patch would silently stay applied.
    if entry.wiring.is_empty() {
        let name = parse_gem_purl(&entry.base_purl)
            .map(|(n, _)| n.into_owned())
            .unwrap_or_else(|| "<unknown>".to_string());
        return RevertOutcome::failed(format!(
            "vendor_wiring_unknown: the ledger records no wiring for `{name}` (an \
             entry without recoverable originals); refusing to delete {} and \
             strand the pair edit — manually remove the `path:` option (or the socket-patch \
             managed block) for `{name}` from the Gemfile, restore its registry entry in \
             Gemfile.lock (or delete the lock and re-run `bundle install`), then delete \
             {uuid_dir_rel} and this state.json entry",
            entry.artifact.path
        ));
    }

    // Wiring is restored in reverse application order: lock first, Gemfile
    // last (the mirror image of vendor's Gemfile-then-lock).
    for w in entry.wiring.iter().rev() {
        let restored = match w.kind.as_str() {
            LOCK_WIRING_KIND => {
                revert_lock_record(&project_root.join(GEMFILE_LOCK), w, dry_run).await
            }
            LOCK_CHECKSUM_WIRING_KIND => {
                revert_lock_checksum_record(&project_root.join(GEMFILE_LOCK), w, dry_run).await
            }
            GEMFILE_WIRING_KIND => {
                revert_gemfile_record(&project_root.join(GEMFILE), w, dry_run).await
            }
            _ => {
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
                ));
                continue;
            }
        };
        let key = w.key.as_deref().unwrap_or("<unknown>");
        match restored {
            Ok(RecordRevert::Done) => {}
            Ok(RecordRevert::Drifted) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{} no longer carries what vendor wrote for {key}; left alone",
                    w.file
                ),
            )),
            // A missing wired file cannot still route through the copy dir:
            // reported, but not drift — the artifact may still be removed.
            Ok(RecordRevert::FileMissing) => warnings.push(VendorWarning::new(
                "vendor_lockfile_missing",
                format!("{} is missing; the {key} entry cannot be restored", w.file),
            )),
            Err(e) => {
                return RevertOutcome {
                    kept_artifact: false,
                    success: false,
                    warnings,
                    error: Some(e),
                };
            }
        }
    }

    let mut outcome = RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    };
    if dry_run {
        return outcome;
    }
    // Drift-keep (see the fn doc): never delete a copy dir a left-alone
    // record may still reference.
    if outcome.drift_skipped() {
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }
    // `--preserve-state` (`keep_artifact`): the artifact dir stays behind
    // (and the caller keeps the ledger entry), so only the deletion is
    // skipped.
    if keep_artifact {
        return outcome;
    }
    // The last gem entry leaves `.socket/vendor/gem/` (and `.socket/vendor/`)
    // empty: the shared helper prunes them so a reverted project carries no
    // vendor residue (non-recursive: siblings keep them).
    if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
        outcome.success = false;
        outcome.error = Some(format!("failed to remove {}: {e}", uuid_dir.display()));
        return outcome;
    }
    outcome
}

// ── Gemfile editing ──────────────────────────────────────────────────────────

/// The planned Gemfile edit.
enum GemfilePlan {
    /// The gem is declared on a safe single top-level line: rewrite it in
    /// place (quote style preserved).
    Rewrite {
        original_line: String,
        new_line: String,
    },
    /// The declaration already carries OUR OWN `path:` wiring from an older
    /// patch uuid (a patch update changes the uuid, never the purl):
    /// repoint it at the new copy in place, everything else on the line
    /// byte-preserved. The wiring record carries `original: None` — the true
    /// pre-vendor line lives in the ledger entry being replaced and the
    /// caller carries it forward by wiring identity (`persist_vendor_entry`);
    /// recording the old-uuid line would make a later revert "restore" a
    /// dangling vendor pointer. `managed_block` is `Some(updated block)` when
    /// the line sits inside our managed fence (the transitive-gem form): the
    /// record then stays `Added` with the whole block, so revert still
    /// deletes the fence.
    RewireOurs {
        original_line: String,
        new_line: String,
        managed_block: Option<String>,
    },
    /// The gem is transitive (not declared): append a fenced managed block.
    Append { block: String },
}

/// Decide how to edit the Gemfile, or explain why it cannot be edited.
///
/// Deliberately conservative: only a single, top-level, statically-parseable
/// `gem "<name>" …` line qualifies for rewriting. Anything else — indented
/// (inside a `group`/`platforms`/conditional block), parenthesized,
/// continued onto the next line, conditional, or already carrying a
/// `path:`/`git:`/`github:` source — is refused rather than guessed at: a
/// wrong Gemfile rewrite executes on every `bundle` invocation. The one
/// `path:` exception is our own vendored dir for this gem (an older patch
/// uuid), which is repointed in place — see [`GemfilePlan::RewireOurs`].
fn plan_gemfile_edit(
    text: &str,
    name: &str,
    version: &str,
    rel: &str,
) -> Result<GemfilePlan, String> {
    let lines: Vec<&str> = text.split('\n').collect();
    // (line idx, top-level?, paren-call?, quote, rest-after-name)
    let mut found: Vec<(usize, bool, bool, char, String)> = Vec::new();
    let mut unparsed_mention = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(d) = gem_declaration(trimmed, name) {
            found.push((
                i,
                trimmed.len() == line.len(),
                d.paren,
                d.quote,
                d.rest.to_string(),
            ));
        } else if gem_call_mentions_name(trimmed, name) {
            unparsed_mention = true;
        }
    }
    if found.is_empty() {
        // Gate the append behind the looser "declared at all?" probe (the
        // redirect rewriter's `declared_re` twin): a declaration the strict
        // grammar above cannot see — `gem"{name}"` with no separator,
        // `gem ("{name}")` with a space before the paren, both valid Ruby —
        // must refuse, never Append. Appending the managed block next to the
        // unseen declaration leaves the Gemfile declaring the gem TWICE, and
        // bundler hard-fails every install on the duplicate.
        if unparsed_mention {
            return Err(format!(
                "a `gem` call names \"{name}\" in a form the line grammar cannot parse; \
                 refusing to append a second declaration (bundler hard-fails on duplicates)"
            ));
        }
        return Ok(GemfilePlan::Append {
            block: format!(
                "{MANAGED_OPEN}\ngem \"{name}\", \"{version}\", path: \"{rel}\"\n{MANAGED_CLOSE}\n"
            ),
        });
    }
    if found.len() > 1 {
        return Err(format!(
            "`gem \"{name}\"` is declared more than once in the Gemfile"
        ));
    }
    let (idx, top_level, paren, q, rest) = found.remove(0);
    if !top_level {
        return Err(format!(
            "the `gem \"{name}\"` declaration is indented (inside a group/conditional block)"
        ));
    }
    if paren {
        return Err(format!(
            "the `gem \"{name}\"` declaration uses a parenthesized call"
        ));
    }
    // Our own wiring from an older patch uuid: the `path:` value parses as
    // the socket vendor dir for exactly this gem. Repoint it in place —
    // refusing here (the source-option blocklist below) would make every
    // patch update demand a manual `vendor --revert` first. A path that
    // parses as anything else (a user fork, another gem's dir) still refuses.
    if let Some(prev_rel) = gem_line_path_value(&rest) {
        if is_our_vendor_rel(prev_rel, name, version) {
            let original_line = lines[idx].to_string();
            // The rel appears exactly once (its charset excludes quotes and
            // `#`, and the code before `path:` cannot contain a `/`-bearing
            // token); swapping just the value preserves quote style and
            // trailing options verbatim.
            let new_line = original_line.replacen(prev_rel, rel, 1);
            let managed_block = (idx > 0
                && lines[idx - 1] == MANAGED_OPEN
                && lines.get(idx + 1).is_some_and(|l| *l == MANAGED_CLOSE))
            .then(|| format!("{MANAGED_OPEN}\n{new_line}\n{MANAGED_CLOSE}\n"));
            return Ok(GemfilePlan::RewireOurs {
                original_line,
                new_line,
                managed_block,
            });
        }
    }
    if let Some(reason) = rest_blocks_edit(&rest) {
        return Err(format!(
            "the `gem \"{name}\"` declaration is not editable: {reason}"
        ));
    }
    // Trailing options (`require: false`, `group: :test`, …) must survive the
    // rewrite: dropping `require: false` auto-requires the gem at boot,
    // changing app behavior while vendored.
    // Positional arguments the tail keeps (`gem "x", *V`, `gem "x",
    // VERSION`, `ENV.fetch(…)`) are version constraints, superseded by the
    // exact pin exactly like quoted ones: carried after `path:` they are a
    // Ruby syntax error, and carried before it bundler sees `(= v, ~> 1)`
    // against the lock's `(= v)!` and refuses every frozen install (#847).
    let opts = gemfile::trailing_options(&rest);
    let tail = split_kept_tail(&opts);
    let mut new_line = format!("gem {q}{name}{q}, {q}{version}{q}, path: {q}{rel}{q}");
    if !tail.keywords.is_empty() {
        new_line.push_str(", ");
        new_line.push_str(tail.keywords);
    }
    if !tail.comment.is_empty() {
        new_line.push(' ');
        new_line.push_str(tail.comment);
    }
    Ok(GemfilePlan::Rewrite {
        original_line: lines[idx].to_string(),
        new_line,
    })
}

/// Refuse an [`GemfilePlan::Append`] for a gem the lock lists under
/// `DEPENDENCIES`: bundler resolved it as a DIRECT dependency, so the Gemfile
/// declares it somewhere the line grammar cannot see (`eval_gemfile`, a
/// loop, a gemspec). The managed block would declare it a second time and
/// bundler refuses every install (#482). Every other plan passes through.
fn refuse_append_of_direct_dependency(
    plan: GemfilePlan,
    lock_text: &str,
    name: &str,
) -> Result<GemfilePlan, String> {
    if matches!(plan, GemfilePlan::Append { .. })
        && crate::formats::gem::lock_lists_direct_dependency(lock_text, name)
    {
        return Err(format!(
            "Gemfile.lock lists \"{name}\" as a direct dependency, but the Gemfile declares \
             it somewhere the line grammar cannot edit (an `eval_gemfile`d file, a loop, a \
             gemspec); refusing to append a second declaration (bundler hard-fails on \
             duplicates)"
        ));
    }
    Ok(plan)
}

/// Looser "declared at all?" probe — the redirect rewriter's `declared_re`
/// twin. True when a non-comment line is a `gem` call (the keyword followed
/// by anything but an identifier character) whose arguments quote the exact
/// gem name, in ANY form — including ones [`gem_declaration`]'s strict
/// grammar cannot see. Gates [`plan_gemfile_edit`]'s transitive Append plan
/// fail-closed; a false positive (the name quoted elsewhere in a `gem` call's
/// arguments) costs an honest refusal, never a wrong edit.
fn gem_call_mentions_name(trimmed: &str, name: &str) -> bool {
    let Some(rest) = trimmed.strip_prefix("gem") else {
        return false;
    };
    if rest
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return false;
    }
    rest.contains(&format!("\"{name}\"")) || rest.contains(&format!("'{name}'"))
}

/// A leading Ruby string literal `"…"` / `'…'` (no escape handling):
/// `(quote, contents, the text after the closing quote)`.
pub(crate) fn quoted_literal(s: &str) -> Option<(char, &str, &str)> {
    let q = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &s[1..];
    let end = rest.find(q)?;
    Some((q, &rest[..end], &rest[end + 1..]))
}

/// One `gem "<name>"` / `gem '<name>'` declaration (see [`gem_declaration_any`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GemDecl<'a> {
    pub(crate) name: &'a str,
    pub(crate) quote: char,
    /// Everything after the name's closing quote.
    pub(crate) rest: &'a str,
    /// Whether the call is parenthesized (`gem("x"…`).
    pub(crate) paren: bool,
}

/// Match `gem "<name>"` / `gem '<name>'` (or the parenthesized call form) at
/// the start of a trimmed line, for any gem name. Space OR tab after the
/// keyword — a tab-separated declaration the grammar cannot see would fall
/// through to the transitive Append plan, leaving the Gemfile declaring the
/// gem twice (bundler hard-fails on the duplicate). Never `gemspec` /
/// `gem_group`. Shared with lockfile discovery's Gemfile `source … do` block
/// reader (`vex::discover::gem`).
pub(crate) fn gem_declaration_any(trimmed: &str) -> Option<GemDecl<'_>> {
    let rest = trimmed.strip_prefix("gem")?;
    let (paren, rest) = match rest.strip_prefix([' ', '\t']) {
        Some(r) => (false, r),
        None => (true, rest.strip_prefix('(')?),
    };
    let (quote, name, rest) = quoted_literal(rest.trim_start())?;
    Some(GemDecl {
        name,
        quote,
        rest,
        paren,
    })
}

/// [`gem_declaration_any`] for exactly the gem `name`.
fn gem_declaration<'a>(trimmed: &'a str, name: &str) -> Option<GemDecl<'a>> {
    gem_declaration_any(trimmed).filter(|d| d.name == name)
}

/// The parts of a gem declaration's kept argument tail (what
/// [`gemfile::trailing_options`] returns) that survive the vendored
/// rewrite: the keyword options after any leading positional arguments,
/// and a trailing `#` comment. Each is a verbatim slice, trimmed.
struct KeptTail<'a> {
    keywords: &'a str,
    comment: &'a str,
}

/// Split the kept tail at the first keyword argument: a `key:` label, a
/// `"key":` label, a `=>` pair or a `**` double splat. Everything before it
/// (`*V`, `VERSION`, `ENV.fetch("V", "~> 1")`, a later quoted constraint) is
/// positional and dropped. Commas, `=>` and `#` only count outside strings
/// and brackets.
fn split_kept_tail(opts: &str) -> KeptTail<'_> {
    let bytes = opts.as_bytes();
    let mut quote: Option<u8> = None;
    let mut depth: i64 = 0;
    let mut arg_start = 0;
    let mut code_end = opts.len();
    let mut keyword_start: Option<usize> = None;
    let mut rocket = false;
    let mut i = 0;
    let close_arg = |start: usize, end: usize, rocket: bool, kw: &mut Option<usize>| {
        if kw.is_none() && (rocket || is_keyword_arg(opts[start..end].trim())) {
            *kw = Some(start);
        }
    };
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => quote = Some(c),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 && bytes.get(i + 1) == Some(&b'>') => rocket = true,
            b',' if depth == 0 => {
                close_arg(arg_start, i, rocket, &mut keyword_start);
                arg_start = i + 1;
                rocket = false;
            }
            b'#' if depth == 0 => {
                code_end = i;
                break;
            }
            _ => {}
        }
        i += 1;
    }
    close_arg(arg_start, code_end, rocket, &mut keyword_start);
    let code = &opts[..code_end];
    let comment = opts[code_end..].trim();
    match keyword_start {
        Some(k) => KeptTail {
            keywords: code[k..].trim(),
            comment,
        },
        None => KeptTail {
            keywords: "",
            comment,
        },
    }
}

/// True when one top-level argument is a keyword argument: a `**` double
/// splat or a `key:` / `"key":` label (not a `Const::Path`).
fn is_keyword_arg(arg: &str) -> bool {
    if arg.starts_with("**") {
        return true;
    }
    let label_end = match arg.as_bytes().first() {
        Some(q @ (b'"' | b'\'')) => arg[1..].find(*q as char).map(|e| e + 2),
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' => Some(
            arg.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(|e| match arg.as_bytes()[e] {
                    b'?' | b'!' => e + 1,
                    _ => e,
                })
                .unwrap_or(arg.len()),
        ),
        _ => None,
    };
    let Some(end) = label_end else {
        return false;
    };
    let after = &arg.as_bytes()[end..];
    after.first() == Some(&b':') && after.get(1) != Some(&b':')
}

/// Why the text after the gem name blocks an in-place rewrite (`None` = safe).
/// Only the code before any `#` comment counts — a comment trailing plain
/// version constraints is dropped by the rewrite (acceptable: the verbatim
/// original line lives in the ledger for revert), while one trailing kept
/// options rides along with them verbatim. Every source-selecting option is
/// blocked, not just `path:`/`git:`: bundler allows ONE source per gem, so a
/// preserved `source:`, `gitlab:` or custom `git_source` key (in any
/// spelling — the shared [`gemfile::source_option`] reader, the one hosted
/// mode refuses with) alongside the `path:` we add would fail every
/// `bundle` invocation.
fn rest_blocks_edit(rest: &str) -> Option<String> {
    if let Some(reason) = gem_line_tail_blocks_edit(rest) {
        return Some(reason);
    }
    let code = rest.split('#').next().unwrap_or("").trim();
    if code.is_empty() {
        return None;
    }
    // A `**opts` splat or hash literal is kept after `path:` (#847): a
    // source hidden in it makes bundler refuse the Gemfile loudly.
    gemfile::source_option(rest)
        .filter(|opt| !opt.dynamic)
        .map(|opt| {
            format!(
                "the declaration already carries `{}` (revert any previous vendoring first)",
                opt.spelling
            )
        })
}

/// The quoted `path:` option value on a gem line's argument tail (only the
/// code before any `#` comment counts) — the form our own rewrite emits.
/// `None` for anything else (`:path =>`, interpolation, no `path:` at all):
/// those fall through to [`rest_blocks_edit`]'s refusal, fail-closed.
fn gem_line_path_value(rest: &str) -> Option<&str> {
    let code = rest.split('#').next().unwrap_or("");
    let idx = code.find("path:")?;
    if idx > 0 && !matches!(code.as_bytes()[idx - 1], b' ' | b'\t' | b',') {
        return None;
    }
    let after = code[idx + "path:".len()..].trim_start();
    let q = after.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let value = &after[1..];
    let end = value.find(q)?;
    Some(&value[..end])
}

/// True when a `path:`/`remote:` value is OUR vendored dir for exactly this
/// gem (`.socket/vendor/gem/<any-uuid>/<name>-<version>`) — the shape
/// [`vendor_gem`] wires, and the only wiring a patch UPDATE (new uuid, same
/// purl) may rewire.
fn is_our_vendor_rel(value: &str, name: &str, version: &str) -> bool {
    parse_vendor_path(value)
        .is_some_and(|p| p.eco == "gem" && p.leaf == format!("{name}-{version}"))
}

fn apply_gemfile_plan(text: &str, plan: &GemfilePlan) -> String {
    match plan {
        GemfilePlan::Rewrite {
            original_line,
            new_line,
        }
        | GemfilePlan::RewireOurs {
            original_line,
            new_line,
            ..
        } => {
            let mut lines: Vec<&str> = text.split('\n').collect();
            if let Some(i) = lines.iter().position(|l| *l == original_line) {
                lines[i] = new_line;
            }
            lines.join("\n")
        }
        GemfilePlan::Append { block } => {
            let mut out = text.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(block);
            out
        }
    }
}

// ── Gemfile.lock editing ─────────────────────────────────────────────────────

/// The applied lock edit plus the verbatim fragments the ledger records.
struct LockEdit {
    text: String,
    /// The gem's GEM spec block as removed (4-space line + 6-space sublines).
    removed_spec_block: Vec<String>,
    /// The pre-vendor DEPENDENCIES entry (`None` = the gem was transitive and
    /// the entry was added; revert deletes it).
    old_dep_line: Option<String>,
    /// The emitted PATH section lines.
    path_section: Vec<String>,
    /// The DEPENDENCIES entry we wrote (`  <name> (= <version>)!`).
    new_dep_line: String,
    /// CHECKSUMS rewrite `(original line, bare replacement)`; `None` when the
    /// lock has no CHECKSUMS section, no entry for the gem, or the entry was
    /// already bare (idempotency: our own edit is never recorded as an
    /// "original" — reverting it onto a registry-sourced lock would break
    /// frozen installs).
    checksum_rewrite: Option<(String, String)>,
    /// The spec block was lifted from OUR OWN previous PATH section (a
    /// re-vendor to a newer patch uuid), not from GEM/specs: the lifted
    /// fragments are this backend's own prior wiring, so the caller records
    /// `original: None` and the true pre-vendor originals ride forward from
    /// the ledger entry being replaced (`persist_vendor_entry`).
    rewired_ours: bool,
    /// The already-bare CHECKSUMS line for the gem, when one is present.
    /// Only consulted on a re-vendor (`rewired_ours`): the checksum record
    /// must ride again or the first run's registry `sha256=` restore line
    /// drops out of the ledger with the entry being replaced.
    checksum_bare: Option<String>,
    /// The `  remote: ` line of the GEM section the spec block was lifted
    /// from, when that is not the lock's first GEM section (#779). Revert
    /// puts the block back into that section.
    source_remote: Option<String>,
}

/// The `gemfile_lock_spec` record's `(original, new)` line arrays for
/// `edit` (see [`LOCK_WIRING_KIND`] for the positional grammar).
fn lock_record_lines(edit: &LockEdit) -> (Vec<String>, Vec<String>) {
    let mut original = edit.removed_spec_block.clone();
    original.extend(edit.source_remote.iter().cloned());
    original.extend(edit.old_dep_line.iter().cloned());
    let mut new = edit.path_section.clone();
    new.push(edit.new_dep_line.clone());
    (original, new)
}

/// Produce the pair-edited lock text (see the module doc for the canonical
/// form). Pure string surgery on exact line spans — every byte not
/// deliberately changed is preserved, which is what keeps the result
/// byte-identical to what bundler regenerates.
fn edit_lock(text: &str, name: &str, version: &str, rel: &str) -> Result<LockEdit, String> {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // 1. Lift the gem's spec block out of GEM/specs — or, on a re-vendor to
    // a newer patch uuid (same purl), out of the PATH section our previous
    // run emitted. Bundler 2.2+ writes one GEM section per rubygems source
    // (sorted by remote), so the spec may sit in any of them (#779).
    let gem_sections = gem_section_spans(&lines);
    if gem_sections.is_empty() {
        return Err("Gemfile.lock has no GEM section".to_string());
    }
    if gem_sections
        .iter()
        .any(|&(gs, ge)| !(gs..ge).any(|i| lines[i] == "  specs:"))
    {
        return Err("Gemfile.lock GEM section has no specs: stanza".to_string());
    }
    // SECURITY/fail-closed: platform-suffixed installs were refused
    // (`platform_gem_unsupported`) before this point, so a platform-suffixed
    // GEM spec sibling means the lock disagrees with the installed tree —
    // and lifting only the plain entry would leave the sibling behind as a
    // stale registry spec. The CHECKSUMS branch below refuses the same
    // shape, but only bundler ≥ 2.6 locks have a CHECKSUMS section to catch
    // it in.
    let platform_prefix = format!("{version}-");
    for &(gs, ge) in &gem_sections {
        for line in lines.iter().take(ge).skip(gs + 1) {
            if let Some((n, v)) = spec_entry(line) {
                if n == name && v.starts_with(&platform_prefix) {
                    return Err(format!(
                        "Gemfile.lock GEM specs has a platform-suffixed entry `{n} ({v})` but the installed gem is not platform-specific; the lock disagrees with the install (re-resolve it before vendoring)"
                    ));
                }
            }
        }
    }
    let target = format!("    {name} ({version})");
    let mut hits = gem_sections
        .iter()
        .enumerate()
        .filter_map(|(k, &(gs, ge))| {
            (gs..ge)
                .find(|&i| lines[i] == target)
                .map(|i| (k, gs, ge, i))
        });
    let hit = hits.next();
    if hits.next().is_some() {
        // SECURITY/fail-closed: bundler locks one spec per gem; the same
        // entry under two sources is a lock this backend does not
        // understand, and lifting either copy would be a guess.
        return Err(format!(
            "Gemfile.lock lists `{name} ({version})` in more than one GEM section"
        ));
    }
    let mut source_remote: Option<String> = None;
    let mut rewired_ours = false;
    let removed_spec_block: Vec<String> = match hit {
        Some((k, gem_start, gem_end, block_start)) => {
            if k > 0 {
                // Revert must find this section again; without a remote
                // line there is nothing to find it by.
                source_remote = Some(
                    lines[gem_start..gem_end]
                        .iter()
                        .find(|l| l.starts_with("  remote: "))
                        .cloned()
                        .ok_or_else(|| {
                            format!("Gemfile.lock GEM section holding `{name} ({version})` has no remote: line")
                        })?,
                );
            }
            let mut block_end = block_start + 1;
            while block_end < gem_end && lines[block_end].starts_with("      ") {
                block_end += 1;
            }
            lines.drain(block_start..block_end).collect()
        }
        None => {
            // Re-vendor: the entry lives in the PATH section our previous
            // run emitted (remote parses as our vendored dir for exactly
            // this gem). Lift the block and drop the old section — step 3
            // re-emits it at the NEW uuid's sorted position. The lifted
            // lines are our own wiring, not pre-vendor originals: flagged
            // via `rewired_ours` (see the `LockEdit` field docs).
            let Some((ps, pe)) = find_our_path_section(&lines, name, version) else {
                return Err(format!(
                    "Gemfile.lock GEM specs has no entry `{name} ({version})`"
                ));
            };
            let block_start = (ps..pe).find(|&i| lines[i] == target).ok_or_else(|| {
                format!(
                    "Gemfile.lock PATH section for `{name}` lost its `{name} ({version})` spec entry"
                )
            })?;
            let mut block_end = block_start + 1;
            while block_end < pe && lines[block_end].starts_with("      ") {
                block_end += 1;
            }
            // Grammar-strict: besides the block, the section must be exactly
            // what vendor wrote (header, one remote, specs:, blank
            // separators). Anything extra — a hand edit, a merged-in second
            // spec — would be destroyed by the drain below; never guess.
            let non_block: Vec<&str> = (ps..pe)
                .filter(|i| !(block_start..block_end).contains(i))
                .map(|i| lines[i].as_str())
                .filter(|l| !l.is_empty())
                .collect();
            if non_block.len() != 3
                || non_block[0] != "PATH"
                || !non_block[1].starts_with("  remote: ")
                || non_block[2] != "  specs:"
            {
                return Err(format!(
                    "Gemfile.lock PATH section for `{name} ({version})` is not the shape vendor wrote; refusing to rewire it"
                ));
            }
            let block: Vec<String> = lines[block_start..block_end].to_vec();
            lines.drain(ps..pe);
            rewired_ours = true;
            block
        }
    };

    // 2. DEPENDENCIES: exact pin + `!` path-source marker. A transitive gem
    // (absent pre-vendor) is inserted at bundler's sorted position — it is a
    // Gemfile dependency now.
    let (dep_start, dep_end) = section_span(&lines, "DEPENDENCIES")
        .ok_or_else(|| "Gemfile.lock has no DEPENDENCIES section".to_string())?;
    let new_dep_line = format!("  {name} (= {version})!");
    let mut old_dep_line: Option<String> = None;
    let mut insert_at = dep_start + 1;
    let mut existing_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().take(dep_end).skip(dep_start + 1) {
        let Some(dep_name) = dep_entry_name(line) else {
            continue;
        };
        if dep_name == name {
            existing_idx = Some(i);
            break;
        }
        if dep_name < name {
            insert_at = i + 1;
        }
    }
    match existing_idx {
        Some(i) => {
            old_dep_line = Some(lines[i].clone());
            lines[i] = new_dep_line.clone();
        }
        None => lines.insert(insert_at, new_dep_line.clone()),
    }

    // 3. PATH section above the GEM section, at bundler's SORTED position
    // among any existing PATH sections: bundler emits path/git/plugin
    // sources sorted by identifier (source_list.rb `lock_other_sources`,
    // verified against bundler 4.0.15) — `source at `<path>`` for a path
    // source, so PATH sections order by their remote path and all sit in one
    // contiguous run (no other source's identifier can start with that
    // prefix). Splicing at invocation order instead churns the committed
    // lock on the next `bundle lock`. Non-PATH leading sections keep the
    // legacy insert-before-GEM fallback. `remote:` is the bare relative
    // path (spike claim 2).
    let mut path_section = vec![
        "PATH".to_string(),
        format!("  remote: {rel}"),
        "  specs:".to_string(),
    ];
    path_section.extend(removed_spec_block.iter().cloned());
    let gem_hdr = lines
        .iter()
        .position(|l| l.as_str() == "GEM")
        .ok_or_else(|| "Gemfile.lock lost its GEM section".to_string())?;
    let our_ident = path_source_identifier(rel);
    let mut at = gem_hdr;
    let mut i = 0;
    while i < gem_hdr {
        if lines[i].as_str() == "PATH" {
            let end = section_end(&lines, i);
            match path_section_remote(&lines[i..end]) {
                Some(existing) if path_source_identifier(existing) > our_ident => {
                    at = i;
                    break;
                }
                // Ours sorts after this section (a remote-less section is
                // grammar-degenerate; keep the legacy after-everything spot).
                _ => at = end.min(gem_hdr),
            }
            i = end;
        } else {
            i += 1;
        }
    }
    let mut insert = path_section.clone();
    insert.push(String::new()); // blank separator before the next section
    lines.splice(at..at, insert);

    // 4. CHECKSUMS (bundler ≥ 2.6 `lockfile_checksums`): a path-sourced gem
    // keeps a BARE `  <name> (<version>)` entry — bundler's own re-lock emits
    // exactly that form (spike G2), so the registry `sha256=` token must be
    // stripped here or the committed lock diverges from any regen forever
    // (spike G4: bundler silently preserves a stale token, never repairs it).
    // Absent section / absent entry are both tolerated by bundler — touched
    // by nothing. Re-found via section_span because the PATH splice above
    // shifted every index.
    let mut checksum_rewrite: Option<(String, String)> = None;
    let mut checksum_bare: Option<String> = None;
    if let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") {
        let bare = format!("  {name} ({version})");
        let mut plain_at: Option<usize> = None;
        for (i, line) in lines.iter().enumerate().take(ck_end).skip(ck_start + 1) {
            match checksum_entry(line) {
                Some((n, v)) if n == name && v == version => {
                    if plain_at.is_some() {
                        // SECURITY/fail-closed: duplicate entries mean the
                        // grammar assumption is wrong for this lock — editing
                        // one of them would be a guess.
                        return Err(format!(
                            "Gemfile.lock CHECKSUMS has more than one entry for `{name} ({version})`"
                        ));
                    }
                    plain_at = Some(i);
                }
                Some((n, v)) if n == name && v.starts_with(&platform_prefix) => {
                    // SECURITY/fail-closed: platform-suffixed installs were
                    // refused (`platform_gem_unsupported`) before this point,
                    // so a platform sibling here means the lock disagrees
                    // with the installed tree — never guess which entries
                    // bundler would collapse for a PATH spec.
                    return Err(format!(
                        "Gemfile.lock CHECKSUMS has a platform-suffixed entry `{n} ({v})` but the installed gem is not platform-specific; the lock disagrees with the install (re-resolve it before vendoring)"
                    ));
                }
                Some(_) => {}
                // SECURITY/fail-closed: a line that names the gem but does
                // not fit the entry grammar would be left half-edited or
                // skipped silently — both wrong. Err unwinds the Gemfile.
                None if checksum_line_names_gem(line, name) => {
                    return Err(format!(
                        "Gemfile.lock CHECKSUMS entry for `{name}` is not parseable: {line:?}"
                    ));
                }
                None => {}
            }
        }
        if let Some(i) = plain_at {
            if lines[i] != bare {
                checksum_rewrite = Some((lines[i].clone(), bare.clone()));
                lines[i] = bare;
            } else {
                checksum_bare = Some(bare);
            }
        }
    }

    Ok(LockEdit {
        text: lines.join("\n"),
        removed_spec_block,
        old_dep_line,
        path_section,
        new_dep_line,
        checksum_rewrite,
        rewired_ours,
        checksum_bare,
        source_remote,
    })
}

/// `[start, end)` of a lock section: the column-0 `header` line through (not
/// including) the next column-0 line. Blank separator lines belong to the
/// section they follow.
fn section_span(lines: &[String], header: &str) -> Option<(usize, usize)> {
    let start = lines.iter().position(|l| l.as_str() == header)?;
    Some((start, section_end(lines, start)))
}

/// End (exclusive) of the section whose column-0 header sits at `start` —
/// the [`section_span`] rule for a known header position.
fn section_end(lines: &[String], start: usize) -> usize {
    let mut end = start + 1;
    while end < lines.len() {
        let l = &lines[end];
        if !l.is_empty() && !l.starts_with(' ') {
            break;
        }
        end += 1;
    }
    end
}

/// `[start, end)` of every GEM section, in lock order.
fn gem_section_spans(lines: &[String]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].as_str() == "GEM" {
            let end = section_end(lines, i);
            spans.push((i, end));
            i = end;
        } else {
            i += 1;
        }
    }
    spans
}

/// The GEM section a `gemfile_lock_spec` record's spec block belongs in:
/// the one carrying the recorded `remote:` line, or the first GEM section
/// when none was recorded (the block came from it).
fn record_gem_section(lines: &[String], source_remote: Option<&str>) -> Option<(usize, usize)> {
    let spans = gem_section_spans(lines);
    match source_remote {
        None => spans.first().copied(),
        Some(remote) => spans
            .into_iter()
            .find(|&(gs, ge)| lines[gs..ge].iter().any(|l| l == remote)),
    }
}

/// The recorded source-section `remote:` line in a `gemfile_lock_spec`
/// record's `original` (present only when it was not the first GEM section).
fn record_source_remote(original_lines: &[String]) -> Option<&str> {
    original_lines
        .iter()
        .map(String::as_str)
        .find(|l| l.starts_with("  remote: "))
}

/// Bundler's lock-sort identifier for a path source — `source at `<path>``
/// (`Source::Path#to_s`, aliased as `identifier`); sections order by a
/// byte-wise comparison of these, which Rust's `str` ordering matches.
fn path_source_identifier(path: &str) -> String {
    format!("source at `{path}`")
}

/// The `  remote: ` value of the section slice starting at its header line.
fn path_section_remote(section: &[String]) -> Option<&str> {
    section.iter().find_map(|l| l.strip_prefix("  remote: "))
}

/// Find the PATH section whose `remote:` is OUR vendored dir for this gem —
/// any patch uuid (the previous run's wiring, sought during a re-vendor).
fn find_our_path_section(lines: &[String], name: &str, version: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < lines.len() {
        if lines[i].as_str() == "PATH" {
            let end = section_end(lines, i);
            if path_section_remote(&lines[i..end])
                .is_some_and(|p| is_our_vendor_rel(p, name, version))
            {
                return Some((i, end));
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// `line`'s entry text at exactly `indent` (2 or 4) spaces: non-empty and
/// not more deeply indented.
fn at_indent(line: &str, indent: usize) -> Option<&str> {
    let rest = line.strip_prefix(&"    "[..indent])?;
    (!rest.is_empty() && !rest.starts_with(' ')).then_some(rest)
}

/// Name of a 2-space DEPENDENCIES entry (`  rack (~> 3.1)` / `  rack!`).
fn dep_entry_name(line: &str) -> Option<&str> {
    let rest = at_indent(line, 2)?;
    let end = rest.find([' ', '(', '!']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Name of a 4-space spec entry (`    rack (3.2.6)`).
fn spec_entry_name(line: &str) -> Option<&str> {
    let rest = at_indent(line, 4)?;
    Some(rest.split(' ').next().unwrap_or(rest))
}

/// Parse a 4-space specs entry line: `    <name> (<token>)`, nothing after
/// the closing paren. Returns `(name, parenthesized token)` — the platform
/// suffix stays inside the token, mirroring [`checksum_entry`]'s grammar at
/// specs indentation (`    ffi (1.17.2-aarch64-linux-gnu)`).
fn spec_entry(line: &str) -> Option<(&str, &str)> {
    match split_entry(at_indent(line, 4)?)? {
        (name, ver, "") => Some((name, ver)),
        _ => None,
    }
}

/// Parse a CHECKSUMS entry line: two-space indent, `<name> (<version>)` or
/// `<name> (<version>-<platform>)`, then optional space-separated tokens
/// (`sha256=<hex>` on registry entries, nothing on path entries). Returns
/// `(name, parenthesized token)` — the platform suffix stays inside the token
/// because matching must mirror the GEM specs grammar (spike G5: native gems
/// get one CHECKSUMS line per platform spec, `ffi (1.17.2-aarch64-linux-gnu)`).
fn checksum_entry(line: &str) -> Option<(&str, &str)> {
    let (name, ver, _) = split_checksum_entry(at_indent(line, 2)?)?;
    Some((name, ver))
}

/// True when a CHECKSUMS-section line's leading token is `name` — used to
/// fail closed on lines that mention the gem but do not fit the
/// [`checksum_entry`] grammar (editing around them would be a guess).
fn checksum_line_names_gem(line: &str, name: &str) -> bool {
    line.strip_prefix("  ")
        .filter(|r| !r.starts_with(' '))
        .and_then(|r| r.split([' ', '(']).next())
        == Some(name)
}

/// True when the lock's CHECKSUMS section is coherent with a path-sourced
/// gem: no section, no entry for the gem, or exactly the bare
/// `  <name> (<version>)` form. A leftover registry `sha256=` token (a lock
/// wired by a pre-CHECKSUMS-aware socket-patch) is NOT in sync — bundler
/// silently preserves it forever (spike G4), so the hot path must not declare
/// such a lock done; only revert + re-vendor can repair it.
fn lock_checksum_in_sync(lock_text: &str, name: &str, version: &str) -> bool {
    let lines: Vec<String> = lock_text.split('\n').map(str::to_string).collect();
    let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") else {
        return true;
    };
    let bare = format!("  {name} ({version})");
    let platform_prefix = format!("{version}-");
    for line in &lines[ck_start + 1..ck_end] {
        match checksum_entry(line) {
            Some((n, v)) if n == name && (v == version || v.starts_with(&platform_prefix)) => {
                if line.as_str() != bare {
                    return false;
                }
            }
            Some(_) => {}
            None if checksum_line_names_gem(line, name) => return false,
            None => {}
        }
    }
    true
}

// ── revert helpers ───────────────────────────────────────────────────────────

/// What restoring one wiring record found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordRevert {
    /// Restored (or would be, on a dry run) — or already in its reverted
    /// state (convergence: silent per the LIVENESS CONTRACT on
    /// [`RevertOutcome::drift_skipped`]).
    Done,
    /// What vendor wrote is gone and the pre-vendor original is not back
    /// either: genuine third-party drift, left alone in full.
    Drifted,
    /// The wired file itself no longer exists: nothing can still route
    /// through the vendored copy via it.
    FileMissing,
}

/// Restore one `gemfile_line` record.
async fn revert_gemfile_record(
    gemfile_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<RecordRevert, String> {
    let text = match read_regular_to_string(gemfile_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RecordRevert::FileMissing),
        Err(e) => return Err(format!("unreadable Gemfile: {e}")),
    };
    let Some(written) = w.new.as_ref().and_then(Value::as_str) else {
        return Ok(RecordRevert::Drifted);
    };
    let restored = match w.action {
        WiringAction::Rewritten => {
            let Some(original) = w.original.as_ref().and_then(Value::as_str) else {
                return Ok(RecordRevert::Drifted);
            };
            let mut lines: Vec<&str> = text.split('\n').collect();
            let Some(i) = lines.iter().position(|l| *l == written) else {
                // ALREADY CONVERGED: the pre-vendor line is back (a hand
                // restore, a `bundle update` regeneration, an earlier partial
                // revert) — not drift, nothing to write.
                return Ok(if lines.contains(&original) {
                    RecordRevert::Done
                } else {
                    RecordRevert::Drifted
                });
            };
            lines[i] = original;
            lines.join("\n")
        }
        WiringAction::Added => {
            let Some(at) = text.find(written) else {
                // ALREADY CONVERGED: an Added block's reverted state is its
                // absence (the LIVENESS CONTRACT's "key is absent" case).
                return Ok(RecordRevert::Done);
            };
            let mut out = String::with_capacity(text.len());
            out.push_str(&text[..at]);
            out.push_str(&text[at + written.len()..]);
            out
        }
    };
    if !dry_run {
        atomic_write_bytes_preserving_mode(gemfile_path, restored.as_bytes())
            .await
            .map_err(|e| format!("failed to write Gemfile: {e}"))?;
    }
    Ok(RecordRevert::Done)
}

/// Restore one `gemfile_lock_spec` record. Drift leaves the lock alone in
/// full — a partial splice would corrupt it.
async fn revert_lock_record(
    lock_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<RecordRevert, String> {
    let Some(original_lines) = wiring_string_array(w.original.as_ref()) else {
        return Ok(RecordRevert::Drifted);
    };
    let Some(new_lines) = wiring_string_array(w.new.as_ref()) else {
        return Ok(RecordRevert::Drifted);
    };
    let text = match read_regular_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RecordRevert::FileMissing),
        Err(e) => return Err(format!("unreadable Gemfile.lock: {e}")),
    };
    let Some(restored) = revert_lock_text(&text, &original_lines, &new_lines) else {
        // ALREADY CONVERGED: our PATH section is gone and every pre-vendor
        // spec line is back in GEM/specs (a `bundle update` regeneration or
        // an earlier partial revert) — not drift, nothing to write.
        return Ok(
            if lock_record_converged(&text, &original_lines, &new_lines) {
                RecordRevert::Done
            } else {
                RecordRevert::Drifted
            },
        );
    };
    if !dry_run {
        atomic_write_bytes_preserving_mode(lock_path, restored.as_bytes())
            .await
            .map_err(|e| format!("failed to write Gemfile.lock: {e}"))?;
    }
    Ok(RecordRevert::Done)
}

/// True when the lock already holds the record's reverted state: no PATH
/// section carries vendor's `remote:` line and every spec-block line of the
/// pre-vendor original is present.
fn lock_record_converged(text: &str, original_lines: &[String], new_lines: &[String]) -> bool {
    // A record whose `new` lost its `remote:` line is malformed, never
    // converged (the tampered-ledger matrix pins it as drift).
    let Some(remote_line) = new_lines.get(1).filter(|l| l.starts_with("  remote: ")) else {
        return false;
    };
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    if find_path_section(&lines, remote_line).is_some() {
        return false;
    }
    let Some((gs, ge)) = record_gem_section(&lines, record_source_remote(original_lines)) else {
        return false;
    };
    let gem = &lines[gs..ge];
    let mut spec_block = original_lines.iter().filter(|l| l.starts_with("    "));
    let mut any = false;
    let all_present = spec_block.all(|l| {
        any = true;
        gem.contains(l)
    });
    any && all_present
}

fn wiring_string_array(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// Restore one `gemfile_lock_checksum` record: the registry CHECKSUMS line
/// (`sha256=` token and all) goes back over the bare path-form line vendor
/// wrote. Restoring is not optional polish — a bare entry left on a
/// registry-sourced gem hard-fails `BUNDLE_FROZEN=true bundle install`
/// (exit 16) and plain installs rewrite the lock to refill the token (churn);
/// the token is not recomputable offline (spike `bare-checksum-registry-gem`
/// pair). The search is confined to the CHECKSUMS section so a coincidental
/// identical line elsewhere (e.g. a DEPENDENCIES entry) is never clobbered.
/// The line vendor wrote being gone is drift — unless the registry line it
/// replaced is already back (convergence), left alone either way.
async fn revert_lock_checksum_record(
    lock_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<RecordRevert, String> {
    let Some(written) = w.new.as_ref().and_then(Value::as_str) else {
        return Ok(RecordRevert::Drifted);
    };
    let text = match read_regular_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RecordRevert::FileMissing),
        Err(e) => return Err(format!("unreadable Gemfile.lock: {e}")),
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") else {
        return Ok(RecordRevert::Drifted);
    };
    let original = w.original.as_ref().and_then(Value::as_str);
    let Some(i) = (ck_start + 1..ck_end).find(|&i| lines[i] == written) else {
        // ALREADY CONVERGED: the registry line vendor replaced is back.
        let converged =
            original.is_some_and(|orig| (ck_start + 1..ck_end).any(|i| lines[i] == orig));
        return Ok(if converged {
            RecordRevert::Done
        } else {
            RecordRevert::Drifted
        });
    };
    let Some(original) = original else {
        // A re-vendor rides the checksum record forward with `original: None`
        // for the caller's carry-forward to fill. When the chain has no
        // registry line to fill FROM — the pre-vendor entry was ALREADY the
        // bare path form (vendor then recorded no checksum wiring at all) —
        // there is nothing to restore: the bare line still standing IS the
        // pre-vendor state, not drift.
        return Ok(RecordRevert::Done);
    };
    lines[i] = original.to_string();
    if !dry_run {
        atomic_write_bytes_preserving_mode(lock_path, lines.join("\n").as_bytes())
            .await
            .map_err(|e| format!("failed to write Gemfile.lock: {e}"))?;
    }
    Ok(RecordRevert::Done)
}

/// Pure splice reversing [`edit_lock`]: drop the PATH section vendor emitted,
/// move the spec block back into GEM/specs at its sorted position, and
/// restore (or delete) the DEPENDENCIES entry. All preconditions are checked
/// BEFORE any mutation so drift never yields a half-restored lock; `None`
/// means "drifted, leave the lock alone".
fn revert_lock_text(text: &str, original_lines: &[String], new_lines: &[String]) -> Option<String> {
    let (new_dep_line, path_lines) = new_lines.split_last()?;
    let remote_line = path_lines.get(1)?;
    if !remote_line.starts_with("  remote: ") {
        return None;
    }
    let spec_block: Vec<&String> = original_lines
        .iter()
        .filter(|l| l.starts_with("    "))
        .collect();
    let source_remote = record_source_remote(original_lines);
    let old_dep_line = original_lines
        .iter()
        .find(|l| l.starts_with("  ") && !l[2..].starts_with(' ') && !l.starts_with("  remote: "));
    let our_name = spec_entry_name(spec_block.first()?)?.to_string();

    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // Preconditions on the untouched lines.
    let (path_start, path_end) = find_path_section(&lines, remote_line)?;
    if !lines.iter().any(|l| l == new_dep_line) {
        return None;
    }
    {
        let (gs, ge) = record_gem_section(&lines, source_remote)?;
        (gs..ge).find(|&i| lines[i] == "  specs:")?;
    }

    // 1. Drop the PATH section (incl. its trailing blank separator).
    lines.drain(path_start..path_end);

    // 2. Spec block back into GEM/specs, sorted by entry name (bundler keeps
    // specs alphabetized; the block came out of a sorted list), in the GEM
    // section it was lifted from.
    let (gs, ge) = record_gem_section(&lines, source_remote)?;
    let specs_idx = (gs..ge).find(|&i| lines[i] == "  specs:")?;
    let mut insert_at = specs_idx + 1;
    let mut i = specs_idx + 1;
    while i < ge {
        let line = &lines[i];
        if line.is_empty() {
            break;
        }
        match spec_entry_name(line) {
            Some(n) if n > our_name.as_str() => break,
            Some(_) => {
                i += 1;
                while i < ge && lines[i].starts_with("      ") {
                    i += 1;
                }
                insert_at = i;
            }
            None => i += 1,
        }
    }
    lines.splice(
        insert_at..insert_at,
        spec_block.iter().map(|l| (*l).clone()),
    );

    // 3. DEPENDENCIES entry: restore the original line, or delete the one we
    // added for a transitive gem.
    let dep_idx = lines.iter().position(|l| l == new_dep_line)?;
    match old_dep_line {
        Some(orig) => lines[dep_idx] = orig.clone(),
        None => {
            lines.remove(dep_idx);
        }
    }

    Some(lines.join("\n"))
}

/// Find the PATH section containing exactly `remote_line` (there may be
/// several PATH sections; only ours is touched).
fn find_path_section(lines: &[String], remote_line: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(off) = lines[from..].iter().position(|l| l.as_str() == "PATH") {
        let start = from + off;
        let mut end = start + 1;
        while end < lines.len() {
            let l = &lines[end];
            if !l.is_empty() && !l.starts_with(' ') {
                break;
            }
            end += 1;
        }
        if lines[start..end].iter().any(|l| l.as_str() == remote_line) {
            return Some((start, end));
        }
        from = end;
    }
    None
}

// ── shared helpers ───────────────────────────────────────────────────────────

/// The one shared gemspec line-scanner: locate a `.{attr}` mention in `line`
/// and return what follows it (leading-whitespace-trimmed), or `None`.
///
/// `anchored` additionally requires the mention to OPEN the line as
/// `<receiver>.{attr}` with a plain-identifier receiver (`s.summary = …`,
/// `  spec.authors= …`). Anchoring makes a preceding comment marker
/// impossible, so anchored callers scan RAW lines with no comment-stripping —
/// stripping at `#` would truncate inside string literals and misjudge
/// `s.summary = "#1 Ruby web server"` as missing. A mention whose attr
/// continues as a longer identifier (`.extensions_dir`, `.authors` when
/// looking for `.author`) is never a match. Only the FIRST mention per line
/// is examined — one attribute per line is the shape `Specification#to_ruby`
/// emits. Parsing ruby for real would need a ruby.
fn attr_mention<'a>(line: &'a str, attr: &str, anchored: bool) -> Option<&'a str> {
    let needle = format!(".{attr}");
    let idx = line.find(&needle)?;
    if anchored {
        let receiver = line[..idx].trim_start();
        if receiver.is_empty()
            || !receiver
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@'))
        {
            return None;
        }
    }
    let after = &line[idx + needle.len()..];
    if after
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(after.trim_start())
}

/// Textual heuristic for `s.extensions = […]` / `spec.extensions << …` style
/// declarations (comment-stripped per line — a commented-out declaration is
/// not one; the truncation caveat in [`attr_mention`] only loses this
/// refusal's nicer error, never safety, because a match REFUSES). A miss —
/// e.g. extensions assigned through interpolation tricks — falls through,
/// which likewise only loses the nicer error.
fn gemspec_declares_extensions(spec_text: &str) -> bool {
    for raw in spec_text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        if let Some(after) = attr_mention(line, "extensions", false) {
            if (after.starts_with('=') && !after.starts_with("=="))
                || after.starts_with("<<")
                || after.starts_with("+=")
                || after.starts_with(".push")
                || after.starts_with(".concat")
            {
                return true;
            }
        }
    }
    false
}

/// Every RHS assigned to any of the `attrs` aliases at a line start
/// (assignments only — `==` comparisons don't count), via [`attr_mention`].
fn gemspec_attr_rhs<'a>(spec_text: &'a str, attrs: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    for raw in spec_text.lines() {
        for attr in attrs {
            if let Some(after) = attr_mention(raw, attr, true) {
                if let Some(rhs) = after.strip_prefix('=') {
                    if !rhs.starts_with('=') {
                        out.push(rhs.trim());
                    }
                }
            }
        }
    }
    out
}

/// Does any line assign one of the `attrs` aliases? Pass every alias rubygems
/// accepts for the attribute (`["authors", "author"]`, `["licenses",
/// "license"]`).
fn gemspec_assigns_attr(spec_text: &str, attrs: &[&str]) -> bool {
    !gemspec_attr_rhs(spec_text, attrs).is_empty()
}

/// Textually: does this `authors` RHS collapse to NO String elements?
/// Rubygems' `authors=` writer keeps only Strings (`grep(String)`), so `[]`,
/// `nil`, `[nil]`, and empty word-arrays (`%w[]`) all yield an empty authors
/// list — the hard `authors may not be empty` error — while `[""]` keeps its
/// String and validates. Fail-open: anything not demonstrably empty passes
/// (a `[42]` would slip through, but `to_ruby` never emits one and bundler
/// still reports it — the heuristic only loses the nicer error).
fn authors_rhs_collapses_empty(rhs: &str) -> bool {
    let cleaned = rhs.replace(".freeze", "");
    let cleaned = cleaned.trim();
    let body = cleaned
        .strip_prefix("%w")
        .or_else(|| cleaned.strip_prefix("%W"))
        .unwrap_or(cleaned);
    !body
        .split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | '(' | ')' | ','))
        .any(|tok| !tok.is_empty() && tok != "nil")
}

/// The rubygems-REQUIRED attributes a stub gemspec must assign for bundler to
/// accept it as a path source, returned as the list it is missing (empty =
/// valid). Every bundler major validates path-source gemspecs, so a stub
/// missing these bricks every later `bundle install`.
///
/// The bar is EMPIRICAL, verified against rubygems 3.3 / 3.5 / 3.6
/// (`Gem::Specification#validate`, both packaging modes, in the bundler
/// 1.17 / 2.7 / 4.0 era images):
///
/// * `summary` — hard `missing value for attribute summary` ONLY when never
///   assigned. The `summary=` writer coerces `nil`/`""` to a present value
///   (empty is at most a warning), so ANY assignment line satisfies it.
/// * `authors` — hard `authors may not be empty` when never assigned (the
///   singular `author =` alias counts) or when every assignment textually
///   collapses to no String elements ([`authors_rhs_collapses_empty`]).
///
/// A missing `licenses` is only a rubygems WARNING, deliberately not checked
/// here (callers may mention it in advisory text via
/// [`gemspec_assigns_attr`]). Fail-open by construction: only a stub that
/// demonstrably fails the bar is flagged, so a legitimate stub always passes
/// and is written byte-verbatim.
fn gemspec_missing_required_attrs(spec_text: &str) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !gemspec_assigns_attr(spec_text, &["summary"]) {
        missing.push("summary");
    }
    let author_rhs = gemspec_attr_rhs(spec_text, &["authors", "author"]);
    if author_rhs.is_empty()
        || author_rhs
            .iter()
            .all(|rhs| authors_rhs_collapses_empty(rhs))
    {
        missing.push("authors");
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::VerifyStatus;
    use crate::vendor::common::{backup_dir_for, swap_sibling_for};
    use crate::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:gem/rack@3.2.6";
    const PRISTINE: &[u8] = b"module Rack\n  VERSION = \"3.2.6\"\nend\n";
    const PATCHED: &[u8] = b"module Rack\n  SOCKET_PATCHED = true\n  VERSION = \"3.2.6\"\nend\n";

    const GEMSPEC: &str = "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\n  s.summary = \"a modular Ruby web server interface\"\n  s.authors = [\"Rack maintainers\"]\n  s.require_paths = [\"lib\"]\nend\n";

    const GEMFILE_DIRECT: &str =
        "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\"\n";
    const GEMFILE_TRANSITIVE: &str = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";

    const LOCK_DIRECT: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";
    const LOCK_TRANSITIVE: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n\nBUNDLED WITH\n   2.5.22\n";

    fn copy_rel() -> String {
        format!(".socket/vendor/gem/{UUID}/rack-3.2.6")
    }

    /// Fixture: a gem home (gems/ + specifications/ siblings), a bundler
    /// project (Gemfile + Gemfile.lock), and a blobs dir with the patched
    /// bytes. Returns (tmp, project_root, installed_dir, blobs, record).
    async fn fixture(
        gemfile: &str,
        lock: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let installed = base.join("gem_home/gems/rack-3.2.6");
        tokio::fs::create_dir_all(installed.join("lib"))
            .await
            .unwrap();
        tokio::fs::write(installed.join("lib/rack.rb"), PRISTINE)
            .await
            .unwrap();
        let specs = base.join("gem_home/specifications");
        tokio::fs::create_dir_all(&specs).await.unwrap();
        tokio::fs::write(specs.join("rack-3.2.6.gemspec"), GEMSPEC)
            .await
            .unwrap();

        let root = base.join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join(GEMFILE), gemfile).await.unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), lock)
            .await
            .unwrap();

        let before = compute_git_sha256_from_bytes(PRISTINE);
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = base.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "lib/rack.rb".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, root, installed, blobs, record)
    }

    fn unwrap_done(o: VendorOutcome) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match o {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => panic!("refused: {code}: {detail}"),
        }
    }

    fn unwrap_refused(o: VendorOutcome) -> (&'static str, String) {
        match o {
            VendorOutcome::Refused { code, detail } => (code, detail),
            VendorOutcome::Done { result, .. } => panic!("not refused: {result:?}"),
        }
    }

    /// The download plan's gate names exactly the gems whose vendor call asks
    /// the patch service for a grant: none it refuses first (a native
    /// platform, an installed dir that is not the gem's, a non-canonical
    /// uuid), not the empty patch's no-op, and — once vendored — not the
    /// in-sync re-run.
    #[tokio::test]
    async fn service_preflight_names_exactly_the_gems_that_ask_for_a_grant() {
        use crate::vendor::test_support::{
            empty_patch, mount_no_results, plan_matches_grants, service_cfg, with_uuid, Borrowed,
            PLAN_UUID_B, PLAN_UUID_C,
        };
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let root = root.as_path();
        let server = wiremock::MockServer::start().await;
        mount_no_results(&server).await;
        let cfg = service_cfg(&server.uri(), crate::vendor::VendorSource::Service, false);
        let sources = PatchSources::blobs_only(&blobs);
        let cases = [
            (PURL, record.clone()),
            (
                "pkg:gem/rack@3.2.6?platform=x86_64-linux",
                with_uuid(&record, PLAN_UUID_B),
            ),
            (PURL, with_uuid(&record, "not-a-uuid")),
            ("pkg:gem/absent@1.0.0", with_uuid(&record, PLAN_UUID_C)),
            (PURL, empty_patch(&record, PLAN_UUID_C)),
        ];
        let installed = &installed;
        let gate = |purl: String, rec: PatchRecord| -> Borrowed<'_, bool> {
            Box::pin(async move {
                service_preflight(&purl, installed, root, &rec)
                    .await
                    .is_some()
            })
        };
        let vendor = |purl: String, rec: PatchRecord| -> Borrowed<'_, VendorOutcome> {
            let (sources, cfg) = (&sources, &cfg);
            Box::pin(async move {
                crate::vendor::test_support::vendor_gem(
                    &purl,
                    installed.as_path(),
                    root,
                    &rec,
                    sources,
                    "2026-06-09T00:00:00Z",
                    false,
                    false,
                    Some(cfg),
                )
                .await
            })
        };
        let planned = plan_matches_grants(&server, &cases, gate, vendor).await;
        assert_eq!(planned, vec![UUID.to_string()]);
        // A failed download leaves the same package eligible on retry.
        let rerun = plan_matches_grants(&server, &cases[..1], gate, vendor).await;
        assert_eq!(rerun, planned);
    }

    async fn run_vendor(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        run_vendor_purl(PURL, root, blobs, installed, record, dry_run).await
    }

    /// [`run_vendor`] with a caller-chosen purl (e.g. a `?platform=` variant).
    async fn run_vendor_purl(
        purl: &str,
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_gem(
            purl,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    /// Simulate the CLI caller's `persist_vendor_entry` carry-forward: fill
    /// the replacement entry's `original: None` holes from the entry being
    /// replaced, by wiring identity (file, kind, key).
    fn carry_forward_originals(prev: &VendorEntry, next: &mut VendorEntry) {
        for rec in &mut next.wiring {
            if rec.action == WiringAction::Rewritten && rec.original.is_none() {
                if let Some(p) = prev
                    .wiring
                    .iter()
                    .find(|p| p.file == rec.file && p.kind == rec.kind && p.key == rec.key)
                {
                    rec.original = p.original.clone();
                }
            }
        }
    }

    fn expected_lock_direct() -> String {
        format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
            rel = copy_rel()
        )
    }

    /// #341: a `gems.rb` beside the Gemfile is the manifest bundler loads
    /// ("Multiple gemfiles ... ignoring them in favor of gems.rb"). Wiring
    /// the ignored Gemfile reported success while bundler installed the
    /// upstream gem; vendor must refuse before any write instead.
    #[tokio::test]
    async fn gems_rb_twin_is_refused_before_any_write() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("gems.rb"), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join("gems.locked"), LOCK_DIRECT)
            .await
            .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_not_loaded");
        assert!(detail.contains("gems.rb"), "{detail}");
        for (file, want) in [
            (GEMFILE, GEMFILE_DIRECT),
            (GEMFILE_LOCK, LOCK_DIRECT),
            ("gems.rb", GEMFILE_DIRECT),
            ("gems.locked", LOCK_DIRECT),
        ] {
            assert_eq!(
                tokio::fs::read_to_string(root.join(file)).await.unwrap(),
                want
            );
        }
        assert!(!root.join(".socket/vendor").exists());
    }

    /// #390: `bundle config set --local gemfile Gemfile.next` makes bundler
    /// load `Gemfile.next` (+ `Gemfile.next.lock`); wiring `Gemfile` left the
    /// loaded manifest unpatched. Refused before any write.
    #[tokio::test]
    async fn bundle_gemfile_naming_another_manifest_is_refused() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("Gemfile.next"), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join("Gemfile.next.lock"), LOCK_DIRECT)
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_not_loaded");
        assert!(detail.contains("Gemfile.next"), "{detail}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// `BUNDLE_GEMFILE` naming the project's own Gemfile beside a `gems.rb`
    /// makes bundler load the Gemfile, so vendoring wires it as usual.
    #[tokio::test]
    async fn bundle_gemfile_naming_the_gemfile_overrides_a_gems_rb_twin() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("gems.rb"), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile\"\n",
        )
        .await
        .unwrap();

        let (result, _entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct()
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("gems.rb"))
                .await
                .unwrap(),
            GEMFILE_DIRECT
        );
    }

    #[tokio::test]
    async fn test_direct_dep_happy_path() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);

        // Copy patched + gemspec materialized; installed dir untouched.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("lib/rack.rb")).await.unwrap(),
            PATCHED
        );
        assert_eq!(
            tokio::fs::read_to_string(copy.join("rack.gemspec"))
                .await
                .unwrap(),
            GEMSPEC,
            "stub gemspec copied in as <name>.gemspec"
        );
        assert_eq!(
            tokio::fs::read(installed.join("lib/rack.rb"))
                .await
                .unwrap(),
            PRISTINE
        );

        // Gemfile: line rewritten in place, double quotes preserved.
        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert_eq!(
            gemfile,
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", path: \"{}\"\n",
                copy_rel()
            )
        );

        // Lock: the exact bundler-canonical pair-edit form (PATH before GEM,
        // bare relative remote, spec block moved with its sublines, exact-pin
        // `!` dependency, PLATFORMS/BUNDLED WITH byte-preserved).
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(lock, expected_lock_direct());

        // Marker present in the uuid dir.
        let marker = tokio::fs::read_to_string(
            root.join(format!(".socket/vendor/gem/{UUID}/{VENDOR_MARKER_FILE}")),
        )
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("\"ecosystem\": \"gem\""));

        // Ledger entry: artifact + both wiring records with verbatim text.
        let entry = entry.expect("success must carry a ledger entry");
        assert_eq!(entry.ecosystem, "gem");
        assert_eq!(entry.base_purl, PURL);
        assert_eq!(entry.artifact.path, copy_rel());
        assert_eq!(entry.wiring.len(), 2);
        let gf = &entry.wiring[0];
        assert_eq!(gf.file, GEMFILE);
        assert_eq!(gf.kind, GEMFILE_WIRING_KIND);
        assert_eq!(gf.action, WiringAction::Rewritten);
        assert_eq!(gf.key.as_deref(), Some("rack"));
        assert_eq!(
            gf.original.as_ref().unwrap(),
            &Value::String("gem \"rack\", \"~> 3.1\"".to_string())
        );
        let lk = &entry.wiring[1];
        assert_eq!(lk.file, GEMFILE_LOCK);
        assert_eq!(lk.kind, LOCK_WIRING_KIND);
        assert_eq!(lk.action, WiringAction::Rewritten);
        let orig = lk.original.as_ref().unwrap().as_array().unwrap();
        assert_eq!(
            orig,
            &vec![
                Value::String("    rack (3.2.6)".to_string()),
                Value::String("      base64 (>= 0.1.0)".to_string()),
                Value::String("  rack (~> 3.1)".to_string()),
            ],
            "spec block + old DEPENDENCIES line recorded verbatim"
        );
        let new = lk.new.as_ref().unwrap().as_array().unwrap();
        assert_eq!(
            new.last().unwrap(),
            &Value::String("  rack (= 3.2.6)!".to_string())
        );
    }

    #[tokio::test]
    async fn test_single_quote_style_preserved() {
        let gemfile = "source 'https://rubygems.org'\n\ngem 'rack', '~> 3.1'\n";
        let lock = LOCK_DIRECT
            .replace("  puma\n", "")
            .replace("    puma (6.4.2)\n      nio4r (~> 2.0)\n", "");
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, &lock).await;

        let (result, _e, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert!(
            new_gemfile.contains(&format!("gem 'rack', '3.2.6', path: '{}'", copy_rel())),
            "single-quote style preserved: {new_gemfile}"
        );
    }

    #[tokio::test]
    async fn test_transitive_appends_managed_block_and_sorted_dep() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert_eq!(
            gemfile,
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\n{MANAGED_OPEN}\ngem \"rack\", \"3.2.6\", path: \"{}\"\n{MANAGED_CLOSE}\n",
                copy_rel()
            )
        );

        // DEPENDENCIES gains the pin in sorted position (after puma).
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert!(
            lock.contains("DEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n"),
            "sorted insert: {lock}"
        );

        let entry = entry.unwrap();
        assert_eq!(entry.wiring[0].action, WiringAction::Added);
        assert!(entry.wiring[0].original.is_none());
        // No old DEPENDENCIES line recorded → revert deletes the added one.
        let orig = entry.wiring[1]
            .original
            .as_ref()
            .unwrap()
            .as_array()
            .unwrap();
        assert!(
            orig.iter().all(|l| l.as_str().unwrap().starts_with("    ")),
            "transitive: only the spec block is recorded: {orig:?}"
        );
    }

    #[tokio::test]
    async fn test_refuses_missing_gemfile() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_file(root.join(GEMFILE)).await.unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_missing");
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    #[tokio::test]
    async fn test_refuses_missing_lock() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_file(root.join(GEMFILE_LOCK))
            .await
            .unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(!root.join(".socket").exists());
    }

    /// The required-attribute heuristic ([`gemspec_missing_required_attrs`]):
    /// flag ONLY what real rubygems hard-fails on (empirically verified
    /// against rubygems 3.3/3.5/3.6, see the fn doc) — a stub rubygems
    /// tolerates must always pass, whatever its spelling.
    #[test]
    fn required_attrs_heuristic() {
        // The defective served shape: no summary, no authors.
        assert_eq!(
            gemspec_missing_required_attrs(
                "Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n"
            ),
            vec!["summary", "authors"]
        );
        // A real converter/to_ruby stub: `.freeze`-d scalar + array. Valid.
        assert_eq!(
            gemspec_missing_required_attrs(
                "Gem::Specification.new do |s|\n  s.summary = \"web server interface\".freeze\n  s.authors = [\"A. Person\".freeze, \"B. Person\".freeze]\nend\n"
            ),
            Vec::<&str>::new()
        );
        // Alternate spellings a valid stub may use: another block variable,
        // no space around `=`, the singular `author =` alias, %w arrays.
        assert_eq!(
            gemspec_missing_required_attrs(
                "Gem::Specification.new do |spec|\n  spec.summary=\"x\"\n  spec.author = \"A. Person\"\nend\n"
            ),
            Vec::<&str>::new()
        );
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\"\ns.authors = %w[alice bob]\n"),
            Vec::<&str>::new()
        );
        // A `#` inside a string literal is CONTENT, not a comment — this
        // valid stub must never be judged missing (scanning raw lines,
        // anchored to the line start, instead of comment-stripping).
        assert_eq!(
            gemspec_missing_required_attrs(
                "s.summary = \"#1 Ruby web server\".freeze\ns.authors = [\"D. #2 Person\".freeze]\n"
            ),
            Vec::<&str>::new()
        );
        // One present, one absent → only the absent one is named.
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\".freeze\n"),
            vec!["authors"]
        );
        // Rubygems TOLERATES nil/empty summary (the writer coerces; empty is
        // a warning) and an empty-STRING author ([""] keeps its String), so
        // none of these flag.
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"\".freeze\ns.authors = [\"\"]\n"),
            Vec::<&str>::new()
        );
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = nil\ns.authors = [\"a\"]\n"),
            Vec::<&str>::new()
        );
        // Rubygems HARD-FAILS an authors list with no String elements
        // (`authors may not be empty`): [], nil, [nil], %w[] all flag.
        for empty_authors in ["[]", "[].freeze", "nil", "[nil]", "%w[]", "%W()"] {
            assert_eq!(
                gemspec_missing_required_attrs(&format!(
                    "s.summary = \"x\"\ns.authors = {empty_authors}\n"
                )),
                vec!["authors"],
                "authors = {empty_authors} must flag"
            );
        }
        // Commented-out assignments, `==` comparisons, and mid-line mentions
        // are not assignments.
        assert_eq!(
            gemspec_missing_required_attrs(
                "# s.summary = \"x\"\nraise if s.authors == [\"x\"]\nfoo(s.summary = \"x\")\n"
            ),
            vec!["summary", "authors"]
        );
        // Longer identifiers are not the attribute (`.authors` != `.author`).
        assert_eq!(
            gemspec_missing_required_attrs("s.summary_text = \"x\"\ns.author_email = \"x\"\n"),
            vec!["summary", "authors"]
        );
    }

    #[tokio::test]
    async fn test_refuses_native_extensions() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let spec = installed
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("specifications/rack-3.2.6.gemspec");
        tokio::fs::write(
            &spec,
            "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  # not this: extensions_dir = \"x\"\n  s.extensions = [\"ext/rack/extconf.rb\"]\nend\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "native_extensions_unsupported");
        assert!(detail.contains("native extensions"));
        assert!(!root.join(".socket").exists());
        // Neither file touched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn test_refuses_platform_suffixed_dir() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Simulate a precompiled platform install: rack-3.2.6-x86_64-linux.
        let platform_dir = installed.parent().unwrap().join("rack-3.2.6-x86_64-linux");
        tokio::fs::rename(&installed, &platform_dir).await.unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(&root, &blobs, &platform_dir, &record, false).await);
        assert_eq!(code, "platform_gem_unsupported");
        assert!(!root.join(".socket").exists());
    }

    /// Fail-closed allowlist: an install dir whose name is neither the
    /// `<name>-<version>` leaf nor the legacy `gem` staging dir is refused —
    /// even though it is NOT a `<leaf>-<platform>` suffix, so a suffix-only
    /// check would admit it. Only the two legitimate dir names may pass.
    #[tokio::test]
    async fn test_refuses_unexpected_install_dir_name() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // A wholly-unexpected dir name: not `rack-3.2.6`, not `gem`, and not a
        // `rack-3.2.6-<suffix>` platform build.
        let odd_dir = installed.parent().unwrap().join("random-unrelated");
        tokio::fs::rename(&installed, &odd_dir).await.unwrap();

        let (code, _d) = unwrap_refused(run_vendor(&root, &blobs, &odd_dir, &record, false).await);
        assert_eq!(code, "platform_gem_unsupported");
        assert!(!root.join(".socket").exists());
    }

    /// A native `?platform=` qualifier (e.g. `x86_64-linux`) is refused as a
    /// platform-specific build EVEN when the resolved install dir is the clean
    /// portable leaf — the purl qualifier is the authoritative signal.
    #[tokio::test]
    async fn test_refuses_native_platform_qualifier() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // installed dir is the pristine `rack-3.2.6` leaf; only the purl says
        // this is a native build.
        let purl = "pkg:gem/rack@3.2.6?platform=x86_64-linux";
        let (code, detail) =
            unwrap_refused(run_vendor_purl(purl, &root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "platform_gem_unsupported");
        assert!(
            detail.contains("x86_64-linux"),
            "refusal names the offending platform: {detail}"
        );
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    /// A pure-ruby gem in the legacy `gem` staging dir (still admitted, though
    /// a server download now stages at `<name>-<version>`) vendors
    /// with the purl's `?platform=ruby` (the portable default) — the staging
    /// dir name is not a platform signal.
    #[tokio::test]
    async fn test_platform_ruby_gem_from_autofetch_staging_dir_vendors() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Rename the install dir to the legacy `gem` staging leaf. The
        // sibling `specifications/rack-3.2.6.gemspec` (needed by the local
        // build) is derived from installed_dir.parent().parent(),
        // so keeping the dir under the same gem_home preserves it.
        let staged = installed.parent().unwrap().join("gem");
        tokio::fs::rename(&installed, &staged).await.unwrap();

        let purl = "pkg:gem/rack@3.2.6?platform=ruby";
        let (result, _entry, _w) =
            unwrap_done(run_vendor_purl(purl, &root, &blobs, &staged, &record, false).await);
        assert!(
            result.success,
            "pure-ruby (?platform=ruby) gem from an auto-fetch `gem` staging dir must vendor: {:?}",
            result.error
        );
        // The patched copy landed under the leaf, not the staging dir name.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("lib/rack.rb")).await.unwrap(),
            PATCHED
        );
    }

    #[tokio::test]
    async fn test_refuses_unparseable_declaration() {
        // (a) indented inside a group block
        let grouped =
            "source \"https://rubygems.org\"\n\ngroup :test do\n  gem \"rack\", \"~> 3.1\"\nend\n";
        let (_tmp, root, installed, blobs, record) = fixture(grouped, LOCK_DIRECT).await;
        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("indented"), "{detail}");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            grouped
        );

        // (b) multi-line declaration (trailing comma continuation)
        let multiline = "source \"https://rubygems.org\"\n\ngem \"rack\",\n  \"~> 3.1\"\n";
        let (_tmp2, root2, installed2, blobs2, record2) = fixture(multiline, LOCK_DIRECT).await;
        let (code, detail) =
            unwrap_refused(run_vendor(&root2, &blobs2, &installed2, &record2, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("continues"), "{detail}");

        // (c) already path-sourced (a previous run / a user fork)
        let pathed = "source \"https://rubygems.org\"\n\ngem \"rack\", path: \"../rack-fork\"\n";
        let (_tmp3, root3, installed3, blobs3, record3) = fixture(pathed, LOCK_DIRECT).await;
        let (code, detail) =
            unwrap_refused(run_vendor(&root3, &blobs3, &installed3, &record3, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("path:"), "{detail}");
    }

    /// SECURITY: a traversal uuid (tampered manifest) must be refused before
    /// any disk access.
    #[tokio::test]
    async fn test_refuses_traversal_uuid() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let mut bad = record.clone();
        bad.uuid = "../../escape".to_string();

        let (code, _d) = unwrap_refused(run_vendor(&root, &blobs, &installed, &bad, false).await);
        assert_eq!(code, "unsafe_coordinates");
        assert!(!root.join(".socket").exists());
        assert!(!root.parent().unwrap().join("escape").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn test_empty_gem_specs_stanza_kept() {
        // The vendored gem is the ONLY entry: the GEM section must keep its
        // empty `specs:` stanza (that is the form bundler regenerates).
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n";
        let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.2.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, lock).await;

        let (result, _e, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(
            new_lock,
            format!(
                "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
                rel = copy_rel()
            )
        );
    }

    #[tokio::test]
    async fn test_idempotent_rerun_in_sync() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success);
        assert!(r2.files_patched.is_empty(), "in-sync rerun patches nothing");
        assert!(
            r2.files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "synthesized AlreadyPatched: {:?}",
            r2.files_verified
        );
        assert!(
            e2.is_none(),
            "hot path must not re-record (would clobber the originals in the ledger)"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// Wired Gemfile+lock with a deleted committed copy: the artifact (and
    /// its stub gemspec) is rebuilt, the pair stays byte-identical, no entry.
    #[tokio::test]
    async fn test_wired_missing_copy_rebuilds_artifact_only() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let copy_root = root.join(format!(".socket/vendor/gem/{UUID}/rack-3.2.6"));
        assert!(copy_root.exists());

        crate::patch::copy_tree::remove_tree(&copy_root)
            .await
            .unwrap();

        let (r2, e2, w2) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        // Artifact-only rebuild: a refreshed fingerprint with NO wiring of
        // its own (re-recording the live pair edit as `original` would
        // break --revert; the caller carries the first run's records).
        let e2 = e2.expect("the rebuild refreshes the ledger fingerprint");
        assert!(
            e2.wiring.is_empty(),
            "no re-recorded wiring: {:?}",
            e2.wiring
        );
        assert!(
            e2.artifact.file_inventory.is_some(),
            "rebuilt tree inventoried"
        );
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {w2:?}"
        );
        assert!(
            copy_root.join("rack.gemspec").exists(),
            "stub gemspec regenerated with the rebuilt copy"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run records nothing");
        assert!(!root.join(".socket").exists(), "no copy created");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn test_unwind_on_lock_edit_failure() {
        // The lock has no GEM spec entry for rack@3.2.6 (version skew): the
        // lock edit fails AFTER the Gemfile was rewritten, so vendor must
        // unwind the Gemfile to its original bytes and drop the copy.
        let lock = LOCK_DIRECT.replace("    rack (3.2.6)", "    rack (3.1.0)");
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Gemfile.lock"));
        assert!(entry.is_none());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile unwound to its original bytes"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock,
            "lock untouched"
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "half-built copy removed"
        );
    }

    #[tokio::test]
    async fn test_revert_round_trip_direct() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile byte-identical to the fixture"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT,
            "lock byte-identical to the fixture"
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "uuid dir removed"
        );
    }

    #[tokio::test]
    async fn test_revert_round_trip_transitive() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TRANSITIVE,
            "managed block deleted, Gemfile byte-identical"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TRANSITIVE,
            "spec block moved back, added DEPENDENCIES entry deleted"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// A `bundle update` regenerated both files back to their pre-vendor
    /// registry form: that is CONVERGENCE (the reverted state is already on
    /// disk), not drift — revert stays silent (LIVENESS CONTRACT), leaves the
    /// files alone and still removes the artifact dir, so the entry can never
    /// wedge in the ledger forever.
    #[tokio::test]
    async fn test_revert_converged_files_are_silent_and_still_remove() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        tokio::fs::write(root.join(GEMFILE), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), LOCK_DIRECT)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "regenerated pre-vendor files are convergence, not drift: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "uuid dir still removed"
        );
    }

    // ── bundler ≥ 2.6 CHECKSUMS (spike: gemChecksums, bundler 2.7.2) ─────────

    const PURL_318: &str = "pkg:gem/rack@3.1.8";
    const PRISTINE_318: &[u8] = b"module Rack\n  VERSION = \"3.1.8\"\nend\n";
    const PATCHED_318: &[u8] =
        b"module Rack\n  SOCKET_PATCHED = true\n  VERSION = \"3.1.8\"\nend\n";
    const GEMSPEC_318: &str = "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.1.8\"\n  s.summary = \"a modular Ruby web server interface\"\n  s.authors = [\"Rack maintainers\"]\n  s.require_paths = [\"lib\"]\nend\n";

    // Embedded VERBATIM from a captured before/after pair (bundler
    // 2.7.2, ruby 3.3.11, aarch64-linux; the `after` lock was written by
    // bundler itself via `bundle lock`, never by hand), verified exactly this
    // pair byte-stable under `bundle install`, `BUNDLE_FROZEN=true bundle
    // install` and a from-scratch `bundle lock`.
    const SPIKE_GEMFILE_CHECKSUMS: &str =
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"3.1.8\"\n";
    const SPIKE_RACK_SHA_LINE: &str =
        "  rack (3.1.8) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1";
    const SPIKE_LOCK_CHECKSUMS_BEFORE: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.8)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  rack (= 3.1.8)\n\nCHECKSUMS\n  rack (3.1.8) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1\n\nBUNDLED WITH\n   2.7.2\n";
    const SPIKE_LOCK_CHECKSUMS_AFTER: &str = "PATH\n  remote: vendored/rack-3.1.8\n  specs:\n    rack (3.1.8)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  rack (= 3.1.8)!\n\nCHECKSUMS\n  rack (3.1.8)\n\nBUNDLED WITH\n   2.7.2\n";

    fn copy_rel_318() -> String {
        format!(".socket/vendor/gem/{UUID}/rack-3.1.8")
    }

    /// The spike `after` lock byte-for-byte, except the PATH remote points
    /// into `.socket/vendor/` instead of the spike's hand-placed `vendored/`
    /// dir — the only divergence; everything else (including the bare
    /// CHECKSUMS entry) must match bundler's own output exactly for the lock
    /// to stay byte-stable under re-lock.
    fn expected_lock_checksums() -> String {
        SPIKE_LOCK_CHECKSUMS_AFTER.replace(
            "  remote: vendored/rack-3.1.8\n",
            &format!("  remote: {}\n", copy_rel_318()),
        )
    }

    /// rack-3.1.8 twin of [`fixture`] (the CHECKSUMS spike pinned that exact
    /// version, so the oracles can embed the spike locks verbatim).
    async fn fixture_318(
        gemfile: &str,
        lock: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let installed = base.join("gem_home/gems/rack-3.1.8");
        tokio::fs::create_dir_all(installed.join("lib"))
            .await
            .unwrap();
        tokio::fs::write(installed.join("lib/rack.rb"), PRISTINE_318)
            .await
            .unwrap();
        let specs = base.join("gem_home/specifications");
        tokio::fs::create_dir_all(&specs).await.unwrap();
        tokio::fs::write(specs.join("rack-3.1.8.gemspec"), GEMSPEC_318)
            .await
            .unwrap();

        let root = base.join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join(GEMFILE), gemfile).await.unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), lock)
            .await
            .unwrap();

        let before = compute_git_sha256_from_bytes(PRISTINE_318);
        let after = compute_git_sha256_from_bytes(PATCHED_318);
        let blobs = base.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED_318)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "lib/rack.rb".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, root, installed, blobs, record)
    }

    async fn run_vendor_318(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_gem(
            PURL_318,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn test_checksums_direct_vendor_matches_spike_pair() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);

        // Lock: bundler's own path-gem output (spike G3 pair) byte-for-byte,
        // modulo the PATH remote value.
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(lock, expected_lock_checksums());

        // Ledger: the checksum rewrite is its own third record with the
        // verbatim registry line as original and the bare form as new.
        let entry = entry.expect("success must carry a ledger entry");
        assert_eq!(entry.wiring.len(), 3);
        let ck = &entry.wiring[2];
        assert_eq!(ck.file, GEMFILE_LOCK);
        assert_eq!(ck.kind, LOCK_CHECKSUM_WIRING_KIND);
        assert_eq!(ck.action, WiringAction::Rewritten);
        assert_eq!(ck.key.as_deref(), Some("rack"));
        assert_eq!(
            ck.original.as_ref().unwrap(),
            &Value::String(SPIKE_RACK_SHA_LINE.to_string())
        );
        assert_eq!(
            ck.new.as_ref().unwrap(),
            &Value::String("  rack (3.1.8)".to_string())
        );
        // The positional gemfile_lock_spec record must NOT have absorbed the
        // checksum line (its revert parses original/new by position).
        let spec = &entry.wiring[1];
        assert!(
            !spec
                .original
                .as_ref()
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l.as_str().unwrap().contains("sha256=")),
            "checksum line must not leak into gemfile_lock_spec: {:?}",
            spec.original
        );
    }

    #[tokio::test]
    async fn test_checksums_transitive_vendor_strips_only_our_token() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
        let puma_sha_line =
            "  puma (6.4.2) sha256=9c4f1f9d8f7c3a1b5e2d6c8a0b4f7e1d3c5a9b8e7f6d4c2a1b3e5d7c9f8a6b4c";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.1.8)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  puma\n\nCHECKSUMS\n{puma_sha_line}\n{SPIKE_RACK_SHA_LINE}\n\nBUNDLED WITH\n   2.7.2\n"
        );
        let (_tmp, root, installed, blobs, record) = fixture_318(gemfile, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        // Full oracle: rack moved to PATH + sorted `!` dep + bare CHECKSUMS
        // entry; puma's checksum line is byte-untouched.
        let new_lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(
            new_lock,
            format!(
                "PATH\n  remote: {rel}\n  specs:\n    rack (3.1.8)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.1.8)!\n\nCHECKSUMS\n{puma_sha_line}\n  rack (3.1.8)\n\nBUNDLED WITH\n   2.7.2\n",
                rel = copy_rel_318()
            )
        );

        // Revert restores both files byte-exactly (added dep deleted, managed
        // block removed, registry checksum line back).
        let entry = entry.unwrap();
        assert_eq!(entry.wiring.len(), 3);
        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock
        );
    }

    #[tokio::test]
    async fn test_checksums_revert_round_trip() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        // Byte-exact restore — the registry sha256 token is back (a bare
        // CHECKSUMS entry on a registry gem fails frozen installs, exit 16).
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[tokio::test]
    async fn test_checksums_idempotent_rerun_in_sync() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        // The bare CHECKSUMS entry counts as in-sync: the rerun takes the hot
        // path and records nothing.
        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success);
        assert!(e2.is_none(), "hot path must not re-record");
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    #[tokio::test]
    async fn test_checksums_already_bare_records_nothing() {
        // Spike `bare-checksum-registry-gem/before`: a registry-sourced lock
        // whose CHECKSUMS entry is already the bare form. Vendor must not
        // record our own target form as an "original" — reverting it later
        // would NOT be a restore (and per the spike a bare entry is exactly
        // what the path form needs anyway).
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, "  rack (3.1.8)");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            entry.wiring.len(),
            2,
            "already-bare entry must not produce a checksum record: {:?}",
            entry.wiring
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_checksums(),
            "the bare line is kept verbatim"
        );
    }

    #[tokio::test]
    async fn test_checksums_absent_entry_untouched() {
        // CHECKSUMS section present but no entry for our gem: bundler
        // tolerates absent entries, so vendor touches nothing there.
        let other_line =
            "  puma (6.4.2) sha256=9c4f1f9d8f7c3a1b5e2d6c8a0b4f7e1d3c5a9b8e7f6d4c2a1b3e5d7c9f8a6b4c";
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, other_line);
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            entry.unwrap().wiring.len(),
            2,
            "no checksum record for an absent entry"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_checksums().replace(
                "  rack (3.1.8)\n\nBUNDLED",
                &format!("{other_line}\n\nBUNDLED")
            ),
            "the foreign entry is byte-untouched"
        );
    }

    #[tokio::test]
    async fn test_checksums_unparseable_entry_unwinds() {
        // A CHECKSUMS line that names our gem but breaks the entry grammar
        // (lost closing paren) fails closed AFTER the Gemfile was rewritten:
        // the pair-edit unwind must restore the Gemfile bytes.
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE
            .replace(SPIKE_RACK_SHA_LINE, "  rack (3.1.8 sha256=deadbeef");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(!result.success);
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("CHECKSUMS") && err.contains("not parseable"),
            "{err}"
        );
        assert!(entry.is_none());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS,
            "Gemfile unwound to its original bytes"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock,
            "lock untouched"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[tokio::test]
    async fn test_checksums_platform_sibling_fails_closed() {
        // vendor_gem refuses platform-suffixed INSTALL dirs before the lock
        // edit, so a platform-suffixed CHECKSUMS sibling means the lock
        // disagrees with the installed tree — never guess which entries
        // bundler would collapse; fail closed and unwind.
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(
            SPIKE_RACK_SHA_LINE,
            &format!("{SPIKE_RACK_SHA_LINE}\n  rack (3.1.8-aarch64-linux) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1"),
        );
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("platform-specific"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS,
            "Gemfile unwound"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[test]
    fn test_checksums_duplicate_entries_fail_closed() {
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(
            SPIKE_RACK_SHA_LINE,
            &format!("{SPIKE_RACK_SHA_LINE}\n{SPIKE_RACK_SHA_LINE}"),
        );
        let err = match edit_lock(&lock, "rack", "3.1.8", &copy_rel_318()) {
            Err(e) => e,
            Ok(_) => panic!("duplicate CHECKSUMS entries must fail closed"),
        };
        assert!(err.contains("more than one entry"), "{err}");
    }

    #[test]
    fn test_no_checksums_lock_records_no_checksum_wiring() {
        // A lock WITHOUT a CHECKSUMS section must keep producing
        // the exact pre-CHECKSUMS output and no checksum record.
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        assert!(edit.checksum_rewrite.is_none());
        assert_eq!(edit.text, expected_lock_direct());
    }

    #[tokio::test]
    async fn test_checksums_revert_drift_warning() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // Third-party drift on ONLY the checksum line (someone hand-restored
        // a token): revert must leave that line alone with a warning, never
        // clobber it, while the other records still restore cleanly.
        let drifted_line = "  rack (3.1.8) sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let edited = wired.replace(
            "\nCHECKSUMS\n  rack (3.1.8)\n",
            &format!("\nCHECKSUMS\n{drifted_line}\n"),
        );
        assert_ne!(edited, wired, "fixture edit must hit the bare line");
        tokio::fs::write(root.join(GEMFILE_LOCK), &edited)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let drift_count = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lock_entry_drifted")
            .count();
        assert_eq!(
            drift_count, 1,
            "exactly the checksum record drifts: {:?}",
            outcome.warnings
        );
        assert!(
            outcome.kept_artifact,
            "genuine drift keeps the artifact (and the ledger entry): {:?}",
            outcome.warnings
        );
        assert!(
            root.join(copy_rel_318()).exists(),
            "the copy dir survives a drift-keep"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, drifted_line),
            "everything else restored; the drifted checksum line preserved verbatim"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    #[tokio::test]
    async fn test_stale_checksum_rerun_refused_with_guidance() {
        // A lock wired by a pre-CHECKSUMS-aware socket-patch: PATH wiring in
        // place but the registry sha256 token still on the CHECKSUMS line
        // (the spike's stale-checksum-v1-bug shape — bundler itself never
        // repairs it). The rerun must NOT report in-sync, and must refuse
        // with the revert+re-vendor repair path rather than silently editing
        // a lock it has no ledger entry for.
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, _e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let v1 = wired.replace(
            "\nCHECKSUMS\n  rack (3.1.8)\n",
            &format!("\nCHECKSUMS\n{SPIKE_RACK_SHA_LINE}\n"),
        );
        assert_ne!(v1, wired, "fixture edit must hit the bare line");
        tokio::fs::write(root.join(GEMFILE_LOCK), &v1)
            .await
            .unwrap();
        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_stale_lock_checksum");
        assert!(detail.contains("vendor --revert"), "{detail}");
        // The refusal mutates nothing.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            v1
        );
    }

    // ── multiple vendored gems: PATH sections sort like bundler's ────────────

    /// Second gem for multi-PATH tests. Its uuid sorts BEFORE rack's
    /// (`1a…` < `9f…`), so vendoring rack first is the order a naive
    /// insert-before-GEM splice would leave unsorted.
    const UUID_PUMA: &str = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
    const PURL_PUMA: &str = "pkg:gem/puma@6.4.2";
    const PRISTINE_PUMA: &[u8] = b"module Puma\n  VERSION = \"6.4.2\"\nend\n";
    const PATCHED_PUMA: &[u8] =
        b"module Puma\n  SOCKET_PATCHED = true\n  VERSION = \"6.4.2\"\nend\n";
    const GEMSPEC_PUMA: &str = "Gem::Specification.new do |s|\n  s.name = \"puma\"\n  s.version = \"6.4.2\"\n  s.summary = \"a fast, concurrent web server\"\n  s.authors = [\"Puma maintainers\"]\n  s.require_paths = [\"lib\"]\nend\n";

    fn puma_rel() -> String {
        format!(".socket/vendor/gem/{UUID_PUMA}/puma-6.4.2")
    }

    /// Add a puma install + blob + record alongside [`fixture`]'s rack, so a
    /// test can vendor TWO gems into one project.
    async fn add_puma_fixture(installed_rack: &Path, blobs: &Path) -> (PathBuf, PatchRecord) {
        let gems = installed_rack.parent().unwrap();
        let installed = gems.join("puma-6.4.2");
        tokio::fs::create_dir_all(installed.join("lib"))
            .await
            .unwrap();
        tokio::fs::write(installed.join("lib/puma.rb"), PRISTINE_PUMA)
            .await
            .unwrap();
        let specs = gems.parent().unwrap().join("specifications");
        tokio::fs::write(specs.join("puma-6.4.2.gemspec"), GEMSPEC_PUMA)
            .await
            .unwrap();
        let before = compute_git_sha256_from_bytes(PRISTINE_PUMA);
        let after = compute_git_sha256_from_bytes(PATCHED_PUMA);
        tokio::fs::write(blobs.join(&after), PATCHED_PUMA)
            .await
            .unwrap();
        let mut files = HashMap::new();
        files.insert(
            "lib/puma.rb".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let record = PatchRecord {
            uuid: UUID_PUMA.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (installed, record)
    }

    fn expected_lock_two_path() -> String {
        format!(
            "PATH\n  remote: {puma}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPATH\n  remote: {rack}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma (= 6.4.2)!\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
            puma = puma_rel(),
            rack = copy_rel()
        )
    }

    /// Bundler regenerates PATH sections sorted by source identifier — by
    /// remote path, the uuid level deciding here (verified against a real
    /// bundler 4.0.15 `bundle lock` over this exact two-PATH shape). The
    /// splice must land each new section at that sorted position no matter
    /// the vendor invocation order, or the committed lock churns on the
    /// next `bundle lock`/`bundle install`.
    #[tokio::test]
    async fn test_two_path_sections_sorted_regardless_of_vendor_order() {
        for rack_first in [true, false] {
            let (_tmp, root, installed_rack, blobs, record_rack) =
                fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let (installed_puma, record_puma) = add_puma_fixture(&installed_rack, &blobs).await;
            let runs: [(&str, &Path, &PatchRecord); 2] = if rack_first {
                [
                    (PURL, &installed_rack, &record_rack),
                    (PURL_PUMA, &installed_puma, &record_puma),
                ]
            } else {
                [
                    (PURL_PUMA, &installed_puma, &record_puma),
                    (PURL, &installed_rack, &record_rack),
                ]
            };
            for (purl, installed, record) in runs {
                let (result, _e, _w) = unwrap_done(
                    run_vendor_purl(purl, &root, &blobs, installed, record, false).await,
                );
                assert!(result.success, "vendor {purl} failed: {:?}", result.error);
            }
            let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap();
            assert_eq!(lock, expected_lock_two_path(), "rack_first={rack_first}");
        }
    }

    // ── re-vendor: a patch update (new uuid, same purl) ──────────────────────

    /// Re-vendor uuid; sorts BEFORE `UUID_PUMA`'s (`0e…` < `1a…`).
    const UUID2: &str = "0e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a4b";

    /// A patch update moves the manifest to a NEW uuid for the same gem. The
    /// CLI re-vendors straight over the first run's live wiring (originals
    /// carried forward and the old uuid dir swept by the caller — no
    /// revert-first; the cargo backend pins the same design). Both pair
    /// files must be repointed in place, with `original: None` on the
    /// rewired records.
    #[tokio::test]
    async fn test_revendor_new_uuid_direct_rewires_in_place() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);

        let new_rel = format!(".socket/vendor/gem/{UUID2}/rack-3.2.6");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", path: \"{new_rel}\"\n"
            ),
            "Gemfile repointed in place"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct().replace(UUID, UUID2),
            "lock repointed in place"
        );
        // New copy built; the old uuid dir is left for the caller's
        // stale-artifact sweep (the caller owns the ledger).
        assert_eq!(
            tokio::fs::read(root.join(&new_rel).join("lib/rack.rb"))
                .await
                .unwrap(),
            PATCHED
        );
        assert!(root.join(format!(".socket/vendor/gem/{UUID}")).exists());

        // The rewired records carry `original: None` — never the old-uuid
        // lines (reverting those would "restore" a dangling vendor pointer).
        let mut entry2 = e2.expect("re-vendor emits the new ledger entry");
        assert_eq!(entry2.uuid, UUID2);
        assert_eq!(entry2.wiring.len(), 2);
        for rec in &entry2.wiring {
            assert_eq!(rec.action, WiringAction::Rewritten);
            assert!(rec.original.is_none(), "{rec:?}");
        }

        // With the caller's carry-forward applied, revert restores the
        // PRE-VENDOR files byte-exactly.
        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// Transitive form: the managed block is repointed in place (never
    /// duplicated) and the record stays `Added` with the WHOLE updated block,
    /// so a later revert deletes the fence.
    #[tokio::test]
    async fn test_revendor_new_uuid_transitive_updates_managed_block() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);

        let new_rel = format!(".socket/vendor/gem/{UUID2}/rack-3.2.6");
        let new_block = format!(
            "{MANAGED_OPEN}\ngem \"rack\", \"3.2.6\", path: \"{new_rel}\"\n{MANAGED_CLOSE}\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!("source \"https://rubygems.org\"\n\ngem \"puma\"\n{new_block}"),
            "ONE managed block, repointed — never a duplicate declaration"
        );

        let mut entry2 = e2.unwrap();
        assert_eq!(entry2.wiring[0].action, WiringAction::Added);
        assert!(entry2.wiring[0].original.is_none());
        assert_eq!(
            entry2.wiring[0].new.as_ref().unwrap(),
            &Value::String(new_block)
        );

        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TRANSITIVE
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TRANSITIVE
        );
    }

    /// A re-vendor must RE-SORT: the replacement PATH section lands wherever
    /// the NEW uuid sorts among the other vendored gems' sections, not where
    /// the old one sat.
    #[tokio::test]
    async fn test_revendor_new_uuid_resorts_path_sections() {
        let (_tmp, root, installed_rack, blobs, record_rack) =
            fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (installed_puma, record_puma) = add_puma_fixture(&installed_rack, &blobs).await;
        for (purl, installed, record) in [
            (PURL, &installed_rack, &record_rack),
            (PURL_PUMA, &installed_puma, &record_puma),
        ] {
            let (result, _e, _w) =
                unwrap_done(run_vendor_purl(purl, &root, &blobs, installed, record, false).await);
            assert!(result.success, "vendor {purl} failed: {:?}", result.error);
        }

        // The patch update moves rack to a uuid sorting BEFORE puma's.
        let mut rack2 = record_rack.clone();
        rack2.uuid = UUID2.to_string();
        let (result, _e, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed_rack, &rack2, false).await);
        assert!(result.success, "re-vendor must succeed: {:?}", result.error);

        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(
            lock,
            expected_lock_two_path()
                .replace(
                    &format!("PATH\n  remote: {puma}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPATH\n  remote: {rack}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\n", puma = puma_rel(), rack = copy_rel()),
                    &format!("PATH\n  remote: {rack}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPATH\n  remote: {puma}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\n", puma = puma_rel(), rack = copy_rel().replace(UUID, UUID2)),
                ),
            "rack's section moved to the new uuid's sorted position"
        );
    }

    /// On a re-vendor over a CHECKSUMS lock the checksum record must ride
    /// AGAIN with `original: None`: dropped, the first run's registry
    /// `sha256=` line would vanish from the ledger with the replaced entry,
    /// and a post-update revert would leave a bare CHECKSUMS entry on a
    /// registry gem (frozen installs exit 16).
    #[tokio::test]
    async fn test_revendor_new_uuid_checksums_keeps_restore_data() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_checksums().replace(UUID, UUID2)
        );

        let mut entry2 = e2.unwrap();
        assert_eq!(entry2.wiring.len(), 3, "{:?}", entry2.wiring);
        let ck = &entry2.wiring[2];
        assert_eq!(ck.kind, LOCK_CHECKSUM_WIRING_KIND);
        assert!(ck.original.is_none(), "{:?}", ck.original);
        assert_eq!(
            ck.new.as_ref().unwrap(),
            &Value::String("  rack (3.1.8)".to_string())
        );

        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE,
            "registry sha256 line restored"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    /// The GEM-specs twin of `test_checksums_platform_sibling_fails_closed`:
    /// on a bundler < 2.6 lock (no CHECKSUMS section to catch it in) a
    /// platform-suffixed sibling spec must fail the lift closed — lifting
    /// only the plain entry would leave the sibling behind as a stale
    /// registry spec.
    #[test]
    fn test_gem_specs_platform_sibling_fails_closed() {
        let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0)\n      racc (~> 1.4)\n    nokogiri (1.16.0-arm64-darwin)\n      racc (~> 1.4)\n\nPLATFORMS\n  arm64-darwin\n  ruby\n\nDEPENDENCIES\n  nokogiri\n\nBUNDLED WITH\n   2.5.22\n";
        let rel = format!(".socket/vendor/gem/{UUID}/nokogiri-1.16.0");
        let err = match edit_lock(lock, "nokogiri", "1.16.0", &rel) {
            Err(e) => e,
            Ok(_) => panic!("a platform-suffixed GEM specs sibling must fail closed"),
        };
        assert!(err.contains("platform-suffixed"), "{err}");
    }

    /// Trailing options on the declaration (`require: false`, `group: :test`,
    /// …) must survive the rewrite: dropping `require: false` auto-requires
    /// the gem at boot, changing app behavior while vendored.
    #[tokio::test]
    async fn test_rewrite_preserves_trailing_options() {
        let gemfile =
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\", require: false\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", path: \"{}\", require: false\n",
                copy_rel()
            ),
            "trailing options must survive the rewrite"
        );

        // Revert restores the original line (options and all) verbatim.
        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// #847: positional arguments the kept tail leads with (a splat, a
    /// constant, a method call) are version constraints the exact pin
    /// supersedes, so the rewrite drops them like quoted ones. The old
    /// `path: …, *V` rewrite left a Gemfile no `bundle` command could parse
    /// (a positional argument after a keyword one). Keyword options and a
    /// trailing comment still follow `path:`.
    #[tokio::test]
    async fn test_rewrite_drops_positional_constraints() {
        let rel = copy_rel();
        for (decl, want) in [
            (
                "gem \"rack\", *RV",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", ENV.fetch(\"RV\", \"~> 3.1\")",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", RACK_VERSION, require: false",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", require: false"),
            ),
            (
                "gem \"rack\", \"~> 3.1\", *RV, :require => false # web",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", :require => false # web"),
            ),
            (
                "gem \"rack\", RV, \"require\": false, **OPTS",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", \"require\": false, **OPTS"),
            ),
            (
                "gem \"rack\", Rack::VERSION, group: :web",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", group: :web"),
            ),
        ] {
            let gemfile = format!("source \"https://rubygems.org\"\n\nRV = [\"~> 3.1\"]\n{decl}\n");
            let (_tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_DIRECT).await;

            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{decl}: {:?}", result.error);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                format!("source \"https://rubygems.org\"\n\nRV = [\"~> 3.1\"]\n{want}\n"),
                "{decl}: positional constraints are dropped, options kept after `path:`"
            );

            let outcome = revert_gem(&entry.unwrap(), &root, false).await;
            assert!(outcome.success, "{decl}: {:?}", outcome.error);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile,
                "{decl}: revert restores the original line"
            );
        }
    }

    /// [`split_kept_tail`] leg by leg: commas, `=>` and `#` inside strings
    /// or brackets never split, `Const::Path` is not a `key:` label, and
    /// leading positional arguments are dropped.
    #[test]
    fn split_kept_tail_grammar() {
        for (opts, keywords, comment) in [
            ("", "", ""),
            ("require: false", "require: false", ""),
            ("*V", "", ""),
            ("*V # pinned", "", "# pinned"),
            ("ENV.fetch(\"a, b\", \"#x\")", "", ""),
            ("V, require: false", "require: false", ""),
            ("A::B, group: [:a, :b]", "group: [:a, :b]", ""),
            ("V, :require => false", ":require => false", ""),
            ("V, \"require\" => false", "\"require\" => false", ""),
            ("V, **OPTS", "**OPTS", ""),
            ("{x: 1}.fetch(:x), required?: 1", "required?: 1", ""),
        ] {
            let tail = split_kept_tail(opts);
            assert_eq!(tail.keywords, keywords, "{opts:?}");
            assert_eq!(tail.comment, comment, "{opts:?}");
        }
    }

    /// `source:` selects a registry — carried alongside the `path:` we add it
    /// is a bundler error (one source per gem), and silently dropping it
    /// would hide the user's routing. Refused like `git:`/`github:`.
    #[tokio::test]
    async fn test_refuses_source_option_declaration() {
        let gemfile =
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\", source: \"https://gems.example\"\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("source:"), "{detail}");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// `gem\t"rack"` (tab separator) is a valid ruby call. If the grammar
    /// cannot see it, the plan falls through to the transitive Append and the
    /// Gemfile ends up declaring rack TWICE (registry line + managed path:
    /// block) — bundler hard-fails every install until hand-repaired.
    #[tokio::test]
    async fn test_tab_separated_declaration_rewritten_not_duplicated() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem\t\"rack\", \"~> 3.1\"\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert!(
            !new_gemfile.contains(MANAGED_OPEN),
            "must rewrite in place, never append a duplicate declaration: {new_gemfile}"
        );
        assert!(
            !new_gemfile.contains("~> 3.1"),
            "registry declaration replaced: {new_gemfile}"
        );
        assert!(new_gemfile.contains(&copy_rel()), "{new_gemfile}");

        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// Gemfile + Gemfile.lock are USER-owned files vendor merely edits: the
    /// pair edit and every revert write must keep their permission bits (the
    /// plain atomic writer swaps in a umask-default inode — a 0600 private
    /// Gemfile silently becomes 0644; see
    /// `atomic_write_bytes_preserving_mode`). The CHECKSUMS fixture exercises
    /// all three revert writers.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_pair_edit_and_revert_preserve_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        for f in [GEMFILE, GEMFILE_LOCK] {
            tokio::fs::set_permissions(root.join(f), std::fs::Permissions::from_mode(0o600))
                .await
                .unwrap();
        }

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        for f in [GEMFILE, GEMFILE_LOCK] {
            let mode = tokio::fs::metadata(root.join(f))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f} mode reset by the vendor pair edit");
        }

        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        for f in [GEMFILE, GEMFILE_LOCK] {
            let mode = tokio::fs::metadata(root.join(f))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f} mode reset by revert");
        }
    }

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::vendor::VendorSource;

    /// A valid path-source stub (no native extensions; assigns the
    /// rubygems-required `summary` + `authors`, which every bundler major
    /// validates on path-source gemspecs).
    const SERVICE_STUB: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.summary = \"a modular Ruby web server interface\".freeze\n  s.authors = [\"Rack maintainers\".freeze]\n  s.licenses = [\"MIT\".freeze]\n  s.require_paths = [\"lib\".freeze]\nend\n";
    /// A stub that declares native extensions (must be refused).
    const SERVICE_STUB_NATIVE: &[u8] = b"Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.extensions = [\"ext/rack/extconf.rb\"]\nend\n";
    /// A DEFECTIVE stub shape: it never assigns the rubygems-required
    /// `summary` / `authors` (nor `licenses`), so bundler's path-source
    /// validation rejects it and every post-vendor `bundle install` exits 1.
    const SERVICE_STUB_INVALID: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n";

    fn sri_sha512(bytes: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha512};
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    fn gem_service_cfg(uri: &str, source: VendorSource, offline: bool) -> VendorServiceConfig {
        VendorServiceConfig {
            maven_config: None,
            source,
            client: Some(
                ApiClient::new(ApiClientOptions {
                    api_url: uri.to_string(),
                    api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                    use_public_proxy: false,
                    org_slug: Some("acme".into()),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none()),
            ),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline,
        }
    }

    /// Build a `.gem` (uncompressed outer tar holding `data.tar.gz` +
    /// `metadata.gz`). `data_files` are the inner data.tar.gz entries at the
    /// root (no prefix dir), as a real `.gem` carries them.
    fn make_gem(data_files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut data_tar = tar::Builder::new(Vec::new());
        for (rel, content) in data_files {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            data_tar.append_data(&mut h, rel, *content).unwrap();
        }
        let data_tar = data_tar.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&data_tar).unwrap();
        let data_gz = enc.finish().unwrap();
        // A token metadata.gz: the CLI service path never reads it (it uses the
        // served stub), but a real `.gem` always carries one.
        let mut menc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        menc.write_all(b"--- !ruby/object:Gem::Specification\nname: rack\n")
            .unwrap();
        let metadata_gz = menc.finish().unwrap();
        let mut outer = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("metadata.gz", metadata_gz.as_slice()),
            ("data.tar.gz", data_gz.as_slice()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            outer.append_data(&mut h, name, bytes).unwrap();
        }
        outer.into_inner().unwrap()
    }

    /// Mount the two-step granted flow: POST returns the `.gem` (tarball) and,
    /// when `stub` is `Some`, the `gem-stub-gemspec` second artifact; GET serves
    /// each artifact's bytes. `gem_sha512` / the stub's advertised sha512 are
    /// passed explicitly so a test can advertise a WRONG hash.
    async fn mount_gem_granted(
        server: &wiremock::MockServer,
        gem_bytes: &[u8],
        gem_sha512: &str,
        stub: Option<(&[u8], &str)>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let gem_path = format!("/patch/gem/rack/3.2.6/tok/{UUID}/rack-3.2.6.gem");
        let gem_url = format!("{}{gem_path}", server.uri());
        let mut artifacts = vec![serde_json::json!({
            "kind": "tarball", "url": gem_url,
            "integrity": { "sha512": gem_sha512 }
        })];
        let stub_path = format!("/patch/gem/rack/3.2.6/tok/{UUID}/rack-3.2.6.gemspec");
        if let Some((stub_bytes, stub_sha512)) = stub {
            let stub_url = format!("{}{stub_path}", server.uri());
            artifacts.push(serde_json::json!({
                "kind": "gem-stub-gemspec", "url": stub_url,
                "integrity": { "sha512": stub_sha512 }
            }));
            Mock::given(method("GET"))
                .and(path(stub_path.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(stub_bytes.to_vec()))
                .mount(server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": gem_url,
                    "purl": PURL,
                    "artifacts": artifacts
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(gem_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gem_bytes.to_vec()))
            .mount(server)
            .await;
    }

    async fn mount_gem_status(server: &wiremock::MockServer, status: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
            .mount(server)
            .await;
    }

    /// An `installed_dir` that does NOT exist on disk but is named `<leaf>` (so
    /// the platform-gem check passes): the service path must need no local copy.
    fn missing_install(root: &Path) -> PathBuf {
        root.join("no-such-install/rack-3.2.6")
    }

    fn copy_lib(root: &Path) -> PathBuf {
        root.join(format!(".socket/vendor/gem/{UUID}/rack-3.2.6/lib/rack.rb"))
    }

    fn copy_gemspec(root: &Path) -> PathBuf {
        root.join(format!(".socket/vendor/gem/{UUID}/rack-3.2.6/rack.gemspec"))
    }

    /// Service success: the prebuilt `.gem` is extracted into the copy dir, the
    /// served stub is written as `rack.gemspec` BYTE-VERBATIM (a valid stub —
    /// one assigning `summary`/`authors` — must pass the required-attribute
    /// validation untouched), the Gemfile + lock are wired, and a
    /// `vendor_prebuilt_downloaded` advisory is emitted — WITHOUT a local
    /// install (a deliberately-missing `installed_dir`).
    #[tokio::test]
    async fn service_success_extracts_gem_and_wires_lock() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (result, entry, warnings) = unwrap_done(outcome);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(tokio::fs::read(copy_lib(&root)).await.unwrap(), PATCHED);
        assert_eq!(
            tokio::fs::read(copy_gemspec(&root)).await.unwrap(),
            SERVICE_STUB
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct()
        );
        assert!(warnings
            .iter()
            .any(|w| w.code == "vendor_prebuilt_downloaded"));
    }

    /// `service` mode + a `.gem` integrity mismatch hard-fails; nothing wired.
    #[tokio::test]
    async fn service_gem_integrity_mismatch_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let wrong = sri_sha512(b"different bytes");
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &wrong, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        // The lock is untouched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// `service` mode + a stub integrity mismatch hard-fails.
    #[tokio::test]
    async fn service_stub_integrity_mismatch_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let wrong_stub = sri_sha512(b"not the stub");
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &wrong_stub))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// `service` mode + a missing stub artifact hard-fails (old un-rebuilt row /
    /// native gem): the `.gem` is present but no `gem-stub-gemspec` is served.
    #[tokio::test]
    async fn service_stub_missing_service_mode_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, None).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[tokio::test]
    async fn service_stub_missing_miss_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, None).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let error = crate::vendor::test_support::expect_failure(outcome);
        assert!(
            error.contains("prebuilt") || error.contains("patch service"),
            "{error}"
        );
    }
    /// Explicit `service` mode + a served stub
    /// that never assigns the rubygems-required `summary`/`authors` refuses
    /// with its own `vendor_prebuilt_stub_invalid` code, naming the missing
    /// attributes — writing it verbatim would make every later `bundle install`
    /// exit 1 (all bundler majors validate path-source gemspecs). No partial
    /// artifacts are left and the lock is untouched.
    #[tokio::test]
    async fn service_stub_invalid_service_mode_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("summary") && detail.contains("authors"),
            "the refusal must name the missing attributes: {detail}"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        // The lock is untouched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn service_stub_invalid_miss_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let error = crate::vendor::test_support::expect_failure(outcome);
        assert!(
            error.contains("prebuilt") || error.contains("patch service"),
            "{error}"
        );
    }
    #[tokio::test]
    async fn service_stub_invalid_auto_not_installed_refuses_truthfully() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("summary") && detail.contains("authors"),
            "the refusal must carry the served-stub defect: {detail}"
        );
        assert!(
            detail.contains("Retry after the patch service"),
            "the refusal must advise installing the gem: {detail}"
        );
        assert!(
            !detail.contains("--vendor-source=service"),
            "circular advice (service refuses on the same defect): {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    /// Invalid served stub + explicit `service` + the gem NOT installed: the hard refusal is
    /// the same as the installed case — installation is irrelevant to
    /// `service` mode, which never falls back.
    #[tokio::test]
    async fn service_stub_invalid_service_mode_not_installed_hard_fails() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("Retry after the patch service"),
            "the service refusal names the auto/build remedy: {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    /// The write choke point validates the LOCALLY-derived stub too: a
    /// corrupted `specifications/` stub missing the required attributes is an
    /// honest `gem_spec_invalid` refusal naming the file — never a vendored
    /// copy bundler will reject at install time.
    #[tokio::test]
    async fn local_stub_invalid_refuses_with_gem_spec_invalid() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let spec = installed
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("specifications/rack-3.2.6.gemspec");
        tokio::fs::write(
            &spec,
            "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\n  s.require_paths = [\"lib\"]\nend\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("summary")
                && detail.contains("authors")
                && detail.contains("served stub gemspec for rack"),
            "the refusal names the file and the missing attributes: {detail}"
        );
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// Invalid-stub heal: a project vendored before the stub check carries
    /// the invalid served stub on disk. The idempotent hot path must not re-bless it as
    /// `already_vendored`: the on-disk stub fails the required-attribute bar,
    /// routing into the artifact-only rebuild, which rewrites a valid stub
    /// with the pair edit and the ledger entry untouched.
    #[tokio::test]
    async fn wired_copy_with_invalid_stub_is_rebuilt() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (result, entry, _) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        // Simulate the pre-fix victim: the served invalid stub on disk.
        tokio::fs::write(copy_gemspec(&root), SERVICE_STUB_INVALID)
            .await
            .unwrap();

        let (result2, entry2, warnings2) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result2.success, "{:?}", result2.error);
        let entry2 = entry2.expect("the rebuild refreshes the ledger fingerprint");
        assert!(
            entry2.wiring.is_empty(),
            "artifact-only rebuild must not re-record wiring: {:?}",
            entry2.wiring
        );
        assert!(
            warnings2
                .iter()
                .any(|w| w.code == "vendor_artifact_rebuilt"),
            "the heal must surface as a rebuild, not a silent no-op: {warnings2:?}"
        );
        assert_eq!(
            tokio::fs::read_to_string(copy_gemspec(&root))
                .await
                .unwrap(),
            GEMSPEC,
            "the invalid on-disk stub must be replaced with the valid local stub"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired,
            "the heal must not touch the Gemfile"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired,
            "the heal must not touch Gemfile.lock"
        );
    }

    /// A failed hot-path artifact rebuild must
    /// never destroy the live-wired vendored copy. Drift the committed copy
    /// (bad merge / hand edit — still buildable: the path source exists and
    /// the stub is valid), then re-run with the patch content unavailable
    /// (empty blobs dir — the offline shape: a drifted file harvests no
    /// blob): the rebuild fails, but the previous — drifted yet buildable —
    /// copy, the marker, the Gemfile, and the lock must all be left exactly
    /// as they were, never a deleted uuid dir under a still-pointing pair
    /// edit.
    #[tokio::test]
    async fn failed_rebuild_preserves_live_wired_copy() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        tokio::fs::write(copy_lib(&root), b"drifted but buildable\n")
            .await
            .unwrap();

        let empty = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();
        let (r2, e2, _) = crate::vendor::test_support::expect_failed(
            run_vendor(&root, &empty, &installed, &record, false).await,
        );
        assert!(!r2.success, "rebuild must fail without patch content");
        assert!(e2.is_none());

        // The live-wired state is untouched: copy, marker, Gemfile, lock.
        assert_eq!(
            tokio::fs::read(copy_lib(&root)).await.unwrap(),
            b"drifted but buildable\n",
            "the previous committed copy must survive a failed rebuild"
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}/{VENDOR_MARKER_FILE}"))
                .exists(),
            "marker must survive"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired,
            "Gemfile untouched"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired,
            "lock untouched"
        );
        // And the failed rebuild's swap siblings never leak into the uuid dir.
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        let mut rd = tokio::fs::read_dir(&uuid_dir).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(!n.contains("socket-stage"), "stage litter: {n}");
            assert!(!n.contains("socket-old"), "backup litter: {n}");
        }
    }

    /// The swap itself must never leave less recoverable state than it
    /// started with. Force the stage rename to fail (stage absent — the same
    /// io::Error surface as a Windows file lock) with a live copy in place:
    /// the old copy must be restored byte-identical, with no backup parked
    /// beside it.
    #[tokio::test]
    async fn swap_failure_restores_previous_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("rack-3.2.6");
        tokio::fs::create_dir_all(copy.join("lib")).await.unwrap();
        tokio::fs::write(copy.join("lib/rack.rb"), b"live\n")
            .await
            .unwrap();

        let stage = stage_dir_for(&copy);
        assert!(
            swap_stage_into_place(&stage, &copy).await.is_err(),
            "swapping a missing stage must fail"
        );
        assert_eq!(
            tokio::fs::read(copy.join("lib/rack.rb")).await.unwrap(),
            b"live\n",
            "the previous copy must be restored after a failed swap"
        );
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// Same destroy class, service leg: a wired-but-stale hot-path rebuild
    /// whose served `.gem` fails to extract (garbage bytes behind a correct
    /// SRI) hard-fails — and must leave the drifted-but-present copy and the
    /// live pair edit exactly as they were, not delete the uuid dir the
    /// Gemfile `path:` still points at.
    #[tokio::test]
    async fn failed_service_rebuild_preserves_live_wired_copy() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, _, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        tokio::fs::write(copy_lib(&root), b"drifted but buildable\n")
            .await
            .unwrap();

        let garbage = b"not a gem archive".to_vec();
        let sri = sri_sha512(&garbage);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &garbage, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_extract_failed");

        assert_eq!(
            tokio::fs::read(copy_lib(&root)).await.unwrap(),
            b"drifted but buildable\n",
            "the previous committed copy must survive a failed service rebuild"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired
        );
    }

    #[tokio::test]
    async fn service_unavailable_miss_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "not_found").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let error = crate::vendor::test_support::expect_failure(outcome);
        assert!(
            error.contains("prebuilt") || error.contains("patch service"),
            "{error}"
        );
    }
    /// A served stub that declares native extensions is refused (defense in
    /// depth — the converter should never emit one).
    #[tokio::test]
    async fn service_native_ext_stub_hard_fails() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_NATIVE);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_NATIVE, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "native_extensions_unsupported");
    }

    /// `--offline` + `--vendor-source=service` refuses without any network.
    #[tokio::test]
    async fn offline_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                "http://127.0.0.1:1",
                VendorSource::Service,
                true,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_service_offline_conflict");
    }

    // ── empty-wiring guards ──────────────────────────────────────────────

    const GEMFILE_PINNED: &str =
        "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\"\n";
    const LOCK_PINNED: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)\n\nBUNDLED WITH\n   2.5.22\n";

    /// The empty-wiring revert guard: an entry without recoverable wiring must FAIL loudly — deleting the artifact would
    /// strand the Gemfile `path:` + lock PATH section on a dead dir. The
    /// files and the artifact stay untouched.
    #[tokio::test]
    async fn revert_refuses_empty_wiring_entry() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let mut entry = entry.expect("wired entry");
        entry.wiring = Vec::new();

        let gemfile_before = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_before = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        for dry_run in [true, false] {
            let outcome = revert_gem(&entry, &root, dry_run).await;
            assert!(!outcome.success, "dry_run={dry_run}: must fail loudly");
            let err = outcome.error.expect("error detail");
            assert!(err.contains("vendor_wiring_unknown"), "{err}");
            assert!(err.contains("Gemfile"), "names the files to clean: {err}");
        }
        assert!(
            root.join(copy_rel()).join("lib/rack.rb").is_file(),
            "the artifact must NOT be deleted"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_before
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_before
        );
    }

    /// The empty-wiring refusal applies under `keep_artifact`
    /// (`--preserve-state`) TOO: a preserve-state
    /// rollback that cannot restore the wiring must not report the system
    /// restored while the pair edit still wires the vendored dir in (the
    /// patch would silently stay applied). Pins that decision.
    #[tokio::test]
    async fn preserve_state_revert_refuses_empty_wiring_entry() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let mut entry = entry.expect("wired entry");
        entry.wiring = Vec::new();

        let gemfile_before = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_before = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        for dry_run in [true, false] {
            let outcome = revert_gem_opts(
                &entry,
                &root,
                RevertOpts {
                    dry_run,
                    keep_artifact: true,
                },
            )
            .await;
            assert!(
                !outcome.success,
                "dry_run={dry_run}: must refuse under keep_artifact too"
            );
            let err = outcome.error.expect("error detail");
            assert!(err.contains("vendor_wiring_unknown"), "{err}");
        }
        assert!(
            root.join(copy_rel()).join("lib/rack.rb").is_file(),
            "the artifact must NOT be deleted"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_before
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_before
        );
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted as `Gemfile.lock` must fail fast instead of wedging
    /// every lock reader — vendor's pair read and revert's three restore
    /// readers — forever in an `open(2)` that waits for a writer that never
    /// comes. Same `open_regular_file` guard class as the composer.lock /
    /// Cargo.lock twins. Vendor refuses loudly; revert fails without
    /// deleting the artifacts (what to restore can't be determined).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_instead_of_wedging() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        // A real vendor run first so revert has a live ledger entry.
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();

        let lock_path = root.join(GEMFILE_LOCK);
        tokio::fs::remove_file(&lock_path).await.unwrap();
        mkfifo(&lock_path);

        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime waits for on shutdown; connect a writer to release it so
        // the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let all = async {
            (
                run_vendor(&root, &blobs, &installed, &record, false).await,
                revert_gem(&entry, &root, false).await,
            )
        };
        let Ok((vendor_outcome, revert_outcome)) = tokio::time::timeout(deadline, all).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&lock_path);
            panic!("Gemfile.lock reads must fail fast on a FIFO");
        };
        let (code, detail) = unwrap_refused(vendor_outcome);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(
            detail.contains("unreadable"),
            "a squatted lock is unreadable, not missing: {detail}"
        );
        assert!(
            !revert_outcome.success,
            "revert must fail when the lock can't be read: {revert_outcome:?}"
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "failed revert must not delete the artifacts"
        );
    }

    /// A declaration the strict line grammar cannot see — `gem"rack"` with no
    /// separator, `gem ("rack")` with a space before the paren; both valid
    /// Ruby — must REFUSE, never fall through to the transitive Append plan:
    /// appending the managed block next to the unseen declaration leaves the
    /// Gemfile declaring the gem TWICE, and bundler hard-fails every install
    /// on the duplicate until hand-repaired (the redirect rewriter gates its
    /// append with the same looser `declared_re` probe).
    #[tokio::test]
    async fn unrecognized_gem_call_refuses_instead_of_duplicating() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem\"rack\", \"~> 3.1\"\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile,
            "refusal must write nothing: {detail}"
        );

        // The space-before-paren call form (single-arg, valid Ruby) is the
        // same class: unseen by the grammar, so the plan must refuse too.
        let spaced = "source \"https://rubygems.org\"\n\ngem (\"rack\")\n";
        assert!(
            plan_gemfile_edit(spaced, "rack", "3.2.6", &copy_rel()).is_err(),
            "a space-before-paren declaration must refuse, not Append"
        );
    }

    /// #482: a DIRECT dependency declared where the line grammar cannot see
    /// it (`eval_gemfile`, a loop) is listed under the lock's DEPENDENCIES.
    /// Appending the managed block would declare it twice and bundler
    /// refuses every install, so the plan must refuse before any write.
    #[tokio::test]
    async fn direct_dependency_declared_out_of_sight_refuses_instead_of_appending() {
        for gemfile in [
            "source \"https://rubygems.org\"\n\ngem \"puma\"\neval_gemfile \"Gemfile.common\"\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n%w[rack].each { |g| gem g, \"~> 3.1\" }\n",
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;
            let (code, detail) =
                unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert_eq!(code, "gemfile_declaration_not_editable", "{gemfile}");
            assert!(detail.contains("direct dependency"), "{detail}");
            assert!(!root.join(".socket").exists());
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile,
                "refusal must write nothing: {detail}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                LOCK_DIRECT
            );
        }
    }

    /// Re-vendor (new uuid) over a lock whose CHECKSUMS entry was ALREADY
    /// bare pre-vendor: the first run recorded no checksum wiring, so the
    /// re-vendor's `original: None` checksum record has nothing to
    /// carry-forward from. Revert must treat that as "nothing to restore" —
    /// the bare line still standing IS the pre-vendor state — never as
    /// drift: the pair restores byte-exactly and no
    /// `vendor_lock_entry_drifted` warning fires.
    #[tokio::test]
    async fn revendor_over_already_bare_checksum_reverts_without_drift() {
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, "  rack (3.1.8)");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry1 = e1.unwrap();
        assert_eq!(entry1.wiring.len(), 2, "already-bare: no checksum record");

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);
        let mut entry2 = e2.unwrap();

        // The caller's carry-forward finds no checksum record to fill from —
        // the record legitimately keeps `original: None`.
        carry_forward_originals(&entry1, &mut entry2);
        let ck = entry2
            .wiring
            .iter()
            .find(|w| w.kind == LOCK_CHECKSUM_WIRING_KIND)
            .expect("re-vendor rides the checksum record");
        assert!(ck.original.is_none());

        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock,
            "pre-vendor lock (bare CHECKSUMS entry) restored byte-exactly"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    /// vendor records the whole-tree file inventory (patched lib + stub
    /// gemspec) with hand-pinned plain-sha256 values.
    #[tokio::test]
    async fn vendor_records_dir_file_inventory() {
        use sha2::{Digest, Sha256};

        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        let inventory = entry
            .artifact
            .file_inventory
            .as_ref()
            .expect("dir-shaped entries record an inventory");
        assert_eq!(
            inventory.keys().collect::<Vec<_>>(),
            ["lib/rack.rb", "rack.gemspec"],
            "sorted keys, gemspec included"
        );
        assert_eq!(
            inventory["lib/rack.rb"],
            hex::encode(Sha256::digest(PATCHED))
        );
        assert_eq!(
            inventory["rack.gemspec"],
            hex::encode(Sha256::digest(GEMSPEC.as_bytes()))
        );
    }

    // ── refusal / failure legs ────

    /// [`run_vendor`] with an explicit service config (the service tests
    /// above inline this shape; the tests below share it).
    async fn run_vendor_service(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        cfg: &VendorServiceConfig,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_gem(
            PURL,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(cfg),
        )
        .await
    }

    /// Coordinate guards fire before any disk access: a non-gem purl and a
    /// version outside the plain gem-token charset (both embedded verbatim
    /// into ruby source + lock grammar) are `unsafe_coordinates` refusals
    /// that write nothing.
    #[tokio::test]
    async fn refuses_non_gem_purl_and_unsafe_tokens() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (code, detail) = unwrap_refused(
            run_vendor_purl(
                "pkg:npm/left-pad@1.0.0",
                &root,
                &blobs,
                &installed,
                &record,
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
        assert!(detail.contains("not a gem purl"), "{detail}");

        // `+` is valid in a purl version but NOT in the plain gem token
        // charset vendor may embed into the Gemfile / lock grammar.
        let (code, detail) = unwrap_refused(
            run_vendor_purl(
                "pkg:gem/rack@3.2.6+meta",
                &root,
                &blobs,
                &installed,
                &record,
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
        assert!(detail.contains("unsafe gem coordinates"), "{detail}");

        assert!(
            !root.join(".socket").exists(),
            "refusals must write nothing"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A patch record with no files is meaningless to vendor: a no-op
    /// success — no ledger entry, no copy, neither project file touched.
    #[tokio::test]
    async fn empty_record_files_is_a_noop_success() {
        let (_tmp, root, installed, blobs, mut record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        record.files.clear();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "a no-op records no ledger entry");
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert!(!root.join(".socket").exists(), "no writes at all");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// The Gemfile twin of [`fifo_lock_fails_fast_instead_of_wedging`]: a
    /// FIFO planted as the Gemfile must fail vendor's pair read fast (the
    /// `open_regular_file` guard) with the "unreadable" (not "missing")
    /// refusal, instead of wedging in `open(2)` forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_gemfile_fails_fast_instead_of_wedging() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gemfile_path = root.join(GEMFILE);
        tokio::fs::remove_file(&gemfile_path).await.unwrap();
        mkfifo(&gemfile_path);

        let deadline = std::time::Duration::from_secs(5);
        let fut = run_vendor(&root, &blobs, &installed, &record, false);
        let Ok(outcome) = tokio::time::timeout(deadline, fut).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&gemfile_path);
            panic!("Gemfile reads must fail fast on a FIFO");
        };
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "gemfile_missing");
        assert!(
            detail.contains("unreadable"),
            "a squatted Gemfile is unreadable, not missing: {detail}"
        );
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    /// Wired pair + stale copy + dry run: falls through the artifact rebuild
    /// to the verify-only preview — the copy is NOT recreated and nothing is
    /// written.
    #[tokio::test]
    async fn wired_missing_copy_dry_run_previews_without_rebuilding() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, _, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let copy_root = root.join(copy_rel());
        crate::patch::copy_tree::remove_tree(&copy_root)
            .await
            .unwrap();

        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, true).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_none(), "dry run records nothing");
        assert!(
            !copy_root.exists(),
            "a dry run must not rebuild the missing copy"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// Wired pair + stale copy + `--offline --vendor-source=service`: the
    /// artifact-rebuild path re-checks the conflict and refuses before any
    /// network or disk write.
    #[tokio::test]
    async fn wired_missing_copy_offline_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, _, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let copy_root = root.join(copy_rel());
        crate::patch::copy_tree::remove_tree(&copy_root)
            .await
            .unwrap();

        let cfg = gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, true);
        let (code, _d) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_service_offline_conflict");
        assert!(!copy_root.exists(), "refusal must not rebuild");
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    #[tokio::test]
    async fn fresh_copy_failure_cleans_up_and_touches_nothing() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_dir_all(&installed).await.unwrap();

        let (result, entry, _w) = crate::vendor::test_support::expect_failed(
            run_vendor(&root, &blobs, &installed, &record, false).await,
        );
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("patch service request failed"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "no uuid-dir husk after a failed fresh vendor"
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "the empty vendor levels this run created are pruned"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A marker-write failure is informational only (state.json is the
    /// ledger of record): a DIRECTORY squatting the marker path survives
    /// materialise (which only rebuilds the copy dir) and makes the atomic
    /// marker write fail — vendor still succeeds, entry recorded, with a
    /// `vendor_marker_write_failed` warning.
    #[tokio::test]
    async fn marker_write_failure_downgrades_to_warning() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let marker_path = root.join(format!(".socket/vendor/gem/{UUID}/{VENDOR_MARKER_FILE}"));
        tokio::fs::create_dir_all(&marker_path).await.unwrap();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "a marker failure must not drop the entry");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "{warnings:?}"
        );
        // The pair edit went through normally.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct()
        );
        assert_eq!(
            tokio::fs::read(copy_lib(&root)).await.unwrap(),
            PATCHED,
            "copy still materialised"
        );
    }

    /// A Gemfile atomic-write failure (read-only project root: the stage
    /// file cannot be created) unwinds the freshly-built uuid dir and
    /// reports an un-successful Done with both project files byte-untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn gemfile_write_failure_unwinds_uuid_dir() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Pre-create the writable uuid chain so materialise needs no write
        // under the (about to be read-only) project root itself.
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let outcome = run_vendor(&root, &blobs, &installed, &record, false).await;

        // Restore before asserting so TempDir cleanup works even on failure.
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        let (result, entry, _w) = unwrap_done(outcome);
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to write Gemfile"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(!uuid_dir.exists(), "failed pair edit unwinds the uuid dir");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    // ── service miss / failure matrix (coverage-gap legs) ─────────────────

    /// [`mount_gem_granted`], but the advertised `gem-stub-gemspec` GET
    /// returns 500 — the stub-fetch `Failed` leg.
    async fn mount_gem_granted_stub_get_fails(
        server: &wiremock::MockServer,
        gem_bytes: &[u8],
        gem_sha512: &str,
        stub_sha512: &str,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let gem_path = format!("/patch/gem/rack/3.2.6/tok/{UUID}/rack-3.2.6.gem");
        let gem_url = format!("{}{gem_path}", server.uri());
        let stub_path = format!("/patch/gem/rack/3.2.6/tok/{UUID}/rack-3.2.6.gemspec");
        let stub_url = format!("{}{stub_path}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": gem_url,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": gem_url,
                          "integrity": { "sha512": gem_sha512 } },
                        { "kind": "gem-stub-gemspec", "url": stub_url,
                          "integrity": { "sha512": stub_sha512 } }
                    ]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(gem_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gem_bytes.to_vec()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(stub_path))
            .respond_with(ResponseTemplate::new(500))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn disabled_service_config_silently_builds_locally() {
        for cfg in [
            gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, false),
            gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, true),
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let error = crate::vendor::test_support::expect_failure(
                run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
            );
            assert!(
                error.contains("prebuilt") || error.contains("service"),
                "{error}"
            );
        }
    }
    /// `service` mode + a still-building archive (`pending_build`) refuses
    /// with the "still building" detail; nothing is written.
    #[tokio::test]
    async fn service_pending_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "pending_build").await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("still building"), "{detail}");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn service_pending_auto_warns_and_builds_locally() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "pending_build").await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let error = crate::vendor::test_support::expect_failure(
            run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("prebuilt") || error.contains("service"),
            "{error}"
        );
    }
    /// `service` mode + a terminal miss (`not_found`) hard-fails naming the
    /// unavailability (the `auto` fallback leg is covered above).
    #[tokio::test]
    async fn service_unavailable_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "not_found").await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("unavailable"), "{detail}");
        assert!(!root.join(".socket").exists());
    }

    /// `service` mode + a stub-artifact GET failure (HTTP 500) hard-fails
    /// with the "could not fetch the stub gemspec" detail.
    #[tokio::test]
    async fn stub_fetch_failure_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted_stub_get_fails(&server, &gem, &sri, &stub_sri).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(
            detail.contains("could not fetch the stub gemspec"),
            "{detail}"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// `auto` + the same stub-fetch failure warns (`vendor_prebuilt_unavailable`)
    /// and builds locally with the local stub.
    #[tokio::test]
    async fn stub_fetch_failure_auto_warns_and_builds_locally() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted_stub_get_fails(&server, &gem, &sri, &stub_sri).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let error = crate::vendor::test_support::expect_failure(
            run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("prebuilt") || error.contains("service"),
            "{error}"
        );
    }
    /// `service` mode + a served `.gem` whose extracted layout misses the
    /// recorded file paths fails closed (`vendor_prebuilt_layout_mismatch`
    /// miss → `vendor_prebuilt_required` refusal); no husk is left.
    #[tokio::test]
    async fn service_layout_mismatch_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("wrong/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("unexpected layout"), "{detail}");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// `auto` + the same layout mismatch warns and falls back to the local
    /// build — the wrong-layout service bytes never land in the copy.
    #[tokio::test]
    async fn service_layout_mismatch_auto_falls_back_with_warning() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("wrong/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let error = crate::vendor::test_support::expect_failure(
            run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("prebuilt") || error.contains("service"),
            "{error}"
        );
    }
    /// A served `.gem` whose data.tar.gz carries a DIRECTORY at the stub
    /// path (`rack.gemspec/…`) makes the stub write fail — a hard
    /// `vendor_prebuilt_write_failed`, no husk.
    #[tokio::test]
    async fn service_gem_with_dir_at_stub_path_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED), ("rack.gemspec/inner.rb", b"x")]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot write the stub gemspec"), "{detail}");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A regular FILE squatting `.socket/vendor/gem` makes the service
    /// stage's `create_dir_all` fail — a hard `vendor_prebuilt_write_failed`
    /// naming the un-creatable path; the pair is untouched.
    #[tokio::test]
    async fn service_stage_create_failure_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::create_dir_all(root.join(".socket/vendor"))
            .await
            .unwrap();
        tokio::fs::write(root.join(".socket/vendor/gem"), b"not a dir")
            .await
            .unwrap();
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot create"), "{detail}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// An invalid served stub that DOES assign `licenses` must not carry the
    /// "also omits `licenses`" advisory — the empty-note branch of the
    /// invalid-stub refusal detail.
    #[tokio::test]
    async fn invalid_stub_with_licenses_omits_licenses_advisory() {
        const STUB_INVALID_WITH_LICENSE: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.licenses = [\"MIT\".freeze]\n  s.require_paths = [\"lib\".freeze]\nend\n";
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(STUB_INVALID_WITH_LICENSE);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(
            &server,
            &gem,
            &sri,
            Some((STUB_INVALID_WITH_LICENSE, &stub_sri)),
        )
        .await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(detail.contains("does not assign"), "{detail}");
        assert!(
            !detail.contains("also omits"),
            "a stub assigning licenses must not get the licenses advisory: {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    #[tokio::test]
    async fn invalid_served_and_local_stub_refuses_with_honest_note() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(
            installed
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("specifications/rack-3.2.6.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\nend\n",
        )
        .await
        .unwrap();
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("Retry after the patch service publishes a corrected artifact"),
            "the served-stub defect must ride the local refusal: {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    // ── revert guard / drift / failure legs (coverage-gap) ────────────────

    /// SECURITY: a traversal uuid in a (tamperable) ledger entry must refuse
    /// the revert before any disk access — wiring and artifact untouched.
    #[tokio::test]
    async fn revert_refuses_traversal_uuid() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let mut entry = e1.unwrap();
        entry.uuid = "../../escape".to_string();
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("non-canonical patch uuid"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired,
            "refusal happens before any wiring restore"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired
        );
        assert!(
            root.join(copy_rel()).join("lib/rack.rb").is_file(),
            "artifact untouched"
        );
    }

    /// An unrecognized wiring kind (a newer ledger) warns and continues —
    /// forward compatibility: the known records still restore byte-exactly.
    /// The unknown record is a left-alone fragment, so the copy dir it may
    /// still reference is kept (the family-wide drift-keep), never deleted
    /// under a record this build cannot read.
    #[tokio::test]
    async fn revert_unrecognized_wiring_kind_warns_and_continues() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let mut entry = e1.unwrap();
        entry.wiring.push(WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: "gemfile_lock_future_thing".to_string(),
            action: WiringAction::Added,
            key: Some("rack".to_string()),
            original: None,
            new: None,
        });

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let unknown: Vec<_> = outcome
            .warnings
            .iter()
            .filter(|w| w.detail.contains("unrecognized wiring kind"))
            .collect();
        assert_eq!(unknown.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(unknown[0].code, "vendor_lock_entry_drifted");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "known records still restore"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(
            outcome.kept_artifact && root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "an unreadable record keeps the copy dir it may reference"
        );
    }

    /// Artifact removal failing at revert's END (read-only parent dir): the
    /// wiring is ALREADY restored (it runs first) and the outcome reports
    /// the removal failure instead of a false success.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_artifact_removal_failure_reports_error_after_restore() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();

        let eco = root.join(".socket/vendor/gem");
        tokio::fs::set_permissions(&eco, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        let outcome = revert_gem(&entry, &root, false).await;
        tokio::fs::set_permissions(&eco, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to remove"),
            "{:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "the un-removable uuid dir is still there"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "wiring restored before the removal attempt"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A deleted Gemfile is reported as missing (NotFound → nothing can
    /// route through the copy via it, so NOT a drift-keep) while the lock
    /// record still restores and the artifact is still removed.
    #[tokio::test]
    async fn revert_missing_gemfile_warns_and_restores_lock() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        tokio::fs::remove_file(root.join(GEMFILE)).await.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!outcome.drift_skipped(), "{:?}", outcome.warnings);
        let missing = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lockfile_missing")
            .count();
        assert_eq!(missing, 1, "{:?}", outcome.warnings);
        assert!(!root.join(GEMFILE).exists(), "the missing file stays gone");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// A deleted lock reports BOTH lock-side records (spec + checksum, via
    /// NotFound) as missing — not drift — while the Gemfile still restores
    /// and the artifact is still removed.
    #[tokio::test]
    async fn revert_missing_lock_warns_and_restores_gemfile() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        assert_eq!(entry.wiring.len(), 3);
        tokio::fs::remove_file(root.join(GEMFILE_LOCK))
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!outcome.drift_skipped(), "{:?}", outcome.warnings);
        let missing = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lockfile_missing")
            .count();
        assert_eq!(
            missing, 2,
            "both lock-side records report the missing lock: {:?}",
            outcome.warnings
        );
        assert!(!root.join(GEMFILE_LOCK).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// Malformed / hand-stripped ledger records must degrade to a drift
    /// warning — never a partial splice. Each tamper is probed with a
    /// DRY-RUN revert (no writes), so one vendored fixture serves the whole
    /// matrix; the intact entry still reverts byte-exactly afterwards.
    #[tokio::test]
    async fn revert_tampered_ledger_records_drift_instead_of_partial_splice() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        assert_eq!(entry.wiring.len(), 3, "gemfile + lock spec + checksum");
        let wired_gemfile = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let wired_lock = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        fn t_gemfile_new_none(e: &mut VendorEntry) {
            e.wiring[0].new = None;
        }
        fn t_gemfile_original_none(e: &mut VendorEntry) {
            e.wiring[0].original = None;
        }
        fn t_lock_original_not_array(e: &mut VendorEntry) {
            e.wiring[1].original = Some(Value::Bool(true));
        }
        fn t_lock_new_remote_tampered(e: &mut VendorEntry) {
            let arr = e.wiring[1].new.as_mut().unwrap().as_array_mut().unwrap();
            arr[1] = Value::String("  broken".to_string());
        }
        fn t_checksum_new_none(e: &mut VendorEntry) {
            e.wiring[2].new = None;
        }
        type Tamper = fn(&mut VendorEntry);
        let cases: [(&str, Tamper); 5] = [
            ("gemfile record without `new`", t_gemfile_new_none),
            (
                "rewritten gemfile record without `original`",
                t_gemfile_original_none,
            ),
            (
                "lock record with non-array `original`",
                t_lock_original_not_array,
            ),
            (
                "lock record whose `new` lost its remote line",
                t_lock_new_remote_tampered,
            ),
            ("checksum record without `new`", t_checksum_new_none),
        ];
        for (label, tamper) in cases {
            let mut tampered = entry.clone();
            tamper(&mut tampered);
            let outcome = revert_gem(&tampered, &root, true).await;
            assert!(outcome.success, "{label}: {:?}", outcome.error);
            let drift = outcome
                .warnings
                .iter()
                .filter(|w| w.code == "vendor_lock_entry_drifted")
                .count();
            assert_eq!(drift, 1, "{label}: {:?}", outcome.warnings);
            assert_eq!(
                tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
                wired_gemfile,
                "{label}: dry run writes nothing"
            );
            assert_eq!(
                tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
                wired_lock,
                "{label}"
            );
            assert!(root.join(copy_rel_318()).exists(), "{label}");
        }

        // The intact entry still restores everything byte-exactly.
        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE
        );
    }

    /// The lock lost the `!` dep pin: the spec record's precondition fails →
    /// that record drifts (left alone in FULL — no partial splice) while the
    /// checksum record and Gemfile still restore.
    #[tokio::test]
    async fn revert_missing_dep_pin_leaves_lock_spec_alone() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let no_pin = wired.replace("DEPENDENCIES\n  rack (= 3.1.8)!\n", "DEPENDENCIES\n");
        assert_ne!(no_pin, wired, "fixture edit must hit the pin");
        tokio::fs::write(root.join(GEMFILE_LOCK), &no_pin)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let drift = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lock_entry_drifted")
            .count();
        assert_eq!(drift, 1, "{:?}", outcome.warnings);
        assert!(
            outcome.kept_artifact && root.join(copy_rel_318()).exists(),
            "the lock still holds the PATH section: the copy dir is kept"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            no_pin.replace(
                "CHECKSUMS\n  rack (3.1.8)\n",
                &format!("CHECKSUMS\n{SPIKE_RACK_SHA_LINE}\n")
            ),
            "checksum restored; the drifted spec fragment left alone in full"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS,
            "Gemfile still restored"
        );
    }

    /// The whole CHECKSUMS section is gone: only the checksum record drifts;
    /// the spec splice and Gemfile restore normally.
    #[tokio::test]
    async fn revert_checksums_section_gone_drifts_only_checksum_record() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let no_section = wired.replace("CHECKSUMS\n  rack (3.1.8)\n\n", "");
        assert_ne!(no_section, wired, "fixture edit must drop the section");
        tokio::fs::write(root.join(GEMFILE_LOCK), &no_section)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let drift = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lock_entry_drifted")
            .count();
        assert_eq!(drift, 1, "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE
                .replace(&format!("CHECKSUMS\n{SPIKE_RACK_SHA_LINE}\n\n"), ""),
            "spec block + dep entry restored; no CHECKSUMS resurrected"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    /// A hand-deleted managed block (the `Added` Gemfile record's written
    /// text is gone) is already in its reverted state — convergence, not
    /// drift (LIVENESS CONTRACT: an Added record with no original is
    /// reverted once absent) — so the lock restores and the artifact is
    /// removed without a drift-keep.
    #[tokio::test]
    async fn revert_added_block_gone_is_converged() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        tokio::fs::write(root.join(GEMFILE), GEMFILE_TRANSITIVE)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert!(!outcome.kept_artifact);
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TRANSITIVE
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TRANSITIVE
        );
    }

    /// The CHECKSUM reader's FIFO twin of
    /// [`fifo_lock_fails_fast_instead_of_wedging`]: on a CHECKSUMS-vendored
    /// project the checksum record is restored FIRST (reverse order), so a
    /// FIFO planted as the lock must fail revert fast through
    /// `revert_lock_checksum_record`'s guarded reader.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_revert_via_checksum_reader() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        assert_eq!(
            entry.wiring[2].kind, LOCK_CHECKSUM_WIRING_KIND,
            "checksum record is last → restored first"
        );

        let lock_path = root.join(GEMFILE_LOCK);
        tokio::fs::remove_file(&lock_path).await.unwrap();
        mkfifo(&lock_path);

        let deadline = std::time::Duration::from_secs(5);
        let fut = revert_gem(&entry, &root, false);
        let Ok(outcome) = tokio::time::timeout(deadline, fut).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&lock_path);
            panic!("the checksum revert reader must fail fast on a FIFO");
        };
        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("unreadable Gemfile.lock"),
            "{:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "failed revert must not delete the artifacts"
        );
    }

    /// Reverting one of TWO vendored gems must walk past the other's PATH
    /// section to find its own; both reverts land the fixture pair
    /// byte-exactly with zero drift.
    #[tokio::test]
    async fn multi_gem_revert_walks_past_other_path_sections() {
        let (_tmp, root, installed_rack, blobs, record_rack) =
            fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (installed_puma, record_puma) = add_puma_fixture(&installed_rack, &blobs).await;
        let (r_rack, e_rack, _) = unwrap_done(
            run_vendor_purl(PURL, &root, &blobs, &installed_rack, &record_rack, false).await,
        );
        assert!(r_rack.success, "{:?}", r_rack.error);
        let (r_puma, e_puma, _) = unwrap_done(
            run_vendor_purl(
                PURL_PUMA,
                &root,
                &blobs,
                &installed_puma,
                &record_puma,
                false,
            )
            .await,
        );
        assert!(r_puma.success, "{:?}", r_puma.error);

        // puma's PATH section sorts FIRST, so rack's revert must walk past it.
        let rack_out = revert_gem(&e_rack.unwrap(), &root, false).await;
        assert!(rack_out.success, "{:?}", rack_out.error);
        assert!(
            !rack_out
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            rack_out.warnings
        );
        let puma_out = revert_gem(&e_puma.unwrap(), &root, false).await;
        assert!(puma_out.success, "{:?}", puma_out.error);
        assert!(
            !puma_out
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            puma_out.warnings
        );

        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert!(!root
            .join(format!(".socket/vendor/gem/{UUID_PUMA}"))
            .exists());
    }

    // ── edit_lock / grammar fail-closed units (coverage-gap) ──────────────

    /// A GEM section without a `specs:` stanza is not a lock this backend
    /// understands — fail closed.
    #[test]
    fn edit_lock_missing_specs_stanza_fails_closed() {
        let lock = LOCK_DIRECT.replace("  specs:\n", "");
        assert_ne!(lock, LOCK_DIRECT);
        let err = edit_lock(&lock, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a specs:-less GEM section must fail closed");
        assert!(err.contains("no specs: stanza"), "{err}");
    }

    /// Re-vendor guards: our previous PATH section must carry exactly the
    /// shape vendor wrote — a missing spec entry and a hand-edited extra
    /// line each fail closed instead of being rewired around.
    #[test]
    fn edit_lock_revendor_path_section_guards_fail_closed() {
        let tail = "\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n";

        let lost = format!(
            "PATH\n  remote: {rel}\n  specs:\n    other (1.0)\n{tail}",
            rel = copy_rel()
        );
        let err = edit_lock(&lost, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a PATH section without its spec entry must fail closed");
        assert!(err.contains("lost its"), "{err}");

        let edited = format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n  hand: edit\n{tail}",
            rel = copy_rel()
        );
        let err = edit_lock(&edited, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a hand-edited PATH section must fail closed");
        assert!(err.contains("not the shape vendor wrote"), "{err}");
    }

    /// A non-PATH leading section (a GIT source — a real-world lock shape)
    /// keeps the legacy insert-before-GEM fallback: our PATH section lands
    /// between the GIT section and GEM, everything else byte-preserved.
    #[test]
    fn edit_lock_git_leading_section_keeps_insert_before_gem() {
        let git =
            "GIT\n  remote: https://example.com/dep.git\n  revision: abc123\n  specs:\n    dep (1.0)\n\n";
        let lock = format!("{git}{LOCK_DIRECT}");
        let edit = edit_lock(&lock, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.text, format!("{git}{}", expected_lock_direct()));
    }

    /// Tail-grammar rejects: text after the closing paren (or deeper indent)
    /// makes an entry unparseable — these `None`s are what route malformed
    /// lines into the fail-closed "not parseable" refusals.
    #[test]
    fn spec_and_checksum_entry_tail_grammar_rejects() {
        assert_eq!(spec_entry("    rack (3.2.6)"), Some(("rack", "3.2.6")));
        assert_eq!(spec_entry("    rack (3.2.6)x"), None);
        assert_eq!(
            checksum_entry("  rack (3.1.8) sha256=abc"),
            Some(("rack", "3.1.8"))
        );
        assert_eq!(checksum_entry("  rack (3.2.6)x"), None);
        assert_eq!(checksum_entry("   deep (1)"), None);
    }

    /// The in-sync hot path must skip OTHER gems' CHECKSUMS entries: a
    /// rerun over the transitive fixture (puma's registry sha line present)
    /// is a no-op that records nothing and rewrites nothing.
    #[tokio::test]
    async fn checksums_rerun_hot_path_skips_foreign_entries() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
        let puma_sha_line =
            "  puma (6.4.2) sha256=9c4f1f9d8f7c3a1b5e2d6c8a0b4f7e1d3c5a9b8e7f6d4c2a1b3e5d7c9f8a6b4c";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.1.8)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  puma\n\nCHECKSUMS\n{puma_sha_line}\n{SPIKE_RACK_SHA_LINE}\n\nBUNDLED WITH\n   2.7.2\n"
        );
        let (_tmp, root, installed, blobs, record) = fixture_318(gemfile, &lock).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            e2.is_none(),
            "puma's foreign sha line must not defeat the in-sync hot path"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// #826: the vendored rewrite replaces the declaration's whole line, so
    /// a second `;`-joined statement on it must refuse rather than vanish;
    /// a bare trailing `;` is a complete declaration and still rewrites.
    #[test]
    fn plan_gemfile_edit_semicolon_statements() {
        let rel = copy_rel();
        for gemfile in [
            "gem \"rack\", \"~> 3.1\"; gem \"rainbow\", \"3.1.1\"\n",
            "gem \"rack\", require: false;gem \"rainbow\" # pair\n",
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .expect("a second statement on the line must refuse");
            assert!(err.contains("another statement"), "{gemfile:?}: {err}");
        }
        for (gemfile, want) in [
            (
                "gem \"rack\", \"~> 3.1\";\n",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", \"~> 3.1\"; # web\n",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", require: false;\n",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", require: false"),
            ),
        ] {
            match plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel) {
                Ok(GemfilePlan::Rewrite { new_line, .. }) => {
                    assert_eq!(new_line, want, "{gemfile:?}")
                }
                Ok(_) => panic!("{gemfile:?}: expected an in-place rewrite"),
                Err(e) => panic!("{gemfile:?}: {e}"),
            }
        }
    }

    /// [`plan_gemfile_edit`]'s refusal grammar, leg by leg — a wrong Gemfile
    /// rewrite executes on every `bundle`, so each unsafe shape must name
    /// its refusal (and the `gemspec` keyword must NOT block the Append).
    #[test]
    fn plan_gemfile_edit_refusal_grammar() {
        let rel = copy_rel();

        // (`GemfilePlan` is deliberately Debug-less, so refusals are pulled
        // out via `.err()` rather than `unwrap_err`.)
        let err = plan_gemfile_edit(
            "gem \"rack\", \"~> 3.0\"\ngem \"rack\"\n",
            "rack",
            "3.2.6",
            &rel,
        )
        .err()
        .expect("duplicate declarations must refuse");
        assert!(err.contains("more than once"), "{err}");

        let err = plan_gemfile_edit("gem(\"rack\", \"~> 3.1\")\n", "rack", "3.2.6", &rel)
            .err()
            .expect("a parenthesized call must refuse");
        assert!(err.contains("parenthesized"), "{err}");

        let err = plan_gemfile_edit("gem \"rack\" if ENV[\"CI\"]\n", "rack", "3.2.6", &rel)
            .err()
            .expect("trailing non-option tokens must refuse");
        assert!(err.contains("unexpected tokens"), "{err}");

        let err = plan_gemfile_edit(
            "gem \"rack\", \"~> 3.1\" unless ENV[\"CI\"]\n",
            "rack",
            "3.2.6",
            &rel,
        )
        .err()
        .expect("a conditional declaration must refuse");
        assert!(err.contains("conditional"), "{err}");

        // #340: the shared tail guard also catches continuations and
        // modifiers the old substring checks missed.
        for (gemfile, want) in [
            ("gem \"rack\", platforms: [\n  :mri]\n", "continues"),
            ("gem \"rack\", :require =>\n  false\n", "continues"),
            (
                "gem \"rack\", \"~> 3.1\"\tunless ENV[\"CI\"]\n",
                "conditional",
            ),
            ("gem \"rack\", require: false rescue nil\n", "rescue"),
            ("gem \"rack\", \"~> 3.1\" if::FEATURE\n", "conditional"),
            ("gem \"rack\", \"~> 3.1\" unless::FEATURE\n", "conditional"),
            (
                "gem \"rack\", \"~> 3.1\" if:enabled == ENV[\"MODE\"].to_sym\n",
                "conditional",
            ),
            (
                "gem \"rack\", require: <<~REQUIRE_PATH.chomp\n  rack\nREQUIRE_PATH\n",
                "continues",
            ),
            (
                "gem \"rack\", require: <<'REQUIRE_PATH'\nrack\nREQUIRE_PATH\n",
                "continues",
            ),
            (
                "gem \"rack\", require: \"#{<<~REQUIRE_PATH}\".chomp\n  rack\nREQUIRE_PATH\n",
                "continues",
            ),
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .expect("a multi-line or modified declaration must refuse");
            assert!(err.contains(want), "{gemfile:?}: {err}");
        }

        for gemfile in [
            "gem \"rack\", mypath: \"y\"\n",
            "gem \"rack\", path: File.expand_path(\"x\")\n",
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .expect("path-shaped options must refuse");
            assert!(err.contains("path:"), "{gemfile:?}: {err}");
        }

        // #652: every git source refuses, whatever its key or spelling —
        // bundler's built-in `gitlab:`, a custom `git_source(:local)`, and
        // the string-keyed `"git" =>` — since a vendored `path:` next to it
        // is a second source bundler refuses.
        for (gemfile, tok) in [
            ("gem \"rack\", gitlab: \"rack/rack\"\n", "`gitlab:`"),
            (
                "git_source(:local) { |r| \"/srv/#{r}\" }\ngem \"rack\", local: \"rack\"\n",
                "`local:`",
            ),
            ("gem \"rack\", \"git\" => \"/srv/rack\"\n", "`\"git\" =>`"),
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .unwrap_or_else(|| panic!("{gemfile:?}: a git source must refuse"));
            assert!(err.contains(tok), "{gemfile:?}: {err}");
        }

        for options in [
            "require: { if: \"rack\" }.values",
            "require: \"<<REQUIRE_PATH\"",
            "require: '#{<<REQUIRE_PATH}'",
            "require: \"\\#{<<REQUIRE_PATH}\"",
            "group: :unless",
        ] {
            let gemfile = format!("gem \"rack\", {options}\n");
            let plan = plan_gemfile_edit(&gemfile, "rack", "3.2.6", &rel).unwrap();
            let GemfilePlan::Rewrite { new_line, .. } = plan else {
                panic!("a one-line declaration must rewrite: {gemfile}");
            };
            assert!(new_line.ends_with(options), "{new_line}");
        }

        // `gemspec name: "rack"` opens with the keyword but continues as an
        // identifier — NOT a gem-call mention; the transitive Append stays
        // available (the identifier-continuation guard must not false-fire).
        let plan = plan_gemfile_edit(
            "source \"https://rubygems.org\"\n\ngemspec name: \"rack\"\n",
            "rack",
            "3.2.6",
            &rel,
        )
        .unwrap();
        assert!(matches!(plan, GemfilePlan::Append { .. }));
    }

    /// The Append splice on a Gemfile with NO trailing newline must insert
    /// one before the managed block — never concatenate onto the last line.
    #[tokio::test]
    async fn append_inserts_newline_before_managed_block() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_TRANSITIVE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\n{MANAGED_OPEN}\ngem \"rack\", \"3.2.6\", path: \"{}\"\n{MANAGED_CLOSE}\n",
                copy_rel()
            ),
            "a newline is inserted before the block — never line concatenation"
        );
    }

    /// [`gemspec_declares_extensions`] alternate operators and the
    /// [`gemspec_attr_rhs`] line-start `==` comparison (not an assignment).
    #[test]
    fn gemspec_heuristic_operator_variants() {
        for decl in [
            "s.extensions << \"ext/e/extconf.rb\"",
            "s.extensions += [\"ext/e/extconf.rb\"]",
            "s.extensions.push(\"ext/e/extconf.rb\")",
            "s.extensions.concat([\"ext/e/extconf.rb\"])",
        ] {
            assert!(
                gemspec_declares_extensions(&format!(
                    "Gem::Specification.new do |s|\n  {decl}\nend\n"
                )),
                "{decl} must count as declaring extensions"
            );
        }
        assert!(
            !gemspec_declares_extensions("raise if s.extensions == [\"e\"]\n"),
            "a `==` comparison is not a declaration"
        );
        assert!(
            !gemspec_declares_extensions("s.extensions_dir = \"x\"\n"),
            "a longer identifier is not the attribute"
        );
        // A line-start `==` comparison is not an assignment for the
        // required-attribute bar either.
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\"\ns.authors == [\"a\"]\n"),
            vec!["authors"]
        );
    }

    // ── swap / prune / grammar / unwind edges ───────

    /// A parentless `copy_dir` (e.g. the filesystem root) has no directory to
    /// place a same-dir sibling in; the fallback nests the suffix under the
    /// copy dir itself instead of panicking.
    #[test]
    fn swap_sibling_for_parentless_copy_dir_nests_suffix() {
        assert_eq!(
            swap_sibling_for(Path::new("/"), ".socket-stage"),
            PathBuf::from("/.socket-stage")
        );
    }

    /// The stage rename failing with NO previous copy parked (fresh vendor,
    /// stage vanished): the swap must bubble the error without inventing a
    /// copy dir or leaving a backup behind.
    #[tokio::test]
    async fn swap_failure_without_previous_copy_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("rack-3.2.6");
        let stage = stage_dir_for(&copy);
        assert!(
            swap_stage_into_place(&stage, &copy).await.is_err(),
            "swapping a missing stage with no old copy must fail"
        );
        assert!(!copy.exists(), "no half-made copy dir");
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// The PARK rename itself failing hard (an unwritable uuid dir — the same
    /// io::Error surface as a Windows file lock on the copy): the error
    /// bubbles and the live copy is left exactly where it was.
    #[cfg(unix)]
    #[tokio::test]
    async fn swap_park_failure_bubbles_and_keeps_live_copy() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let dir = tempfile::tempdir().unwrap();
        let uuid = dir.path().join("uuid");
        let copy = uuid.join("rack-3.2.6");
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("f.rb"), b"live\n")
            .await
            .unwrap();
        let stage = stage_dir_for(&copy);
        tokio::fs::create_dir_all(&stage).await.unwrap();
        tokio::fs::set_permissions(&uuid, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let swapped = swap_stage_into_place(&stage, &copy).await;

        tokio::fs::set_permissions(&uuid, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        assert!(
            swapped.is_err(),
            "parking the old copy must fail under a read-only uuid dir"
        );
        assert_eq!(
            tokio::fs::read(copy.join("f.rb")).await.unwrap(),
            b"live\n",
            "the live copy must be untouched"
        );
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// `prune_empty_vendor_levels` removes exactly the three levels a failed
    /// run may have created (`<uuid>` → `gem` → `vendor`) and never climbs
    /// higher; a parentless uuid path has no levels above it and returns.
    #[tokio::test]
    async fn prune_empty_vendor_levels_removes_three_levels_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep");
        let uuid = keep.join("vendor/gem").join(UUID);
        tokio::fs::create_dir_all(&uuid).await.unwrap();
        prune_empty_vendor_levels(&uuid).await;
        assert!(
            !keep.join("vendor").exists(),
            "all three empty levels pruned"
        );
        assert!(
            keep.exists(),
            "the prune never climbs past the vendor level"
        );

        // A sibling entry keeps the `gem` level non-empty: the empty uuid
        // level is still pruned, but the climb stops there — another gem's
        // vendor state must never be collateral of this run's cleanup.
        let busy = dir.path().join("busy");
        let uuid_b = busy.join("vendor/gem").join(UUID);
        tokio::fs::create_dir_all(&uuid_b).await.unwrap();
        tokio::fs::write(busy.join("vendor/gem/other-gem-marker"), b"x")
            .await
            .unwrap();
        prune_empty_vendor_levels(&uuid_b).await;
        assert!(!uuid_b.exists(), "the empty uuid level is pruned");
        assert!(
            busy.join("vendor/gem/other-gem-marker").exists(),
            "a non-empty gem level stops the prune"
        );

        // Parentless uuid path: nothing above to prune, returns cleanly.
        prune_empty_vendor_levels(Path::new("")).await;
    }

    /// DEPENDENCIES entries are exactly 2-space-indented and specs entries
    /// exactly 4: blank rests and deeper (continuation) indentation are not
    /// entries.
    #[test]
    fn dep_and_spec_entry_names_reject_blank_and_deeper_indentation() {
        assert_eq!(dep_entry_name("  rack (~> 3.1)"), Some("rack"));
        assert_eq!(dep_entry_name("  "), None);
        assert_eq!(dep_entry_name("    base64 (>= 0.1.0)"), None);
        assert_eq!(spec_entry_name("    rack (3.2.6)"), Some("rack"));
        assert_eq!(spec_entry_name("    "), None);
        assert_eq!(spec_entry_name("      base64 (>= 0.1.0)"), None);
    }

    /// An unreadable (present but non-regular) Gemfile fails a `gemfile_line`
    /// revert loudly — unlike a MISSING one, which is reported as
    /// `vendor_lockfile_missing` (`FileMissing`, not drift) and does not
    /// block artifact removal.
    #[tokio::test]
    async fn revert_gemfile_record_unreadable_gemfile_is_an_error() {
        // The tempdir itself squats the Gemfile path: a directory is
        // readable-as-path but not a regular file, so the guarded read
        // errors with a non-NotFound kind.
        let dir = tempfile::tempdir().unwrap();
        let w = WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some("rack".to_string()),
            original: Some(Value::String("gem \"rack\", \"~> 3.1\"".to_string())),
            new: Some(Value::String(format!(
                "gem \"rack\", path: \"{}\"",
                copy_rel()
            ))),
        };
        let err = revert_gemfile_record(dir.path(), &w, true)
            .await
            .expect_err("a directory squatting the Gemfile path must error");
        assert!(err.contains("unreadable Gemfile"), "{err}");
    }

    /// A `gemfile_lock_spec` record whose `new` is not a string array is
    /// drift (`Ok(RecordRevert::Drifted)`), decided BEFORE the lock is read — proven with a
    /// lock path that would error loudly (a directory) if it were read.
    #[tokio::test]
    async fn revert_lock_record_non_array_new_is_drift_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let w = WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: LOCK_WIRING_KIND.to_string(),
            action: WiringAction::Added,
            key: Some("rack".to_string()),
            original: Some(serde_json::json!(["    rack (3.2.6)"])),
            new: Some(Value::String("not-an-array".to_string())),
        };
        let restored = revert_lock_record(dir.path(), &w, true).await.unwrap();
        assert_eq!(
            restored,
            RecordRevert::Drifted,
            "malformed `new` wiring is drift, not an error"
        );
    }

    /// The specs-splice scan steps over a line inside GEM/specs that is not
    /// a spec entry (a stray 6-space continuation with no parent entry)
    /// instead of breaking the splice or mis-sorting the restored block.
    #[test]
    fn revert_lock_text_steps_over_non_spec_lines_in_gem_specs() {
        let rel = ".socket/vendor/gem/u/aaa-1.0.0";
        let new_lines: Vec<String> = [
            "PATH",
            &format!("  remote: {rel}") as &str,
            "  specs:",
            "    aaa (1.0.0)",
            "",
            "  aaa (= 1.0.0)!",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let original_lines: Vec<String> = ["    aaa (1.0.0)", "  aaa (~> 1.0)"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let text = format!(
            "PATH\n  remote: {rel}\n  specs:\n    aaa (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n      orphan-continuation (~> 1.0)\n    zzz (1.0)\n\nDEPENDENCIES\n  aaa (= 1.0.0)!\n  zzz\n"
        );
        let restored = revert_lock_text(&text, &original_lines, &new_lines)
            .expect("an odd-but-parseable specs section must still revert");
        assert_eq!(
            restored,
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    aaa (1.0.0)\n      orphan-continuation (~> 1.0)\n    zzz (1.0)\n\nDEPENDENCIES\n  aaa (~> 1.0)\n  zzz\n"
        );
    }

    /// An anchored attribute mention that is not an assignment at all (no
    /// `=` after the attr — `.push(…)`) yields no RHS, so a push-only
    /// `authors` still fails the required-attribute bar.
    #[test]
    fn gemspec_attr_rhs_ignores_non_assignment_mentions() {
        assert!(
            gemspec_attr_rhs("s.authors.push(\"m\")\n", &["authors", "author"]).is_empty(),
            "a method call on the attribute is not an assignment"
        );
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\"\ns.authors.push(\"m\")\n"),
            vec!["authors"]
        );
    }

    #[tokio::test]
    async fn local_swap_failure_reports_move_error_and_touches_nothing() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join("rack-3.2.6.socket-old"), b"husk")
            .await
            .unwrap();

        let (result, entry, _w) = crate::vendor::test_support::expect_failed(
            run_vendor(&root, &blobs, &installed, &record, false).await,
        );
        assert!(!result.success, "the swap failure must fail the vendor");
        assert!(entry.is_none(), "no ledger entry for a failed vendor");
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("cannot move the extracted .gem into place"),
            "{err}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT,
            "lock untouched"
        );
        assert!(
            !uuid_dir.exists(),
            "a fresh-vendor failure unwinds the uuid dir"
        );
    }

    /// The SERVICE path's swap failing the same way hard-fails under its own
    /// `vendor_prebuilt_write_failed` code, with the project untouched.
    #[tokio::test]
    async fn service_swap_failure_hard_fails_and_unwinds() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join("rack-3.2.6.socket-old"), b"husk")
            .await
            .unwrap();

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(
            detail.contains("cannot move the extracted .gem into place"),
            "{detail}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT,
            "lock untouched"
        );
        assert!(
            !uuid_dir.exists(),
            "a fresh-vendor failure unwinds the uuid dir"
        );
    }

    /// A Gemfile.lock write failure AFTER the Gemfile edit landed (macOS
    /// user-immutable flag on the lock: the atomic rename fails EPERM while
    /// the Gemfile in the same dir writes fine) unwinds the Gemfile to its
    /// recorded original bytes — the pair is never left half-wired — and
    /// removes the freshly-built uuid dir.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn lock_write_failure_unwinds_gemfile_and_uuid_dir() {
        if unsafe { libc::geteuid() } == 0 {
            return; // uchg semantics under root differ — the trigger is not guaranteed
        }
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let lock_path = root.join(GEMFILE_LOCK);
        let set = std::process::Command::new("chflags")
            .arg("uchg")
            .arg(&lock_path)
            .status()
            .expect("run chflags uchg");
        assert!(set.success(), "chflags uchg must succeed");

        let outcome = run_vendor(&root, &blobs, &installed, &record, false).await;

        let cleared = std::process::Command::new("chflags")
            .arg("nouchg")
            .arg(&lock_path)
            .status()
            .expect("run chflags nouchg");
        assert!(cleared.success(), "chflags nouchg must succeed");

        let (result, entry, _w) = unwrap_done(outcome);
        assert!(
            !result.success,
            "the lock write failure must fail the vendor"
        );
        assert!(entry.is_none(), "no ledger entry for a failed vendor");
        let err = result.error.as_deref().unwrap_or("");
        assert!(err.contains("failed to write Gemfile.lock"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "the Gemfile edit must be unwound to the original bytes"
        );
        assert_eq!(
            tokio::fs::read_to_string(&lock_path).await.unwrap(),
            LOCK_DIRECT,
            "the failed rename must leave the lock byte-identical"
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "the freshly-built uuid dir is unwound"
        );
    }

    // ── source flip: the hot path decides "in sync" from the
    //    COMMITTED copy before any service call, so a service ↔ local flip
    //    between runs is a byte-identical no-op with no request. ──

    async fn flip_run(
        root: &Path,
        installed: &Path,
        blobs: &Path,
        record: &PatchRecord,
        server: &wiremock::MockServer,
    ) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        let sources = PatchSources::blobs_only(blobs);
        unwrap_done(
            crate::vendor::test_support::vendor_gem(
                PURL,
                installed,
                root,
                record,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                Some(&gem_service_cfg(
                    &server.uri(),
                    VendorSource::Service,
                    false,
                )),
            )
            .await,
        )
    }

    async fn flip_granted() -> wiremock::MockServer {
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        server
    }

    #[tokio::test]
    async fn flip_service_then_local_is_noop() {
        use crate::vendor::test_support as ts;
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let up = flip_granted().await;
        let (r1, e1, w1) = flip_run(&root, &installed, &blobs, &record, &up).await;
        assert!(r1.success && e1.is_some());
        assert!(ts::has_warning(&w1, "vendor_prebuilt_downloaded"));
        assert_eq!(
            tokio::fs::read(copy_gemspec(&root)).await.unwrap(),
            SERVICE_STUB
        );
        let before = ts::tree_snapshot(&root);
        let down = wiremock::MockServer::start().await;
        ts::mount_503(&down).await;
        let (r2, e2, w2) = flip_run(&root, &installed, &blobs, &record, &down).await;
        assert!(r2.success);
        assert!(e2.is_none());
        assert!(
            w2.iter().all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{w2:?}"
        );
        assert_eq!(before, ts::tree_snapshot(&root));
        assert_eq!(ts::request_count(&down).await, 0);
    }

    /// Vendored from the service (served stub gemspec), the
    /// committed copy is lost and rebuilt LOCALLY (local gemspec → different
    /// tree). The ledger the CLI persists must carry the rebuilt tree's
    /// inventory, and its carried-forward wiring must still revert cleanly.
    #[tokio::test]
    async fn wired_rebuild_refreshes_ledger_inventory() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(
            &server,
            &gem,
            &sri_sha512(&gem),
            Some((SERVICE_STUB, &sri_sha512(SERVICE_STUB))),
        )
        .await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);
        let (r1, e1, _) =
            unwrap_done(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert!(r1.success, "{:?}", r1.error);
        let e1 = e1.expect("first vendor records an entry");
        assert_eq!(
            crate::vendor::check_vendored_artifact(&root, &e1, &record).await,
            crate::vendor::ArtifactHealth::Healthy
        );

        tokio::fs::remove_file(copy_lib(&root)).await.unwrap();
        let (r2, e2, w2) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{w2:?}"
        );
        assert_eq!(
            tokio::fs::read_to_string(copy_gemspec(&root))
                .await
                .unwrap(),
            GEMSPEC,
            "precondition: the local rebuild used the local stub"
        );

        let ledger = match e2 {
            Some(mut fresh) => {
                crate::vendor::carry_forward_wiring(&e1, &mut fresh);
                fresh
            }
            None => e1.clone(),
        };
        assert_eq!(
            crate::vendor::check_vendored_artifact(&root, &ledger, &record).await,
            crate::vendor::ArtifactHealth::Healthy,
            "the ledger inventory must describe the rebuilt copy"
        );
        assert_eq!(
            ledger.wiring, e1.wiring,
            "Gemfile/lock revert records preserved"
        );
        let rv = revert_gem(&ledger, &root, false).await;
        assert!(rv.success, "{:?}", rv.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn integrity_mismatch_hard_fails_under_auto() {
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        for bad_stub in [false, true] {
            let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let server = wiremock::MockServer::start().await;
            let (gem_sri, stub_sri) = if bad_stub {
                (sri_sha512(&gem), sri_sha512(b"not the stub"))
            } else {
                (sri_sha512(b"different bytes"), sri_sha512(SERVICE_STUB))
            };
            mount_gem_granted(&server, &gem, &gem_sri, Some((SERVICE_STUB, &stub_sri))).await;
            let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);
            let outcome = run_vendor_service(&root, &blobs, &installed, &record, &cfg).await;
            let VendorOutcome::Refused { code, .. } = outcome else {
                panic!("bad_stub={bad_stub}: tampered bytes fell back: {outcome:?}");
            };
            assert_eq!(
                code, "vendor_prebuilt_integrity_mismatch",
                "bad_stub={bad_stub}"
            );
            assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                LOCK_DIRECT
            );
        }
    }

    /// `--vendor-source=service` with no configured client must
    /// fail closed, never quietly build locally.
    #[tokio::test]
    async fn service_mode_without_client_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let mut cfg = gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, false);
        cfg.client = None;
        let outcome = run_vendor_service(&root, &blobs, &installed, &record, &cfg).await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("service mode without a client built locally: {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(".socket").exists(), "nothing written");
    }

    // ── #775: the takeover's declaration preflight ─────────────────────

    const TAKEOVER_IDX: &str = "https://patch.socket.dev/patch-registry/gem/11111111-1111-1111-1111-111111111111/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/";

    /// A converged, CHECKSUMS-less hosted lock (restoring it needs no
    /// registry lookup, so the preflight runs offline).
    fn hosted_takeover_lock() -> String {
        format!(
            "GEM\n  remote: {TAKEOVER_IDX}\n  specs:\n    rails (7.0.0)\n\nGEM\n  remote: \
             https://rubygems.org/\n  specs:\n    puma (6.0.0)\n\nPLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  puma\n  rails (= 7.0.0)!\n\nBUNDLED WITH\n   2.4.0\n"
        )
    }

    async fn takeover_preflight(gemfile: &str) -> (Option<(&'static str, String)>, PathBuf) {
        let dir = tempfile::tempdir().unwrap().keep();
        std::fs::write(dir.join(GEMFILE), gemfile).unwrap();
        std::fs::write(dir.join(GEMFILE_LOCK), hosted_takeover_lock()).unwrap();
        let pin = crate::patch::redirect::upstream::HostedPin {
            purl: "pkg:gem/rails@7.0.0".to_string(),
            uuid: UUID.to_string(),
            files: vec![GEMFILE.to_string(), GEMFILE_LOCK.to_string()],
        };
        let opts = crate::patch::redirect::upstream::RestoreOptions {
            dry_run: false,
            offline: true,
            patch_server_origins: Vec::new(),
            bun_lockb: true,
        };
        let refusal = gem_vendor_target_preflight(&dir, "pkg:gem/rails@7.0.0", &pin, &opts).await;
        (refusal, dir)
    }

    #[tokio::test]
    async fn takeover_preflight_refuses_a_hosted_gem_inside_a_group_block() {
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n\ngroup :development do\n\
             source \"{TAKEOVER_IDX}\" do\n  gem \"rails\", \"7.0.0\"\nend\nend\n"
        );
        let (refusal, dir) = takeover_preflight(&gemfile).await;
        let (code, detail) = refusal.expect("an indented declaration is not editable");
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("indented"), "{detail}");
        // A preflight: the hosted pair is never written, even though the
        // caller's options are a wet run.
        assert_eq!(std::fs::read_to_string(dir.join(GEMFILE)).unwrap(), gemfile);
        assert_eq!(
            std::fs::read_to_string(dir.join(GEMFILE_LOCK)).unwrap(),
            hosted_takeover_lock()
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn takeover_preflight_passes_a_top_level_hosted_gem() {
        // The hosted source block is socket-patch's own wiring: evaluated on
        // the restored Gemfile, the declaration is a plain top-level line.
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n\nsource \"{TAKEOVER_IDX}\" do\n  \
             gem \"rails\", \"7.0.0\"\nend\n"
        );
        let (refusal, dir) = takeover_preflight(&gemfile).await;
        assert_eq!(refusal, None);
        assert_eq!(std::fs::read_to_string(dir.join(GEMFILE)).unwrap(), gemfile);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn takeover_preflight_leaves_a_refused_restore_to_the_takeover() {
        // A hand-edited hosted block the restore cannot unwind: the restore
        // refuses, and the takeover reports that itself
        // (`redirect_revert_failed`), not this gate.
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\ngroup :test do\nsource \"{TAKEOVER_IDX}\" do\n  \
             gem \"rails\", \"~> 7.0\"\nend\nend\n"
        );
        let (refusal, dir) = takeover_preflight(&gemfile).await;
        assert_eq!(refusal, None);
        std::fs::remove_dir_all(dir).ok();
    }

    // ── #779: a gem outside the lock's first GEM section ──────────────────

    /// Bundler 2.2+ writes one GEM section per rubygems source, sorted by
    /// remote, so a private source can put rubygems.org second.
    const GEMFILE_TWO_SOURCES: &str = "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\"\n\nsource \"https://gems.example.com\" do\n  gem \"aaa-internal\"\nend\n";
    const LOCK_TWO_SOURCES: &str = "GEM\n  remote: https://gems.example.com/\n  specs:\n    aaa-internal (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  aaa-internal!\n  puma\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";

    /// Bundler's own re-lock of [`LOCK_TWO_SOURCES`] with rack path-sourced
    /// (shape verified against bundler 4.0.17 `bundle lock --local`).
    fn expected_lock_two_sources() -> String {
        format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nGEM\n  remote: https://gems.example.com/\n  specs:\n    aaa-internal (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  aaa-internal!\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
            rel = copy_rel()
        )
    }

    /// #779: the spec sits in the second GEM section. It used to fail with
    /// "GEM specs has no entry" although the lock lists it.
    #[test]
    fn edit_lock_lifts_spec_from_second_gem_section() {
        let edit = edit_lock(LOCK_TWO_SOURCES, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.text, expected_lock_two_sources());
        assert!(!edit.rewired_ours);
        assert_eq!(
            edit.removed_spec_block,
            vec!["    rack (3.2.6)", "      base64 (>= 0.1.0)"]
        );
        assert_eq!(
            edit.source_remote.as_deref(),
            Some("  remote: https://rubygems.org/")
        );
    }

    /// The first-section case keeps its ledger shape: no source remote is
    /// recorded, so ledgers written before #779 and after it agree.
    #[test]
    fn edit_lock_first_gem_section_records_no_source_remote() {
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.source_remote, None);
        let (original, _new) = lock_record_lines(&edit);
        assert!(original.iter().all(|l| !l.starts_with("  remote: ")));
    }

    /// SECURITY/fail-closed: the same `name (version)` in two GEM sections
    /// means the lock disagrees with bundler's one-spec-per-gem model.
    /// Lifting either copy would be a guess.
    #[test]
    fn edit_lock_spec_in_two_gem_sections_fails_closed() {
        let lock = LOCK_TWO_SOURCES.replace(
            "    aaa-internal (1.0.0)\n",
            "    aaa-internal (1.0.0)\n    rack (3.2.6)\n",
        );
        let err = edit_lock(&lock, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a spec listed in two GEM sections must fail closed");
        assert!(err.contains("more than one GEM section"), "{err}");
    }

    /// SECURITY/fail-closed: a platform-suffixed sibling in ANOTHER GEM
    /// section is still a lock that disagrees with the install.
    #[test]
    fn edit_lock_platform_sibling_in_other_gem_section_fails_closed() {
        let lock = LOCK_TWO_SOURCES.replace(
            "    aaa-internal (1.0.0)\n",
            "    aaa-internal (1.0.0)\n    rack (3.2.6-x86_64-linux)\n",
        );
        let err = edit_lock(&lock, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a platform sibling in any GEM section must fail closed");
        assert!(err.contains("platform-suffixed"), "{err}");
    }

    /// #779 end to end: vendor a gem from the second GEM section, then
    /// revert. The lock is Bundler's canonical form while vendored, and
    /// revert puts the spec back into the section it came from, restoring
    /// the original bytes exactly.
    #[tokio::test]
    async fn second_gem_section_vendor_and_revert_round_trip() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TWO_SOURCES, LOCK_TWO_SOURCES).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_two_sources()
        );

        // Idempotent re-run: nothing to change.
        let lock_before = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let (r2, _e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_before
        );

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TWO_SOURCES
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TWO_SOURCES,
            "revert must restore the spec into the second GEM section"
        );
    }

    /// Re-vendor to a newer patch uuid (the spec now lives in our PATH
    /// section) keeps the source section recorded by the first run, so a
    /// later revert still targets the second GEM section.
    #[test]
    fn revert_lock_text_targets_recorded_gem_section() {
        let edit = edit_lock(LOCK_TWO_SOURCES, "rack", "3.2.6", &copy_rel()).unwrap();
        let (original, new) = lock_record_lines(&edit);
        assert_eq!(
            revert_lock_text(&edit.text, &original, &new).as_deref(),
            Some(LOCK_TWO_SOURCES)
        );
        // A regenerated lock that already put rack back into its section is
        // converged, not drifted.
        assert!(lock_record_converged(LOCK_TWO_SOURCES, &original, &new));
        // The recorded section vanished (the source was dropped): drift,
        // never a guess at another section.
        let gone = edit.text.replace(
            "  remote: https://rubygems.org/\n",
            "  remote: https://mirror.example/\n",
        );
        assert_eq!(revert_lock_text(&gone, &original, &new), None);
        assert!(!lock_record_converged(
            &LOCK_TWO_SOURCES.replace("https://rubygems.org/", "https://mirror.example/"),
            &original,
            &new
        ));
    }

    /// #779 re-vendor: a superseding patch uuid lifts the spec out of our
    /// own PATH section, and the carried-forward original still names the
    /// second GEM section, so revert restores the pre-vendor bytes.
    #[tokio::test]
    async fn second_gem_section_revendor_then_revert_restores_original() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TWO_SOURCES, LOCK_TWO_SOURCES).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = "0e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a4b".to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_two_sources().replace(UUID, &record2.uuid)
        );

        let mut entry2 = e2.unwrap();
        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TWO_SOURCES
        );
    }
}
