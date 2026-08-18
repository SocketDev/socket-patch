//! Gem (Bundler) vendor backend: the Gemfile + Gemfile.lock pair edit.
//!
//! Spike-verified mechanism (bundler 2.5 — `spikes/PHASE0-FINDINGS.txt`):
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
//!   gem keeps a BARE `  <name> (<version>)` entry (bundler 2.7.2 spike —
//!   `spikes/PHASE0-V2-FINDINGS.txt` gemChecksums G2/G3). The registry token
//!   MUST be stripped on vendor — bundler never repairs it itself (G4: a stale
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

use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::path_safety::is_safe_single_segment;
use crate::patch::redirect::gem_line_trailing_options;
use crate::utils::fs::atomic_write_bytes_preserving_mode;
use crate::utils::purl::{build_gem_purl, parse_gem_purl, purl_qualifier};

use super::common::{
    already_patched_result, copy_matches_after_hashes, done, refused, service_offline_conflict,
    synthesized_result,
};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::registry_fetch::extract_gem_data;
use super::service_fetch::{
    fetch_verified_archive, fetch_verified_secondary, SecondaryArtifactResult, ServiceArtifact,
};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

const GEMFILE: &str = "Gemfile";
const GEMFILE_LOCK: &str = "Gemfile.lock";

/// Wiring-record discriminators (`key` is the gem name for all three).
///
/// `gemfile_line`: `original`/`new` are verbatim line/block strings.
///
/// `gemfile_lock_spec`: `original` and `new` are arrays of verbatim lock
/// lines. In `original`, lines indented 4+ spaces are the gem's GEM spec
/// block and the single 2-space line (if any) is the pre-vendor DEPENDENCIES
/// entry — its absence means the gem was transitive and revert deletes the
/// added entry. In `new`, the last element is the DEPENDENCIES entry we wrote
/// and the rest is the emitted PATH section.
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

/// Vendor a gem: materialize a patched copy (plus its stub gemspec) under
/// `.socket/vendor/gem/<uuid>/<name>-<version>` and pair-edit Gemfile +
/// Gemfile.lock at it (see the module doc).
///
/// `installed_dir` is the crawler's gem dir (`<gem_home>/gems/<name>-<version>`,
/// the same root `apply` patches — manifest file keys resolve relative to it);
/// the LOCAL build's stub gemspec is derived from it
/// (`<gem_home>/specifications/<name>-<version>.gemspec` — `specifications/`
/// is a sibling of `gems/`).
///
/// `service` (when configured) lets the materialise step download the prebuilt
/// patched `.gem` + the converter's `gem-stub-gemspec` second artifact from
/// patch.socket.dev instead of copying + patching locally — no local install
/// or stub needed (`auto` falls back to the local build on a miss, `service`
/// fails closed). The wiring (Gemfile + Gemfile.lock pair edit) is identical
/// either way; only how `copy_dir` + its `<name>.gemspec` are produced differs.
///
/// Edit order: materialise → Gemfile → Gemfile.lock; a lock-edit failure
/// unwinds the Gemfile to its recorded original bytes, so the pair is never
/// left half-wired.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_gem(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some((name, version)) = parse_gem_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a gem purl: {purl}"));
    };
    // SECURITY: `uuid`, `name` and `version` come from committed, tamper-able
    // manifest data. They key the copy dir vendor creates and `--revert`
    // deletes, and — stricter than the path guard — they are embedded
    // VERBATIM into the user's Gemfile (ruby source executed on every
    // `bundle`) and into Gemfile.lock's line grammar. A quote, space, paren,
    // or newline would be a code/grammar injection, so only the plain gem
    // token charset is accepted. Reject fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("gem", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        );
    };
    if !is_safe_single_segment(name)
        || !is_safe_single_segment(version)
        || !is_plain_gem_token(name)
        || !is_plain_gem_token(version)
    {
        return refused(
            "unsafe_coordinates",
            format!("unsafe gem coordinates `{name}` @ `{version}`"),
        );
    }

    let leaf = format!("{name}-{version}");
    let copy_rel = format!("{uuid_dir_rel}/{leaf}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let copy_dir = project_root.join(&copy_rel);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if record.files.is_empty() {
        return done(
            synthesized_result(purl, &copy_dir, Vec::new(), true, None),
            None,
            Vec::new(),
        );
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
    // The old gate tested only `dir_name != leaf`, which spuriously refused
    // EVERY pure-ruby gem fetched via the registry auto-fetch ladder: that
    // path stages the pristine `.gem` into a private tempdir named literally
    // `gem` (see registry_fetch::fetch_gem), so `dir_name` was `gem`, never
    // `<name>-<version>`. Gating on the platform (not the staging dir name)
    // lets `?platform=ruby` and bare purls vendor while still refusing true
    // native builds by either signal.
    if let Some(platform) = purl_qualifier(purl, "platform") {
        if !platform.is_empty() && !platform.eq_ignore_ascii_case("ruby") {
            return refused(
                "platform_gem_unsupported",
                format!(
                    "`{name}@{version}` is a platform-specific gem build (`platform={platform}`); precompiled platform gems cannot be vendored portably"
                ),
            );
        }
    }
    let dir_name = installed_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Fail closed: only two dir names are legitimate here — the installed
    // gem's own `<name>-<version>` leaf, and the literal `gem` staging dir
    // created by the registry auto-fetch ladder (registry_fetch::fetch_gem).
    // Everything else is refused, including a `<name>-<version>-<platform>`
    // precompiled build; an allowlist (not a suffix match) means an unexpected
    // install dir name can never slip through into a vendored copy.
    if dir_name != leaf && dir_name != "gem" {
        return refused(
            "platform_gem_unsupported",
            format!(
                "installed dir `{dir_name}` is not the portable `{leaf}` gem (platform-specific or unexpected gem builds cannot be vendored portably)"
            ),
        );
    }

    // ── project files ────────────────────────────────────────────────────
    let gemfile_path = project_root.join(GEMFILE);
    let gemfile_text = match tokio::fs::read_to_string(&gemfile_path).await {
        Ok(t) => t,
        Err(_) => {
            return refused(
                "gemfile_missing",
                format!("no Gemfile at {}", gemfile_path.display()),
            );
        }
    };
    let lock_path = project_root.join(GEMFILE_LOCK);
    let lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
        Err(_) => {
            return refused(
                "vendor_lockfile_missing",
                format!(
                    "no Gemfile.lock at {} (the pair edit needs the lock)",
                    lock_path.display()
                ),
            );
        }
    };

    // ── stub gemspec (local) ─────────────────────────────────────────────
    // `specifications/` is a sibling of `gems/`; derive it from installed_dir.
    // The read is non-fatal: the LOCAL build needs this stub, but the service
    // path brings its own (the converter-generated `gem-stub-gemspec`), so an
    // auto-fetched (not-installed) gem whose only `installed_dir` is a bare
    // `data.tar.gz` extraction can still vendor via the service. The
    // `gem_spec_missing` refusal moves into the local-build fallback, where the
    // stub is actually required.
    let spec_src = installed_dir
        .parent()
        .and_then(Path::parent)
        .map(|home| home.join("specifications").join(format!("{leaf}.gemspec")));
    let spec_text: Option<String> = match &spec_src {
        Some(p) => tokio::fs::read_to_string(p).await.ok(),
        None => None,
    };
    // Textual heuristic, deliberately fail-closed on a match: bundler skips
    // extension builds for path sources entirely, so a native gem would
    // install fine and then fail at `require` time with a missing `.so`.
    // Only the local stub is checked here (when present); the service stub is
    // re-checked in `gem_service_copy`, and a native gem emits no service stub
    // at all (the converter refuses it), so the service path also misses.
    if let Some(text) = &spec_text {
        if gemspec_declares_extensions(text) {
            return refused(
                "native_extensions_unsupported",
                format!(
                    "{leaf}.gemspec declares native extensions; bundler does not build extensions for path-sourced gems"
                ),
            );
        }
    }

    // ── idempotent hot path ──────────────────────────────────────────────
    // Copy (incl. the gemspec) already carries every afterHash and both files
    // already reference the uuid path → touch nothing. `entry` stays `None`:
    // the first run's ledger entry holds the only copy of the pre-vendor
    // originals.
    let remote_line = format!("  remote: {copy_rel}");
    let lock_wired =
        lock_text.split('\n').any(|l| l == remote_line) && gemfile_text.contains(&copy_rel);
    let copy_ok = copy_matches_after_hashes(&copy_dir, &record.files).await
        && tokio::fs::metadata(copy_dir.join(format!("{name}.gemspec")))
            .await
            .is_ok();
    if lock_wired {
        if lock_checksum_in_sync(&lock_text, name, version) {
            if copy_ok {
                return done(
                    already_patched_result(purl, &copy_dir, &record.files),
                    None,
                    Vec::new(),
                );
            }
            // Wired (Gemfile + lock + CHECKSUMS) but the committed copy is
            // missing/stale: rebuild the ARTIFACT only — the pair edit is
            // already correct and the full path would re-record the live
            // vendored fragments as `original`, breaking a later --revert.
            // Service-preferred like the full path (an auto-fetched gem has no
            // local stub to rebuild from — only the service can).
            if !dry_run {
                if let Some(refusal) = service_offline_conflict(service) {
                    return refusal;
                }
                let mut warnings: Vec<VendorWarning> = Vec::new();
                let result = match materialise_patched_copy(
                    purl,
                    installed_dir,
                    &copy_dir,
                    &uuid_dir,
                    name,
                    version,
                    spec_text.as_deref(),
                    record,
                    sources,
                    force,
                    service,
                    &mut warnings,
                )
                .await
                {
                    Ok(result) => result,
                    Err(outcome) => return *outcome,
                };
                if result.success {
                    warnings.push(VendorWarning::new(
                        "vendor_artifact_rebuilt",
                        format!(
                            "the committed vendored copy for {name}@{version} was missing or \
                             stale; rebuilt at {copy_rel} (Gemfile and Gemfile.lock untouched)"
                        ),
                    ));
                }
                return done(result, None, warnings);
            }
            // Dry runs fall through to the verify-only preview below.
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
            return refused(
                "vendor_stale_lock_checksum",
                format!(
                    "Gemfile.lock already wires `{name}` to {copy_rel} but its CHECKSUMS entry is not bundler's bare path-gem form (an earlier socket-patch left the registry line in place); run `vendor --revert` for {purl} and re-vendor to repair it"
                ),
            );
        }
    }

    // ── dry run: verify-only against the installed dir, no writes ────────
    if dry_run {
        let mut dry_warnings: Vec<VendorWarning> = Vec::new();
        let mut result = super::force_apply_staged(
            purl,
            installed_dir,
            record,
            sources,
            true,
            force,
            name,
            version,
            &mut dry_warnings,
        )
        .await;
        result.package_path = copy_dir.display().to_string();
        return done(result, None, dry_warnings);
    }

    // ── Gemfile edit plan (refusals before any write) ────────────────────
    let plan = match plan_gemfile_edit(&gemfile_text, name, version, &copy_rel) {
        Ok(p) => p,
        Err(detail) => return refused("gemfile_declaration_not_editable", detail),
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
        &copy_dir,
        &uuid_dir,
        name,
        version,
        spec_text.as_deref(),
        record,
        sources,
        force,
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
    let new_gemfile = apply_gemfile_plan(&gemfile_text, &plan);
    if let Err(e) = atomic_write_bytes_preserving_mode(&gemfile_path, new_gemfile.as_bytes()).await
    {
        let _ = remove_tree(&uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write Gemfile: {e}"));
        return done(result, None, warnings);
    }

    // ── Gemfile.lock edit (a failure here unwinds the Gemfile) ───────────
    let lock_edit = match edit_lock(&lock_text, name, version, &copy_rel) {
        Ok(edit) => {
            match atomic_write_bytes_preserving_mode(&lock_path, edit.text.as_bytes()).await {
                Ok(()) => Ok(edit),
                Err(e) => Err(format!("failed to write Gemfile.lock: {e}")),
            }
        }
        Err(e) => Err(format!("failed to edit Gemfile.lock: {e}")),
    };
    let lock_edit = match lock_edit {
        Ok(edit) => edit,
        Err(mut detail) => {
            // Unwind: a Gemfile pointing at a path the lock doesn't agree
            // with is exactly the half-wired state the pair edit exists to
            // prevent — restore the recorded original bytes.
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&gemfile_path, gemfile_text.as_bytes()).await
            {
                detail.push_str(&format!(" (Gemfile unwind also failed: {e})"));
            }
            let _ = remove_tree(&uuid_dir).await;
            result.success = false;
            result.error = Some(detail);
            return done(result, None, warnings);
        }
    };

    // ── marker + ledger entry ────────────────────────────────────────────
    let base_purl = build_gem_purl(name, version);
    let marker = VendorMarker::new("gem", &base_purl, record, vendored_at);
    if let Err(e) = write_marker(&uuid_dir, &marker).await {
        // Informational only (state.json is the ledger of record) — a marker
        // failure must not fail an otherwise-wired vendor.
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write {}: {e}", super::state::VENDOR_MARKER_FILE),
        ));
    }

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
    let lock_original = if lock_edit.rewired_ours {
        None
    } else {
        let mut original_lines: Vec<Value> = lock_edit
            .removed_spec_block
            .iter()
            .map(|l| Value::String(l.clone()))
            .collect();
        if let Some(dep) = &lock_edit.old_dep_line {
            original_lines.push(Value::String(dep.clone()));
        }
        Some(Value::Array(original_lines))
    };
    let mut new_lines: Vec<Value> = lock_edit
        .path_section
        .iter()
        .map(|l| Value::String(l.clone()))
        .collect();
    new_lines.push(Value::String(lock_edit.new_dep_line.clone()));
    let lock_record = WiringRecord {
        file: GEMFILE_LOCK.to_string(),
        kind: LOCK_WIRING_KIND.to_string(),
        action: WiringAction::Rewritten,
        key: Some(name.to_string()),
        original: lock_original,
        new: Some(Value::Array(new_lines)),
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

    // Whole-tree inventory of the committed copy (stub gemspec included):
    // no lockfile integrity covers a path source's bytes, so this is the
    // only whole-artifact drift/tamper anchor verify/VEX/repair have for a
    // dir-shaped artifact. Fail-soft: an uninventoriable copy (symlink,
    // non-UTF-8 name) vendors like a pre-inventory entry, with the gap
    // surfaced here and again at repair time.
    let file_inventory = match super::verify::compute_dir_inventory(&copy_dir).await {
        Ok(inv) => Some(inv),
        Err(detail) => {
            warnings.push(VendorWarning::new(
                "vendor_inventory_unrecorded",
                format!(
                    "could not inventory the vendored copy for {name}@{version} ({detail}); \
                     drift in its unpatched files will not be detectable"
                ),
            ));
            None
        }
    };

    let entry = VendorEntry {
        ecosystem: "gem".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
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
    };

    done(result, Some(entry), warnings)
}

// ── materialisation (service download / local build) ──────────────────────────

/// The path-source stub gemspec served as the gem's SECOND artifact, alongside
/// the `.gem` (mirrors npm's `yarn-berry-zip`). The converter generates it
/// because a `.gem` only carries the gemspec as YAML in `metadata.gz`, not the
/// eval-able Ruby form a bundler path source loads.
const GEM_STUB_ARTIFACT_KIND: &str = "gem-stub-gemspec";

/// Outcome of attempting to materialise the gem copy from the patch service.
enum GemServiceCopy {
    /// The prebuilt `.gem` was extracted into `copy_dir` and the verified stub
    /// gemspec written as `<name>.gemspec`.
    Used,
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
    /// Fall back to copying the installed gem + local stub and patching it.
    FallBack,
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
/// in depth.
async fn gem_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    copy_dir: &Path,
    uuid_dir: &Path,
    warnings: &mut Vec<VendorWarning>,
) -> GemServiceCopy {
    let Some(cfg) = service else {
        return GemServiceCopy::FallBack;
    };
    if !cfg.service_enabled() {
        return GemServiceCopy::FallBack;
    }
    fn hard(code: &'static str, detail: String) -> GemServiceCopy {
        GemServiceCopy::HardFail(Box::new(refused(code, detail)))
    }
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            GemServiceCopy::FallBack
        }
    };

    // Step 1: the prebuilt `.gem` (sha512-verified against the reference).
    let archive = match fetch_verified_archive(cfg, &record.uuid).await {
        ServiceArtifact::Ready(archive) => archive,
        ServiceArtifact::IntegrityMismatch(reason) => {
            return miss(
                warnings,
                "vendor_prebuilt_integrity_mismatch",
                format!("prebuilt .gem failed integrity ({reason})"),
            );
        }
        ServiceArtifact::Pending => {
            return miss(
                warnings,
                "vendor_prebuilt_pending",
                "prebuilt .gem is still building".to_string(),
            );
        }
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                return hard(
                    "vendor_prebuilt_required",
                    format!("prebuilt .gem unavailable: {reason}"),
                );
            }
            return GemServiceCopy::FallBack;
        }
        ServiceArtifact::Failed(reason) => {
            return miss(
                warnings,
                "vendor_prebuilt_unavailable",
                format!("patch service request failed ({reason})"),
            );
        }
    };

    // Step 2: the stub gemspec the converter generated alongside the `.gem`.
    let stub = match fetch_verified_secondary(cfg, &archive, GEM_STUB_ARTIFACT_KIND).await {
        SecondaryArtifactResult::Ready(bytes) => bytes,
        SecondaryArtifactResult::Absent => {
            return miss(
                warnings,
                "vendor_prebuilt_stub_missing",
                "the patch service served no stub gemspec for this gem (a native-extension \
                 gem, or a patch built before the stub rollout)"
                    .to_string(),
            );
        }
        SecondaryArtifactResult::IntegrityMismatch(reason) => {
            return miss(
                warnings,
                "vendor_prebuilt_integrity_mismatch",
                format!("prebuilt stub gemspec failed integrity ({reason})"),
            );
        }
        SecondaryArtifactResult::Failed(reason) => {
            return miss(
                warnings,
                "vendor_prebuilt_unavailable",
                format!("could not fetch the stub gemspec ({reason})"),
            );
        }
    };

    // Defense in depth: the converter does not emit a stub for native gems, but
    // refuse one here too — bundler silently skips extension builds for path
    // sources, so a native gem would install and then fail at `require` time.
    if gemspec_declares_extensions(&String::from_utf8_lossy(&stub)) {
        return hard(
            "native_extensions_unsupported",
            format!(
                "the served stub gemspec for {name} declares native extensions; bundler does \
                 not build extensions for path-sourced gems"
            ),
        );
    }

    // Extract the patched `.gem`'s data.tar.gz into a clean copy dir, then add
    // the stub as `<name>.gemspec` (a `.gem`'s data.tar.gz never carries one —
    // the gemspec lives in metadata.gz).
    let _ = remove_tree(copy_dir).await;
    if let Err(e) = tokio::fs::create_dir_all(copy_dir).await {
        return hard(
            "vendor_prebuilt_write_failed",
            format!("cannot create {}: {e}", copy_dir.display()),
        );
    }
    if let Err(e) = extract_gem_data(&archive.bytes, copy_dir) {
        let _ = remove_tree(uuid_dir).await;
        return hard(
            "vendor_prebuilt_extract_failed",
            format!("cannot extract the prebuilt .gem: {e}"),
        );
    }
    if let Err(e) = tokio::fs::write(copy_dir.join(format!("{name}.gemspec")), &stub).await {
        let _ = remove_tree(uuid_dir).await;
        return hard(
            "vendor_prebuilt_write_failed",
            format!("cannot write the stub gemspec into the vendored dir: {e}"),
        );
    }
    // Verify the EXTRACTED data.tar.gz tree, not just the .gem bytes: the
    // SRI proves the download is intact, but an unexpected internal layout
    // lands the patched files at the wrong paths and the caller would
    // synthesize success from `record.files` while the copy is wrong. (The
    // stub gemspec we just wrote is not in record.files, so it is not part
    // of this check.) Fail closed → `auto` falls back to the local build.
    // (Mirrors composer_lock.rs.)
    if !copy_matches_after_hashes(copy_dir, &record.files).await {
        let _ = remove_tree(uuid_dir).await;
        return miss(
            warnings,
            "vendor_prebuilt_layout_mismatch",
            format!(
                "prebuilt .gem for {name} extracted to an unexpected layout \
                 (patched files absent at their recorded paths)"
            ),
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
/// `ApplyResult` (the caller returns it as a `Done` with no ledger entry); this
/// helper cleans up its own partial copy in that case.
#[allow(clippy::too_many_arguments)]
async fn materialise_patched_copy(
    purl: &str,
    installed_dir: &Path,
    copy_dir: &Path,
    uuid_dir: &Path,
    name: &str,
    version: &str,
    spec_text: Option<&str>,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<ApplyResult, Box<VendorOutcome>> {
    match gem_service_copy(service, record, name, copy_dir, uuid_dir, warnings).await {
        GemServiceCopy::Used => {
            // The service `.gem` is the patched package; trust its verified
            // integrity (every file reads as AlreadyPatched).
            Ok(already_patched_result(purl, copy_dir, &record.files))
        }
        GemServiceCopy::HardFail(outcome) => Err(outcome),
        GemServiceCopy::FallBack => {
            // The local build needs the stub gemspec from the installed gem's
            // `specifications/` dir — absent for an auto-fetched (not-installed)
            // gem, whose only route is the service path.
            let Some(spec_text) = spec_text else {
                return Err(Box::new(refused(
                    "gem_spec_missing",
                    format!(
                        "no local stub gemspec for {name}@{version} (a path source cannot be \
                         wired without one); install the gem or use --vendor-source=service"
                    ),
                )));
            };
            if let Err(e) = fresh_copy(installed_dir, copy_dir, None).await {
                return Ok(synthesized_result(
                    purl,
                    copy_dir,
                    Vec::new(),
                    false,
                    Some(format!("failed to copy installed gem: {e}")),
                ));
            }
            // The vendored dir is freshly created and not yet referenced by
            // anything, so a plain write suffices for the gemspec.
            if let Err(e) =
                tokio::fs::write(copy_dir.join(format!("{name}.gemspec")), spec_text).await
            {
                let _ = remove_tree(uuid_dir).await;
                return Ok(synthesized_result(
                    purl,
                    copy_dir,
                    Vec::new(),
                    false,
                    Some(format!(
                        "failed to copy the stub gemspec into the vendored dir: {e}"
                    )),
                ));
            }
            let mut result = super::force_apply_staged(
                purl, copy_dir, record, sources, false, force, name, version, warnings,
            )
            .await;
            result.package_path = copy_dir.display().to_string();
            if !result.success {
                // Don't leave a half-built copy; neither project file was touched.
                let _ = remove_tree(uuid_dir).await;
            }
            Ok(result)
        }
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

    // Fail-closed guard: an entry with NO wiring records (a ledger repair
    // reconstructed without recoverable wiring, or a hand-stripped
    // state.json) must not "succeed" by deleting the artifact — the
    // Gemfile `path:` and the lock's PATH section would keep pointing at
    // the removed dir and the next `bundle install` hard-fails. Refuse
    // loudly with the manual cleanup steps instead. (Every entry
    // `vendor_gem` records carries at least the Gemfile + lock records.)
    if entry.wiring.is_empty() {
        let name = parse_gem_purl(&entry.base_purl)
            .map(|(n, _)| n)
            .unwrap_or("<unknown>");
        return RevertOutcome::failed(format!(
            "vendor_wiring_unknown: the ledger records no wiring for `{name}` (a \
             reconstructed entry without recoverable originals); refusing to delete {} and \
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
        match restored {
            Ok(true) => {}
            Ok(false) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{} no longer carries what vendor wrote for {}; left alone",
                    w.file,
                    w.key.as_deref().unwrap_or("<unknown>")
                ),
            )),
            Err(e) => {
                return RevertOutcome {
                    success: false,
                    warnings,
                    error: Some(e),
                };
            }
        }
    }

    if !dry_run {
        if let Err(e) = remove_tree(&uuid_dir).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("failed to remove {}: {e}", uuid_dir.display())),
            };
        }
    }

    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

// ── ledger reconstruction ───────────────────────────────────────────────────

/// Re-synthesize the wiring records for a gem entry whose ledger was lost
/// (`repair`'s no-ledger reconstruction), by recognizing this backend's OWN
/// emitted wiring in the live Gemfile + Gemfile.lock pair — the same
/// recognizers the re-vendor-new-uuid path trusts. Everything is
/// grammar-strict and fail-closed: any shape vendor does not write yields
/// `Err` and the caller keeps an empty-wiring entry (whose revert then
/// refuses loudly) instead of guessing.
///
/// Three documented degradations, all inherent to a lost ledger:
///
/// * a REWRITTEN declaration's pre-vendor line is reconstructed in the
///   canonical exact-pin form (`gem "<name>", "<version>"` + preserved
///   trailing options) — the user's original version constraint lived only
///   in the lost ledger, and the exact pin restores a consistent,
///   installable pair resolving to the same version;
/// * a trailing `#` comment on the pre-vendor gem line is unrecoverable:
///   vendor's exact-pin rewrite drops it (the verbatim line lived only in
///   the lost ledger), so the reconstructed original restores the line
///   comment-less;
/// * a CHECKSUMS `sha256=` token is NOT recomputable offline, so no
///   checksum record is emitted: revert leaves bundler's bare path-gem
///   entry, which a non-frozen `bundle install` refills byte-identically
///   (bundler 4.0.15 verified; frozen installs fail with a self-explanatory
///   `empty CHECKSUMS entry` message until then) — surfaced as the
///   `vendor_checksum_unrecoverable` warning. The warning is deliberately
///   conservative: a gem whose PRE-vendor CHECKSUMS entry was already bare
///   (real for file-sourced gems — bundler 4.0.15 writes no `sha256=` for
///   them; vendor then records no checksum wiring at all and the bare-line
///   revert is byte-perfect) is indistinguishable from a lost token, so it
///   warns too.
///
/// The transitive-vs-declared split is recovered from the Gemfile form:
/// vendor appends the managed fence exactly when the gem was undeclared,
/// which is also exactly when the pre-vendor DEPENDENCIES entry was absent.
pub async fn reconstruct_gem_wiring(
    project_root: &Path,
    entry: &VendorEntry,
) -> Result<(Vec<WiringRecord>, Vec<VendorWarning>), String> {
    let Some((name, version)) = parse_gem_purl(&entry.base_purl) else {
        return Err(format!("not a gem purl: {}", entry.base_purl));
    };
    // SECURITY: the coordinates come from a re-synthesized entry
    // (manifest/API purl) and are matched against Gemfile/lock line
    // grammar — the same fail-closed token guard as `vendor_gem`.
    if !is_safe_single_segment(name)
        || !is_safe_single_segment(version)
        || !is_plain_gem_token(name)
        || !is_plain_gem_token(version)
    {
        return Err(format!("unsafe gem coordinates `{name}` @ `{version}`"));
    }
    let rel = entry.artifact.path.replace('\\', "/");
    let leaf = format!("{name}-{version}");
    match parse_vendor_path(&rel) {
        Some(p) if p.eco == "gem" && p.uuid == entry.uuid && p.leaf == leaf => {}
        _ => {
            return Err(format!(
                "artifact path `{rel}` is not this entry's canonical vendored dir"
            ));
        }
    }

    // ── Gemfile: exactly one declaration, carrying OUR `path:` ───────────
    let gemfile_text = tokio::fs::read_to_string(project_root.join(GEMFILE))
        .await
        .map_err(|e| format!("unreadable Gemfile: {e}"))?;
    let lines: Vec<&str> = gemfile_text.split('\n').collect();
    let mut found: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if gem_declaration(trimmed, name).is_some() && found.replace(i).is_some() {
            return Err(format!(
                "`gem \"{name}\"` is declared more than once in the Gemfile"
            ));
        }
    }
    let Some(idx) = found else {
        return Err(format!("the Gemfile does not declare `{name}`"));
    };
    let line = lines[idx];
    if line.trim_start().len() != line.len() {
        return Err(format!(
            "the `gem \"{name}\"` declaration is indented — not the wiring vendor writes"
        ));
    }
    let managed = idx > 0
        && lines[idx - 1] == MANAGED_OPEN
        && lines.get(idx + 1).is_some_and(|l| *l == MANAGED_CLOSE);
    let gemfile_record = if managed {
        // The Append plan always emits exactly this double-quoted,
        // option-free line; revert deletes the whole fenced block.
        if line != format!("gem \"{name}\", \"{version}\", path: \"{rel}\"") {
            return Err(format!(
                "the managed block line for `{name}` is not the form vendor writes"
            ));
        }
        WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Added,
            key: Some(name.to_string()),
            original: None,
            new: Some(Value::String(format!(
                "{MANAGED_OPEN}\n{line}\n{MANAGED_CLOSE}\n"
            ))),
        }
    } else {
        let de_vendored = devendored_gem_line(line, name, version, &rel).ok_or_else(|| {
            format!(
                "the `gem \"{name}\"` line is not the exact-pin + `path:` form vendor \
                 writes; its pre-vendor original cannot be reconstructed"
            )
        })?;
        WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(name.to_string()),
            original: Some(Value::String(de_vendored)),
            new: Some(Value::String(line.to_string())),
        }
    };

    // ── Gemfile.lock: our PATH section + the `!` DEPENDENCIES pin ────────
    let lock_text = tokio::fs::read_to_string(project_root.join(GEMFILE_LOCK))
        .await
        .map_err(|e| format!("unreadable Gemfile.lock: {e}"))?;
    let lock_lines: Vec<String> = lock_text.split('\n').map(str::to_string).collect();
    let (ps, pe) = find_our_path_section(&lock_lines, name, version)
        .ok_or_else(|| format!("Gemfile.lock has no PATH section wiring `{name}`"))?;
    let remote_line = format!("  remote: {rel}");
    let target = format!("    {name} ({version})");
    let block_start = (ps..pe)
        .find(|&i| lock_lines[i] == target)
        .ok_or_else(|| format!("the PATH section for `{name}` lost its spec entry"))?;
    let mut block_end = block_start + 1;
    while block_end < pe && lock_lines[block_end].starts_with("      ") {
        block_end += 1;
    }
    // Grammar-strict, mirroring the re-vendor rewire guard: besides the
    // spec block, the section must be exactly what vendor wrote — and its
    // remote must be THIS entry's uuid dir, not some other patch's.
    let non_block: Vec<&str> = (ps..pe)
        .filter(|i| !(block_start..block_end).contains(i))
        .map(|i| lock_lines[i].as_str())
        .filter(|l| !l.is_empty())
        .collect();
    if non_block.len() != 3
        || non_block[0] != "PATH"
        || non_block[1] != remote_line
        || non_block[2] != "  specs:"
    {
        return Err(format!(
            "the Gemfile.lock PATH section for `{name} ({version})` is not the shape \
             vendor writes"
        ));
    }
    let new_dep_line = format!("  {name} (= {version})!");
    let (ds, de) = section_span(&lock_lines, "DEPENDENCIES")
        .ok_or_else(|| "Gemfile.lock has no DEPENDENCIES section".to_string())?;
    if !(ds..de).any(|i| lock_lines[i] == new_dep_line) {
        return Err(format!(
            "Gemfile.lock DEPENDENCIES lacks the `{name} (= {version})!` pin vendor writes"
        ));
    }

    let block = &lock_lines[block_start..block_end];
    let mut new_lines: Vec<Value> = vec![
        Value::String("PATH".to_string()),
        Value::String(remote_line),
        Value::String("  specs:".to_string()),
    ];
    new_lines.extend(block.iter().map(|l| Value::String(l.clone())));
    new_lines.push(Value::String(new_dep_line));
    let mut original_lines: Vec<Value> = block.iter().map(|l| Value::String(l.clone())).collect();
    if !managed {
        // Declared gem ⇒ DEPENDENCIES carried an entry pre-vendor. The
        // canonical exact-pin form pairs with the reconstructed Gemfile
        // line (see the function docs for the degradation contract).
        original_lines.push(Value::String(format!("  {name} (= {version})")));
    }
    let lock_record = WiringRecord {
        file: GEMFILE_LOCK.to_string(),
        kind: LOCK_WIRING_KIND.to_string(),
        action: WiringAction::Rewritten,
        key: Some(name.to_string()),
        original: Some(Value::Array(original_lines)),
        new: Some(Value::Array(new_lines)),
    };

    // ── CHECKSUMS: bare path-form entry expected; sha256 unrecoverable ───
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some((cs, ce)) = section_span(&lock_lines, "CHECKSUMS") {
        let bare = format!("  {name} ({version})");
        for line in &lock_lines[cs + 1..ce] {
            match checksum_entry(line) {
                Some((n, v)) if n == name && v == version => {
                    if line.as_str() != bare {
                        return Err(format!(
                            "Gemfile.lock CHECKSUMS still carries a registry `sha256=` \
                             entry for `{name} ({version})` while the lock is path-wired \
                             — not a state vendor writes; re-resolve the lock before \
                             repairing"
                        ));
                    }
                    warnings.push(VendorWarning::new(
                        "vendor_checksum_unrecoverable",
                        format!(
                            "the pre-vendor CHECKSUMS `sha256=` line for {name} ({version}) \
                             is not recoverable from a reconstructed ledger; after `vendor \
                             --revert`, run a non-frozen `bundle install` once to refill it \
                             (frozen installs fail on the empty entry until then)"
                        ),
                    ));
                }
                Some(_) => {}
                None if checksum_line_names_gem(line, name) => {
                    return Err(format!(
                        "Gemfile.lock CHECKSUMS entry for `{name}` is not parseable: {line:?}"
                    ));
                }
                None => {}
            }
        }
    }

    Ok((vec![gemfile_record, lock_record], warnings))
}

/// Strip our `path:` option back out of a line the exact-pin rewrite
/// emitted: `gem {q}{name}{q}, {q}{version}{q}, path: {q}{rel}{q}[, opts]` →
/// `gem {q}{name}{q}, {q}{version}{q}[, opts]`. `None` for any other shape
/// (fail-closed), including trailing options that would re-select a source.
fn devendored_gem_line(line: &str, name: &str, version: &str, rel: &str) -> Option<String> {
    for q in ['"', '\''] {
        let head = format!("gem {q}{name}{q}, {q}{version}{q}");
        let with_path = format!("{head}, path: {q}{rel}{q}");
        if line == with_path {
            return Some(head);
        }
        if let Some(opts) = line
            .strip_prefix(with_path.as_str())
            .and_then(|t| t.strip_prefix(", "))
        {
            if opts.is_empty() || rest_blocks_edit(&format!(", {opts}")).is_some() {
                return None;
            }
            return Some(format!("{head}, {opts}"));
        }
    }
    None
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
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some((q, rest, paren)) = gem_declaration(trimmed, name) {
            found.push((i, trimmed.len() == line.len(), paren, q, rest.to_string()));
        }
    }
    if found.is_empty() {
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
    let opts = gem_line_trailing_options(&rest);
    let new_line = if opts.is_empty() {
        format!("gem {q}{name}{q}, {q}{version}{q}, path: {q}{rel}{q}")
    } else {
        format!("gem {q}{name}{q}, {q}{version}{q}, path: {q}{rel}{q}, {opts}")
    };
    Ok(GemfilePlan::Rewrite {
        original_line: lines[idx].to_string(),
        new_line,
    })
}

/// Match `gem "<name>"` / `gem '<name>'` (or the parenthesized call form) at
/// the start of a trimmed line. Returns the quote char, everything after the
/// closing quote, and whether the call was parenthesized. Space OR tab after
/// the keyword — a tab-separated declaration the grammar cannot see would
/// fall through to the transitive Append plan, leaving the Gemfile declaring
/// the gem twice (bundler hard-fails on the duplicate).
fn gem_declaration<'a>(trimmed: &'a str, name: &str) -> Option<(char, &'a str, bool)> {
    let rest = trimmed.strip_prefix("gem")?;
    let (paren, rest) = match rest.strip_prefix([' ', '\t']) {
        Some(r) => (false, r),
        None => (true, rest.strip_prefix('(')?),
    };
    let rest = rest.trim_start();
    let q = rest.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(q)?;
    if &rest[..end] != name {
        return None;
    }
    Some((q, &rest[end + 1..], paren))
}

/// Why the text after the gem name blocks an in-place rewrite (`None` = safe).
/// Only the code before any `#` comment counts — a comment trailing plain
/// version constraints is dropped by the rewrite (acceptable: the verbatim
/// original line lives in the ledger for revert), while one trailing kept
/// options rides along with them verbatim. Every source-selecting option is
/// blocked, not just `path:`/`git:`: bundler allows ONE source per gem, so a
/// preserved `source:` (etc.) alongside the `path:` we add would fail every
/// `bundle` invocation.
fn rest_blocks_edit(rest: &str) -> Option<String> {
    let code = rest.split('#').next().unwrap_or("").trim();
    if code.is_empty() {
        return None;
    }
    if !code.starts_with(',') {
        return Some("unexpected tokens after the gem name".to_string());
    }
    if code.ends_with(',') {
        return Some("the declaration continues on the next line".to_string());
    }
    for tok in [
        "path:",
        ":path",
        "git:",
        ":git",
        "github:",
        ":github",
        "source:",
        ":source",
        "gist:",
        ":gist",
        "bitbucket:",
        ":bitbucket",
    ] {
        if code.contains(tok) {
            return Some(format!(
                "the declaration already carries `{tok}` (revert any previous vendoring first)"
            ));
        }
    }
    if code.contains(" if ") || code.contains(" unless ") {
        return Some("conditional declaration".to_string());
    }
    None
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
}

/// Produce the pair-edited lock text (see the module doc for the canonical
/// form). Pure string surgery on exact line spans — every byte not
/// deliberately changed is preserved, which is what keeps the result
/// byte-identical to what bundler regenerates.
fn edit_lock(text: &str, name: &str, version: &str, rel: &str) -> Result<LockEdit, String> {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // 1. Lift the gem's spec block out of GEM/specs — or, on a re-vendor to
    // a newer patch uuid (same purl), out of the PATH section our previous
    // run emitted.
    let (gem_start, gem_end) =
        section_span(&lines, "GEM").ok_or_else(|| "Gemfile.lock has no GEM section".to_string())?;
    if !(gem_start..gem_end).any(|i| lines[i] == "  specs:") {
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
    for line in lines.iter().take(gem_end).skip(gem_start + 1) {
        if let Some((n, v)) = spec_entry(line) {
            if n == name && v.starts_with(&platform_prefix) {
                return Err(format!(
                    "Gemfile.lock GEM specs has a platform-suffixed entry `{n} ({v})` but the installed gem is not platform-specific; the lock disagrees with the install (re-resolve it before vendoring)"
                ));
            }
        }
    }
    let target = format!("    {name} ({version})");
    let mut rewired_ours = false;
    let removed_spec_block: Vec<String> = match (gem_start..gem_end).find(|&i| lines[i] == target) {
        Some(block_start) => {
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

/// Name of a 2-space DEPENDENCIES entry (`  rack (~> 3.1)` / `  rack!`).
fn dep_entry_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    if rest.is_empty() || rest.starts_with(' ') {
        return None;
    }
    let end = rest.find([' ', '(', '!']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Name of a 4-space spec entry (`    rack (3.2.6)`).
fn spec_entry_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("    ")?;
    if rest.is_empty() || rest.starts_with(' ') {
        return None;
    }
    Some(rest.split(' ').next().unwrap_or(rest))
}

/// Parse a 4-space specs entry line: `    <name> (<token>)`, nothing after
/// the closing paren. Returns `(name, parenthesized token)` — the platform
/// suffix stays inside the token, mirroring [`checksum_entry`]'s grammar at
/// specs indentation (`    ffi (1.17.2-aarch64-linux-gnu)`).
fn spec_entry(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("    ")?;
    if rest.is_empty() || rest.starts_with(' ') {
        return None;
    }
    let open = rest.find(" (")?;
    let after = &rest[open + 2..];
    let close = after.find(')')?;
    let (name, ver, tail) = (&rest[..open], &after[..close], &after[close + 1..]);
    if name.is_empty() || ver.is_empty() || !tail.is_empty() {
        return None;
    }
    Some((name, ver))
}

/// Parse a CHECKSUMS entry line: two-space indent, `<name> (<version>)` or
/// `<name> (<version>-<platform>)`, then optional space-separated tokens
/// (`sha256=<hex>` on registry entries, nothing on path entries). Returns
/// `(name, parenthesized token)` — the platform suffix stays inside the token
/// because matching must mirror the GEM specs grammar (spike G5: native gems
/// get one CHECKSUMS line per platform spec, `ffi (1.17.2-aarch64-linux-gnu)`).
fn checksum_entry(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("  ")?;
    if rest.is_empty() || rest.starts_with(' ') {
        return None;
    }
    let open = rest.find(" (")?;
    let after = &rest[open + 2..];
    let close = after.find(')')?;
    let (name, ver, tail) = (&rest[..open], &after[..close], &after[close + 1..]);
    if name.is_empty() || ver.is_empty() || !(tail.is_empty() || tail.starts_with(' ')) {
        return None;
    }
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

/// Restore one `gemfile_line` record. `Ok(true)` = restored (or would be, on
/// dry run); `Ok(false)` = the written line/block is gone (drift), left alone.
async fn revert_gemfile_record(
    gemfile_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<bool, String> {
    let text = match tokio::fs::read_to_string(gemfile_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("unreadable Gemfile: {e}")),
    };
    let Some(written) = w.new.as_ref().and_then(Value::as_str) else {
        return Ok(false);
    };
    let restored = match w.action {
        WiringAction::Rewritten => {
            let Some(original) = w.original.as_ref().and_then(Value::as_str) else {
                return Ok(false);
            };
            let mut lines: Vec<&str> = text.split('\n').collect();
            let Some(i) = lines.iter().position(|l| *l == written) else {
                return Ok(false);
            };
            lines[i] = original;
            lines.join("\n")
        }
        WiringAction::Added => {
            let Some(at) = text.find(written) else {
                return Ok(false);
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
    Ok(true)
}

/// Restore one `gemfile_lock_spec` record. `Ok(true)` = restored (or would
/// be, on dry run); `Ok(false)` = the lock no longer carries what vendor
/// wrote (drift), left alone in full — a partial splice would corrupt it.
async fn revert_lock_record(
    lock_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<bool, String> {
    let Some(original_lines) = wiring_string_array(w.original.as_ref()) else {
        return Ok(false);
    };
    let Some(new_lines) = wiring_string_array(w.new.as_ref()) else {
        return Ok(false);
    };
    let text = match tokio::fs::read_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("unreadable Gemfile.lock: {e}")),
    };
    let Some(restored) = revert_lock_text(&text, &original_lines, &new_lines) else {
        return Ok(false);
    };
    if !dry_run {
        atomic_write_bytes_preserving_mode(lock_path, restored.as_bytes())
            .await
            .map_err(|e| format!("failed to write Gemfile.lock: {e}"))?;
    }
    Ok(true)
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
/// `Ok(true)` = restored (or would be, on dry run); `Ok(false)` = the line is
/// gone (drift), left alone.
async fn revert_lock_checksum_record(
    lock_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<bool, String> {
    let Some(original) = w.original.as_ref().and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(written) = w.new.as_ref().and_then(Value::as_str) else {
        return Ok(false);
    };
    let text = match tokio::fs::read_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("unreadable Gemfile.lock: {e}")),
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") else {
        return Ok(false);
    };
    let Some(i) = (ck_start + 1..ck_end).find(|&i| lines[i] == written) else {
        return Ok(false);
    };
    lines[i] = original.to_string();
    if !dry_run {
        atomic_write_bytes_preserving_mode(lock_path, lines.join("\n").as_bytes())
            .await
            .map_err(|e| format!("failed to write Gemfile.lock: {e}"))?;
    }
    Ok(true)
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
    let old_dep_line = original_lines
        .iter()
        .find(|l| l.starts_with("  ") && !l[2..].starts_with(' '));
    let our_name = spec_entry_name(spec_block.first()?)?.to_string();

    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // Preconditions on the untouched lines.
    let (path_start, path_end) = find_path_section(&lines, remote_line)?;
    if !lines.iter().any(|l| l == new_dep_line) {
        return None;
    }
    {
        let (gs, ge) = section_span(&lines, "GEM")?;
        (gs..ge).find(|&i| lines[i] == "  specs:")?;
    }

    // 1. Drop the PATH section (incl. its trailing blank separator).
    lines.drain(path_start..path_end);

    // 2. Spec block back into GEM/specs, sorted by entry name (bundler keeps
    // specs alphabetized; the block came out of a sorted list).
    let (gs, ge) = section_span(&lines, "GEM")?;
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

/// Plain gem-token charset (letters, digits, `.`, `_`, `-`). See the SECURITY
/// note in [`vendor_gem`] — these strings are embedded verbatim into ruby
/// source and lock line grammar, so this is deliberately stricter than the
/// path-level `is_safe_single_segment`.
fn is_plain_gem_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Textual heuristic for `s.extensions = […]` / `spec.extensions << …` style
/// declarations (comment-stripped per line). A match always refuses
/// (fail-closed); a miss — e.g. extensions assigned through interpolation
/// tricks — falls through, which only loses the refusal's nicer error, not
/// safety. Parsing ruby for real would need a ruby.
fn gemspec_declares_extensions(spec_text: &str) -> bool {
    for raw in spec_text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        if let Some(idx) = line.find(".extensions") {
            let after = line[idx + ".extensions".len()..].trim_start();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::VerifyStatus;
    use crate::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:gem/rack@3.2.6";
    const PRISTINE: &[u8] = b"module Rack\n  VERSION = \"3.2.6\"\nend\n";
    const PATCHED: &[u8] = b"module Rack\n  SOCKET_PATCHED = true\n  VERSION = \"3.2.6\"\nend\n";

    const GEMSPEC: &str = "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\n  s.summary = \"a modular Ruby web server interface\"\n  s.require_paths = [\"lib\"]\nend\n";

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
        vendor_gem(
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

    /// Fail-closed allowlist regression: an install dir whose name is neither
    /// the `<name>-<version>` leaf nor the `gem` auto-fetch staging dir is
    /// refused — even though it is NOT a `<leaf>-<platform>` suffix, so the old
    /// suffix-only check (`dir_name.starts_with("{leaf}-")`) would have ADMITTED
    /// it. Only the two legitimate dir names may pass.
    #[tokio::test]
    async fn test_refuses_unexpected_install_dir_name() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // A wholly-unexpected dir name: not `rack-3.2.6`, not `gem`, and not a
        // `rack-3.2.6-<suffix>` platform build (which the old suffix check caught).
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

    /// Regression: a pure-ruby gem fetched via the registry auto-fetch ladder
    /// is staged into a private tempdir named literally `gem` (NOT
    /// `<name>-<version>`). The old gate refused every such gem with
    /// `platform_gem_unsupported` because `dir_name != leaf`. With the purl's
    /// `?platform=ruby` (the portable default) the vendor must now SUCCEED —
    /// the staging dir name is not a platform signal.
    #[tokio::test]
    async fn test_platform_ruby_gem_from_autofetch_staging_dir_vendors() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Rename the install dir to `gem`, mirroring registry_fetch::fetch_gem's
        // staging leaf. The sibling `specifications/rack-3.2.6.gemspec` (needed
        // by the local build) is derived from installed_dir.parent().parent(),
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

    #[tokio::test]
    async fn test_refuses_missing_spec_file() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_file(
            installed
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("specifications/rack-3.2.6.gemspec"),
        )
        .await
        .unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gem_spec_missing");
        assert!(!root.join(".socket").exists());
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
        assert!(
            e2.is_none(),
            "artifact-only rebuild must not re-record the ledger entry"
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

    #[tokio::test]
    async fn test_revert_drift_warnings() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // Third-party drift: a `bundle update` regenerated both files back to
        // registry form. Revert must leave them alone, warn per file, and
        // still remove the artifact dir.
        tokio::fs::write(root.join(GEMFILE), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), LOCK_DIRECT)
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
            drift_count, 2,
            "one drift warning per file: {:?}",
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
    const GEMSPEC_318: &str = "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.1.8\"\n  s.require_paths = [\"lib\"]\nend\n";

    // Embedded VERBATIM from the spike pair
    // `spikes/gem-checksums/path-with-checksums/{before,after}/` (bundler
    // 2.7.2, ruby 3.3.11, aarch64-linux; the `after` lock was written by
    // bundler itself via `bundle lock`, never by hand). G3 pinned exactly this
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
        vendor_gem(
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
        // Regression: a lock WITHOUT a CHECKSUMS section must keep producing
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
    const GEMSPEC_PUMA: &str = "Gem::Specification.new do |s|\n  s.name = \"puma\"\n  s.version = \"6.4.2\"\n  s.require_paths = [\"lib\"]\nend\n";

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
    /// the gem at boot, changing app behavior while vendored (the redirect
    /// backend's `gem_line_trailing_options` twin, FIXED there 2026-07-06).
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

    // ─────────────── service-download path (Tier B: gem) ──────────────────
    //
    // gem vendors a patched source DIRECTORY plus a stub gemspec, so the
    // service path downloads the prebuilt `.gem` AND the `gem-stub-gemspec`
    // second artifact, verifies both, extracts the `.gem`'s data.tar.gz into the
    // copy dir, and writes the stub as `<name>.gemspec`. Both the service path
    // and the local-build fallback are exercised.

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::vendor::VendorSource;

    /// A valid path-source stub (no native extensions).
    const SERVICE_STUB: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n";
    /// A stub that declares native extensions (must be refused).
    const SERVICE_STUB_NATIVE: &[u8] = b"Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.extensions = [\"ext/rack/extconf.rb\"]\nend\n";

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
            source,
            client: Some(ApiClient::new(ApiClientOptions {
                api_url: uri.to_string(),
                api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                use_public_proxy: false,
                org_slug: Some("acme".into()),
            })),
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
    /// served stub is written as `rack.gemspec`, the Gemfile + lock are wired,
    /// and a `vendor_prebuilt_downloaded` advisory is emitted — WITHOUT a local
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

        let outcome = vendor_gem(
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

        let outcome = vendor_gem(
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

        let outcome = vendor_gem(
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

        let outcome = vendor_gem(
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

    /// `auto` + a missing stub artifact falls back to the LOCAL build (which
    /// copies the installed gem + local stub and patches it).
    #[tokio::test]
    async fn service_stub_missing_auto_falls_back_to_build() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, None).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, _) = unwrap_done(outcome);
        assert!(result.success, "auto must fall back: {:?}", result.error);
        assert!(entry.is_some());
        // The locally-built copy carries the patched content + the LOCAL stub.
        assert_eq!(tokio::fs::read(copy_lib(&root)).await.unwrap(), PATCHED);
        assert_eq!(
            tokio::fs::read_to_string(copy_gemspec(&root))
                .await
                .unwrap(),
            GEMSPEC
        );
    }

    /// `auto` + a not-built service status falls back to the local build.
    #[tokio::test]
    async fn service_unavailable_auto_falls_back_to_build() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "not_found").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, _) = unwrap_done(outcome);
        assert!(result.success, "auto must fall back: {:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(tokio::fs::read(copy_lib(&root)).await.unwrap(), PATCHED);
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

        let outcome = vendor_gem(
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
        let outcome = vendor_gem(
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

    // ── ledger reconstruction ────────────────────────────────────────────

    const GEMFILE_PINNED: &str =
        "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\"\n";
    const LOCK_PINNED: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)\n\nBUNDLED WITH\n   2.5.22\n";

    /// STRONG oracle for an exact-pin declaration: reconstruction from the
    /// live wired pair must reproduce vendor's own recorded wiring
    /// byte-for-byte — and reverting with the reconstructed records must
    /// byte-restore both files, exactly like the real ledger would.
    #[tokio::test]
    async fn reconstruction_reproduces_vendor_wiring_for_pinned_declaration() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        let (wiring, warnings) = reconstruct_gem_wiring(&root, &entry).await.unwrap();
        assert_eq!(
            wiring, entry.wiring,
            "reconstructed wiring must equal what vendor recorded"
        );
        assert!(
            warnings.is_empty(),
            "no CHECKSUMS section, no degradation notes: {warnings:?}"
        );

        // Revert with ONLY the reconstructed records: byte-restored pair,
        // artifact gone.
        let mut synth = entry.clone();
        synth.wiring = wiring;
        let outcome = revert_gem(&synth, &root, false).await;
        assert!(outcome.success, "revert failed: {:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_PINNED
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_PINNED
        );
        assert!(!root.join(copy_rel()).exists(), "artifact removed");
    }

    /// Transitive gem (managed fence): the reconstructed Added record must
    /// equal vendor's, and the lock original must carry NO dependencies
    /// entry (revert deletes the added pin).
    #[tokio::test]
    async fn reconstruction_reproduces_vendor_wiring_for_managed_block() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        let (wiring, _) = reconstruct_gem_wiring(&root, &entry).await.unwrap();
        assert_eq!(wiring, entry.wiring);

        let mut synth = entry.clone();
        synth.wiring = wiring;
        let outcome = revert_gem(&synth, &root, false).await;
        assert!(outcome.success, "revert failed: {:?}", outcome.error);
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

    /// The documented degradation: a RANGE constraint (`~> 3.1`) lived only
    /// in the lost ledger, so the reconstructed originals pin the exact
    /// locked version — a consistent, installable pair, hand-pinned here.
    #[tokio::test]
    async fn reconstruction_degrades_range_constraint_to_exact_pin() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        let (wiring, _) = reconstruct_gem_wiring(&root, &entry).await.unwrap();
        assert_eq!(
            wiring[0].original,
            Some(Value::String("gem \"rack\", \"3.2.6\"".to_string())),
            "canonical exact pin, NOT the unrecoverable `~> 3.1`"
        );
        let lock_original = wiring[1].original.as_ref().unwrap().as_array().unwrap();
        assert_eq!(
            lock_original.last().unwrap(),
            &Value::String("  rack (= 3.2.6)".to_string()),
            "the DEPENDENCIES restore pairs with the pinned Gemfile line"
        );

        // The reverted pair is CONSISTENT (both halves pin 3.2.6).
        let mut synth = entry.clone();
        synth.wiring = wiring;
        let outcome = revert_gem(&synth, &root, false).await;
        assert!(outcome.success, "revert failed: {:?}", outcome.error);
        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert!(gemfile.contains("gem \"rack\", \"3.2.6\"\n"), "{gemfile}");
        assert!(!gemfile.contains("path:"), "{gemfile}");
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert!(lock.contains("\n  rack (= 3.2.6)\n"), "{lock}");
        assert!(!lock.contains("PATH"), "{lock}");
    }

    /// Trailing options ride the reconstruction (`require: false` dropped
    /// on restore would auto-require the gem at boot).
    #[tokio::test]
    async fn reconstruction_preserves_trailing_options() {
        let gemfile =
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", require: false\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        let (wiring, _) = reconstruct_gem_wiring(&root, &entry).await.unwrap();
        assert_eq!(
            wiring[0].original,
            Some(Value::String(
                "gem \"rack\", \"3.2.6\", require: false".to_string()
            ))
        );
    }

    /// A bare CHECKSUMS entry (bundler ≥ 2.6 lock): the `sha256=` token is
    /// not offline-recoverable, so reconstruction emits NO checksum record
    /// (revert leaves the bare line for a plain `bundle install` to refill
    /// — bundler 4.0.15 verified) and surfaces the gap as a warning.
    #[tokio::test]
    async fn reconstruction_flags_unrecoverable_checksum() {
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)\n\nCHECKSUMS\n  puma (6.4.2) sha256={}\n  rack (3.2.6) sha256={}\n\nBUNDLED WITH\n   2.5.22\n",
            "a".repeat(64),
            "b".repeat(64),
        );
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, &lock).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");
        assert_eq!(entry.wiring.len(), 3, "vendor recorded a checksum record");

        let (wiring, warnings) = reconstruct_gem_wiring(&root, &entry).await.unwrap();
        assert_eq!(
            wiring.len(),
            2,
            "no checksum record — the sha256 is unrecoverable: {wiring:?}"
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0].code, "vendor_checksum_unrecoverable");
    }

    /// Fail-closed refusals: anything that is not vendor's own emitted
    /// wiring yields `Err`, never guessed-at records.
    #[tokio::test]
    async fn reconstruction_refuses_foreign_or_mismatched_wiring() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        // A user fork's path: (not our vendored dir) in place of ours.
        let gemfile_path = root.join(GEMFILE);
        let wired = tokio::fs::read_to_string(&gemfile_path).await.unwrap();
        tokio::fs::write(
            &gemfile_path,
            wired.replace(&copy_rel(), "vendor/forks/rack"),
        )
        .await
        .unwrap();
        let err = reconstruct_gem_wiring(&root, &entry).await.unwrap_err();
        assert!(err.contains("exact-pin"), "{err}");
        tokio::fs::write(&gemfile_path, &wired).await.unwrap();

        // A DIFFERENT patch uuid's dir wired in the pair: not this entry's.
        let mut other = entry.clone();
        other.uuid = "11111111-2222-4333-8444-555555555555".to_string();
        other.artifact.path =
            ".socket/vendor/gem/11111111-2222-4333-8444-555555555555/rack-3.2.6".to_string();
        let err = reconstruct_gem_wiring(&root, &other).await.unwrap_err();
        assert!(
            err.contains("exact-pin") || err.contains("PATH section"),
            "{err}"
        );

        // The lock lost the `!` pin.
        let lock_path = root.join(GEMFILE_LOCK);
        let wired_lock = tokio::fs::read_to_string(&lock_path).await.unwrap();
        tokio::fs::write(
            &lock_path,
            wired_lock.replace("  rack (= 3.2.6)!", "  rack (= 3.2.6)"),
        )
        .await
        .unwrap();
        let err = reconstruct_gem_wiring(&root, &entry).await.unwrap_err();
        assert!(err.contains("(= 3.2.6)!"), "{err}");
        tokio::fs::write(&lock_path, &wired_lock).await.unwrap();

        // A registry `sha256=` CHECKSUMS entry while path-wired (the stale
        // pre-CHECKSUMS-aware state): never silently blessed.
        let stale = format!(
            "{wired_lock}\nCHECKSUMS\n  rack (3.2.6) sha256={}\n",
            "c".repeat(64)
        );
        tokio::fs::write(&lock_path, stale).await.unwrap();
        let err = reconstruct_gem_wiring(&root, &entry).await.unwrap_err();
        assert!(err.contains("sha256"), "{err}");
    }

    /// The empty-wiring revert guard: a reconstructed entry without
    /// recoverable wiring must FAIL loudly — deleting the artifact would
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
}
