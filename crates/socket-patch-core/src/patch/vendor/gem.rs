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
//! it is a statically-parseable single top-level line, quote style preserved)
//! or, for a transitive dependency, a managed block appended at EOF. Anything
//! the conservative line grammar cannot prove safe to rewrite is REFUSED —
//! never guessed at.
//!
//! The stub gemspec from `<gem_home>/specifications/` is copied into the
//! vendored dir as `<name>.gemspec` (a path source needs one; the spike showed
//! the stub works warning-free). Gems whose gemspec declares native
//! extensions are refused: bundler silently skips extension builds for path
//! sources and the missing `.so` only fails at `require` time with a
//! confusing error — refusing up front is the honest failure.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::{
    apply_package_patch, is_safe_relative_subpath, normalize_file_path, ApplyResult, PatchSources,
    VerifyResult, VerifyStatus,
};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::fs::atomic_write_bytes;
use crate::utils::purl::{build_gem_purl, parse_gem_purl};

use super::path::vendor_uuid_dir_rel;
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

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

/// Marker schema version written into `socket-patch.vendor.json`.
const MARKER_SCHEMA_VERSION: u32 = 1;

/// Vendor a gem: materialize a patched copy (plus its stub gemspec) under
/// `.socket/vendor/gem/<uuid>/<name>-<version>` and pair-edit Gemfile +
/// Gemfile.lock at it (see the module doc).
///
/// `installed_dir` is the crawler's gem dir (`<gem_home>/gems/<name>-<version>`,
/// the same root `apply` patches — manifest file keys resolve relative to it);
/// the stub gemspec is derived from it
/// (`<gem_home>/specifications/<name>-<version>.gemspec` — `specifications/`
/// is a sibling of `gems/`).
///
/// Edit order: copy+patch → Gemfile → Gemfile.lock; a lock-edit failure
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
        return VendorOutcome::Done {
            result: synthesized_result(purl, &copy_dir, Vec::new(), true, None),
            entry: None,
            warnings: Vec::new(),
        };
    }

    // Platform-suffixed installs (`<name>-<version>-x86_64-linux`) ship
    // precompiled artifacts that are machine-specific — committing one would
    // break every other platform, so they are refused, not guessed at.
    let dir_name = installed_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if dir_name != leaf {
        return refused(
            "platform_gem_unsupported",
            format!(
                "installed dir `{dir_name}` does not equal `{leaf}` (platform-specific gem builds cannot be vendored portably)"
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

    // ── stub gemspec ─────────────────────────────────────────────────────
    // `specifications/` is a sibling of `gems/`; derive it from installed_dir.
    let spec_src = installed_dir
        .parent()
        .and_then(Path::parent)
        .map(|home| home.join("specifications").join(format!("{leaf}.gemspec")));
    let spec_text = match &spec_src {
        Some(p) => tokio::fs::read_to_string(p).await.ok(),
        None => None,
    };
    let Some(spec_text) = spec_text else {
        return refused(
            "gem_spec_missing",
            format!(
                "no stub gemspec at {} (a path source cannot be wired without one)",
                spec_src
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<gem_home>/specifications".to_string())
            ),
        );
    };
    // Textual heuristic, deliberately fail-closed on a match: bundler skips
    // extension builds for path sources entirely, so a native gem would
    // install fine and then fail at `require` time with a missing `.so`.
    if gemspec_declares_extensions(&spec_text) {
        return refused(
            "native_extensions_unsupported",
            format!(
                "{leaf}.gemspec declares native extensions; bundler does not build extensions for path-sourced gems"
            ),
        );
    }

    // ── idempotent hot path ──────────────────────────────────────────────
    // Copy (incl. the gemspec) already carries every afterHash and both files
    // already reference the uuid path → touch nothing. `entry` stays `None`:
    // the first run's ledger entry holds the only copy of the pre-vendor
    // originals.
    let remote_line = format!("  remote: {copy_rel}");
    let wired = copy_matches_after_hashes(&copy_dir, &record.files).await
        && tokio::fs::metadata(copy_dir.join(format!("{name}.gemspec")))
            .await
            .is_ok()
        && lock_text.split('\n').any(|l| l == remote_line)
        && gemfile_text.contains(&copy_rel);
    if wired {
        if lock_checksum_in_sync(&lock_text, name, version) {
            let verified = record
                .files
                .keys()
                .map(|f| already_patched_verify(f))
                .collect();
            return VendorOutcome::Done {
                result: synthesized_result(purl, &copy_dir, verified, true, None),
                entry: None,
                warnings: Vec::new(),
            };
        }
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

    // ── dry run: verify-only against the installed dir, no writes ────────
    if dry_run {
        let mut result = apply_package_patch(
            purl,
            installed_dir,
            &record.files,
            sources,
            Some(&record.uuid),
            true,
            force,
        )
        .await;
        result.package_path = copy_dir.display().to_string();
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── Gemfile edit plan (refusals before any write) ────────────────────
    let plan = match plan_gemfile_edit(&gemfile_text, name, version, &copy_rel) {
        Ok(p) => p,
        Err(detail) => return refused("gemfile_declaration_not_editable", detail),
    };

    // ── copy + patch ─────────────────────────────────────────────────────
    if let Err(e) = fresh_copy(installed_dir, &copy_dir, None).await {
        return VendorOutcome::Done {
            result: synthesized_result(
                purl,
                &copy_dir,
                Vec::new(),
                false,
                Some(format!("failed to copy installed gem: {e}")),
            ),
            entry: None,
            warnings: Vec::new(),
        };
    }
    // The vendored dir is freshly created and not yet referenced by anything,
    // so a plain write suffices for the gemspec.
    if let Err(e) = tokio::fs::write(copy_dir.join(format!("{name}.gemspec")), &spec_text).await {
        let _ = remove_tree(&uuid_dir).await;
        return VendorOutcome::Done {
            result: synthesized_result(
                purl,
                &copy_dir,
                Vec::new(),
                false,
                Some(format!(
                    "failed to copy the stub gemspec into the vendored dir: {e}"
                )),
            ),
            entry: None,
            warnings: Vec::new(),
        };
    }
    let mut result = apply_package_patch(
        purl,
        &copy_dir,
        &record.files,
        sources,
        Some(&record.uuid),
        false,
        force,
    )
    .await;
    result.package_path = copy_dir.display().to_string();
    if !result.success {
        // Don't leave a half-built copy; neither file was touched.
        let _ = remove_tree(&uuid_dir).await;
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── Gemfile edit ─────────────────────────────────────────────────────
    let new_gemfile = apply_gemfile_plan(&gemfile_text, &plan);
    if let Err(e) = atomic_write_bytes(&gemfile_path, new_gemfile.as_bytes()).await {
        let _ = remove_tree(&uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write Gemfile: {e}"));
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── Gemfile.lock edit (a failure here unwinds the Gemfile) ───────────
    let lock_edit = match edit_lock(&lock_text, name, version, &copy_rel) {
        Ok(edit) => match atomic_write_bytes(&lock_path, edit.text.as_bytes()).await {
            Ok(()) => Ok(edit),
            Err(e) => Err(format!("failed to write Gemfile.lock: {e}")),
        },
        Err(e) => Err(format!("failed to edit Gemfile.lock: {e}")),
    };
    let lock_edit = match lock_edit {
        Ok(edit) => edit,
        Err(mut detail) => {
            // Unwind: a Gemfile pointing at a path the lock doesn't agree
            // with is exactly the half-wired state the pair edit exists to
            // prevent — restore the recorded original bytes.
            if let Err(e) = atomic_write_bytes(&gemfile_path, gemfile_text.as_bytes()).await {
                detail.push_str(&format!(" (Gemfile unwind also failed: {e})"));
            }
            let _ = remove_tree(&uuid_dir).await;
            result.success = false;
            result.error = Some(detail);
            return VendorOutcome::Done {
                result,
                entry: None,
                warnings: Vec::new(),
            };
        }
    };

    // ── marker + ledger entry ────────────────────────────────────────────
    let mut warnings = Vec::new();
    let base_purl = build_gem_purl(name, version);
    let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulnerabilities.sort();
    let marker = VendorMarker {
        schema_version: MARKER_SCHEMA_VERSION,
        purl: base_purl.clone(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "gem".to_string(),
        vulnerabilities,
        vendored_at: vendored_at.to_string(),
    };
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
    };
    let mut original_lines: Vec<Value> = lock_edit
        .removed_spec_block
        .iter()
        .map(|l| Value::String(l.clone()))
        .collect();
    if let Some(dep) = &lock_edit.old_dep_line {
        original_lines.push(Value::String(dep.clone()));
    }
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
        original: Some(Value::Array(original_lines)),
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
    }

    let entry = VendorEntry {
        ecosystem: "gem".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: copy_rel,
            sha256: String::new(), // dir-shaped: integrity is per-file afterHashes
            size: None,
            platform_locked: None,
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };

    VendorOutcome::Done {
        result,
        entry: Some(entry),
        warnings,
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

// ── Gemfile editing ──────────────────────────────────────────────────────────

/// The planned Gemfile edit.
enum GemfilePlan {
    /// The gem is declared on a safe single top-level line: rewrite it in
    /// place (quote style preserved).
    Rewrite {
        original_line: String,
        new_line: String,
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
/// wrong Gemfile rewrite executes on every `bundle` invocation.
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
    if let Some(reason) = rest_blocks_edit(&rest) {
        return Err(format!(
            "the `gem \"{name}\"` declaration is not editable: {reason}"
        ));
    }
    Ok(GemfilePlan::Rewrite {
        original_line: lines[idx].to_string(),
        new_line: format!("gem {q}{name}{q}, {q}{version}{q}, path: {q}{rel}{q}"),
    })
}

/// Match `gem "<name>"` / `gem '<name>'` (or the parenthesized call form) at
/// the start of a trimmed line. Returns the quote char, everything after the
/// closing quote, and whether the call was parenthesized.
fn gem_declaration<'a>(trimmed: &'a str, name: &str) -> Option<(char, &'a str, bool)> {
    let rest = trimmed.strip_prefix("gem")?;
    let (paren, rest) = match rest.strip_prefix(' ') {
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
/// Only the code before any `#` comment counts — a trailing comment is
/// dropped by the rewrite, which is acceptable because the verbatim original
/// line lives in the ledger for revert.
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
    for tok in ["path:", ":path", "git:", ":git", "github:", ":github"] {
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

fn apply_gemfile_plan(text: &str, plan: &GemfilePlan) -> String {
    match plan {
        GemfilePlan::Rewrite {
            original_line,
            new_line,
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
}

/// Produce the pair-edited lock text (see the module doc for the canonical
/// form). Pure string surgery on exact line spans — every byte not
/// deliberately changed is preserved, which is what keeps the result
/// byte-identical to what bundler regenerates.
fn edit_lock(text: &str, name: &str, version: &str, rel: &str) -> Result<LockEdit, String> {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // 1. Lift the gem's spec block out of GEM/specs.
    let (gem_start, gem_end) =
        section_span(&lines, "GEM").ok_or_else(|| "Gemfile.lock has no GEM section".to_string())?;
    if !(gem_start..gem_end).any(|i| lines[i] == "  specs:") {
        return Err("Gemfile.lock GEM section has no specs: stanza".to_string());
    }
    let target = format!("    {name} ({version})");
    let block_start = (gem_start..gem_end)
        .find(|&i| lines[i] == target)
        .ok_or_else(|| format!("Gemfile.lock GEM specs has no entry `{name} ({version})`"))?;
    let mut block_end = block_start + 1;
    while block_end < gem_end && lines[block_end].starts_with("      ") {
        block_end += 1;
    }
    let removed_spec_block: Vec<String> = lines.drain(block_start..block_end).collect();

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

    // 3. PATH section directly above the GEM section (bundler's canonical
    // placement; spike claim 2). `remote:` is the bare relative path.
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
    let mut insert = path_section.clone();
    insert.push(String::new()); // blank separator before GEM
    lines.splice(gem_hdr..gem_hdr, insert);

    // 4. CHECKSUMS (bundler ≥ 2.6 `lockfile_checksums`): a path-sourced gem
    // keeps a BARE `  <name> (<version>)` entry — bundler's own re-lock emits
    // exactly that form (spike G2), so the registry `sha256=` token must be
    // stripped here or the committed lock diverges from any regen forever
    // (spike G4: bundler silently preserves a stale token, never repairs it).
    // Absent section / absent entry are both tolerated by bundler — touched
    // by nothing. Re-found via section_span because the PATH splice above
    // shifted every index.
    let mut checksum_rewrite: Option<(String, String)> = None;
    if let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") {
        let bare = format!("  {name} ({version})");
        let platform_prefix = format!("{version}-");
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
    })
}

/// `[start, end)` of a lock section: the column-0 `header` line through (not
/// including) the next column-0 line. Blank separator lines belong to the
/// section they follow.
fn section_span(lines: &[String], header: &str) -> Option<(usize, usize)> {
    let start = lines.iter().position(|l| l.as_str() == header)?;
    let mut end = start + 1;
    while end < lines.len() {
        let l = &lines[end];
        if !l.is_empty() && !l.starts_with(' ') {
            break;
        }
        end += 1;
    }
    Some((start, end))
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
        atomic_write_bytes(gemfile_path, restored.as_bytes())
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
        atomic_write_bytes(lock_path, restored.as_bytes())
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
        atomic_write_bytes(lock_path, lines.join("\n").as_bytes())
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

/// True when the copy exists and every patched file in it already hashes to
/// its `afterHash` (the vendor twin of `go_redirect::redirect_in_sync`).
async fn copy_matches_after_hashes(
    copy_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    if tokio::fs::metadata(copy_dir).await.is_err() {
        return false;
    }
    for (file_name, info) in files {
        let normalized = normalize_file_path(file_name);
        // SECURITY: never hash through a manifest key that escapes the copy
        // dir — fail the sync check instead (the full pipeline would refuse
        // the key anyway).
        if !is_safe_relative_subpath(normalized) {
            return false;
        }
        match compute_file_git_sha256(&copy_dir.join(normalized)).await {
            Ok(h) if h == info.after_hash => {}
            _ => return false,
        }
    }
    true
}

fn refused(code: &'static str, detail: impl Into<String>) -> VendorOutcome {
    VendorOutcome::Refused {
        code,
        detail: detail.into(),
    }
}

fn synthesized_result(
    package_key: &str,
    copy_dir: &Path,
    files_verified: Vec<VerifyResult>,
    success: bool,
    error: Option<String>,
) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: copy_dir.display().to_string(),
        success,
        files_verified,
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error,
        sidecar: None,
    }
}

fn already_patched_verify(file: &str) -> VerifyResult {
    VerifyResult {
        file: file.to_string(),
        status: VerifyStatus::AlreadyPatched,
        message: None,
        current_hash: None,
        expected_hash: None,
        target_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;
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
        let sources = PatchSources::blobs_only(blobs);
        vendor_gem(
            PURL,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
        )
        .await
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
                .contains("platform-suffixed"),
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
}
