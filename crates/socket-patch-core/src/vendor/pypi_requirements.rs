//! requirements.txt wiring (pip & `uv pip`).
//!
//! The spike-verified line shape is
//! `./<rel wheel>[ ; <marker>] [--hash=sha256:<hex>]  # socket-patch vendor: <name>==<ver>`:
//! both pip 26 and uv 0.11 accept the bare relative path (resolved against
//! the INVOKING CWD, never the requirements-file dir — hence the documented
//! root-only constraint), enforce the `--hash` pin, strip the trailing
//! comment, and genuinely EVALUATE a `; marker` on a path line — so an
//! environment marker is carried over from the replaced pin instead of
//! refused.
//!
//! The `--hash` is written only when the requirements tree is already in
//! pip's hash-checking mode ([`requires_hashes`]): any `--hash` on any line
//! turns that mode on for the whole install, so a hashed vendor line in an
//! unhashed tree would make pip refuse every other requirement (#376). A
//! path line cannot carry a `#sha256=` fragment instead; the committed
//! wheel is the repository's own content.
//!
//! Logical-line model: physical lines join on a trailing `\`; comments start
//! at a `#` preceded by whitespace (or column 0) outside that. The dominant
//! newline style is preserved.

use std::collections::HashSet;
use std::path::Path;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::line_endings::{self, terminator};
use crate::utils::requirements::{
    expand_env_vars, hash_options, logical_lines, parse_requirement, requirement_name,
    requires_hashes, shlex_split, split_comment, strip_comment, vendor_tag,
};

use super::common::refuse_symlinked;
use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorWarning};

/// Classification of the target package within one requirements file read
/// as the whole requirement set ([`find_pin`], the tests' view of
/// [`scan_pins`]).
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum PinSearch {
    /// A clean `name==version` pin (no extras). `line_start` / `line_count`
    /// span the PHYSICAL lines (0-based) of the first matching logical line.
    Exact {
        line_start: usize,
        line_count: usize,
        /// The environment marker verbatim (text after `;`), to carry over.
        marker: Option<String>,
        /// The pin carries `--hash` options (informational; the rewrite
        /// always emits a fresh `--hash`).
        hashed: bool,
    },
    /// The pin names the package with extras (`requests[socks]==…`) — a path
    /// line cannot express extras, so the vendor refuses.
    Extras,
    /// The package is named but not exactly `==version`-pinned (range
    /// specifier, bare name, or a pin to a different version).
    Range,
    /// The package is not named in this file.
    Absent,
}

/// One clean exact pin occurrence: `(line_start, line_count, marker, hashed)`
/// — the PHYSICAL-line span (0-based) of the logical line, the environment
/// marker to carry over, and whether the pin carried `--hash` options.
type PinSpan = (usize, usize, Option<String>, bool);

/// What one file says about the target package ([`scan_pins`]).
struct PinScan {
    /// Every clean exact `canon_name==version` pin.
    exact: Vec<PinSpan>,
    /// Some occurrence carries extras.
    extras: bool,
    /// Some occurrence names the package ambiguously on its own.
    range: bool,
    /// Some occurrence exactly pins a DIFFERENT version on its own
    /// environment-marker branch; whether that is ambiguous depends on the
    /// target pins of the whole requirement set ([`marker_split_ok`]).
    other_branches: bool,
}

/// Whether the other version's marker branches (if any) in a requirement
/// set are harmless given its target pins: every target pin must carry a
/// marker too, and there must be one. That is the shape `uv pip compile --universal` writes when
/// a package resolves differently per Python (#928), and pip installs
/// exactly one branch. Only the target branches are rewritten; the other
/// branch is left alone, as hosted requirements and vendored pylock already
/// do. Without markers on both sides pip could see both pins at once, so it
/// stays a refusal.
///
/// pip merges the root file and its `-r` includes into one requirement set,
/// so [`plan_requirements`] asks this once over every file's scan: the two
/// branches may sit in different files (#1104).
fn marker_split_ok(scans: &[PinScan]) -> bool {
    let mut exact = scans.iter().flat_map(|s| s.exact.iter()).peekable();
    !scans.iter().any(|s| s.other_branches)
        || (exact.peek().is_some() && exact.all(|(_, _, marker, _)| marker.is_some()))
}

/// Why one file's pins refuse the vendor, in fail-closed precedence: any
/// extras occurrence wins over any ambiguous occurrence wins over the other
/// version's marker branch when the requirement set's target pins do not
/// all carry a marker (`split_ok` from [`marker_split_ok`]).
#[derive(Debug, PartialEq, Eq)]
enum PinRefusal {
    Extras,
    NotPinned,
    UnmarkedSplit,
}

fn pin_refusal(scan: &PinScan, split_ok: bool) -> Option<PinRefusal> {
    if scan.extras {
        Some(PinRefusal::Extras)
    } else if scan.range {
        Some(PinRefusal::NotPinned)
    } else if scan.other_branches && !split_ok {
        Some(PinRefusal::UnmarkedSplit)
    } else {
        None
    }
}

/// Scan one file for the target package: every clean exact
/// `canon_name==version` pin, plus whether any occurrence carries extras,
/// names the package ambiguously, or pins another version on its own
/// marker branch ([`marker_split_ok`]).
fn scan_pins(content: &str, canon_name: &str, version: &str) -> PinScan {
    let mut exact: Vec<PinSpan> = Vec::new();
    let mut found_extras = false;
    let mut found_range = false;
    let mut other_branches = false;
    for ll in logical_lines(content) {
        let code = strip_comment(&ll.text);
        let Some(req) = parse_requirement(code) else {
            // A line that names the package but is no requirement pip
            // reads cleanly is never a pin to rewrite (fail closed).
            if requirement_name(code).is_some_and(|name| canonicalize_pypi_name(name) == canon_name)
            {
                found_range = true;
            }
            continue;
        };
        if canonicalize_pypi_name(req.name) != canon_name {
            continue;
        }
        if req.extras.is_some() {
            found_extras = true;
            continue;
        }
        // pip resolves `==` under PEP 440 (`==1.16` installs 1.16.0).
        // Arbitrary equality (`===`) stays a refusal here by policy: the
        // vendored rewrite replaces only an exact registry pin.
        let pinned = req.exact_version();
        let hashed = req.options.contains("--hash");
        // The rewritten wheel line carries only `--hash`: a pin with any
        // other per-requirement option (`--config-settings`, its short
        // `-C`, …; a `--hash` value never starts with `-`) would lose
        // it, so it is refused rather than rewritten.
        let other_options = req
            .options
            .split_whitespace()
            .any(|token| token.starts_with('-') && !token.starts_with("--hash"));
        if other_options {
            found_range = true;
            continue;
        }
        if pinned.is_some_and(|pinned| crate::utils::pep440::versions_equal(pinned, version)) {
            exact.push((
                ll.start,
                ll.physical.len(),
                req.marker.map(str::to_string),
                hashed,
            ));
        } else if req.marker.is_some() && pinned.is_some_and(crate::utils::pep440::is_valid) {
            other_branches = true;
        } else {
            found_range = true;
        }
    }
    PinScan {
        exact,
        extras: found_extras,
        range: found_range,
        other_branches,
    }
}

/// Whether one requirements file's content names the package at all (any
/// spec, extras or marker): a file that pins it is an install source of it.
pub(super) fn names_package(content: &str, canon_name: &str) -> bool {
    logical_lines(content).into_iter().any(|ll| {
        requirement_name(strip_comment(&ll.text))
            .is_some_and(|name| canonicalize_pypi_name(name) == canon_name)
    })
}

/// Find the target pin in one file's content, read as the whole
/// requirement set, through the same [`pin_refusal`] precedence
/// [`plan_requirements`] applies: a file that names the package ambiguously
/// is never rewritten (a marker-split other version is not ambiguous; see
/// [`marker_split_ok`]).
#[cfg(test)]
fn find_pin(content: &str, canon_name: &str, version: &str) -> PinSearch {
    let scan = scan_pins(content, canon_name, version);
    let split_ok = marker_split_ok(std::slice::from_ref(&scan));
    match pin_refusal(&scan, split_ok) {
        Some(PinRefusal::Extras) => return PinSearch::Extras,
        Some(PinRefusal::NotPinned | PinRefusal::UnmarkedSplit) => return PinSearch::Range,
        None => {}
    }
    match scan.exact.into_iter().next() {
        Some((line_start, line_count, marker, hashed)) => PinSearch::Exact {
            line_start,
            line_count,
            marker,
            hashed,
        },
        None => PinSearch::Absent,
    }
}

/// Pre-flight verdict: wire fresh, or the files are already wired to this
/// exact patch generation (mirrors `UvTarget` / `PoetryTarget`).
pub(super) enum RequirementsTarget {
    Fresh,
    InSync {
        /// The wheel path + sha256 the wired vendor line still pins — the
        /// very pin `pip install --require-hashes` verifies. The in-sync
        /// rebuild guard falls back to it when the state.json ledger has no
        /// entry left for the patch. An unhashed vendor line (written into
        /// an unhashed requirements set) pins its path alone: the sha256 is
        /// empty and the guard checks only the path.
        pin: Option<(String, String)>,
    },
    /// The files route the package to socket-patch's own vendored wheel for
    /// an OLDER patch uuid, and the ledger still holds that entry: re-wire
    /// its recorded vendor lines in place to the superseding uuid
    /// ([`rewire_requirements`]), carrying the pre-vendor originals over.
    Rewire {
        prev: Box<VendorEntry>,
    },
}

/// Pre-flight the wiring without writing — the orchestrator runs this before
/// building the wheel so every refusal happens with the tree byte-untouched.
///
/// A file already carrying a socket vendor line for this package
/// short-circuits the plan: at the SAME patch uuid it is our own first-run
/// edit (in sync — the artifact-only rebuild path handles a deleted wheel);
/// at a DIFFERENT uuid it is a superseding patch (#765), re-wired in place
/// when the ledger still records that older entry's wiring
/// ([`RequirementsTarget::Rewire`]). Without that record it refuses:
/// appending a second wheel line would leave pip two competing
/// requirements, and a re-wire with no recorded pre-vendor original could
/// never be reverted.
pub(super) async fn preflight_requirements(
    root: &Path,
    canon_name: &str,
    version: &str,
    record_uuid: &str,
) -> Result<RequirementsTarget, (&'static str, String)> {
    let files = collect_requirements_files(root).await?;
    for file in &files {
        if let Some(found) = vendored_uuid_for(&file.content, canon_name) {
            if found == record_uuid {
                return Ok(RequirementsTarget::InSync {
                    pin: wired_pin_in(&file.content, canon_name, record_uuid),
                });
            }
            let refused = |why: &str| {
                (
                    "pypi_requirements_already_vendored",
                    format!(
                        "{}: already routes {canon_name} to the socket-patch vendored wheel for \
                         patch {found}{why}; {remedy}",
                        file.rel,
                        remedy = super::common::REVERT_ALL_AND_REVENDOR,
                    ),
                )
            };
            let Some(prev) = superseded_entry(root, canon_name, version, &found).await else {
                return Err(refused(
                    " and the vendor ledger records no wiring for it to carry over",
                ));
            };
            return match plan_rewire(&files, &prev, canon_name, version, "", "") {
                Ok(_) => Ok(RequirementsTarget::Rewire {
                    prev: Box::new(prev),
                }),
                Err(why) => Err(refused(&format!(" ({why})"))),
            };
        }
    }
    plan_requirements(root, canon_name, version, "", "")
        .await
        .map(|_| RequirementsTarget::Fresh)
}

/// The vendor lines for `canon_name` in one file's content, read as pip's
/// logical lines: `(wheel-path token's vendor path parts, bare token, code)`
/// for every line whose comment carries the
/// `# socket-patch vendor: <name>==<version>` tag ([`vendor_tag`]) and whose
/// first token is a pypi vendor path — the exact shape [`vendor_line`]
/// writes, lexed like lockfile discovery reads it.
fn vendor_lines<'a>(
    content: &'a str,
    canon_name: &'a str,
) -> impl Iterator<Item = (super::path::VendorPathParts, String, String)> + 'a {
    logical_lines(content).into_iter().filter_map(move |ll| {
        let (code, comment) = split_comment(&ll.text);
        let (name, _) = comment.and_then(vendor_tag)?;
        if name != canon_name {
            return None;
        }
        let token = code.split_whitespace().next()?;
        let parts = super::path::parse_vendor_path(token).filter(|p| p.eco == "pypi")?;
        Some((parts, token.to_string(), code.to_string()))
    })
}

/// Whether one file's content holds a socket vendor line for `canon_name`
/// ([`vendor_lines`]).
pub(super) fn has_vendor_line(content: &str, canon_name: &str) -> bool {
    vendor_lines(content, canon_name).next().is_some()
}

/// Find a socket vendor line for `canon_name` in one file's content and
/// return the patch uuid its wheel path names ([`vendor_lines`]).
fn vendored_uuid_for(content: &str, canon_name: &str) -> Option<String> {
    vendor_lines(content, canon_name)
        .next()
        .map(|(parts, _, _)| parts.uuid)
}

/// Extract the (wheel path, sha256) pin the wired vendor line for
/// `canon_name` carries — the same line shape [`vendored_uuid_for`] matches,
/// restricted to THIS patch uuid. A line with no `--hash` (vendor writes
/// none into an unhashed requirements set) still pins its path, with an
/// empty sha256; a `--hash` that is not a sha256 hex digest pins nothing.
/// Paths are returned bare (no `./` prefix), matching the ledger's
/// `artifact.path` spelling.
fn wired_pin_in(content: &str, canon_name: &str, record_uuid: &str) -> Option<(String, String)> {
    vendor_lines(content, canon_name).find_map(|(parts, token, code)| {
        if parts.uuid != record_uuid {
            return None;
        }
        let sha = hash_options(&code).into_iter().next().unwrap_or_default();
        if !sha.is_empty() && (sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit())) {
            return None;
        }
        let path = token.strip_prefix("./").unwrap_or(&token);
        Some((path.to_string(), sha))
    })
}

/// Whether the requirements set beside a Pipenv or uv lock (`pipenv
/// requirements > requirements.txt`, `uv export -o requirements.txt`: the
/// Docker / plain-pip install path) pins `canon_name==version` exactly from
/// the registry in a shape the wiring rewrites in place, with no vendor line
/// for the package yet (#612, #1368). Vendored Pipenv and uv wire such a pin
/// together with their lock, as hosted mode rewrites both; anything else (no
/// pin, a range, extras, an include outside the root, an existing vendor
/// line, a symlinked file the rewrite would replace) is left to the
/// `pypi_multiple_lockfiles` warning.
pub(super) async fn sibling_pin_wirable(root: &Path, canon_name: &str, version: &str) -> bool {
    let Ok(files) = collect_requirements_files(root).await else {
        return false;
    };
    if files
        .iter()
        .any(|f| vendored_uuid_for(&f.content, canon_name).is_some())
    {
        return false;
    }
    let Ok(plan) = plan_requirements(root, canon_name, version, "", "").await else {
        return false;
    };
    let rels: Vec<&str> = plan.iter().map(|f| f.rel.as_str()).collect();
    !plan.is_empty()
        && plan
            .iter()
            .flat_map(|f| f.records.iter())
            .all(|r| r.action == WiringAction::Rewritten)
        && refuse_symlinked(root, &rels).await.is_ok()
}

/// The `requirements_line` records of a mixed entry (a Pipenv or uv entry
/// that also wired its exported requirements file, #612 / #1368).
pub(super) const RECORD_KIND: &str = "requirements_line";

/// Refuse a wheel path or digest that cannot sit on one requirements line
/// as a single token: a CR/LF (or any whitespace / control character) would
/// let a caller-supplied path (a committed ledger's, say) add requirement
/// lines or options of its own.
pub(super) fn check_line_tokens(
    rel_wheel: &str,
    wheel_sha256_hex: &str,
) -> Result<(), (&'static str, String)> {
    let bad_path = rel_wheel.is_empty()
        || rel_wheel
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '#');
    let bad_hash = !wheel_sha256_hex.chars().all(|c| c.is_ascii_hexdigit());
    if bad_path || bad_hash {
        return Err((
            "vendor_path_unsafe",
            format!(
                "refusing to write the vendored wheel path {rel_wheel:?} (sha256 \
                 {wheel_sha256_hex:?}) into requirements.txt: it is not a single plain token"
            ),
        ));
    }
    Ok(())
}

/// Rewrite every exact pin across the root `requirements.txt` and its `-r`
/// includes (or append a managed transitive line at the root EOF when the
/// package is absent). Returns the wiring records in application order.
pub(super) async fn wire_requirements(
    root: &Path,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_sha256_hex: &str,
) -> Result<Vec<WiringRecord>, (&'static str, String)> {
    check_line_tokens(rel_wheel, wheel_sha256_hex)?;
    let plan = plan_requirements(root, canon_name, version, rel_wheel, wheel_sha256_hex).await?;
    write_plan(root, &plan).await
}

/// Re-wire the vendor lines `prev` (the ledger entry of an OLDER patch uuid
/// for this package) recorded, in place, to the superseding wheel (#765).
/// Each returned record keeps `prev`'s file, key, action and pre-vendor
/// `original`, so reverting the new entry restores the user's own pins.
pub(super) async fn rewire_requirements(
    root: &Path,
    prev: &VendorEntry,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_sha256_hex: &str,
) -> Result<Vec<WiringRecord>, (&'static str, String)> {
    check_line_tokens(rel_wheel, wheel_sha256_hex)?;
    let files = collect_requirements_files(root).await?;
    let plan = plan_rewire(
        &files,
        prev,
        canon_name,
        version,
        rel_wheel,
        wheel_sha256_hex,
    )
    .map_err(|why| {
        (
            "pypi_requirements_already_vendored",
            format!(
                "cannot re-wire {canon_name} from patch {}: {why}; {remedy}",
                prev.uuid,
                remedy = super::common::REVERT_ALL_AND_REVENDOR,
            ),
        )
    })?;
    write_plan(root, &plan).await
}

/// Write a planned edit set, unwinding the files already written if any
/// write fails. Returns the wiring records in application order.
async fn write_plan(
    root: &Path,
    plan: &[PlannedFile],
) -> Result<Vec<WiringRecord>, (&'static str, String)> {
    // Before ANY write: a symlinked requirements file (root or `-r` include)
    // would be replaced by the rename-over.
    let planned: Vec<&str> = plan.iter().map(|f| f.rel.as_str()).collect();
    refuse_symlinked(root, &planned).await?;
    let mut wiring = Vec::new();
    let mut written: Vec<&PlannedFile> = Vec::new();
    for file in plan {
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&root.join(&file.rel), file.new_content.as_bytes())
                .await
        {
            // Unwind: the orchestrator sweeps the wheel dir on a wiring
            // error, so a surviving half-wired file would reference a
            // deleted artifact — with no ledger entry recorded to revert it.
            for w in written.iter().rev() {
                let _ = atomic_write_bytes_preserving_mode(
                    &root.join(&w.rel),
                    w.original_content.as_bytes(),
                )
                .await;
            }
            return Err((
                "pypi_requirements_write_failed",
                format!("cannot write {}: {e}", file.rel),
            ));
        }
        written.push(file);
        wiring.extend(file.records.iter().cloned());
    }
    Ok(wiring)
}

/// Reverse the wiring: splice the recorded original physical lines back over
/// each vendor line (or delete an appended line). Lines that no longer match
/// what vendor wrote are left alone with `vendor_revert_line_drifted`; any
/// surviving reference to the vendored uuid dir afterwards raises
/// `vendor_revert_residual_reference`.
pub(super) async fn revert_requirements(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    let mut warnings: Vec<VendorWarning> = Vec::new();

    // Group records per file, preserving application order within each.
    //
    // SECURITY: `rec.file` comes verbatim from the committed, tamper-able
    // state.json and is about to be READ and atomically REWRITTEN. Every
    // other backend writes only to fixed/whitelisted lockfile paths; the
    // requirements flavor legitimately edits multiple files (`-r` includes),
    // so each recorded path must re-pass the same in-root constraint
    // vendor-time planning enforced — a `..`/absolute/NUL path would
    // otherwise let a poisoned ledger splice attacker `original` lines into
    // an arbitrary file via `vendor --revert`. Reject fail-closed per file
    // (skip + drift warning), never fail open.
    let mut files: Vec<String> = Vec::new();
    for rec in &entry.wiring {
        let norm = rec.file.replace('\\', "/");
        if norm.is_empty()
            || norm.starts_with('/')
            || norm.contains('\0')
            || !crate::patch::apply::is_safe_relative_subpath(&norm)
        {
            warnings.push(VendorWarning::new(
                "vendor_revert_line_drifted",
                format!(
                    "refusing to revert wiring record for unsafe path `{}` \
                     (outside the project root)",
                    rec.file
                ),
            ));
            continue;
        }
        if !files.contains(&rec.file) {
            files.push(rec.file.clone());
        }
    }

    // A symlinked file would be replaced by the atomic rewrite-over, leaving
    // its target stale and never restoring the link. Keep the artifact (the
    // wiring still routes through the linked file) and fail.
    let file_refs: Vec<&str> = files.iter().map(String::as_str).collect();
    if let Err((code, detail)) = refuse_symlinked(root, &file_refs).await {
        return RevertOutcome {
            kept_artifact: true,
            success: false,
            warnings,
            error: Some(format!("{code}: {detail}")),
        };
    }

    let mut reverted: Vec<(String, String)> = Vec::new();
    for file in &files {
        let path = root.join(file);
        let content = match read_regular_to_string(&path).await {
            Ok(c) => c,
            Err(e) => {
                return RevertOutcome::failed(format!("cannot read {file}: {e}"));
            }
        };
        let nl = terminator(&content);
        let mut lines = split_lines(&content);

        // Reverse order = bottom-up matching, so identical vendor lines pair
        // with their own originals (records were emitted top-down).
        for rec in entry.wiring.iter().rev().filter(|r| &r.file == file) {
            let Some(new_line) = rec.new.as_ref().and_then(serde_json::Value::as_str) else {
                warnings.push(drift_warning(file, rec));
                continue;
            };
            let Some(idx) = lines.iter().rposition(|l| l.text.trim() == new_line.trim()) else {
                warnings.push(drift_warning(file, rec));
                continue;
            };
            match rec.action {
                WiringAction::Added => {
                    lines.remove(idx);
                }
                WiringAction::Rewritten => {
                    let originals: Vec<&str> = rec
                        .original
                        .as_ref()
                        .and_then(serde_json::Value::as_array)
                        .map(|arr| arr.iter().filter_map(serde_json::Value::as_str).collect())
                        .unwrap_or_default();
                    let restored = restored_span(&originals, lines[idx].eol, nl);
                    lines.splice(idx..idx + 1, restored);
                }
            }
        }

        reverted.push((file.clone(), join_lines(&lines)));
    }

    if !dry_run {
        for (file, content) in &reverted {
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&root.join(file), content.as_bytes()).await
            {
                return RevertOutcome {
                    kept_artifact: false,
                    success: false,
                    warnings,
                    error: Some(format!("cannot write {file}: {e}")),
                };
            }
        }
    }

    // Residual-reference sweep over the reverted contents: a leftover line
    // pointing at the (about to be deleted) uuid dir would break installs.
    let needle = format!(".socket/vendor/pypi/{}", entry.uuid);
    for (file, content) in &reverted {
        if content.contains(&needle) {
            warnings.push(VendorWarning::new(
                "vendor_revert_residual_reference",
                format!("{file} still references {needle} after revert"),
            ));
        }
    }

    RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    }
}

fn drift_warning(file: &str, rec: &WiringRecord) -> VendorWarning {
    VendorWarning::new(
        "vendor_revert_line_drifted",
        format!(
            "{file}: the vendor line for {} changed since vendoring; left untouched",
            rec.key_label()
        ),
    )
}

// ── planning ─────────────────────────────────────────────────────────────

/// One physical line and the terminator it ends with: `"\r\n"`, `"\n"`, or
/// `""` for an unterminated last line. The writers edit these so a file that
/// mixes CRLF and LF keeps every line they leave alone byte for byte
/// (#1567). Splitting with `str::lines()` and re-joining with one terminator
/// re-terminated every minority-style line.
#[derive(Debug, Clone)]
struct Line {
    text: String,
    eol: &'static str,
}

/// `content`'s physical lines, indexed like `str::lines()` (the indices
/// [`scan_pins`] reports).
fn split_lines(content: &str) -> Vec<Line> {
    line_endings::split_lines(content)
        .into_iter()
        .map(|(text, eol)| Line {
            text: text.to_string(),
            eol,
        })
        .collect()
}

/// The recorded `original` of a replaced span: each physical line's text.
/// The span's last line ends the way the vendor line does, so the revert
/// takes its ending from there; an earlier line whose ending differs from
/// it (a continuation that mixes CRLF and LF) keeps its ending in the
/// record ([`restored_span`] reads it back).
fn recorded_span(span: &[Line]) -> Vec<serde_json::Value> {
    let last_eol = span.last().map_or("", |l| l.eol);
    let count = span.len();
    span.iter()
        .enumerate()
        .map(|(i, l)| {
            let text = if i + 1 < count && l.eol != last_eol {
                format!("{}{}", l.text, l.eol)
            } else {
                l.text.clone()
            };
            serde_json::Value::String(text)
        })
        .collect()
}

/// The lines a [`recorded_span`] restores in place of a vendor line that
/// ends with `eol`. A recorded line that keeps its own ending gets it back;
/// the others end like the vendor line, or, before an unterminated vendor
/// line, in the file's terminator `nl` (records written before #1567 keep
/// no endings at all).
fn restored_span(originals: &[&str], eol: &'static str, nl: &'static str) -> Vec<Line> {
    let inner = if eol.is_empty() { nl } else { eol };
    let mut lines: Vec<Line> = originals
        .iter()
        .map(|text| match line_endings::split_lines(text).as_slice() {
            [(text, own)] if !own.is_empty() => Line {
                text: text.to_string(),
                eol: own,
            },
            _ => Line {
                text: text.to_string(),
                eol: inner,
            },
        })
        .collect();
    if let Some(last) = lines.last_mut() {
        last.eol = eol;
    }
    lines
}

/// The content [`split_lines`] read, with any edits made to it.
fn join_lines(lines: &[Line]) -> String {
    lines
        .iter()
        .flat_map(|l| [l.text.as_str(), l.eol])
        .collect()
}

struct PlannedFile {
    /// Root-relative, forward-slashed path.
    rel: String,
    /// The pre-edit content, kept so a multi-file write that fails partway
    /// can restore the files already written.
    original_content: String,
    new_content: String,
    records: Vec<WiringRecord>,
}

/// One reachable requirements file.
struct ReqFile {
    rel: String,
    content: String,
    /// In-root files may be edited; out-of-root includes are read-only
    /// (their pins refuse the vendor instead).
    editable: bool,
}

/// Compute the full edit set (or refuse). Pure read — no writes happen here.
async fn plan_requirements(
    root: &Path,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_sha256_hex: &str,
) -> Result<Vec<PlannedFile>, (&'static str, String)> {
    let files = collect_requirements_files(root).await?;
    // pip's hash-checking mode spans the whole install: every reachable
    // file (includes too) decides whether the vendor line is hashed.
    let hashed = files.iter().any(|f| requires_hashes(&f.content));
    let mut planned: Vec<PlannedFile> = Vec::new();
    let mut rewrote_any = false;

    let scans: Vec<PinScan> = files
        .iter()
        .map(|f| scan_pins(&f.content, canon_name, version))
        .collect();
    // pip reads the root and its includes as one requirement set, so the
    // other version's marker branch may sit in a different file than the
    // target's (#1104): decide that over the whole tree.
    let split_ok = marker_split_ok(&scans);

    for (file, scan) in files.iter().zip(scans) {
        match pin_refusal(&scan, split_ok) {
            Some(PinRefusal::Extras) => {
                return Err((
                    "pypi_extras_unsupported",
                    format!(
                        "{}: the {canon_name} pin declares extras, which a vendored wheel path \
                         line cannot express; remove the extras or use agent mode \
                         (`scan --mode agent` + `socket-patch apply`) instead",
                        file.rel
                    ),
                ));
            }
            Some(PinRefusal::NotPinned) => {
                return Err((
                    "pypi_requirement_not_pinned",
                    format!(
                        "{}: {canon_name} is not pinned to =={version}; pin it exactly or use \
                         agent mode (`scan --mode agent` + `socket-patch apply`) instead",
                        file.rel
                    ),
                ));
            }
            Some(PinRefusal::UnmarkedSplit) => {
                return Err((
                    "pypi_requirement_not_pinned",
                    format!(
                        "{}: pins another {canon_name} version on an environment-marker \
                         branch, but not every =={version} pin in the requirements tree sits \
                         on a marker branch of its own (or there is none), so pip may install \
                         either version; pin =={version} on its own marker branch or use agent \
                         mode (`scan --mode agent` + `socket-patch apply`) instead",
                        file.rel
                    ),
                ));
            }
            None => {}
        }
        if scan.exact.is_empty() {
            continue;
        }
        if !file.editable {
            // SECURITY/scope: an include outside the project root cannot be
            // edited by a committable vendor flow; rewriting only the in-root
            // copy would leave pip a duplicate requirement. Fail closed.
            return Err((
                "pypi_requirements_outside_root",
                format!(
                    "{}: {canon_name} is pinned in a requirements include outside the project \
                     root, which vendor cannot edit; inline it or use agent mode \
                     (`scan --mode agent` + `socket-patch apply`) instead",
                    file.rel
                ),
            ));
        }

        // Rewrite EVERY exact-pin occurrence in this file, bottom-up so the
        // recorded spans (against the original content) stay valid.
        let spans = scan.exact;
        let original_lines = split_lines(&file.content);
        let mut lines = original_lines.clone();
        let mut records = Vec::new();
        for (start, count, marker, _) in spans.iter().rev() {
            let line = vendor_line(
                rel_wheel,
                hashed.then_some(wheel_sha256_hex),
                canon_name,
                version,
                marker,
                false,
            );
            let replaced = &original_lines[*start..*start + *count];
            // The vendor line ends the way the span's last line did.
            let eol = replaced.last().map_or("", |l| l.eol);
            lines.splice(
                *start..*start + *count,
                [Line {
                    text: line.clone(),
                    eol,
                }],
            );
            records.push(WiringRecord {
                file: file.rel.clone(),
                kind: RECORD_KIND.to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{}:{}", file.rel, start + 1)),
                original: Some(serde_json::Value::Array(recorded_span(replaced))),
                new: Some(serde_json::Value::String(line)),
            });
        }
        records.reverse(); // application order = top-down
        planned.push(PlannedFile {
            rel: file.rel.clone(),
            original_content: file.content.clone(),
            new_content: join_lines(&lines),
            records,
        });
        rewrote_any = true;
    }

    if !rewrote_any {
        // Transitive: append a managed line at the ROOT file's EOF. pip
        // treats it as one more requirement and the resolver folds it into
        // the graph.
        let root_file = files
            .first()
            .expect("collect_requirements_files always yields the root file first");
        let line = vendor_line(
            rel_wheel,
            hashed.then_some(wheel_sha256_hex),
            canon_name,
            version,
            &None,
            true,
        );
        let nl = terminator(&root_file.content);
        let mut new_content = root_file.content.clone();
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push_str(nl);
        }
        new_content.push_str(&line);
        new_content.push_str(nl);
        planned.push(PlannedFile {
            rel: root_file.rel.clone(),
            original_content: root_file.content.clone(),
            new_content,
            records: vec![WiringRecord {
                file: root_file.rel.clone(),
                kind: "requirements_line".to_string(),
                action: WiringAction::Added,
                key: Some(format!("{}:eof", root_file.rel)),
                original: None,
                new: Some(serde_json::Value::String(line)),
            }],
        });
    }
    Ok(planned)
}

/// The ledger entry an OLDER patch uuid left for this package's
/// requirements wiring: a pypi entry at `uuid` whose every record is a
/// `requirements_line` tagged `canon_name==version`. `None` when the ledger
/// is missing or unreadable, holds no such entry, or holds more than one
/// (ambiguous: no single set of originals to carry over).
async fn superseded_entry(
    root: &Path,
    canon_name: &str,
    version: &str,
    uuid: &str,
) -> Option<VendorEntry> {
    let state = super::state::load_state_shared(root).await.ok()?;
    let mut hits = state.entries.values().filter(|e| {
        e.ecosystem == "pypi"
            && e.uuid == uuid
            && !e.wiring.is_empty()
            && e.wiring.iter().all(|r| {
                r.kind == "requirements_line"
                    && r.new
                        .as_ref()
                        .and_then(serde_json::Value::as_str)
                        .and_then(|line| split_comment(line).1)
                        .and_then(vendor_tag)
                        .is_some_and(|(n, v)| n == canon_name && v == version)
            })
    });
    let hit = hits.next()?.clone();
    hits.next().is_none().then_some(hit)
}

/// The environment marker a vendor line carries (`./<wheel> ; <marker>
/// [--hash=…]`, the shape [`vendor_line`] writes), from its code part.
fn vendor_line_marker(code: &str) -> Option<String> {
    let rest = code.trim().split_once(char::is_whitespace)?.1.trim_start();
    let marker = rest.strip_prefix(';')?;
    let end = marker.find("--hash").unwrap_or(marker.len());
    let marker = marker[..end].trim();
    (!marker.is_empty()).then(|| marker.to_string())
}

/// Plan the in-place re-wire of `prev`'s recorded vendor lines to the
/// superseding wheel (#765). Pure read. Every line `prev` recorded must
/// still be present verbatim in an editable file of the tree, and they must
/// be ALL the vendor lines for the package (an unrecorded one could not be
/// reverted); otherwise the reason is returned.
fn plan_rewire(
    files: &[ReqFile],
    prev: &VendorEntry,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_sha256_hex: &str,
) -> Result<Vec<PlannedFile>, String> {
    let hashed = files.iter().any(|f| requires_hashes(&f.content));
    let mut order: Vec<&str> = Vec::new();
    for rec in &prev.wiring {
        if !order.contains(&rec.file.as_str()) {
            order.push(&rec.file);
        }
    }
    let mut planned = Vec::new();
    let mut rewired = 0usize;
    for rel in order {
        let Some(file) = files.iter().find(|f| f.rel == rel) else {
            return Err(format!(
                "the recorded {rel} is no longer part of the requirements tree"
            ));
        };
        if !file.editable {
            return Err(format!("{rel} is outside the project root"));
        }
        let mut lines = split_lines(&file.content);
        let mut taken: HashSet<usize> = HashSet::new();
        let mut records = Vec::new();
        // Bottom-up, pairing identical lines with their own records exactly
        // as the revert does.
        for rec in prev.wiring.iter().rev().filter(|r| r.file == rel) {
            let old = rec
                .new
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{rel}: a recorded vendor line is empty"))?;
            let idx = (0..lines.len())
                .rev()
                .find(|i| !taken.contains(i) && lines[*i].text.trim() == old.trim())
                .ok_or_else(|| format!("{rel}: the vendor line changed since vendoring"))?;
            let marker = vendor_line_marker(split_comment(old).0);
            let line = vendor_line(
                rel_wheel,
                hashed.then_some(wheel_sha256_hex),
                canon_name,
                version,
                &marker,
                rec.action == WiringAction::Added,
            );
            lines[idx].text = line.clone();
            taken.insert(idx);
            records.push(WiringRecord {
                new: Some(serde_json::Value::String(line)),
                ..rec.clone()
            });
        }
        records.reverse(); // application order = top-down
        rewired += records.len();
        planned.push(PlannedFile {
            rel: file.rel.clone(),
            original_content: file.content.clone(),
            new_content: join_lines(&lines),
            records,
        });
    }
    let live: usize = files
        .iter()
        .map(|f| vendor_lines(&f.content, canon_name).count())
        .sum();
    if live != rewired {
        return Err(format!(
            "the requirements tree has {live} vendor line(s) for {canon_name}, the vendor \
             ledger records {rewired}"
        ));
    }
    Ok(planned)
}

/// The committed vendor line. `sha256_hex` is the `--hash` pin, `None` for a
/// requirements tree outside hash-checking mode (module docs). `transitive`
/// adds the `(transitive)` note so a reader knows the line was appended (no
/// pin was replaced).
///
/// Visible to the rest of `vendor` so the lockfile inventory's round-trip
/// test can read back exactly what this writes (the two grammars — the one
/// that writes a vendored line and the one that reads it — must agree).
pub(in crate::vendor) fn vendor_line(
    rel_wheel: &str,
    sha256_hex: Option<&str>,
    canon_name: &str,
    version: &str,
    marker: &Option<String>,
    transitive: bool,
) -> String {
    let marker_part = marker
        .as_ref()
        .map(|m| format!(" ; {m}"))
        .unwrap_or_default();
    let hash_part = sha256_hex
        .map(|hex| format!(" --hash=sha256:{hex}"))
        .unwrap_or_default();
    let note = if transitive { " (transitive)" } else { "" };
    format!(
        "./{rel_wheel}{marker_part}{hash_part}  # socket-patch vendor: {canon_name}=={version}{note}"
    )
}

/// Walk the root `requirements.txt` plus its `-r`/`--requirement` includes
/// (depth-first, resolved against the INCLUDING file's directory, visited-set
/// cycle guard). `-c` constraints files are never followed — they may not
/// introduce requirements, so a pin there is pip's problem, not ours, and we
/// must never edit them. The root file is always element 0.
async fn collect_requirements_files(root: &Path) -> Result<Vec<ReqFile>, (&'static str, String)> {
    let mut out: Vec<ReqFile> = Vec::new();
    // Strict UTF-8: the planner rewrites these files byte-exact, so a file
    // in another encoding is refused below rather than re-encoded.
    let utf8 = |bytes: Vec<u8>| {
        String::from_utf8(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    };
    let view = crate::vendor::lock_inventory::ProjectView::Disk(root);
    walk_requirements_tree(view, utf8, |rel, read| match read {
        Ok(content) => {
            // Out-of-root (`../`) and absolute includes resolve outside any
            // committable root — readable so a pin inside can refuse, never
            // editable. (`Path::join` passes an absolute `rel` through
            // verbatim.)
            let editable = is_in_root_rel(rel);
            out.push(ReqFile {
                rel: rel.to_string(),
                content,
                editable,
            });
            Ok(true)
        }
        // pip decodes a UTF-16 file by its BOM (#721), so a pin inside one
        // is installed; wiring around it would leave that pin unpatched.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err((
            "pypi_no_requirements",
            format!(
                "{} is not UTF-8 text (for example UTF-16, which Windows PowerShell 5.1 \
                 writes for `pip freeze > requirements.txt`); re-save it as UTF-8 and re-run",
                root.join(rel).display()
            ),
        )),
        Err(_) if out.is_empty() => Err((
            "pypi_no_requirements",
            format!("cannot read {}", root.join(rel).display()),
        )),
        // A broken include is pip's error to report; vendor just can't see
        // inside it. Skip.
        Err(_) => Ok(false),
    })
    .await?;
    // Depth-first stack order put the root last among pushes; restore "root
    // first" deterministically.
    out.sort_by_key(|f| f.rel != "requirements.txt");
    Ok(out)
}

/// The requirements files a fresh wiring of `canon_name==version` would
/// write (the dry run's view of [`wire_requirements`]). Empty when the
/// planner refuses: the wet run reports that refusal instead.
pub(super) async fn planned_files(
    root: &Path,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
) -> Vec<String> {
    let placeholder = "0".repeat(64);
    plan_requirements(root, canon_name, version, rel_wheel, &placeholder)
        .await
        .map(|plan| plan.into_iter().map(|file| file.rel).collect())
        .unwrap_or_default()
}

/// Every requirements file the vendor planner may have written a pin into:
/// the root `requirements.txt` plus each IN-ROOT `-r`/`--requirement`
/// include it reaches (same walk as the planner, so a vendored pin hosted in
/// an include is found where the planner put it). Names are root-relative
/// (`requirements/base.txt`), the root first; a file that does not exist is
/// still named (so a caller probing it sees a clean "absent"), it is just
/// not descended into. FIFO-safe. `Err` when a reached file EXISTS but
/// cannot be read (a permission-denied include, a FIFO in its place): the
/// tree is then unknowable, and callers that must prove the absence of a
/// reference — the unwired-revert guard — fail closed on it. Out-of-root
/// and absolute includes are never editable, so they are neither named nor
/// followed.
pub async fn requirements_include_names(root: &Path) -> std::io::Result<Vec<String>> {
    requirements_include_names_in(crate::vendor::lock_inventory::ProjectView::Disk(root)).await
}

/// [`requirements_include_names`] over any project view (the disk, a
/// snapshot of it, or an in-memory project).
pub(crate) async fn requirements_include_names_in(
    view: crate::vendor::lock_inventory::ProjectView<'_>,
) -> std::io::Result<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    // Decoded as pip decodes it (#1120): a UTF-16 or PEP 263 file is read
    // and descended into, not taken for an unreadable one.
    walk_requirements_tree(view, decode_requirements, |rel, read| {
        if !is_in_root_rel(rel) {
            return Ok(false);
        }
        names.push(rel.to_string());
        match read {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    })
    .await?;
    names.sort_by_key(|rel| rel != "requirements.txt");
    Ok(names)
}

/// A root-relative requirements path that stays inside the project root
/// (not `../…`, not absolute) — the only files the planner may edit.
pub(crate) fn is_in_root_rel(rel: &str) -> bool {
    !rel.starts_with("../") && !Path::new(rel).is_absolute()
}

/// A requirements file's bytes decoded as pip decodes them
/// ([`crate::utils::requirements::decode`]); `InvalidData` when pip's
/// rules give no text this reader can model.
pub(crate) fn decode_requirements(bytes: Vec<u8>) -> std::io::Result<String> {
    crate::utils::requirements::decode(&bytes).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not text pip's decoding rules can read (a byte-order mark, a PEP 263 \
             coding line, or UTF-8)",
        )
    })
}

/// The shared include walk behind [`collect_requirements_files`] and
/// [`requirements_include_names`]: depth-first from the root
/// `requirements.txt`, each `-r`/`--requirement` target resolved against the
/// INCLUDING file's directory and lexically normalized, visited-set cycle
/// guard, FIFO-safe reads, each file's bytes turned into text by `decode`.
/// `visit` sees every reached file with its read result and answers whether
/// to descend into its includes (`Ok(true)`), or aborts the walk with its
/// own error.
async fn walk_requirements_tree<E>(
    view: crate::vendor::lock_inventory::ProjectView<'_>,
    decode: impl Fn(Vec<u8>) -> std::io::Result<String>,
    mut visit: impl FnMut(&str, std::io::Result<String>) -> Result<bool, E>,
) -> Result<(), E> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = vec!["requirements.txt".to_string()];
    while let Some(rel) = stack.pop() {
        if !visited.insert(rel.clone()) {
            continue;
        }
        let read = view.read_bytes(&rel).await.and_then(&decode);
        // Parse the includes BEFORE handing the content over (the visitor
        // takes it by value); nothing is pushed unless it asks to descend.
        let includes: Vec<String> = match &read {
            Ok(content) => requirements_includes(&rel, content),
            Err(_) => Vec::new(),
        };
        if visit(&rel, read)? {
            stack.extend(includes);
        }
    }
    Ok(())
}

/// The `-r`/`--requirement` includes of the requirements file `rel`
/// (root-relative) with `content`, in file order: each target resolved
/// against the INCLUDING file's directory and lexically normalized
/// (`requirements/../x.txt` → `x.txt`; an escape keeps its `../`). The one
/// include grammar behind the planner's walk and the lock inventory's.
pub(crate) fn requirements_includes(rel: &str, content: &str) -> Vec<String> {
    nested_files(rel, content)
        .into_iter()
        .filter_map(|nested| match nested {
            NestedFile::Requirements(target) => Some(target),
            NestedFile::Constraints(_) => None,
        })
        .collect()
}

/// The `-c`/`--constraint` targets of the requirements file `rel`,
/// resolved as [`requirements_includes`] resolves `-r`.
fn requirements_constraints(rel: &str, content: &str) -> Vec<String> {
    nested_files(rel, content)
        .into_iter()
        .filter_map(|nested| match nested {
            NestedFile::Constraints(target) => Some(target),
            NestedFile::Requirements(_) => None,
        })
        .collect()
}

/// The nested files of the requirements file `rel` with `content`, in file
/// order, each resolved against `rel`'s directory and lexically normalized.
fn nested_files(rel: &str, content: &str) -> Vec<NestedFile> {
    let dir = match rel.rfind('/') {
        Some(i) => &rel[..i],
        None => "",
    };
    let resolve = |target: String| {
        let joined = if dir.is_empty() {
            target
        } else {
            format!("{dir}/{target}")
        };
        crate::utils::relpath::normalize_rel_keeping_escapes(&joined)
    };
    logical_lines(content)
        .iter()
        .filter_map(|ll| nested_file(&ll.text))
        .map(|nested| match nested {
            NestedFile::Requirements(target) => NestedFile::Requirements(resolve(target)),
            NestedFile::Constraints(target) => NestedFile::Constraints(resolve(target)),
        })
        .collect()
}

/// A sibling requirements file that pip reads `target` from as constraints
/// (`-c target`), found by [`constraint_readers_in`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConstraintReader {
    /// Root-relative path of the file with the `-c` line.
    pub reader: String,
    /// Root-relative path of the constraints file it names.
    pub target: String,
}

/// Whether `name` looks like a pip requirements file: `*.txt`, or a
/// pip-tools `*.in` input.
fn requirements_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".txt") || lower.ends_with(".in")
}

/// Top-level directories never searched for constraint readers: installed
/// packages and build output, not the project's own requirements.
const NOT_READER_DIRS: &[&str] = &[
    "node_modules",
    "site-packages",
    "venv",
    "env",
    "target",
    "build",
    "dist",
    "__pycache__",
];

/// Every requirements file beside `targets` that names one of them as a
/// `-c` / `--constraint` file (#740). The writers turn a pin in a target
/// into a link (a hosted `@ <url>` or a vendored wheel path), which pip
/// 20.3.x and 21.0.x refuse in a constraints file ("Links are not allowed
/// as constraints"), so each reader found is an install that breaks there.
///
/// Read: each `*.txt` / `*.in` file in the project root and in a root
/// directory whose name mentions `requirement` (`requirements/`), and each
/// one named like requirements (`requirements.txt`, `dev.in`) in the other
/// top-level directories (`docs/requirements.txt`, the Read the Docs
/// layout). Hidden directories and [`NOT_READER_DIRS`] are skipped, and a
/// file whose bytes never hold `-c` is not parsed. A file that cannot be
/// read or decoded is skipped (this only warns). A constraints file named
/// only on the pip command line (`pip install -c requirements.txt`) is not
/// visible here.
pub(crate) async fn constraint_readers_in(
    view: crate::vendor::lock_inventory::ProjectView<'_>,
    targets: &[String],
) -> Vec<ConstraintReader> {
    if targets.is_empty() {
        return Vec::new();
    }
    let mut candidates: Vec<String> = Vec::new();
    let mut dirs: Vec<(String, bool)> = Vec::new();
    for entry in view.list_dir("").await.unwrap_or_default() {
        let lower = entry.name.to_ascii_lowercase();
        if !entry.is_dir {
            if requirements_file_name(&entry.name) {
                candidates.push(entry.name);
            }
        } else if !entry.name.starts_with('.') && !NOT_READER_DIRS.contains(&lower.as_str()) {
            dirs.push((entry.name, lower.contains("requirement")));
        }
    }
    for (dir, every_file) in dirs {
        for entry in view.list_dir(&dir).await.unwrap_or_default() {
            let lower = entry.name.to_ascii_lowercase();
            if !entry.is_dir
                && requirements_file_name(&entry.name)
                && (every_file || lower.contains("requirement") || lower.ends_with(".in"))
            {
                candidates.push(format!("{dir}/{}", entry.name));
            }
        }
    }
    candidates.sort();
    let mut readers = Vec::new();
    for rel in candidates {
        let Ok(bytes) = view.read_bytes(&rel).await else {
            continue;
        };
        // Every `-c` / `--constraint` spelling holds the bytes `-c`; a
        // file without them (UTF-16 aside) is never parsed.
        let utf16 = bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]);
        if !utf16 && !bytes.windows(2).any(|w| w == b"-c") {
            continue;
        }
        let Ok(content) = decode_requirements(bytes) else {
            continue;
        };
        for target in requirements_constraints(&rel, &content) {
            if target != rel && targets.contains(&target) {
                let reader = ConstraintReader {
                    reader: rel.clone(),
                    target,
                };
                if !readers.contains(&reader) {
                    readers.push(reader);
                }
            }
        }
    }
    readers
}

/// The remedy both writers name for a [`ConstraintReader`].
pub(crate) const CONSTRAINT_LINK_REMEDY: &str =
    "pip 20.3.x and 21.0.x refuse a link in a constraints file (\"Links are not allowed as \
     constraints\"), so installing with that file fails on those pips; use pip 21.1 or later \
     (or pip 20.2), or stop reading this file with `-c`";

/// The `-r`/`--requirement` include target of a logical line, if any,
/// read the way pip's `req_file.py` reads it: comment stripped, `${NAME}`
/// expanded from the environment, then the options `shlex`-split, so
/// `-r "dev reqs.txt"`, `-r dev\\ reqs.txt`, `--requirement="dev.txt"` and
/// `-r ${REQDIR}/dev.txt` name the file pip opens (#994).
#[cfg(test)]
fn include_target(text: &str) -> Option<String> {
    include_target_with(text, |name| std::env::var(name).ok())
}

/// [`nested_file_with`] over the process environment.
fn nested_file(text: &str) -> Option<NestedFile> {
    nested_file_with(text, |name| std::env::var(name).ok())
}

/// The long options pip's requirements-file parser knows that take a
/// value (`SUPPORTED_OPTIONS` plus the per-requirement
/// `SUPPORTED_OPTIONS_REQ`, and `--install-option` from older pips).
const REQ_FILE_VALUE_OPTIONS: &[&str] = &[
    "--index-url",
    "--extra-index-url",
    "--constraint",
    "--requirement",
    "--editable",
    "--find-links",
    "--no-binary",
    "--only-binary",
    "--trusted-host",
    "--use-feature",
    "--global-option",
    "--install-option",
    "--hash",
    "--config-settings",
];

/// The flag-only long options of pip's requirements-file parser. Only
/// used to resolve optparse's unique-prefix abbreviations
/// (`--requirem` is `--requirement`, `--require` is ambiguous).
const REQ_FILE_FLAG_OPTIONS: &[&str] =
    &["--no-index", "--prefer-binary", "--require-hashes", "--pre"];

/// Resolve a long option name the way optparse's `_match_abbrev` does: an
/// exact name, else the one known option it is a unique prefix of.
/// `None` for an unknown or ambiguous name.
fn resolve_long_option(name: &str) -> Option<&'static str> {
    let all = REQ_FILE_VALUE_OPTIONS
        .iter()
        .chain(REQ_FILE_FLAG_OPTIONS)
        .copied();
    if let Some(exact) = all.clone().find(|o| *o == name) {
        return Some(exact);
    }
    let mut matches = all.filter(|o| o.starts_with(name));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

/// [`include_target`] with the environment lookup injected (tests).
///
/// pip splits a line into its requirement part (the leading words that
/// don't start with `-`) and its options, and runs optparse over every
/// option word (#1028). A line with a requirement or an `-e` is a
/// requirement, never an include; otherwise the first `-r` value is the
/// file pip follows (`opts.requirements[0]`). An option's value is
/// consumed even when it looks like `-r`, as optparse does.
#[cfg(test)]
fn include_target_with(text: &str, env: impl Fn(&str) -> Option<String>) -> Option<String> {
    match nested_file_with(text, env)? {
        NestedFile::Requirements(target) => Some(target),
        NestedFile::Constraints(_) => None,
    }
}

/// The file an options line makes pip open next, and how pip reads it.
#[derive(Debug, PartialEq, Eq)]
enum NestedFile {
    /// `-r` / `--requirement`: read as requirements.
    Requirements(String),
    /// `-c` / `--constraint`: read as constraints.
    Constraints(String),
}

/// The nested file of a logical line, read with [`include_target_with`]'s
/// option grammar. pip's `handle_option_line` follows ONE file per line:
/// the first `-r` value when the line has one, else the first `-c` value,
/// so `-c c.txt -r dev.txt` follows only `dev.txt`.
fn nested_file_with(text: &str, env: impl Fn(&str) -> Option<String>) -> Option<NestedFile> {
    let code = expand_env_vars(strip_comment(text), env);
    // pip's break_args_options: a leading word without `-` is a
    // requirement, whose per-requirement options never recurse.
    if !code.trim_start().starts_with('-') {
        return None;
    }
    // An unbalanced quote is pip's "Could not split options" error: there
    // is no file to follow.
    let mut words = shlex_split(&code)?.into_iter();
    let mut target: Option<String> = None;
    let mut constraint: Option<String> = None;
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            // An unknown option is pip's parse error; read past it as a
            // flag rather than drop the rest of the line.
            let Some(option) = resolve_long_option(&format!("--{name}")) else {
                continue;
            };
            if !REQ_FILE_VALUE_OPTIONS.contains(&option) {
                continue;
            }
            let value = match attached {
                // `--requirement= dev.txt` (a space after the `=`) is
                // read as the next word, as before the shlex split.
                Some(v) if v.is_empty() && option == "--requirement" => words.next(),
                Some(v) => Some(v),
                None => words.next(),
            };
            match option {
                "--editable" => return None,
                "--requirement" if target.is_none() => target = value,
                "--constraint" if constraint.is_none() => constraint = value,
                _ => {}
            }
        } else if let Some(short) = word.strip_prefix('-') {
            let mut chars = short.chars();
            let Some(flag) = chars.next() else {
                continue;
            };
            if !matches!(flag, 'i' | 'c' | 'r' | 'e' | 'f') {
                continue;
            }
            // pip's optparse also accepts the attached short form
            // (`-rdev.txt`, `-r"dev reqs.txt"`).
            let rest = chars.as_str();
            let value = if rest.is_empty() {
                words.next()
            } else {
                Some(rest.to_string())
            };
            match flag {
                'e' => return None,
                'r' if target.is_none() => target = value,
                'c' if constraint.is_none() => constraint = value,
                _ => {}
            }
        }
        // A bare word among the options is an optparse positional that
        // pip ignores.
    }
    match target {
        Some(target) => (!target.is_empty()).then_some(NestedFile::Requirements(target)),
        None => constraint
            .filter(|c| !c.is_empty())
            .map(NestedFile::Constraints),
    }
}

// The logical-line lexer lives in `utils::requirements` (shared with the
// lockfile inventory and lockfile discovery).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::VendorArtifact;

    /// #740: an options line names one nested file, the first `-r` when it
    /// has one, else the first `-c`, in every spelling pip's optparse takes.
    #[test]
    fn nested_file_reads_constraints_like_pip() {
        let env = |_: &str| None;
        let constraint = |t: &str| Some(NestedFile::Constraints(t.to_string()));
        for (line, want) in [
            ("-c requirements.txt", constraint("requirements.txt")),
            ("-crequirements.txt", constraint("requirements.txt")),
            (
                "--constraint requirements.txt",
                constraint("requirements.txt"),
            ),
            (
                "--constraint=requirements.txt",
                constraint("requirements.txt"),
            ),
            // Only `--requirement=` reads past an empty attached value.
            (
                "--constraint= -r dev.txt",
                Some(NestedFile::Requirements("dev.txt".into())),
            ),
            (
                "--constr requirements.txt  # pins",
                constraint("requirements.txt"),
            ),
            ("-c a.txt -c b.txt", constraint("a.txt")),
            (
                "-c a.txt -r b.txt",
                Some(NestedFile::Requirements("b.txt".into())),
            ),
            ("-r b.txt", Some(NestedFile::Requirements("b.txt".into()))),
            ("six==1.16.0", None),
            ("-e . -c requirements.txt", None),
            ("--constraint=", None),
            ("# -c requirements.txt", None),
        ] {
            assert_eq!(nested_file_with(line, env), want, "{line:?}");
        }
    }

    /// #740: the readers of a constraints file are the root and
    /// `requirements*/` files, and the requirements-named files of other
    /// top-level directories, whose `-c` resolves to it against the
    /// reader's own directory. `-r` lines, other targets, the file itself,
    /// deeper, hidden and dependency directories are not.
    #[tokio::test]
    async fn constraint_readers_resolve_against_the_reading_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for dir in [
            "requirements",
            "Requirements-CI",
            "docs",
            "requirements/nested",
            "node_modules/pkg",
            ".tox",
        ] {
            tokio::fs::create_dir_all(root.join(dir)).await.unwrap();
        }
        for (rel, content) in [
            ("requirements.txt", "six==1.16.0\n-c requirements.txt\n"),
            ("requirements-dev.txt", "-c requirements.txt\nidna==3.7\n"),
            ("dev.in", "-c ./requirements.txt\n"),
            ("include.txt", "-r requirements.txt\n"),
            ("other.txt", "-c constraints.txt\n"),
            (
                "requirements/test.txt",
                "--constraint ../requirements.txt\n",
            ),
            ("requirements/base.txt", "-c requirements.txt\n"),
            ("Requirements-CI/ci.txt", "-c ../requirements/base.txt\n"),
            (
                "requirements/nested/deep.txt",
                "-c ../../requirements.txt\n",
            ),
            ("docs/requirements.txt", "-c ../requirements.txt\n"),
            ("docs/notes.txt", "-c ../requirements.txt\n"),
            ("node_modules/requirements.txt", "-c ../requirements.txt\n"),
            (".tox/requirements.txt", "-c ../requirements.txt\n"),
            ("setup.cfg", "-c requirements.txt\n"),
        ] {
            tokio::fs::write(root.join(rel), content).await.unwrap();
        }
        let view = crate::vendor::lock_inventory::ProjectView::Disk(root);
        let readers = |found: Vec<ConstraintReader>| {
            found
                .into_iter()
                .map(|r| format!("{} -> {}", r.reader, r.target))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            readers(constraint_readers_in(view, &["requirements.txt".into()]).await),
            vec![
                "dev.in -> requirements.txt",
                "docs/requirements.txt -> requirements.txt",
                "requirements-dev.txt -> requirements.txt",
                "requirements/test.txt -> requirements.txt",
            ]
        );
        assert_eq!(
            readers(
                constraint_readers_in(
                    view,
                    &["requirements.txt".into(), "requirements/base.txt".into()]
                )
                .await
            ),
            vec![
                "Requirements-CI/ci.txt -> requirements/base.txt",
                "dev.in -> requirements.txt",
                "docs/requirements.txt -> requirements.txt",
                "requirements-dev.txt -> requirements.txt",
                "requirements/test.txt -> requirements.txt",
            ]
        );
        assert!(constraint_readers_in(view, &[]).await.is_empty());
    }

    /// #1120: [`requirements_include_names`] decodes each file as pip does,
    /// so the includes of a UTF-16 root file (a Windows PowerShell 5.1
    /// export) and of a PEP 263 include are named, not an `Err` that reads
    /// as an unknowable tree.
    #[tokio::test]
    async fn requirements_include_names_decodes_as_pip_does() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let root_bytes: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                "-r base.txt\r\nsix==1.16.0\r\n"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect();
        tokio::fs::write(root.join("requirements.txt"), root_bytes)
            .await
            .unwrap();
        tokio::fs::write(
            root.join("base.txt"),
            b"# -*- coding: latin-1 -*-\n# Jos\xe9\n-r dev.txt\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("dev.txt"), "pytest\n")
            .await
            .unwrap();
        assert_eq!(
            requirements_include_names(root).await.unwrap(),
            vec!["requirements.txt", "base.txt", "dev.txt"]
        );
        // The vendored planner, which rewrites byte-exact, still refuses
        // a file that is not UTF-8.
        let Err(err) = collect_requirements_files(root).await else {
            panic!("a UTF-16 root file must be refused by the planner");
        };
        assert!(err.1.contains("is not UTF-8 text"), "{}", err.1);
    }

    /// [`requirements_include_names`] names every file the planner may
    /// have pinned into — root first, nested includes resolved against the
    /// including file, a missing include still named but not descended —
    /// and never an out-of-root include (never editable). A reached
    /// include that exists but cannot be read (a FIFO here) is an `Err`,
    /// so a fail-closed caller can refuse.
    #[tokio::test]
    async fn requirements_include_names_walks_in_root_includes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::create_dir(root.join("requirements"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("requirements.txt"),
            "-r requirements/base.txt\n-c constraints.txt\n-r ../shared.txt\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("constraints.txt"), "six<2\n")
            .await
            .unwrap();
        tokio::fs::write(
            root.join("requirements/base.txt"),
            "--requirement=dev.txt\n-r missing.txt\nsix==1.16.0\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("requirements/dev.txt"), "pytest\n")
            .await
            .unwrap();
        let names = requirements_include_names(root).await.unwrap();
        assert_eq!(names[0], "requirements.txt", "{names:?}");
        let mut rest = names[1..].to_vec();
        rest.sort();
        assert_eq!(
            rest,
            vec![
                "requirements/base.txt".to_string(),
                "requirements/dev.txt".to_string(),
                "requirements/missing.txt".to_string(),
            ],
            "constraints and out-of-root includes are never named"
        );

        // No root requirements.txt at all: still names the root (absent).
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            requirements_include_names(empty.path()).await.unwrap(),
            vec!["requirements.txt".to_string()]
        );

        #[cfg(unix)]
        {
            tokio::fs::remove_file(root.join("requirements/dev.txt"))
                .await
                .unwrap();
            let fifo = std::ffi::CString::new(root.join("requirements/dev.txt").to_str().unwrap())
                .unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
            let err = requirements_include_names(root)
                .await
                .expect_err("an include that exists but cannot be read is an Err");
            assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "{err:?}");
        }
    }

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const REL_WHEEL: &str =
        ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl";
    const SHA: &str = "f75f0d4e2f0a4d29b8d3f3a87b8d6cbe9a1c1f95d97d4a92f51e1b04b6a3c9aa";
    /// A different canonical uuid, for "another patch generation" fixtures.
    const OTHER_UUID: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

    fn expected_line() -> String {
        format!("./{REL_WHEEL} --hash=sha256:{SHA}  # socket-patch vendor: six==1.16.0")
    }

    /// [`expected_line`] for a requirements tree outside hash-checking mode.
    fn expected_unhashed_line() -> String {
        format!("./{REL_WHEEL}  # socket-patch vendor: six==1.16.0")
    }

    async fn write_root(content: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("requirements.txt"), content)
            .await
            .unwrap();
        tmp
    }

    /// #721: pip installs from a UTF-16 requirements file (what Windows
    /// PowerShell 5.1's `pip freeze >` writes), so vendoring must refuse it
    /// by name, as the root file or as an include, never wire around it.
    #[tokio::test]
    async fn a_utf16_requirements_file_is_refused_by_name() {
        let utf16 = |text: &str| -> Vec<u8> {
            let mut out = vec![0xFF, 0xFE];
            for unit in text.encode_utf16() {
                out.extend(unit.to_le_bytes());
            }
            out
        };
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("requirements.txt"),
            utf16("six==1.16.0\r\n"),
        )
        .unwrap();
        let err = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_no_requirements");
        assert!(
            err.1.contains("requirements.txt is not UTF-8 text"),
            "{}",
            err.1
        );

        let tmp = write_root("-r inc.txt\nidna==3.7\n").await;
        std::fs::write(tmp.path().join("inc.txt"), utf16("six==1.16.0\r\n")).unwrap();
        let err = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert!(err.1.contains("inc.txt is not UTF-8 text"), "{}", err.1);
        assert_eq!(read_root(tmp.path()).await, "-r inc.txt\nidna==3.7\n");
    }

    async fn read_root(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("requirements.txt"))
            .await
            .unwrap()
    }

    fn entry_for(wiring: Vec<WiringRecord>) -> VendorEntry {
        VendorEntry {
            flavor: Some("requirements".into()),
            ..VendorEntry::new(
                "pypi".into(),
                "pkg:pypi/six@1.16.0".into(),
                UUID.into(),
                VendorArtifact {
                    yarn_berry10c0: None,
                    path: REL_WHEEL.into(),
                    sha256: SHA.into(),
                    size: Some(11053),
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring,
            )
        }
    }

    /// #1365: the vendored planner reads a requirements line with the same
    /// grammar as the lock inventory (`exact_pin`), so a pin scan offers is
    /// one vendor wires. pip reads the legacy parenthesised `six (==1.16.0)`
    /// as the exact pin `==1.16.0`. Arbitrary equality stays a refusal
    /// here by policy, although the inventory and hosted mode differ on it.
    #[test]
    fn find_pin_agrees_with_the_inventory_exact_pin() {
        for (line, inventory, vendored) in [
            ("six==1.16.0", true, true),
            ("six (==1.16.0)", true, true),
            ("six (== 1.16.0)", true, true),
            ("six===1.16.0", false, false),
            ("six==1.16.0,!=1.15", false, false),
        ] {
            assert_eq!(
                crate::utils::requirements::exact_pin(line) == Some(("six", "1.16.0")),
                inventory,
                "inventory: {line}"
            );
            let found = find_pin(&format!("{line}\n"), "six", "1.16.0");
            assert_eq!(
                matches!(found, PinSearch::Exact { .. }),
                vendored,
                "vendored: {line} -> {found:?}"
            );
            if !vendored {
                assert_eq!(found, PinSearch::Range, "{line}");
            }
        }
        // PEP 440 reads an epoch and a `v` prefix; pip installs 1.16.0.
        for line in ["six==0!1.16.0\n", "six==v1.16.0\n"] {
            assert!(
                matches!(find_pin(line, "six", "1.16.0"), PinSearch::Exact { .. }),
                "{line}"
            );
        }
        // A pin whose other options the rewrite would drop is refused.
        for line in [
            "six==1.16.0 --config-settings x=y --hash=sha256:ab\n",
            "six==1.16.0 --hash=sha256:ab -C x=y\n",
            "six==1.16.0 --hash sha256:ab -Cx=y\n",
        ] {
            assert_eq!(find_pin(line, "six", "1.16.0"), PinSearch::Range, "{line}");
        }
        assert!(matches!(
            find_pin(
                "six==1.16.0 --hash sha256:ab --hash=sha256:cd\n",
                "six",
                "1.16.0"
            ),
            PinSearch::Exact { hashed: true, .. }
        ));
        // A line that names the package but is no clean requirement is
        // never treated as absent (fail closed).
        for line in ["six @ ./six-1.16.0.whl extra\n", "six/x==1.16.0\n"] {
            assert_eq!(find_pin(line, "six", "1.16.0"), PinSearch::Range, "{line}");
            assert!(names_package(line, "six"), "{line}");
        }
    }

    #[test]
    fn find_pin_classifies_every_shape() {
        // Clean pin, with marker + hash flags captured.
        let found = find_pin(
            "requests==2.31.0\nsix==1.16.0 ; python_version >= \"3.8\" --hash=sha256:abc\n",
            "six",
            "1.16.0",
        );
        match found {
            PinSearch::Exact {
                line_start,
                line_count,
                marker,
                hashed,
            } => {
                assert_eq!(line_start, 1);
                assert_eq!(line_count, 1);
                assert_eq!(marker.as_deref(), Some("python_version >= \"3.8\""));
                assert!(hashed);
            }
            other => panic!("expected Exact, got {other:?}"),
        }

        // Spaces around the operator still count as the pin.
        assert!(matches!(
            find_pin("six == 1.16.0\n", "six", "1.16.0"),
            PinSearch::Exact { .. }
        ));
        // #475: pip selects the pinned release under PEP 440, so these
        // spellings all pin exactly 1.16.0.
        for pin in [
            "six==1.16\n",
            "six==1.16.0.0\n",
            "Six==01.16.0\n",
            "six == 1.16\n",
        ] {
            assert!(
                matches!(find_pin(pin, "six", "1.16.0"), PinSearch::Exact { .. }),
                "{pin}"
            );
        }
        // Arbitrary equality is string equality; a wildcard is a range.
        assert_eq!(find_pin("six===1.16\n", "six", "1.16.0"), PinSearch::Range);
        assert_eq!(find_pin("six==1.16.*\n", "six", "1.16.0"), PinSearch::Range);
        // PEP 503 name canonicalization on both sides.
        assert!(matches!(
            find_pin("Six_Pkg==1.0\n", "six-pkg", "1.0"),
            PinSearch::Exact { .. }
        ));
        assert_eq!(
            find_pin("six[socks]==1.16.0\n", "six", "1.16.0"),
            PinSearch::Extras
        );
        assert_eq!(find_pin("six>=1.0\n", "six", "1.16.0"), PinSearch::Range);
        assert_eq!(find_pin("six\n", "six", "1.16.0"), PinSearch::Range);
        // Pinned, but to a different version than the one being vendored.
        assert_eq!(find_pin("six==1.15.0\n", "six", "1.16.0"), PinSearch::Range);
        // #928: `uv pip compile --universal` splits a package across marker
        // branches; the other branch's exact pin is disjoint, not ambiguous.
        match find_pin(
            "six==1.16.0 ; python_full_version < '3.12'\n\
             six==1.17.0 ; python_full_version >= '3.12'\n",
            "six",
            "1.16.0",
        ) {
            PinSearch::Exact {
                line_start, marker, ..
            } => {
                assert_eq!(line_start, 0);
                assert_eq!(marker.as_deref(), Some("python_full_version < '3.12'"));
            }
            other => panic!("expected Exact, got {other:?}"),
        }
        // The other branch first in the file is the same split.
        assert!(matches!(
            find_pin(
                "six==1.17.0 ; python_version >= \"3.12\"\nsix==1.16.0 ; python_version < \"3.12\"\n",
                "six",
                "1.16.0"
            ),
            PinSearch::Exact { line_start: 1, .. }
        ));
        // Still fail-closed whenever pip could see both pins at once, or
        // the other branch is not itself an exact pin.
        for content in [
            // Other version unmarked.
            "six==1.16.0 ; python_version < \"3.12\"\nsix==1.17.0\n",
            // Target unmarked.
            "six==1.16.0\nsix==1.17.0 ; python_version >= \"3.12\"\n",
            // One target occurrence unmarked among marked ones.
            "six==1.16.0 ; python_version < \"3.12\"\nsix==1.16.0\n\
             six==1.17.0 ; python_version >= \"3.12\"\n",
            // Other branch is a range / arbitrary equality / wildcard.
            "six==1.16.0 ; python_version < \"3.12\"\nsix>=1.17 ; python_version >= \"3.12\"\n",
            "six==1.16.0 ; python_version < \"3.12\"\nsix===1.17.0 ; python_version >= \"3.12\"\n",
            "six==1.16.0 ; python_version < \"3.12\"\nsix==1.17.* ; python_version >= \"3.12\"\n",
            // No target pin at all: appending an unmarked line would clash.
            "six==1.17.0 ; python_version >= \"3.12\"\n",
        ] {
            assert_eq!(
                find_pin(content, "six", "1.16.0"),
                PinSearch::Range,
                "{content}"
            );
        }
        assert_eq!(
            find_pin("requests==2.31.0\n", "six", "1.16.0"),
            PinSearch::Absent
        );
        // `sixty` must not match `six` (name boundary).
        assert_eq!(
            find_pin("sixty==1.16.0\n", "six", "1.16.0"),
            PinSearch::Absent
        );
        // Comment-only and option lines are not requirements.
        assert_eq!(
            find_pin("# six==1.16.0\n-r other.txt\n", "six", "1.16.0"),
            PinSearch::Absent
        );
    }

    // ── wiring ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rewrites_plain_pin_and_round_trips_revert_byte_identically() {
        let original = "requests==2.31.0\nsix==1.16.0\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!("requests==2.31.0\n{}\n", expected_unhashed_line())
        );
        assert_eq!(wiring.len(), 1);
        assert_eq!(wiring[0].kind, "requirements_line");
        assert_eq!(wiring[0].action, WiringAction::Rewritten);

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            read_root(tmp.path()).await,
            original,
            "byte-identical revert"
        );
    }

    /// #1365: the legacy parenthesised pin is the exact pin pip reads, so
    /// vendor wires it (it used to refuse with a false "not pinned"), and
    /// the revert restores the line as spelled.
    #[tokio::test]
    async fn wires_and_reverts_a_parenthesised_pin() {
        for pin in ["six (==1.16.0)", "six (== 1.16.0)", "six ( ==1.16 )"] {
            let original = format!("requests==2.31.0\n{pin}\n");
            let tmp = write_root(&original).await;
            let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
                .await
                .unwrap_or_else(|err| panic!("{pin}: {err:?}"));
            assert_eq!(
                read_root(tmp.path()).await,
                format!("requests==2.31.0\n{}\n", expected_unhashed_line()),
                "{pin}"
            );
            let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
            assert!(outcome.success, "{pin}");
            assert_eq!(read_root(tmp.path()).await, original, "{pin}");
        }
    }

    #[tokio::test]
    async fn rewrites_hash_pinned_continuation_and_preserves_crlf() {
        // A hash-pinned requirement spanning two physical lines, CRLF file.
        let original = "requests==2.31.0\r\nsix==1.16.0 \\\r\n    --hash=sha256:000111\r\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        let written = read_root(tmp.path()).await;
        assert_eq!(
            written,
            format!("requests==2.31.0\r\n{}\r\n", expected_line()),
            "both physical lines replaced; CRLF preserved"
        );
        // The record keeps BOTH original physical lines for the revert.
        let originals = wiring[0].original.as_ref().unwrap().as_array().unwrap();
        assert_eq!(originals.len(), 2);

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(read_root(tmp.path()).await, original);
    }

    /// #1567: a file mixing CRLF and LF lines keeps every line's own
    /// ending. The vendor line takes the replaced pin's terminator, no
    /// other line is re-terminated, and the revert restores the original
    /// byte for byte. Both majority directions from the issue's repro.
    #[tokio::test]
    async fn mixed_line_endings_survive_vendor_and_revert() {
        let line = expected_unhashed_line();
        for (original, wired) in [
            // LF majority: the two CRLF lines used to turn LF.
            (
                "idna==3.7\r\nsix==1.16.0\nrequests==2.31.0\r\n# tail\n",
                format!("idna==3.7\r\n{line}\nrequests==2.31.0\r\n# tail\n"),
            ),
            // CRLF majority: the pin's own LF used to turn CRLF.
            (
                "idna==3.7\r\nsix==1.16.0\n# a\r\n# b\r\n",
                format!("idna==3.7\r\n{line}\n# a\r\n# b\r\n"),
            ),
            // A CRLF pin in an LF-majority file, unterminated last line.
            (
                "idna==3.7\nsix==1.16.0\r\n# a\n# b",
                format!("idna==3.7\n{line}\r\n# a\n# b"),
            ),
        ] {
            let tmp = write_root(original).await;
            let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
                .await
                .unwrap_or_else(|err| panic!("{original:?}: {err:?}"));
            assert_eq!(read_root(tmp.path()).await, wired, "{original:?}");

            let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
            assert!(outcome.success, "{original:?}: {:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(read_root(tmp.path()).await, original, "{original:?}");
        }
    }

    /// #1567: a hash-pinned continuation in a mixed file. The vendor line
    /// takes the terminator of the span's last physical line, and the
    /// lines around the span keep theirs through vendor and revert.
    #[tokio::test]
    async fn mixed_line_endings_around_a_continuation_span() {
        let original =
            "idna==3.7\nsix==1.16.0 \\\r\n    --hash=sha256:000111\r\nrequests==2.31.0\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!("idna==3.7\n{}\r\nrequests==2.31.0\n", expected_line())
        );
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(read_root(tmp.path()).await, original);
    }

    /// #1567: a continuation whose own physical lines end differently.
    /// The record keeps the ending of each earlier line that differs from
    /// the last one, so the revert restores the span byte for byte.
    #[tokio::test]
    async fn a_continuation_span_with_mixed_endings_reverts_byte_identically() {
        for (original, wired) in [
            (
                "idna==3.7\nsix==1.16.0 \\\n    --hash=sha256:000111\r\nrequests==2.31.0\n",
                format!("idna==3.7\n{}\r\nrequests==2.31.0\n", expected_line()),
            ),
            (
                "idna==3.7\r\nsix==1.16.0 \\\r\n    --hash=sha256:000111 \\\n    --hash=sha256:222333\r\n",
                format!("idna==3.7\r\n{}\r\n", expected_line()),
            ),
            // Unterminated last line: the earlier lines keep their own.
            (
                "idna==3.7\r\nsix==1.16.0 \\\n    --hash=sha256:000111",
                format!("idna==3.7\r\n{}", expected_line()),
            ),
        ] {
            let tmp = write_root(original).await;
            let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
                .await
                .unwrap_or_else(|err| panic!("{original:?}: {err:?}"));
            assert_eq!(read_root(tmp.path()).await, wired, "{original:?}");
            let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
            assert!(outcome.success, "{original:?}: {:?}", outcome.error);
            assert_eq!(read_root(tmp.path()).await, original, "{original:?}");
        }
    }

    /// A uniform span records plain line texts, as before #1567, and a
    /// ledger written before it (no endings recorded) still reverts: its
    /// lines end like the vendor line.
    #[tokio::test]
    async fn a_uniform_span_records_plain_texts() {
        let original = "six==1.16.0 \\\r\n    --hash=sha256:000111\r\nidna==3.7\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            wiring[0].original,
            Some(serde_json::json!([
                "six==1.16.0 \\",
                "    --hash=sha256:000111"
            ]))
        );
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(read_root(tmp.path()).await, original);
    }

    /// #1567: the transitive append to a mixed file adds one line in the
    /// file's majority terminator and touches no other line; the revert
    /// restores the original.
    #[tokio::test]
    async fn mixed_line_endings_survive_a_transitive_append() {
        let line = format!("./{REL_WHEEL}  # socket-patch vendor: six==1.16.0 (transitive)");
        for (original, wired) in [
            (
                "idna==3.7\r\nrequests==2.31.0\n",
                format!("idna==3.7\r\nrequests==2.31.0\n{line}\n"),
            ),
            (
                "idna==3.7\r\n# a\r\nrequests==2.31.0\n",
                format!("idna==3.7\r\n# a\r\nrequests==2.31.0\n{line}\r\n"),
            ),
        ] {
            let tmp = write_root(original).await;
            let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
                .await
                .unwrap_or_else(|err| panic!("{original:?}: {err:?}"));
            assert_eq!(wiring[0].action, WiringAction::Added);
            assert_eq!(read_root(tmp.path()).await, wired, "{original:?}");
            let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
            assert!(outcome.success, "{original:?}: {:?}", outcome.error);
            assert_eq!(read_root(tmp.path()).await, original, "{original:?}");
        }
    }

    /// #1567: the superseding re-vendor (#765) rewrites only the vendor
    /// line's text in a mixed file, and reverting the new entry still
    /// restores the user's original bytes.
    #[tokio::test]
    async fn mixed_line_endings_survive_rewire_and_revert() {
        let original = "idna==3.7\r\nsix==1.16.0\nrequests==2.31.0\r\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        let newer = format!(".socket/vendor/pypi/{OTHER_UUID}/six-1.16.0-py2.py3-none-any.whl");
        let rewired =
            rewire_requirements(tmp.path(), &entry_for(wiring), "six", "1.16.0", &newer, SHA)
                .await
                .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "idna==3.7\r\n./{newer}  # socket-patch vendor: six==1.16.0\nrequests==2.31.0\r\n"
            )
        );
        let outcome = revert_requirements(&entry_for(rewired), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(read_root(tmp.path()).await, original);
    }

    /// #376: an unhashed requirements set must stay unhashed. pip turns
    /// hash-checking mode on for the whole install as soon as one line has a
    /// `--hash`, so a hashed vendor line makes `pip install -r` refuse every
    /// other (unhashed) requirement. A bare path cannot carry a `#sha256=`
    /// fragment, so the committed wheel's line goes without one.
    #[tokio::test]
    async fn unhashed_requirements_get_an_unhashed_vendor_line() {
        for (original, wired) in [
            (
                "six==1.16.0\nidna==3.7\n",
                format!("./{REL_WHEEL}  # socket-patch vendor: six==1.16.0\nidna==3.7\n"),
            ),
            (
                "idna==3.7\n",
                format!(
                    "idna==3.7\n./{REL_WHEEL}  # socket-patch vendor: six==1.16.0 (transitive)\n"
                ),
            ),
        ] {
            let tmp = write_root(original).await;
            let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
                .await
                .unwrap();
            assert_eq!(read_root(tmp.path()).await, wired);
            // Still read back as our line for this patch, pinning the path.
            assert!(matches!(
                preflight_requirements(tmp.path(), "six", "1.16.0", UUID).await,
                Ok(RequirementsTarget::InSync { pin: Some((path, sha)) })
                    if path == REL_WHEEL && sha.is_empty()
            ));
            let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert_eq!(read_root(tmp.path()).await, original);
        }
    }

    /// #376: hashes anywhere in the requirements tree (an `-r` include, or
    /// `--require-hashes`) mean pip is in hash-checking mode, so the vendor
    /// line keeps its `--hash` pin.
    #[tokio::test]
    async fn hashes_in_an_include_keep_the_vendor_line_hashed() {
        let tmp = write_root("-r deps.txt\nsix==1.16.0\n").await;
        tokio::fs::write(tmp.path().join("deps.txt"), "idna==3.7 --hash=sha256:aa\n")
            .await
            .unwrap();
        wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!("-r deps.txt\n{}\n", expected_line())
        );

        let tmp = write_root("--require-hashes\nsix==1.16.0\n").await;
        wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!("--require-hashes\n{}\n", expected_line())
        );
    }

    #[tokio::test]
    async fn marker_is_carried_over_verbatim() {
        let tmp = write_root("six==1.16.0 ; python_version >= \"3.8\"\n").await;
        wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "./{REL_WHEEL} ; python_version >= \"3.8\"  # socket-patch vendor: six==1.16.0\n"
            )
        );
    }

    /// #928: a `uv pip compile --universal --generate-hashes` file splits six
    /// across marker branches. Only the vendored version's branch is
    /// rewritten (marker kept); the other branch is left alone, and revert
    /// is byte-identical.
    #[tokio::test]
    async fn marker_split_rewrites_only_the_vendored_branch() {
        let original = "six==1.16.0 ; python_full_version < '3.12' \\\r\n    \
             --hash=sha256:1111\r\n\
             six==1.17.0 ; python_full_version >= '3.12' \\\r\n    \
             --hash=sha256:2222\r\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "./{REL_WHEEL} ; python_full_version < '3.12' --hash=sha256:{SHA}  \
                 # socket-patch vendor: six==1.16.0\r\n\
                 six==1.17.0 ; python_full_version >= '3.12' \\\r\n    \
                 --hash=sha256:2222\r\n"
            )
        );

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(read_root(tmp.path()).await, original);
    }

    /// #928: the split with no hashes, as `uv pip compile --universal`
    /// writes it, also passes the preflight the orchestrator runs first.
    #[tokio::test]
    async fn marker_split_preflights_fresh_and_wires_unhashed() {
        let original = "six==1.16.0 ; python_full_version < '3.12'\n\
             six==1.17.0 ; python_full_version >= '3.12'\n";
        let tmp = write_root(original).await;
        assert!(matches!(
            preflight_requirements(tmp.path(), "six", "1.16.0", "u").await,
            Ok(RequirementsTarget::Fresh)
        ));
        wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "./{REL_WHEEL} ; python_full_version < '3.12'  \
                 # socket-patch vendor: six==1.16.0\n\
                 six==1.17.0 ; python_full_version >= '3.12'\n"
            )
        );
    }

    /// #1104: pip merges the root and its `-r` includes into one
    /// requirement set, so a marker split is a split across the whole tree,
    /// not per file. Either way round, the vendored version's branch is
    /// rewritten where it lives (marker kept), the other branch is left
    /// alone, and revert is byte-identical.
    #[tokio::test]
    async fn marker_split_across_an_include_rewrites_only_the_vendored_branch() {
        let target = "six==1.16.0 ; python_version < \"3.12\"\n";
        let other = "six==1.17.0 ; python_version >= \"3.12\"\n";
        let rewritten = format!(
            "./{REL_WHEEL} ; python_version < \"3.12\"  # socket-patch vendor: six==1.16.0\n"
        );
        // (root body after `-r base.txt`, base.txt) and the expected rewrites.
        let layouts = [
            (target, format!("idna==3.7\n{other}"), true),
            (other, format!("idna==3.7\n{target}"), false),
        ];
        for (root_pin, base, target_in_root) in layouts {
            let root_original = format!("-r base.txt\n{root_pin}");
            let tmp = write_root(&root_original).await;
            tokio::fs::write(tmp.path().join("base.txt"), &base)
                .await
                .unwrap();
            assert!(
                matches!(
                    preflight_requirements(tmp.path(), "six", "1.16.0", "u").await,
                    Ok(RequirementsTarget::Fresh)
                ),
                "target in root: {target_in_root}"
            );
            assert!(sibling_pin_wirable(tmp.path(), "six", "1.16.0").await);
            let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, "")
                .await
                .unwrap();
            assert_eq!(wiring.len(), 1);
            assert_eq!(wiring[0].action, WiringAction::Rewritten);
            let base_now = tokio::fs::read_to_string(tmp.path().join("base.txt"))
                .await
                .unwrap();
            if target_in_root {
                assert_eq!(
                    read_root(tmp.path()).await,
                    format!("-r base.txt\n{rewritten}")
                );
                assert_eq!(base_now, base);
            } else {
                assert_eq!(read_root(tmp.path()).await, root_original);
                assert_eq!(base_now, format!("idna==3.7\n{rewritten}"));
            }

            let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert_eq!(read_root(tmp.path()).await, root_original);
            assert_eq!(
                tokio::fs::read_to_string(tmp.path().join("base.txt"))
                    .await
                    .unwrap(),
                base
            );
        }
    }

    /// #1104's guard rails: across the tree, the other version's branch is
    /// only tolerated when every target pin carries a marker too. An
    /// unmarked target pin, or no target pin at all, means pip could pick
    /// the other version, so the vendor still refuses (naming the file
    /// that pins the other version) and writes nothing.
    #[tokio::test]
    async fn marker_split_across_an_include_still_refuses_an_unmarked_or_missing_target() {
        let other = "six==1.17.0 ; python_version >= \"3.12\"\n";
        let cases = [
            // An unmarked target pin in the root next to a marked other
            // branch in the include.
            ("-r base.txt\nsix==1.16.0\n", other.to_string(), "base.txt"),
            // The unmarked target in the include, the other branch in the root.
            (
                &*format!("-r base.txt\n{other}"),
                "six==1.16.0\n".to_string(),
                "requirements.txt",
            ),
            // Only the other version's branch anywhere in the tree.
            ("-r base.txt\nidna==3.7\n", other.to_string(), "base.txt"),
        ];
        for (root, base, named) in cases {
            let tmp = write_root(root).await;
            tokio::fs::write(tmp.path().join("base.txt"), &base)
                .await
                .unwrap();
            let err = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
                .await
                .unwrap_err();
            assert_eq!(err.0, "pypi_requirement_not_pinned", "{root:?} / {base:?}");
            assert!(
                err.1
                    .starts_with(&format!("{named}: pins another six version"))
                    && err.1.contains("pin ==1.16.0 on its own marker branch"),
                "{}",
                err.1
            );
            assert_eq!(read_root(tmp.path()).await, root);
            assert_eq!(
                tokio::fs::read_to_string(tmp.path().join("base.txt"))
                    .await
                    .unwrap(),
                base
            );
        }
    }

    #[tokio::test]
    async fn absent_package_appends_managed_transitive_line() {
        let tmp = write_root("python-dateutil==2.8.2\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "python-dateutil==2.8.2\n./{REL_WHEEL}  # socket-patch vendor: six==1.16.0 (transitive)\n"
            )
        );
        assert_eq!(wiring[0].action, WiringAction::Added);

        // Revert deletes the appended line.
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(read_root(tmp.path()).await, "python-dateutil==2.8.2\n");
    }

    #[tokio::test]
    async fn follows_dash_r_includes_and_rewrites_pin_in_place() {
        let tmp = write_root("-r deps/pinned.txt\nrequests==2.31.0\n").await;
        tokio::fs::create_dir_all(tmp.path().join("deps"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("deps/pinned.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        // The pin is rewritten where it lives; the root stays untouched (no
        // duplicate appended).
        assert_eq!(
            read_root(tmp.path()).await,
            "-r deps/pinned.txt\nrequests==2.31.0\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/pinned.txt"))
                .await
                .unwrap(),
            format!("{}\n", expected_unhashed_line())
        );
        assert_eq!(wiring.len(), 1);
        assert_eq!(wiring[0].file, "deps/pinned.txt");

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/pinned.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    /// Multi-file wiring is transactional: when the write to the SECOND
    /// planned file fails, the already-written first file is restored. The
    /// orchestrator sweeps the wheel dir on a wiring error, so a surviving
    /// half-wired file would reference a deleted artifact — with no ledger
    /// entry recorded to revert it. (wire_uv rolls its pyproject write back
    /// the same way when the lock write fails.)
    #[cfg(unix)]
    #[tokio::test]
    async fn wire_failure_rolls_back_already_written_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let original_root = "six==1.16.0\n-r deps/pinned.txt\n";
        let tmp = write_root(original_root).await;
        tokio::fs::create_dir_all(tmp.path().join("deps"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("deps/pinned.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        // Read-only include dir: planning READS it fine, the atomic write
        // (temp file in the same dir) fails. Root is planned/written first.
        let deps = tmp.path().join("deps");
        let mut perms = std::fs::metadata(&deps).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&deps, perms.clone()).unwrap();

        let err = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        perms.set_mode(0o755);
        std::fs::set_permissions(&deps, perms).unwrap();
        assert_eq!(err.0, "pypi_requirements_write_failed");
        assert_eq!(
            read_root(tmp.path()).await,
            original_root,
            "the already-written root must be rolled back on a later write failure"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/pinned.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    /// Wire and revert both rewrite requirements files in place; a committed
    /// file's mode (e.g. group-readable 0o640 under a strict umask) must
    /// survive both. The plain atomic writer swaps in a fresh umask-default
    /// inode — same class as the npm/pipenv lockfile mode resets.
    #[cfg(unix)]
    #[tokio::test]
    async fn wire_and_revert_preserve_requirements_file_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = write_root("six==1.16.0\n").await;
        let path = tmp.path().join("requirements.txt");
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o640);
        std::fs::set_permissions(&path, perms).unwrap();

        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640,
            "wire must preserve the file mode"
        );

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640,
            "revert must preserve the file mode"
        );
    }

    /// pip's join_lines never treats a comment line ending in `\` as a
    /// continuation (COMMENT_RE guard) — the pin on the next physical line is
    /// a real requirement. Swallowing it into the comment classifies the
    /// package as absent, and the appended duplicate makes
    /// `pip install -r requirements.txt` fail with a double requirement.
    #[tokio::test]
    async fn comment_ending_in_backslash_does_not_swallow_the_next_line() {
        let tmp = write_root("# vendored from C:\\deps\\\nsix==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(
            wiring[0].action,
            WiringAction::Rewritten,
            "the pin below the comment must be rewritten in place, not duplicated"
        );
        assert_eq!(
            read_root(tmp.path()).await,
            format!("# vendored from C:\\deps\\\n{}\n", expected_unhashed_line())
        );
    }

    /// An absolute `-r /abs/path.txt` include resolves outside any committable
    /// root; a pin there must refuse exactly like a `../` include. Mangling it
    /// into an in-root relative path silently skips the file pip *can* read,
    /// and the transitive line appended at the root EOF gives pip a "double
    /// requirement" error. The path is quoted, as pip needs it on Windows:
    /// pip `shlex`-splits the line, so an unquoted `C:\…` loses its
    /// backslashes (#994).
    #[tokio::test]
    async fn pin_in_absolute_include_refuses() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        let shared = outer.path().join("shared.txt");
        tokio::fs::write(&shared, "six==1.16.0\n").await.unwrap();
        let root_content = format!("-r \"{}\"\n", shared.display());
        tokio::fs::write(root.join("requirements.txt"), &root_content)
            .await
            .unwrap();
        let err = wire_requirements(&root, "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_requirements_outside_root");
        assert_eq!(
            tokio::fs::read_to_string(root.join("requirements.txt"))
                .await
                .unwrap(),
            root_content,
            "refusal leaves the root untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(&shared).await.unwrap(),
            "six==1.16.0\n",
            "the absolute include is never edited"
        );
    }

    #[tokio::test]
    async fn include_cycles_terminate() {
        let tmp = write_root("-r a.txt\nsix==1.16.0\n").await;
        tokio::fs::write(tmp.path().join("a.txt"), "-r requirements.txt\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            wiring.len(),
            1,
            "cycle guard must not duplicate the rewrite"
        );
    }

    #[tokio::test]
    async fn extras_and_range_pins_refuse() {
        let tmp = write_root("six[socks]==1.16.0\n").await;
        let err = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_extras_unsupported");

        let tmp = write_root("six~=1.16\n").await;
        let err = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_requirement_not_pinned");
        // Refusals leave the file untouched.
        assert_eq!(read_root(tmp.path()).await, "six~=1.16\n");
    }

    #[tokio::test]
    async fn pin_in_out_of_root_include_refuses() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("requirements.txt"), "-r ../shared.txt\n")
            .await
            .unwrap();
        tokio::fs::write(outer.path().join("shared.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let err = wire_requirements(&root, "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_requirements_outside_root");
        // The out-of-root file is never edited.
        assert_eq!(
            tokio::fs::read_to_string(outer.path().join("shared.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    // ── revert edge cases ────────────────────────────────────────────────

    /// SECURITY: a poisoned state.json wiring record naming a
    /// `..`/absolute `file` must never make `--revert` read or rewrite a file
    /// outside the project root — the record is skipped with a warning and
    /// the out-of-tree target stays byte-identical (joining `rec.file`
    /// unvalidated would be an arbitrary content-injection write).
    #[tokio::test]
    async fn revert_refuses_unsafe_wiring_file_paths() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        // A precious sibling OUTSIDE the project root.
        let precious = outer.path().join("precious.txt");
        tokio::fs::write(&precious, "keep me intact\n")
            .await
            .unwrap();

        for bad in ["../precious.txt", "/etc/hosts", "a/../../precious.txt"] {
            let wiring = vec![WiringRecord {
                file: bad.to_string(),
                kind: "requirements_line".to_string(),
                action: WiringAction::Rewritten,
                key: None,
                original: Some(serde_json::json!(["malicious payload"])),
                new: Some(serde_json::json!("keep me intact")),
            }];
            let outcome = revert_requirements(&entry_for(wiring), &root, false).await;
            assert!(
                outcome.success,
                "unsafe record is skipped (fail-closed), not a hard error: {bad}"
            );
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_revert_line_drifted"),
                "skip must be surfaced for {bad}"
            );
        }
        assert_eq!(
            tokio::fs::read_to_string(&precious).await.unwrap(),
            "keep me intact\n",
            "out-of-tree file must be byte-untouched"
        );
    }

    #[tokio::test]
    async fn revert_warns_on_drifted_line_and_leaves_it() {
        let tmp = write_root("six==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        // Drift: the user edited the vendor line (added a marker).
        let drifted = read_root(tmp.path()).await.replace(
            "  # socket-patch vendor",
            " ; python_version >= \"3\"  # socket-patch vendor",
        );
        assert_ne!(drifted, read_root(tmp.path()).await);
        tokio::fs::write(tmp.path().join("requirements.txt"), &drifted)
            .await
            .unwrap();

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert!(outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_line_drifted"));
        // The ledger key reads as recorded, never as `Some("…")` (#1608).
        assert!(
            outcome.warnings.iter().any(|w| w.detail.contains(
                "requirements.txt: the vendor line for requirements.txt:1 changed since vendoring"
            )),
            "{:?}",
            outcome.warnings
        );
        // A drifted edit (still referencing the uuid dir) also raises the
        // residual-reference warning.
        assert!(outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_residual_reference"));
        assert_eq!(
            read_root(tmp.path()).await,
            drifted,
            "drifted line left alone"
        );
    }

    #[tokio::test]
    async fn revert_warns_on_residual_reference_from_other_lines() {
        let tmp = write_root("six==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        // A second, manually-added reference to the vendored wheel.
        let mut content = read_root(tmp.path()).await;
        content.push_str(&format!("./{REL_WHEEL}\n"));
        tokio::fs::write(tmp.path().join("requirements.txt"), &content)
            .await
            .unwrap();

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert!(outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_residual_reference"));
        // The managed line was reverted; the manual line survives.
        assert_eq!(
            read_root(tmp.path()).await,
            format!("six==1.16.0\n./{REL_WHEEL}\n")
        );
    }

    #[tokio::test]
    async fn revert_dry_run_writes_nothing() {
        let tmp = write_root("six==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        let wired = read_root(tmp.path()).await;
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), true).await;
        assert!(outcome.success);
        assert_eq!(read_root(tmp.path()).await, wired, "dry run must not write");
    }

    /// pip decodes requirements files with `auto_decode` (utf-8-sig strips
    /// the BOM) and uv strips it too — probed against pip 26.0 and uv
    /// 0.11: both see a pin on a BOM'd first line. Missing it classifies
    /// the package as absent, and the appended transitive wheel line gives
    /// `pip install -r` a double requirement (or an unhashed-pin error in
    /// the --require-hashes mode the wheel line switches on).
    #[tokio::test]
    async fn bom_first_line_pin_is_rewritten_not_duplicated() {
        let original = "\u{feff}six==1.16.0\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(
            wiring[0].action,
            WiringAction::Rewritten,
            "the BOM'd pin must be rewritten in place, not duplicated"
        );
        assert_eq!(
            read_root(tmp.path()).await,
            format!("{}\n", expected_unhashed_line())
        );

        // The BOM travels inside the replaced physical line's record, so
        // the revert is byte-identical.
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(
            read_root(tmp.path()).await,
            original,
            "byte-identical revert restores the BOM"
        );
    }

    /// pip's optparse accepts the attached short form `-rdev.txt` (no
    /// space) — probed against pip 26.0. Not following it hides the pin,
    /// and the transitive line appended at the root EOF gives pip a double
    /// requirement. (uv 0.11 rejects the spelling outright, so such a file
    /// is pip-only either way.)
    #[tokio::test]
    async fn attached_short_form_include_is_followed() {
        let tmp = write_root("-rdev.txt\n").await;
        tokio::fs::write(tmp.path().join("dev.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(wiring[0].file, "dev.txt");
        assert_eq!(
            read_root(tmp.path()).await,
            "-rdev.txt\n",
            "root untouched — no duplicate appended"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("dev.txt"))
                .await
                .unwrap(),
            format!("{}\n", expected_unhashed_line())
        );
    }

    /// mkfifo(2) directly rather than shelling out to the `mkfifo` binary —
    /// same helper as the pypi.rs / pypi_pdm.rs FIFO tests: fork/exec flakes
    /// under heavy parallel load and the syscall needs no process at all.
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

    /// A FIFO planted as `requirements.txt` (or an include) must not wedge
    /// wire or revert: `detect_pypi_flavor`'s routing probe is metadata-only
    /// (a FIFO stats fine), so this module's raw `read_to_string` open(2) is
    /// the FIRST open — it waits for a writer that never comes, wedging
    /// every requirements-project vendor run (and `vendor --revert`)
    /// indefinitely. Same `open_regular_file` guard class as the sibling
    /// vendor backends.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_requirements_does_not_wedge_wire_or_revert() {
        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);

        // FIFO as the root file: the wire must refuse fast.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("requirements.txt");
        mkfifo(&fifo);
        let Ok(res) = tokio::time::timeout(
            deadline,
            wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA),
        )
        .await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("wire_requirements must complete promptly with a FIFO requirements.txt");
        };
        assert_eq!(res.unwrap_err().0, "pypi_no_requirements");

        // FIFO as an include: skipped like any unreadable include; the root
        // pin still rewrites promptly.
        let tmp = write_root("-r inc.txt\nsix==1.16.0\n").await;
        let inc = tmp.path().join("inc.txt");
        mkfifo(&inc);
        let Ok(res) = tokio::time::timeout(
            deadline,
            wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA),
        )
        .await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&inc);
            panic!("a FIFO include must be skipped, not wedge the wire");
        };
        assert_eq!(res.unwrap().len(), 1);

        // Revert reads the wired file itself: must fail fast, not wedge.
        let tmp = write_root("six==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        let path = tmp.path().join("requirements.txt");
        tokio::fs::remove_file(&path).await.unwrap();
        mkfifo(&path);
        let Ok(outcome) = tokio::time::timeout(
            deadline,
            revert_requirements(&entry_for(wiring), tmp.path(), false),
        )
        .await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&path);
            panic!("revert_requirements must complete promptly with a FIFO requirements.txt");
        };
        assert!(!outcome.success, "FIFO requirements must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot read"),
            "{:?}",
            outcome.error
        );
    }

    /// Two identical pins: each record must splice back its OWN original
    /// (bottom-up matching), and both lines must be rewritten.
    #[tokio::test]
    async fn multiple_occurrences_all_rewritten_and_reverted() {
        let original = "six==1.16.0\nrequests==2.31.0\nsix==1.16.0  # twice\n";
        let tmp = write_root(original).await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 2);
        let written = read_root(tmp.path()).await;
        assert_eq!(written.matches(&expected_unhashed_line()).count(), 2);

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(read_root(tmp.path()).await, original);
    }

    // ── preflight / vendored_uuid_for ────────────────────────────────────

    /// `vendored_uuid_for` must recognize ONLY this module's own line shape
    /// for the queried package: another package's tag, a name-prefix tag
    /// (`sixty`), a non-vendor path token, and a foreign-ecosystem vendor
    /// path are all invisible. Each false positive would misroute preflight
    /// into InSync (skipping the wire) or an already-vendored refusal for a
    /// line that does not actually wire the queried package.
    #[test]
    fn vendored_uuid_for_skips_other_packages_and_foreign_paths() {
        // Positive control: our own line shape yields the patch uuid.
        assert_eq!(
            vendored_uuid_for(&format!("{}\n", expected_line()), "six"),
            Some(UUID.to_string())
        );
        // The tag names a DIFFERENT package than the one queried.
        assert_eq!(
            vendored_uuid_for(&format!("{}\n", expected_line()), "requests"),
            None
        );
        // Name boundary: a `sixty==…` tag must not match `six`.
        let sixty = expected_line().replace("six==1.16.0", "sixty==1.16.0");
        assert_eq!(vendored_uuid_for(&sixty, "six"), None);
        // Tag matches, but the first token is not a vendor path at all
        // (hand-written local wheel line).
        assert_eq!(
            vendored_uuid_for(
                "./wheels/six-1.16.0-py2.py3-none-any.whl  # socket-patch vendor: six==1.16.0\n",
                "six"
            ),
            None
        );
        // Tag matches and the token IS a vendor path — for another
        // ecosystem's dir, which can never be a pypi wiring.
        assert_eq!(
            vendored_uuid_for(
                &format!(
                    "./.socket/vendor/npm/{UUID}/six.tgz  # socket-patch vendor: six==1.16.0\n"
                ),
                "six"
            ),
            None
        );
    }

    /// The vendor-line readers lex pip's LOGICAL lines, like lockfile
    /// discovery: a vendor line whose `--hash` and tag sit on a `\\`
    /// continuation is still the wiring (a physical-line scan saw the tag on
    /// a line whose first token is `--hash=…`, and missed it).
    #[test]
    fn vendor_line_readers_join_continuations() {
        let hex = "a".repeat(64);
        let wheel = format!("./.socket/vendor/pypi/{UUID}/six-1.16.0-py3-none-any.whl");
        let content = format!(
            "{wheel} \\\n    --hash=sha256:{hex}  # socket-patch vendor: six==1.16.0\nattrs==23.1.0\n"
        );
        assert_eq!(vendored_uuid_for(&content, "six"), Some(UUID.to_string()));
        assert_eq!(
            wired_pin_in(&content, "six", UUID),
            Some((wheel.trim_start_matches("./").to_string(), hex.clone()))
        );
        // Another uuid, or a malformed pin, is not this patch's pin.
        assert_eq!(wired_pin_in(&content, "six", "not-the-uuid"), None);
        let short = content.replace(&hex, "abc");
        assert_eq!(wired_pin_in(&short, "six", UUID), None);
        // An unhashed vendor line still pins its path, with no sha256.
        let unhashed = format!("{wheel}  # socket-patch vendor: six==1.16.0\nattrs==23.1.0\n");
        assert_eq!(
            wired_pin_in(&unhashed, "six", UUID),
            Some((wheel.trim_start_matches("./").to_string(), String::new()))
        );
    }

    /// Multi-package coexistence: a root already carrying ANOTHER package's
    /// vendor line (at another patch uuid) plus a clean `six` pin is a Fresh
    /// wire for six — the foreign line must neither read as InSync nor
    /// refuse as already-vendored.
    #[tokio::test]
    async fn preflight_ignores_other_packages_vendor_line() {
        let requests_line = format!(
            "./.socket/vendor/pypi/{OTHER_UUID}/requests-2.31.0-py3-none-any.whl \
             --hash=sha256:{SHA}  # socket-patch vendor: requests==2.31.0"
        );
        let tmp = write_root(&format!("{requests_line}\nsix==1.16.0\n")).await;
        let res = preflight_requirements(tmp.path(), "six", "1.16.0", UUID).await;
        assert!(
            matches!(res, Ok(RequirementsTarget::Fresh)),
            "another package's vendor line must not block a fresh six vendor"
        );
    }

    // ── more revert edge cases ───────────────────────────────────────────

    /// A hand-edited/poisoned state.json record whose `new` field is missing
    /// or not a string must be skipped fail-closed with a drift warning —
    /// never panic, never guess a line to splice.
    #[tokio::test]
    async fn revert_warns_on_record_with_missing_or_nonstring_new() {
        let tmp = write_root("six==1.16.0\n").await;
        let rec = |new: Option<serde_json::Value>| WiringRecord {
            file: "requirements.txt".to_string(),
            kind: "requirements_line".to_string(),
            action: WiringAction::Rewritten,
            key: Some("requirements.txt:1".to_string()),
            original: Some(serde_json::json!(["six==1.16.0"])),
            new,
        };
        let wiring = vec![rec(None), rec(Some(serde_json::json!(42)))];
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            outcome.warnings.len(),
            2,
            "one drift warning per unusable record: {:?}",
            outcome.warnings
        );
        assert!(outcome
            .warnings
            .iter()
            .all(|w| w.code == "vendor_revert_line_drifted"));
        assert_eq!(
            read_root(tmp.path()).await,
            "six==1.16.0\n",
            "unusable records must leave the file byte-untouched"
        );
    }

    /// Mirror of `wire_failure_rolls_back_already_written_files` for the
    /// REVERT side: when the atomic write fails, the outcome reports the
    /// failure (`cannot write …`) with `kept_artifact: false`, and the wired
    /// file survives byte-identical — the atomic temp-file write never
    /// touches the target on failure.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_write_failure_reports_error_and_keeps_wired_content() {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let tmp = write_root("six==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        let wired = read_root(tmp.path()).await;
        // Read-only project root: revert READS fine, the atomic write (temp
        // file in the same dir) fails.
        let mut perms = std::fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(tmp.path(), perms.clone()).unwrap();
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        perms.set_mode(0o755);
        std::fs::set_permissions(tmp.path(), perms).unwrap();

        assert!(!outcome.success);
        assert!(!outcome.kept_artifact);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write requirements.txt"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            read_root(tmp.path()).await,
            wired,
            "a failed atomic write must leave the wired file untouched"
        );
    }

    /// Unlike wire (which rolls back already-written files on a later write
    /// failure), revert deliberately leaves earlier reverted files in place:
    /// the orchestrator keeps the artifact dir and ledger entry on
    /// `!success`, so a partial revert converges on re-run. Pin that shape:
    /// root reverted, the unwritable include still wired, outcome failed.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_write_failure_does_not_roll_back_earlier_reverted_files() {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let original_root = "six==1.16.0\n-r deps/pinned.txt\n";
        let tmp = write_root(original_root).await;
        tokio::fs::create_dir_all(tmp.path().join("deps"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("deps/pinned.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 2, "both files wired");
        let wired_include = tokio::fs::read_to_string(tmp.path().join("deps/pinned.txt"))
            .await
            .unwrap();
        // Only the include dir is read-only: the root write succeeds first
        // (records are grouped in application order — root first), then the
        // include write fails.
        let deps = tmp.path().join("deps");
        let mut perms = std::fs::metadata(&deps).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&deps, perms.clone()).unwrap();
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        perms.set_mode(0o755);
        std::fs::set_permissions(&deps, perms).unwrap();

        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write deps/pinned.txt"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            read_root(tmp.path()).await,
            original_root,
            "the root reverted before the failure stays reverted (no rollback)"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/pinned.txt"))
                .await
                .unwrap(),
            wired_include,
            "the unwritable include keeps its wired content for the re-run"
        );
    }

    // ── transitive append without a trailing newline ─────────────────────

    /// Transitive append when the root lacks a trailing newline: the
    /// separator is inserted before the appended vendor line (every other
    /// append fixture is newline-terminated). NOTE: the revert of this shape
    /// is asserted at CURRENT behavior — the pin set is restored but the
    /// file gains a trailing newline the original never had, because the
    /// revert writer re-terminates any non-empty file that was wired with a
    /// final newline.
    #[tokio::test]
    async fn transitive_append_to_root_without_trailing_newline() {
        let tmp = write_root("requests==2.31.0").await; // NO trailing newline
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring[0].action, WiringAction::Added);
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "requests==2.31.0\n./{REL_WHEEL}  # socket-patch vendor: six==1.16.0 (transitive)\n"
            )
        );
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        // Not byte-identical: the original had no final newline.
        assert_eq!(read_root(tmp.path()).await, "requests==2.31.0\n");
    }

    /// CRLF root without a trailing newline: the inserted separator (and the
    /// appended line's terminator) must both use the file's dominant `\r\n`.
    #[tokio::test]
    async fn transitive_append_crlf_root_without_trailing_newline() {
        let tmp = write_root("requests==2.31.0\r\nzope.interface==5.0").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring[0].action, WiringAction::Added);
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "requests==2.31.0\r\nzope.interface==5.0\r\n./{REL_WHEEL}  # socket-patch vendor: six==1.16.0 (transitive)\r\n"
            )
        );
    }

    // ── nested includes ──────────────────────────────────────────────────

    /// A `-r` inside a non-root file resolves against the INCLUDING file's
    /// directory (the module's documented contract): `deps/a.txt` reaches
    /// `b.txt` (sibling → `deps/b.txt`) and `../c.txt` (back at the root —
    /// the interior `..` pop of `normalize_rel_keeping_escapes`). The pin in deps/b.txt
    /// is rewritten in place; nothing else is touched and no transitive
    /// duplicate is appended, proving BOTH nested includes were walked.
    #[tokio::test]
    async fn nested_include_resolves_against_including_dir() {
        let tmp = write_root("-r deps/a.txt\n").await;
        tokio::fs::create_dir_all(tmp.path().join("deps"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("deps/a.txt"), "-r b.txt\n-r ../c.txt\n")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("deps/b.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("c.txt"), "requests==2.31.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(
            wiring[0].file, "deps/b.txt",
            "the pin lives two includes deep, resolved against deps/"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/b.txt"))
                .await
                .unwrap(),
            format!("{}\n", expected_unhashed_line())
        );
        // No transitive duplicate at the root, and the other files are
        // byte-untouched — the walk really visited them.
        assert_eq!(read_root(tmp.path()).await, "-r deps/a.txt\n");
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/a.txt"))
                .await
                .unwrap(),
            "-r b.txt\n-r ../c.txt\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("c.txt"))
                .await
                .unwrap(),
            "requests==2.31.0\n"
        );

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("deps/b.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    /// An interior-`..` include that then escapes the root
    /// (`deps/../../shared.txt` → `../shared.txt`) must still refuse: the
    /// pop-then-leading-parent normalization may not launder an out-of-root
    /// path into an editable one.
    #[tokio::test]
    async fn interior_parent_include_escaping_root_still_refuses() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(root.join("deps")).await.unwrap();
        tokio::fs::write(root.join("requirements.txt"), "-r deps/a.txt\n")
            .await
            .unwrap();
        tokio::fs::write(root.join("deps/a.txt"), "-r ../../shared.txt\n")
            .await
            .unwrap();
        tokio::fs::write(outer.path().join("shared.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let err = wire_requirements(&root, "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_requirements_outside_root");
        assert_eq!(
            tokio::fs::read_to_string(outer.path().join("shared.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n",
            "the escaped include is never edited"
        );
    }

    /// pip also accepts the attached long form `--requirement=dev.txt`;
    /// missing it would classify the pin as absent and append a duplicate at
    /// the root EOF — the same pip double-requirement failure class the
    /// `-rdev.txt` test documents.
    #[tokio::test]
    async fn requirement_equals_long_form_include_is_followed() {
        // Unit shape checks for the `=` arm.
        assert_eq!(
            include_target("--requirement=dev.txt").as_deref(),
            Some("dev.txt")
        );
        assert_eq!(
            include_target("--requirement= dev.txt ").as_deref(),
            Some("dev.txt"),
            "the attached value is trimmed"
        );
        assert_eq!(
            include_target("--requirement=").as_deref(),
            None,
            "an empty attached value is not an include"
        );

        let tmp = write_root("--requirement=dev.txt\n").await;
        tokio::fs::write(tmp.path().join("dev.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(wiring[0].file, "dev.txt");
        assert_eq!(
            read_root(tmp.path()).await,
            "--requirement=dev.txt\n",
            "root untouched — no duplicate appended"
        );
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("dev.txt"))
                .await
                .unwrap(),
            format!("{}\n", expected_unhashed_line())
        );
    }

    /// #994: an include target is read the way pip reads it — `${NAME}`
    /// expanded, then the options `shlex`-split — so quotes, backslash
    /// escapes and env references name the file pip opens.
    #[test]
    fn include_target_unquotes_and_expands_like_pip() {
        let env = |name: &str| (name == "REQDIR").then(|| "sub".to_string());
        let cases: &[(&str, Option<&str>)] = &[
            ("-r dev.txt", Some("dev.txt")),
            ("-r\tdev.txt", Some("dev.txt")),
            ("-r \"dev reqs.txt\"", Some("dev reqs.txt")),
            ("-r 'dev reqs.txt'", Some("dev reqs.txt")),
            ("-r \"dev.txt\"", Some("dev.txt")),
            ("-r dev\\ reqs.txt", Some("dev reqs.txt")),
            ("-r ${REQDIR}/dev.txt", Some("sub/dev.txt")),
            ("-r ${UNSET}/dev.txt", Some("${UNSET}/dev.txt")),
            ("--requirement \"dev.txt\"", Some("dev.txt")),
            ("--requirement=\"dev.txt\"", Some("dev.txt")),
            ("--requirement='dev reqs.txt'", Some("dev reqs.txt")),
            ("-r\"dev reqs.txt\"", Some("dev reqs.txt")),
            ("-rdev.txt", Some("dev.txt")),
            ("-r \"dev reqs.txt\" # comment", Some("dev reqs.txt")),
            ("-r \"dev.txt", None),
            ("-r \"\"", None),
            ("-r", None),
            ("-c constraints.txt", None),
            ("six==1.16.0", None),
            ("--require-hashes", None),
        ];
        for (line, want) in cases {
            assert_eq!(include_target_with(line, env).as_deref(), *want, "{line:?}");
        }
    }

    /// #1028: pip parses every option word of a line, so a `-r` after
    /// other options is an include, an option's value is never read as
    /// `-r`, and the first of several `-r`s wins (`opts.requirements[0]`).
    /// A requirement line (`six==1.16.0 ...`) or an editable is never an
    /// include.
    #[test]
    fn include_target_scans_every_option_word() {
        let env = |_: &str| None;
        let cases: &[(&str, Option<&str>)] = &[
            ("--pre -r dev.txt", Some("dev.txt")),
            ("-i https://pypi.org/simple -r dev.txt", Some("dev.txt")),
            ("-ihttps://pypi.org/simple -r dev.txt", Some("dev.txt")),
            ("--index-url https://x/simple -r dev.txt", Some("dev.txt")),
            ("--index-url=https://x/simple -r dev.txt", Some("dev.txt")),
            (
                "--extra-index-url https://x/simple -r dev.txt",
                Some("dev.txt"),
            ),
            ("--prefer-binary -r dev.txt", Some("dev.txt")),
            ("-c c.txt -r dev.txt", Some("dev.txt")),
            ("--constraint c.txt --requirement dev.txt", Some("dev.txt")),
            ("--prefer-binary --requirement=dev.txt", Some("dev.txt")),
            ("-f ./wheels -rdev.txt", Some("dev.txt")),
            ("--no-binary :all: -r dev.txt", Some("dev.txt")),
            ("--trusted-host h -r \"dev reqs.txt\"", Some("dev reqs.txt")),
            ("-r dev.txt -r other.txt", Some("dev.txt")),
            ("-r dev.txt --pre", Some("dev.txt")),
            // optparse's unique-prefix long options.
            ("--requirem dev.txt", Some("dev.txt")),
            ("--pre --requirem=dev.txt", Some("dev.txt")),
            // An option value that looks like `-r` is the value.
            ("-i -r dev.txt", None),
            ("--index-url -r", None),
            ("-c -r", None),
            // Only constraints: not a requirements include.
            ("-c c.txt", None),
            // A requirement line's per-requirement options never recurse.
            ("six==1.16.0 -r dev.txt", None),
            // An editable makes the line a requirement.
            ("-e ./pkg -r dev.txt", None),
            ("-r dev.txt -e ./pkg", None),
            // `--` ends the options.
            ("--pre -- -r dev.txt", None),
            ("--pre", None),
        ];
        for (line, want) in cases {
            assert_eq!(include_target_with(line, env).as_deref(), *want, "{line:?}");
        }
    }

    /// #1028: the planner follows an include that comes after another
    /// option and wires the pin there instead of appending at the root.
    #[tokio::test]
    async fn include_after_other_option_is_followed() {
        let tmp = write_root("--pre -r dev.txt\n").await;
        tokio::fs::write(tmp.path().join("dev.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(wiring[0].file, "dev.txt");
        assert_eq!(
            read_root(tmp.path()).await,
            "--pre -r dev.txt\n",
            "root untouched — no duplicate appended"
        );
    }

    /// #994: the planner follows a quoted include with a space in its name
    /// and wires the pin there instead of appending a duplicate at the root.
    #[tokio::test]
    async fn quoted_include_with_space_is_followed() {
        let tmp = write_root("-r \"dev reqs.txt\"\n").await;
        tokio::fs::write(tmp.path().join("dev reqs.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(wiring.len(), 1);
        assert_eq!(wiring[0].file, "dev reqs.txt");
        assert_eq!(read_root(tmp.path()).await, "-r \"dev reqs.txt\"\n");
        assert_eq!(
            requirements_include_names(tmp.path()).await.unwrap(),
            vec!["requirements.txt".to_string(), "dev reqs.txt".to_string()]
        );
    }

    // ── pure-function matrices ───────────────────────────────────────────

    /// Lines that do not start with a PEP 508 name are not requirements —
    /// in particular this module's OWN vendor-line shape must be invisible
    /// to the pin search, or an already-wired path line would misparse as a
    /// pin during a later scan.
    #[test]
    fn parse_requirement_line_ignores_path_and_nonname_lines() {
        assert!(parse_requirement(strip_comment(&expected_line())).is_none());
        assert!(parse_requirement(strip_comment("./local/wheel.whl --hash=sha256:abc")).is_none());
        assert!(parse_requirement(strip_comment("=six==1.0")).is_none());
        assert!(parse_requirement(strip_comment("[section]")).is_none());
        // A stray path line neither matches nor shifts the classification of
        // the real pin below it.
        assert_eq!(
            find_pin(
                "./other/wheel.whl --hash=sha256:def\nsix==1.16.0\n",
                "six",
                "1.16.0"
            ),
            PinSearch::Exact {
                line_start: 1,
                line_count: 1,
                marker: None,
                hashed: false,
            }
        );
    }

    /// A symlinked requirements file is refused before any write by both
    /// wire and revert: the rename-over would replace the link with a
    /// regular file and leave its target stale, and revert would never
    /// restore the link.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_requirements_refuses_wire_and_revert_without_writing() {
        // wire: the planned root file is a link.
        let outer = tempfile::tempdir().unwrap();
        let real = outer.path().join("real.txt");
        tokio::fs::write(&real, "six==1.16.0\n").await.unwrap();
        let root = outer.path().join("proj");
        tokio::fs::create_dir_all(&root).await.unwrap();
        std::os::unix::fs::symlink(&real, root.join("requirements.txt")).unwrap();
        let err = wire_requirements(&root, "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap_err();
        assert_eq!(err.0, crate::hosted::engine::SYMLINK_REFUSAL);
        assert!(std::fs::symlink_metadata(root.join("requirements.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(read_root(&root).await, "six==1.16.0\n");

        // revert: a wired regular file swapped for a link afterwards.
        let tmp = write_root("six==1.16.0\n").await;
        let wiring = wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        let wired = read_root(tmp.path()).await;
        let target = outer.path().join("wired.txt");
        tokio::fs::write(&target, &wired).await.unwrap();
        tokio::fs::remove_file(tmp.path().join("requirements.txt"))
            .await
            .unwrap();
        std::os::unix::fs::symlink(&target, tmp.path().join("requirements.txt")).unwrap();
        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(!outcome.success);
        assert!(outcome.kept_artifact);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains(crate::hosted::engine::SYMLINK_REFUSAL)),
            "{:?}",
            outcome.error
        );
        assert!(
            std::fs::symlink_metadata(tmp.path().join("requirements.txt"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            read_root(tmp.path()).await,
            wired,
            "the link target is untouched"
        );
    }

    // ── in-use probe (#786) ───────────────────────────────────────────────

    const PROBE_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    /// The prune GC's in-use verdict for the requirements-flavored entry
    /// of [`probe_vendor_line`]'s wheel
    /// ([`crate::vex::discover::Discovery::vendor_entry_in_use`]).
    async fn in_use(root: &Path) -> Option<bool> {
        let entry: crate::vendor::state::VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": PROBE_UUID,
            "artifact": {
                "path": format!(".socket/vendor/pypi/{PROBE_UUID}/six-1.16.0-py2.py3-none-any.whl"),
                "sha256": "",
            },
            "wiring": [],
            "flavor": "requirements",
        }))
        .expect("a minimal vendor entry");
        crate::vex::discover::discover_patched_refs(root)
            .await
            .vendor_entry_in_use(root, &entry)
            .await
    }

    fn probe_vendor_line(transitive: bool) -> String {
        vendor_line(
            &format!(".socket/vendor/pypi/{PROBE_UUID}/six-1.16.0-py2.py3-none-any.whl"),
            None,
            "six",
            "1.16.0",
            &None,
            transitive,
        )
    }

    /// The wired shapes: the rewritten pin in the root file, the appended
    /// `(transitive)` line, and a pin rewritten inside an `-r` include all
    /// keep the entry in use.
    #[tokio::test]
    async fn in_use_probe_sees_wired_vendor_lines() {
        for (root_txt, include) in [
            (format!("{}\nidna==3.7\n", probe_vendor_line(false)), None),
            (format!("idna==3.7\n{}\n", probe_vendor_line(true)), None),
            (
                "-r requirements/base.txt\nidna==3.7\n".to_string(),
                Some(format!("{}\n", probe_vendor_line(false))),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            tokio::fs::write(root.join("requirements.txt"), &root_txt)
                .await
                .unwrap();
            if let Some(include) = &include {
                tokio::fs::create_dir(root.join("requirements"))
                    .await
                    .unwrap();
                tokio::fs::write(root.join("requirements/base.txt"), include)
                    .await
                    .unwrap();
            }
            assert_eq!(
                in_use(root).await,
                Some(true),
                "root={root_txt:?} include={include:?}"
            );
        }
    }

    /// #786: the user removed the vendored pin (case A), bumped it to
    /// another release (case B), or commented it out (pip ignores the
    /// line). The requirements tree was read and nothing pip installs
    /// names the uuid dir any more, so the entry is unused.
    #[tokio::test]
    async fn in_use_probe_reports_removed_or_bumped_pins_unused() {
        for root_txt in [
            "idna==3.7\n".to_string(),
            "six==1.17.0\nidna==3.7\n".to_string(),
            format!("# {}\nidna==3.7\n", probe_vendor_line(false)),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            tokio::fs::write(tmp.path().join("requirements.txt"), &root_txt)
                .await
                .unwrap();
            assert_eq!(in_use(tmp.path()).await, Some(false), "{root_txt:?}");
        }
        // A line for ANOTHER uuid (a superseding patch) does not keep this
        // one in use either.
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(
            tmp.path().join("requirements.txt"),
            probe_vendor_line(false).replace(PROBE_UUID, "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d"),
        )
        .await
        .unwrap();
        assert_eq!(in_use(tmp.path()).await, Some(false));
    }

    /// Nothing proves the entry unused when the tree cannot be read: no
    /// `requirements.txt` at all, or a reached include that exists but is
    /// unreadable (a FIFO). Callers keep the entry.
    #[cfg(unix)]
    #[tokio::test]
    async fn in_use_probe_is_undeterminable_without_a_readable_tree() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(in_use(tmp.path()).await, None);

        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("requirements.txt"), "-r base.txt\n")
            .await
            .unwrap();
        mkfifo(&tmp.path().join("base.txt"));
        assert_eq!(in_use(tmp.path()).await, None);
    }
}
