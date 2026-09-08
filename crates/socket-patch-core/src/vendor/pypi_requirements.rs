//! requirements.txt wiring (pip & `uv pip`).
//!
//! The spike-verified line shape is
//! `./<rel wheel> --hash=sha256:<hex>[ ; <marker>]  # socket-patch vendor: <name>==<ver>`:
//! both pip 26 and uv 0.11 accept the bare relative path (resolved against
//! the INVOKING CWD, never the requirements-file dir — hence the documented
//! root-only constraint), enforce the `--hash` pin (implicitly: any
//! `--hash` on any line turns hash-checking on), strip the trailing comment,
//! and genuinely EVALUATE a `; marker` on a path line — so an environment
//! marker is carried over from the replaced pin instead of refused.
//!
//! Logical-line model: physical lines join on a trailing `\`; comments start
//! at a `#` preceded by whitespace (or column 0) outside that. The dominant
//! newline style is preserved.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

use super::common::detect_eol;
use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorWarning};

/// Guarded read shared in shape with the sibling backend twins:
/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular
/// files, so a FIFO planted as `requirements.txt` (or an include) fails
/// fast instead of wedging every requirements-project vendor run (and
/// revert) forever in an `open(2)` that waits for a writer — the
/// flavor-routing probe ahead of the walk is metadata-only, so these are
/// the first opens.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

/// Classification of the target package within the requirements tree.
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

/// Scan one file for the target package: every clean exact
/// `canon_name==version` pin, plus whether any occurrence carries extras or
/// a non-exact specifier.
fn scan_pins(content: &str, canon_name: &str, version: &str) -> (Vec<PinSpan>, bool, bool) {
    let mut exact = Vec::new();
    let mut found_extras = false;
    let mut found_range = false;
    for ll in logical_lines(content) {
        let Some(req) = parse_requirement_line(&ll.text) else {
            continue;
        };
        if canonicalize_pypi_name(&req.name) != canon_name {
            continue;
        }
        if req.extras.is_some() {
            found_extras = true;
            continue;
        }
        let spec_no_ws: String = req
            .specifier
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if spec_no_ws == format!("=={version}") {
            exact.push((ll.start, ll.physical.len(), req.marker, req.hashed));
        } else {
            found_range = true;
        }
    }
    (exact, found_extras, found_range)
}

/// Find the target pin in one file's content. Precedence is fail-closed:
/// any extras occurrence wins over any non-pin occurrence wins over a clean
/// exact pin — a file that names the package ambiguously is never rewritten.
fn find_pin(content: &str, canon_name: &str, version: &str) -> PinSearch {
    let (exact, found_extras, found_range) = scan_pins(content, canon_name, version);
    if found_extras {
        return PinSearch::Extras;
    }
    if found_range {
        return PinSearch::Range;
    }
    match exact.into_iter().next() {
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
        /// entry left for the patch.
        pin: Option<(String, String)>,
    },
}

/// Pre-flight the wiring without writing — the orchestrator runs this before
/// building the wheel so every refusal happens with the tree byte-untouched.
///
/// A file already carrying a socket vendor line for this package
/// short-circuits the plan: at the SAME patch uuid it is our own first-run
/// edit (in sync — the artifact-only rebuild path handles a deleted wheel);
/// at a DIFFERENT uuid it refuses — appending a second wheel line would
/// leave pip two competing requirements, and the new ledger entry would
/// clobber the old one's record, orphaning its line.
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
            return Err((
                "pypi_requirements_already_vendored",
                format!(
                    "{}: already routes {canon_name} to the socket-patch vendored wheel for \
                     patch {found}; run `socket-patch vendor --revert` before re-vendoring",
                    file.rel
                ),
            ));
        }
    }
    plan_requirements(root, canon_name, version, "", "")
        .await
        .map(|_| RequirementsTarget::Fresh)
}

/// Find a socket vendor line for `canon_name` in one file's content and
/// return the patch uuid its wheel path names. Matches the exact shape
/// [`vendor_line`] writes: a wheel-path token plus the
/// `# socket-patch vendor: <name>==<version>` comment tag.
fn vendored_uuid_for(content: &str, canon_name: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        let Some((_, tag)) = trimmed.split_once("# socket-patch vendor: ") else {
            continue;
        };
        if !tag.starts_with(canon_name) || !tag[canon_name.len()..].starts_with("==") {
            continue;
        }
        let token = trimmed.split_whitespace().next().unwrap_or("");
        if let Some(parts) = super::path::parse_vendor_path(token) {
            if parts.eco == "pypi" {
                return Some(parts.uuid);
            }
        }
    }
    None
}

/// Extract the (wheel path, sha256) pin the wired vendor line for
/// `canon_name` carries — the same line shape [`vendored_uuid_for`] matches,
/// restricted to THIS patch uuid and requiring the `--hash=sha256:` pin
/// vendor always writes. Paths are returned bare (no `./` prefix), matching
/// the ledger's `artifact.path` spelling.
fn wired_pin_in(content: &str, canon_name: &str, record_uuid: &str) -> Option<(String, String)> {
    for line in content.lines() {
        let trimmed = line.trim();
        let Some((_, tag)) = trimmed.split_once("# socket-patch vendor: ") else {
            continue;
        };
        if !tag.starts_with(canon_name) || !tag[canon_name.len()..].starts_with("==") {
            continue;
        }
        let token = trimmed.split_whitespace().next().unwrap_or("");
        let Some(parts) = super::path::parse_vendor_path(token) else {
            continue;
        };
        if parts.eco != "pypi" || parts.uuid != record_uuid {
            continue;
        }
        let Some(sha) = trimmed
            .split_whitespace()
            .find_map(|t| t.strip_prefix("--hash=sha256:"))
        else {
            continue;
        };
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let path = token.strip_prefix("./").unwrap_or(token);
        return Some((path.to_string(), sha.to_string()));
    }
    None
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
    let plan = plan_requirements(root, canon_name, version, rel_wheel, wheel_sha256_hex).await?;
    let mut wiring = Vec::new();
    let mut written: Vec<&PlannedFile> = Vec::new();
    for file in &plan {
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

    let mut reverted: Vec<(String, String)> = Vec::new();
    for file in &files {
        let path = root.join(file);
        let content = match read_regular_to_string(&path).await {
            Ok(c) => c,
            Err(e) => {
                return RevertOutcome::failed(format!("cannot read {file}: {e}"));
            }
        };
        let nl = detect_eol(&content);
        let had_trailing_newline = content.ends_with('\n');
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();

        // Reverse order = bottom-up matching, so identical vendor lines pair
        // with their own originals (records were emitted top-down).
        for rec in entry.wiring.iter().rev().filter(|r| &r.file == file) {
            let Some(new_line) = rec.new.as_ref().and_then(serde_json::Value::as_str) else {
                warnings.push(drift_warning(file, rec));
                continue;
            };
            let Some(idx) = lines.iter().rposition(|l| l.trim() == new_line.trim()) else {
                warnings.push(drift_warning(file, rec));
                continue;
            };
            match rec.action {
                WiringAction::Added => {
                    lines.remove(idx);
                }
                WiringAction::Rewritten => {
                    let originals: Vec<String> = rec
                        .original
                        .as_ref()
                        .and_then(serde_json::Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    lines.splice(idx..idx + 1, originals);
                }
            }
        }

        let mut new_content = lines.join(nl);
        if had_trailing_newline && !new_content.is_empty() {
            new_content.push_str(nl);
        }
        reverted.push((file.clone(), new_content));
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
            "{file}: the vendor line for {:?} changed since vendoring; left untouched",
            rec.key
        ),
    )
}

// ── planning ─────────────────────────────────────────────────────────────

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
    let mut planned: Vec<PlannedFile> = Vec::new();
    let mut rewrote_any = false;

    for file in &files {
        match find_pin(&file.content, canon_name, version) {
            PinSearch::Extras => {
                return Err((
                    "pypi_extras_unsupported",
                    format!(
                        "{}: the {canon_name} pin declares extras, which a vendored wheel path \
                         line cannot express; remove the extras or use the `socket-patch setup` \
                         .pth install hook instead",
                        file.rel
                    ),
                ));
            }
            PinSearch::Range => {
                return Err((
                    "pypi_requirement_not_pinned",
                    format!(
                        "{}: {canon_name} is not pinned to =={version}; pin it exactly or use \
                         the `socket-patch setup` .pth install hook instead",
                        file.rel
                    ),
                ));
            }
            PinSearch::Absent => continue,
            PinSearch::Exact { .. } => {}
        }
        if !file.editable {
            // SECURITY/scope: an include outside the project root cannot be
            // edited by a committable vendor flow; rewriting only the in-root
            // copy would leave pip a duplicate requirement. Fail closed.
            return Err((
                "pypi_requirements_outside_root",
                format!(
                    "{}: {canon_name} is pinned in a requirements include outside the project \
                     root, which vendor cannot edit; inline it or use the `socket-patch setup` \
                     .pth install hook instead",
                    file.rel
                ),
            ));
        }

        // Rewrite EVERY exact-pin occurrence in this file, bottom-up so the
        // recorded spans (against the original content) stay valid.
        let (spans, _, _) = scan_pins(&file.content, canon_name, version);
        if spans.is_empty() {
            continue;
        }
        let nl = detect_eol(&file.content);
        let original_lines: Vec<String> = file.content.lines().map(str::to_string).collect();
        let mut lines = original_lines.clone();
        let mut records = Vec::new();
        for (start, count, marker, _) in spans.iter().rev() {
            let line = vendor_line(
                rel_wheel,
                wheel_sha256_hex,
                canon_name,
                version,
                marker,
                false,
            );
            let replaced: Vec<String> = original_lines[*start..*start + *count].to_vec();
            lines.splice(*start..*start + *count, [line.clone()]);
            records.push(WiringRecord {
                file: file.rel.clone(),
                kind: "requirements_line".to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{}:{}", file.rel, start + 1)),
                original: Some(serde_json::Value::Array(
                    replaced
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                )),
                new: Some(serde_json::Value::String(line)),
            });
        }
        records.reverse(); // application order = top-down
        let mut new_content = lines.join(nl);
        if file.content.ends_with('\n') && !new_content.is_empty() {
            new_content.push_str(nl);
        }
        planned.push(PlannedFile {
            rel: file.rel.clone(),
            original_content: file.content.clone(),
            new_content,
            records,
        });
        rewrote_any = true;
    }

    if !rewrote_any {
        // Transitive: append a managed line at the ROOT file's EOF. pip
        // treats it as one more requirement; the resolver folds it into the
        // graph exactly like the spike's mixed-requirements run.
        let root_file = files
            .first()
            .expect("collect_requirements_files always yields the root file first");
        let line = vendor_line(
            rel_wheel,
            wheel_sha256_hex,
            canon_name,
            version,
            &None,
            true,
        );
        let nl = detect_eol(&root_file.content);
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

/// The committed vendor line. `transitive` adds the `(transitive)` note so a
/// reader knows the line was appended (no pin was replaced).
fn vendor_line(
    rel_wheel: &str,
    sha256_hex: &str,
    canon_name: &str,
    version: &str,
    marker: &Option<String>,
    transitive: bool,
) -> String {
    let marker_part = marker
        .as_ref()
        .map(|m| format!(" ; {m}"))
        .unwrap_or_default();
    let note = if transitive { " (transitive)" } else { "" };
    format!(
        "./{rel_wheel} --hash=sha256:{sha256_hex}{marker_part}  # socket-patch vendor: {canon_name}=={version}{note}"
    )
}

/// Walk the root `requirements.txt` plus its `-r`/`--requirement` includes
/// (depth-first, resolved against the INCLUDING file's directory, visited-set
/// cycle guard). `-c` constraints files are never followed — they may not
/// introduce requirements, so a pin there is pip's problem, not ours, and we
/// must never edit them. The root file is always element 0.
async fn collect_requirements_files(root: &Path) -> Result<Vec<ReqFile>, (&'static str, String)> {
    let mut out: Vec<ReqFile> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<(String, PathBuf)> = vec![(
        "requirements.txt".to_string(),
        root.join("requirements.txt"),
    )];
    while let Some((rel, path)) = stack.pop() {
        if !visited.insert(rel.clone()) {
            continue;
        }
        let Ok(content) = read_regular_to_string(&path).await else {
            if out.is_empty() {
                return Err((
                    "pypi_no_requirements",
                    format!("cannot read {}", path.display()),
                ));
            }
            // A broken include is pip's error to report; vendor just can't
            // see inside it. Skip.
            continue;
        };
        // Out-of-root (`../`) and absolute includes resolve outside any
        // committable root — readable so a pin inside can refuse, never
        // editable. (`Path::join` passes an absolute `rel` through verbatim.)
        let editable = !rel.starts_with("../") && !Path::new(&rel).is_absolute();
        let include_dir = match rel.rfind('/') {
            Some(i) => rel[..i].to_string(),
            None => String::new(),
        };
        for ll in logical_lines(&content) {
            let Some(target) = include_target(&ll.text) else {
                continue;
            };
            let joined = if include_dir.is_empty() {
                target.to_string()
            } else {
                format!("{include_dir}/{target}")
            };
            let normalized = normalize_rel_path(&joined);
            stack.push((normalized.clone(), root.join(&normalized)));
        }
        out.push(ReqFile {
            rel,
            content,
            editable,
        });
    }
    // Depth-first stack order put the root last among pushes; restore "root
    // first" deterministically.
    out.sort_by_key(|f| f.rel != "requirements.txt");
    Ok(out)
}

/// The `-r`/`--requirement` include target of a logical line, if any.
fn include_target(text: &str) -> Option<&str> {
    let code = strip_comment(text).trim();
    if let Some(rest) = code.strip_prefix("--requirement=") {
        return Some(rest.trim()).filter(|s| !s.is_empty());
    }
    let mut tokens = code.split_whitespace();
    match tokens.next() {
        Some("-r") | Some("--requirement") => tokens.next(),
        // pip's optparse also accepts the attached short form (`-rdev.txt`);
        // the bare `-r` was consumed by the arm above, so the value here is
        // never empty. (No other requirements-file option starts with `-r`.)
        Some(t) if t.starts_with("-r") && !t.starts_with("--") => Some(&t[2..]),
        _ => None,
    }
}

/// Lexically normalize a relative path (`a/../b` → `b`); escapes above the
/// root keep their `../` prefix and absolute paths keep their leading `/`,
/// so the caller can spot out-of-root includes.
fn normalize_rel_path(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    let mut leading_parents = 0usize;
    let normalized = path.replace('\\', "/");
    let absolute = normalized.starts_with('/');
    for comp in normalized.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if stack.is_empty() {
                    leading_parents += 1;
                } else {
                    stack.pop();
                }
            }
            other => stack.push(other),
        }
    }
    let mut out = String::new();
    if absolute {
        out.push('/');
    }
    for _ in 0..leading_parents {
        out.push_str("../");
    }
    out.push_str(&stack.join("/"));
    out
}

// ── logical-line lexer ───────────────────────────────────────────────────

struct LogicalLine {
    /// 0-based index of the first physical line.
    start: usize,
    /// The raw physical lines (no newlines, no `\r`).
    physical: Vec<String>,
    /// Continuation-joined text (comments NOT yet stripped).
    text: String,
}

fn logical_lines(content: &str) -> Vec<LogicalLine> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let mut physical = vec![lines[i].to_string()];
        // pip's join_lines never continues a comment line: `# ...\` is a
        // complete comment, not a continuation of the next line.
        while lines[i].trim_end().ends_with('\\')
            && !lines[i].trim_start().starts_with('#')
            && i + 1 < lines.len()
        {
            i += 1;
            physical.push(lines[i].to_string());
        }
        let mut text = String::new();
        for (k, pl) in physical.iter().enumerate() {
            if k + 1 < physical.len() {
                // pip's join: the backslash and the newline vanish.
                text.push_str(pl.trim_end().strip_suffix('\\').unwrap_or(pl));
            } else {
                text.push_str(pl);
            }
        }
        // pip decodes the file with utf-8-sig (`auto_decode`) and uv strips
        // the BOM too: exactly one leading BOM at file start is encoding,
        // not data. Only `text` (the parse substrate) drops it — `physical`
        // stays raw, so a rewrite records (and a revert restores) the
        // original bytes.
        if start == 0 {
            if let Some(stripped) = text.strip_prefix('\u{feff}') {
                text = stripped.to_string();
            }
        }
        out.push(LogicalLine {
            start,
            physical,
            text,
        });
        i += 1;
    }
    out
}

/// Cut a trailing comment: `#` at column 0 or preceded by whitespace
/// (`--hash=sha256:ab#cd` is NOT a comment — no preceding whitespace).
fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &text[..i];
        }
    }
    text
}

struct ParsedRequirement {
    name: String,
    extras: Option<String>,
    specifier: String,
    marker: Option<String>,
    hashed: bool,
}

/// Parse one logical line as a requirement; `None` for blank lines, option
/// lines (`-r`, `--index-url`, …) and path/URL lines (no leading name).
fn parse_requirement_line(text: &str) -> Option<ParsedRequirement> {
    let code = strip_comment(text).trim();
    if code.is_empty() || code.starts_with('-') {
        return None;
    }
    // Per-line `--hash` options come after the requirement (and marker).
    let (req_part, hashed) = match code.find(" --hash") {
        Some(i) => (code[..i].trim_end(), true),
        None => (code, false),
    };
    // The environment marker is everything after the first `;` (specifiers
    // and names cannot contain one), carried VERBATIM for the rewrite.
    let (req_part, marker) = match req_part.find(';') {
        Some(i) => (
            req_part[..i].trim_end(),
            Some(req_part[i + 1..].trim().to_string()).filter(|m| !m.is_empty()),
        ),
        None => (req_part, None),
    };
    // PEP 508 name: must start alphanumeric.
    let name_end = req_part
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .map(|(i, _)| i)
        .unwrap_or(req_part.len());
    if name_end == 0 || !req_part.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    let name = req_part[..name_end].to_string();
    let mut rest = req_part[name_end..].trim_start();
    let mut extras = None;
    if let Some(stripped) = rest.strip_prefix('[') {
        let close = stripped.find(']')?;
        extras = Some(stripped[..close].trim().to_string());
        rest = stripped[close + 1..].trim_start();
    }
    Some(ParsedRequirement {
        name,
        extras,
        specifier: rest.trim().to_string(),
        marker,
        hashed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const REL_WHEEL: &str =
        ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl";
    const SHA: &str = "f75f0d4e2f0a4d29b8d3f3a87b8d6cbe9a1c1f95d97d4a92f51e1b04b6a3c9aa";
    /// A different canonical uuid, for "another patch generation" fixtures.
    const OTHER_UUID: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

    fn expected_line() -> String {
        format!("./{REL_WHEEL} --hash=sha256:{SHA}  # socket-patch vendor: six==1.16.0")
    }

    async fn write_root(content: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("requirements.txt"), content)
            .await
            .unwrap();
        tmp
    }

    async fn read_root(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("requirements.txt"))
            .await
            .unwrap()
    }

    fn entry_for(wiring: Vec<WiringRecord>) -> VendorEntry {
        VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: REL_WHEEL.into(),
                sha256: SHA.into(),
                size: Some(11053),
                platform_locked: None,
                file_inventory: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("requirements".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    // ── lexer ────────────────────────────────────────────────────────────

    #[test]
    fn lexer_joins_continuations_and_strips_comments_correctly() {
        let lines = logical_lines("six==1.16.0 \\\n    --hash=sha256:abc\nrequests\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].start, 0);
        assert_eq!(lines[0].physical.len(), 2);
        assert_eq!(lines[0].text, "six==1.16.0     --hash=sha256:abc");
        assert_eq!(lines[1].start, 2);

        // Comment rules: whitespace-preceded `#` (or column 0) only.
        assert_eq!(strip_comment("six==1.0  # pinned"), "six==1.0  ");
        assert_eq!(strip_comment("# whole line"), "");
        assert_eq!(
            strip_comment("x --hash=sha256:ab#cd"),
            "x --hash=sha256:ab#cd",
            "a # without preceding whitespace is data, not a comment"
        );
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
            format!("requests==2.31.0\n{}\n", expected_line())
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

    #[tokio::test]
    async fn marker_is_carried_over_verbatim() {
        let tmp = write_root("six==1.16.0 ; python_version >= \"3.8\"\n").await;
        wire_requirements(tmp.path(), "six", "1.16.0", REL_WHEEL, SHA)
            .await
            .unwrap();
        assert_eq!(
            read_root(tmp.path()).await,
            format!(
                "./{REL_WHEEL} --hash=sha256:{SHA} ; python_version >= \"3.8\"  # socket-patch vendor: six==1.16.0\n"
            )
        );
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
                "python-dateutil==2.8.2\n./{REL_WHEEL} --hash=sha256:{SHA}  # socket-patch vendor: six==1.16.0 (transitive)\n"
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
            format!("{}\n", expected_line())
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
            format!("# vendored from C:\\deps\\\n{}\n", expected_line())
        );
    }

    /// An absolute `-r /abs/path.txt` include resolves outside any committable
    /// root; a pin there must refuse exactly like a `../` include. Mangling it
    /// into an in-root relative path silently skips the file pip *can* read,
    /// and the transitive line appended at the root EOF gives pip a "double
    /// requirement" error.
    #[tokio::test]
    async fn pin_in_absolute_include_refuses() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        let shared = outer.path().join("shared.txt");
        tokio::fs::write(&shared, "six==1.16.0\n").await.unwrap();
        let root_content = format!("-r {}\n", shared.display());
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

    /// SECURITY regression: a poisoned state.json wiring record naming a
    /// `..`/absolute `file` must never make `--revert` read or rewrite a file
    /// outside the project root — the record is skipped with a warning and
    /// the out-of-tree target stays byte-identical. (Found by adversarial
    /// review: revert previously joined `rec.file` unvalidated, an arbitrary
    /// content-injection write.)
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
        // Drift: the user edited the vendor line (changed the hash).
        let drifted = read_root(tmp.path()).await.replace(SHA, &"0".repeat(64));
        tokio::fs::write(tmp.path().join("requirements.txt"), &drifted)
            .await
            .unwrap();

        let outcome = revert_requirements(&entry_for(wiring), tmp.path(), false).await;
        assert!(outcome.success);
        assert!(outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_line_drifted"));
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
        assert_eq!(read_root(tmp.path()).await, format!("{}\n", expected_line()));

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
            format!("{}\n", expected_line())
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
            outcome.error.as_deref().unwrap_or("").contains("cannot read"),
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
        assert_eq!(written.matches(&expected_line()).count(), 2);

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
                "requests==2.31.0\n./{REL_WHEEL} --hash=sha256:{SHA}  # socket-patch vendor: six==1.16.0 (transitive)\n"
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
                "requests==2.31.0\r\nzope.interface==5.0\r\n./{REL_WHEEL} --hash=sha256:{SHA}  # socket-patch vendor: six==1.16.0 (transitive)\r\n"
            )
        );
    }

    // ── nested includes ──────────────────────────────────────────────────

    /// A `-r` inside a non-root file resolves against the INCLUDING file's
    /// directory (the module's documented contract): `deps/a.txt` reaches
    /// `b.txt` (sibling → `deps/b.txt`) and `../c.txt` (back at the root —
    /// the interior `..` pop of `normalize_rel_path`). The pin in deps/b.txt
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
            format!("{}\n", expected_line())
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
        assert_eq!(include_target("--requirement=dev.txt"), Some("dev.txt"));
        assert_eq!(
            include_target("--requirement= dev.txt "),
            Some("dev.txt"),
            "the attached value is trimmed"
        );
        assert_eq!(
            include_target("--requirement="),
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
            format!("{}\n", expected_line())
        );
    }

    // ── pure-function matrices ───────────────────────────────────────────

    /// Lexical normalization: interior `..` pops the stack (which decides
    /// editable-vs-refuse for nested includes); escapes keep their `../`
    /// prefix; absolute paths keep their leading `/`.
    #[test]
    fn normalize_rel_path_unit_matrix() {
        assert_eq!(normalize_rel_path("deps/../dev.txt"), "dev.txt");
        assert_eq!(normalize_rel_path("a/b/../../c"), "c");
        assert_eq!(
            normalize_rel_path("deps/../../x"),
            "../x",
            "pop, then the second `..` escapes"
        );
        assert_eq!(normalize_rel_path("./a//b/./c"), "a/b/c");
        assert_eq!(normalize_rel_path("../x"), "../x");
        assert_eq!(normalize_rel_path("/abs/../x"), "/x");
        assert_eq!(normalize_rel_path("deps\\..\\dev.txt"), "dev.txt");
    }

    /// Lines that do not start with a PEP 508 name are not requirements —
    /// in particular this module's OWN vendor-line shape must be invisible
    /// to the pin search, or an already-wired path line would misparse as a
    /// pin during a later scan.
    #[test]
    fn parse_requirement_line_ignores_path_and_nonname_lines() {
        assert!(parse_requirement_line(&expected_line()).is_none());
        assert!(parse_requirement_line("./local/wheel.whl --hash=sha256:abc").is_none());
        assert!(parse_requirement_line("=six==1.0").is_none());
        assert!(parse_requirement_line("[section]").is_none());
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
}
