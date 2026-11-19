//! Pure text builders for `scan`'s human output: the status notes, the
//! dry-run line, the `--verbose` per-patch preview, and the hints. The
//! rows and the closing totals are `report`'s.
//! No I/O and no terminal state (color is decided by the caller and passed
//! in), so every string is unit-testable byte for byte.

use std::collections::HashMap;

use socket_patch_core::api::types::{PatchSearchResult, VulnerabilityResponse};

use crate::args::GlobalArgs;
use crate::ui::{self, plural};
use socket_patch_core::api::ranking::severity_order;

/// Per-patch preview limits for API free text (unless `--verbose`).
const SUMMARY_MAX: usize = 76;
const DESCRIPTION_MAX: usize = 72;

/// Fit a PURL into `max` characters, keeping the `@version` (and any
/// `?qualifiers`) tail and eliding the middle of the name:
/// `pkg:npm/@typescript-eslint/typescript-estree@6.0.0` at 40 becomes
/// `pkg:npm/@typ...t/typescript-estree@6.0.0`. Falls back to a plain
/// truncation when the tail alone does not fit.
pub(super) fn elide_purl(purl: &str, max: usize) -> String {
    let chars: Vec<char> = purl.chars().collect();
    if chars.len() <= max {
        return purl.to_string();
    }
    const DOTS: &str = "...";
    // The version starts at the last `@` that is not the scope marker
    // right after the type (`pkg:npm/@scope/...`).
    let at = chars
        .iter()
        .rposition(|&c| c == '@')
        .filter(|&i| i > 0 && chars[i - 1] != '/');
    let Some(at) = at else {
        return ui::truncate(purl, max);
    };
    let tail = &chars[at..];
    // Keep at least a few characters of the name on each side.
    let budget = max.saturating_sub(tail.len() + DOTS.len());
    if budget < 8 {
        return ui::truncate(purl, max);
    }
    // The end of the name (the package's own name) says more than the
    // start (type and scope), so it gets the larger share.
    let name = &chars[..at];
    let head_len = budget * 2 / 5;
    let end_len = budget - head_len;
    let head: String = name[..head_len].iter().collect();
    let end: String = name[name.len() - end_len..].iter().collect();
    let tail: String = tail.iter().collect();
    format!("{head}{DOTS}{end}{tail}")
}

/// How many packages have a newer patch than the one the project records.
pub(super) fn updates_line(n: usize) -> String {
    if n == 1 {
        "1 package has a newer patch available.".to_string()
    } else {
        format!("{n} packages have newer patches available.")
    }
}

/// The note after the crawl summary for lockfile-only packages.
pub(super) fn lockfile_only_note(n: usize) -> String {
    let verb = if n == 1 { "is" } else { "are" };
    format!(
        "Note: {} from project lockfiles {verb} not yet installed (lockfile-only).",
        plural(n, "package", "packages")
    )
}

/// What an empty crawl says when `warnings` on stderr say why nothing was
/// found (a lockfile or layout that could not be read, project directories
/// below that an agent-mode scan left): the generic "install first" hint
/// would send the user the wrong way.
pub(crate) fn no_packages_unreadable(warnings: usize) -> String {
    if warnings == 1 {
        "No packages found (see the warning).".to_string()
    } else {
        "No packages found (see the warnings).".to_string()
    }
}

/// What an empty crawl says, naming the filter that emptied it when there
/// was one (`--ecosystems`, PATH scoping) instead of a generic
/// "install first" hint.
pub(crate) fn no_packages_message(
    global: bool,
    ecosystems: Option<&[String]>,
    paths: &[String],
) -> String {
    if global {
        return "No global packages found.".to_string();
    }
    if !paths.is_empty() {
        return format!(
            "No installed packages found under {}.",
            quoted_list(paths, "the given path", "the given paths")
        );
    }
    if let Some(list) = ecosystems.filter(|l| !l.is_empty()) {
        return format!("No {} packages found.", list.join("/"));
    }
    "No packages found. Run your package manager's install first.".to_string()
}

/// What a scan says when the consent gate held back every package it
/// found: `declared` packages the project patches itself, and `unreadable`
/// ones held back only because a project file could not be read. A broken
/// file is fixed, not overridden, so only the first line names
/// `--allow-patch-conflicts`. The notice above
/// ([`project_patch_notice`]) names the files and the packages.
pub(crate) fn user_patch_withheld_lines(declared: usize, unreadable: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if unreadable > 0 {
        lines.push(format!(
            "{} not scanned: this project's own patches could not be checked (see the \
             warning). Fix the file it names and run again.",
            plural(unreadable, "package was", "packages were")
        ));
    }
    if declared > 0 {
        let (was, them) = if declared == 1 {
            ("was", "it")
        } else {
            ("were", "them")
        };
        lines.push(format!(
            "{} protected by this project's own patches and {was} not scanned. Pass \
             --allow-patch-conflicts to scan {them} anyway.",
            plural(declared, "package is", "packages are")
        ));
    }
    lines
}

/// A package the project's own patches cover, as the scan's consent gate
/// found it.
pub(crate) struct Protected {
    pub purl: String,
    /// The project files that cover it.
    pub sources: Vec<String>,
    /// Covered only because one of those files could not be read or
    /// parsed: nothing the project is known to declare.
    pub unreadable: bool,
}

/// How many packages, and how many files, a project-patch notice names
/// before it folds the rest.
const PROTECTED_NAMED: usize = 3;

/// The scan's notice of the packages the project's own patches cover: one
/// short block per kind, where there used to be a warning per package (a
/// project file that cannot be read covers every package of its
/// ecosystem, so that was a warning per installed package).
///
/// - Left alone because the project declares a patch or replacement for
///   them: a `Note:`, the steady state of a project that patches a few
///   dependencies itself.
/// - Left alone because a project file could not be read: a `Warning:`
///   that says to fix the file.
/// - Not left alone, under `--allow-patch-conflicts` (`allowed`): a
///   `Warning:` to review the result.
///
/// Each names the files (relative to `cwd`) and the first few packages;
/// `--verbose` lists every package under its block with its own files.
pub(crate) fn project_patch_notice(
    protected: &[Protected],
    allowed: bool,
    verbose: bool,
    cwd: &std::path::Path,
) -> Vec<String> {
    let mut lines = Vec::new();
    if allowed {
        let group: Vec<&Protected> = protected.iter().collect();
        notice_block(&mut lines, &group, Kind::Allowed, verbose, cwd);
    } else {
        let (unreadable, declared): (Vec<&Protected>, Vec<&Protected>) =
            protected.iter().partition(|p| p.unreadable);
        notice_block(&mut lines, &unreadable, Kind::Unreadable, verbose, cwd);
        notice_block(&mut lines, &declared, Kind::Declared, verbose, cwd);
    }
    lines
}

/// Which block of [`project_patch_notice`] a group of packages gets.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Declared,
    Unreadable,
    Allowed,
}

/// A project file as the notice names it: relative to `cwd` when it is
/// below it. A source may carry a reason after the path
/// (`package.json (not valid JSON: ...)`), which stays.
fn shown_source(source: &str, cwd: &std::path::Path) -> String {
    let base = cwd.to_string_lossy();
    source
        .strip_prefix(base.as_ref())
        .and_then(|rest| rest.strip_prefix(['/', '\\']))
        .filter(|rest| !rest.is_empty())
        .unwrap_or(source)
        .to_string()
}

fn notice_block(
    lines: &mut Vec<String>,
    group: &[&Protected],
    kind: Kind,
    verbose: bool,
    cwd: &std::path::Path,
) {
    use socket_patch_core::utils::purl::canonical_purl;
    use std::collections::{BTreeMap, BTreeSet};

    // One entry per package: a crawl finds a release once per installed
    // copy.
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in group {
        packages
            .entry(canonical_purl(&package.purl))
            .or_default()
            .extend(package.sources.iter().map(|s| shown_source(s, cwd)));
    }
    if packages.is_empty() {
        return;
    }
    let names = ui::package_names(&packages.keys().map(String::as_str).collect::<Vec<_>>());
    let sources: Vec<String> = packages
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let files = ui::folded(&sources, PROTECTED_NAMED);
    let count = plural(names.len(), "package", "packages");
    let (it, lists) = if names.len() == 1 {
        ("it", "")
    } else {
        ("them", "; --verbose lists them all")
    };
    // Every name fits, or `--verbose` lists them below: the fold is for
    // the long lists only.
    let named = if verbose && names.len() > PROTECTED_NAMED {
        String::new()
    } else {
        format!(": {}", ui::folded(&names, PROTECTED_NAMED))
    };
    let more = if names.len() > PROTECTED_NAMED && !verbose {
        lists
    } else {
        ""
    };
    match kind {
        Kind::Declared => {
            lines.push(format!(
                "Note: skipped {count} covered by this project's own patches ({files}){named}."
            ));
            lines.push(format!("  --allow-patch-conflicts patches {it} too{more}."));
        }
        Kind::Unreadable => {
            let fix = if sources.len() == 1 {
                "that file"
            } else {
                "those files"
            };
            lines.push(format!(
                "Warning: {count} not patched, because this project's own patches could not \
                 be checked: {files}. Fix {fix} and run again."
            ));
        }
        Kind::Allowed => {
            lines.push(format!(
                "Warning: --allow-patch-conflicts: {count} covered by this project's own \
                 patches ({files}) may get a Socket patch too{named}. Review and test the \
                 combined result."
            ));
        }
    }
    if verbose && names.len() > PROTECTED_NAMED {
        for (name, own) in names.iter().zip(packages.values()) {
            // A package's files are worth a line's width only where they
            // are not the block's.
            if own.len() == sources.len() {
                lines.push(format!("  {name}"));
            } else {
                let own: Vec<String> = own.iter().cloned().collect();
                lines.push(format!("  {name}  ({})", own.join(", ")));
            }
        }
    }
}

/// What a bare scan's search for project directories left out, one line
/// each: roots under an ignored path, and a walk that gave up.
/// `filter_paths`: the run's selection filter skips roots by path too (and
/// goes on skipping one that is named).
pub(super) fn discovery_notes(ignored: usize, truncated: bool, filter_paths: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if ignored > 0 {
        let (lists, unless) = if filter_paths {
            (
                "socket.yml path filters, the selection filter's skip.paths and the built-in \
                 test and fixture directories",
                " (the selection filter still skips the ones it names)",
            )
        } else {
            (
                "socket.yml path filters and the built-in test and fixture directories",
                "",
            )
        };
        lines.push(format!(
            "Note: {} under ignored paths ({lists}) {} not scanned; name a directory to scan \
             it{unless}.",
            plural(ignored, "project directory", "project directories"),
            if ignored == 1 { "was" } else { "were" },
        ));
    }
    if truncated {
        lines.push(
            "Warning: this directory tree is too large to search for project directories; \
             some may have been missed. Name the project directories to scan them."
                .to_string(),
        );
    }
    lines
}

/// Warning code: a scan found project directories below `--cwd` that it
/// did not scan. A `--json` or `--vex` scan reports on one directory, and
/// an agent-mode scan patches the packages installed for one.
pub(super) const PROJECTS_NOT_SCANNED: &str = "projects_not_scanned";

/// The [`PROJECTS_NOT_SCANNED`] detail: which directories, and the run
/// that covers each.
pub(super) fn unscanned_projects_detail(dirs: &[String], json: bool) -> String {
    let flag = if json { "--json" } else { "--vex" };
    format!(
        "{}: {flag} takes one project directory. \
         Run one scan per directory, e.g. `socket-patch scan {}`",
        projects_left(dirs.len(), &dirs.join(", ")),
        ui::shell_word(&dirs[0]),
    )
}

/// The [`PROJECTS_NOT_SCANNED`] detail of an agent-mode scan: the project
/// directories below `--cwd` (`dirs`) whose installed packages it did not
/// read, and `command`, the run that covers the first. A long list is cut
/// short: a checkout can hold hundreds of projects.
pub(super) fn unscanned_agent_projects_detail(dirs: &[String], command: &str) -> String {
    let names: Vec<&str> = dirs.iter().map(String::as_str).collect();
    format!(
        "{}: an agent-mode scan patches the packages installed for the one project \
         directory it runs in. Run one scan per directory, e.g. `{command}`",
        projects_left(
            dirs.len(),
            &crate::commands::projects_below::spelled_out(&names)
        ),
    )
}

/// `2 project directories below this one were not scanned (a, b)`: how a
/// [`PROJECTS_NOT_SCANNED`] detail opens, for `count` directories listed
/// as `names`.
fn projects_left(count: usize, names: &str) -> String {
    format!(
        "{} below this one {} not scanned ({names})",
        plural(count, "project directory", "project directories"),
        if count == 1 { "was" } else { "were" },
    )
}

/// `the given path: a` / `the given paths: a, b`.
fn quoted_list(items: &[String], one: &str, many: &str) -> String {
    let label = if items.len() == 1 { one } else { many };
    format!("{label}: {}", items.join(", "))
}

/// The warning for one failed API batch of several (the scan goes on
/// with the others). A one-batch scan prints only [`all_batches_failed`].
pub(super) fn batch_failed_warning(batch: usize, total: usize, err: &str) -> String {
    format!("Warning: API batch {batch} of {total} failed: {err}")
}

/// The error when every API batch failed.
pub(super) fn all_batches_failed(total: usize, err: &str) -> String {
    if total == 1 {
        format!("Error: The API query failed: {err}")
    } else {
        format!("Error: All {total} API batch queries failed (last error: {err})")
    }
}

/// How many unanswered purls [`unanswered_lookups`] spells out.
const UNANSWERED_NAMED: usize = 5;

/// The warning detail for packages the patch API gave no answer for while
/// it answered for others: how many of the `total` queried, which ones
/// (the first few), and the first one's error. `unanswered` is
/// `(purl, error)`, never empty.
pub(super) fn unanswered_lookups(unanswered: &[(String, String)], total: usize) -> String {
    let mut names: Vec<&str> = unanswered
        .iter()
        .take(UNANSWERED_NAMED)
        .map(|(purl, _)| purl.as_str())
        .collect();
    let more = format!("{} more", unanswered.len().saturating_sub(names.len()));
    if unanswered.len() > names.len() {
        names.push(&more);
    }
    format!(
        "{} of {total} packages could not be checked for patches ({}): {}",
        unanswered.len(),
        names.join(", "),
        unanswered.first().map_or("", |(_, error)| error.as_str())
    )
}

/// The result line of a scan that found no patch but could not check
/// every package (a failed batch, or packages the API gave no answer for):
/// "no patches" is only known for the ones that were answered.
pub(super) const NO_PATCHES_AMONG_CHECKED: &str = "No patches found for the packages that could \
     be checked; the others were not checked (see the warning above).";

/// Warning printed when `--prune` cannot run because nothing was crawled
/// (pruning every manifest entry is too destructive to do implicitly).
pub(super) const PRUNE_SKIPPED_EMPTY: &str = "Warning: --prune skipped: no installed packages \
     were found, and pruning every manifest entry is too destructive to do implicitly; run \
     `socket-patch repair` to clean up .socket/ explicitly.";

/// The `vendor_ledger_entry_unwired` warning: vendored entries whose
/// dependency left the lockfile (upgraded or removed), so the scan no
/// longer discovers them, and `--prune` reverts them. A prune that
/// drift-keeps an entry (its lock entries were re-resolved since vendoring)
/// explains that on its own `GC: kept` line, so the detail points there
/// rather than suggesting a lock edit whose reach it cannot bound.
pub(super) fn unwired_vendored_detail(purls: &[String]) -> String {
    let one = purls.len() == 1;
    let them = if one { "it" } else { "them" };
    format!(
        "{} no longer used by the lockfile (the dependency was upgraded or removed) and {} \
         skipped ({}); run `socket-patch scan --prune` to revert {them} (a prune that keeps \
         {them} because the lock entries were re-resolved since vendoring says so on its \
         `GC: kept` line)",
        crate::ui::plural(purls.len(), "vendored entry is", "vendored entries are"),
        if one { "was" } else { "were" },
        purls.join(", "),
    )
}

/// What the dry-run line says the run would do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// Agent mode: download `new` patches and apply them in place, and
    /// re-apply the `recorded` ones the manifest already holds.
    Apply { new: usize, recorded: usize },
    /// Vendored mode: of `total` selected patches, `refused` would be
    /// refused by the vendored preflight (listed as `[would-refuse]`
    /// lines) and `in_sync` are held by the ledger at this uuid (listed as
    /// `[skip] … (already vendored)` lines); `skipped` are expected skips
    /// (a gem version the project doesn't lock, listed as `[skip]` lines
    /// with their code); the rest are downloaded and vendored.
    Vendor {
        total: usize,
        refused: usize,
        in_sync: usize,
        skipped: usize,
    },
}

/// The `--dry-run` headline. A vendored plan leaves out what the wet run
/// refuses or skips as already vendored, so the headline never promises
/// to vendor either (#1850).
pub(super) fn dry_run_line(plan: Plan) -> String {
    let what = match plan {
        Plan::Apply { new, recorded: 0 } => {
            format!("download and apply {}", plural(new, "patch", "patches"))
        }
        Plan::Apply { new, recorded } => format!(
            "download and apply {} and re-apply {recorded} already recorded",
            plural(new, "patch", "patches")
        ),
        Plan::Vendor {
            total,
            refused,
            in_sync,
            skipped,
        } if refused > 0 || in_sync > 0 || skipped > 0 => {
            let mut why = Vec::new();
            if in_sync > 0 {
                why.push(format!("{in_sync} already vendored"));
            }
            if skipped > 0 {
                why.push(format!("{skipped} would be skipped"));
            }
            if refused > 0 {
                why.push(format!("{refused} would be refused"));
            }
            format!(
                "download and vendor {} of {} ({})",
                total.saturating_sub(refused + in_sync + skipped),
                plural(total, "patch", "patches"),
                why.join(", ")
            )
        }
        Plan::Vendor { total, .. } => {
            format!("download and vendor {}", plural(total, "patch", "patches"))
        }
    };
    format!("[dry-run] Would {what}. No changes made.")
}

/// Lines printed after a report-only scan (`--prune` or global with no
/// mode, so no lockfile to rewire): how to apply what it found. A global
/// run's commands repeat its scope (`-g` or `--global-prefix <dir>`):
/// without it, running the hint verbatim patches the cwd project and
/// leaves the global copy unpatched (#464).
pub(super) fn report_only_hint(common: &GlobalArgs) -> [String; 3] {
    let scope = ui::global_scope_arg(common);
    let (scan, get) = match &scope {
        Some(scope) => (
            format!("  socket-patch scan --mode agent {scope}"),
            format!("  socket-patch get {scope} <package-name-or-purl-or-CVE-ID>"),
        ),
        None => (
            "  socket-patch scan --mode agent [PATHS]".to_string(),
            "  socket-patch get <package-name-or-purl-or-CVE-ID>".to_string(),
        ),
    };
    [
        "To apply these patches in place, run:".to_string(),
        scan,
        get,
    ]
}

/// Printed (vendored mode, before vendoring) for a selected package whose
/// installed bytes differ from the patch baseline: vendoring still
/// proceeds, with the verified patched content.
pub(super) fn baseline_mismatch_line(purl: &str) -> String {
    format!(
        "  {purl}: installed content differs from patch baseline; the patched content will be vendored"
    )
}

/// `[skip]` line for a package owned by the vendored mode.
pub(super) fn vendored_skip_line(purl: &str) -> String {
    format!("  [skip] {purl} (vendored; run `socket-patch scan --mode vendored` to update it)")
}

/// `[skip]` line for a lockfile-only package in agent mode.
pub(super) fn not_installed_skip_line(purl: &str) -> String {
    format!(
        "  [skip] {purl} (not installed; run your package manager's install first, \
         or `socket-patch scan --mode vendored` to vendor it from the lockfile)"
    )
}

/// How many not-installed packages [`not_installed_skip_lines`] names one
/// per line; past it they share one line that names this many.
const NOT_INSTALLED_NAMED: usize = 3;

/// The `[skip]` lines for the lockfile-only packages an agent-mode scan
/// leaves out: one [`not_installed_skip_line`] each, or (past three of
/// them, unless `--verbose`) one line for them all. A fresh clone locks
/// every package and installs none, and the remedy is the same for each.
pub(super) fn not_installed_skip_lines(purls: &[String], verbose: bool) -> Vec<String> {
    if verbose || purls.len() <= NOT_INSTALLED_NAMED {
        return purls.iter().map(|p| not_installed_skip_line(p)).collect();
    }
    vec![format!(
        "  [skip] {} with patches are not installed ({}, +{} more); run your package \
         manager's install first, or `socket-patch scan --mode vendored` to vendor them from \
         the lockfile",
        plural(purls.len(), "package", "packages"),
        purls[..NOT_INSTALLED_NAMED].join(", "),
        purls.len() - NOT_INSTALLED_NAMED,
    )]
}

/// Line for a selection the manifest already records: `[re-apply]` on a
/// wet agent run (the nested apply re-applies it), `[skip]` in a preview.
pub(super) fn already_recorded_line(purl: &str, uuid: &str, reapply: bool) -> String {
    let tag = if reapply { "re-apply" } else { "skip" };
    format!(
        "  [{tag}] {purl} (already recorded: {})",
        crate::ui::short_uuid(uuid)
    )
}

/// Printed when every selection is already recorded and nothing is applied
/// (report-only scan).
pub(super) const ALL_ALREADY_RECORDED: &str =
    "All selected patches are already recorded in the manifest; run `socket-patch apply` to re-apply them.";

/// [`ALL_ALREADY_RECORDED`] for an agent-mode `--dry-run`. A report-only
/// dry run keeps [`ALL_ALREADY_RECORDED`]: dropping `--dry-run` there still
/// only reports.
pub(super) const ALL_ALREADY_RECORDED_DRY_RUN: &str =
    "All selected patches are already recorded in the manifest; a run without --dry-run re-applies them.";

/// The terminal error when no package's patch details could be fetched.
pub(super) fn fetch_details_failed(failed: &[(String, String)]) -> String {
    match failed {
        [] => "Error: could not fetch patch details.".to_string(),
        [(purl, err)] => format!("Error: could not fetch patch details for {purl}: {err}"),
        [.., (_, last)] => format!(
            "Error: could not fetch patch details for any of the {} (last error: {last})",
            plural(failed.len(), "package", "packages")
        ),
    }
}

/// What the manifest already records for a package the preview offers a
/// different patch for.
pub(super) struct Replaces<'a> {
    pub uuid: &'a str,
    /// Vulnerability ids the recorded patch fixes.
    pub vuln_ids: Vec<&'a str>,
}

/// Everything [`patch_block`] needs about one selected patch.
pub(super) struct PatchBlock<'a> {
    pub patch: &'a PatchSearchResult,
    /// The severity label, already colored by the caller.
    pub severity: &'a str,
    pub replaces: Option<Replaces<'a>>,
    /// `--verbose`: no truncation of API free text.
    pub verbose: bool,
}

/// The patch's vulnerabilities, worst first, then by id: a stable order
/// (the API map is a `HashMap`, whose order changes between runs).
fn sorted_vulns(
    vulns: &HashMap<String, VulnerabilityResponse>,
) -> Vec<(&String, &VulnerabilityResponse)> {
    let mut v: Vec<_> = vulns.iter().collect();
    v.sort_by(|a, b| {
        severity_order(Some(&a.1.severity))
            .cmp(&severity_order(Some(&b.1.severity)))
            .then_with(|| vuln_label(a.0, a.1).cmp(&vuln_label(b.0, b.1)))
    });
    v
}

/// A vulnerability's display id(s): its CVEs, or the advisory id when it
/// has none.
fn vuln_label(id: &str, vuln: &VulnerabilityResponse) -> String {
    if vuln.cves.is_empty() {
        id.to_string()
    } else {
        let mut cves = vuln.cves.clone();
        cves.sort();
        cves.join(", ")
    }
}

/// The worst severity among the patch's vulnerabilities, if any.
pub(super) fn highest_severity(patch: &PatchSearchResult) -> Option<&str> {
    patch
        .vulnerabilities
        .values()
        .map(|v| v.severity.as_str())
        .min_by_key(|s| severity_order(Some(s)))
}

/// The warning for a replacement that leaves some of the recorded patch's
/// vulnerabilities unfixed (fewer, or different ones). The caller prints
/// it on stderr, right under the block's first line. `None` when the new
/// patch fixes everything the recorded one does.
pub(super) fn replacement_warning(b: &PatchBlock) -> Option<String> {
    let r = b.replaces.as_ref()?;
    let old: std::collections::HashSet<&str> = r.vuln_ids.iter().copied().collect();
    let missing = old
        .iter()
        .filter(|id| !b.patch.vulnerabilities.contains_key(**id))
        .count();
    if missing == 0 {
        None
    } else if old.len() == 1 {
        Some(
            "    Warning: this patch does not fix the vulnerability the recorded patch fixes"
                .to_string(),
        )
    } else if missing == old.len() {
        Some(format!(
            "    Warning: this patch fixes none of the {} vulnerabilities the recorded patch fixes",
            old.len()
        ))
    } else {
        Some(format!(
            "    Warning: this patch does not fix {missing} of the {} vulnerabilities the recorded patch fixes",
            old.len()
        ))
    }
}

/// One patch in the "Patches to apply/vendor" preview, ending with a
/// blank line.
pub(super) fn patch_block(b: &PatchBlock) -> Vec<String> {
    let p = b.patch;
    let fit = |s: &str, max: usize| ui::truncate(s, if b.verbose { usize::MAX } else { max });
    let mut lines = Vec::new();
    let replaces = b
        .replaces
        .as_ref()
        .map(|r| format!(" (replaces {})", crate::ui::short_uuid(r.uuid)))
        .unwrap_or_default();
    lines.push(format!(
        "  {} [{}] {}{replaces}",
        socket_patch_core::utils::purl::normalize_purl(&p.purl),
        p.tier.to_uppercase(),
        b.severity,
    ));
    let vulns = sorted_vulns(&p.vulnerabilities);
    if !vulns.is_empty() {
        let ids: Vec<String> = vulns.iter().map(|(id, v)| vuln_label(id, v)).collect();
        lines.push(format!("    Fixes: {}", ids.join(", ")));
    }
    for (id, v) in &vulns {
        if !v.summary.trim().is_empty() {
            lines.push(format!(
                "    - {}: {}",
                vuln_label(id, v),
                fit(&v.summary, SUMMARY_MAX)
            ));
        }
    }
    let desc = fit(&p.description, DESCRIPTION_MAX);
    if !desc.is_empty() {
        lines.push(format!("    {desc}"));
    }
    lines.push(String::new());
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_failure_lines() {
        assert_eq!(
            batch_failed_warning(2, 3, "Network error: refused"),
            "Warning: API batch 2 of 3 failed: Network error: refused"
        );
        assert_eq!(
            all_batches_failed(1, "Network error: refused"),
            "Error: The API query failed: Network error: refused"
        );
        assert_eq!(
            all_batches_failed(3, "Network error: refused"),
            "Error: All 3 API batch queries failed (last error: Network error: refused)"
        );
    }

    #[test]
    fn unanswered_lookups_counts_names_and_bounds_the_list() {
        let miss = |i: usize| (format!("pkg:npm/p{i}@1.0.0"), format!("error {i}"));
        assert_eq!(
            unanswered_lookups(&[miss(1)], 3),
            "1 of 3 packages could not be checked for patches (pkg:npm/p1@1.0.0): error 1"
        );
        let many: Vec<_> = (1..=7).map(miss).collect();
        assert_eq!(
            unanswered_lookups(&many, 500),
            "7 of 500 packages could not be checked for patches (pkg:npm/p1@1.0.0, \
             pkg:npm/p2@1.0.0, pkg:npm/p3@1.0.0, pkg:npm/p4@1.0.0, pkg:npm/p5@1.0.0, 2 more): \
             error 1"
        );
    }

    fn vuln(cves: &[&str], summary: &str, severity: &str) -> VulnerabilityResponse {
        VulnerabilityResponse {
            cves: cves.iter().map(|s| s.to_string()).collect(),
            summary: summary.to_string(),
            severity: severity.to_string(),
            description: String::new(),
        }
    }

    fn patch(vulns: &[(&str, VulnerabilityResponse)], description: &str) -> PatchSearchResult {
        PatchSearchResult {
            uuid: "884e9f6d-0000-0000-0000-000000000000".to_string(),
            purl: "pkg:npm/%40scope/nuxt@4.5.0".to_string(),
            published_at: String::new(),
            description: description.to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
            vulnerabilities: vulns
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }

    fn block<'a>(p: &'a PatchSearchResult, verbose: bool) -> PatchBlock<'a> {
        PatchBlock {
            patch: p,
            severity: "HIGH",
            replaces: None,
            verbose,
        }
    }

    // ---- table ------------------------------------------------------------

    #[test]
    fn elide_purl_keeps_version() {
        let purl = "pkg:npm/@typescript-eslint/typescript-estree@6.0.0";
        assert_eq!(elide_purl(purl, 60), purl);
        let out = elide_purl(purl, 40);
        assert_eq!(out, "pkg:npm/@typ...t/typescript-estree@6.0.0");
        assert_eq!(out.chars().count(), 40);
    }

    #[test]
    fn elide_purl_never_exceeds_max() {
        let purl = "pkg:npm/@typescript-eslint/typescript-estree@6.0.0";
        for max in 0..60 {
            let out = elide_purl(purl, max);
            assert!(out.chars().count() <= max, "max={max} out={out:?}");
        }
    }

    #[test]
    fn elide_purl_without_version_or_room_truncates() {
        let no_version = format!("pkg:generic/{}", "a".repeat(60));
        assert_eq!(elide_purl(&no_version, 20), ui::truncate(&no_version, 20));
        // Only the scope `@`: not a version marker.
        let scoped = format!("pkg:npm/@{}", "s".repeat(60));
        assert_eq!(elide_purl(&scoped, 20), ui::truncate(&scoped, 20));
        // A huge version leaves no room for the name: plain truncation.
        let big = format!("pkg:npm/foo@{}", "9".repeat(40));
        assert_eq!(elide_purl(&big, 30), ui::truncate(&big, 30));
    }

    #[test]
    fn elide_purl_multibyte_is_char_safe() {
        let purl = format!("pkg:npm/{}@1.0.0", "日".repeat(50));
        let out = elide_purl(&purl, 30);
        assert!(out.ends_with("@1.0.0"), "{out}");
        assert_eq!(out.chars().count(), 30);
    }

    // ---- summary lines -------------------------------------------------------

    #[test]
    fn updates_line_agrees_in_number() {
        assert_eq!(updates_line(1), "1 package has a newer patch available.");
        assert_eq!(updates_line(2), "2 packages have newer patches available.");
    }

    #[test]
    fn lockfile_only_note_agrees_in_number() {
        assert_eq!(
            lockfile_only_note(1),
            "Note: 1 package from project lockfiles is not yet installed (lockfile-only)."
        );
        assert_eq!(
            lockfile_only_note(3),
            "Note: 3 packages from project lockfiles are not yet installed (lockfile-only)."
        );
    }

    /// An agent-mode scan's `projects_not_scanned` detail names the
    /// directories it left and the command for the first (#2125).
    #[test]
    fn unscanned_agent_projects_detail_names_the_dirs_and_the_command() {
        let one = unscanned_agent_projects_detail(
            &["api".to_string()],
            "socket-patch scan --mode agent --cwd api",
        );
        assert!(
            one.starts_with("1 project directory below this one was not scanned (api): "),
            "{one}"
        );
        assert!(
            one.ends_with("e.g. `socket-patch scan --mode agent --cwd api`"),
            "{one}"
        );
        let two = unscanned_agent_projects_detail(
            &["api".to_string(), "web".to_string()],
            "socket-patch scan --mode agent --cwd api",
        );
        assert!(
            two.starts_with("2 project directories below this one were not scanned (api, web): "),
            "{two}"
        );
        let many: Vec<String> = (0..12).map(|n| format!("p{n:02}")).collect();
        let cut = unscanned_agent_projects_detail(&many, "socket-patch scan --cwd p00");
        assert!(
            cut.starts_with(
                "12 project directories below this one were not scanned (p00, p01, p02, p03, \
                 p04, p05, p06, p07, p08, p09, and 2 more): "
            ),
            "{cut}"
        );
    }

    #[test]
    fn no_packages_message_names_the_filter() {
        assert_eq!(
            no_packages_message(true, None, &[]),
            "No global packages found."
        );
        assert_eq!(
            no_packages_message(false, None, &["apps/**".to_string()]),
            "No installed packages found under the given path: apps/**."
        );
        assert_eq!(
            no_packages_message(false, None, &["a".to_string(), "b".to_string()]),
            "No installed packages found under the given paths: a, b."
        );
        let ecos = vec!["pypi".to_string(), "cargo".to_string()];
        assert_eq!(
            no_packages_message(false, Some(&ecos), &[]),
            "No pypi/cargo packages found."
        );
        // A lockfile that could not be read explains the empty result.
        assert_eq!(
            no_packages_unreadable(1),
            "No packages found (see the warning)."
        );
        assert_eq!(
            no_packages_unreadable(2),
            "No packages found (see the warnings)."
        );
        let generic = no_packages_message(false, Some(&[]), &[]);
        assert_eq!(
            generic,
            "No packages found. Run your package manager's install first."
        );
        assert_eq!(generic, no_packages_message(false, None, &[]));
    }

    // ---- dry-run / hints -------------------------------------------

    fn vendor(total: usize, refused: usize, in_sync: usize) -> Plan {
        Plan::Vendor {
            total,
            refused,
            in_sync,
            skipped: 0,
        }
    }

    /// #2075: an expected skip is not a refusal, and not work either.
    #[test]
    fn dry_run_line_counts_expected_skips() {
        let plan = |total, refused, skipped| Plan::Vendor {
            total,
            refused,
            in_sync: 0,
            skipped,
        };
        assert_eq!(
            dry_run_line(plan(1, 0, 1)),
            "[dry-run] Would download and vendor 0 of 1 patch (1 would be skipped). No changes made."
        );
        assert_eq!(
            dry_run_line(plan(4, 1, 2)),
            "[dry-run] Would download and vendor 1 of 4 patches (2 would be skipped, \
             1 would be refused). No changes made."
        );
    }

    #[test]
    fn dry_run_line_counts_refusals() {
        assert_eq!(
            dry_run_line(Plan::Apply {
                new: 1,
                recorded: 0
            }),
            "[dry-run] Would download and apply 1 patch. No changes made."
        );
        // The rows under the line also list a recorded patch the wet run
        // re-applies: the line says so, so the two counts add up.
        assert_eq!(
            dry_run_line(Plan::Apply {
                new: 5,
                recorded: 1
            }),
            "[dry-run] Would download and apply 5 patches and re-apply 1 already recorded. No \
             changes made."
        );
        assert_eq!(
            dry_run_line(vendor(2, 0, 0)),
            "[dry-run] Would download and vendor 2 patches. No changes made."
        );
        assert_eq!(
            dry_run_line(vendor(2, 2, 0)),
            "[dry-run] Would download and vendor 0 of 2 patches (2 would be refused). No changes made."
        );
        assert_eq!(
            dry_run_line(vendor(1, 1, 0)),
            "[dry-run] Would download and vendor 0 of 1 patch (1 would be refused). No changes made."
        );
    }

    #[test]
    fn dry_run_line_counts_already_vendored() {
        // #1850: an in-sync patch is not work the wet run would do.
        assert_eq!(
            dry_run_line(vendor(1, 0, 1)),
            "[dry-run] Would download and vendor 0 of 1 patch (1 already vendored). No changes made."
        );
        assert_eq!(
            dry_run_line(vendor(4, 1, 2)),
            "[dry-run] Would download and vendor 1 of 4 patches (2 already vendored, \
             1 would be refused). No changes made."
        );
    }

    #[test]
    fn user_patch_withheld_lines_separate_broken_files_from_declared_patches() {
        assert_eq!(
            user_patch_withheld_lines(0, 2),
            [
                "2 packages were not scanned: this project's own patches could not be checked \
              (see the warning). Fix the file it names and run again."
            ]
        );
        assert_eq!(
            user_patch_withheld_lines(3, 0),
            [
                "3 packages are protected by this project's own patches and were not scanned. \
              Pass --allow-patch-conflicts to scan them anyway."
            ]
        );
        let both = user_patch_withheld_lines(1, 1);
        assert_eq!(both.len(), 2);
        assert!(
            both[0].starts_with("1 package was not scanned: "),
            "{both:?}"
        );
        assert!(
            both[1].starts_with("1 package is protected by this project's own patches and was "),
            "{both:?}"
        );
        assert!(user_patch_withheld_lines(0, 0).is_empty());
    }

    fn protected(purl: &str, sources: &[&str], unreadable: bool) -> Protected {
        Protected {
            purl: purl.to_string(),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            unreadable,
        }
    }

    /// The reported flood: one long warning per package the project
    /// patches itself. They are one note now: the count, the files, the
    /// first few names, and the flag.
    #[test]
    fn project_patch_notice_is_one_block_not_a_warning_per_package() {
        let cwd = std::path::Path::new("/work/app");
        let lock = "/work/app/pnpm-lock.yaml";
        let workspace = "/work/app/pnpm-workspace.yaml";
        let few = [
            protected("pkg:npm/next-auth@4.24.15", &[lock, workspace], false),
            // A second installed copy of the same release is the same
            // package.
            protected("pkg:npm/next-auth@4.24.15", &[lock, workspace], false),
            protected("pkg:npm/%40rmp135/sql-ts@1.18.1", &[workspace], false),
        ];
        assert_eq!(
            project_patch_notice(&few, false, false, cwd),
            [
                "Note: skipped 2 packages covered by this project's own patches \
                 (pnpm-lock.yaml, pnpm-workspace.yaml): @rmp135/sql-ts@1.18.1, \
                 next-auth@4.24.15.",
                "  --allow-patch-conflicts patches them too.",
            ]
        );
        assert_eq!(
            project_patch_notice(&few[..1], false, false, cwd),
            [
                "Note: skipped 1 package covered by this project's own patches \
                 (pnpm-lock.yaml, pnpm-workspace.yaml): next-auth@4.24.15.",
                "  --allow-patch-conflicts patches it too.",
            ]
        );

        let many: Vec<Protected> = (0..33)
            .map(|i| protected(&format!("pkg:npm/dep-{i:02}@1.0.0"), &[workspace], false))
            .collect();
        assert_eq!(
            project_patch_notice(&many, false, false, cwd),
            [
                "Note: skipped 33 packages covered by this project's own patches \
                 (pnpm-workspace.yaml): dep-00@1.0.0, dep-01@1.0.0, dep-02@1.0.0 and 30 more.",
                "  --allow-patch-conflicts patches them too; --verbose lists them all.",
            ]
        );
        // `--verbose` lists every one, each with its own files.
        let verbose = project_patch_notice(&many, false, true, cwd);
        assert_eq!(verbose.len(), 2 + 33, "{verbose:#?}");
        assert_eq!(
            verbose[..3],
            [
                "Note: skipped 33 packages covered by this project's own patches \
                 (pnpm-workspace.yaml).",
                "  --allow-patch-conflicts patches them too.",
                "  dep-00@1.0.0",
            ]
        );
        // A package says which files cover it where they are not all of
        // the block's.
        let mut uneven = many;
        uneven[1].sources.push(lock.to_string());
        let verbose = project_patch_notice(&uneven, false, true, cwd);
        assert_eq!(
            verbose[2..5],
            [
                "  dep-00@1.0.0  (pnpm-workspace.yaml)",
                "  dep-01@1.0.0",
                "  dep-02@1.0.0  (pnpm-workspace.yaml)",
            ]
        );
        assert!(project_patch_notice(&[], false, false, cwd).is_empty());
    }

    /// A file that could not be read is a warning of its own, with the
    /// reason and the remedy, and it never offers the override. Under the
    /// override everything is one warning to review the result. Packages of
    /// two ecosystems are named by purl, and a file outside `--cwd` by its
    /// whole path.
    #[test]
    fn project_patch_notice_separates_unreadable_files_and_the_override() {
        let cwd = std::path::Path::new("/work/app");
        let broken = "/work/app/package.json (not valid JSON: expected value at line 1)";
        let mixed = [
            protected("pkg:npm/a@1.0.0", &[broken], true),
            protected("pkg:npm/b@2.0.0", &[broken], true),
            protected("pkg:cargo/serde@1.0.0", &["/work/Cargo.toml"], false),
            protected(
                "pkg:npm/c@3.0.0",
                &["/work/app/patches/c+3.0.0.patch"],
                false,
            ),
        ];
        assert_eq!(
            project_patch_notice(&mixed, false, false, cwd),
            [
                "Warning: 2 packages not patched, because this project's own patches could \
                 not be checked: package.json (not valid JSON: expected value at line 1). Fix \
                 that file and run again.",
                "Note: skipped 2 packages covered by this project's own patches \
                 (/work/Cargo.toml, patches/c+3.0.0.patch): pkg:cargo/serde@1.0.0, \
                 pkg:npm/c@3.0.0.",
                "  --allow-patch-conflicts patches them too.",
            ]
        );
        assert_eq!(
            project_patch_notice(&mixed[2..], true, false, cwd),
            [
                "Warning: --allow-patch-conflicts: 2 packages covered by this project's own \
                 patches (/work/Cargo.toml, patches/c+3.0.0.patch) may get a Socket patch too: \
                 pkg:cargo/serde@1.0.0, pkg:npm/c@3.0.0. Review and test the combined result.",
            ]
        );
    }

    #[test]
    fn report_only_hint_names_agent_mode() {
        let project = report_only_hint(&GlobalArgs::default());
        assert_eq!(
            project,
            [
                "To apply these patches in place, run:",
                "  socket-patch scan --mode agent [PATHS]",
                "  socket-patch get <package-name-or-purl-or-CVE-ID>",
            ]
        );
    }

    /// #464: the hint after a report-only global scan keeps the run's
    /// global scope, or running it verbatim patches the cwd project.
    #[test]
    fn report_only_hint_keeps_global_scope() {
        let global = GlobalArgs {
            global: true,
            ..GlobalArgs::default()
        };
        assert_eq!(
            report_only_hint(&global)[1..],
            [
                "  socket-patch scan --mode agent -g",
                "  socket-patch get -g <package-name-or-purl-or-CVE-ID>",
            ]
        );
        let mut rows = vec![
            (
                false,
                "/opt/node/lib/node_modules",
                "/opt/node/lib/node_modules",
            ),
            // `--global-prefix` alone selects the global tree; `-g` is not
            // repeated next to it.
            (
                true,
                "/opt/node/lib/node_modules",
                "/opt/node/lib/node_modules",
            ),
        ];
        if cfg!(windows) {
            rows.push((
                false,
                r"C:\Program Files\nodejs",
                r#""C:\Program Files\nodejs""#,
            ));
            rows.push((false, r"C:\nodejs\node_modules", r"C:\nodejs\node_modules"));
            rows.push((
                false,
                r"C:\Program Files\nodejs\",
                r#""C:\Program Files\nodejs\\""#,
            ));
        } else {
            rows.push((false, "/tmp/global lib", "'/tmp/global lib'"));
            rows.push((false, "/tmp/it's", r"'/tmp/it'\''s'"));
            rows.push((false, "/tmp/$HOME", "'/tmp/$HOME'"));
        }
        for (global, prefix, shown) in rows {
            let args = GlobalArgs {
                global,
                global_prefix: Some(prefix.into()),
                ..GlobalArgs::default()
            };
            assert_eq!(
                report_only_hint(&args)[1..],
                [
                    format!("  socket-patch scan --mode agent --global-prefix {shown}"),
                    format!(
                        "  socket-patch get --global-prefix {shown} <package-name-or-purl-or-CVE-ID>"
                    ),
                ],
                "prefix {prefix:?}"
            );
        }
    }

    #[test]
    fn skip_lines_use_documented_flag() {
        assert_eq!(
            vendored_skip_line("pkg:npm/x@1"),
            "  [skip] pkg:npm/x@1 (vendored; run `socket-patch scan --mode vendored` to update it)"
        );
        let l = not_installed_skip_line("pkg:npm/x@1");
        assert!(l.contains("`socket-patch scan --mode vendored`"), "{l}");
        assert!(!l.contains("--vendor`"), "{l}");
        assert_eq!(
            already_recorded_line("pkg:npm/x@1", "884e9f6d-aaaa", false),
            "  [skip] pkg:npm/x@1 (already recorded: 884e9f6d)"
        );
        assert_eq!(
            already_recorded_line("pkg:npm/x@1", "884e9f6d-aaaa", true),
            "  [re-apply] pkg:npm/x@1 (already recorded: 884e9f6d)"
        );
    }

    #[test]
    fn fetch_details_failed_names_cause() {
        assert_eq!(
            fetch_details_failed(&[]),
            "Error: could not fetch patch details."
        );
        assert_eq!(
            fetch_details_failed(&[("pkg:npm/a@1".into(), "404".into())]),
            "Error: could not fetch patch details for pkg:npm/a@1: 404"
        );
        assert_eq!(
            fetch_details_failed(&[
                ("pkg:npm/a@1".into(), "404".into()),
                ("pkg:npm/b@1".into(), "502".into())
            ]),
            "Error: could not fetch patch details for any of the 2 packages (last error: 502)"
        );
    }

    // ---- patch block ---------------------------------------------------------

    #[test]
    fn patch_block_exact_and_sorted() {
        let p = patch(
            &[
                ("GHSA-zzzz", vuln(&["CVE-2026-2"], "low one", "low")),
                ("GHSA-cccc", vuln(&[], "no-cve issue", "high")),
                (
                    "GHSA-aaaa",
                    vuln(&["CVE-2026-9", "CVE-2026-1"], "crit", "critical"),
                ),
                ("GHSA-bbbb", vuln(&["CVE-2026-5"], "", "high")),
            ],
            "Fixes things",
        );
        assert_eq!(
            patch_block(&block(&p, false)),
            vec![
                "  pkg:npm/@scope/nuxt@4.5.0 [FREE] HIGH",
                "    Fixes: CVE-2026-1, CVE-2026-9, CVE-2026-5, GHSA-cccc, CVE-2026-2",
                "    - CVE-2026-1, CVE-2026-9: crit",
                "    - GHSA-cccc: no-cve issue",
                "    - CVE-2026-2: low one",
                "    Fixes things",
                "",
            ]
        );
    }

    #[test]
    fn patch_block_is_deterministic_across_hash_orders() {
        // Build the same map many times: HashMap iteration order varies
        // per instance, the rendered block must not.
        let make = || {
            patch(
                &(0..12)
                    .map(|i| {
                        (
                            Box::leak(format!("GHSA-{i:02}").into_boxed_str()) as &str,
                            vuln(&[&format!("CVE-2026-{i:02}")], "s", "high"),
                        )
                    })
                    .collect::<Vec<_>>(),
                "",
            )
        };
        let first = patch_block(&block(&make(), false));
        for _ in 0..20 {
            assert_eq!(patch_block(&block(&make(), false)), first);
        }
    }

    #[test]
    fn patch_block_truncates_unless_verbose() {
        let long = "word ".repeat(40);
        let p = patch(&[("GHSA-a", vuln(&[], &long, "low"))], &long);
        let lines = patch_block(&block(&p, false));
        assert!(lines[2].ends_with("..."), "{lines:?}");
        assert!(lines[2].chars().count() <= "    - GHSA-a: ".len() + SUMMARY_MAX);
        assert!(lines[3].chars().count() <= 4 + DESCRIPTION_MAX);
        let lines = patch_block(&block(&p, true));
        assert!(!lines[2].ends_with("..."), "{lines:?}");
        assert_eq!(lines[3], format!("    {}", long.trim_end()));
    }

    #[test]
    fn patch_block_multibyte_summary_is_char_safe() {
        let p = patch(&[("GHSA-a", vuln(&[], &"漏".repeat(200), "low"))], "");
        let lines = patch_block(&block(&p, false));
        assert_eq!(
            lines[2].chars().count(),
            "    - GHSA-a: ".chars().count() + SUMMARY_MAX
        );
    }

    #[test]
    fn patch_block_marks_replacement() {
        let p = patch(&[("GHSA-a", vuln(&["CVE-1"], "", "high"))], "");
        let mut b = block(&p, false);
        b.replaces = Some(Replaces {
            uuid: "11111111-2222",
            vuln_ids: vec!["GHSA-a", "GHSA-b", "GHSA-c"],
        });
        assert_eq!(
            patch_block(&b),
            vec![
                "  pkg:npm/@scope/nuxt@4.5.0 [FREE] HIGH (replaces 11111111)",
                "    Fixes: CVE-1",
                "",
            ]
        );
    }

    #[test]
    fn replacement_warning_fires_whenever_a_recorded_vuln_is_dropped() {
        let p = patch(
            &[
                ("GHSA-a", vuln(&["CVE-1"], "", "high")),
                ("GHSA-x", vuln(&[], "", "low")),
            ],
            "",
        );
        let mut b = block(&p, false);
        assert_eq!(replacement_warning(&b), None);
        let with = |ids: Vec<&'static str>| Replaces {
            uuid: "11111111-2222",
            vuln_ids: ids,
        };
        // Fewer (subset).
        b.replaces = Some(with(vec!["GHSA-a", "GHSA-b", "GHSA-c"]));
        assert_eq!(
            replacement_warning(&b).as_deref(),
            Some("    Warning: this patch does not fix 2 of the 3 vulnerabilities the recorded patch fixes")
        );
        // Different ones (not a subset, same size).
        b.replaces = Some(with(vec!["GHSA-a", "GHSA-b"]));
        assert_eq!(
            replacement_warning(&b).as_deref(),
            Some("    Warning: this patch does not fix 1 of the 2 vulnerabilities the recorded patch fixes")
        );
        // Disjoint.
        b.replaces = Some(with(vec!["GHSA-z"]));
        assert_eq!(
            replacement_warning(&b).as_deref(),
            Some("    Warning: this patch does not fix the vulnerability the recorded patch fixes")
        );
        b.replaces = Some(with(vec!["GHSA-y", "GHSA-z"]));
        assert_eq!(
            replacement_warning(&b).as_deref(),
            Some("    Warning: this patch fixes none of the 2 vulnerabilities the recorded patch fixes")
        );
        // Superset or equal: no regression.
        b.replaces = Some(with(vec!["GHSA-a"]));
        assert_eq!(replacement_warning(&b), None);
    }

    #[test]
    fn highest_severity_picks_worst() {
        let p = patch(
            &[
                ("a", vuln(&[], "", "low")),
                ("b", vuln(&[], "", "critical")),
            ],
            "",
        );
        assert_eq!(highest_severity(&p), Some("critical"));
        assert_eq!(highest_severity(&patch(&[], "")), None);
    }
}
