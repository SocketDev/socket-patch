//! Pure text builders for `scan`'s human output: the results table, the
//! summary and prompt lines, the per-patch preview, and the hints. No I/O
//! and no terminal state (color is decided by the caller and passed in),
//! so every string is unit-testable byte for byte.

use std::collections::HashMap;

use socket_patch_core::api::types::{PatchSearchResult, VulnerabilityResponse};

use super::discovery::severity_order;
use crate::ui::{self, plural, Align};

/// Visible widths of the table's PATCHES and SEVERITY columns.
pub(super) const PATCHES_COL: usize = 8;
pub(super) const SEVERITY_COL: usize = 16;
/// The PACKAGE column grows to the longest PURL, up to this many columns;
/// longer PURLs are middle-elided (keeping `@version`).
pub(super) const MAX_PURL_COL: usize = 60;
/// Vulnerability ids shown per table row before `(+N)` (unless `--verbose`).
const VULN_IDS_SHOWN: usize = 2;
/// Per-patch preview limits for API free text (unless `--verbose`).
const SUMMARY_MAX: usize = 76;
const DESCRIPTION_MAX: usize = 72;

const HEADER_PACKAGE: &str = "PACKAGE";

/// Width of the PACKAGE column for these (display) PURLs: the longest,
/// never narrower than the header and never wider than [`MAX_PURL_COL`].
pub(super) fn purl_col_width<'a>(purls: impl IntoIterator<Item = &'a str>) -> usize {
    purls
        .into_iter()
        .map(|p| p.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(HEADER_PACKAGE.len(), MAX_PURL_COL)
}

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

/// The table's column header, aligned like [`table_row`].
pub(super) fn table_header(purl_w: usize) -> String {
    table_row(
        purl_w,
        HEADER_PACKAGE,
        "PATCHES",
        "SEVERITY",
        "VULNERABILITIES",
        "",
    )
}

/// One table row. Cells may carry color: padding counts visible
/// characters only, so colored and plain rows line up. `count` is
/// right-aligned; `markers` (`[UPDATE]`, ...) trail the vulnerabilities.
pub(super) fn table_row(
    purl_w: usize,
    purl: &str,
    count: &str,
    severity: &str,
    vulns: &str,
    markers: &str,
) -> String {
    format!(
        "{}  {}  {}  {vulns}{markers}",
        ui::pad(purl, purl_w, Align::Left),
        ui::pad(count, PATCHES_COL, Align::Right),
        ui::pad(severity, SEVERITY_COL, Align::Left),
    )
}

/// The `=` rule above and below the table: as wide as its widest line,
/// capped at `cap` columns (the terminal width) so it never wraps.
pub(super) fn ruler<'a>(lines: impl IntoIterator<Item = &'a str>, cap: Option<usize>) -> String {
    let widest = lines.into_iter().map(ui::visible_width).max().unwrap_or(0);
    let width = cap.map_or(widest, |c| widest.min(c)).max(1);
    "=".repeat(width)
}

/// The VULNERABILITIES cell: the first two ids plus `(+N)` for the rest of
/// `vulns.count`, every id under `--verbose`, `-` when there are none.
pub(super) fn vuln_cell(vulns: &super::discovery::VulnIds, verbose: bool) -> String {
    if verbose {
        return if vulns.all.is_empty() {
            "-".to_string()
        } else {
            vulns.all.join(", ")
        };
    }
    let shown = &vulns.primary[..vulns.primary.len().min(VULN_IDS_SHOWN)];
    let extra = vulns.count.saturating_sub(shown.len());
    match (shown.is_empty(), extra) {
        (true, 0) => "-".to_string(),
        (true, n) => format!("(+{n})"),
        (false, 0) => shown.join(", "),
        (false, n) => format!("{} (+{n})", shown.join(", ")),
    }
}

/// The line under the table: how many packages have patches and how many
/// of those patches this account can download.
pub(super) fn summary_line(packages: usize, patches: usize, all_accessible: bool) -> String {
    let kind = if all_accessible {
        ("available patch", "available patches")
    } else {
        ("free patch", "free patches")
    };
    format!(
        "Summary: {} with {}",
        plural(packages, "package", "packages"),
        plural(patches, kind.0, kind.1)
    )
}

/// The indented follow-up to [`summary_line`] for free accounts.
pub(super) fn paid_extra_line(paid: usize) -> String {
    let verb = if paid == 1 { "is" } else { "are" };
    format!(
        "         + {} {verb} available with a paid subscription",
        plural(paid, "additional patch", "additional patches")
    )
}

/// How many table rows carry `[UPDATE]`.
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

/// `the given path: a` / `the given paths: a, b`.
fn quoted_list(items: &[String], one: &str, many: &str) -> String {
    let label = if items.len() == 1 { one } else { many };
    format!("{label}: {}", items.join(", "))
}

/// Warning printed when `--prune` cannot run because nothing was crawled
/// (pruning every manifest entry is too destructive to do implicitly).
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

pub(super) const PRUNE_SKIPPED_EMPTY: &str = "Warning: --prune skipped: no installed packages \
     were found, and pruning every manifest entry is too destructive to do implicitly; run \
     `socket-patch repair` to clean up .socket/ explicitly.";

/// Note printed when the user declines the download prompt of a
/// `--prune` run: nothing is changed, the GC included.
pub(super) const PRUNE_SKIPPED_DECLINED: &str = "Note: --prune skipped (download declined).";

/// What the confirm prompt / dry-run line is about to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// Agent mode: download `n` patches and apply them in place.
    Apply(usize),
    /// Vendored mode: download `n` patches and vendor them.
    Vendor(usize),
}

/// The confirm prompt for `plan` (the `[Y/n]` hint is added by the prompt).
pub(super) fn confirm_prompt(plan: Plan) -> String {
    match plan {
        Plan::Apply(n) => format!("Download and apply {}?", plural(n, "patch", "patches")),
        Plan::Vendor(n) => format!("Download and vendor {}?", plural(n, "patch", "patches")),
    }
}

/// The hosted-mode confirm prompt (the `[Y/n]` hint is added by the prompt).
pub(super) fn hosted_confirm_prompt(n: usize) -> String {
    format!(
        "Redirect {} to the hosted patch server?",
        plural(n, "package", "packages")
    )
}

/// The `--dry-run` headline. `refused` counts the patches the vendored
/// preflight would refuse (listed right after as `[would-refuse]` lines),
/// so the headline never promises to vendor what the wet run refuses.
pub(super) fn dry_run_line(plan: Plan, refused: usize) -> String {
    let what = match plan {
        Plan::Apply(n) => format!("download and apply {}", plural(n, "patch", "patches")),
        Plan::Vendor(n) if refused > 0 => format!(
            "download and vendor {} of {} ({refused} would be refused)",
            n.saturating_sub(refused),
            plural(n, "patch", "patches")
        ),
        Plan::Vendor(n) => format!("download and vendor {}", plural(n, "patch", "patches")),
    };
    format!("[dry-run] Would {what}. No changes made.")
}

/// Lines printed after the user declines the prompt: how to pick patches
/// one at a time in the same mode.
pub(super) fn decline_hint(vendor: bool) -> [String; 3] {
    if vendor {
        [
            "To vendor a single patch, run:".to_string(),
            "  socket-patch get <package-name-or-purl> --mode vendored".to_string(),
            "  socket-patch get <CVE-ID> --mode vendored".to_string(),
        ]
    } else {
        [
            "To apply a single patch, run:".to_string(),
            "  socket-patch get <package-name-or-purl>".to_string(),
            "  socket-patch get <CVE-ID>".to_string(),
        ]
    }
}

/// Lines printed after the user declines the hosted-mode prompt: how to
/// redirect packages one at a time (`get` defaults to agent mode, so the
/// mode is named).
pub(super) fn hosted_decline_hint() -> [String; 3] {
    [
        "To redirect a package, run:".to_string(),
        "  socket-patch get <package-name-or-purl> --mode hosted".to_string(),
        "  socket-patch get <CVE-ID> --mode hosted".to_string(),
    ]
}

/// Printed (vendored mode, before the prompt) for a selected package whose
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

/// `[skip]` line for a selection the manifest already records.
pub(super) fn already_recorded_line(purl: &str, uuid: &str) -> String {
    format!(
        "  [skip] {purl} (already recorded: {})",
        super::super::get::short_uuid(uuid)
    )
}

/// Printed when every selection is already recorded (agent mode).
pub(super) const ALL_ALREADY_RECORDED: &str =
    "All selected patches are already recorded in the manifest; run `socket-patch apply` to re-apply them.";

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
        severity_order(&a.1.severity)
            .cmp(&severity_order(&b.1.severity))
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
        .min_by_key(|s| severity_order(s))
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
        .map(|r| format!(" (replaces {})", super::super::get::short_uuid(r.uuid)))
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
    fn purl_col_width_tracks_longest_within_bounds() {
        assert_eq!(purl_col_width([]), HEADER_PACKAGE.len());
        assert_eq!(purl_col_width(["a"]), HEADER_PACKAGE.len());
        assert_eq!(purl_col_width(["pkg:npm/minimist@1.2.5"]), 22);
        let long = "x".repeat(100);
        assert_eq!(purl_col_width([long.as_str()]), MAX_PURL_COL);
        // Chars, not bytes.
        assert_eq!(purl_col_width(["pkg:npm/日本語@1.0.0"]), 17);
    }

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

    #[test]
    fn table_colored_and_plain_rows_align_identically() {
        let w = 24;
        let vulns_at = w + 2 + PATCHES_COL + 2 + SEVERITY_COL + 2;
        let header = table_header(w);
        assert_eq!(header.find("VULNERABILITIES"), Some(vulns_at));
        assert_eq!(
            header.find("PATCHES").map(|i| i + "PATCHES".len()),
            Some(w + 2 + PATCHES_COL)
        );
        let row = |on: bool, sev: &str, paid: bool| {
            let count = if paid {
                format!("0+{}", ui::paint("2", "33", on))
            } else {
                "1".to_string()
            };
            table_row(
                w,
                "pkg:npm/minimist@1.2.5",
                &count,
                &ui::severity(sev, on),
                "CVE-2021-44906",
                &ui::paint(" [UPDATE]", "33", on),
            )
        };
        for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW", "unknown"] {
            for paid in [false, true] {
                let plain = row(false, sev, paid);
                assert_eq!(ui::strip_ansi(&row(true, sev, paid)), plain);
                assert_eq!(plain.find("CVE-"), Some(vulns_at), "{plain:?}");
                assert!(plain.ends_with("CVE-2021-44906 [UPDATE]"), "{plain:?}");
                let count_end = w + 2 + PATCHES_COL;
                let want = if paid { "0+2" } else { "1" };
                assert_eq!(&plain[count_end - want.len()..count_end], want);
            }
        }
    }

    #[test]
    fn table_row_exact_string() {
        assert_eq!(
            table_row(10, "pkg:a@1", "1", "HIGH", "CVE-1", " [UPDATE]"),
            "pkg:a@1            1  HIGH              CVE-1 [UPDATE]"
        );
    }

    #[test]
    fn ruler_fits_widest_line_and_cap() {
        assert_eq!(ruler(["abc", "abcdef"], None), "======");
        assert_eq!(ruler(["abc", "abcdef"], Some(4)), "====");
        assert_eq!(ruler(["\x1b[31mab\x1b[0m"], None), "==");
        assert_eq!(ruler([], None), "=");
    }

    fn vids(primary: &[&str], all: &[&str], count: usize) -> super::super::discovery::VulnIds {
        super::super::discovery::VulnIds {
            primary: primary.iter().map(|s| s.to_string()).collect(),
            all: all.iter().map(|s| s.to_string()).collect(),
            count,
        }
    }

    #[test]
    fn vuln_cell_caps_unless_verbose() {
        let four = ["CVE-1", "CVE-2", "CVE-3", "CVE-4"];
        assert_eq!(
            vuln_cell(&vids(&four, &four, 4), false),
            "CVE-1, CVE-2 (+2)"
        );
        assert_eq!(
            vuln_cell(&vids(&four, &four, 4), true),
            "CVE-1, CVE-2, CVE-3, CVE-4"
        );
        assert_eq!(
            vuln_cell(&vids(&four[..2], &four[..2], 2), false),
            "CVE-1, CVE-2"
        );
        assert_eq!(vuln_cell(&vids(&four[..1], &four[..1], 1), false), "CVE-1");
        assert_eq!(vuln_cell(&vids(&[], &[], 0), false), "-");
        assert_eq!(vuln_cell(&vids(&[], &[], 0), true), "-");
    }

    #[test]
    fn vuln_cell_counts_vulnerabilities_not_ids() {
        // 1 CVE + its alias + a GHSA-only advisory: two vulnerabilities.
        let v = vids(&["CVE-1"], &["CVE-1", "GHSA-a", "GHSA-b"], 2);
        assert_eq!(vuln_cell(&v, false), "CVE-1 (+1)");
        assert_eq!(vuln_cell(&v, true), "CVE-1, GHSA-a, GHSA-b");
        let v = vids(&["CVE-1", "CVE-2", "GHSA-c"], &[], 5);
        assert_eq!(vuln_cell(&v, false), "CVE-1, CVE-2 (+3)");
    }

    // ---- summary lines -------------------------------------------------------

    #[test]
    fn summary_line_singular_and_plural() {
        assert_eq!(
            summary_line(1, 1, true),
            "Summary: 1 package with 1 available patch"
        );
        assert_eq!(
            summary_line(2, 4, true),
            "Summary: 2 packages with 4 available patches"
        );
        assert_eq!(
            summary_line(1, 0, false),
            "Summary: 1 package with 0 free patches"
        );
        assert_eq!(
            summary_line(3, 1, false),
            "Summary: 3 packages with 1 free patch"
        );
    }

    #[test]
    fn paid_extra_line_agrees_in_number() {
        assert_eq!(
            paid_extra_line(1),
            "         + 1 additional patch is available with a paid subscription"
        );
        assert_eq!(
            paid_extra_line(3),
            "         + 3 additional patches are available with a paid subscription"
        );
    }

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
        let generic = no_packages_message(false, Some(&[]), &[]);
        assert_eq!(
            generic,
            "No packages found. Run your package manager's install first."
        );
        assert_eq!(generic, no_packages_message(false, None, &[]));
    }

    // ---- prompt / dry-run / hints -------------------------------------------

    #[test]
    fn confirm_prompt_counts_patches() {
        assert_eq!(
            confirm_prompt(Plan::Apply(1)),
            "Download and apply 1 patch?"
        );
        assert_eq!(
            confirm_prompt(Plan::Apply(3)),
            "Download and apply 3 patches?"
        );
        assert_eq!(
            confirm_prompt(Plan::Vendor(2)),
            "Download and vendor 2 patches?"
        );
        assert_eq!(
            hosted_confirm_prompt(1),
            "Redirect 1 package to the hosted patch server?"
        );
        assert_eq!(
            hosted_confirm_prompt(2),
            "Redirect 2 packages to the hosted patch server?"
        );
    }

    #[test]
    fn dry_run_line_counts_refusals() {
        assert_eq!(
            dry_run_line(Plan::Apply(1), 0),
            "[dry-run] Would download and apply 1 patch. No changes made."
        );
        assert_eq!(
            dry_run_line(Plan::Vendor(2), 0),
            "[dry-run] Would download and vendor 2 patches. No changes made."
        );
        assert_eq!(
            dry_run_line(Plan::Vendor(2), 2),
            "[dry-run] Would download and vendor 0 of 2 patches (2 would be refused). No changes made."
        );
        assert_eq!(
            dry_run_line(Plan::Vendor(1), 1),
            "[dry-run] Would download and vendor 0 of 1 patch (1 would be refused). No changes made."
        );
    }

    #[test]
    fn decline_hint_matches_mode() {
        assert_eq!(decline_hint(false)[0], "To apply a single patch, run:");
        assert!(decline_hint(false).iter().all(|l| !l.contains("--mode")));
        assert_eq!(decline_hint(true)[0], "To vendor a single patch, run:");
        assert!(decline_hint(true)[1..]
            .iter()
            .all(|l| l.ends_with(" --mode vendored")));
        assert_eq!(hosted_decline_hint()[0], "To redirect a package, run:");
        assert!(hosted_decline_hint()[1..]
            .iter()
            .all(|l| l.ends_with(" --mode hosted")));
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
            already_recorded_line("pkg:npm/x@1", "884e9f6d-aaaa"),
            "  [skip] pkg:npm/x@1 (already recorded: 884e9f6d)"
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
