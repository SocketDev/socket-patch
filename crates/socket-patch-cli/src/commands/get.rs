use clap::Args;
use futures_util::StreamExt;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, hold_back_debug,
    is_fallback_candidate, ApiClient, ApiError,
};
use socket_patch_core::api::ranking::cmp_search_results;
use socket_patch_core::api::types::{
    PatchResponse, PatchSearchResult, SearchResponse, VulnerabilityResponse,
};
use socket_patch_core::crawlers::fuzzy_match::fuzzy_match_packages;
use socket_patch_core::formats::pnpm::PnpmLock;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::records::{build_patch_record, files_for_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{track_patch_fetch_failed, track_patch_fetched, TelemetryAuth};
use socket_patch_core::utils::concurrent::{api_concurrency_for, ordered_concurrent};
use socket_patch_core::utils::purl::{canonical_purl, normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::utils::target::{Target, TargetKind};
use socket_patch_core::vendor::load_state;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
// The agent download engine's public entry points keep their
// `commands::get` paths (the in-process tests and embedders call them);
// the engine itself lives in the shared `agent_download` helper.
use crate::commands::agent_download::{
    apply_warning_lines, decide_patch_action, download_patch_records_preflighted,
    download_patch_records_reusing, filter_to_installed_releases, fold_apply_failures,
    max_vuln_severity, merge_metadata, nested_apply_args, patch_event_metadata, report_error,
    report_lock_failure, run_nested_apply, run_outcome, unwind_new_blobs,
    warn_on_vendored_uuid_drift, write_all_patch_blobs, DetachedDownload, PatchAction,
    VendorRefusals,
};
pub use crate::commands::agent_download::{
    download_and_apply_patches_with, DownloadParams, DownloadRun,
};
use crate::commands::apply::ApplyRunReport;
use crate::commands::bun_preflight::{bun_vendor_preflight, BunVendorRefusal};
use crate::commands::vlt_preflight::{
    vlt_refusal_for, vlt_vendor_preflight_selected, VltVendorRefusal,
};
use crate::ecosystem_dispatch::{crawl_ecosystems, find_packages_for_rollback, partition_purls};
use crate::json_envelope::{usage_error, Command as JsonCommand};
use crate::ui::{print_json, select_one, SelectError};

/// Best-effort ecosystem extractor for a `pkg:<eco>/...` PURL. Used as
/// the telemetry `ecosystem` field. Returns an empty string when the
/// PURL is malformed — telemetry events should never block on input
/// validation.
fn ecosystem_from_purl(purl: &str) -> String {
    purl.strip_prefix("pkg:")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
        .to_string()
}

/// Build a no-results JSON envelope with the given status code. Used in
/// the `no_packages`, `no_match`, and `not_found` branches of `get`,
/// which all share the same `{status, counts, patches: []}` shape.
fn empty_result_json(status: &str) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "found": 0,
        "downloaded": 0,
        "applied": 0,
        "patches": [],
    })
}

/// Fire a `patch_fetch_failed` telemetry event and surface the error to
/// the caller (JSON envelope or stderr). Returns `1` so callers can
/// just `return report_fetch_failure(...).await;`.
async fn report_fetch_failure(
    identifier: &str,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    telemetry: &TelemetryAuth,
    json: bool,
) -> i32 {
    let msg = error.to_string();
    track_patch_fetch_failed(identifier, &msg, fallback_to_proxy, telemetry).await;
    report_error(json, "patch_fetch_failed", msg);
    1
}

#[derive(Args)]
pub struct GetArgs {
    /// Patch identifier (UUID, CVE ID, GHSA ID, PURL, or package name).
    pub identifier: String,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Force identifier to be treated as a patch UUID.
    #[arg(long, default_value_t = false)]
    pub id: bool,

    /// Force identifier to be treated as a CVE ID.
    #[arg(long, default_value_t = false)]
    pub cve: bool,

    /// Force identifier to be treated as a GHSA ID.
    #[arg(long, default_value_t = false)]
    pub ghsa: bool,

    /// Force identifier to be treated as a package name.
    #[arg(short = 'p', long = "package", default_value_t = false)]
    pub package: bool,

    /// Download the patch and record it in the manifest without applying it.
    // `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    // clap's default bool parser accepts only the literal strings
    // `true`/`false` from the env binding, so `SOCKET_SAVE_ONLY=1` (or an
    // exported-but-empty `SOCKET_SAVE_ONLY=`) would abort every `get`.
    #[arg(
        long = "save-only",
        env = "SOCKET_SAVE_ONLY",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub save_only: bool,

    /// Download patches for every release variant of a matched package,
    /// not just the one matching the locally-installed distribution.
    ///
    /// Affects ecosystems with per-release variants: PyPI (wheel/sdist),
    /// RubyGems (platform) and Maven (classifier). Also turns off the
    /// installed-version filter for CVE/GHSA searches, so every version's
    /// patch is fetched, installed or not.
    // Variant keys: PyPI `artifact_id`, RubyGems `platform`, Maven
    // `classifier`. Off by default: only the patch(es) for the installed
    // dist are fetched.
    #[arg(
        long = "all-releases",
        env = "SOCKET_ALL_RELEASES",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub all_releases: bool,

    /// How to consume the patches: the same modes as `scan --mode`
    /// [default: the mode the project's patch state already records, else
    /// hosted; agent with `--save-only` or `--global`]
    // agent = record in .socket/manifest.json + blobs and apply in place;
    // hosted = rewrite lockfiles so the patched deps resolve to Socket's
    // hosted patch server (no manifest, no blobs, no ledger: the lockfile
    // is the record); vendored = commit patched artifacts under
    // .socket/vendor/ and rewire the lockfile (no manifest, no blobs; the
    // vendor ledger carries the records). Hosted/vendored runs produce the
    // same on-disk result as `scan --mode hosted|vendored` selecting the
    // same patch. The per-value help comes from `ScanMode`'s variant docs.
    // No env binding, matching `scan --mode`.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<super::scan::ScanMode>,
}

/// Advisory labels for a patch: every advisory's CVE ids, or the advisory
/// id itself when it has no CVE assigned yet (a fresh GHSA). Sorted and
/// deduplicated, so the text never depends on `HashMap` iteration order.
fn vuln_labels(vulns: &HashMap<String, VulnerabilityResponse>) -> Vec<String> {
    let mut labels: Vec<String> = vulns
        .iter()
        .flat_map(|(id, v)| {
            if v.cves.is_empty() {
                vec![id.clone()]
            } else {
                v.cves.clone()
            }
        })
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// Render one patch as an interactive-selection option line:
/// `<uuid> [<TIER>] (fixes: <ids>) - <description>`.
///
/// The `(fixes: …)` segment is omitted for a patch with no
/// vulnerabilities, and ` - <description>` for an empty description (no
/// dangling dash). The tier is upper-cased to match the search listing.
/// The description is truncated to 60 characters.
fn format_patch_option(p: &PatchSearchResult) -> String {
    let labels = vuln_labels(&p.vulnerabilities);
    let vulns = if labels.is_empty() {
        String::new()
    } else {
        format!(" (fixes: {})", labels.join(", "))
    };
    let desc = crate::ui::truncate(&p.description, 60);
    let desc = if desc.is_empty() {
        String::new()
    } else {
        format!(" - {desc}")
    };
    format!("{} [{}]{vulns}{desc}", p.uuid, p.tier.to_uppercase())
}

/// One-line human summary of a patch:
/// `<purl> [<TIER>] <short uuid>: fixes <id> (<SEVERITY>)`, or with
/// several advisories `fixes <ids> (highest: <SEVERITY>)` — a bare
/// `(HIGH)` after a list reads as the last id's severity.
///
/// `patch_id` is omitted (with its colon) when `None`, the `fixes` part
/// when the patch has no advisories, and the severity when none is known.
/// The severity is colored when `color` is on. The purl is shown decoded
/// (`%40scope` → `@scope`).
fn format_patch_summary(
    purl: &str,
    tier: &str,
    patch_id: Option<&str>,
    vulns: &HashMap<String, VulnerabilityResponse>,
    color: bool,
) -> String {
    let mut line = format!("{} [{}]", normalize_purl(purl), tier.to_uppercase());
    if let Some(id) = patch_id {
        line.push(' ');
        line.push_str(crate::ui::short_uuid(id));
    }
    let labels = vuln_labels(vulns);
    if !labels.is_empty() {
        let sep = if patch_id.is_some() { ": " } else { " " };
        line.push_str(&format!("{sep}fixes {}", labels.join(", ")));
        if let Some(sev) = max_vuln_severity(vulns) {
            let sev = crate::ui::severity(&sev.to_uppercase(), color);
            if labels.len() > 1 {
                line.push_str(&format!(" (highest: {sev})"));
            } else {
                line.push_str(&format!(" ({sev})"));
            }
        }
    }
    line
}

/// Compare two strings the way a person sorts versions: runs of ASCII
/// digits compare as numbers (`4.17.2` < `4.17.10`), everything else
/// character by character. Ties on numeric value (`01` vs `1`) fall back
/// to plain string order so the result is a total order.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut x, mut y) = (a.as_bytes(), b.as_bytes());
    loop {
        match (x.first(), y.first()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let xl = x.iter().take_while(|c| c.is_ascii_digit()).count();
                let yl = y.iter().take_while(|c| c.is_ascii_digit()).count();
                let trim = |s: &[u8]| -> usize { s.iter().take_while(|&&c| c == b'0').count() };
                let (xn, yn) = (&x[trim(&x[..xl])..xl], &y[trim(&y[..yl])..yl]);
                let ord = xn.len().cmp(&yn.len()).then_with(|| xn.cmp(yn));
                if ord != Ordering::Equal {
                    return ord;
                }
                x = &x[xl..];
                y = &y[yl..];
            }
            (Some(c), Some(d)) => {
                if c != d {
                    return c.cmp(d);
                }
                x = &x[1..];
                y = &y[1..];
            }
        }
    }
}

/// The search listing printed before selection: grouped by PURL (in
/// natural version order) and best-first within each PURL — the same
/// order [`select_patches`] resolves in, so a package's first entry is the
/// one that will be applied. A `by-cve` / `by-ghsa` search can span
/// several packages, hence the grouping. Severities are colored when
/// `color` is on. Ends with a blank line.
fn format_search_results(
    patches: &[&PatchSearchResult],
    can_access_paid: bool,
    color: bool,
) -> String {
    let mut patches: Vec<&PatchSearchResult> = patches.to_vec();
    patches.sort_by(|a, b| natural_cmp(&a.purl, &b.purl).then_with(|| cmp_search_results(a, b)));

    let mut out = format!(
        "Found {}:\n\n",
        crate::ui::plural(patches.len(), "patch", "patches")
    );
    for (i, patch) in patches.iter().enumerate() {
        let tier_label = if patch.tier == "paid" {
            " [PAID]"
        } else {
            " [FREE]"
        };
        let access_label = if patch.tier == "paid" && !can_access_paid {
            " (no access)"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {}. {}{tier_label}{access_label}\n",
            i + 1,
            normalize_purl(&patch.purl)
        ));
        out.push_str(&format!("     UUID: {}\n", patch.uuid));
        let desc = crate::ui::truncate(&patch.description, 80);
        if !desc.is_empty() {
            out.push_str(&format!("     Description: {desc}\n"));
        }
        let mut fixes: Vec<(String, String)> = patch
            .vulnerabilities
            .iter()
            .map(|(id, vuln)| {
                let ids = if vuln.cves.is_empty() {
                    id.to_string()
                } else {
                    let mut cves = vuln.cves.clone();
                    cves.sort();
                    cves.join(", ")
                };
                (ids, vuln.severity.clone())
            })
            .collect();
        fixes.sort();
        if !fixes.is_empty() {
            let fixes: Vec<String> = fixes
                .iter()
                .map(|(ids, sev)| {
                    if sev.is_empty() {
                        ids.clone()
                    } else {
                        format!("{ids} ({})", crate::ui::severity(sev, color))
                    }
                })
                .collect();
            out.push_str(&format!("     Fixes: {}\n", fixes.join(", ")));
        }
        out.push('\n');
    }
    out
}

/// The stderr line naming the installed packages a package-name search
/// matched (every one of them is searched).
fn format_matched_packages(purls: &[String]) -> String {
    let names: Vec<String> = purls
        .iter()
        .map(|p| normalize_purl(p).into_owned())
        .collect();
    match names.as_slice() {
        [one] => format!("Matched: {one}"),
        many => format!(
            "Matched {} installed packages: {}",
            many.len(),
            many.join(", ")
        ),
    }
}

/// Every installed purl a package-name `target` selects, deduplicated and
/// sorted (a monorepo can hold the same release in several places).
fn installed_target_matches(
    target: &Target,
    packages: &[socket_patch_core::crawlers::CrawledPackage],
) -> Vec<String> {
    let mut purls: Vec<String> = packages
        .iter()
        .filter(|pkg| target.matches_package(&pkg.purl))
        .map(|pkg| pkg.purl.clone())
        .collect();
    purls.sort();
    purls.dedup();
    purls
}

/// "Did you mean" for a name that matched nothing exactly: up to five
/// installed names the fuzzy ranker puts closest. A suggestion only — a
/// near name is never searched or patched.
fn format_did_you_mean(
    query: &str,
    packages: &[socket_patch_core::crawlers::CrawledPackage],
) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    for pkg in fuzzy_match_packages(query, packages, usize::MAX) {
        let name = match &pkg.namespace {
            Some(ns) => format!("{ns}/{}", pkg.name),
            None => pkg.name.clone(),
        };
        if !names.contains(&name) {
            names.push(name);
        }
        if names.len() == 5 {
            break;
        }
    }
    (!names.is_empty()).then(|| format!("Did you mean: {}?", names.join(", ")))
}

/// The `--verbose` per-version detail behind [`format_skip_summary`]: one
/// `[skip]` line per purl (a free and a paid patch for the same version
/// would otherwise repeat it), in natural version order.
fn format_verbose_skips(skips: &[serde_json::Value]) -> Vec<String> {
    let mut by_purl: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for rec in skips {
        let purl = rec["purl"].as_str().unwrap_or_default();
        let reason = match rec["errorCode"].as_str() {
            Some("package_not_installed") | None => "version not installed",
            Some(code) => code,
        };
        by_purl.entry(purl).or_insert(reason);
    }
    let mut rows: Vec<(String, &str)> = by_purl
        .into_iter()
        .map(|(purl, reason)| (normalize_purl(purl).into_owned(), reason))
        .collect();
    rows.sort_by(|a, b| natural_cmp(&a.0, &b.0));
    rows.into_iter()
        .map(|(purl, reason)| format!("  [skip] {purl} ({reason})"))
        .collect()
}

/// Whether [`select_patches`] has a choice to make that nobody made in
/// advance: a free user, several accessible patches for one purl, and no
/// `--yes`/`--json`. It then shows a menu (interactive stdin) or prints
/// the non-interactive note (unless `--silent`).
pub(crate) fn selection_has_choice(
    candidates: &[PatchSearchResult],
    can_access_paid: bool,
    common: &GlobalArgs,
) -> bool {
    if can_access_paid || common.yes || common.json {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    candidates
        .iter()
        .filter(|p| p.tier == "free")
        .any(|p| !seen.insert(p.purl.as_str()))
}

/// Whether [`select_patches`] will put a menu in front of the user for
/// these candidates: [`selection_has_choice`] and an interactive stdin
/// (mirrors `select_one`).
fn selection_prompted(
    candidates: &[PatchSearchResult],
    can_access_paid: bool,
    common: &GlobalArgs,
) -> bool {
    use std::io::IsTerminal;
    selection_has_choice(candidates, can_access_paid, common) && std::io::stdin().is_terminal()
}

/// The "which patch will be installed" block printed before the prompt
/// when the listing above showed more patches than were selected (a paid
/// user's auto-pick, or narrowing): one [`format_patch_summary`] line per
/// selected patch. Ends with a blank line.
fn format_selected_patches(selected: &[PatchSearchResult], color: bool) -> String {
    let mut out = String::from("Selected:\n");
    for p in selected {
        out.push_str(&format!(
            "  {}\n",
            format_patch_summary(&p.purl, &p.tier, Some(&p.uuid), &p.vulnerabilities, color)
        ));
    }
    out.push('\n');
    out
}

/// Number of distinct purls among skip records.
fn distinct_skip_purls(skips: &[serde_json::Value]) -> usize {
    let purls: std::collections::BTreeSet<&str> = skips
        .iter()
        .map(|r| r["purl"].as_str().unwrap_or_default())
        .collect();
    purls.len()
}

/// Summary lines for the patches the installed-version narrowing dropped,
/// one line per reason (instead of one `[skip]` line per version), in a
/// fixed order: not installed first, then each layout code alphabetically.
fn format_skip_summary(skips: &[serde_json::Value]) -> Vec<String> {
    let mut by_code: std::collections::BTreeMap<&str, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    for rec in skips {
        let code = rec["errorCode"].as_str().unwrap_or("package_not_installed");
        by_code.entry(code).or_default().push(rec.clone());
    }
    let mut lines = Vec::new();
    if let Some(recs) = by_code.remove("package_not_installed") {
        let n = recs.len();
        let versions = distinct_skip_purls(&recs);
        lines.push(format!(
            "Skipped {} for {} not installed here (use --all-releases to include {}).",
            crate::ui::plural(n, "patch", "patches"),
            crate::ui::plural(versions, "package version", "package versions"),
            if n == 1 { "it" } else { "them" },
        ));
    }
    for (code, recs) in by_code {
        lines.push(format!(
            "Skipped {} for {} ({code}; see the warning above).",
            crate::ui::plural(recs.len(), "patch", "patches"),
            crate::ui::plural(
                distinct_skip_purls(&recs),
                "package version",
                "package versions"
            ),
        ));
    }
    lines
}

/// The result line when the installed-version narrowing dropped EVERY
/// accessible patch.
fn format_all_narrowed(skips: &[serde_json::Value]) -> String {
    // When every skip is a PnP layout refusal, "not installed" and the
    // --all-releases advice would both be wrong: the packages were never
    // judged (structurally invisible), and the escape hatch cannot make a
    // PnP layout patchable — point at the layout warning instead.
    let pnp_only = skips.iter().all(|rec| {
        matches!(
            rec["errorCode"].as_str(),
            Some("yarn_pnp_unsupported" | "pnpm_pnp_unsupported")
        )
    });
    if pnp_only {
        return format!(
            "Found {}, but this project's Plug'n'Play layout makes its npm packages \
             unpatchable here; see the layout warning above for the remedy.",
            crate::ui::plural(skips.len(), "patch", "patches")
        );
    }
    match distinct_skip_purls(skips) {
        1 => "Patches exist for 1 package version, but it is not installed here. \
              Use --all-releases to fetch it anyway."
            .to_string(),
        n => format!(
            "Patches exist for {n} package versions, but none of them are installed here. \
             Use --all-releases to fetch them anyway."
        ),
    }
}

/// The agent-mode confirmation question for `n` selected patches (hosted
/// and vendored `get` never prompt).
fn format_confirm_prompt(save_only: bool, n: usize) -> String {
    let patches = crate::ui::plural(n, "patch", "patches");
    if save_only {
        format!("Download {patches}?")
    } else {
        format!("Download and apply {patches}?")
    }
}

/// The `--dry-run` result line: `[dry-run] Would <action> N patches. No
/// changes made.`
fn format_dry_run(action: &str, n: usize) -> String {
    format!(
        "[dry-run] Would {action} {}. No changes made.",
        crate::ui::plural(n, "patch", "patches")
    )
}

/// What a package-name search says when the crawl found nothing: scan's
/// empty-crawl line (get has no ecosystem or path filter to name).
fn no_packages_message(global: bool) -> String {
    crate::commands::scan::render::no_packages_message(global, None, &[])
}

/// The human result for a patch the caller's plan cannot download.
/// `patch` names it (a purl, or the uuid when the purl is unknown).
fn format_paid_required(patch: &str) -> String {
    format!(
        "This patch requires a paid Socket plan.\n  Patch: {patch}\n{}",
        crate::ui::PAID_UPGRADE
    )
}

/// The summary after a single-uuid save. `what` is `"Patch"` or `"Patch
/// record"`. `ends_run` says an unchanged record really ends the run (the
/// agent path under `--save-only`); the agent path still re-applies an
/// unchanged record and the vendored path still runs its vendor step, so
/// neither may promise "nothing to update".
fn format_single_save(
    what: &str,
    action: &PatchAction,
    manifest_path: &Path,
    purl: &str,
    ends_run: bool,
) -> String {
    match action {
        PatchAction::Added => format!("{what} saved to {}\n  Added: 1", manifest_path.display()),
        PatchAction::Updated { old_uuid } => format!(
            "{what} saved to {}\n  Updated: 1 (replacing {})",
            manifest_path.display(),
            crate::ui::short_uuid(old_uuid)
        ),
        PatchAction::Skipped => format!(
            "{} already has this patch recorded in {}{}",
            normalize_purl(purl),
            manifest_path.display(),
            if ends_run {
                "; nothing to update."
            } else {
                "."
            }
        ),
    }
}

/// Local shape check for an identifier forced with `--id` / `--cve` /
/// `--ghsa`, so a typo fails fast with a readable message instead of a raw
/// API 400 body. `None` when it is well-formed (or the type is not
/// shape-checked).
///
/// The message never echoes the argument: it reaches stderr, and CodeQL
/// treats anything that may be a patch uuid as sensitive
/// (rust/cleartext-logging). The user typed it, so naming the expected
/// form is enough.
fn forced_identifier_error(target: &Target) -> Option<String> {
    if target.shape_ok() {
        return None;
    }
    let (what, form) = match target.kind() {
        TargetKind::Uuid => ("patch UUID", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),
        TargetKind::Cve => ("CVE ID", "CVE-YYYY-NNNN"),
        TargetKind::Ghsa => ("GHSA ID", "GHSA-xxxx-xxxx-xxxx"),
        TargetKind::Purl | TargetKind::Name => return None,
    };
    Some(format!(
        "The identifier is not a valid {what} (expected {form})"
    ))
}

/// Select one patch per PURL from available patches.
///
/// Within a PURL, candidates are ranked by [`cmp_search_results`]: severity
/// first (critical → low), then most advisories fixed, then most recently
/// published. `tier` is an access filter here, not a ranking signal — a
/// free critical patch outranks a paid low one.
///
/// - Users with paid access: auto-select the top-ranked patch per PURL.
/// - Free users with one patch, or with `--yes`: auto-select the
///   top-ranked one.
/// - Free users with multiple patches: interactive selection via dialoguer,
///   with the options presented in ranked order so the best patch is both
///   the highlighted default and what a non-TTY run auto-picks.
/// - JSON mode with multiple free patches: returns an error with options list.
///
/// The returned vec is sorted by PURL. It is assembled from a `HashMap`,
/// whose iteration order is randomized per process; without the sort the
/// download order — and every `--json` array derived from it — would differ
/// run to run.
///
/// Returns `Ok(selected_patches)` or `Err(exit_code)` if selection fails.
pub(crate) fn select_patches(
    patches: &[PatchSearchResult],
    can_access_paid: bool,
    common: &GlobalArgs,
) -> Result<Vec<PatchSearchResult>, i32> {
    let mut by_purl: HashMap<String, Vec<&PatchSearchResult>> = HashMap::new();
    for p in patches {
        if p.tier == "free" || can_access_paid {
            by_purl.entry(p.purl.clone()).or_default().push(p);
        }
    }

    let mut selected = Vec::new();

    // Iterate PURLs in a fixed order too: the interactive prompts below are
    // presented to a human one after another, and a randomized sequence
    // would be disorienting across otherwise identical runs.
    let mut groups: Vec<(String, Vec<&PatchSearchResult>)> = by_purl.into_iter().collect();
    groups.sort_by(|a, b| a.0.cmp(&b.0));

    for (purl, mut group) in groups {
        // Canonical best-first order (see `api::ranking`). The API client
        // already sorts each response, but this call site merges results
        // across several queries, so re-sort the assembled group.
        group.sort_by(|a, b| cmp_search_results(a, b));

        if can_access_paid {
            // Take the top-ranked patch. Note this is NOT "prefer paid":
            // tier only breaks ties once the severity/coverage/recency ranking
            // (see `api::ranking`) has tied.
            selected.push(group[0].clone());
        } else if group.len() == 1 || (common.yes && !common.json) {
            // One candidate, or `--yes` (which answers every prompt with its
            // default — the menu's default is the top-ranked patch). JSON
            // mode keeps its `selection_required` contract below.
            selected.push(group[0].clone());
        } else {
            // Free user with multiple patches: interactive selection
            let options: Vec<String> = group.iter().map(|p| format_patch_option(p)).collect();

            match select_one(
                &format!("Multiple patches available for {purl}. Select one:"),
                &options,
                common,
            ) {
                Ok(idx) => {
                    selected.push(group[idx].clone());
                }
                Err(SelectError::JsonModeNeedsExplicit) => {
                    let options_json: Vec<serde_json::Value> = group
                        .iter()
                        .map(|p| {
                            let vulns: Vec<serde_json::Value> = p
                                .vulnerabilities
                                .iter()
                                .map(|(id, v)| {
                                    serde_json::json!({
                                        "id": id,
                                        "cves": v.cves,
                                        "severity": v.severity,
                                        "summary": v.summary,
                                    })
                                })
                                .collect();
                            serde_json::json!({
                                "uuid": p.uuid,
                                "tier": p.tier,
                                "published_at": p.published_at,
                                "description": p.description,
                                "vulnerabilities": vulns,
                            })
                        })
                        .collect();
                    print_json(&serde_json::json!({
                        "status": "selection_required",
                        "error": {
                            "code": "selection_required",
                            "message": format!("Multiple patches available for {purl}. Re-run with the chosen UUID as the identifier (`socket-patch get <uuid>`) to select one."),
                        },
                        "purl": purl,
                        "options": options_json,
                    }));
                    return Err(1);
                }
                Err(SelectError::Cancelled) => {
                    eprintln!("{}", crate::ui::CANCELLED);
                    return Err(0);
                }
            }
        }
    }

    // PURL-sorted by construction: `groups` was sorted above and this loop
    // pushes at most one entry per group.
    Ok(selected)
}

/// Outcome of the coarse installed-VERSION narrowing over a CVE/GHSA/PURL
/// search fan-out (see [`filter_to_installed_purls`]).
struct InstalledNarrowing {
    /// Results whose package version is present (kept for selection).
    kept: Vec<PatchSearchResult>,
    /// Contract-shaped skip records for the filtered-out results
    /// (`action: "skipped"` + `errorCode`), purl-sorted.
    skip_records: Vec<serde_json::Value>,
    /// Run-level `(code, detail)` warnings (PnP layout refusals), for both
    /// stderr and the JSON `warnings[]`.
    warnings: Vec<(String, String)>,
}

/// Narrow a search fan-out to the package VERSIONS actually present, so a
/// GHSA with patches for dozens of versions acts only on what this system
/// runs — the coarse layer above [`filter_to_installed_releases`]'s
/// per-release variant narrowing (which still runs later, unchanged).
///
/// Presence evidence per result purl (compared by [`PurlKey`] — API purls
/// are percent-encoded/qualified/mixed-case, crawler purls literal):
/// * installed on disk — `find_packages_for_rollback` over the deduped base
///   purls (the qualified-aware resolver; memory invariant);
/// * already tracked in the manifest — the user opted this purl in earlier,
///   and updating its record must keep working on hosts without an
///   installed copy (CI manifest-maintenance);
/// * hosted/vendored modes only: resolved in the project lockfile(s)
///   (hosted rewrites the lock; vendored auto-fetches pristine) or claimed
///   by the vendor ledger (fresh-clone re-vendor) — scan's own
///   lockfile/vendored-ledger discovery supplements (a corrupt vendor
///   ledger falls back to the committed artifacts, as in scan), including
///   their global-scan gate.
///
/// PnP layouts are surfaced, never silently misreported: yarn PnP packages
/// are structurally unpatchable in every mode (skip records carry
/// `yarn_pnp_unsupported`, not a false "not installed"). pnpm PnP skips
/// carry `pnpm_pnp_unsupported` in agent/vendored modes; hosted mode — the
/// refusal's own remedy — keeps the versions the raw pnpm-lock.yaml text
/// resolves ([`PnpmLock::resolves`]), labels a judged miss
/// `package_not_installed` like any other mode, and reserves the layout
/// code for an unreadable lock (no judgment possible).
///
/// Callers exempt UUID identifiers, exact-versioned PURLs, `--save-only`
/// (record-only has no installation precondition), `--all-releases`, and
/// the package-name path (already installed-derived).
async fn filter_to_installed_purls(
    accessible: &[PatchSearchResult],
    common: &GlobalArgs,
    mode: super::scan::ScanMode,
) -> InstalledNarrowing {
    use socket_patch_core::vendor::lock_inventory;
    use std::collections::HashSet;

    // Deduped base purls, probed against the installed tree. The resolver
    // keys its result by the purls we pass, so canonicalize the found keys
    // the same way as the membership probes below.
    let bases: Vec<String> = {
        let mut seen = HashSet::new();
        accessible
            .iter()
            .map(|p| strip_purl_qualifiers(&p.purl).to_string())
            .filter(|b| seen.insert(b.clone()))
            .collect()
    };
    let partitioned = partition_purls(&bases, None);
    let found = find_packages_for_rollback(&partitioned, &common.crawler_options(), true).await;
    let mut present: HashSet<PurlKey> = found.keys().map(|k| PurlKey::new(k)).collect();

    let ctx = super::context::ProjectContext::new(common);
    // Manifest membership counts as presence (read-only probe: a corrupt
    // manifest degrades to "no extension" here — the download path's
    // fail-closed read still guards every write).
    if let Some(manifest) = ctx.ledgers().await.manifest {
        present.extend(manifest.patches.keys().map(|k| PurlKey::new(k)));
    }

    // scan's lockfile + vendored-ledger discovery supplements (and their
    // gate: never on global scans, which target the machine tree, not this
    // project).
    let mut pnp_diags: Vec<lock_inventory::UnsupportedNpmLayout> = Vec::new();
    if !common.is_global() {
        let supplement = super::scan::project_lockfile_supplement(&ctx, &[], None).await;
        pnp_diags = supplement.unsupported;
        if mode != super::scan::ScanMode::Agent {
            present.extend(supplement.entries.iter().map(|e| PurlKey::new(&e.purl)));
            let vendored =
                super::scan::project_vendored_supplement(&ctx, &[], &ctx.loaded().await.vendor)
                    .await;
            present.extend(vendored.packages.iter().map(|p| PurlKey::new(&p.purl)));
        }
    }

    let warnings = super::scan::unsupported_layout_warnings(&pnp_diags);
    let pnp_yarn = pnp_diags
        .iter()
        .any(|d| d.code == "vendor_yarn_berry_unsupported");
    let pnp_pnpm = pnp_diags
        .iter()
        .any(|d| d.code == "vendor_pnpm_pnp_unsupported");
    // pnpm PnP + hosted: the lock inventory REFUSED, so nothing above could
    // mark the installed version — but the pnpm-lock.yaml the hosted
    // rewriter will edit is right there. Read its raw text once and gate the
    // keep-branch below on version membership, so a large advisory fan-out
    // doesn't request grants for every version ever patched. Read FIFO-safe,
    // like the hosted flow's own candidate-file reads: a FIFO planted at
    // `pnpm-lock.yaml` must not wedge `get` in open(2).
    let pnpm_pnp_lock_text: Option<String> = (pnp_pnpm && mode == super::scan::ScanMode::Hosted)
        .then(|| {
            socket_patch_core::utils::fs::read_regular_to_string_sync(
                &common.cwd.join("pnpm-lock.yaml"),
            )
            .ok()
        })
        .flatten();
    let pnpm_pnp_lock = pnpm_pnp_lock_text.as_deref().map(PnpmLock::parse);

    let mut out = InstalledNarrowing {
        kept: Vec::new(),
        skip_records: Vec::new(),
        warnings,
    };
    for result in accessible {
        if present.contains(&PurlKey::new(&result.purl)) {
            out.kept.push(result.clone());
            continue;
        }
        // An ecosystem THIS binary has no crawler for (a newer patch
        // server's `pkg:<type>/`) was silently absent from the probe —
        // absence carries no information there (the same fail-safe as
        // scan's prune GC), so keep the result instead of claiming
        // "not installed" about a package we cannot see.
        if !crate::ecosystem_dispatch::crawl_covers_purl(&result.purl) {
            out.kept.push(result.clone());
            continue;
        }
        let is_npm = strip_purl_qualifiers(&result.purl).starts_with("pkg:npm/");
        let error_code = if is_npm && pnp_yarn {
            // Structurally invisible, in EVERY mode — never claim "not
            // installed" when the truth is "cannot see".
            "yarn_pnp_unsupported"
        } else if is_npm && pnp_pnpm {
            // The pnpm PnP refusal's own remedy is the hosted lockfile
            // rewrite — but only for versions the lock ACTUALLY resolves:
            // keeping the whole fan-out would request grants for every
            // version ever patched. The lock model's key probe
            // (`PnpmLock::resolves`); a hit is kept (the rewriter's
            // per-dep confirmation still decides). A judged MISS is a
            // genuine "version not resolved" verdict — the layout blocked
            // nothing — so it carries the same `package_not_installed` code
            // a non-PnP pnpm project would get; only an UNREADABLE lock
            // (no judgment possible) keeps the layout-refusal code.
            let decoded = canonical_purl(&result.purl);
            let coord = decoded.strip_prefix("pkg:npm/").unwrap_or(&decoded);
            if mode == super::scan::ScanMode::Hosted {
                match (&pnpm_pnp_lock, coord.rsplit_once('@')) {
                    (Some(lock), Some((name, version))) => {
                        if lock.resolves(name, version) {
                            out.kept.push(result.clone());
                            continue;
                        }
                        "package_not_installed"
                    }
                    _ => "pnpm_pnp_unsupported",
                }
            } else {
                "pnpm_pnp_unsupported"
            }
        } else {
            "package_not_installed"
        };
        out.skip_records.push(serde_json::json!({
            "purl": result.purl, "uuid": result.uuid,
            "action": "skipped", "errorCode": error_code,
        }));
    }
    out.skip_records
        .sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    out
}

/// Fold the coarse-narrowing skip records + PnP warnings into a get JSON
/// envelope: they were "found" by the search and skipped before download,
/// mirroring scan's vendored/not-installed fold. Warnings land as strings
/// (get's `warnings[]` is a string array — unlike scan's `{code, detail}`
/// objects) with the stable code prefixed for greppability.
fn fold_narrowing_into_result(
    result: &mut serde_json::Value,
    skip_records: &[serde_json::Value],
    warnings: &[(String, String)],
) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    // Only success-shaped envelopes carry a patches[] array to fold into —
    // error envelopes ({status, error}) keep their minimal shape.
    if !skip_records.is_empty() && obj.get("patches").and_then(|p| p.as_array()).is_some() {
        let n = skip_records.len() as u64;
        for key in ["found", "skipped"] {
            let bumped = obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0) + n;
            obj.insert(key.to_string(), serde_json::json!(bumped));
        }
        if let Some(patches) = obj.get_mut("patches").and_then(|p| p.as_array_mut()) {
            patches.extend(skip_records.iter().cloned());
        }
    }
    if !warnings.is_empty() {
        let mut merged: Vec<String> = obj
            .get("warnings")
            .and_then(|w| w.as_array())
            .map(|w| {
                w.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        merged.extend(
            warnings
                .iter()
                .map(|(code, detail)| format!("({code}) {detail}")),
        );
        obj.insert("warnings".to_string(), serde_json::json!(merged));
    }
}

/// Download patches WITHOUT touching the manifest and return the fetched
/// records keyed by purl — the download phase of every vendored run
/// (`scan` / `get --mode vendored`), where the vendor ledger carries the
/// records (`detached`). Honors the same installed-release narrowing as
/// [`download_and_apply_patches_with`]. A purl already vendored detached at the
/// selected uuid skips the network fetch and reuses the ledger's embedded
/// record, so idempotent re-runs stay cheap.
///
/// `api_client` is the run's client (built once, proxy fallback included).
/// `prefetched` maps uuid → an already-fetched view: the `get <uuid>` path
/// resolved its identifier by fetching the view, and scan's vendored arm
/// pre-verified baselines from the views — neither must fetch again (a
/// fresh fetch could re-hit the 401 the proxy fallback just recovered
/// from). The ledger idempotency check runs before the cache lookup, and a
/// cache miss still fetches.
///
pub(crate) async fn download_patch_records_with(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
) -> DetachedDownload {
    download_patch_records_reusing(selected, params, api_client, prefetched, None).await
}

pub async fn run(args: GetArgs) -> i32 {
    // Validate flags
    let type_flags = [args.id, args.cve, args.ghsa, args.package]
        .iter()
        .filter(|&&f| f)
        .count();
    if type_flags > 1 {
        return usage_error(
            JsonCommand::Get,
            args.common.json,
            args.common.dry_run,
            "invalid_args",
            "Only one of --id, --cve, --ghsa, or --package can be specified",
        );
    }
    // v5: with no `--mode`, like scan, the project keeps the mode its
    // state already records (#1088) and a project with no state is hosted.
    // `--save-only` (records a manifest entry) and global installs (no
    // project lockfile) mean agent mode. Usage errors exit 2, like clap's
    // and scan's (v5.0).
    let mode = match args.mode {
        Some(mode) => mode,
        None if args.save_only || args.common.is_global() => super::scan::ScanMode::Agent,
        None => match super::mode_from_project_state(&args.common).await {
            Ok(mode) => {
                if !args.common.json && !args.common.silent {
                    if let Some(note) = super::kept_mode_note(mode) {
                        eprintln!("{note}");
                    }
                }
                mode
            }
            Err(message) => {
                return usage_error(
                    JsonCommand::Get,
                    args.common.json,
                    args.common.dry_run,
                    "mode_ambiguous",
                    &message,
                );
            }
        },
    };
    // Global installs have no project lockfile: an explicit hosted or
    // vendored mode would rewire the cwd project, not the global copy.
    if let Some(conflict) = super::global_mode_conflict(&args.common, mode) {
        return usage_error(
            JsonCommand::Get,
            args.common.json,
            args.common.dry_run,
            "global_scope_unsupported",
            &conflict,
        );
    }
    // Hosted and vendored mode rewire `--cwd`'s lockfiles and vendor
    // ledger: a manifest in another project would split the run (#745).
    if let Some(conflict) = (mode != super::scan::ScanMode::Agent)
        .then(|| {
            super::foreign_manifest_conflict(&args.common, &format!("--mode {}", mode.cli_name()))
        })
        .flatten()
    {
        return usage_error(
            JsonCommand::Get,
            args.common.json,
            args.common.dry_run,
            super::FOREIGN_MANIFEST_PROJECT,
            &conflict,
        );
    }
    if args.save_only && mode != super::scan::ScanMode::Agent {
        return usage_error(
            JsonCommand::Get,
            args.common.json,
            args.common.dry_run,
            "invalid_args",
            &format!(
                "--save-only cannot be used with --mode {}: hosted mode never writes the \
                 manifest, and vendored mode's vendor step IS the persistence (plain \
                 `get --save-only` already records without applying)",
                mode.cli_name()
            ),
        );
    }
    // Strict airgap (CLI_CONTRACT.md `--offline`: never contact the
    // network; operations that need remote data fail loudly). Every `get`
    // mode fetches remote patch data — proceeding would hit the API (and
    // save the fetched patch into the manifest) — so refuse before the
    // client is built (org auto-resolve is itself a network call). No
    // telemetry fires here: offline gates `is_telemetry_disabled` too.
    if args.common.offline {
        report_error(
            args.common.json,
            "offline_unsupported",
            "Fetching patches needs network access, so `get` cannot run with \
             --offline/SOCKET_OFFLINE (strict airgap)",
        );
        return 1;
    }

    // Classify the identifier with the shared target grammar (the same
    // one `remove` and `rollback` use), or take the forced kind.
    let forced = [
        (args.id, TargetKind::Uuid),
        (args.cve, TargetKind::Cve),
        (args.ghsa, TargetKind::Ghsa),
        (args.package, TargetKind::Name),
    ]
    .into_iter()
    .find_map(|(set, kind)| set.then_some(kind));
    let target = match forced {
        Some(kind) => Target::with_kind(&args.identifier, kind),
        None => Target::parse(&args.identifier),
    };
    let id_type = target.kind();
    // A forced type is shape-checked locally, before any network call, so
    // a typo reads as a plain message instead of a raw API 400 body.
    if args.id || args.cve || args.ghsa {
        if let Some(err) = forced_identifier_error(&target) {
            return usage_error(
                JsonCommand::Get,
                args.common.json,
                args.common.dry_run,
                "identifier_invalid",
                &err,
            );
        }
    }

    apply_env_toggles(&args.common);
    // `--silent` is "errors only" (CLI_CONTRACT.md): every informational
    // print below is gated on this; errors and JSON envelopes are not.
    let quiet = args.common.json || args.common.silent;
    if !quiet && id_type == TargetKind::Name && !args.package {
        eprintln!("Treating \"{}\" as a package name search", args.identifier);
    }
    let overrides = args.common.api_client_overrides();
    let (mut api_client, mut use_public_proxy) =
        get_api_client_with_overrides(overrides.clone()).await;
    let telemetry = TelemetryAuth::for_client(&api_client);
    // A token whose org could not be resolved put the whole run on the
    // public proxy (the client already warned on stderr): `--json`
    // consumers get it in `warnings[]` too.
    let org_warnings: Vec<(String, String)> = match api_client.org_unresolved() {
        Some(reason) if args.common.json => vec![(
            crate::commands::vex_sources::NOTE_API_AUTH_FALLBACK.to_string(),
            reason.to_string(),
        )],
        _ => Vec::new(),
    };
    // Set to `true` after the first 401/403 from the authenticated
    // endpoint triggered a rebuild against the public proxy. Plumbed
    // through to every subsequent telemetry event so we can track the
    // incidence of stale-token fallbacks.
    let mut fallback_to_proxy = false;

    // Progress for the network/crawl phases below. Built after the client:
    // building it may print core advisories straight to stderr, which
    // would land on the end of a live line.
    let mut status = crate::ui::StatusLine::stderr(args.common.json, args.common.silent);

    // Handle UUID: fetch and download directly
    if id_type == TargetKind::Uuid {
        status.set(format!("Fetching patch {}...", args.identifier));
        let mut fetch_result = api_client.fetch_patch(&args.identifier).await;
        // 401/403 from the auth endpoint → swap to the public proxy
        // and retry once. Free patches still surface; paid patches
        // come back as the existing "paid_required" branch below.
        if !use_public_proxy {
            if let Err(ref e) = fetch_result {
                if is_fallback_candidate(e) {
                    // Errors-only under --silent; --json keeps it on stderr
                    // (same gate as scan's batch fallback).
                    if !args.common.silent {
                        status.println(format!(
                            "Warning: authenticated API returned {e}; \
                             falling back to public patch API proxy (free patches only)."
                        ));
                    }
                    // Building the proxy client may print core's proxy
                    // notice straight to stderr: take the line down first.
                    status.finish();
                    api_client = build_proxy_fallback_client(&overrides);
                    use_public_proxy = true;
                    fallback_to_proxy = true;
                    status.set(format!("Fetching patch {}...", args.identifier));
                    fetch_result = api_client.fetch_patch(&args.identifier).await;
                }
            }
        }
        status.finish();
        match fetch_result {
            Ok(Some(patch)) => {
                // The search path's selection rules hold here too: a patch
                // outside `--ecosystems` is never acted on — checked before
                // the paid gate, the "Found patch" line and the fetched
                // event, since it is not this run's patch.
                if !args.common.purl_ecosystem_selected(&patch.purl) {
                    if args.common.json {
                        print_json(&empty_result_json("not_found"));
                    } else if !args.common.silent {
                        println!(
                            "No patch found with UUID: {} in the selected ecosystems \
                             (it patches {})",
                            args.identifier,
                            normalize_purl(&patch.purl)
                        );
                    }
                    return 0;
                }
                if patch.tier == "paid" && use_public_proxy {
                    return report_paid_required_uuid(
                        &args,
                        Some(&patch.purl),
                        &patch.uuid,
                        fallback_to_proxy,
                        &telemetry,
                        &org_warnings,
                    )
                    .await;
                }
                if !quiet {
                    eprintln!(
                        "Found patch for {}",
                        format_patch_summary(
                            &patch.purl,
                            &patch.tier,
                            None,
                            &patch.vulnerabilities,
                            crate::ui::stderr_color(),
                        )
                    );
                }

                // Record the fetch BEFORE the save+apply step so the
                // event captures patch identity even if a downstream
                // file-system error trips up save_and_apply. The save
                // step has its own apply-side telemetry (track_patch_applied)
                // so we don't lose visibility into the rest of the pipeline.
                track_patch_fetched(
                    &patch.uuid,
                    &patch.tier,
                    &ecosystem_from_purl(&patch.purl),
                    fallback_to_proxy,
                    &telemetry,
                )
                .await;
                let selected = vec![search_result_from_response(&patch)];
                // Acting against the repo's socket.yml says so
                // (`policy_bypassed`).
                let mut uuid_warnings =
                    super::scan::policy::policy_bypass_warnings(&args.common, &selected);
                if !args.common.silent {
                    for (_, detail) in &uuid_warnings {
                        eprintln!("Warning: {detail}");
                    }
                }
                // Already on stderr from the client: JSON only, after the
                // print above.
                uuid_warnings.extend(org_warnings.iter().cloned());
                // Mode dispatch. All three reuse THIS fetched patch and
                // this possibly-proxy-fallback client rather than
                // re-fetching with a fresh one, which would re-hit the
                // 401/403 the fallback just recovered from. An explicit
                // UUID is exempt from installed narrowing (exact intent).
                return match mode {
                    // Save to manifest and apply in place.
                    super::scan::ScanMode::Agent => {
                        save_and_apply_patch(&args, &api_client, &patch, &uuid_warnings).await
                    }
                    super::scan::ScanMode::Hosted => {
                        run_get_hosted(&args, &api_client, &selected, &[], &uuid_warnings).await
                    }
                    super::scan::ScanMode::Vendored => {
                        run_get_vendored(
                            &args,
                            &api_client,
                            use_public_proxy,
                            &selected,
                            Some(&patch),
                            &[],
                            &uuid_warnings,
                            &telemetry,
                        )
                        .await
                    }
                };
            }
            // The public proxy answers a paid patch with 403 rather than
            // a tier=paid view: the same outcome as the branch above, not
            // a raw "Forbidden" error.
            Err(ApiError::Forbidden(_)) if use_public_proxy => {
                return report_paid_required_uuid(
                    &args,
                    None,
                    &args.identifier,
                    fallback_to_proxy,
                    &telemetry,
                    &org_warnings,
                )
                .await;
            }
            Ok(None) => {
                track_patch_fetch_failed(
                    &args.identifier,
                    "not_found",
                    fallback_to_proxy,
                    &telemetry,
                )
                .await;
                if args.common.json {
                    let mut result = empty_result_json("not_found");
                    fold_narrowing_into_result(&mut result, &[], &org_warnings);
                    print_json(&result);
                } else if !args.common.silent {
                    println!("No patch found with UUID: {}", args.identifier);
                }
                return 0;
            }
            Err(e) => {
                return report_fetch_failure(
                    &args.identifier,
                    e,
                    fallback_to_proxy,
                    &telemetry,
                    args.common.json,
                )
                .await;
            }
        }
    }

    // For CVE/GHSA/PURL/package, search first.
    // CVE / GHSA / PURL share the same path: log the search, dispatch to
    // the matching endpoint, and surface errors via `report_fetch_failure`.
    let search_response: SearchResponse = match id_type {
        TargetKind::Cve | TargetKind::Ghsa | TargetKind::Purl => {
            status.set(format!(
                "Searching patches for {id_type} {}...",
                args.identifier
            ));
            let result = match id_type {
                TargetKind::Cve => api_client.search_patches_by_cve(&args.identifier).await,
                TargetKind::Ghsa => api_client.search_patches_by_ghsa(&args.identifier).await,
                TargetKind::Purl => api_client.search_patches_by_package(&args.identifier).await,
                _ => unreachable!(),
            };
            status.finish();
            match result {
                Ok(r) => r,
                Err(e) => {
                    return report_fetch_failure(
                        &args.identifier,
                        e,
                        fallback_to_proxy,
                        &telemetry,
                        args.common.json,
                    )
                    .await;
                }
            }
        }
        TargetKind::Name => {
            status.set("Enumerating packages...");
            // `--ecosystems` scopes the crawl, so a name can only resolve
            // inside the selected ecosystems.
            let only = args.common.ecosystems.as_deref().filter(|l| !l.is_empty());
            let (all_packages, _, _) = crawl_ecosystems(&args.common.crawler_options(), only).await;

            if all_packages.is_empty() {
                status.finish();
                if args.common.json {
                    print_json(&empty_result_json("no_packages"));
                } else if !args.common.silent {
                    println!("{}", no_packages_message(args.common.global));
                }
                return 0;
            }

            status.finish_with(format!(
                "Found {}",
                crate::ui::plural(all_packages.len(), "package", "packages")
            ));

            // The shared target grammar: an EXACT name (full or last
            // segment, case-insensitive, PEP 503 for PyPI), never a prefix
            // or substring, and every installed version of it.
            let matched = installed_target_matches(&target, &all_packages);
            if matched.is_empty() {
                if args.common.json {
                    print_json(&empty_result_json("no_match"));
                } else if !args.common.silent {
                    println!("No packages matching \"{}\" found.", args.identifier);
                    // Near names are only ever suggested, never acted on.
                    if let Some(hint) = format_did_you_mean(&args.identifier, &all_packages) {
                        println!("{hint}");
                    }
                }
                return 0;
            }

            // A name reaching several packages by last segment (`core` →
            // `@angular/core` and `@babel/core`) is refused: `get` acts on
            // one package per name, and only on the one the check settled
            // on (`lodash` beside `@types/lodash` is `lodash` alone).
            let target = match target.settle(matched.iter().map(String::as_str)) {
                Ok(settled) => settled,
                Err(msg) => {
                    report_error(args.common.json, "ambiguous_target", &msg);
                    return 1;
                }
            };
            let matched: Vec<String> = matched
                .into_iter()
                .filter(|purl| target.matches_package(purl))
                .collect();
            if !quiet {
                eprintln!("{}", format_matched_packages(&matched));
            }
            let mut merged = SearchResponse {
                patches: Vec::new(),
                can_access_paid_patches: false,
            };
            // One search per installed version, concurrently, merged in
            // `matched` order. Any failed search still fails the run (as
            // the single search did): a partial result could silently
            // miss the patch for the version that failed.
            status.set(format!(
                "Searching patches for {}...",
                crate::ui::plural(matched.len(), "installed version", "installed versions")
            ));
            let window_len = matched.len();
            let api = &api_client;
            let mut searches = std::pin::pin!(ordered_concurrent(
                matched.iter(),
                api_concurrency_for(api.uses_public_proxy(), window_len),
                |purl| async move { hold_back_debug(api.search_patches_by_package(purl)).await },
            ));
            while let Some(held) = searches.next().await {
                match held.release() {
                    Ok(r) => {
                        merged.can_access_paid_patches |= r.can_access_paid_patches;
                        for patch in r.patches {
                            if !merged.patches.iter().any(|p| p.uuid == patch.uuid) {
                                merged.patches.push(patch);
                            }
                        }
                    }
                    Err(e) => {
                        status.finish();
                        return report_fetch_failure(
                            &args.identifier,
                            e,
                            fallback_to_proxy,
                            &telemetry,
                            args.common.json,
                        )
                        .await;
                    }
                }
            }
            status.finish();
            merged
        }
        _ => unreachable!(),
    };
    drop(status);

    // `--ecosystems` restricts what `get` acts on, whatever the identifier
    // kind: an advisory or purl search can return patches for other
    // ecosystems, and those are never selected.
    let mut search_response = search_response;
    search_response
        .patches
        .retain(|p| args.common.purl_ecosystem_selected(&p.purl));

    if search_response.patches.is_empty() {
        if args.common.json {
            let mut result = empty_result_json("not_found");
            fold_narrowing_into_result(&mut result, &[], &org_warnings);
            print_json(&result);
        } else if !args.common.silent {
            println!("No patches found for {}: {}", id_type, args.identifier);
        }
        return 0;
    }

    let color = crate::ui::stdout_color();

    // Filter accessible patches
    let accessible: Vec<_> = search_response
        .patches
        .iter()
        .filter(|p| p.tier == "free" || search_response.can_access_paid_patches)
        .cloned()
        .collect();

    if accessible.is_empty() {
        if args.common.json {
            let records = search_response
                .patches
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "purl": p.purl,
                        "uuid": p.uuid,
                        "tier": p.tier,
                    })
                })
                .collect();
            print_json(&paid_required_json(records, &org_warnings));
        } else if !args.common.silent {
            let all: Vec<&PatchSearchResult> = search_response.patches.iter().collect();
            if id_type == TargetKind::Name && !quiet {
                // Separate the stderr `Matched` line above on a terminal;
                // stdout itself starts with the result.
                eprintln!();
            }
            print!(
                "{}",
                format_search_results(&all, search_response.can_access_paid_patches, color)
            );
            println!("All available patches require a paid Socket plan.");
            println!("{}", crate::ui::PAID_UPGRADE);
        }
        return 0;
    }

    // Coarse installed-VERSION narrowing of the fan-out (a GHSA/CVE search
    // returns one record per patched version — only the versions present
    // here should be acted on). Exempt: --all-releases (the documented
    // escape), --save-only (record-only has no installation precondition —
    // the fresh-clone `get --save-only` → `vendor` flow must keep working),
    // exact-versioned PURL identifiers (explicit intent, like a UUID), and
    // the package-name path (its search key IS an installed purl). Runs
    // AFTER the paid gate above: a paid-only result is `paid_required`,
    // never "not installed".
    let narrowing_exempt = args.all_releases
        || args.save_only
        || id_type == TargetKind::Name
        || target.is_versioned_purl();
    // The narrowing runs over EVERY result (one crawl), paid no-access ones
    // included, so the listing can still show an installed package's paid
    // fix as `[PAID] (no access)`; selection, the skip records and the
    // JSON envelope only ever see the accessible share.
    let (accessible, listed, narrow_skips, mut narrow_warnings) = if narrowing_exempt {
        let listed: Vec<PatchSearchResult> = search_response.patches.clone();
        (accessible, listed, Vec::new(), Vec::new())
    } else {
        let narrowing =
            filter_to_installed_purls(&search_response.patches, &args.common, mode).await;
        let accessible_uuids: std::collections::HashSet<&str> =
            accessible.iter().map(|p| p.uuid.as_str()).collect();
        let kept_accessible: Vec<PatchSearchResult> = narrowing
            .kept
            .iter()
            .filter(|p| accessible_uuids.contains(p.uuid.as_str()))
            .cloned()
            .collect();
        let skips: Vec<serde_json::Value> = narrowing
            .skip_records
            .into_iter()
            .filter(|r| accessible_uuids.contains(r["uuid"].as_str().unwrap_or_default()))
            .collect();
        (kept_accessible, narrowing.kept, skips, narrowing.warnings)
    };
    // `get` bypasses the repo's socket.yml policy, but says so.
    narrow_warnings.extend(super::scan::policy::policy_bypass_warnings(
        &args.common,
        &accessible,
    ));
    // Layout refusals print even when informational output is quieted only
    // by --json (stderr; the envelope carries them too) — but --silent
    // mutes them like scan does.
    if !args.common.silent {
        for (_, detail) in &narrow_warnings {
            eprintln!("Warning: {detail}");
        }
    }
    // Already on stderr from the client: JSON only, after the print above.
    narrow_warnings.extend(org_warnings);
    if accessible.is_empty() {
        // Every accessible patch was narrowed out. Additive status (never
        // `no_match`, which is pinned to the package-name path):
        // exit 0, the skips carry the detail via their errorCode.
        if args.common.json {
            let mut result = serde_json::json!({
                "status": "not_installed",
                "found": narrow_skips.len(),
                "downloaded": 0,
                "applied": 0,
                "patches": narrow_skips,
            });
            fold_narrowing_into_result(&mut result, &[], &narrow_warnings);
            print_json(&result);
        } else if !args.common.silent {
            println!("{}", format_all_narrowed(&narrow_skips));
            if !quiet && args.common.verbose {
                for line in format_verbose_skips(&narrow_skips) {
                    eprintln!("{line}");
                }
            }
        }
        return 0;
    }

    // The listing shows only what survived the narrowing (a CVE fan-out
    // can span dozens of versions that are not installed here): the
    // skipped ones are summarized in one line each instead, with the
    // per-version detail after the summary under --verbose.
    let listed: Vec<&PatchSearchResult> = listed.iter().collect();
    if !quiet {
        if id_type == TargetKind::Name || !narrow_warnings.is_empty() {
            // Separate the stderr lines above (`Matched`, warnings) on a
            // terminal; stdout itself starts with the result.
            eprintln!();
        }
        print!(
            "{}",
            format_search_results(&listed, search_response.can_access_paid_patches, color)
        );
        let mut skip_lines = format_skip_summary(&narrow_skips);
        if args.common.verbose {
            skip_lines.extend(format_verbose_skips(&narrow_skips));
        }
        for line in &skip_lines {
            eprintln!("{line}");
        }
        if !skip_lines.is_empty() {
            eprintln!();
        }
    }

    // Smart patch selection: pick one patch per PURL. `accessible` is
    // non-empty here and every entry passes the selector's tier filter, so
    // the selection is never empty (one patch per purl group, or `Err`).
    // Hosted and vendored `get` never prompt (v5.0): like `scan`, they take
    // the top-ranked accessible patch per package, in JSON mode too.
    let auto_pick = mode != super::scan::ScanMode::Agent;
    let select_common = if auto_pick {
        super::scan::selection_args(&args.common)
    } else {
        args.common.clone()
    };
    let selected = match select_patches(
        &accessible,
        auto_pick || search_response.can_access_paid_patches,
        &select_common,
    ) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // The candidates can hold several patches per package and the pick
    // was made without the user (paid auto-pick, `--yes`, non-TTY): say
    // which will be installed. A menu pick is not echoed back, and paid
    // no-access entries (never candidates) do not count.
    if !quiet
        && accessible.len() > selected.len()
        && !selection_prompted(
            &accessible,
            search_response.can_access_paid_patches,
            &select_common,
        )
    {
        print!("{}", format_selected_patches(&selected, color));
    }

    // Agent wet runs and vendored runs narrow variants in their download
    // engines. Hosted runs and agent previews need the same narrowing here.
    let agent_preview = args.common.dry_run && mode == super::scan::ScanMode::Agent;
    let selected = if agent_preview || mode == super::scan::ScanMode::Hosted {
        let (selected, variant_warnings, _) = filter_to_installed_releases(
            &selected,
            args.all_releases,
            &args.common.crawler_options(),
            quiet,
            &api_client,
        )
        .await;
        narrow_warnings.extend(
            variant_warnings
                .into_iter()
                .map(|w| ("release_narrowing".to_string(), w)),
        );
        selected
    } else {
        selected
    };
    if agent_preview {
        return agent_dry_run(&args, &selected, &narrow_skips, &narrow_warnings).await;
    }

    // Agent mode confirms before acting (default YES). Dry runs skip the
    // prompt: nothing mutates, so nothing to confirm. Hosted and vendored
    // runs never prompt (v5.0), like `scan`.
    if mode == super::scan::ScanMode::Agent {
        let prompt = format_confirm_prompt(args.save_only, selected.len());
        if !crate::ui::confirm(&prompt, true, &args.common) {
            if !quiet {
                eprintln!("{}", crate::ui::CANCELLED);
            }
            return 0;
        }
    }

    match mode {
        super::scan::ScanMode::Hosted => {
            return run_get_hosted(
                &args,
                &api_client,
                &selected,
                &narrow_skips,
                &narrow_warnings,
            )
            .await;
        }
        super::scan::ScanMode::Vendored => {
            return run_get_vendored(
                &args,
                &api_client,
                use_public_proxy,
                &selected,
                None,
                &narrow_skips,
                &narrow_warnings,
                &telemetry,
            )
            .await;
        }
        super::scan::ScanMode::Agent => {}
    }

    // Download and apply (agent mode), with the run's client and flags.
    let params = get_download_params(&args, args.save_only, /*persist_blobs=*/ true);
    let run = DownloadRun {
        api_client: &api_client,
        lock_timeout: args.common.lock_timeout,
        verbose: args.common.verbose,
    };
    let (code, mut result_json) = download_and_apply_patches_with(&selected, &params, &run).await;
    // A download-phase HARD error (lock refused, unreadable manifest,
    // failed manifest write) is an `error`-status envelope the engine has
    // ALREADY printed — printing below would put a second JSON document on
    // stdout (get's `--json` contract is exactly one per run). Per-patch
    // failures are NOT this case: they ride a success-shaped
    // (`partial_failure`) envelope the engine leaves for us to print.
    if result_json["status"] == "error" {
        return code;
    }
    fold_narrowing_into_result(&mut result_json, &narrow_skips, &narrow_warnings);

    if args.common.json {
        print_json(&result_json);
    }

    code
}

/// `get --json`'s one paid-plan shape (CLI_CONTRACT.md, `paid_required`):
/// the legacy top-level `status: "paid_required"` with the refused
/// `patches` records and nothing downloaded or applied. No `events`, no
/// `error`: it is a clean outcome (exit 0).
fn paid_required_json(
    records: Vec<serde_json::Value>,
    org_warnings: &[(String, String)],
) -> serde_json::Value {
    let mut result = serde_json::json!({
        "status": "paid_required",
        "found": records.len(),
        "downloaded": 0,
        "applied": 0,
        "patches": records,
    });
    fold_narrowing_into_result(&mut result, &[], org_warnings);
    result
}

/// `paid_required` for the uuid path: the patch exists but the caller
/// (on the public proxy) cannot download it. A clean outcome, exit 0.
/// `purl` is `None` when the proxy refused with 403 before naming it.
async fn report_paid_required_uuid(
    args: &GetArgs,
    purl: Option<&str>,
    patch_id: &str,
    fallback_to_proxy: bool,
    telemetry: &TelemetryAuth,
    org_warnings: &[(String, String)],
) -> i32 {
    track_patch_fetch_failed(patch_id, "paid_required", fallback_to_proxy, telemetry).await;
    if args.common.json {
        let mut record = serde_json::json!({ "uuid": patch_id, "tier": "paid" });
        if let Some(purl) = purl {
            record["purl"] = serde_json::json!(purl);
        }
        print_json(&paid_required_json(vec![record], org_warnings));
    } else if !args.common.silent {
        let name = purl.map(|p| normalize_purl(p).into_owned());
        println!(
            "{}",
            format_paid_required(name.as_deref().unwrap_or(patch_id))
        );
    }
    0
}

/// Agent-mode `--dry-run`: classify each selected patch against the
/// manifest (read-only) and report what a wet run would do — no download,
/// no manifest or blob write, no apply, no prompt. JSON carries
/// `dryRun: true` and per-patch `would_add` / `would_update` (+`oldUuid`)
/// / `skipped` records, plus the narrowing skips.
async fn agent_dry_run(
    args: &GetArgs,
    selected: &[PatchSearchResult],
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
) -> i32 {
    // Fail closed like the wet run: a preview over an unreadable manifest
    // would promise an outcome the wet run refuses.
    let manifest = match read_manifest(&args.common.resolved_manifest_path()).await {
        Ok(m) => m.unwrap_or_else(PatchManifest::new),
        Err(e) => {
            report_error(
                args.common.json,
                "manifest_unreadable",
                format!("Failed to read manifest: {e}"),
            );
            return 1;
        }
    };
    let mut records = Vec::new();
    let mut lines = Vec::new();
    let mut changing = 0usize;
    let mut skipped = 0usize;
    for p in selected {
        let shown = normalize_purl(&p.purl);
        match decide_patch_action(&manifest, &p.purl, &p.uuid) {
            PatchAction::Added => {
                changing += 1;
                lines.push(format!("  [would-add] {shown}"));
                records.push(serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_add",
                }));
            }
            PatchAction::Updated { old_uuid } => {
                changing += 1;
                lines.push(format!(
                    "  [would-update] {shown} (replacing {})",
                    crate::ui::short_uuid(&old_uuid)
                ));
                records.push(serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_update",
                    "oldUuid": old_uuid,
                }));
            }
            PatchAction::Skipped => {
                skipped += 1;
                lines.push(format!("  [skip] {shown} (already in manifest)"));
                records.push(serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "skipped",
                }));
            }
        }
    }
    if args.common.json {
        let mut result = serde_json::json!({
            "status": "success",
            "dryRun": true,
            "found": selected.len(),
            "downloaded": 0,
            "skipped": skipped,
            "applied": 0,
            "patches": records,
        });
        fold_narrowing_into_result(&mut result, narrow_skips, narrow_warnings);
        print_json(&result);
    } else if !args.common.silent {
        for line in &lines {
            println!("{line}");
        }
        let action = if args.save_only {
            "download and record"
        } else {
            "download and apply"
        };
        println!("{}", format_dry_run(action, changing));
    }
    0
}

/// The manifest-record half of the agent single-uuid save, under the apply
/// lock: fail-closed manifest read, the no-applicable-files guardrail,
/// action classification against the manifest, and — unless the same uuid
/// is already recorded — the blob writes and the manifest write. Takes the
/// `PatchResponse` the caller fetched rather than re-fetching by UUID: the
/// caller's client may have fallen back to the public proxy after a
/// 401/403, and a fresh client would hit the same auth failure again. A
/// same-uuid re-get writes nothing (matching the multi-patch engine's
/// `skipped`). Runs under the apply lock the caller (`save_and_apply_patch`)
/// holds — the RMW must be serialized against `remove`/`rollback`, and the
/// nested apply then runs under that same guard.
///
/// Errors are reported here and surface as `Err(exit_code)`.
async fn save_patch_record(
    args: &GetArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    patch: &PatchResponse,
) -> Result<PatchAction, i32> {
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => PatchManifest::new(),
        // Fail closed like the download flow: an unreadable manifest
        // treated as empty would be rewritten below with only this one
        // patch, destroying every tracked record.
        Err(e) => {
            report_error(
                args.common.json,
                "manifest_unreadable",
                format!("Failed to read manifest: {e}"),
            );
            return Err(1);
        }
    };

    // Build the manifest `files` map, retaining patch-added new files
    // (a file with after_hash but no before_hash records an empty
    // `before_hash` sentinel, which apply treats as a new-file insert).
    let files = files_for_manifest(patch);

    // GUARDRAIL: a patch that yields NO recordable files cannot be
    // applied — recording an empty `files` map and reporting the patch
    // as applied would claim protection while writing nothing. Fail
    // loudly instead of counting a defective patch as `applied:1`.
    if files.is_empty() {
        report_error(
            args.common.json,
            "patch_no_applicable_files",
            format!(
                "Patch {} has no applicable files; nothing to apply",
                patch.purl
            ),
        );
        return Err(1);
    }

    // Classify against the manifest state BEFORE the insert, with the same
    // vocabulary `download_and_apply_patches_with` emits (CLI_CONTRACT.md): a
    // different uuid already recorded at this purl is `updated` (+`oldUuid`),
    // not `added` — consumers diff manifest replacements on that action.
    let action = decide_patch_action(&manifest, &patch.purl, &patch.uuid);
    if action == PatchAction::Skipped {
        return Ok(action);
    }

    let blobs_dir = socket_dir.join("blobs");
    let Ok(new_blobs) = write_all_patch_blobs(&blobs_dir, patch, args.common.json).await else {
        if args.common.json {
            print_json(&serde_json::json!({
                "status": "error",
                "found": 1,
                "downloaded": 0,
                "applied": 0,
                "error": {
                    "code": "blob_write_failed",
                    "message": "Blob decode or write failed",
                },
                "patches": [{
                    "purl": patch.purl,
                    "uuid": patch.uuid,
                    "action": "failed",
                    "error": "Blob decode or write failed",
                }],
            }));
        } else {
            eprintln!(
                "Error: Blob decode or write failed for patch {}",
                patch.purl
            );
        }
        return Err(1);
    };

    manifest
        .patches
        .insert(patch.purl.clone(), build_patch_record(patch, files));
    if let Err(e) = write_manifest(manifest_path, &manifest).await {
        // No record points at the blobs just written: unwind exactly those.
        unwind_new_blobs(&blobs_dir, &new_blobs).await;
        report_error(
            args.common.json,
            "manifest_write_failed",
            format!("Failed to write manifest: {e}"),
        );
        return Err(1);
    }
    Ok(action)
}

/// The uuid path's agent arm: record `patch` in the manifest and, unless
/// `--save-only`, apply it — under ONE apply lock, on the `client` the
/// fetch used (a fresh client could re-hit the 401/403 its proxy fallback
/// just recovered from).
/// `run_warnings` are the run's `(code, detail)` warnings for the JSON
/// envelope (`policy_bypassed`, and the org-unresolved auth fallback),
/// already on stderr; the envelope carries them like the search path's.
async fn save_and_apply_patch(
    args: &GetArgs,
    client: &ApiClient,
    patch: &PatchResponse,
    run_warnings: &[(String, String)],
) -> i32 {
    // Same "errors only" gate as `run` — informational prints respect
    // `--silent`; errors and the JSON envelope do not.
    let quiet = args.common.json || args.common.silent;
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = args.common.socket_dir();
    let lock_timeout = Duration::from_secs(args.common.lock_timeout.unwrap_or(0));
    // A dry run previews against the manifest and writes nothing — not
    // even the lock (which would create `.socket/`).
    if args.common.dry_run {
        return agent_dry_run(
            args,
            &[search_result_from_response(patch)],
            &[],
            run_warnings,
        )
        .await;
    }
    // See `download_and_apply_patches_with`: the RMW runs under the lock,
    // which also creates `.socket/` and prunes it again when nothing lands;
    // an error return below drops the guard.
    let guard = match crate::commands::lock_cli::acquire_with_status(&socket_dir, lock_timeout) {
        Ok(guard) => guard,
        Err(e) => {
            report_lock_failure(args.common.json, &socket_dir, &e, lock_timeout);
            return 1;
        }
    };

    let action = match save_patch_record(args, &manifest_path, &socket_dir, patch).await {
        Ok(action) => action,
        Err(code) => return code,
    };
    let changed = action != PatchAction::Skipped;
    // The record is now in the manifest whatever `action` says, so the
    // nested apply follows unless `--save-only`: a same-uuid re-get must
    // still reconcile an installed copy that was reinstalled pristine since
    // it was recorded (#454). Carried into the nested apply (it releases
    // the lock after its last mutation), released here otherwise.
    let apply_lock = if !args.save_only {
        Some(guard)
    } else {
        drop(guard);
        None
    };
    let action_label = match &action {
        PatchAction::Added => "added",
        PatchAction::Updated { .. } => "updated",
        PatchAction::Skipped => "skipped",
    };

    // Vendored-uuid drift (mirrors `download_and_apply_patches_with`): the user
    // explicitly fetched this uuid; if the vendor ledger still wires a
    // different one, VEX verification fails closed (`vendor_uuid_mismatch`)
    // until a `vendor` run refreshes the committed artifact.
    let mut warnings: Vec<String> = Vec::new();
    if changed {
        warn_on_vendored_uuid_drift(
            &args.common.project_root(),
            quiet,
            &[serde_json::json!({
                "purl": patch.purl,
                "uuid": patch.uuid,
                "action": action_label,
            })],
            &mut warnings,
        )
        .await;
    }

    // Progress narration goes to stderr, like the search path's.
    if !quiet {
        eprintln!(
            "{}",
            format_single_save(
                "Patch",
                &action,
                &manifest_path,
                &patch.purl,
                // An unchanged record ends the run only when no apply follows.
                apply_lock.is_none()
            )
        );
    }

    let mut apply_report: Option<ApplyRunReport> = None;
    if let Some(lock) = apply_lock {
        if !quiet {
            eprintln!();
            eprintln!("Applying patches...");
        }
        apply_report = Some(
            run_nested_apply(
                nested_apply_args(&args.common, &manifest_path, quiet),
                args.common.json,
                client,
                lock,
            )
            .await,
        );
    }
    let apply_succeeded = apply_report.as_ref().is_some_and(|r| r.code == 0);

    // The apply step ran (not --save-only) but failed →
    // partial failure. The `status` field must agree with the exit code
    // returned below; a hardcoded `success` alongside a non-zero exit
    // misleads JSON consumers.
    let apply_failed = !apply_succeeded && !args.save_only;
    // No "download failed" concept here — a blob failure early-returns
    // with status `error` above — so only the apply step can degrade us.
    let (status, exit_code) = run_outcome(false, apply_failed);

    if args.common.json {
        let mut patch_record = serde_json::json!({
            "purl": patch.purl,
            "uuid": patch.uuid,
            "action": action_label,
        });
        if let PatchAction::Updated { old_uuid } = &action {
            patch_record["oldUuid"] = serde_json::json!(old_uuid);
        }
        if changed {
            // Only enrich added/updated records — a `skipped` record means
            // the consumer already saw the metadata last time.
            merge_metadata(&mut patch_record, patch_event_metadata(patch));
        }
        let mut result_json = serde_json::json!({
            "status": status,
            "found": 1,
            "downloaded": if changed { 1 } else { 0 },
            "applied": if apply_succeeded { 1 } else { 0 },
            "patches": [patch_record],
        });
        // A failed apply names what failed (#424); `failed` appears only
        // then, so a clean run's envelope is unchanged.
        if let Some(report) = apply_report.as_ref().filter(|r| r.code != 0) {
            // The manifest names the uuid of any other failing record.
            let recorded = Box::pin(read_manifest(&manifest_path)).await.ok().flatten();
            result_json["failed"] = serde_json::json!(0);
            let applied = fold_apply_failures(&mut result_json, report, |purl| {
                let record = recorded.as_ref()?.patches.get(purl)?;
                Some(record.uuid.clone())
            });
            result_json["applied"] = serde_json::json!(applied);
        }
        // Same contract as `download_and_apply_patches_with`: omitted when clean.
        warnings.extend(apply_warning_lines(apply_report.as_ref()));
        if !warnings.is_empty() {
            result_json["warnings"] = serde_json::json!(warnings);
        }
        fold_narrowing_into_result(&mut result_json, &[], run_warnings);
        print_json(&result_json);
    }

    exit_code
}

/// Bridge a fetched patch view to the search shape the mode flows consume —
/// the uuid path fetches the view directly and never runs a search.
fn search_result_from_response(patch: &PatchResponse) -> PatchSearchResult {
    PatchSearchResult {
        uuid: patch.uuid.clone(),
        purl: patch.purl.clone(),
        published_at: patch.published_at.clone(),
        description: patch.description.clone(),
        license: patch.license.clone(),
        tier: patch.tier.clone(),
        vulnerabilities: patch.vulnerabilities.clone(),
    }
}

/// The `DownloadParams` a `get` run hands its download engine. Only the
/// posture differs per mode: agent persists blobs and applies unless
/// `--save-only`; vendored holds content in memory (`save_only`, no blobs)
/// because the vendor step is the persistence.
fn get_download_params(args: &GetArgs, save_only: bool, persist_blobs: bool) -> DownloadParams {
    DownloadParams {
        cwd: args.common.cwd.clone(),
        manifest_path: args.common.resolved_manifest_path(),
        save_only,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: args.common.json,
        silent: args.common.silent,
        all_releases: args.all_releases,
        strict: args.common.strict,
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs,
        patch_server_url: args.common.patch_server_url.clone(),
    }
}

/// `get … --mode hosted`: hand the selected (purl, uuid) pairs to scan's
/// hosted engine ([`super::scan::boxed_run_redirect_selected`]) — lockfile
/// rewrite only, no manifest, no blobs, no ledger — so the on-disk result
/// matches `scan --mode hosted` selecting the same patches. The engine owns
/// all output (and honors `--dry-run` internally); in JSON mode it nests its
/// `redirect` block into the get base envelope passed as `scan_result`.
async fn run_get_hosted(
    args: &GetArgs,
    api_client: &ApiClient,
    selected: &[PatchSearchResult],
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
) -> i32 {
    let pairs: Vec<(String, String)> = selected
        .iter()
        .map(|s| (s.purl.clone(), s.uuid.clone()))
        .collect();
    // `scan_result` iff --json: the engine's human/JSON split keys on
    // common.json, and a --json caller passing None would get a minimal
    // envelope that drops get's keys (see run_redirect_selected's doc).
    let scan_result = args.common.json.then(|| {
        let mut result = serde_json::json!({
            "status": "success",
            "found": pairs.len() + narrow_skips.len(),
            "patches": narrow_skips,
        });
        fold_narrowing_into_result(&mut result, &[], narrow_warnings);
        result
    });
    // Embedded VEX stays a scan/vendor feature (get has no --vex): a
    // default-off VexEmbedArgs — deliberately NOT env-bound here, so an
    // ambient SOCKET_VEX only affects commands that declare the flag.
    let vex = crate::commands::vex::VexEmbedArgs::default();
    super::scan::boxed_run_redirect_selected(
        &args.common,
        &vex,
        /*prune_requested=*/ false,
        api_client,
        &pairs,
        scan_result,
        None,
        // `get` is explicit intent: the rollout cap never applies.
        None,
    )
    .await
}

/// `get … --mode vendored`, both identifier paths: scan's vendored posture
/// end to end — the detached download phase ([`download_patch_records_with`]:
/// records fetched into memory, no manifest, no blobs) feeding scan's
/// detached vendor step (apply lock, in-memory staging seeded with the
/// downloaded blobs, the vendor engine over the same run-level client; the
/// ledger carries every record `detached: true`), telemetry included — so
/// the result matches `scan --mode vendored` selecting the same patches.
/// `.socket/manifest.json` is never read or written here.
///
/// `prefetched` is the `get <uuid>` path's already-fetched view: it resolved
/// the identifier by fetching it (with the possibly-proxy-fallback client)
/// and the engine serves the record from it instead of fetching again. That
/// path also refuses a Bun project BEFORE the engine, with the contract's
/// exact pre-record envelope, so a refused run writes nothing at all; the
/// search path lets the engine record the refusal per patch and still runs
/// the vendor step (scan parity).
#[allow(clippy::too_many_arguments)]
async fn run_get_vendored(
    args: &GetArgs,
    api_client: &ApiClient,
    use_public_proxy: bool,
    selected: &[PatchSearchResult],
    prefetched: Option<&PatchResponse>,
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
    telemetry: &TelemetryAuth,
) -> i32 {
    // Dry run: ledger-classification preview only (scan's posture) — no
    // download, no vendor step, no writes.
    if args.common.dry_run {
        let takeover = super::vendor::gem_takeover_preview_refusals(
            &args.common,
            selected.iter().map(|p| p.purl.as_str()),
        )
        .await;
        let preview = super::scan::preview_vendor_json(
            &args.common.cwd,
            selected,
            &super::hosted_unwind::patch_server_origins(&args.common),
            &takeover,
        )
        .await;
        if args.common.json {
            let mut result = serde_json::json!({
                "status": "success",
                "found": selected.len() + narrow_skips.len(),
                "patches": narrow_skips,
            });
            fold_narrowing_into_result(&mut result, &[], narrow_warnings);
            result["vendor"] = preview;
            print_json(&result);
        } else if !args.common.silent {
            println!("{}", format_dry_run("download and vendor", selected.len()));
            super::scan::print_dry_run_refusals(&preview);
        }
        return 0;
    }

    // The uuid path's Bun preflight, run ONCE here and handed to the download
    // phase below (which otherwise runs its own): the pre-record refusal
    // shape is this path's, so it owns the read.
    let mut bun_refusal: Option<BunVendorRefusal> = None;
    let mut vlt_refusals: Vec<(String, VltVendorRefusal)> = Vec::new();
    if let Some(patch) = prefetched {
        // Bun preflight (see `BunVendorRefusal`): refuse BEFORE the engine
        // and the vendor step, so the tree stays exactly as it was (no
        // `.socket/` is created on a fresh project). The already-fetched
        // patch is the only network traffic of a refused run.
        //
        // JSON shape (contract: `get <uuid> --mode vendored` pre-record
        // refusal; the record carries BOTH `errorCode` and `error` like the
        // search path's failed records, and the envelope carries `skipped`
        // like this path's success shape):
        //
        // {
        //   "status": "error",
        //   "found": 1, "downloaded": 0, "skipped": 0, "failed": 1,
        //   "error": { "code": "<vendor code>", "message": "<detail>" },
        //   "patches": [{ "purl": "…", "uuid": "…", "action": "failed",
        //                 "errorCode": "<vendor code>", "error": "<detail>" }]
        // }
        //
        // Human: `Error (<code>): <detail>` on stderr — an error, so it is
        // exempt from `--silent` like every other `Error (…)` line here.
        bun_refusal = bun_vendor_preflight(&args.common.project_root(), selected).await;
        let ledger = load_state(&args.common.project_root()).await;
        vlt_refusals = vlt_vendor_preflight_selected(
            &args.common.cwd,
            selected,
            ledger.as_ref().map(|s| &s.entries),
        )
        .await;
        let refusal = bun_refusal
            .as_ref()
            .filter(|r| r.applies_to(&patch.purl))
            .map(|r| (&r.code, &r.detail))
            .or_else(|| vlt_refusal_for(&vlt_refusals, &patch.purl).map(|r| (&r.code, &r.detail)));
        if let Some((code, detail)) = refusal {
            // Same failure telemetry as the vendor-step Err arm below: this
            // run exits 1 without vendoring anything.
            socket_patch_core::telemetry::track_patch_vendor_failed(
                &detail,
                args.common.dry_run,
                telemetry,
            )
            .await;
            if args.common.json {
                print_json(&serde_json::json!({
                    "status": "error",
                    "found": 1,
                    "downloaded": 0,
                    "skipped": 0,
                    "failed": 1,
                    "error": { "code": code, "message": detail },
                    "patches": [{
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "failed",
                        "errorCode": code,
                        "error": detail,
                    }],
                }));
            } else {
                eprintln!(
                    "{}",
                    crate::commands::scan::vendor_flow::format_vendor_step_error(code, detail)
                );
            }
            return 1;
        }
    }

    // Download phase — records in memory, blobs never persisted, the nested
    // apply structurally never runs (save_only): the vendor step IS the
    // persistence. Boxed: the future embeds the narrowing + fetch loop, and
    // `run`'s poll frame must fit Windows' 1 MiB main-thread stack.
    let params = get_download_params(
        args, /*save_only=*/ true, /*persist_blobs=*/ false,
    );
    let prefetched_views: HashMap<String, PatchResponse> = prefetched
        .map(|p| HashMap::from([(p.uuid.clone(), p.clone())]))
        .unwrap_or_default();
    let (dl_code, mut result, records) = if prefetched.is_some() {
        // The preflight above already read the lock: hand its outcome down.
        let vendor_state = load_state(&args.common.project_root()).await;
        Box::pin(download_patch_records_preflighted(
            selected,
            &params,
            api_client,
            prefetched_views,
            vendor_state,
            VendorRefusals {
                bun: bun_refusal.as_ref(),
                vlt: &vlt_refusals,
            },
            None,
        ))
        .await
    } else {
        Box::pin(download_patch_records_with(
            selected,
            &params,
            api_client,
            prefetched_views,
        ))
        .await
    };
    fold_narrowing_into_result(&mut result, narrow_skips, narrow_warnings);

    // The vendor step (scan's, verbatim): apply lock, in-memory staging
    // seeded with the blobs fetched above, the engine over exactly the
    // records fetched above (moved in — nothing here needs them afterwards)
    // and over this run's client, then the run's telemetry. A per-patch
    // download failure does not skip it (scan parity).
    match super::scan::boxed_vendor_step(super::scan::VendorStep {
        common: &args.common,
        records,
        client: api_client.clone(),
        use_public_proxy,
        report_empty: true,
        prior: None,
        download_errors: dl_code != 0,
        telemetry_auth: telemetry,
    })
    .await
    {
        Ok((has_errors, venv)) => {
            if args.common.json {
                result["status"] = serde_json::json!(if has_errors {
                    "partial_failure"
                } else {
                    "success"
                });
                result["vendor"] =
                    serde_json::to_value(&venv).unwrap_or_else(|_| serde_json::json!({}));
                print_json(&result);
            }
            i32::from(has_errors)
        }
        Err((code, message, venv)) => {
            if args.common.json {
                // A vendor envelope built before the failure (events
                // included) must reach the JSON consumer even though the
                // run aborts here.
                if let Some(venv) = venv {
                    result["vendor"] =
                        serde_json::to_value(&*venv).unwrap_or_else(|_| serde_json::json!({}));
                }
                crate::json_envelope::set_error(
                    &mut result,
                    crate::json_envelope::EnvelopeError::new(code, message),
                );
                print_json(&result);
            } else {
                eprintln!(
                    "{}",
                    crate::commands::scan::vendor_flow::format_vendor_step_error(code, &message)
                );
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::agent_download::{
        base64_decode, files_with_both_hashes, format_record_skip, format_save_summary,
        nested_apply_args_from_params, severity_rank, write_blob_entry, APPLY_FAILED,
    };
    use socket_patch_core::crawlers::CrawlerOptions;
    use socket_patch_core::manifest::records::record_from_patch_response;
    use socket_patch_core::manifest::schema::PatchRecord;
    use std::path::PathBuf;

    use socket_patch_core::api::types::{PatchFileResponse, VulnerabilityResponse};
    use std::collections::HashMap;

    // --- identifier classification (the shared core target grammar) -------

    /// `get`'s view of [`Target::parse`]: `None` for the bare-name fallback.
    fn detect_identifier_type(identifier: &str) -> Option<TargetKind> {
        let kind = Target::parse(identifier).kind();
        (kind != TargetKind::Name).then_some(kind)
    }

    #[test]
    fn detect_uuid_lowercase() {
        assert_eq!(
            detect_identifier_type("80630680-4da6-45f9-bba8-b888e0ffd58c"),
            Some(TargetKind::Uuid)
        );
    }

    #[test]
    fn detect_uuid_uppercase() {
        // Case-insensitive UUID regex per contract.
        assert_eq!(
            detect_identifier_type("80630680-4DA6-45F9-BBA8-B888E0FFD58C"),
            Some(TargetKind::Uuid)
        );
    }

    #[test]
    fn detect_cve_uppercase() {
        assert_eq!(
            detect_identifier_type("CVE-2021-44906"),
            Some(TargetKind::Cve)
        );
    }

    #[test]
    fn detect_cve_lowercase() {
        // Load-bearing: CVE detection must be case-insensitive.
        assert_eq!(
            detect_identifier_type("cve-2021-44906"),
            Some(TargetKind::Cve)
        );
    }

    #[test]
    fn detect_ghsa_uppercase() {
        assert_eq!(
            detect_identifier_type("GHSA-abcd-1234-wxyz"),
            Some(TargetKind::Ghsa)
        );
    }

    #[test]
    fn detect_ghsa_lowercase() {
        // Load-bearing: GHSA detection must be case-insensitive.
        assert_eq!(
            detect_identifier_type("ghsa-abcd-1234-wxyz"),
            Some(TargetKind::Ghsa)
        );
    }

    #[test]
    fn detect_purl() {
        assert_eq!(
            detect_identifier_type("pkg:npm/foo@1.0"),
            Some(TargetKind::Purl)
        );
    }

    #[test]
    fn detect_package_name_returns_none() {
        // Bare package names don't match any pattern; caller treats this as
        // Package via the `else` branch in run().
        assert_eq!(detect_identifier_type("minimist"), None);
    }

    #[test]
    fn detect_malformed_cve_returns_none() {
        assert_eq!(detect_identifier_type("CVE-not-a-year"), None);
    }

    #[test]
    fn detect_empty_string_returns_none() {
        assert_eq!(detect_identifier_type(""), None);
    }

    // --- select_patches ---------------------------------------------------

    fn human_args() -> GlobalArgs {
        GlobalArgs::default()
    }

    fn json_args() -> GlobalArgs {
        GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        }
    }

    fn mk_patch(uuid: &str, purl: &str, tier: &str, published_at: &str) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.into(),
            purl: purl.into(),
            published_at: published_at.into(),
            description: format!("desc-{uuid}"),
            license: "MIT".into(),
            tier: tier.into(),
            vulnerabilities: HashMap::<String, VulnerabilityResponse>::new(),
        }
    }

    /// `mk_patch` with a single vulnerability at the given severity, so the
    /// severity rung of the ranking is exercised.
    fn mk_patch_sev(
        uuid: &str,
        purl: &str,
        tier: &str,
        published_at: &str,
        severity: &str,
    ) -> PatchSearchResult {
        let mut p = mk_patch(uuid, purl, tier, published_at);
        p.vulnerabilities.insert(
            format!("GHSA-{uuid}"),
            VulnerabilityResponse {
                cves: vec![],
                summary: String::new(),
                severity: severity.into(),
                description: String::new(),
            },
        );
        p
    }

    #[test]
    fn select_free_user_one_free_patch_returns_it() {
        let patches = vec![mk_patch("u1", "pkg:npm/foo@1.0", "free", "2024-01-01")];
        let out = select_patches(&patches, false, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "u1");
    }

    #[test]
    fn select_paid_user_picks_highest_severity_not_most_recent() {
        // An authorized user's package has a fresh `low` patch and an older
        // `critical` one: taking the newest would leave the critical
        // unfixed.
        let patches = vec![
            mk_patch_sev("new_low", "pkg:npm/foo@1.0", "paid", "2026-06-01", "low"),
            mk_patch_sev(
                "old_crit",
                "pkg:npm/foo@1.0",
                "paid",
                "2024-01-01",
                "critical",
            ),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "old_crit");
    }

    #[test]
    fn select_paid_user_picks_free_critical_over_paid_low() {
        // Severity outranks tier: `tier` gates *access*, it does not rank.
        // A paid subscriber must not be handed a low-severity paid patch
        // when a critical free one exists for the same package.
        let patches = vec![
            mk_patch_sev("paid_low", "pkg:npm/foo@1.0", "paid", "2026-06-01", "low"),
            mk_patch_sev(
                "free_crit",
                "pkg:npm/foo@1.0",
                "free",
                "2024-01-01",
                "critical",
            ),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "free_crit");
        assert_eq!(out[0].tier, "free");
    }

    /// `mk_patch_sev` with one advisory per severity — two or more makes it
    /// a *merged* patch (see `api::ranking::merged_coverage`), which is
    /// inferred from the advisory count, not from any API flag.
    fn mk_patch_multi(
        uuid: &str,
        purl: &str,
        tier: &str,
        published_at: &str,
        severities: &[&str],
    ) -> PatchSearchResult {
        let mut p = mk_patch(uuid, purl, tier, published_at);
        for (i, sev) in severities.iter().enumerate() {
            p.vulnerabilities.insert(
                format!("GHSA-{uuid}-{i}"),
                VulnerabilityResponse {
                    cves: vec![],
                    summary: String::new(),
                    severity: (*sev).into(),
                    description: String::new(),
                },
            );
        }
        p
    }

    #[test]
    fn select_prefers_merged_patch_when_severities_tie() {
        // The general preference: `z_merged` remediates two HIGH advisories
        // in one blob, `a_single` only one. Severities tie, so breadth
        // decides. `a_single` is both newer AND earlier by uuid, so only
        // the coverage rung can produce this result.
        let patches = vec![
            mk_patch_sev("a_single", "pkg:npm/foo@1.0", "paid", "2026-06-01", "high"),
            mk_patch_multi(
                "z_merged",
                "pkg:npm/foo@1.0",
                "free",
                "2020-01-01",
                &["high", "high"],
            ),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "z_merged");
    }

    #[test]
    fn select_prefers_a_higher_severity_patch_over_a_lower_severity_merge() {
        let patches = vec![
            mk_patch_sev(
                "a_critical",
                "pkg:npm/foo@1.0",
                "free",
                "2026-06-01",
                "critical",
            ),
            mk_patch_multi(
                "z_merged",
                "pkg:npm/foo@1.0",
                "free",
                "2020-01-01",
                &["high", "high"],
            ),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "a_critical");
    }

    #[test]
    fn select_prefers_more_fixes_between_equal_severity_merges() {
        let patches = vec![
            mk_patch_multi(
                "a_newer",
                "pkg:npm/foo@1.0",
                "free",
                "2026-06-01",
                &["high", "high"],
            ),
            mk_patch_multi(
                "z_broader",
                "pkg:npm/foo@1.0",
                "free",
                "2020-01-01",
                &["high", "low", "low"],
            ),
        ];
        let mut args = human_args();
        args.yes = true;
        for can_access_paid in [true, false] {
            let out = select_patches(&patches, can_access_paid, &args).expect("ok");
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].uuid, "z_broader");
        }
    }

    #[test]
    fn select_recency_is_chronological_not_lexicographic() {
        // `publishedAt` is RFC 2822 on the wire, so a raw-string compare
        // would order by weekday name. With equal severities the newer
        // patch must win regardless of which weekday it fell on.
        let older = "Wed, 01 Jan 2025 00:00:00 GMT";
        let newer = "Fri, 01 Aug 2026 00:00:00 GMT";
        assert!(older > newer, "precondition: raw strings sort backwards");
        // Adversarial UUIDs: `a_older` sorts first, so the final uuid
        // tiebreak points at the wrong patch and cannot rescue this test if
        // the date rung breaks.
        let patches = vec![
            mk_patch_sev("a_older", "pkg:npm/foo@1.0", "paid", older, "high"),
            mk_patch_sev("z_newer", "pkg:npm/foo@1.0", "paid", newer, "high"),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "z_newer");
    }

    #[test]
    fn select_recency_uses_the_patch_date_not_the_package_release_date() {
        // Real production pair: both patches are for `axios@1.6.0` — one
        // package version, one upstream release date (2023-10-26) — yet
        // they carry different publish dates because the field describes
        // the PATCH. Severities tie, so the date is the deciding rung.
        //
        // Non-vacuity: `0bc312a6` < `83f5a654`, so if the ranking ever fell
        // back to the UUID tiebreak (which is what a package-level date
        // would cause, both keys being equal) this would select the OLDER
        // patch and fail.
        let patches = vec![
            mk_patch_sev(
                "0bc312a6",
                "pkg:npm/axios@1.6.0",
                "free",
                "Fri, 27 Mar 2026 19:12:42 GMT",
                "HIGH",
            ),
            mk_patch_sev(
                "83f5a654",
                "pkg:npm/axios@1.6.0",
                "free",
                "Mon, 03 Aug 2026 20:23:06 GMT",
                "HIGH",
            ),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1, "one patch per PURL");
        assert_eq!(out[0].uuid, "83f5a654");
    }

    #[test]
    fn select_returns_purl_sorted_output() {
        // The grouping map has randomized iteration order; without an
        // explicit sort the download sequence (and every JSON array derived
        // from it) would differ run to run.
        let patches = vec![
            mk_patch("c", "pkg:npm/ccc@1.0", "paid", "2024-01-01"),
            mk_patch("a", "pkg:npm/aaa@1.0", "paid", "2024-01-01"),
            mk_patch("b", "pkg:npm/bbb@1.0", "paid", "2024-01-01"),
        ];
        for _ in 0..8 {
            let out = select_patches(&patches, true, &human_args()).expect("ok");
            let purls: Vec<&str> = out.iter().map(|p| p.purl.as_str()).collect();
            assert_eq!(
                purls,
                ["pkg:npm/aaa@1.0", "pkg:npm/bbb@1.0", "pkg:npm/ccc@1.0"]
            );
        }
    }

    #[test]
    fn select_paid_user_prefers_paid_when_everything_else_ties() {
        // Tier survives only as a late tiebreak: same advisory count, same
        // (absent) severity, same publish date → paid wins.
        let patches = vec![
            mk_patch("free1", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("paid1", "pkg:npm/foo@1.0", "paid", "2024-01-01"),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "paid1");
        assert_eq!(out[0].tier, "paid");
    }

    #[test]
    fn select_paid_user_picks_most_recent_paid() {
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "paid", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "paid", "2024-06-01"),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
    }

    #[test]
    fn select_paid_user_falls_back_to_most_recent_free_when_no_paid() {
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
    }

    #[test]
    fn select_free_user_multi_free_json_mode_errors() {
        // JSON mode requires explicit selection; multiple free patches in JSON
        // mode means the caller must pass --id.
        let patches = vec![
            mk_patch("a", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("b", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let err = select_patches(&patches, false, &json_args()).expect_err("should fail");
        assert_eq!(err, 1);
    }

    #[test]
    fn select_empty_input_returns_empty() {
        let out = select_patches(&[], false, &human_args()).expect("ok");
        assert!(out.is_empty());
        let out = select_patches(&[], true, &human_args()).expect("ok");
        assert!(out.is_empty());
        let out = select_patches(&[], false, &json_args()).expect("ok");
        assert!(out.is_empty());
    }

    #[test]
    fn select_free_user_paid_filtered_out_then_single_free_auto_selects() {
        // Free user: paid patch is filtered out before grouping; only the free
        // patch survives, and since the group has exactly one entry it
        // auto-selects without hitting the interactive path.
        let patches = vec![
            mk_patch("paid", "pkg:npm/foo@1.0", "paid", "2024-06-01"),
            mk_patch("free", "pkg:npm/foo@1.0", "free", "2024-01-01"),
        ];
        let out = select_patches(&patches, false, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "free");
        assert_eq!(out[0].tier, "free");
    }

    // --- decide_patch_action ---------------------------------------------
    // Locks in the per-patch action vocabulary surfaced by
    // download_and_apply_patches_with in JSON mode. See CLI_CONTRACT.md.

    fn manifest_with_entry(purl: &str, uuid: &str) -> PatchManifest {
        let mut m = PatchManifest::new();
        m.patches.insert(
            purl.to_string(),
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: String::new(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: "free".to_string(),
            },
        );
        m
    }

    #[test]
    fn decide_patch_action_added_when_purl_absent() {
        let manifest = PatchManifest::new();
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/foo@1.0", "uuid-a"),
            PatchAction::Added,
        );
    }

    #[test]
    fn decide_patch_action_skipped_when_same_uuid() {
        let manifest = manifest_with_entry("pkg:npm/foo@1.0", "uuid-a");
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/foo@1.0", "uuid-a"),
            PatchAction::Skipped,
        );
    }

    #[test]
    fn decide_patch_action_updated_when_different_uuid() {
        let manifest = manifest_with_entry("pkg:npm/foo@1.0", "uuid-a");
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/foo@1.0", "uuid-b"),
            PatchAction::Updated {
                old_uuid: "uuid-a".to_string()
            },
        );
    }

    #[test]
    fn decide_patch_action_added_for_different_purl_even_with_overlapping_manifest() {
        // Ensure update detection keys on PURL, not UUID. A new PURL with a
        // UUID that happens to match an existing entry under a different
        // PURL must still be `Added`.
        let manifest = manifest_with_entry("pkg:npm/foo@1.0", "uuid-a");
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/bar@2.0", "uuid-a"),
            PatchAction::Added,
        );
    }

    // --- severity_rank / max_vuln_severity / patch_event_metadata --------
    // Pins the JSON shape of the metadata spliced into `added` / `updated`
    // per-patch records by `download_and_apply_patches_with`. PR-comment bots
    // rely on these fields — see CLI_CONTRACT.md (`get` / `scan` JSON
    // output, patches array).

    #[test]
    fn severity_rank_orders_canonical_labels() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        // GHSA's `moderate` is treated as medium.
        assert_eq!(severity_rank("moderate"), severity_rank("medium"));
        // Unknown / blank labels rank below all known severities.
        assert!(severity_rank("low") > severity_rank(""));
        assert!(severity_rank("low") > severity_rank("unknown"));
    }

    #[test]
    fn max_vuln_severity_picks_highest() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-low".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-low".into()],
                summary: String::new(),
                severity: "low".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-crit".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-crit".into()],
                summary: String::new(),
                severity: "critical".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-mod".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-mod".into()],
                summary: String::new(),
                severity: "moderate".into(),
                description: String::new(),
            },
        );
        assert_eq!(max_vuln_severity(&vulns).as_deref(), Some("critical"));
    }

    #[test]
    fn max_vuln_severity_returns_none_for_empty() {
        assert_eq!(max_vuln_severity(&HashMap::new()), None);
    }

    #[test]
    fn max_vuln_severity_returns_none_when_all_unrecognized() {
        // Non-empty map but every severity is off-canon (rank 0). Per the
        // doc contract this must be `None` — NOT `Some("")`/`Some("unknown")`.
        // Regression guard: `max_by_key` alone returns the element for any
        // non-empty map, leaking a garbage severity label.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-a".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: "informational".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-b".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: String::new(),
                description: String::new(),
            },
        );
        assert_eq!(max_vuln_severity(&vulns), None);
    }

    #[test]
    fn max_vuln_severity_recognized_wins_over_unrecognized() {
        // A single recognized severity alongside unrecognized ones must
        // surface — the rank-0 filter only suppresses the all-unrecognized
        // case, never a real label.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-junk".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: "unknown".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-real".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: "low".into(),
                description: String::new(),
            },
        );
        assert_eq!(max_vuln_severity(&vulns).as_deref(), Some("low"));
    }

    #[test]
    fn patch_event_metadata_omits_severity_when_all_unrecognized() {
        // The consumer-facing contract: a patch whose vulnerabilities all
        // carry non-canonical severities must NOT emit a `severity` key
        // (it would otherwise be `""`), while still listing the vulns.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-aaaa-bbbb-cccc".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-0001".into()],
                summary: "Something".into(),
                severity: "informational".into(),
                description: String::new(),
            },
        );
        let patch = PatchResponse {
            uuid: String::new(),
            purl: String::new(),
            published_at: "ts".into(),
            files: HashMap::new(),
            vulnerabilities: vulns,
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let meta = patch_event_metadata(&patch);
        assert!(meta.as_object().unwrap().get("severity").is_none());
        // The vulnerability itself is still surfaced (with its raw label).
        let vulns_out = meta["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns_out.len(), 1);
        assert_eq!(vulns_out[0]["severity"], "informational");
    }

    #[test]
    fn patch_event_metadata_includes_all_keys() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-aaaa-bbbb-cccc".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-12345".into()],
                summary: "Prototype Pollution".into(),
                severity: "high".into(),
                description: "merge() does not check Object.prototype".into(),
            },
        );
        let patch = PatchResponse {
            uuid: "11111111-1111-4111-8111-111111111111".into(),
            purl: "pkg:npm/minimist@1.2.2".into(),
            published_at: "2024-01-01T00:00:00Z".into(),
            files: HashMap::new(),
            vulnerabilities: vulns,
            description: "Fixes prototype pollution in minimist".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let meta = patch_event_metadata(&patch);
        assert_eq!(meta["description"], "Fixes prototype pollution in minimist");
        assert_eq!(meta["license"], "MIT");
        assert_eq!(meta["tier"], "free");
        assert_eq!(meta["exportedAt"], "2024-01-01T00:00:00Z");
        assert_eq!(meta["severity"], "high");
        let vulns_out = meta["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns_out.len(), 1);
        assert_eq!(vulns_out[0]["id"], "GHSA-aaaa-bbbb-cccc");
        assert_eq!(vulns_out[0]["cves"][0], "CVE-2024-12345");
        assert_eq!(vulns_out[0]["severity"], "high");
        assert_eq!(vulns_out[0]["summary"], "Prototype Pollution");
    }

    #[test]
    fn patch_event_metadata_sorts_vulnerabilities_by_id() {
        // HashMap iteration is otherwise nondeterministic — verify the
        // output is stable so test snapshots and consumer diffs don't
        // flap.
        let mut vulns = HashMap::new();
        for id in ["GHSA-zzz", "GHSA-aaa", "GHSA-mmm"] {
            vulns.insert(
                id.into(),
                VulnerabilityResponse {
                    cves: Vec::new(),
                    summary: String::new(),
                    severity: "low".into(),
                    description: String::new(),
                },
            );
        }
        let patch = PatchResponse {
            uuid: String::new(),
            purl: String::new(),
            published_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: vulns,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        let meta = patch_event_metadata(&patch);
        let ids: Vec<&str> = meta["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["GHSA-aaa", "GHSA-mmm", "GHSA-zzz"]);
    }

    #[test]
    fn patch_event_metadata_omits_severity_when_no_vulns() {
        let patch = PatchResponse {
            uuid: String::new(),
            purl: String::new(),
            published_at: "ts".into(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let meta = patch_event_metadata(&patch);
        // `severity` is intentionally omitted (not null) when there
        // aren't any vulnerabilities to derive it from — consumers
        // should treat absence as "no severity available".
        assert!(meta.as_object().unwrap().get("severity").is_none());
        // The empty vulnerabilities array is still present so the
        // shape stays consistent.
        assert_eq!(meta["vulnerabilities"].as_array().unwrap().len(), 0);
    }

    // --- run_outcome -----------------------------------------------------
    // The `status` field and the process exit code are derived from the
    // same predicate: a failed *apply* step (no download failures) must
    // still report `partial_failure` AND exit 1.

    #[test]
    fn run_outcome_clean_is_success_exit_zero() {
        assert_eq!(run_outcome(false, false), ("success", 0));
    }

    #[test]
    fn run_outcome_download_failure_is_partial_exit_one() {
        assert_eq!(run_outcome(true, false), ("partial_failure", 1));
    }

    #[test]
    fn run_outcome_apply_failure_alone_is_partial_exit_one() {
        // The load-bearing case: nothing failed to download, but the apply
        // step failed. status MUST agree with the non-zero exit code.
        assert_eq!(run_outcome(false, true), ("partial_failure", 1));
    }

    #[test]
    fn run_outcome_both_failures_is_partial_exit_one() {
        assert_eq!(run_outcome(true, true), ("partial_failure", 1));
    }

    #[test]
    fn run_outcome_status_and_exit_never_disagree() {
        // Exhaustive: a `success` status iff exit 0, `partial_failure` iff
        // exit 1, for every input combination.
        for pf in [false, true] {
            for af in [false, true] {
                let (status, code) = run_outcome(pf, af);
                assert_eq!(
                    status == "success",
                    code == 0,
                    "status/exit disagree for patches_failed={pf}, apply_failed={af}"
                );
            }
        }
    }

    // --- fold_apply_failures (#424) ---------------------------------------

    fn failure(purl: &str, code: &str, error: &str) -> crate::commands::apply::ApplyFailure {
        crate::commands::apply::ApplyFailure {
            purl: purl.to_string(),
            code: code.to_string(),
            error: error.to_string(),
        }
    }

    fn report_with(
        failures: Vec<crate::commands::apply::ApplyFailure>,
        applied: &[&str],
    ) -> ApplyRunReport {
        ApplyRunReport {
            code: 1,
            failures,
            run_error: None,
            applied: applied.iter().map(|p| p.to_string()).collect(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn fold_apply_failures_marks_the_failed_record_and_drops_metadata() {
        let mut env = serde_json::json!({
            "failed": 0,
            "patches": [
                {"purl": "pkg:npm/a@1.0.0", "uuid": "ua", "action": "added", "license": "MIT"},
                {"purl": "pkg:npm/b@1.0.0", "uuid": "ub", "action": "updated", "oldUuid": "o"},
            ],
        });
        let report = report_with(
            vec![failure("pkg:npm/a@1.0.0", "apply_failed", "denied")],
            &["pkg:npm/b@1.0.0"],
        );
        assert_eq!(
            fold_apply_failures(&mut env, &report, |_| None),
            1,
            "b applied"
        );
        assert_eq!(
            env["patches"][0],
            serde_json::json!({
                "purl": "pkg:npm/a@1.0.0", "uuid": "ua", "action": "failed",
                "errorCode": "apply_failed", "error": "denied",
            })
        );
        assert_eq!(env["patches"][1]["action"], "updated", "{env}");
        assert_eq!(env["failed"], 1, "{env}");
        assert!(env.get("errorCode").is_none(), "{env}");
    }

    #[test]
    fn fold_apply_failures_matches_percent_encoded_and_base_purl_keys() {
        let mut env = serde_json::json!({
            "failed": 0,
            "patches": [
                {"purl": "pkg:npm/%40scope/a@1.0.0", "uuid": "u1", "action": "added"},
                {"purl": "pkg:pypi/six@1.16.0?artifact_id=w", "uuid": "u2", "action": "added"},
            ],
        });
        // An unqualified (base) key covers its qualified release variants.
        let report = report_with(
            vec![
                failure("pkg:npm/@scope/a@1.0.0", "apply_failed", "x"),
                failure("pkg:pypi/six@1.16.0", "package_not_installed", "y"),
            ],
            &[],
        );
        assert_eq!(fold_apply_failures(&mut env, &report, |_| None), 0);
        assert_eq!(env["patches"][0]["action"], "failed", "{env}");
        assert_eq!(env["patches"][1]["action"], "failed", "{env}");
        assert_eq!(env["patches"][1]["errorCode"], "package_not_installed");
        assert_eq!(env["patches"].as_array().unwrap().len(), 2, "{env}");
        assert_eq!(env["failed"], 2, "{env}");
    }

    #[test]
    fn fold_apply_failures_never_blames_a_sibling_variant() {
        // A qualified failure that matches no selected record must not be
        // pinned on a selected sibling variant that applied: it gets its
        // own record, and the sibling stays applied.
        let mut env = serde_json::json!({
            "failed": 0,
            "patches": [
                {"purl": "pkg:pypi/six@1.16.0?artifact_id=w", "uuid": "u1", "action": "added"},
            ],
        });
        let report = report_with(
            vec![failure(
                "pkg:pypi/six@1.16.0?artifact_id=s",
                "apply_failed",
                "boom",
            )],
            &["pkg:pypi/six@1.16.0?artifact_id=w"],
        );
        let uuid_of = |p: &str| p.ends_with("=s").then(|| "u0".to_string());
        assert_eq!(fold_apply_failures(&mut env, &report, uuid_of), 1);
        assert_eq!(env["patches"][0]["action"], "added", "{env}");
        assert_eq!(
            env["patches"][1]["purl"],
            "pkg:pypi/six@1.16.0?artifact_id=s"
        );
        assert_eq!(env["patches"][1]["uuid"], "u0", "{env}");
        assert_eq!(env["patches"][1]["action"], "failed", "{env}");
        assert_eq!(env["failed"], 1, "{env}");
    }

    #[test]
    fn fold_apply_failures_counts_only_patches_apply_reported_applied() {
        // `c` is selected and recorded but apply never patched it (not
        // installed: only a warning beside `a`'s real failure), so it must
        // not count as applied.
        let mut env = serde_json::json!({
            "failed": 0,
            "patches": [
                {"purl": "pkg:npm/a@1.0.0", "uuid": "ua", "action": "added"},
                {"purl": "pkg:npm/b@1.0.0", "uuid": "ub", "action": "skipped"},
                {"purl": "pkg:npm/c@1.0.0", "uuid": "uc", "action": "added"},
                {"purl": "pkg:npm/d@1.0.0", "uuid": "ud", "action": "skipped",
                 "errorCode": "package_not_installed"},
            ],
        });
        let report = report_with(
            vec![failure("pkg:npm/a@1.0.0", "apply_failed", "x")],
            &["pkg:npm/b@1.0.0", "pkg:npm/d@1.0.0"],
        );
        assert_eq!(
            fold_apply_failures(&mut env, &report, |_| None),
            1,
            "only the already-recorded b applied: {env}"
        );
        assert_eq!(env["patches"][2]["action"], "added", "{env}");
        assert_eq!(env["failed"], 1, "{env}");
    }

    #[test]
    fn fold_apply_failures_appends_an_unselected_manifest_failure() {
        // The nested apply covers the whole (ecosystem-scoped) manifest: a
        // failing record this run did not select still gets named, without
        // costing this run's own patch its `applied` count.
        let mut env = serde_json::json!({
            "failed": 1,
            "patches": [
                {"purl": "pkg:npm/a@1.0.0", "uuid": "ua", "action": "added"},
            ],
        });
        let report = report_with(
            vec![failure("pkg:npm/old@2.0.0", "apply_failed", "z")],
            &["pkg:npm/a@1.0.0"],
        );
        let uuid_of = |p: &str| (p == "pkg:npm/old@2.0.0").then(|| "uo".to_string());
        assert_eq!(fold_apply_failures(&mut env, &report, uuid_of), 1);
        assert_eq!(env["patches"][0]["action"], "added", "{env}");
        assert_eq!(
            env["patches"][1],
            serde_json::json!({
                "purl": "pkg:npm/old@2.0.0", "uuid": "uo", "action": "failed",
                "errorCode": "apply_failed", "error": "z",
            })
        );
        assert_eq!(env["failed"], 2, "download failures stay counted: {env}");
    }

    #[test]
    fn fold_apply_failures_carries_a_run_level_error() {
        let mut env = serde_json::json!({
            "failed": 0,
            "patches": [{"purl": "pkg:npm/a@1.0.0", "uuid": "ua", "action": "added"}],
        });
        let report = ApplyRunReport {
            code: 1,
            failures: Vec::new(),
            run_error: Some(("yarn_pnp_unsupported".to_string(), "pnp".to_string())),
            applied: Vec::new(),
            warnings: Vec::new(),
        };
        assert_eq!(fold_apply_failures(&mut env, &report, |_| None), 0);
        assert!(env.get("errorCode").is_none(), "{env}");
        assert_eq!(
            env["error"],
            serde_json::json!({"code": "yarn_pnp_unsupported", "message": "pnp"}),
            "{env}"
        );
        assert_eq!(env["failed"], 0, "{env}");
    }

    // --- write_blob_entry ------------------------------------------------
    // Blob hashes come straight from the API response and are used as
    // filesystem path components (`blobs_dir.join(hash)`). A hostile or
    // compromised API/proxy returning `afterHash: "../../x"` must not be
    // able to write outside the blobs directory.

    // "patched\n" in base64 — a valid payload so only the hash is at fault.
    const BLOB_B64: &str = "cGF0Y2hlZAo=";
    /// base64 of `"pristine\n"`.
    const PRISTINE_B64: &str = "cHJpc3RpbmUK";

    #[tokio::test]
    async fn write_blob_entry_rejects_relative_traversal_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let res = write_blob_entry(
            &blobs_dir,
            BLOB_B64,
            "../escaped",
            "package/index.js",
            "blob",
        )
        .await;
        assert!(
            res.is_err(),
            "a traversal hash must be rejected, got {res:?}"
        );
        assert!(
            !tmp.path().join("escaped").exists(),
            "traversal hash must not write outside the blobs dir"
        );
    }

    #[tokio::test]
    async fn write_blob_entry_rejects_absolute_path_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        // An absolute "hash" makes Path::join discard blobs_dir entirely.
        let target = tmp.path().join("abs_escape");
        let res = write_blob_entry(
            &blobs_dir,
            BLOB_B64,
            target.to_str().unwrap(),
            "package/index.js",
            "blob",
        )
        .await;
        assert!(
            res.is_err(),
            "an absolute-path hash must be rejected, got {res:?}"
        );
        assert!(
            !target.exists(),
            "absolute-path hash must not write outside the blobs dir"
        );
    }

    #[tokio::test]
    async fn write_blob_entry_accepts_valid_sha256_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let hash = git_sha256(b"patched\n");
        let created = write_blob_entry(&blobs_dir, BLOB_B64, &hash, "package/index.js", "blob")
            .await
            .expect("a canonical 64-hex hash must be accepted");
        assert!(created);
        let written = std::fs::read(blobs_dir.join(&hash)).unwrap();
        assert_eq!(written, b"patched\n");
    }

    fn git_sha256(bytes: &[u8]) -> String {
        socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
    }

    /// #726: inline content that does not hash to its name writes nothing,
    /// and a verified blob already in the store is never replaced.
    #[tokio::test]
    async fn write_blob_entry_verifies_content_against_its_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");

        let wrong = "1111111111111111111111111111111111111111111111111111111111111111";
        let err = write_blob_entry(&blobs_dir, BLOB_B64, wrong, "package/index.js", "blob")
            .await
            .unwrap_err();
        assert!(err.contains("content hash mismatch"), "{err}");
        assert!(!blobs_dir.join(wrong).exists(), "nothing written");

        let pristine = git_sha256(b"pristine\n");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();
        tokio::fs::write(blobs_dir.join(&pristine), b"pristine\n")
            .await
            .unwrap();
        write_blob_entry(&blobs_dir, BLOB_B64, &pristine, "package/index.js", "blob")
            .await
            .unwrap_err();
        assert_eq!(
            std::fs::read(blobs_dir.join(&pristine)).unwrap(),
            b"pristine\n",
            "a verified blob is byte-identical afterwards"
        );
        let created = write_blob_entry(&blobs_dir, PRISTINE_B64, &pristine, "f", "blob")
            .await
            .unwrap();
        assert!(!created, "an existing verified blob is not re-created");
    }

    /// B24: a committed `.socket/blobs/<hash>` (or `.socket/blobs`) symlink
    /// must not redirect the write out of the project.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_blob_entry_refuses_a_linked_blob_or_blobs_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let hash = git_sha256(b"patched\n");

        let socket = tmp.path().join("p/.socket");
        let blobs_dir = socket.join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        std::os::unix::fs::symlink(&victim, blobs_dir.join(&hash)).unwrap();
        let err = write_blob_entry(&blobs_dir, BLOB_B64, &hash, "package/index.js", "blob")
            .await
            .unwrap_err();
        assert!(err.contains("is a symlink"), "{err}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");

        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let socket2 = tmp.path().join("q/.socket");
        std::fs::create_dir_all(&socket2).unwrap();
        std::os::unix::fs::symlink(&outside, socket2.join("blobs")).unwrap();
        let err = write_blob_entry(&socket2.join("blobs"), BLOB_B64, &hash, "f", "blob")
            .await
            .unwrap_err();
        assert!(err.contains("is a symlink"), "{err}");
        assert!(
            !outside.join(&hash).exists(),
            "nothing written through the link"
        );
    }

    #[test]
    fn base64_decode_tolerates_line_breaks_and_missing_padding() {
        assert_eq!(base64_decode("cGF0\nY2hlZAo=").unwrap(), b"patched\n");
        assert_eq!(base64_decode("cGF0Y2hlZAo").unwrap(), b"patched\n");
    }

    // --- files_for_manifest / files_with_both_hashes ---------------------
    // The download/scan/vendor record builder: a net-new file (afterHash, NO
    // beforeHash) that the patch ADDS must be retained in the manifest
    // record, not silently dropped. E.g. the whole-crate cargo export for
    // `pkg:cargo/traitobject@0.1.1` publishes ALL files with only an
    // afterHash.

    fn file_resp(before: Option<&str>, after: Option<&str>) -> PatchFileResponse {
        PatchFileResponse {
            before_hash: before.map(|s| s.to_string()),
            after_hash: after.map(|s| s.to_string()),
            socket_blob: None,
            blob_content: None,
            before_blob_content: None,
        }
    }

    fn patch_with_files(files: HashMap<String, PatchFileResponse>) -> PatchResponse {
        PatchResponse {
            uuid: "cf2e6f58-0000-4000-8000-000000000000".into(),
            purl: "pkg:cargo/traitobject@0.1.1".into(),
            published_at: "Fri, 27 Mar 2026 19:12:42 GMT".into(),
            files,
            vulnerabilities: HashMap::new(),
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        }
    }

    #[test]
    fn files_for_manifest_retains_new_file_without_before_hash() {
        // A patch that ADDS a new file (afterHash, no beforeHash) — e.g.
        // the gem `lib/rubygems_plugin.rb` runtime guard — must be kept.
        let mut files = HashMap::new();
        files.insert(
            "lib/rubygems_plugin.rb".to_string(),
            file_resp(None, Some("a".repeat(64).as_str())),
        );
        files.insert(
            "lib/existing.rb".to_string(),
            file_resp(Some(&"b".repeat(64)), Some(&"c".repeat(64))),
        );
        let patch = patch_with_files(files);

        let kept = files_for_manifest(&patch);
        // Both files retained: the modified one AND the added one.
        assert_eq!(kept.len(), 2);
        let added = kept
            .get("lib/rubygems_plugin.rb")
            .expect("new file must be retained in the manifest record");
        // New files record an empty-string beforeHash sentinel.
        assert_eq!(added.before_hash, "");
        assert_eq!(added.after_hash, "a".repeat(64));

        // The both-hashes rule (used only for installed-variant matching)
        // drops the added file.
        let strict = files_with_both_hashes(&patch);
        assert_eq!(strict.len(), 1);
        assert!(!strict.contains_key("lib/rubygems_plugin.rb"));
    }

    #[test]
    fn files_for_manifest_keeps_all_new_file_whole_crate_export() {
        // EVERY file is a whole-crate export with only an afterHash: all 9
        // are retained so the record is non-empty and can be applied.
        let mut files = HashMap::new();
        for i in 0..9 {
            files.insert(
                format!("src/file{i}.rs"),
                file_resp(None, Some(&format!("{i:064x}"))),
            );
        }
        let patch = patch_with_files(files);

        let kept = files_for_manifest(&patch);
        assert_eq!(kept.len(), 9, "all whole-crate-export files must be kept");
        assert!(kept.values().all(|f| f.before_hash.is_empty()));

        // Guardrail precondition: the both-hashes rule yields an empty map.
        assert!(files_with_both_hashes(&patch).is_empty());
    }

    #[test]
    fn build_patch_record_from_new_files_is_not_empty() {
        // The record built from a new-files-only patch must carry files —
        // an empty `files` map is what the guardrail treats as a
        // non-applicable (failed), never a successful `applied:1`, patch.
        let mut files = HashMap::new();
        files.insert(
            "src/lib.rs".to_string(),
            file_resp(None, Some(&"d".repeat(64))),
        );
        let patch = patch_with_files(files);

        let (purl, record) = record_from_patch_response(&patch);
        assert_eq!(purl, "pkg:cargo/traitobject@0.1.1");
        assert!(
            !record.files.is_empty(),
            "record_from_patch_response must retain patch-added files"
        );

        // A genuinely empty patch (no afterHash anywhere) yields an empty
        // record — the guardrail-triggering condition the download/apply
        // flows now count as failed rather than applied.
        let mut broken = HashMap::new();
        broken.insert(
            "src/lib.rs".to_string(),
            file_resp(Some(&"e".repeat(64)), None),
        );
        let broken_patch = patch_with_files(broken);
        assert!(
            files_for_manifest(&broken_patch).is_empty(),
            "a patch with no afterHash produces an empty (guardrail) files map"
        );
    }

    // --- base64_decode -----------------------------------------------------
    // Blob content comes straight from the API; a corrupted payload must
    // surface as a decode error (which write_blob_entry turns into a
    // per-file failure), never as garbage bytes silently written to disk.

    #[test]
    fn base64_decode_rejects_invalid_character() {
        let err = base64_decode("ab!cd").expect_err("'!' is not in the base64 alphabet");
        assert!(
            err.contains("Invalid base64 character"),
            "error must say what went wrong; got: {err}"
        );
        assert!(
            err.contains('!'),
            "error must name the offending character; got: {err}"
        );
    }

    // --- write_all_patch_blobs ---------------------------------------------
    // The per-patch fan-out over write_blob_entry: the FIRST bad entry must
    // fail the whole patch (Err(())) and leave nothing outside the blobs
    // dir. This is the branch every blob-failure flow downstream keys on.

    #[tokio::test]
    async fn write_all_patch_blobs_traversal_hash_fails_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let mut files = HashMap::new();
        let mut info = file_resp(None, Some("../escaped"));
        info.blob_content = Some(BLOB_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let patch = patch_with_files(files);

        let res = write_all_patch_blobs(&blobs_dir, &patch, /*quiet=*/ true).await;
        assert_eq!(res, Err(()), "a traversal afterHash must fail the patch");
        assert!(
            !tmp.path().join("escaped").exists(),
            "nothing may be written outside the blobs dir"
        );
        assert!(
            !blobs_dir.exists(),
            "no blob may be written for a rejected patch, and the empty blobs/ husk is pruned"
        );
    }

    /// A patch that fails HALF-WAY (its after-blob landed, its before-blob is
    /// rejected) must not leave the first blob behind as an orphan no record
    /// points at: the blobs this call created are unwound and the emptied
    /// `blobs/` pruned. The after entry is always written before the before
    /// entry of the same file, so one file suffices to pin the order.
    #[tokio::test]
    async fn write_all_patch_blobs_unwinds_its_own_blobs_on_a_later_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join(".socket/blobs");

        // A REAL git-sha256 name, so the after-blob verifies and lands
        // before the before-blob's traversal hash is rejected.
        let after = git_sha256(b"patched\n");
        let mut files = HashMap::new();
        let mut info = file_resp(Some("../escaped"), Some(&after));
        info.blob_content = Some(BLOB_B64.to_string());
        info.before_blob_content = Some(PRISTINE_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let patch = patch_with_files(files);

        let res = write_all_patch_blobs(&blobs_dir, &patch, /*quiet=*/ true).await;
        assert_eq!(res, Err(()));
        assert!(
            !tmp.path().join(".socket/escaped").exists(),
            "nothing is written at the traversal target"
        );
        assert!(
            !blobs_dir.join(&after).exists(),
            "the after-blob written before the failure is unwound"
        );
        assert!(!blobs_dir.exists(), "the emptied blobs/ husk is pruned");
        assert!(
            tmp.path().join(".socket").is_dir(),
            "the prune stops at .socket/ (the lock guard's to remove)"
        );
    }

    /// The unwind removes only blobs THIS call created: a blob that already
    /// existed (a live record's revert data, content-addressed and shared)
    /// survives a later failure of the same patch byte-identical.
    #[tokio::test]
    async fn write_all_patch_blobs_unwind_spares_preexisting_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();
        let after = git_sha256(b"patched\n");
        tokio::fs::write(blobs_dir.join(&after), b"patched\n")
            .await
            .unwrap();

        let mut files = HashMap::new();
        let mut info = file_resp(Some("../escaped"), Some(&after));
        info.blob_content = Some(BLOB_B64.to_string());
        info.before_blob_content = Some(PRISTINE_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let patch = patch_with_files(files);

        let res = write_all_patch_blobs(&blobs_dir, &patch, /*quiet=*/ true).await;
        assert_eq!(res, Err(()));
        assert_eq!(
            tokio::fs::read(blobs_dir.join(&after)).await.unwrap(),
            b"patched\n",
            "a pre-existing blob is never this call's to remove"
        );

        // And a fully successful write reports exactly the NEW hashes.
        let before = git_sha256(b"pristine\n");
        let mut files = HashMap::new();
        let mut info = file_resp(Some(&before), Some(&after));
        info.blob_content = Some(BLOB_B64.to_string());
        info.before_blob_content = Some(PRISTINE_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let created = write_all_patch_blobs(&blobs_dir, &patch_with_files(files), true)
            .await
            .unwrap();
        assert_eq!(
            created,
            vec![before.clone()],
            "the pre-existing after-blob is not new"
        );
        assert!(blobs_dir.join(&before).is_file());
    }

    // --- fold_narrowing_into_result ----------------------------------------
    // Hosted runs stack release-variant warnings (already in the envelope as
    // strings) with coarse-narrowing PnP warnings folded in later; the merge
    // must PRESERVE the existing strings and append the new `(code) detail`
    // ones, while skip records bump found/skipped and extend patches[].

    #[test]
    fn fold_narrowing_merges_into_existing_warnings_and_counts() {
        let mut result = serde_json::json!({
            "status": "success",
            "found": 1,
            "skipped": 0,
            "patches": [{"purl": "pkg:npm/kept@1.0.0", "action": "added"}],
            "warnings": ["existing variant warning"],
        });
        let skips = vec![serde_json::json!({
            "purl": "pkg:npm/skipped@1.0.0", "uuid": "u",
            "action": "skipped", "errorCode": "package_not_installed",
        })];
        let warnings = vec![(
            "yarn_pnp_unsupported".to_string(),
            "PnP layout detail".to_string(),
        )];
        fold_narrowing_into_result(&mut result, &skips, &warnings);

        assert_eq!(result["found"], 2, "skip records count as found");
        assert_eq!(result["skipped"], 1);
        let patches = result["patches"].as_array().unwrap();
        assert_eq!(patches.len(), 2, "skip record folded into patches[]");
        assert_eq!(patches[1]["errorCode"], "package_not_installed");
        assert_eq!(
            result["warnings"],
            serde_json::json!([
                "existing variant warning",
                "(yarn_pnp_unsupported) PnP layout detail"
            ]),
            "existing warning strings must survive the merge, new ones appended"
        );
    }

    /// Engine params for the nested-apply arg tests below.
    fn dl_params() -> DownloadParams {
        DownloadParams {
            cwd: PathBuf::from("."),
            manifest_path: PathBuf::from(".socket/manifest.json"),
            save_only: true,
            global: false,
            global_prefix: None,
            json: true,
            silent: true,
            all_releases: false,
            strict: false,
            ecosystems: None,
            persist_blobs: false,
            patch_server_url: None,
        }
    }

    // --- format_patch_option: vulnerability summaries in the option lines --

    #[test]
    fn patch_option_line_joins_cves_when_advisory_has_them() {
        // An advisory WITH CVEs is summarized by the CVE ids joined with
        // ", " — the advisory id itself is not shown.
        let mut a = mk_patch("a", "pkg:npm/foo@1.0", "free", "2024-01-01");
        a.vulnerabilities.insert(
            "GHSA-with-cves".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-0001".into(), "CVE-2024-0002".into()],
                summary: "s".into(),
                severity: "high".into(),
                description: String::new(),
            },
        );
        assert_eq!(
            format_patch_option(&a),
            "a [FREE] (fixes: CVE-2024-0001, CVE-2024-0002) - desc-a"
        );
    }

    #[test]
    fn patch_option_line_falls_back_to_advisory_id_without_cves() {
        // An advisory WITHOUT CVEs (e.g. a GHSA with no CVE assigned yet)
        // falls back to the advisory id.
        let mut b = mk_patch("b", "pkg:npm/foo@1.0", "free", "2024-06-01");
        b.vulnerabilities.insert(
            "GHSA-no-cves".into(),
            VulnerabilityResponse {
                cves: vec![],
                summary: "s".into(),
                severity: "low".into(),
                description: String::new(),
            },
        );
        assert_eq!(
            format_patch_option(&b),
            "b [FREE] (fixes: GHSA-no-cves) - desc-b"
        );
    }

    #[test]
    fn patch_option_line_omits_fixes_segment_without_vulnerabilities() {
        let c = mk_patch("c", "pkg:npm/foo@1.0", "paid", "2024-06-01");
        assert_eq!(format_patch_option(&c), "c [PAID] - desc-c");
    }

    // --- terminal-UI text helpers ------------------------------------------

    fn vuln(cves: &[&str], severity: &str, summary: &str) -> VulnerabilityResponse {
        VulnerabilityResponse {
            cves: cves.iter().map(|c| c.to_string()).collect(),
            summary: summary.into(),
            severity: severity.into(),
            description: String::new(),
        }
    }

    fn with_vulns(
        mut p: PatchSearchResult,
        vulns: &[(&str, VulnerabilityResponse)],
    ) -> PatchSearchResult {
        for (id, v) in vulns {
            p.vulnerabilities.insert(id.to_string(), v.clone());
        }
        p
    }

    #[test]
    fn patch_option_line_has_no_dangling_dash_for_empty_description() {
        let mut p = mk_patch("u1", "pkg:npm/nuxt@4.5.0", "free", "2024-01-01");
        p.description = String::new();
        let p = with_vulns(p, &[("GHSA-x", vuln(&["CVE-2026-71315"], "high", ""))]);
        assert_eq!(format_patch_option(&p), "u1 [FREE] (fixes: CVE-2026-71315)");
        // Whitespace-only descriptions collapse to nothing too.
        let mut q = mk_patch("u2", "pkg:npm/nuxt@4.5.0", "free", "2024-01-01");
        q.description = "  \n ".into();
        assert_eq!(format_patch_option(&q), "u2 [FREE]");
    }

    #[test]
    fn patch_option_line_sorts_ids_across_advisories_and_truncates_multibyte() {
        let mut p = mk_patch("u", "pkg:npm/a@1", "free", "2024-01-01");
        p.description = "é".repeat(100);
        let p = with_vulns(
            p,
            &[
                ("GHSA-b", vuln(&["CVE-2026-2"], "low", "")),
                ("GHSA-a", vuln(&["CVE-2026-1", "CVE-2025-9"], "high", "")),
                ("GHSA-z", vuln(&[], "low", "")),
            ],
        );
        assert_eq!(
            format_patch_option(&p),
            format!(
                "u [FREE] (fixes: CVE-2025-9, CVE-2026-1, CVE-2026-2, GHSA-z) - {}...",
                "é".repeat(57)
            )
        );
    }

    #[test]
    fn vuln_labels_dedup_and_sort() {
        let mut m = HashMap::new();
        m.insert("GHSA-1".to_string(), vuln(&["CVE-2", "CVE-1"], "high", ""));
        m.insert("GHSA-2".to_string(), vuln(&["CVE-1"], "low", ""));
        assert_eq!(vuln_labels(&m), vec!["CVE-1", "CVE-2"]);
        assert!(vuln_labels(&HashMap::new()).is_empty());
    }

    #[test]
    fn patch_summary_line_shapes() {
        let mut m = HashMap::new();
        m.insert(
            "GHSA-1".to_string(),
            vuln(&["CVE-2021-44906"], "critical", ""),
        );
        assert_eq!(
            format_patch_summary("pkg:npm/minimist@1.2.5", "free", None, &m, false),
            "pkg:npm/minimist@1.2.5 [FREE] fixes CVE-2021-44906 (CRITICAL)"
        );
        assert_eq!(
            format_patch_summary(
                "pkg:npm/%40scope/x@1.0.0",
                "paid",
                Some("a8b05a61-1e2f-4c5f-a65b-93e71deba1ae"),
                &m,
                false
            ),
            "pkg:npm/@scope/x@1.0.0 [PAID] a8b05a61: fixes CVE-2021-44906 (CRITICAL)"
        );
        // No advisories: no `fixes`, no colon.
        assert_eq!(
            format_patch_summary(
                "pkg:npm/a@1",
                "free",
                Some("abcdef0123"),
                &HashMap::new(),
                false
            ),
            "pkg:npm/a@1 [FREE] abcdef01"
        );
        // Unknown severity: ids without a severity suffix.
        let mut u = HashMap::new();
        u.insert("GHSA-2".to_string(), vuln(&[], "", ""));
        assert_eq!(
            format_patch_summary("pkg:npm/a@1", "free", None, &u, false),
            "pkg:npm/a@1 [FREE] fixes GHSA-2"
        );
        // Several advisories: the max severity is labeled as such, and
        // colored like the listing when color is on.
        let mut several = HashMap::new();
        several.insert("GHSA-1".to_string(), vuln(&["CVE-2026-1"], "high", ""));
        several.insert("GHSA-2".to_string(), vuln(&["CVE-2026-2"], "moderate", ""));
        assert_eq!(
            format_patch_summary(
                "pkg:npm/nuxt@4.5.0",
                "paid",
                Some("884e9f6d-x"),
                &several,
                false
            ),
            "pkg:npm/nuxt@4.5.0 [PAID] 884e9f6d: fixes CVE-2026-1, CVE-2026-2 (highest: HIGH)"
        );
        assert_eq!(
            format_patch_summary("pkg:npm/minimist@1.2.5", "free", None, &m, true),
            "pkg:npm/minimist@1.2.5 [FREE] fixes CVE-2021-44906 (\x1b[91mCRITICAL\x1b[0m)"
        );
    }

    #[test]
    fn natural_cmp_orders_versions_numerically() {
        let mut v = vec![
            "pkg:npm/lodash@4.17.10",
            "pkg:npm/lodash@4.2.0",
            "pkg:npm/lodash@4.17.2",
            "pkg:npm/lodash@4.10.0",
            "pkg:npm/lodash@4.9.0",
            "pkg:npm/lodash-amd@4.0.0",
        ];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            v,
            vec![
                "pkg:npm/lodash-amd@4.0.0",
                "pkg:npm/lodash@4.2.0",
                "pkg:npm/lodash@4.9.0",
                "pkg:npm/lodash@4.10.0",
                "pkg:npm/lodash@4.17.2",
                "pkg:npm/lodash@4.17.10",
            ]
        );
        use std::cmp::Ordering;
        assert_eq!(natural_cmp("a1", "a01"), "a1".cmp("a01"));
        assert_ne!(natural_cmp("a1", "a01"), Ordering::Equal);
        assert_eq!(natural_cmp("", ""), Ordering::Equal);
        assert_eq!(natural_cmp("a", "a1"), Ordering::Less);
        assert_eq!(
            natural_cmp("x99999999999999999999999", "x1"),
            Ordering::Greater
        );
        assert_eq!(natural_cmp("é2", "é10"), Ordering::Less);
    }

    #[test]
    fn search_results_listing_exact_text() {
        let a = with_vulns(
            mk_patch("uuid-a", "pkg:npm/lodash@4.17.10", "free", "2024-01-01"),
            &[
                ("GHSA-b", vuln(&["CVE-2026-2"], "MODERATE", "")),
                ("GHSA-a", vuln(&["CVE-2026-1"], "HIGH", "")),
            ],
        );
        let mut b = mk_patch("uuid-b", "pkg:npm/lodash@4.17.2", "paid", "2024-01-01");
        b.description = String::new();
        let out = format_search_results(&[&a, &b], false, false);
        assert_eq!(
            out,
            "Found 2 patches:\n\n\
             \x20 1. pkg:npm/lodash@4.17.2 [PAID] (no access)\n\
             \x20    UUID: uuid-b\n\n\
             \x20 2. pkg:npm/lodash@4.17.10 [FREE]\n\
             \x20    UUID: uuid-a\n\
             \x20    Description: desc-uuid-a\n\
             \x20    Fixes: CVE-2026-1 (HIGH), CVE-2026-2 (MODERATE)\n\n"
        );
        let one = format_search_results(&[&a], true, false);
        assert!(one.starts_with("Found 1 patch:\n\n"), "{one}");
        assert_eq!(
            format_search_results(&[], true, false),
            "Found 0 patches:\n\n"
        );
        let colored = format_search_results(&[&a], true, true);
        assert!(
            colored.contains("CVE-2026-1 (\x1b[31mHIGH\x1b[0m)"),
            "{colored:?}"
        );
    }

    #[test]
    fn selected_block_names_uuid_and_fixes() {
        let a = with_vulns(
            mk_patch(
                "6332e781-0a42-4b0e-95c4-61f834461268",
                "pkg:npm/lodash@4.17.20",
                "free",
                "2024-01-01",
            ),
            &[("GHSA-a", vuln(&["CVE-2026-4800"], "HIGH", ""))],
        );
        assert_eq!(
            format_selected_patches(&[a], false),
            "Selected:\n  pkg:npm/lodash@4.17.20 [FREE] 6332e781: fixes CVE-2026-4800 (HIGH)\n\n"
        );
        assert_eq!(format_selected_patches(&[], false), "Selected:\n\n");
    }

    fn skip(purl: &str, code: &str) -> serde_json::Value {
        serde_json::json!({"purl": purl, "uuid": "u", "action": "skipped", "errorCode": code})
    }

    #[test]
    fn skip_summary_one_line_per_reason() {
        assert!(format_skip_summary(&[]).is_empty());
        assert_eq!(
            format_skip_summary(&[skip("pkg:npm/a@1", "package_not_installed")]),
            vec![
                "Skipped 1 patch for 1 package version not installed here \
                 (use --all-releases to include it)."
            ]
        );
        let many = vec![
            skip("pkg:npm/a@1", "package_not_installed"),
            skip("pkg:npm/a@1", "package_not_installed"),
            skip("pkg:npm/a@2", "package_not_installed"),
            skip("pkg:npm/b@1", "yarn_pnp_unsupported"),
        ];
        assert_eq!(
            format_skip_summary(&many),
            vec![
                "Skipped 3 patches for 2 package versions not installed here \
                 (use --all-releases to include them)."
                    .to_string(),
                "Skipped 1 patch for 1 package version (yarn_pnp_unsupported; \
                 see the warning above)."
                    .to_string(),
            ]
        );
    }

    #[test]
    fn all_narrowed_message_plurals_and_pnp() {
        assert_eq!(
            format_all_narrowed(&[skip("pkg:npm/a@1", "package_not_installed")]),
            "Patches exist for 1 package version, but it is not installed here. \
             Use --all-releases to fetch it anyway."
        );
        assert_eq!(
            format_all_narrowed(&[
                skip("pkg:npm/a@1", "package_not_installed"),
                skip("pkg:npm/a@2", "package_not_installed"),
                skip("pkg:npm/a@2", "package_not_installed"),
            ]),
            "Patches exist for 2 package versions, but none of them are installed here. \
             Use --all-releases to fetch them anyway."
        );
        assert_eq!(
            format_all_narrowed(&[skip("pkg:npm/a@1", "pnpm_pnp_unsupported")]),
            "Found 1 patch, but this project's Plug'n'Play layout makes its npm packages \
             unpatchable here; see the layout warning above for the remedy."
        );
    }

    #[test]
    fn confirm_prompts_agent_mode() {
        assert_eq!(
            format_confirm_prompt(false, 1),
            "Download and apply 1 patch?"
        );
        assert_eq!(
            format_confirm_prompt(false, 2),
            "Download and apply 2 patches?"
        );
        assert_eq!(format_confirm_prompt(true, 1), "Download 1 patch?");
    }

    #[test]
    fn dry_run_line_plurals() {
        assert_eq!(
            format_dry_run("download and apply", 1),
            "[dry-run] Would download and apply 1 patch. No changes made."
        );
        assert_eq!(
            format_dry_run("download and vendor", 0),
            "[dry-run] Would download and vendor 0 patches. No changes made."
        );
    }

    #[test]
    fn no_packages_message_points_at_the_package_manager() {
        assert_eq!(no_packages_message(true), "No global packages found.");
        assert_eq!(
            no_packages_message(false),
            "No packages found. Run your package manager's install first."
        );
    }

    #[test]
    fn paid_required_text() {
        assert_eq!(
            format_paid_required("pkg:npm/a@1"),
            "This patch requires a paid Socket plan.\n  \
             Patch: pkg:npm/a@1\n\
             Upgrade to a paid Socket plan to access all patches: https://socket.dev/pricing"
        );
    }

    #[test]
    fn save_summary_lines() {
        let m = Path::new(".socket/manifest.json");
        assert_eq!(
            format_save_summary(m, 2, 0, 0, 0),
            "Patches saved to .socket/manifest.json\n  Added: 2"
        );
        assert_eq!(
            format_save_summary(m, 1, 1, 1, 1),
            "Patches saved to .socket/manifest.json\n  Added: 1\n  Updated: 1\n  Skipped: 1\n  Failed: 1"
        );
        assert_eq!(
            format_save_summary(m, 0, 0, 2, 0),
            "No changes to .socket/manifest.json\n  Added: 0\n  Skipped: 2"
        );
        assert_eq!(
            format_save_summary(m, 0, 0, 0, 1),
            "No changes to .socket/manifest.json\n  Added: 0\n  Failed: 1"
        );
    }

    #[test]
    fn matched_line_names_every_searched_package() {
        assert_eq!(
            format_matched_packages(&["pkg:npm/%40s/a@1".to_string()]),
            "Matched: pkg:npm/@s/a@1"
        );
        assert_eq!(
            format_matched_packages(&["pkg:npm/a@1".to_string(), "pkg:npm/a@2".to_string()]),
            "Matched 2 installed packages: pkg:npm/a@1, pkg:npm/a@2"
        );
    }

    fn crawled(
        purl: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> socket_patch_core::crawlers::CrawledPackage {
        socket_patch_core::crawlers::CrawledPackage {
            name: name.to_string(),
            version: "1".to_string(),
            namespace: namespace.map(str::to_string),
            purl: purl.to_string(),
            path: std::path::PathBuf::from("/fake"),
        }
    }

    /// B11: a package name selects EXACT matches only — every installed
    /// version — and never a prefix/substring sibling (`yaml` is not
    /// `yaml-ast-parser`); near names are only suggested.
    #[test]
    fn package_name_selects_every_exact_version_and_no_near_names() {
        let pkgs = vec![
            crawled("pkg:npm/lodash@4.17.21", "lodash", None),
            crawled("pkg:npm/lodash@4.17.4", "lodash", None),
            crawled("pkg:npm/lodash@4.17.4", "lodash", None),
            crawled("pkg:npm/lodash-es@4.17.21", "lodash-es", None),
            crawled("pkg:npm/yaml-ast-parser@0.0.43", "yaml-ast-parser", None),
        ];
        assert_eq!(
            installed_target_matches(&Target::parse("lodash"), &pkgs),
            vec!["pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.4"]
        );
        assert!(installed_target_matches(&Target::parse("yaml"), &pkgs).is_empty());
        assert_eq!(
            format_did_you_mean("yaml", &pkgs).as_deref(),
            Some("Did you mean: yaml-ast-parser?")
        );
        assert_eq!(format_did_you_mean("zzqxjvwq", &pkgs), None);
        assert_eq!(
            installed_target_matches(&Target::parse("pkg:npm/lodash"), &pkgs).len(),
            2,
            "a versionless purl selects every installed version"
        );
    }

    #[test]
    fn verbose_skips_dedupe_and_sort_naturally() {
        let rec = |purl: &str, code: Option<&str>| {
            let mut r = serde_json::json!({"purl": purl, "action": "skipped"});
            if let Some(c) = code {
                r["errorCode"] = serde_json::json!(c);
            }
            r
        };
        let skips = vec![
            rec("pkg:npm/a@4.10.0", Some("package_not_installed")),
            rec("pkg:npm/a@4.2.0", None),
            rec("pkg:npm/a@4.10.0", Some("package_not_installed")),
            rec("pkg:npm/a@4.1.0", Some("yarn_pnp_unsupported")),
        ];
        assert_eq!(
            format_verbose_skips(&skips),
            vec![
                "  [skip] pkg:npm/a@4.1.0 (yarn_pnp_unsupported)",
                "  [skip] pkg:npm/a@4.2.0 (version not installed)",
                "  [skip] pkg:npm/a@4.10.0 (version not installed)",
            ]
        );
        assert!(format_verbose_skips(&[]).is_empty());
    }

    #[test]
    fn selection_prompted_only_for_an_interactive_free_choice() {
        let two = vec![
            mk_patch("a", "pkg:npm/x@1", "free", "2024-01-01"),
            mk_patch("b", "pkg:npm/x@1", "free", "2024-02-01"),
        ];
        let one_plus_paid = vec![
            mk_patch("a", "pkg:npm/x@1", "free", "2024-01-01"),
            mk_patch("b", "pkg:npm/x@1", "paid", "2024-02-01"),
        ];
        let plain = GlobalArgs::default();
        let yes = GlobalArgs {
            yes: true,
            ..GlobalArgs::default()
        };
        let json = GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        };
        // Paid users, --yes and --json never see a menu.
        assert!(!selection_prompted(&two, true, &plain));
        assert!(!selection_prompted(&two, false, &yes));
        assert!(!selection_prompted(&two, false, &json));
        // A single free candidate is auto-picked.
        assert!(!selection_prompted(&one_plus_paid, false, &plain));
        // Several free candidates prompt exactly when stdin is a terminal.
        use std::io::IsTerminal;
        assert_eq!(
            selection_prompted(&two, false, &plain),
            std::io::stdin().is_terminal()
        );
    }

    #[test]
    fn single_save_lines() {
        let m = Path::new("p/.socket/manifest.json");
        assert_eq!(
            format_single_save("Patch", &PatchAction::Added, m, "pkg:npm/a@1", true),
            "Patch saved to p/.socket/manifest.json\n  Added: 1"
        );
        assert_eq!(
            format_single_save(
                "Patch record",
                &PatchAction::Updated {
                    old_uuid: "0123456789abcdef".into()
                },
                m,
                "pkg:npm/a@1",
                false
            ),
            "Patch record saved to p/.socket/manifest.json\n  Updated: 1 (replacing 01234567)"
        );
        // A malformed short uuid never panics.
        assert!(format_single_save(
            "Patch",
            &PatchAction::Updated {
                old_uuid: "é".into()
            },
            m,
            "x",
            true
        )
        .ends_with("(replacing é)"));
        assert_eq!(
            format_single_save("Patch", &PatchAction::Skipped, m, "pkg:npm/%40s/a@1", true),
            "pkg:npm/@s/a@1 already has this patch recorded in p/.socket/manifest.json; \
             nothing to update."
        );
        // The vendored path still runs its vendor step: no "nothing to
        // update" promise.
        assert_eq!(
            format_single_save(
                "Patch record",
                &PatchAction::Skipped,
                m,
                "pkg:npm/a@1",
                false
            ),
            "pkg:npm/a@1 already has this patch recorded in p/.socket/manifest.json."
        );
    }

    #[test]
    fn record_skip_line_decodes_the_purl() {
        assert_eq!(
            format_record_skip("pkg:npm/%40scope/a@1.0.0", "already vendored"),
            "  [skip] pkg:npm/@scope/a@1.0.0 (already vendored)"
        );
        assert_eq!(
            format_record_skip("pkg:npm/a@1", "already in manifest"),
            "  [skip] pkg:npm/a@1 (already in manifest)"
        );
    }

    #[test]
    fn apply_failed_line_is_an_error_even_when_silent() {
        assert_eq!(APPLY_FAILED, "Error: Some patches could not be applied.");
    }

    #[test]
    fn forced_identifier_shapes() {
        assert_eq!(
            forced_identifier_error(&Target::with_kind("lodash", TargetKind::Uuid)).as_deref(),
            Some("The identifier is not a valid patch UUID (expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind("lodash", TargetKind::Cve)).as_deref(),
            Some("The identifier is not a valid CVE ID (expected CVE-YYYY-NNNN)")
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind("GHSA-1", TargetKind::Ghsa)).as_deref(),
            Some("The identifier is not a valid GHSA ID (expected GHSA-xxxx-xxxx-xxxx)")
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind(
                "a8b05a61-1e2f-4c5f-a65b-93e71deba1ae",
                TargetKind::Uuid
            )),
            None
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind("cve-2021-44906", TargetKind::Cve)),
            None
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind("GHSA-xvch-5gv4-984h", TargetKind::Ghsa)),
            None
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind("anything", TargetKind::Name)),
            None
        );
        assert_eq!(
            forced_identifier_error(&Target::with_kind("anything", TargetKind::Purl)),
            None
        );
    }

    #[test]
    fn yes_auto_picks_the_top_ranked_free_patch_without_a_prompt() {
        // Two free patches for one purl would open the interactive menu;
        // --yes answers it with its default (the top-ranked patch).
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let yes = GlobalArgs {
            yes: true,
            ..GlobalArgs::default()
        };
        let out = select_patches(&patches, false, &yes).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
        // --json keeps its selection_required contract even with --yes.
        let json_yes = GlobalArgs {
            yes: true,
            json: true,
            ..GlobalArgs::default()
        };
        assert_eq!(select_patches(&patches, false, &json_yes).unwrap_err(), 1);
    }

    #[test]
    fn help_text_has_no_implementation_notes() {
        use clap::CommandFactory;
        let mut cmd = crate::Cli::command();
        let get = cmd
            .find_subcommand_mut("get")
            .expect("get subcommand")
            .clone();
        let mut get = get;
        let help = get.render_long_help().to_string();
        for leak in [
            "value_parser",
            "parse_bool_flag",
            "No env binding",
            "locally- installed",
        ] {
            assert!(!help.contains(leak), "get --help leaks {leak:?}:\n{help}");
        }
        assert!(help.contains("locally-installed distribution"), "{help}");
    }

    // --- download_patch_records (detached download phase) ------------------
    // pub(crate), so its branches are pinned here. wiremock is a dev-dep and
    // available to unit tests. Every override field is set explicitly so no
    // ambient SOCKET_* env can steer the client; the env guard below scrubs
    // the two vars the client constructor still consults for gaps.

    struct EnvVarGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvVarGuard {
        fn scrub(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| {
                    let old = std::env::var(k).ok();
                    std::env::remove_var(k);
                    (*k, old)
                })
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn detached_params(root: &Path) -> DownloadParams {
        DownloadParams {
            cwd: root.to_path_buf(),
            manifest_path: root.join(".socket/manifest.json"),
            save_only: true,
            global: false,
            global_prefix: None,
            json: true,
            silent: true,
            all_releases: false,
            strict: false,
            ecosystems: None,
            // The vendor-detached posture this fn exists for.
            persist_blobs: false,
            patch_server_url: None,
        }
    }

    /// The test client every hermetic engine test drives: the mock server
    /// as API URL, a fake token, the fixture org — every override explicit
    /// so no ambient `SOCKET_*` can steer it.
    async fn test_client(server_url: &str) -> ApiClient {
        get_api_client_with_overrides(socket_patch_core::api::client::ApiClientEnvOverrides {
            api_url: Some(server_url.to_string()),
            api_token: Some("fake".to_string()),
            org_slug: Some("test-org".to_string()),
            proxy_url: None,
        })
        .await
        .0
    }

    /// The 3-arg shape the vendored-download unit tests below drive: builds
    /// the run's client against `server_url`, and drops the blob seed (the
    /// stager's concern, pinned by fetch_stage's tests).
    async fn download_patch_records(
        selected: &[PatchSearchResult],
        params: &DownloadParams,
        server_url: &str,
    ) -> (i32, serde_json::Value, HashMap<String, PatchRecord>) {
        let api_client = test_client(server_url).await;
        let (code, json, records) =
            download_patch_records_with(selected, params, &api_client, HashMap::new()).await;
        (code, json, records)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_no_applicable_files_is_failed_and_unrecorded() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-no-after@1.0.0";
        // Every file lacks an afterHash -> files_for_manifest is empty ->
        // the no-applicable-files guardrail must count a failure, return
        // no record, and never claim the purl was downloaded.
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "guardrail failure must exit 1; json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(json["downloaded"], 0, "json={json}");
        assert!(
            records.is_empty(),
            "no record may be handed to the vendor step"
        );
        assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "patch has no applicable files",
            "json={json}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_view_404_is_fetch_miss() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        // No view mock mounted: wiremock answers 404, which the API client
        // maps to Ok(None) — the "could not fetch details" fetch-miss arm.
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let purl = "pkg:npm/covgap-missing-view@1.0.0";
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];

        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "a fetch miss must exit 1; json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert!(records.is_empty());
        assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "could not fetch details",
            "json={json}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_uninstalled_variant_base_warns_and_keeps_all() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        // Two qualified PyPI variants sharing an UNINSTALLED base: release
        // narrowing must keep both (with the not-installed warning), and the
        // warnings key must ride the detached envelope. Views stay unmounted
        // (404) so both then fail — proving both were kept for the loop.
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let base = "pkg:pypi/covgap-sixish@1.0.0";
        let selected = vec![
            mk_patch(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                &format!("{base}?artifact_id=wheel"),
                "free",
                "2024-01-01",
            ),
            mk_patch(
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                &format!("{base}?artifact_id=sdist"),
                "free",
                "2024-01-01",
            ),
        ];

        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["found"], 2, "both variants must be kept; json={json}");
        assert_eq!(json["failed"], 2, "json={json}");
        assert!(records.is_empty());
        let warnings = json["warnings"]
            .as_array()
            .unwrap_or_else(|| panic!("keep-all fallback must surface warnings; json={json}"));
        assert!(
            warnings.iter().any(|w| w
                .as_str()
                .unwrap_or_default()
                .contains("not installed locally")),
            "warning must explain the keep-all fallback; json={json}"
        );
    }

    // --- misc edge cases -----------------------------------------------------

    /// `merge_metadata` is a best-effort splice: a non-object record (or a
    /// non-object metadata value) must be left untouched, never panic —
    /// callers hand it freshly-built json! values, but the contract is
    /// defensive on both sides.
    #[test]
    fn merge_metadata_leaves_non_object_inputs_untouched() {
        // Non-object record: nothing to insert into.
        let mut record = serde_json::Value::Null;
        merge_metadata(&mut record, serde_json::json!({"severity": "high"}));
        assert!(record.is_null(), "a non-object record must stay untouched");

        // Non-object metadata: nothing to splice from.
        let mut record = serde_json::json!({"purl": "pkg:npm/x@1.0.0"});
        merge_metadata(&mut record, serde_json::Value::String("nope".into()));
        assert_eq!(record, serde_json::json!({"purl": "pkg:npm/x@1.0.0"}));
    }

    /// The `TargetKind` Display labels are user-facing vocabulary (the
    /// "No patches found for {type}: {id}" terminal) — pin all five.
    #[test]
    fn identifier_type_display_labels_are_stable() {
        assert_eq!(TargetKind::Uuid.to_string(), "UUID");
        assert_eq!(TargetKind::Cve.to_string(), "CVE");
        assert_eq!(TargetKind::Ghsa.to_string(), "GHSA");
        assert_eq!(TargetKind::Purl.to_string(), "PURL");
        assert_eq!(TargetKind::Name.to_string(), "package name");
    }

    /// JSON mode with multiple free patches for one purl: the
    /// `selection_required` options must carry each patch's vulnerability
    /// details (id/cves/severity/summary) so a bot can choose without a
    /// second query. The existing json-mode test used vuln-less patches, so
    /// the serialization closure never ran.
    #[test]
    fn select_json_mode_multi_free_options_serialize_vulnerabilities() {
        let mut a = mk_patch("a", "pkg:npm/foo@1.0", "free", "2024-01-01");
        a.vulnerabilities.insert(
            "GHSA-aaaa-bbbb-cccc".to_string(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-1111".to_string()],
                summary: "summary-a".to_string(),
                severity: "high".to_string(),
                description: "desc-a".to_string(),
            },
        );
        let mut b = mk_patch("b", "pkg:npm/foo@1.0", "free", "2024-02-01");
        b.vulnerabilities.insert(
            "GHSA-dddd-eeee-ffff".to_string(),
            VulnerabilityResponse {
                cves: vec![],
                summary: "summary-b".to_string(),
                severity: "low".to_string(),
                description: "desc-b".to_string(),
            },
        );
        let result = select_patches(&[a, b], false, &json_args());
        assert_eq!(
            result.err(),
            Some(1),
            "json mode with multiple free candidates must error with exit 1"
        );
    }

    /// `fold_narrowing_into_result` on a non-object envelope (the error
    /// shapes are the callers' concern) must be a calm no-op.
    #[test]
    fn fold_narrowing_ignores_non_object_result() {
        let mut result = serde_json::json!(["not", "an", "object"]);
        fold_narrowing_into_result(
            &mut result,
            &[serde_json::json!({"purl": "p", "action": "skipped"})],
            &[("code".to_string(), "detail".to_string())],
        );
        assert_eq!(result, serde_json::json!(["not", "an", "object"]));
    }

    /// A corrupt vendor ledger must degrade the coarse narrowing to "no
    /// ledger extension" (the download path's fail-closed read still guards
    /// writes): a purl claimed by nothing else is skipped as not installed,
    /// never kept on the strength of an unreadable state file.
    #[tokio::test]
    async fn filter_to_installed_purls_corrupt_vendor_state_degrades_to_no_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(vendor.join("state.json"), b"{ not json").unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let accessible = vec![mk_patch(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "pkg:npm/covgap-ledger-only@1.0.0",
            "free",
            "2024-01-01",
        )];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        assert!(
            out.kept.is_empty(),
            "nothing may be kept via a corrupt ledger"
        );
        assert_eq!(out.skip_records.len(), 1);
        assert_eq!(out.skip_records[0]["errorCode"], "package_not_installed");
    }

    /// The lockfile/vendor-ledger supplements are gated OFF for
    /// machine-tree-scoped runs (`--global` / `--global-prefix`): a version
    /// resolved only by the PROJECT lockfile must not count as present
    /// there — those runs target the machine tree, not this project.
    #[tokio::test]
    async fn filter_to_installed_purls_prefix_scoped_run_skips_lock_supplement() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tempfile::tempdir().unwrap();
        // The project lockfile resolves the exact version under test.
        std::fs::write(
            tmp.path().join("package-lock.json"),
            serde_json::json!({
                "name": "consumer", "version": "0.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "consumer", "version": "0.0.0" },
                    "node_modules/covgap-lock-only": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/covgap-lock-only/-/covgap-lock-only-1.0.0.tgz",
                        "integrity": "sha512-AAAA=="
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(prefix.path().to_path_buf()),
            ..Default::default()
        };
        let accessible = vec![mk_patch(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "pkg:npm/covgap-lock-only@1.0.0",
            "free",
            "2024-01-01",
        )];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        assert!(
            out.kept.is_empty(),
            "a prefix-scoped run must not treat lockfile resolution as presence"
        );
        assert_eq!(out.skip_records.len(), 1);
        assert_eq!(out.skip_records[0]["errorCode"], "package_not_installed");
    }

    /// B74: a FIFO planted at `pnpm-lock.yaml` of a pnpm-PnP project must
    /// not wedge hosted `get` in open(2). A FIFO present from the start is
    /// already refused by the lock inventory (so this guards the whole
    /// hosted filter path, and passes on the old code too); the raw read
    /// behind the pnpm-PnP keep-gate is now FIFO-safe as well, which closes
    /// the window where a FIFO is swapped in after the inventory read. A
    /// watchdog thread
    /// opens the FIFO's write end (non-blocking) after a grace period, which
    /// releases a reader stuck in open(2): the test then FAILS instead of
    /// hanging the suite.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn filter_to_installed_purls_pnpm_pnp_hosted_fifo_lock_does_not_wedge() {
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".pnp.cjs"), b"// pnp loader\n").unwrap();
        let lock = tmp.path().join("pnpm-lock.yaml");
        let c = std::ffi::CString::new(lock.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        std::fs::write(tmp.path().join("node_modules/.modules.yaml"), b"").unwrap();

        let done = Arc::new(AtomicBool::new(false));
        let rescued = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let (done, rescued, lock) = (done.clone(), rescued.clone(), lock.clone());
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                // Keep releasing until the body returns: each open lets one
                // blocked reader through to EOF.
                while !done.load(Ordering::SeqCst) {
                    if std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&lock)
                        .is_ok()
                    {
                        rescued.store(true, Ordering::SeqCst);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            })
        };

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let accessible = vec![mk_patch(
            "88888888-8888-4888-8888-888888888888",
            "pkg:npm/covgap-judged@1.0.0",
            "free",
            "2024-01-01",
        )];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        done.store(true, Ordering::SeqCst);
        watchdog.join().unwrap();
        assert!(
            !rescued.load(Ordering::SeqCst),
            "a FIFO pnpm-lock.yaml wedged get in open(2)"
        );
        assert!(out.kept.is_empty(), "{:?}", out.kept);
    }

    /// pnpm-PnP + hosted: a purl the lock probe CANNOT judge (no `@version`
    /// coordinate to look for) must keep the layout-refusal code — the same
    /// no-judgment fallback as an unreadable lock — never a false
    /// "not installed" verdict; a judgeable-but-absent version is a genuine
    /// miss and carries `package_not_installed`.
    #[tokio::test]
    async fn filter_to_installed_purls_pnpm_pnp_hosted_unjudgeable_purl_keeps_layout_code() {
        let tmp = tempfile::tempdir().unwrap();
        // pnpm's own node-linker=pnp layout: PnP loader + pnpm-lock.yaml +
        // installed pnpm store marker, no yarn.lock.
        std::fs::write(tmp.path().join(".pnp.cjs"), b"// pnp loader\n").unwrap();
        std::fs::write(
            tmp.path().join("pnpm-lock.yaml"),
            b"lockfileVersion: '9.0'\n\nsnapshots:\n\n  some-other-pkg@2.0.0:\n",
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        std::fs::write(tmp.path().join("node_modules/.modules.yaml"), b"").unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let accessible = vec![
            // Versionless: the probe has no version to anchor on.
            mk_patch(
                "99999999-9999-4999-8999-999999999999",
                "pkg:npm/covgap-noversion",
                "free",
                "2024-01-01",
            ),
            // Versioned but absent from the lock: a judged miss.
            mk_patch(
                "88888888-8888-4888-8888-888888888888",
                "pkg:npm/covgap-judged@1.0.0",
                "free",
                "2024-01-01",
            ),
        ];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        assert!(out.kept.is_empty(), "neither purl may be kept");
        assert!(
            out.warnings.iter().any(|(code, _)| code.contains("pnp")),
            "the layout refusal must surface as a run-level warning; got {:?}",
            out.warnings
        );
        let code_for = |purl: &str| {
            out.skip_records
                .iter()
                .find(|r| r["purl"] == purl)
                .unwrap_or_else(|| panic!("missing skip record for {purl}"))["errorCode"]
                .clone()
        };
        assert_eq!(
            code_for("pkg:npm/covgap-noversion"),
            "pnpm_pnp_unsupported",
            "an unjudgeable purl must keep the layout code"
        );
        assert_eq!(
            code_for("pkg:npm/covgap-judged@1.0.0"),
            "package_not_installed",
            "a judged miss is a genuine not-installed verdict"
        );
    }

    /// `download_patch_records` with `persist_blobs` on a tree whose
    /// `.socket` path is squatted by a regular file: the blobs dir is created
    /// lazily, at the first blob actually persisted, so the failure surfaces
    /// as the per-patch `Blob decode or write failed` after the view fetch —
    /// no record handed to the caller, the squatting file left untouched.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_persist_blobs_unwritable_blobs_dir_is_failed_and_unrecorded() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-blobfail@1.0.0";
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                    "blobContent": "cGF0Y2hlZAo=",
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();

        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let mut params = detached_params(tmp.path());
        params.persist_blobs = true;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "Blob decode or write failed",
            "json={json}"
        );
        assert!(
            records.is_empty(),
            "a blob failure must not hand back a record"
        );
        assert_eq!(
            std::fs::read(tmp.path().join(".socket")).unwrap(),
            b"not a dir",
            "the squatting file must be left untouched"
        );
    }

    /// `download_patch_records` with `persist_blobs`: undecodable blob
    /// content is a per-patch failure — `Blob decode or write failed`, no
    /// record returned, nothing written into `.socket/blobs`.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_persist_blobs_bad_base64_is_failed_and_unrecorded() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-badblob@1.0.0";
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": "0".repeat(64),
                        "afterHash": "1".repeat(64),
                        "blobContent": "%%%not-base64%%%",
                    }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let mut params = detached_params(tmp.path());
        params.persist_blobs = true;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "Blob decode or write failed",
            "json={json}"
        );
        assert!(
            records.is_empty(),
            "a blob failure must not hand back a record"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "the blobs dir is created only once a blob decodes, so undecodable \
             content must leave no `.socket/` behind at all"
        );
    }

    /// Human-mode `download_patch_records` (json=false, silent=false): the
    /// `[fetch]`, no-applicable-files `[fail]`, and fetch-miss `[fail]`
    /// print paths all execute, and the envelope keeps exact per-action
    /// counts alongside them.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_human_mode_mixed_outcomes() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let good_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let good_purl = "pkg:npm/covgap-good@1.0.0";
        let nofiles_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let nofiles_purl = "pkg:npm/covgap-nofiles@1.0.0";
        let missing_uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let missing_purl = "pkg:npm/covgap-missing@1.0.0";

        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/test-org/patches/view/{good_uuid}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": good_uuid, "purl": good_purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": "0".repeat(64),
                        "afterHash": "1".repeat(64),
                        "blobContent": "cGF0Y2hlZAo=",
                    }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/test-org/patches/view/{nofiles_uuid}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": nofiles_uuid, "purl": nofiles_purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
        // missing_uuid's view stays unmounted -> 404 -> fetch miss.

        let tmp = tempfile::tempdir().unwrap();
        let selected = vec![
            mk_patch(good_uuid, good_purl, "free", "2024-01-01"),
            mk_patch(nofiles_uuid, nofiles_purl, "free", "2024-01-01"),
            mk_patch(missing_uuid, missing_purl, "free", "2024-01-01"),
        ];
        let mut params = detached_params(tmp.path());
        params.json = false;
        params.silent = false;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["downloaded"], 1, "json={json}");
        assert_eq!(json["failed"], 2, "json={json}");
        assert_eq!(records.len(), 1, "only the good patch yields a record");
        assert!(records.contains_key(good_purl), "json={json}");
        let errors: Vec<&str> = json["patches"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["error"].as_str())
            .collect();
        assert!(
            errors.contains(&"patch has no applicable files"),
            "json={json}"
        );
        assert!(errors.contains(&"could not fetch details"), "json={json}");
    }

    /// A purl already vendored DETACHED at the selected uuid is served from
    /// the ledger's embedded record with ZERO network traffic — the
    /// idempotent re-run contract (human mode, so the `[skip]` print runs).
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_already_vendored_detached_skips_offline() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await; // trap: no mounts
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-vendored@1.0.0";

        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": uuid,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{uuid}/covgap-vendored-1.0.0.tgz"),
                    },
                    "wiring": [],
                    "detached": true,
                    "record": {
                        "uuid": uuid,
                        "exportedAt": "2024-01-01T00:00:00Z",
                        "files": {
                            "package/index.js": {
                                "beforeHash": "0".repeat(64),
                                "afterHash": "1".repeat(64),
                            }
                        },
                        "vulnerabilities": {},
                        "description": "embedded",
                        "license": "MIT",
                        "tier": "free",
                    }
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let mut params = detached_params(tmp.path());
        params.json = false;
        params.silent = false;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 0, "json={json}");
        assert_eq!(json["skipped"], 1, "json={json}");
        assert_eq!(json["patches"][0]["action"], "skipped", "json={json}");
        assert_eq!(
            records.get(purl).map(|r| r.uuid.as_str()),
            Some(uuid),
            "the ledger's embedded record must be reused"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "an already-vendored entry must never touch the network"
        );
    }

    // --- download_patch_records: Bun preflight (detached parity) -----------
    // The detached download phase must refuse the same Bun projects the
    // manifest-tracked one does, BEFORE any view fetch (request-log oracle),
    // and with the vendor code (never the downstream `package_not_installed`
    // the alias-shaped lockb project would otherwise degrade to).

    /// A real bun 1.3.14 lockfileVersion-1 workspace lock (matrix capture
    /// grammar): 1-tuple `workspace:` entry, blank line between entries,
    /// trailing commas.
    const BUN_V1_WORKSPACE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "unit-fixture",
      "dependencies": {
        "consumer": "workspace:*",
      },
    },
    "packages/consumer": {
      "name": "consumer",
      "version": "1.0.0",
      "dependencies": {
        "covgap-bun": "1.0.0",
      },
    },
  },
  "packages": {
    "consumer": ["consumer@workspace:packages/consumer"],

    "covgap-bun": ["covgap-bun@1.0.0", "", {}, "sha512-AAAA=="],
  }
}
"#;

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_malformed_bun_lockb_refuses_before_fetch() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let purl = "pkg:npm/covgap-bun@1.0.0";
        // A view that WOULD succeed — proves the refusal is decided before
        // the fetch, not by a failed fetch.
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                    "blobContent": "cGF0Y2hlZAo=",
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["found"], 1, "json={json}");
        assert_eq!(json["downloaded"], 0, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
        assert_eq!(
            json["patches"][0]["errorCode"], "vendor_bun_lockb_invalid",
            "json={json}"
        );
        assert!(
            json["patches"][0]["error"]
                .as_str()
                .is_some_and(|d| !d.is_empty()),
            "the record must carry the engine's detail; json={json}"
        );
        assert!(records.is_empty(), "no record may reach the vendor step");
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a refused Bun project must never fetch the patch view"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_bun_v1_workspace_refuses_before_fetch() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await; // trap: no mounts
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), BUN_V1_WORKSPACE_LOCK).unwrap();
        let uuid = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let purl = "pkg:npm/covgap-bun@1.0.0";
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];

        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(
            json["patches"][0]["errorCode"], "vendor_bun_workspace_unsupported",
            "json={json}"
        );
        assert!(records.is_empty());
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "refused before any fetch"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
            BUN_V1_WORKSPACE_LOCK,
            "the preflight is read-only"
        );
    }

    /// The preflight is npm-only: a non-npm purl on a Bun-refused tree is
    /// fetched as usual (here: the view is unmounted, so it fails as a fetch
    /// miss — proving it reached the network, not the refusal).
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_bun_refusal_skips_non_npm_purls() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let uuid = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let purl = "pkg:pypi/covgap-not-bun@1.0.0";
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];

        let (code, json, _) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "could not fetch details",
            "a pypi purl must reach the fetch, not the Bun refusal; json={json}"
        );
        assert!(json["patches"][0].get("errorCode").is_none(), "json={json}");
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            1,
            "exactly the view fetch"
        );
    }

    /// Ledger entries at either the selected or an older UUID must not
    /// bypass the refusal when the live lock contains registry wiring.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_bun_refusal_rejects_unwired_ledger_entries() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), BUN_V1_WORKSPACE_LOCK).unwrap();
        let same = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        let older = "abababab-abab-4bab-8bab-abababababab";
        let newer = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
        let in_sync = "pkg:npm/covgap-bun@1.0.0";
        let stale = "pkg:npm/covgap-bun-stale@1.0.0";
        // Two ledger entries: one in sync with the selection, one stale.
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        let entry = |purl: &str, uuid: &str| {
            serde_json::json!({
                "ecosystem": "npm", "basePurl": purl, "uuid": uuid,
                "artifact": { "path": format!(".socket/vendor/npm/{uuid}/x.tgz") },
                "wiring": [], "flavor": "bun",
            })
        };
        // The in-sync entry carries the D2 shape every vendored run writes
        // (detached + embedded record): exactly what the ledger idempotency
        // skip keys on — the refusal must still win over that skip.
        let mut in_sync_entry = entry(in_sync, same);
        in_sync_entry["detached"] = serde_json::json!(true);
        in_sync_entry["record"] = serde_json::json!({
            "uuid": same,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        });
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { in_sync: in_sync_entry, stale: entry(stale, older) },
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = vec![
            mk_patch(same, in_sync, "free", "2024-01-01"),
            mk_patch(newer, stale, "free", "2024-01-01"),
        ];
        let (code, json, _) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        let by_purl = |purl: &str| {
            json["patches"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["purl"] == purl)
                .cloned()
                .unwrap_or_else(|| panic!("no record for {purl}: {json}"))
        };
        let refused_same = by_purl(in_sync);
        assert_eq!(
            refused_same["errorCode"], "vendor_bun_workspace_unsupported",
            "UUID equality alone cannot bypass the refusal; json={json}"
        );
        let refused = by_purl(stale);
        assert_eq!(
            refused["errorCode"], "vendor_bun_workspace_unsupported",
            "a stale-uuid entry is refused like a fresh vendoring; json={json}"
        );
        let paths: Vec<String> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(paths.is_empty(), "no refused purl may fetch: {paths:?}");
    }

    /// An unreadable vendor ledger silences the drift warning (the main
    /// vendor path reports unreadable state itself) instead of panicking or
    /// fabricating a warning.
    #[tokio::test]
    async fn warn_on_vendored_uuid_drift_unreadable_state_warns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(vendor.join("state.json"), b"{ not json").unwrap();

        let mut warnings = Vec::new();
        warn_on_vendored_uuid_drift(
            tmp.path(),
            true,
            &[serde_json::json!({
                "purl": "pkg:npm/x@1.0.0",
                "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "action": "added",
            })],
            &mut warnings,
        )
        .await;
        assert!(warnings.is_empty(), "unreadable state must warn nothing");
    }

    /// Malformed per-patch records (missing purl/uuid) are skipped without
    /// panicking, while a well-formed drifting record still warns.
    #[tokio::test]
    async fn warn_on_vendored_uuid_drift_skips_malformed_records_and_flags_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/covgap-drift@1.0.0";
        let vendored_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let new_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": vendored_uuid,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{vendored_uuid}/covgap-drift-1.0.0.tgz"),
                    },
                    "wiring": []
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let mut warnings = Vec::new();
        warn_on_vendored_uuid_drift(
            tmp.path(),
            true,
            &[
                // Malformed: no purl/uuid — must be skipped, not panic.
                serde_json::json!({"action": "added"}),
                // Genuine drift: manifest moved to a different uuid.
                serde_json::json!({"purl": purl, "uuid": new_uuid, "action": "added"}),
            ],
            &mut warnings,
        )
        .await;
        assert_eq!(warnings.len(), 1, "warnings={warnings:?}");
        assert!(
            warnings[0].contains(purl) && warnings[0].contains("is vendored at patch"),
            "warnings={warnings:?}"
        );
    }

    /// The nested apply inherits the caller's flags verbatim (`--verbose`,
    /// `--strict`, …), with `json`/`dry_run` forced off — one JSON document per run, and
    /// agent-mode `get` ignores `--dry-run` — `silent` following the caller's
    /// quiet gate, and the manifest path absolutized so apply does not
    /// re-resolve it against its own `--cwd`.
    #[test]
    fn nested_apply_args_flow_caller_flags_and_force_a_real_quiet_apply() {
        let common = GlobalArgs {
            verbose: true,
            strict: true,
            json: true,
            dry_run: true,
            ..GlobalArgs::default()
        };
        let nested = nested_apply_args(&common, Path::new("proj/.socket/manifest.json"), true);
        assert!(
            nested.verbose && nested.strict,
            "--verbose / --strict must flow through"
        );
        assert!(
            !nested.json && !nested.dry_run,
            "the nested apply is always a real, non-JSON run"
        );
        assert!(nested.silent, "silent follows the caller's quiet gate");
        assert!(
            Path::new(&nested.manifest_path).is_absolute(),
            "got {}",
            nested.manifest_path
        );
    }

    /// The engine's variant rebuilds the same shape from `DownloadParams` +
    /// `DownloadRun`: the run's verbosity flag, the caller's scope/mode
    /// flags, and quiet = json || silent. No API fields: the nested apply
    /// runs on the run's client, so `--org` need not be re-threaded.
    #[test]
    fn nested_apply_args_from_params_carry_run_flags() {
        let client = ApiClient::new(socket_patch_core::api::client::ApiClientOptions {
            api_url: "http://127.0.0.1:1".into(),
            api_token: None,
            route: socket_patch_core::api::client::ApiRoute::Proxy,
        });
        let run = DownloadRun {
            api_client: &client,
            lock_timeout: Some(7),
            verbose: true,
        };
        let params = dl_params();
        let nested =
            nested_apply_args_from_params(&params, &run, Path::new(".socket/manifest.json"));
        assert!(nested.verbose);
        assert!(
            nested.org.is_none() && nested.api_token.is_none(),
            "API fields are never threaded through params: the nested apply runs on the run's client"
        );
        assert!(nested.silent, "json || silent params run a quiet apply");
        assert!(!nested.json && !nested.dry_run);
    }

    /// The uuid path hands the engine the view it already fetched: the
    /// record is served from `prefetched` with ZERO network traffic (a
    /// fresh fetch could re-hit the 401 the proxy fallback recovered from),
    /// and the ledger-free classification reports it `downloaded`.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_with_prefetched_view_never_fetches() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await; // trap: no mounts
        let tmp = tempfile::tempdir().unwrap();
        // Two files: one with served `blobContent` (→ the blob seed), one
        // without (→ contributes nothing, and is NOT a failure).
        let mut seeded = file_resp(Some(&"0".repeat(64)), Some(&"1".repeat(64)));
        seeded.blob_content = Some("cGF0Y2hlZA==".to_string()); // "patched"
        let mut patch = patch_with_files(HashMap::from([
            ("package/index.js".to_string(), seeded),
            (
                "package/other.js".to_string(),
                file_resp(Some(&"2".repeat(64)), Some(&"3".repeat(64))),
            ),
        ]));
        patch.uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
        patch.purl = "pkg:npm/covgap-prefetched@1.0.0".into();
        let selected = vec![mk_patch(&patch.uuid, &patch.purl, "free", "2024-01-01")];
        let params = detached_params(tmp.path());
        let client = test_client(&server.uri()).await;
        let prefetched = HashMap::from([(patch.uuid.clone(), patch.clone())]);

        let (code, json, records) =
            download_patch_records_with(&selected, &params, &client, prefetched).await;

        assert_eq!(code, 0, "json={json}");
        assert_eq!(json["downloaded"], 1, "json={json}");
        assert!(!tmp.path().join(".socket/blobs").exists());
        assert_eq!(json["detached"], true, "json={json}");
        assert_eq!(json["patches"][0]["action"], "downloaded", "json={json}");
        assert!(
            json["patches"][0].get("oldUuid").is_none(),
            "no ledger entry, no oldUuid; json={json}"
        );
        assert_eq!(
            records.get(&patch.purl).map(|r| r.uuid.as_str()),
            Some(patch.uuid.as_str()),
            "the record must be built from the prefetched view"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a prefetched view must never be fetched again"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "the detached download phase writes nothing"
        );
    }

    /// A ledger entry at an OLDER uuid: the fetched record is `downloaded`
    /// and carries `oldUuid` — the re-vendor the vendor step will perform —
    /// derived from the ledger, since the vendored flows have no manifest.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_superseding_uuid_carries_old_uuid_from_ledger() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let purl = "pkg:npm/covgap-supersede@1.0.0";
        let old_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let new_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/test-org/patches/view/{new_uuid}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": new_uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                    "blobContent": "cGF0Y2hlZAo=",
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": old_uuid,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{old_uuid}/covgap-supersede-1.0.0.tgz"),
                    },
                    "wiring": []
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = vec![mk_patch(new_uuid, purl, "free", "2024-01-01")];
        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 0, "json={json}");
        assert_eq!(json["downloaded"], 1, "json={json}");
        assert_eq!(json["skipped"], 0, "json={json}");
        assert_eq!(json["patches"][0]["action"], "downloaded", "json={json}");
        assert_eq!(json["patches"][0]["oldUuid"], old_uuid, "json={json}");
        assert_eq!(
            records.get(purl).map(|r| r.uuid.as_str()),
            Some(new_uuid),
            "the superseding record is what the vendor step receives"
        );
    }

    /// The download loop's view GETs run concurrently but fold in selection
    /// order: with later views answering FIRST (reversed latencies) and a
    /// mix of 200 / 404 / 500 / held-in-memory / ledger-reused patches,
    /// every per-patch record keeps its selection slot and its serial
    /// action + error text, and only the views the serial loop fetched are
    /// requested (the held and reused ones never are).
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_concurrent_views_fold_in_selection_order() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = |c: char| {
            format!("{0}{0}{0}{0}{0}{0}{0}{0}-{0}{0}{0}{0}-4{0}{0}{0}-8{0}{0}{0}-{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}", c)
        };
        let purl = |n: &str| format!("pkg:npm/covgap-order-{n}@1.0.0");
        let view = |u: &str, p: &str| {
            serde_json::json!({
                "uuid": u, "purl": p,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })
        };
        // Selection order a..f; the slowest answers belong to the earliest.
        let (a, b, c, d, e, f) = (
            uuid('a'),
            uuid('b'),
            uuid('c'),
            uuid('d'),
            uuid('e'),
            uuid('f'),
        );
        let mount = |u: &str, resp: ResponseTemplate| {
            Mock::given(method("GET"))
                .and(wm_path(format!("/v0/orgs/test-org/patches/view/{u}")))
                .respond_with(resp)
                .expect(1)
        };
        mount(
            &a,
            ResponseTemplate::new(200)
                .set_body_json(view(&a, &purl("a")))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
        mount(
            &b,
            ResponseTemplate::new(404).set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
        mount(
            &c,
            ResponseTemplate::new(500)
                .set_body_string("boom")
                .set_delay(Duration::from_millis(200)),
        )
        .mount(&server)
        .await;
        // `d` is held in memory and `e` is reused from the ledger: never
        // requested.
        for u in [&d, &e] {
            Mock::given(method("GET"))
                .and(wm_path(format!("/v0/orgs/test-org/patches/view/{u}")))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
        }
        mount(
            &f,
            ResponseTemplate::new(200).set_body_json(view(&f, &purl("f"))),
        )
        .mount(&server)
        .await;

        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl("e"): {
                    "ecosystem": "npm",
                    "basePurl": purl("e"),
                    "uuid": e,
                    "detached": true,
                    "record": {
                        "uuid": e,
                        "exportedAt": "2024-01-01T00:00:00Z",
                        "files": { "package/index.js": {
                            "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                        }},
                        "vulnerabilities": {},
                        "description": "d", "license": "MIT", "tier": "free",
                    },
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{e}/covgap-order-e-1.0.0.tgz"),
                    },
                    "wiring": []
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let mut held: PatchResponse = serde_json::from_value(view(&d, &purl("d"))).unwrap();
        held.uuid = d.clone();
        let selected: Vec<PatchSearchResult> = [
            (&a, "a"),
            (&b, "b"),
            (&c, "c"),
            (&d, "d"),
            (&e, "e"),
            (&f, "f"),
        ]
        .iter()
        .map(|(u, n)| mk_patch(u, &purl(n), "free", "2024-01-01"))
        .collect();
        let client = test_client(&server.uri()).await;
        let (_code, json, records) = download_patch_records_with(
            &selected,
            &detached_params(tmp.path()),
            &client,
            HashMap::from([(d.clone(), held)]),
        )
        .await;

        let rows: Vec<(String, String, String)> = json["patches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["purl"].as_str().unwrap_or_default().to_string(),
                    p["action"].as_str().unwrap_or_default().to_string(),
                    p["error"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let row =
            |n: &str, action: &str, error: &str| (purl(n), action.to_string(), error.to_string());
        assert_eq!(
            rows,
            vec![
                row("a", "downloaded", ""),
                row("b", "failed", "could not fetch details"),
                row("c", "failed", "API request failed with status 500: boom"),
                row("d", "downloaded", ""),
                row("e", "skipped", ""),
                row("f", "downloaded", ""),
            ],
            "json={json}"
        );
        assert_eq!(json["downloaded"], 3, "json={json}");
        assert_eq!(json["failed"], 2, "json={json}");
        assert_eq!(json["skipped"], 1, "json={json}");
        let mut got: Vec<&String> = records.keys().collect();
        got.sort();
        assert_eq!(got, vec![&purl("a"), &purl("d"), &purl("e"), &purl("f")]);
        // `.expect` counts are verified on drop.
        drop(server);
    }

    /// Release-variant narrowing fetches every installed base's variant
    /// views concurrently, so each must come back to the variant that
    /// planned it. Two installed multi-variant bases with REVERSED
    /// latencies (the first base's views answer last) plus an uninstalled
    /// one: each base keeps the variant whose file hashes match its own
    /// installed bytes, every cached view is its own variant's, and the
    /// uninstalled base's views are never requested (its variants are not
    /// in the plan, and a plan that drifted to include them would trip
    /// their `expect(0)`).
    #[tokio::test]
    #[serial_test::serial]
    async fn release_narrowing_pairs_each_concurrent_view_with_its_own_variant() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let site = tempfile::tempdir().unwrap();
        // Two installed pypi distributions, each with its own bytes.
        let installed = |name: &str, body: &[u8]| {
            let dist = site.path().join(format!("{name}-1.0.0.dist-info"));
            std::fs::create_dir_all(&dist).unwrap();
            std::fs::write(
                dist.join("METADATA"),
                format!("Name: {name}\nVersion: 1.0.0\n"),
            )
            .unwrap();
            std::fs::write(site.path().join(format!("{name}.py")), body).unwrap();
            compute_git_sha256_from_bytes(body)
        };
        let alpha_hash = installed("alpha", b"alpha installed\n");
        let beta_hash = installed("beta", b"beta installed\n");

        let server = MockServer::start().await;
        let uuid = |n: &str| format!("{n:-<8}-0000-4000-8000-000000000000").replace(' ', "-");
        // `(uuid, file, hash, delay)`: the WHEEL variant of each base names
        // the installed file at its real hash (so it is the one kept); the
        // SDIST variant names a file that base does not have.
        let mount = |u: String, file: String, hash: String, delay: u64| {
            let server = &server;
            async move {
                Mock::given(method("GET"))
                    .and(wm_path(format!("/v0/orgs/test-org/patches/view/{u}")))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({
                                "uuid": u,
                                "purl": "pkg:pypi/ignored@1.0.0",
                                "publishedAt": "2024-01-01T00:00:00Z",
                                "files": { file: {
                                    "beforeHash": hash,
                                    "afterHash": "1".repeat(64),
                                }},
                                "vulnerabilities": {}, "description": "d",
                                "license": "MIT", "tier": "free",
                            }))
                            .set_delay(Duration::from_millis(delay)),
                    )
                    .expect(1)
                    .mount(server)
                    .await;
            }
        };
        // Alpha answers LAST, beta first.
        mount(uuid("aw"), "alpha.py".into(), alpha_hash, 300).await;
        mount(uuid("as"), "alpha_sdist.py".into(), "0".repeat(64), 300).await;
        mount(uuid("bw"), "beta.py".into(), beta_hash, 0).await;
        mount(uuid("bs"), "beta_sdist.py".into(), "0".repeat(64), 0).await;
        for n in ["gw", "gs"] {
            Mock::given(method("GET"))
                .and(wm_path(format!(
                    "/v0/orgs/test-org/patches/view/{}",
                    uuid(n)
                )))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
        }

        let variant = |n: &str, base: &str, artifact: &str| {
            mk_patch(
                &uuid(n),
                &format!("pkg:pypi/{base}@1.0.0?artifact_id={artifact}"),
                "free",
                "2024-01-01",
            )
        };
        let selected = vec![
            variant("aw", "alpha", "wheel"),
            variant("as", "alpha", "sdist"),
            // `ghost` is not installed: both its variants are kept, with a
            // warning, and neither view is fetched.
            variant("gw", "ghost", "wheel"),
            variant("gs", "ghost", "sdist"),
            variant("bw", "beta", "wheel"),
            variant("bs", "beta", "sdist"),
        ];
        let options = CrawlerOptions {
            cwd: site.path().to_path_buf(),
            global: false,
            global_prefix: Some(site.path().to_path_buf()),
        };
        let (kept, warnings, views) = filter_to_installed_releases(
            &selected,
            /*all_releases=*/ false,
            &options,
            /*quiet=*/ true,
            &test_client(&server.uri()).await,
        )
        .await;

        let mut kept_purls: Vec<&str> = kept.iter().map(|s| s.purl.as_str()).collect();
        kept_purls.sort();
        assert_eq!(
            kept_purls,
            vec![
                "pkg:pypi/alpha@1.0.0?artifact_id=wheel",
                "pkg:pypi/beta@1.0.0?artifact_id=wheel",
                "pkg:pypi/ghost@1.0.0?artifact_id=sdist",
                "pkg:pypi/ghost@1.0.0?artifact_id=wheel",
            ],
            "warnings={warnings:?}"
        );
        let mut cached: Vec<(String, String)> = views
            .iter()
            .map(|(u, v)| (u.clone(), v.uuid.clone()))
            .collect();
        cached.sort();
        // Narrowed-out variants' views are dropped, so only the two kept
        // wheels ride on — each under its own uuid. A view that landed on
        // the wrong variant would both keep the wrong variant above and
        // pair a uuid with another variant's response here.
        assert_eq!(
            cached,
            vec![(uuid("aw"), uuid("aw")), (uuid("bw"), uuid("bw"))],
            "each cached view must be its own variant's"
        );
        // `.expect` counts are verified on drop.
        drop(server);
    }

    /// The env guard must RESTORE a variable that was set before the scrub —
    /// the suite depends on it not leaking scrubbed state across tests.
    #[test]
    #[serial_test::serial]
    fn env_var_guard_restores_previously_set_values() {
        std::env::set_var("COVGAP_GET_GUARD_PROBE", "original");
        {
            let _guard = EnvVarGuard::scrub(&["COVGAP_GET_GUARD_PROBE"]);
            assert!(
                std::env::var("COVGAP_GET_GUARD_PROBE").is_err(),
                "scrub must remove the var"
            );
        }
        assert_eq!(
            std::env::var("COVGAP_GET_GUARD_PROBE").as_deref(),
            Ok("original"),
            "drop must restore the pre-scrub value"
        );
        std::env::remove_var("COVGAP_GET_GUARD_PROBE");
    }

    /// Release-variant narrowing must not randomize the selection order.
    ///
    /// `filter_to_installed_releases` buckets every release-variant purl
    /// (PyPI / RubyGems / Maven) into a `HashMap` keyed by base purl and
    /// then drains it, so the singleton bases — the common case — came back
    /// in `HashMap` iteration order. That order is the download loop's
    /// order, which is the order `download.patches` / `apply.patches` are
    /// emitted in, so two identical runs produced different JSON. Every
    /// sibling collection in the same envelope is purl-sorted
    /// (`scan`'s `packages`, the agent flow's `skip_records`), so this one
    /// must be too.
    #[tokio::test]
    async fn release_narrowing_keeps_a_stable_purl_order() {
        let names = [
            "urllib3",
            "requests",
            "idna",
            "certifi",
            "charset-normalizer",
            "jinja2",
            "markupsafe",
            "werkzeug",
            "click",
            "itsdangerous",
            "blinker",
            "flask",
        ];
        let selected: Vec<PatchSearchResult> = {
            let mut v: Vec<PatchSearchResult> = names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    mk_patch(
                        &format!("uuid-{i}"),
                        &format!("pkg:pypi/{n}@1.0.0?artifact_id=wheel"),
                        "free",
                        "2026-01-01T00:00:00Z",
                    )
                })
                .collect();
            v.sort_by(|a, b| a.purl.cmp(&b.purl));
            v
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        // No mock server is needed: every base has exactly one variant, so
        // the narrowing returns before it queries the crawler or the API.
        let client = test_client("http://127.0.0.1:1").await;
        let (kept, _warnings, _views) =
            filter_to_installed_releases(&selected, false, &options, true, &client).await;
        let got: Vec<&str> = kept.iter().map(|p| p.purl.as_str()).collect();
        let want: Vec<&str> = selected.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            got, want,
            "the narrowing must preserve the caller's purl order, not the \
             HashMap's bucket order"
        );
    }

    /// The vendored/agent envelope's `download.patches` array must come out
    /// in the same order on every run. It is built by walking the narrowed
    /// selection, so the `HashMap`-ordered narrowing above leaked straight
    /// into the JSON: two identical runs of the same project emitted the
    /// same records in different orders. No view is mounted — wiremock
    /// answers 404, so every purl lands on the fetch-miss arm and records
    /// one `patches[]` entry, which is all this pins.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patches_json_is_purl_ordered() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL"]);
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let names = [
            "urllib3",
            "requests",
            "idna",
            "certifi",
            "charset-normalizer",
            "jinja2",
            "markupsafe",
            "werkzeug",
            "click",
            "itsdangerous",
            "blinker",
            "flask",
        ];
        let mut selected: Vec<PatchSearchResult> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                mk_patch(
                    &format!("{:08x}-aaaa-4aaa-8aaa-aaaaaaaaaaaa", i),
                    &format!("pkg:pypi/{n}@1.0.0?artifact_id=wheel"),
                    "free",
                    "2026-01-01T00:00:00Z",
                )
            })
            .collect();
        selected.sort_by(|a, b| a.purl.cmp(&b.purl));

        let (_code, json, _records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        let got: Vec<&str> = json["patches"]
            .as_array()
            .expect("patches[]")
            .iter()
            .map(|p| p["purl"].as_str().expect("purl"))
            .collect();
        let want: Vec<&str> = selected.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            got, want,
            "download.patches must be emitted in the selection's purl order; json={json}"
        );
    }
}
