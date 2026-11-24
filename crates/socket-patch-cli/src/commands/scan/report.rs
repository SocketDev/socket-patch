//! `scan`'s human report: one row per package a run patched, and the
//! closing totals of the whole invocation (`Patched 22 packages in 3
//! projects, fixing 39 vulnerabilities ...`, what Socket measured about
//! those patches, then what is left to patch).
//!
//! The counts are occurrences: a package patched in three project
//! directories counts three times, and so does each advisory its patch
//! fixes there. A "vulnerability" is one advisory id as the rows show it
//! (a CVE, or the advisory's own id when it has none).
//!
//! Everything that builds text is pure (style and width are passed in), so
//! each line is unit-tested byte for byte. Only [`Run`] prints, and only
//! it talks to the network: on a terminal it asks the patch service what
//! it measured about the selected patches, in the background, while the
//! run does its work.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use socket_patch_core::api::client::ApiClient;
use socket_patch_core::api::ranking::{cmp_batch_infos, severity_order};
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult, PatchStatistics};
use socket_patch_core::policy::filter::{Reachability, SelectionFilter};
use socket_patch_core::utils::purl_key::PurlKey;

use crate::args::GlobalArgs;
use crate::commands::measured::{self, evidence, Measured, Measurement};
use crate::ui::{self, plural, Style};

/// Advisory ids a row names before `(+N)` (unless `--verbose`).
const IDS_SHOWN: usize = 2;
/// Columns of the closing meter.
const METER_CELLS: usize = 40;
/// How long a project directory's rows wait for measurements still on
/// their way once the directory's own work is done. They are a courtesy:
/// past this the rows print without them, and the answers that come in
/// later still count in the closing lines.
const ROWS_WAIT: Duration = Duration::from_millis(400);
/// Most patches whose measurements one request round asks for (a project
/// directory makes two: the likely selection, then what was selected).
const MEASURED_PER_ROUND: usize = 100;
/// How long the closing lines wait for the last measurements.
const CLOSING_WAIT: Duration = Duration::from_millis(1500);
/// The engineering hours one package upgrade is taken to cost, for the
/// closing lines' estimate of the work patching saved: finding a release
/// with the fix, moving to it, getting the build and the tests through
/// everything else that changed in it, and the review. An assumption, not
/// a measurement: the line that uses it says "about" and states it.
const UPGRADE_HOURS: usize = 2;
/// The package column is as wide as the longest name, up to this many
/// columns; a longer name keeps its `@version` and loses its middle.
const MAX_NAME_COL: usize = 44;

/// One package with a patch on offer, as the report counts and shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Package {
    /// The package purl as the batch lookup spells it.
    pub(crate) purl: String,
    /// The patches the run selected for it (one per release variant);
    /// empty when none could be selected.
    pub(crate) uuids: Vec<String>,
    /// The worst severity among the advisories the selection fixes, or
    /// among the package's patches when nothing was selected.
    pub(crate) severity: Option<String>,
    /// The ids to show for what the selection fixes.
    pub(crate) fixes: Vec<String>,
    /// The ids to show for what it leaves: advisories only the package's
    /// other patches fix. Every advisory of a package with no selection.
    pub(crate) unpatched: Vec<String>,
    /// The ids of `unpatched` that are waiting on a merged patch: another
    /// patch the account can download fixes them, and the patch that
    /// fixes them together with the selection is not published yet (see
    /// [`package_coverage`](super::discovery::package_coverage)).
    pub(crate) merge_pending: Vec<String>,
    /// The ids of `unpatched` that need a paid plan: only patches this
    /// account cannot download fix them.
    pub(crate) needs_paid: Vec<String>,
    /// How many of `fixes` are critical, and how many high.
    pub(crate) fixed_critical: usize,
    pub(crate) fixed_high: usize,
    /// How many of `fixes` / `unpatched` a reachability finding of the
    /// run's selection filter marks reachable (0 without a filter).
    pub(crate) fixed_reachable: usize,
    pub(crate) unpatched_reachable: usize,
    /// Every patch of the package needs a paid plan this account lacks.
    pub(crate) paid_only: bool,
    /// The run patches what the project's lockfile resolves, and the
    /// lockfile does not name this package: a copy installed on this
    /// machine that the project does not use. It is not the project's to
    /// patch, so it is never counted as left.
    pub(crate) outside_project: bool,
}

impl Package {
    /// Whether one of the package's selected patches is in `landed`.
    fn landed(&self, landed: &HashSet<&str>) -> bool {
        self.uuids.iter().any(|uuid| landed.contains(uuid.as_str()))
    }

    /// What was measured about the package's selected patch.
    fn measured<'a>(&self, measured: &'a Measured) -> Option<&'a PatchStatistics> {
        self.uuids.iter().find_map(|uuid| measured.get(uuid))
    }
}

/// What the detail records say about one advisory id of a package: its
/// worst severity and every id it is known by (itself, its CVEs, the
/// advisory they alias).
#[derive(Default)]
struct IdFacts<'a> {
    severity: Option<&'a str>,
    aliases: Vec<&'a str>,
}

/// The facts of every advisory id `records` name, by the id uppercased.
fn id_facts<'a>(records: &[&'a PatchSearchResult]) -> HashMap<String, IdFacts<'a>> {
    let mut facts: HashMap<String, IdFacts<'a>> = HashMap::new();
    for record in records {
        for (advisory, vuln) in &record.vulnerabilities {
            let group: Vec<&str> = std::iter::once(advisory.as_str())
                .chain(vuln.cves.iter().map(String::as_str))
                .collect();
            for id in &group {
                let entry = facts.entry(id.to_ascii_uppercase()).or_default();
                let worse = entry.severity.is_none_or(|known| {
                    severity_order(Some(&vuln.severity)) < severity_order(Some(known))
                });
                if worse {
                    entry.severity = Some(vuln.severity.as_str());
                }
                for alias in &group {
                    if !entry.aliases.contains(alias) {
                        entry.aliases.push(alias);
                    }
                }
            }
        }
    }
    facts
}

/// The report's view of every package in `packages` (the batch lookup's
/// packages with patches, in its order). `selected` is the patch the run
/// chose for each package that got one, `records` every patch record the
/// run fetched (they pair an advisory with its CVEs and its severity), and
/// `filter` the run's selection filter, whose reachability findings mark
/// advisories reachable. `in_project` says whether the project the run
/// patches uses a package (see [`Package::outside_project`]).
pub(crate) fn plan(
    packages: &[BatchPackagePatches],
    selected: &[PatchSearchResult],
    records: &[&PatchSearchResult],
    can_access_paid_patches: bool,
    filter: Option<&SelectionFilter>,
    in_project: &dyn Fn(&str) -> bool,
) -> Vec<Package> {
    fn by_package<'a>(
        patches: &[&'a PatchSearchResult],
    ) -> HashMap<PurlKey, Vec<&'a PatchSearchResult>> {
        let mut map: HashMap<PurlKey, Vec<&PatchSearchResult>> = HashMap::new();
        for patch in patches {
            map.entry(PurlKey::new(&patch.purl))
                .or_default()
                .push(patch);
        }
        map
    }
    let selected: Vec<&PatchSearchResult> = selected.iter().collect();
    let selected_of = by_package(&selected);
    let records_of = by_package(records);
    let filter = filter.filter(|f| f.has_findings());
    packages
        .iter()
        .map(|pkg| {
            let key = PurlKey::new(&pkg.purl);
            let chosen = selected_of.get(&key).map_or(&[][..], Vec::as_slice);
            let coverage = super::discovery::package_coverage(pkg, chosen, can_access_paid_patches);
            // The selection's own records come first: they are the ones
            // that say what a fixed id is.
            let known: Vec<&PatchSearchResult> = chosen
                .iter()
                .chain(records_of.get(&key).into_iter().flatten())
                .copied()
                .collect();
            let facts = id_facts(&known);
            let severity_of = |id: &str| facts.get(&id.to_ascii_uppercase())?.severity;
            let reachable = |id: &&String| {
                let Some(filter) = filter else {
                    return false;
                };
                let aliases: Vec<String> = match facts.get(&id.to_ascii_uppercase()) {
                    Some(known) => known.aliases.iter().map(|a| a.to_string()).collect(),
                    None => vec![id.to_string()],
                };
                filter.reachability(&pkg.purl, &aliases) == Some(Reachability::Reachable)
            };
            let fixed_at = |rank: u8| {
                coverage
                    .fixes
                    .iter()
                    .filter(|id| severity_of(id).is_some_and(|s| severity_order(Some(s)) == rank))
                    .count()
            };
            // The severity of what the selection fixes: its records' own
            // advisories, else what the lookup said of the selected patches
            // (of every patch, when none was selected).
            let listed = |selected_only: bool| {
                pkg.patches
                    .iter()
                    .filter(|p| !selected_only || chosen.iter().any(|c| c.uuid == p.uuid))
                    .filter_map(|p| p.severity.as_deref())
                    .min_by_key(|s| severity_order(Some(s)))
            };
            let severity = chosen
                .iter()
                .flat_map(|p| p.vulnerabilities.values())
                .map(|v| v.severity.as_str())
                .min_by_key(|s| severity_order(Some(s)))
                .or_else(|| listed(!chosen.is_empty()));
            Package {
                purl: pkg.purl.clone(),
                severity: severity.map(str::to_string),
                fixed_critical: fixed_at(0),
                fixed_high: fixed_at(1),
                fixed_reachable: coverage.fixes.iter().filter(reachable).count(),
                unpatched_reachable: coverage.unpatched.iter().filter(reachable).count(),
                paid_only: !can_access_paid_patches
                    && !pkg.patches.is_empty()
                    && pkg.patches.iter().all(|p| p.tier != "free"),
                outside_project: !in_project(&pkg.purl),
                uuids: coverage.uuids,
                fixes: coverage.fixes,
                unpatched: coverage.unpatched,
                merge_pending: coverage.merge_pending,
                needs_paid: coverage.needs_paid,
            }
        })
        .collect()
}

/// What a run did, in the units the closing report counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    /// Packages whose patch landed (or, on a dry run, would).
    pub(crate) patched: usize,
    /// Advisories those patches fix, and how many of them are critical,
    /// high, and reachable.
    pub(crate) fixed: usize,
    pub(crate) fixed_critical: usize,
    pub(crate) fixed_high: usize,
    pub(crate) fixed_reachable: usize,
    /// Advisories left on patched packages that are waiting on a merged
    /// patch ([`Package::merge_pending`]), and how many patched packages
    /// have one.
    pub(crate) left_merge: usize,
    pub(crate) merge_packages: usize,
    /// The other advisories left on patched packages that a patch the
    /// account can download fixes: one patch is applied per package
    /// version, and the run did not select the one that fixes them.
    pub(crate) left_upgrade: usize,
    /// Advisories that need a paid plan: the ones left on patched
    /// packages that only a paid patch fixes ([`Package::needs_paid`]),
    /// and every advisory of a package whose every patch is paid.
    pub(crate) left_paid: usize,
    /// Advisories of the other packages the run did not patch.
    pub(crate) left_unpatched: usize,
    /// How many of the three `left_*` counts are reachable.
    pub(crate) left_reachable: usize,
    /// Patched packages whose patch was measured, and what the
    /// measurements add up to: exploits blocked of those run against the
    /// patches, and package tests passing of those run on them.
    pub(crate) measured: usize,
    pub(crate) exploits_blocked: u64,
    pub(crate) exploits: u64,
    pub(crate) tests_passing: u64,
    pub(crate) tests: u64,
    /// Some lookup of the run saw free patches only (the public proxy):
    /// "nothing left" then speaks for the free patches alone.
    pub(crate) free_only: bool,
}

impl Counts {
    /// The counts of one project directory: `plan` judged by the patches
    /// that landed there (`landed`, by uuid). What was measured about
    /// them is added once every answer is in ([`Self::verify`]).
    pub(crate) fn of(plan: &[Package], landed: &HashSet<&str>) -> Self {
        let mut counts = Counts::default();
        for pkg in plan {
            if pkg.landed(landed) {
                counts.patched += 1;
                counts.fixed += pkg.fixes.len();
                counts.fixed_critical += pkg.fixed_critical;
                counts.fixed_high += pkg.fixed_high;
                counts.fixed_reachable += pkg.fixed_reachable;
                counts.left_merge += pkg.merge_pending.len();
                counts.merge_packages += usize::from(!pkg.merge_pending.is_empty());
                counts.left_paid += pkg.needs_paid.len();
                counts.left_upgrade +=
                    pkg.unpatched.len() - pkg.merge_pending.len() - pkg.needs_paid.len();
                counts.left_reachable += pkg.unpatched_reachable;
            } else if pkg.outside_project {
                // Not the project's package: nothing of it is left to
                // patch here.
            } else {
                let advisories = pkg.fixes.len() + pkg.unpatched.len();
                if pkg.paid_only {
                    counts.left_paid += advisories;
                } else {
                    counts.left_unpatched += advisories;
                }
                counts.left_reachable += pkg.fixed_reachable + pkg.unpatched_reachable;
            }
        }
        counts
    }

    /// Add what was `measured` about the patches of the patched packages
    /// (`patched`: each one's selected uuids).
    pub(crate) fn verify(&mut self, patched: &[Vec<String>], measured: &Measured) {
        for uuids in patched {
            let Some(stats) = uuids.iter().find_map(|uuid| measured.get(uuid)) else {
                continue;
            };
            self.measured += 1;
            if let Some(pocs) = stats.pocs {
                self.exploits_blocked += pocs.blocked_after.count;
                self.exploits += pocs.blocked_after.total;
            }
            if let Some(tests) = stats.tests {
                self.tests_passing += tests.after.count;
                self.tests += tests.after.total;
            }
        }
    }

    fn add(&mut self, other: &Counts) {
        self.patched += other.patched;
        self.fixed += other.fixed;
        self.fixed_critical += other.fixed_critical;
        self.fixed_high += other.fixed_high;
        self.fixed_reachable += other.fixed_reachable;
        self.left_merge += other.left_merge;
        self.merge_packages += other.merge_packages;
        self.left_upgrade += other.left_upgrade;
        self.left_paid += other.left_paid;
        self.left_unpatched += other.left_unpatched;
        self.left_reachable += other.left_reachable;
    }

    /// Advisories with a patch on offer that the run did not fix.
    pub(crate) fn left(&self) -> usize {
        self.left_merge + self.left_upgrade + self.left_paid + self.left_unpatched
    }
}

/// `left` as a share of `fixed + left`, for the closing lines: a whole
/// percentage that never rounds a remainder away (`<1%`) or the fixed
/// part to nothing (`>99%`). `None` when nothing was fixed, where the
/// share says nothing the count does not.
fn percent_left(fixed: usize, left: usize) -> Option<String> {
    if fixed == 0 || left == 0 {
        return None;
    }
    let total = fixed + left;
    let rounded = (left * 100 + total / 2) / total;
    Some(match rounded {
        0 => "<1%".to_string(),
        100 => ">99%".to_string(),
        n => format!("{n}%"),
    })
}

/// How a row names its package: `name@version` when every row of the
/// project is of one ecosystem (the scan line above names it), the full
/// purl otherwise, where a bare name could be either's.
fn display_names(packages: &[&Package]) -> Vec<String> {
    let purls: Vec<&str> = packages.iter().map(|p| p.purl.as_str()).collect();
    ui::package_names(&purls)
}

/// A row's advisory cell at `shown` ids: `CVE-1, CVE-2 (+3)`; every id
/// when `shown` is `None` (`--verbose`); `3 fixed` when there is no room
/// for an id. Empty for a patch that names no advisory.
fn ids_cell(ids: &[String], shown: Option<usize>) -> String {
    match shown {
        None => ids.join(", "),
        Some(_) if ids.is_empty() => String::new(),
        Some(0) => format!("{} fixed", ids.len()),
        Some(n) if ids.len() <= n => ids.join(", "),
        Some(n) => format!("{} (+{})", ids[..n].join(", "), ids.len() - n),
    }
}

/// The rows of one project directory: each package of `plan` whose patch
/// is in `landed`, worst severity first, then by name.
///
/// ```text
///   CRITICAL  shell-quote@1.10.0  CVE-2026-102422                 exploit blocked, 25/25 tests
///   HIGH      undici@8.10.0       CVE-2026-84961, CVE-2026-85024  2 exploits blocked, 35/35 tests  3 unpatched
/// ```
///
/// A row names its first two advisory ids and counts the rest, then says
/// what was `measured` about its patch, then how many advisories of the
/// package stay unpatched. On a terminal `cap` columns wide it names
/// fewer ids, and then drops the measurements, rather than wrap.
/// `--verbose` names every id, and lists the unpatched ones on a line of
/// their own. Where the terminal shows one, `style` opens each row of a
/// patch that is in place (`done`) with a check mark; the rows of a dry
/// run and of a report, whose patches are only on offer, keep the column
/// and leave it blank.
pub(crate) fn rows(
    plan: &[Package],
    landed: &HashSet<&str>,
    measured: &Measured,
    verbose: bool,
    style: Style,
    cap: Option<usize>,
    done: bool,
) -> Vec<String> {
    let mut patched: Vec<&Package> = plan.iter().filter(|p| p.landed(landed)).collect();
    if patched.is_empty() {
        return Vec::new();
    }
    patched.sort_by(|a, b| {
        severity_order(a.severity.as_deref())
            .cmp(&severity_order(b.severity.as_deref()))
            .then_with(|| a.purl.cmp(&b.purl))
    });
    let color = style.color;
    let names = display_names(&patched);
    let name_w = names
        .iter()
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0)
        .min(MAX_NAME_COL);
    // One spelling whatever the source's (`HIGH` from the service,
    // `moderate` from an advisory database).
    let severities: Vec<String> = patched
        .iter()
        .map(|p| p.severity.as_deref().unwrap_or("unknown").to_uppercase())
        .collect();
    let sev_w = severities
        .iter()
        .map(|s| s.chars().count())
        .max()
        .unwrap_or(0);
    let evidence: Vec<String> = patched
        .iter()
        .map(|p| p.measured(measured).map(evidence).unwrap_or_default())
        .collect();

    // One row: the cells that are there, each padded to its column only
    // while a later cell follows it.
    let build = |shown: Option<usize>, with_evidence: bool| -> Vec<String> {
        let ids: Vec<String> = patched
            .iter()
            .map(|p| ids_cell(&p.fixes, shown))
            .map(|ids| match ids.is_empty() {
                true => ids,
                false => ui::dim(&ids, color),
            })
            .collect();
        // The columns after the name: the ids, then the measurements. One
        // that is empty in every row is left out, not left blank.
        let columns: Vec<(&[String], usize)> = [Some(&ids), with_evidence.then_some(&evidence)]
            .into_iter()
            .flatten()
            .map(|cells| {
                let width = cells.iter().map(|c| ui::visible_width(c)).max();
                (cells.as_slice(), width.unwrap_or(0))
            })
            .filter(|(_, width)| *width > 0)
            .collect();
        (0..patched.len())
            .map(|i| {
                let mut row = format!(
                    "{} {}  {}",
                    if done { style.check() } else { " ".to_string() },
                    ui::pad(&ui::severity(&severities[i], color), sev_w),
                    ui::pad(&super::render::elide_purl(&names[i], name_w), name_w),
                );
                for (cells, width) in &columns {
                    row.push_str("  ");
                    row.push_str(&ui::pad(&cells[i], *width));
                }
                if !patched[i].unpatched.is_empty() {
                    let note = format!("{} unpatched", patched[i].unpatched.len());
                    row.push_str("  ");
                    row.push_str(&ui::paint(&note, "33", color));
                }
                row.trim_end().to_string()
            })
            .collect()
    };

    if verbose {
        let mut out = Vec::new();
        for (row, pkg) in build(None, true).into_iter().zip(&patched) {
            out.push(row);
            let among = |ids: &'_ [String]| -> Vec<&str> {
                let listed = pkg.unpatched.iter().filter(|id| ids.contains(id));
                listed.map(String::as_str).collect()
            };
            let rest: Vec<&str> = pkg
                .unpatched
                .iter()
                .filter(|id| !pkg.merge_pending.contains(id) && !pkg.needs_paid.contains(id))
                .map(String::as_str)
                .collect();
            for (what, ids) in [
                ("still unpatched", rest),
                ("waiting on a merged patch", among(&pkg.merge_pending)),
                ("needs a paid Socket plan", among(&pkg.needs_paid)),
            ] {
                if !ids.is_empty() {
                    let line = format!("{what}: {}", ids.join(", "));
                    out.push(format!("      {}", ui::paint(&line, "33", color)));
                }
            }
        }
        return out;
    }
    let fits =
        |rows: &[String]| cap.is_none_or(|cap| rows.iter().all(|row| ui::visible_width(row) < cap));
    // What a narrow terminal gives up, in order: the second id, the
    // measurements, then the ids altogether (a count stays).
    [(2, true), (1, true), (2, false), (1, false), (0, false)]
        .into_iter()
        .map(|(shown, with_evidence)| build(Some(shown.min(IDS_SHOWN)), with_evidence))
        .find(|rows| fits(rows))
        // Too narrow even for the counts: the widest form reads best
        // wrapped.
        .unwrap_or_else(|| build(Some(IDS_SHOWN), true))
}

/// The closing meter: how much of what could be patched was, as a bar and
/// a percentage (`━━━━━━────  63% patched`). Drawn only where the terminal
/// shows glyphs: the sentence above it already says the share.
fn meter(fixed: usize, left: usize, style: Style) -> Option<String> {
    if !style.glyphs || fixed == 0 || left == 0 {
        return None;
    }
    let total = fixed + left;
    // The share the "left" sentence leaves, so the two always add up.
    let percent = 100 - ((left * 100 + total / 2) / total).clamp(1, 99);
    let filled = (METER_CELLS * percent / 100).clamp(1, METER_CELLS - 1);
    Some(format!(
        "{}{}  {}",
        ui::paint(&"━".repeat(filled), "32", style.color),
        ui::paint(&"━".repeat(METER_CELLS - filled), "33", style.color),
        ui::dim(&format!("{percent}% patched"), style.color),
    ))
}

/// The closing lines of a run: what it patched, what was measured about
/// those patches, what is left to patch, and (with reachability findings)
/// the last again for the reachable advisories alone. Empty when the run
/// found nothing to count.
///
/// ```text
/// Patched 22 packages in 3 projects, fixing 39 vulnerabilities (5 critical, 21 high) in 4.2s.
/// Verified: 24 of 24 exploits blocked, 1208 of 1208 package tests passing.
/// Saved about 44 hours of engineering time (22 package upgrades at ~2 hours each).
/// 18 vulnerabilities left to patch (32%): 6 are waiting on a merged patch, 8 need a package upgrade, 4 are in packages this run did not patch.
/// Merged patches not ready yet for 4 packages: Socket is still processing them. Run `socket-patch scan` again later to apply them.
/// Reachable: 9 fixed, 2 left to patch (18%).
/// ```
///
/// An advisory left on a patched package is waiting on a merged patch when
/// another patch the account can download fixes it: the patch that fixes
/// it together with the one applied is not published yet, and the line
/// under the count says so.
///
/// Where the terminal shows glyphs, the lines of what was done open with a
/// check mark (the others are indented to match) and a meter closes them.
pub(crate) fn closing(
    counts: &Counts,
    projects: usize,
    dry_run: bool,
    reachability: bool,
    elapsed: Option<Duration>,
    style: Style,
) -> Vec<String> {
    let left = counts.left();
    if counts.patched == 0 && left == 0 {
        return Vec::new();
    }
    let color = style.color;
    let num = |n: usize, one: &str, many: &str| {
        format!(
            "{} {}",
            ui::bold(&n.to_string(), color),
            if n == 1 { one } else { many }
        )
    };
    // With glyphs every line has a two-column gutter: a check mark for
    // what was done, blank otherwise.
    let done = |line: String| {
        if style.glyphs && !dry_run {
            format!("{} {line}", style.check())
        } else if style.glyphs {
            format!("  {line}")
        } else {
            line
        }
    };
    let plain = |line: String| {
        if style.glyphs {
            format!("  {line}")
        } else {
            line
        }
    };
    let mut lines = Vec::new();
    if counts.patched > 0 {
        let verb = if dry_run { "Would patch" } else { "Patched" };
        let mut line = format!(
            "{} {}",
            ui::paint(verb, "1;32", color),
            num(counts.patched, "package", "packages")
        );
        if projects > 1 {
            line.push_str(&format!(" in {}", num(projects, "project", "projects")));
        }
        if counts.fixed > 0 {
            line.push_str(&format!(
                ", fixing {}",
                num(counts.fixed, "vulnerability", "vulnerabilities")
            ));
            let mut tiers = Vec::new();
            if counts.fixed_critical > 0 {
                tiers.push(format!("{} critical", counts.fixed_critical));
            }
            if counts.fixed_high > 0 {
                tiers.push(format!("{} high", counts.fixed_high));
            }
            if !tiers.is_empty() {
                line.push_str(&format!(" ({})", tiers.join(", ")));
            }
        }
        if let Some(elapsed) = elapsed {
            line.push_str(&format!(" in {:.1}s", elapsed.as_secs_f64()));
        }
        line.push('.');
        lines.push(done(line));
    }
    // What Socket measured about the patches that landed: the exploits of
    // the advisories they fix, run against the patched packages, and the
    // packages' own tests, run on them.
    let mut verified = Vec::new();
    if counts.exploits > 0 {
        verified.push(format!(
            "{} of {} blocked",
            ui::bold(&counts.exploits_blocked.to_string(), color),
            plural(counts.exploits as usize, "exploit", "exploits"),
        ));
    }
    if counts.tests > 0 {
        verified.push(format!(
            "{} of {} passing",
            ui::bold(&counts.tests_passing.to_string(), color),
            plural(counts.tests as usize, "package test", "package tests"),
        ));
    }
    if !verified.is_empty() {
        let all =
            counts.exploits_blocked == counts.exploits && counts.tests_passing == counts.tests;
        let mut line = format!("Verified: {}", verified.join(", "));
        if counts.measured < counts.patched {
            line.push_str(&format!(
                " (measured for {} of {})",
                counts.measured,
                plural(counts.patched, "patch", "patches")
            ));
        }
        line.push('.');
        lines.push(if all { done(line) } else { plain(line) });
    }
    // What the patches stood in for: an upgrade of each patched package,
    // in every project it is patched in. An estimate, and it says so.
    if counts.patched > 0 {
        let hours = counts.patched * UPGRADE_HOURS;
        lines.push(plain(format!(
            "{} about {} of engineering time ({} at ~{UPGRADE_HOURS} hours{}).",
            if dry_run { "Would save" } else { "Saved" },
            num(hours, "hour", "hours"),
            plural(counts.patched, "package upgrade", "package upgrades"),
            if counts.patched == 1 { "" } else { " each" },
        )));
    }
    if left == 0 {
        // The public proxy answers for free patches only: what a paid
        // plan would fix is unknown there, so the line claims no more than
        // the lookup saw.
        let nothing = if counts.free_only {
            "No free patches left to apply."
        } else {
            "Nothing left to patch."
        };
        lines.push(plain(nothing.to_string()));
    } else {
        let mut why = Vec::new();
        if counts.left_merge > 0 {
            why.push(format!(
                "{} waiting on a merged patch",
                plural(counts.left_merge, "is", "are")
            ));
        }
        if counts.left_upgrade > 0 {
            why.push(format!(
                "{} a package upgrade",
                plural(counts.left_upgrade, "needs", "need")
            ));
        }
        if counts.left_paid > 0 {
            why.push(format!(
                "{} a paid Socket plan",
                plural(counts.left_paid, "needs", "need")
            ));
        }
        if counts.left_unpatched > 0 {
            why.push(format!(
                "{} in packages {}",
                plural(counts.left_unpatched, "is", "are"),
                if dry_run {
                    "a run would not patch"
                } else {
                    "this run did not patch"
                },
            ));
        }
        let share = percent_left(counts.fixed, left)
            .map(|p| format!(" ({p})"))
            .unwrap_or_default();
        lines.push(plain(format!(
            "{} {}{share}: {}.",
            ui::paint(&left.to_string(), "1;33", color),
            match (left == 1, dry_run) {
                (true, false) => "vulnerability left to patch",
                (false, false) => "vulnerabilities left to patch",
                (true, true) => "vulnerability would be left to patch",
                (false, true) => "vulnerabilities would be left to patch",
            },
            why.join(", ")
        )));
        // The advisories waiting on a merged patch are not the user's to
        // fix: the patch is on its way, and a later scan moves to it.
        if counts.left_merge > 0 {
            lines.push(plain(match counts.merge_packages {
                1 => "Merged patch not ready yet for 1 package: Socket is still processing it. \
                      Run `socket-patch scan` again later to apply it."
                    .to_string(),
                packages => format!(
                    "Merged patches not ready yet for {packages} packages: Socket is still \
                     processing them. Run `socket-patch scan` again later to apply them."
                ),
            }));
        }
    }
    if reachability {
        let share = percent_left(counts.fixed_reachable, counts.left_reachable)
            .map(|p| format!(" ({p})"))
            .unwrap_or_default();
        lines.push(plain(format!(
            "Reachable: {} {}, {} left to patch{share}.",
            ui::bold(&counts.fixed_reachable.to_string(), color),
            if dry_run { "would be fixed" } else { "fixed" },
            ui::bold(&counts.left_reachable.to_string(), color),
        )));
    }
    if let Some(meter) = meter(counts.fixed, left, style) {
        lines.push(plain(meter));
    }
    lines
}

/// The report of one `scan` invocation: every project directory's run
/// prints its rows through it and adds its counts, and the invocation
/// prints the totals once, when the last directory is done.
pub(crate) struct Run {
    /// Neither `--json` nor `--silent`: the report prints.
    human: bool,
    /// The run shows measurements ([`measured::wanted`]).
    measures: bool,
    dry_run: bool,
    verbose: bool,
    started: Instant,
    counts: Counts,
    /// Project directories a patch landed in.
    projects: usize,
    /// Some directory's selection filter holds reachability findings.
    reachability: bool,
    /// What the patch service measured about the selected patches, as far
    /// as its answers have been collected ([`Self::settle`]).
    measured: Measured,
    /// The measurement requests still out ([`Self::measure`]).
    measuring: Vec<tokio::task::JoinHandle<Vec<Measurement>>>,
    /// The window every round of measurement requests shares, with the
    /// route it is for (`true`: the public proxy).
    window: Option<(bool, measured::Window)>,
    /// The patches whose measurements have been asked for.
    requested: HashSet<String>,
    /// The selected uuids of every package a patch landed in, for the
    /// closing lines' measurements.
    patched: Vec<Vec<String>>,
    /// The API client the first project directory built, with whether it
    /// is on the public proxy ([`Self::client`]).
    client: Option<(ApiClient, bool)>,
    /// The paid-plan line has printed ([`Self::upsell`]).
    upsold: bool,
    /// The run covers several project directories: its client remembers
    /// what the patch service answers ([`Self::share_lookups`]).
    shares_lookups: bool,
    /// Some project directory's lookup ran on the public proxy.
    free_only: bool,
}

impl Run {
    pub(crate) fn new(common: &GlobalArgs) -> Self {
        Run {
            human: !common.json && !common.silent,
            measures: measured::wanted(common),
            dry_run: common.dry_run,
            verbose: common.verbose,
            started: Instant::now(),
            counts: Counts::default(),
            projects: 0,
            reachability: false,
            measured: Measured::new(),
            measuring: Vec::new(),
            window: None,
            requested: HashSet::new(),
            patched: Vec::new(),
            client: None,
            upsold: false,
            shares_lookups: false,
            free_only: false,
        }
    }

    /// The run scans several project directories, which hold many of the
    /// same packages: its client remembers what the patch service answers
    /// about a package, so each is asked about once for the whole run
    /// (and can be asked about ahead of its directory's turn). A run of
    /// one directory asks each question once anyway and is left as it is.
    pub(crate) fn share_lookups(&mut self) {
        self.shares_lookups = true;
        self.client = self
            .client
            .take()
            .map(|(client, proxy)| (client.remembering_lookups(), proxy));
    }

    /// A project directory's lookup ran on the public proxy, which answers
    /// for free patches only: the closing lines then say "no free patches
    /// left", never "nothing left".
    pub(crate) fn saw_free_patches_only(&mut self) {
        self.free_only = true;
    }

    /// Print the paid-plan line (stdout), once per invocation: where a
    /// project directory finds only paid patches, else under the closing
    /// lines of a run that leaves advisories to a paid plan.
    pub(crate) fn upsell(&mut self) {
        if self.human && !std::mem::replace(&mut self.upsold, true) {
            println!("{}", ui::PAID_UPGRADE);
        }
    }

    /// The invocation's API client, built by the first project directory
    /// that needs one (`build`) and shared by the rest: one connection and
    /// one org lookup for the whole run, not one per directory.
    pub(crate) async fn client<F>(&mut self, build: F) -> (ApiClient, bool)
    where
        F: std::future::Future<Output = (ApiClient, bool)>,
    {
        match &self.client {
            Some(client) => client.clone(),
            None => {
                let (mut client, proxy) = build.await;
                if self.shares_lookups {
                    client = client.remembering_lookups();
                }
                self.client = Some((client.clone(), proxy));
                (client, proxy)
            }
        }
    }

    /// A directory's run moved to the public proxy (the API refused its
    /// token): the directories after it start there, and are spared the
    /// refusal and its warning.
    pub(crate) fn fell_back_to(&mut self, proxy: &ApiClient) {
        let mut proxy = proxy.clone();
        if self.shares_lookups {
            proxy = proxy.remembering_lookups();
        }
        self.client = Some((proxy, true));
    }

    /// A project directory's selection filter: once one holds
    /// reachability findings, the closing lines also count the reachable
    /// advisories on their own.
    pub(crate) fn reads_reachability(&mut self, filter: Option<&SelectionFilter>) {
        self.reachability |= filter.is_some_and(SelectionFilter::has_findings);
    }

    /// Ask the patch service what it measured about the patch each of
    /// `packages` is likely to get: the best ranked one this account can
    /// download. Called as soon as the lookup answers, so the requests run
    /// beside the rest of the directory's work and are in by the time its
    /// rows print; [`Self::measure`] then asks about any selection this
    /// guess missed.
    pub(crate) fn measure_likely(
        &mut self,
        client: &ApiClient,
        packages: &[BatchPackagePatches],
        can_access_paid_patches: bool,
    ) {
        let likely = packages.iter().filter_map(|pkg| {
            pkg.patches
                .iter()
                .filter(|p| can_access_paid_patches || p.tier == "free")
                .min_by(|a, b| cmp_batch_infos(a, b))
                .map(|p| p.uuid.clone())
        });
        self.request(client, likely.collect());
    }

    /// Ask the patch service what it measured about the patches `plan`
    /// selected, in the background: the answers are collected by
    /// [`Self::settle`], when the directory's rows are about to print.
    ///
    /// Only for someone watching (a human run whose stdout is a terminal):
    /// a log, a pipe and `--json` make no such request. A failed or late
    /// answer costs its row the measurements and nothing else.
    pub(crate) fn measure(&mut self, client: &ApiClient, plan: &[Package]) {
        let selected = plan
            .iter()
            .filter(|pkg| !pkg.outside_project)
            .filter_map(|pkg| pkg.uuids.first())
            .cloned();
        self.request(client, selected.collect());
    }

    /// Start one round of measurement requests: those of `uuids` not
    /// asked for yet, up to [`MEASURED_PER_ROUND`].
    fn request(&mut self, client: &ApiClient, uuids: Vec<String>) {
        if !self.measures {
            return;
        }
        let uuids: Vec<String> = uuids
            .into_iter()
            .filter(|uuid| self.requested.insert(uuid.clone()))
            .take(MEASURED_PER_ROUND)
            .collect();
        if uuids.is_empty() {
            return;
        }
        // One window for every round of the run: the rounds of a scan of
        // many directories are all out at once.
        let proxy = client.uses_public_proxy();
        let window = match &self.window {
            Some((route, window)) if *route == proxy => window.clone(),
            _ => {
                let window = measured::window(client);
                self.window = Some((proxy, window.clone()));
                window
            }
        };
        let client = client.clone();
        self.measuring.push(tokio::spawn(async move {
            measured::request(&client, uuids, &window).await
        }));
    }

    /// Collect the measurements asked for so far, waiting a moment
    /// ([`ROWS_WAIT`]) for the ones still on their way. Those stay out, and
    /// a later call collects them.
    pub(crate) async fn settle(&mut self) {
        self.collect(ROWS_WAIT).await;
    }

    /// [`Self::settle`], waiting up to `wait` in all. The wait shows on
    /// the status line: it stands between the lookup and the rows, where
    /// nothing else is on screen.
    async fn collect(&mut self, wait: Duration) {
        let _status = (!self.measuring.is_empty()).then(|| {
            let mut status = ui::StatusLine::stderr(!self.human, false);
            status.set("Reading patch test results");
            status
        });
        let deadline = tokio::time::Instant::now() + wait;
        for mut task in std::mem::take(&mut self.measuring) {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(answers)) => measured::collect(&mut self.measured, answers),
                // The task itself failed: nothing to wait for.
                Ok(Err(_)) => {}
                Err(_) => self.measuring.push(task),
            }
        }
    }

    /// Report one project directory: print the rows of the packages whose
    /// patch is in `landed` (stdout), and count the directory into the
    /// totals.
    pub(crate) async fn project(&mut self, plan: &[Package], landed: &HashSet<&str>) {
        self.settle().await;
        for row in self.rows(plan, landed) {
            println!("{row}");
        }
        self.count(plan, landed);
    }

    /// The rows [`Self::project`] prints, for a caller that prints them
    /// itself: none under `--json` or `--silent`. They carry the mark of
    /// a patch in place unless this is a dry run.
    pub(crate) fn rows(&self, plan: &[Package], landed: &HashSet<&str>) -> Vec<String> {
        self.rows_marked(plan, landed, !self.dry_run)
    }

    /// The rows of the packages a patch is on offer for (`offered`), for
    /// a run that reports and patches nothing: no row carries the mark of
    /// a patch in place.
    pub(crate) fn rows_offered(&self, plan: &[Package], offered: &HashSet<&str>) -> Vec<String> {
        self.rows_marked(plan, offered, false)
    }

    fn rows_marked(&self, plan: &[Package], landed: &HashSet<&str>, done: bool) -> Vec<String> {
        if !self.human {
            return Vec::new();
        }
        let cap = ui::attended(ui::Stream::Stdout).then(ui::stdout_width);
        rows(
            plan,
            landed,
            &self.measured,
            self.verbose,
            Style::stdout(),
            cap,
            done,
        )
    }

    /// Count one project directory into the totals: `plan`, judged by the
    /// patches that landed there. Once per directory.
    pub(crate) fn count(&mut self, plan: &[Package], landed: &HashSet<&str>) {
        let counts = Counts::of(plan, landed);
        self.counts.add(&counts);
        self.projects += usize::from(counts.patched > 0);
        self.patched.extend(
            plan.iter()
                .filter(|pkg| pkg.landed(landed))
                .map(|pkg| pkg.uuids.clone()),
        );
    }

    /// Print the closing lines (stdout), under a blank line. The elapsed
    /// time is for someone watching: it prints on a terminal only, so a
    /// log of the same run reads the same every time.
    pub(crate) async fn finish(&mut self) {
        if !self.human {
            return;
        }
        // The last measurements: the ones that missed their rows still
        // count here. Whatever is out after that is given up.
        self.collect(CLOSING_WAIT).await;
        for task in self.measuring.drain(..) {
            task.abort();
        }
        let mut counts = self.counts;
        counts.verify(&self.patched, &self.measured);
        counts.free_only = self.free_only;
        let elapsed = ui::attended(ui::Stream::Stdout).then(|| self.started.elapsed());
        let lines = closing(
            &counts,
            self.projects,
            self.dry_run,
            self.reachability,
            elapsed,
            Style::stdout(),
        );
        if !lines.is_empty() {
            println!();
        }
        for line in lines {
            println!("{line}");
        }
        if counts.left_paid > 0 {
            self.upsell();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::measured::tests::stats;
    use socket_patch_core::api::types::{BatchPatchInfo, VulnerabilityResponse};

    const FANCY: Style = Style {
        color: true,
        glyphs: true,
    };
    const COLOR: Style = Style {
        color: true,
        glyphs: false,
    };
    const PLAIN: Style = Style::PLAIN;

    fn none() -> Measured {
        Measured::new()
    }

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn info(
        uuid: &str,
        tier: &str,
        severity: &str,
        cves: &[&str],
        ghsas: &[&str],
    ) -> BatchPatchInfo {
        BatchPatchInfo {
            uuid: uuid.to_string(),
            purl: String::new(),
            tier: tier.to_string(),
            cve_ids: strs(cves),
            ghsa_ids: strs(ghsas),
            severity: Some(severity.to_string()),
            title: String::new(),
            published_at: None,
        }
    }

    /// A patch record for `purl` fixing `advisories`: `(id, severity, cves)`.
    fn record(purl: &str, uuid: &str, advisories: &[(&str, &str, &[&str])]) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.to_string(),
            purl: purl.to_string(),
            published_at: String::new(),
            description: String::new(),
            license: String::new(),
            tier: "free".to_string(),
            vulnerabilities: advisories
                .iter()
                .map(|(id, severity, cves)| {
                    (
                        id.to_string(),
                        VulnerabilityResponse {
                            cves: strs(cves),
                            summary: String::new(),
                            severity: severity.to_string(),
                            description: String::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn pkg(purl: &str, uuid: &str, severity: &str, fixes: &[&str], unpatched: &[&str]) -> Package {
        Package {
            purl: purl.to_string(),
            uuids: strs(&[uuid]),
            severity: Some(severity.to_string()),
            fixes: strs(fixes),
            unpatched: strs(unpatched),
            ..Package::default()
        }
    }

    fn landed<'a>(uuids: &[&'a str]) -> HashSet<&'a str> {
        uuids.iter().copied().collect()
    }

    const UNDICI: &str = "pkg:npm/undici@8.10.0";
    const CVE_1: &str = "CVE-2024-0001";
    const CVE_2: &str = "CVE-2024-0002";
    const CVE_3: &str = "CVE-2024-0003";
    const CVE_4: &str = "CVE-2024-0004";
    const CVE_9: &str = "CVE-2024-0009";
    const GHSA_A: &str = "GHSA-aaaa-aaaa-aaaa";
    const GHSA_B: &str = "GHSA-bbbb-bbbb-bbbb";
    const GHSA_C: &str = "GHSA-cccc-cccc-cccc";

    /// undici with three patches: the selected one fixes a critical and a
    /// high advisory, a second fixes a third advisory, and a paid one a
    /// fourth. A package nothing was selected for counts whole as left.
    fn undici_plan(filter: Option<&SelectionFilter>, paid_access: bool) -> Vec<Package> {
        let packages = vec![
            BatchPackagePatches {
                purl: UNDICI.to_string(),
                patches: vec![
                    info("u1", "free", "CRITICAL", &[CVE_1, CVE_2], &[GHSA_A, GHSA_B]),
                    info("u2", "free", "LOW", &[CVE_3], &[GHSA_C]),
                    info("u3", "paid", "HIGH", &[CVE_4], &[]),
                ],
            },
            BatchPackagePatches {
                purl: "pkg:npm/devalue@5.9.0".to_string(),
                patches: vec![info("d1", "paid", "HIGH", &[CVE_9], &[])],
            },
        ];
        let chosen = record(
            UNDICI,
            "u1",
            &[(GHSA_A, "CRITICAL", &[CVE_1]), (GHSA_B, "HIGH", &[CVE_2])],
        );
        let other = record(UNDICI, "u2", &[(GHSA_C, "LOW", &[CVE_3])]);
        plan(
            &packages,
            std::slice::from_ref(&chosen),
            &[&chosen, &other],
            paid_access,
            filter,
            &|_| true,
        )
    }

    #[test]
    fn plan_counts_what_the_selection_fixes_and_what_it_leaves() {
        let plan = undici_plan(None, false);
        assert_eq!(
            plan[0],
            Package {
                purl: UNDICI.to_string(),
                uuids: strs(&["u1"]),
                severity: Some("CRITICAL".to_string()),
                fixes: strs(&[CVE_1, CVE_2]),
                unpatched: strs(&[CVE_3, CVE_4]),
                // The other free patch fixes CVE_3, and no free patch
                // fixes it together with the selection. Only a paid
                // patch fixes CVE_4.
                merge_pending: strs(&[CVE_3]),
                needs_paid: strs(&[CVE_4]),
                fixed_critical: 1,
                fixed_high: 1,
                fixed_reachable: 0,
                unpatched_reachable: 0,
                paid_only: false,
                outside_project: false,
            }
        );
        // Nothing selected: its patches' worst severity, every id left,
        // and (for an account without paid access) a paid plan needed.
        assert_eq!(
            plan[1],
            Package {
                purl: "pkg:npm/devalue@5.9.0".to_string(),
                severity: Some("HIGH".to_string()),
                unpatched: strs(&[CVE_9]),
                needs_paid: strs(&[CVE_9]),
                paid_only: true,
                ..Package::default()
            }
        );
        assert!(!undici_plan(None, true)[1].paid_only);

        let counts = Counts::of(&plan, &landed(&["u1"]));
        assert_eq!(
            counts,
            Counts {
                patched: 1,
                fixed: 2,
                fixed_critical: 1,
                fixed_high: 1,
                left_merge: 1,
                merge_packages: 1,
                // CVE_4 on the patched package, and the advisory of the
                // package whose only patch is paid.
                left_paid: 2,
                ..Counts::default()
            }
        );
        assert_eq!(counts.left(), 3);
        // With paid access every patch is downloadable and none fixes all
        // four advisories: both of the others wait on the merged patch.
        let paid = undici_plan(None, true);
        assert_eq!(paid[0].merge_pending, strs(&[CVE_3, CVE_4]));
        assert!(paid[0].needs_paid.is_empty());
        let counts = Counts::of(&paid, &landed(&["u1"]));
        assert_eq!(
            (counts.left_merge, counts.left_upgrade, counts.left_paid),
            (2, 0, 0)
        );
        // A selected patch that did not land fixes nothing: the package
        // counts whole as left, in a package the run did not patch.
        let nothing = Counts::of(&plan, &landed(&[]));
        assert_eq!(
            nothing,
            Counts {
                left_unpatched: 4,
                left_paid: 1,
                ..Counts::default()
            }
        );
    }

    /// A package the project's lockfile does not name is not the
    /// project's: unpatched, it is not counted as left.
    #[test]
    fn a_package_outside_the_project_is_never_left_to_patch() {
        let packages = vec![BatchPackagePatches {
            purl: "pkg:gem/rack@3.0.0".to_string(),
            patches: vec![info("r1", "free", "HIGH", &[CVE_1, CVE_2], &[])],
        }];
        let chosen = record("pkg:gem/rack@3.0.0", "r1", &[(GHSA_A, "HIGH", &[CVE_1])]);
        let plan = plan(
            &packages,
            std::slice::from_ref(&chosen),
            &[&chosen],
            true,
            None,
            &|purl| !purl.starts_with("pkg:gem/"),
        );
        assert!(plan[0].outside_project);
        assert_eq!(Counts::of(&plan, &landed(&[])), Counts::default());
        // Patched all the same (an agent run patches the copy on disk), it
        // counts like any other.
        assert_eq!(Counts::of(&plan, &landed(&["r1"])).patched, 1);
    }

    /// What was measured about the patches that landed adds up; a patch
    /// that did not land, or was not measured, adds nothing.
    #[test]
    fn counts_add_up_the_measurements_of_the_patches_that_landed() {
        let plan = vec![
            pkg(UNDICI, "u", "HIGH", &[CVE_1], &[]),
            pkg("pkg:npm/nuxt@4.5.0", "n", "HIGH", &[CVE_2], &[]),
            pkg("pkg:npm/devalue@5.9.0", "d", "HIGH", &[CVE_3], &[]),
            pkg("pkg:npm/skipped@1.0.0", "k", "HIGH", &[CVE_4], &[]),
        ];
        let measured: Measured = [
            ("u".to_string(), stats(2, 35, 35)),
            ("n".to_string(), stats(1, 104, 106)),
            ("k".to_string(), stats(9, 9, 9)),
        ]
        .into();
        let mut counts = Counts::of(&plan, &landed(&["u", "n", "d"]));
        counts.verify(&[strs(&["u"]), strs(&["n"]), strs(&["d"])], &measured);
        assert_eq!(
            (counts.patched, counts.measured),
            (3, 2),
            "devalue was not measured"
        );
        assert_eq!((counts.exploits_blocked, counts.exploits), (3, 3));
        assert_eq!((counts.tests_passing, counts.tests), (139, 141));
    }

    /// A finding marks an advisory reachable by the advisory's id or by a
    /// CVE alias, whichever of them the row shows.
    #[test]
    fn plan_marks_reachable_advisories_through_their_aliases() {
        let filter = SelectionFilter::parse(
            format!(
                r#"{{"version": 1, "reachability": [
                    {{"advisory": "{GHSA_A}", "state": "reachable"}},
                    {{"advisory": "{CVE_2}", "state": "unreachable"}},
                    {{"advisory": "{GHSA_C}", "state": "reachable"}},
                    {{"advisory": "{CVE_9}", "state": "reachable"}}
                ]}}"#
            )
            .as_bytes(),
        )
        .expect("valid filter");
        let plan = undici_plan(Some(&filter), true);
        // The first CVE is GHSA-a (reachable); the second is unreachable.
        assert_eq!(plan[0].fixed_reachable, 1);
        // The third is GHSA-c (reachable); no finding names the fourth.
        assert_eq!(plan[0].unpatched_reachable, 1);
        assert_eq!(plan[1].unpatched_reachable, 1);
        let counts = Counts::of(&plan, &landed(&["u1"]));
        assert_eq!((counts.fixed_reachable, counts.left_reachable), (1, 2));
        // A filter with no finding marks nothing.
        let bare = SelectionFilter::parse(br#"{"version": 1}"#).expect("valid filter");
        assert_eq!(undici_plan(Some(&bare), true)[0].fixed_reachable, 0);
    }

    #[test]
    fn rows_list_each_patched_package_once_worst_first() {
        let plan = vec![
            pkg(
                UNDICI,
                "u",
                "HIGH",
                &["CVE-84961", "CVE-85024"],
                &["a", "b", "c"],
            ),
            pkg(
                "pkg:npm/shell-quote@1.10.0",
                "s",
                "CRITICAL",
                &["CVE-102422"],
                &[],
            ),
            pkg(
                "pkg:npm/nuxt@4.5.0",
                "n",
                "HIGH",
                &["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
                &["x"],
            ),
            pkg("pkg:npm/skipped@1.0.0", "k", "CRITICAL", &["CVE-7"], &[]),
        ];
        let all = landed(&["u", "s", "n"]);
        assert_eq!(
            rows(&plan, &all, &none(), false, PLAIN, None, true),
            vec![
                "  CRITICAL  shell-quote@1.10.0  CVE-102422",
                "  HIGH      nuxt@4.5.0          CVE-1, CVE-2 (+2)     1 unpatched",
                "  HIGH      undici@8.10.0       CVE-84961, CVE-85024  3 unpatched",
            ]
        );
        // Nothing landed: no rows at all.
        assert!(rows(&plan, &landed(&[]), &none(), false, PLAIN, None, true).is_empty());
        // Color wraps the cells without moving a column.
        let colored = rows(&plan, &all, &none(), false, COLOR, None, true);
        let plain: Vec<String> = colored.iter().map(|r| ui::strip_ansi(r)).collect();
        assert_eq!(plain, rows(&plan, &all, &none(), false, PLAIN, None, true));
        assert!(colored[0].contains("\x1b[91mCRITICAL\x1b[0m"));
        assert!(colored[2].contains("\x1b[33m3 unpatched\x1b[0m"));
    }

    #[test]
    fn rows_name_fewer_ids_rather_than_wrap_a_terminal() {
        let plan = vec![
            pkg(
                UNDICI,
                "u",
                "HIGH",
                &["CVE-2026-84961", "CVE-2026-85024"],
                &["a"],
            ),
            pkg(
                "pkg:npm/nuxt@4.5.0",
                "n",
                "HIGH",
                &["CVE-1", "CVE-2", "CVE-3"],
                &[],
            ),
        ];
        let all = landed(&["u", "n"]);
        let at = |cap| rows(&plan, &all, &none(), false, PLAIN, Some(cap), true);
        assert_eq!(
            at(80),
            vec![
                "  HIGH  nuxt@4.5.0     CVE-1, CVE-2 (+1)",
                "  HIGH  undici@8.10.0  CVE-2026-84961, CVE-2026-85024  1 unpatched",
            ]
        );
        assert_eq!(
            at(60),
            vec![
                "  HIGH  nuxt@4.5.0     CVE-1 (+2)",
                "  HIGH  undici@8.10.0  CVE-2026-84961 (+1)  1 unpatched",
            ]
        );
        assert_eq!(
            at(44),
            vec![
                "  HIGH  nuxt@4.5.0     3 fixed",
                "  HIGH  undici@8.10.0  2 fixed  1 unpatched",
            ]
        );
        for cap in [80, 60, 44] {
            assert!(at(cap).iter().all(|row| row.chars().count() < cap), "{cap}");
        }
        // Narrower than the counts: the full form, wrapped by the terminal.
        assert_eq!(at(10), rows(&plan, &all, &none(), false, PLAIN, None, true));
    }

    #[test]
    fn rows_verbose_name_every_id_and_what_stays_unpatched() {
        let plan = vec![pkg(
            UNDICI,
            "u",
            "HIGH",
            &["CVE-1", "CVE-2", "CVE-3"],
            &["CVE-8", "CVE-9"],
        )];
        assert_eq!(
            rows(&plan, &landed(&["u"]), &none(), true, PLAIN, Some(20), true),
            vec![
                "  HIGH  undici@8.10.0  CVE-1, CVE-2, CVE-3  2 unpatched",
                "      still unpatched: CVE-8, CVE-9",
            ]
        );
        // The ids waiting on a merged patch are named apart.
        let mut waiting = plan;
        waiting[0].merge_pending = strs(&["CVE-9"]);
        assert_eq!(
            rows(
                &waiting,
                &landed(&["u"]),
                &none(),
                true,
                PLAIN,
                Some(20),
                true
            ),
            vec![
                "  HIGH  undici@8.10.0  CVE-1, CVE-2, CVE-3  2 unpatched",
                "      still unpatched: CVE-8",
                "      waiting on a merged patch: CVE-9",
            ]
        );
        waiting[0].merge_pending = strs(&["CVE-8", "CVE-9"]);
        assert_eq!(
            rows(
                &waiting,
                &landed(&["u"]),
                &none(),
                true,
                PLAIN,
                Some(20),
                true
            )[1..],
            ["      waiting on a merged patch: CVE-8, CVE-9"]
        );
        // So are the ones only a paid patch fixes.
        waiting[0].merge_pending = strs(&["CVE-9"]);
        waiting[0].needs_paid = strs(&["CVE-8"]);
        assert_eq!(
            rows(
                &waiting,
                &landed(&["u"]),
                &none(),
                true,
                PLAIN,
                Some(20),
                true
            )[1..],
            [
                "      waiting on a merged patch: CVE-9",
                "      needs a paid Socket plan: CVE-8",
            ]
        );
    }

    #[test]
    fn rows_spell_the_purl_when_ecosystems_mix_and_elide_long_names() {
        let plan = vec![
            pkg("pkg:npm/requests@1.0.0", "a", "LOW", &[], &[]),
            pkg("pkg:pypi/requests@2.31.0", "b", "LOW", &["CVE-1"], &[]),
        ];
        assert_eq!(
            rows(
                &plan,
                &landed(&["a", "b"]),
                &none(),
                false,
                PLAIN,
                None,
                true
            ),
            vec![
                "  LOW  pkg:npm/requests@1.0.0",
                "  LOW  pkg:pypi/requests@2.31.0  CVE-1",
            ]
        );
        // A scoped npm name is decoded, and an unknown severity says so.
        let scoped = vec![Package {
            purl: "pkg:npm/%40scope/a@1.0.0".to_string(),
            uuids: strs(&["a"]),
            ..Package::default()
        }];
        assert_eq!(
            rows(&scoped, &landed(&["a"]), &none(), false, PLAIN, None, true),
            vec!["  UNKNOWN  @scope/a@1.0.0"]
        );
        // A patch that names no advisory leaves no gap where its ids
        // would be: the measurements follow the name.
        let measured: Measured = [("a".to_string(), stats(1, 25, 25))].into();
        assert_eq!(
            rows(
                &scoped,
                &landed(&["a"]),
                &measured,
                false,
                PLAIN,
                None,
                true
            ),
            vec!["  UNKNOWN  @scope/a@1.0.0  exploit blocked, 25/25 tests"]
        );
        // The severity reads the same whatever the source's spelling.
        let lower = vec![pkg("pkg:npm/a@1.0.0", "a", "moderate", &["CVE-1"], &[])];
        assert_eq!(
            rows(&lower, &landed(&["a"]), &none(), false, PLAIN, None, true),
            vec!["  MODERATE  a@1.0.0  CVE-1"]
        );
        let long = format!("pkg:npm/@typescript-eslint/{}@6.0.0", "x".repeat(60));
        let long = vec![pkg(&long, "a", "HIGH", &["CVE-1"], &[])];
        let row = &rows(&long, &landed(&["a"]), &none(), false, PLAIN, None, true)[0];
        assert!(
            row.contains("...") && row.contains("@6.0.0  CVE-1"),
            "{row}"
        );
        assert_eq!(
            row.chars().count(),
            "  HIGH  ".len() + MAX_NAME_COL + "  CVE-1".len()
        );
    }

    fn counts(
        patched: usize,
        fixed: usize,
        upgrade: usize,
        paid: usize,
        unpatched: usize,
    ) -> Counts {
        Counts {
            patched,
            fixed,
            left_upgrade: upgrade,
            left_paid: paid,
            left_unpatched: unpatched,
            ..Counts::default()
        }
    }

    #[test]
    fn closing_totals_the_run() {
        let c = Counts {
            fixed_critical: 5,
            fixed_high: 21,
            ..counts(22, 39, 14, 3, 1)
        };
        assert_eq!(
            closing(&c, 3, false, false, None, PLAIN),
            vec![
                "Patched 22 packages in 3 projects, fixing 39 vulnerabilities (5 critical, 21 high).",
                "Saved about 44 hours of engineering time (22 package upgrades at ~2 hours each).",
                "18 vulnerabilities left to patch (32%): 14 need a package upgrade, 3 need a paid \
                 Socket plan, 1 is in packages this run did not patch.",
            ]
        );
        // One project is not counted out loud; the time is the caller's.
        assert_eq!(
            closing(
                &counts(1, 1, 0, 0, 0),
                1,
                false,
                false,
                Some(Duration::from_millis(4249)),
                PLAIN
            ),
            vec![
                "Patched 1 package, fixing 1 vulnerability in 4.2s.",
                "Saved about 2 hours of engineering time (1 package upgrade at ~2 hours).",
                "Nothing left to patch.",
            ]
        );
        // A patch that names no advisory still patched its package.
        assert_eq!(
            closing(&counts(2, 0, 0, 0, 0), 2, false, false, None, PLAIN),
            vec![
                "Patched 2 packages in 2 projects.",
                "Saved about 4 hours of engineering time (2 package upgrades at ~2 hours each).",
                "Nothing left to patch."
            ]
        );
        // Nothing patched: only what is left, with no share of nothing.
        assert_eq!(
            closing(&counts(0, 0, 0, 4, 1), 0, false, false, None, PLAIN),
            vec![
                "5 vulnerabilities left to patch: 4 need a paid Socket plan, 1 is in packages \
                 this run did not patch."
            ]
        );
        // Nothing found at all: no lines.
        assert!(closing(&Counts::default(), 0, false, false, None, PLAIN).is_empty());
    }

    /// Advisories waiting on a merged patch are counted apart from the
    /// ones that need an upgrade, and the next line says the merged patch
    /// is still being processed.
    #[test]
    fn closing_says_a_merged_patch_is_not_ready_yet() {
        let one = Counts {
            left_merge: 1,
            merge_packages: 1,
            ..counts(1, 1, 0, 0, 0)
        };
        assert_eq!(
            closing(&one, 1, false, false, None, PLAIN)[2..],
            [
                "1 vulnerability left to patch (50%): 1 is waiting on a merged patch.",
                "Merged patch not ready yet for 1 package: Socket is still processing it. Run \
                 `socket-patch scan` again later to apply it.",
            ]
        );
        let many = Counts {
            left_merge: 6,
            merge_packages: 4,
            ..counts(22, 39, 8, 3, 1)
        };
        assert_eq!(
            closing(&many, 3, true, false, None, PLAIN)[2..],
            [
                "18 vulnerabilities would be left to patch (32%): 6 are waiting on a merged \
                 patch, 8 need a package upgrade, 3 need a paid Socket plan, 1 is in packages a \
                 run would not patch.",
                "Merged patches not ready yet for 4 packages: Socket is still processing them. \
                 Run `socket-patch scan` again later to apply them.",
            ]
        );
    }

    #[test]
    fn closing_dry_run_and_reachability() {
        let c = Counts {
            fixed_reachable: 9,
            left_reachable: 2,
            ..counts(22, 39, 1, 0, 2)
        };
        assert_eq!(
            closing(&c, 3, true, true, None, PLAIN),
            vec![
                "Would patch 22 packages in 3 projects, fixing 39 vulnerabilities.",
                "Would save about 44 hours of engineering time (22 package upgrades at ~2 hours \
                 each).",
                "3 vulnerabilities would be left to patch (7%): 1 needs a package upgrade, 2 are \
                 in packages a run would not patch.",
                "Reachable: 9 would be fixed, 2 left to patch (18%).",
            ]
        );
        let none_left = Counts {
            fixed_reachable: 4,
            ..counts(5, 6, 0, 0, 0)
        };
        assert_eq!(
            closing(&none_left, 1, false, true, None, PLAIN)[2..],
            [
                "Nothing left to patch.",
                "Reachable: 4 fixed, 0 left to patch."
            ]
        );
    }

    #[test]
    fn closing_colors_the_numbers_only() {
        let lines = closing(&counts(2, 3, 1, 0, 0), 1, false, false, None, COLOR);
        assert_eq!(
            lines[0],
            "\x1b[1;32mPatched\x1b[0m \x1b[1m2\x1b[0m packages, fixing \x1b[1m3\x1b[0m vulnerabilities."
        );
        let plain: Vec<String> = lines.iter().map(|l| ui::strip_ansi(l)).collect();
        assert_eq!(
            plain,
            closing(&counts(2, 3, 1, 0, 0), 1, false, false, None, PLAIN)
        );
    }

    #[test]
    fn rows_show_the_measurements_and_give_them_up_before_wrapping() {
        let plan = vec![
            pkg(
                UNDICI,
                "u",
                "HIGH",
                &["CVE-2026-84961", "CVE-2026-85024"],
                &["a"],
            ),
            pkg("pkg:npm/nuxt@4.5.0", "n", "HIGH", &["CVE-1"], &[]),
        ];
        let all = landed(&["u", "n"]);
        let measured: Measured = [("u".to_string(), stats(2, 35, 35))].into();
        let at = |cap| rows(&plan, &all, &measured, false, PLAIN, cap, true);
        // A package whose patch was not measured has no such cell.
        assert_eq!(
            at(None),
            vec![
                "  HIGH  nuxt@4.5.0     CVE-1",
                "  HIGH  undici@8.10.0  CVE-2026-84961, CVE-2026-85024  2 exploits blocked, \
                 35/35 tests  1 unpatched",
            ]
        );
        // Narrower: the second id goes first, then the measurements.
        assert_eq!(
            at(Some(90))[1],
            "  HIGH  undici@8.10.0  CVE-2026-84961 (+1)  2 exploits blocked, 35/35 tests  \
             1 unpatched"
        );
        assert_eq!(
            at(Some(80))[1],
            "  HIGH  undici@8.10.0  CVE-2026-84961, CVE-2026-85024  1 unpatched"
        );
        // Where the terminal shows glyphs, a check mark takes the first
        // column and nothing else moves.
        let fancy = rows(&plan, &all, &measured, false, FANCY, None, true);
        let stripped: Vec<String> = fancy.iter().map(|r| ui::strip_ansi(r)).collect();
        let marked: Vec<String> = at(None).iter().map(|r| format!("✔{}", &r[1..])).collect();
        assert_eq!(stripped, marked);
        assert!(fancy[0].starts_with("\x1b[32m✔\x1b[0m "), "{:?}", fancy[0]);
        // A patch that is only on offer (a dry run, a report) is not
        // marked as in place: the column is blank and nothing else moves.
        let offered = rows(&plan, &all, &measured, false, FANCY, None, false);
        let stripped: Vec<String> = offered.iter().map(|r| ui::strip_ansi(r)).collect();
        assert_eq!(stripped, at(None));
        assert!(!offered.iter().any(|row| row.contains('✔')), "{offered:?}");
    }

    #[test]
    fn closing_says_what_was_measured_and_draws_the_meter() {
        let c = Counts {
            fixed_critical: 5,
            fixed_high: 15,
            measured: 22,
            exploits_blocked: 24,
            exploits: 24,
            tests_passing: 1208,
            tests: 1208,
            ..counts(22, 39, 23, 0, 0)
        };
        let plain = closing(&c, 3, false, false, None, PLAIN);
        assert_eq!(
            plain,
            vec![
                "Patched 22 packages in 3 projects, fixing 39 vulnerabilities (5 critical, 15 high).",
                "Verified: 24 of 24 exploits blocked, 1208 of 1208 package tests passing.",
                "Saved about 44 hours of engineering time (22 package upgrades at ~2 hours each).",
                "23 vulnerabilities left to patch (37%): 23 need a package upgrade.",
            ]
        );
        // With glyphs: a check mark on what was done, the rest indented to
        // match, and the meter of the share patched.
        let fancy: Vec<String> = closing(&c, 3, false, false, None, FANCY)
            .iter()
            .map(|l| ui::strip_ansi(l))
            .collect();
        assert_eq!(
            fancy,
            vec![
                format!("✔ {}", plain[0]),
                format!("✔ {}", plain[1]),
                format!("  {}", plain[2]),
                format!("  {}", plain[3]),
                format!("  {}  63% patched", "━".repeat(METER_CELLS)),
            ]
        );
        // Not every patch measured, and not every test passing: said, and
        // not check-marked.
        let partly = Counts {
            measured: 18,
            tests_passing: 1200,
            ..c
        };
        let lines: Vec<String> = closing(&partly, 3, false, false, None, FANCY)
            .iter()
            .map(|l| ui::strip_ansi(l))
            .collect();
        assert_eq!(
            lines[1],
            "  Verified: 24 of 24 exploits blocked, 1200 of 1208 package tests passing \
             (measured for 18 of 22 patches)."
        );
        // Nothing left: no meter to draw.
        let done = closing(&counts(2, 3, 0, 0, 0), 1, false, false, None, FANCY);
        assert_eq!(done.len(), 3);
        assert_eq!(ui::strip_ansi(&done[2]), "  Nothing left to patch.");
        // A lookup that saw free patches only speaks for those alone.
        let free = Counts {
            free_only: true,
            ..counts(2, 3, 0, 0, 0)
        };
        assert_eq!(
            closing(&free, 1, false, false, None, PLAIN)[2],
            "No free patches left to apply."
        );
    }

    #[test]
    fn percent_left_never_rounds_to_all_or_nothing() {
        assert_eq!(percent_left(39, 18).as_deref(), Some("32%"));
        assert_eq!(percent_left(1, 1).as_deref(), Some("50%"));
        assert_eq!(percent_left(999, 1).as_deref(), Some("<1%"));
        assert_eq!(percent_left(1, 999).as_deref(), Some(">99%"));
        assert_eq!(percent_left(0, 5), None);
        assert_eq!(percent_left(5, 0), None);
    }
}
