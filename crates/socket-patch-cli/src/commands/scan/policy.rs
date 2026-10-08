//! Disk `scan`'s side of the socket.yml patch policy: loading it once per
//! invocation, the per-root and per-package filters, the severity floor in
//! selection, the retained set, and the `policy` JSON block / human line.
//! The policy itself lives in `socket_patch_core::policy`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use socket_patch_core::api::ranking::cmp_search_results;
use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::policy::{
    canon, find_repo_root_with_warnings, patch_severity_order, policy_block, repo_relative_checked,
    sanitize, severity_name, DiskPolicyFs, FilterReason, FilteredEntry, Offers, PolicyError,
    PolicySource, PolicyWarning, RetainedEntry, Root, SelectionPolicy, PATCHES_DISABLED,
};
use socket_patch_core::utils::purl::normalize_purl;

use super::ScanArgs;
use crate::hosted_memory::roots::{marker_ecosystem, UNSUPPORTED_MARKERS};

/// Why the policy could not be loaded.
pub(crate) enum PolicyLoadError {
    /// A malformed flag or env value: exit 2.
    Usage(String),
    /// A policy file that cannot be honored: exit 1, `errorCode`.
    Policy(PolicyError),
}

/// The invocation's policy: loaded once, shared by every project
/// directory a PATH list names.
pub(crate) struct InvocationPolicy {
    pub policy: SelectionPolicy,
    pub repo_root: PathBuf,
    pub warnings: Vec<PolicyWarning>,
    /// Set once the invocation's warnings were printed (a PATH list runs
    /// one scan per directory; the file was read once).
    pub warned: std::sync::atomic::AtomicBool,
}

/// Load the policy for `args` (4.5): `--global` scans have no repo and read
/// no file; everything else reads the repo root's socket.yml.
pub(crate) fn load_invocation_policy(args: &ScanArgs) -> Result<InvocationPolicy, PolicyLoadError> {
    let overrides = args
        .socket_yml
        .overrides()
        .map_err(PolicyLoadError::Usage)?;
    let cwd = std::fs::canonicalize(&args.common.cwd).unwrap_or_else(|_| args.common.cwd.clone());
    if args.common.is_global() {
        let policy = SelectionPolicy::load(
            &socket_patch_core::policy::MemoryPolicyFs::default(),
            &overrides,
        )
        .map_err(PolicyLoadError::Policy)?
        .0;
        return Ok(InvocationPolicy {
            policy,
            repo_root: cwd,
            warnings: Vec::new(),
            warned: Default::default(),
        });
    }
    let (repo_root, mut warnings) = find_repo_root_with_warnings(&cwd);
    let (policy, load_warnings) = SelectionPolicy::load(&DiskPolicyFs::new(&repo_root), &overrides)
        .map_err(PolicyLoadError::Policy)?;
    warnings.extend(load_warnings);
    Ok(InvocationPolicy {
        policy,
        repo_root,
        warnings,
        warned: Default::default(),
    })
}

/// The marker files of a disk project root: the same lock markers the
/// in-memory engine detects roots by, plus the maven/nuget markers disk
/// scans support. When a directory has none of those, its manifests
/// ([`MANIFEST_MARKERS`] and the JVM build files) are its markers instead;
/// the in-memory engine has no such fallback (manifests alone never make
/// a root there), so for a lockless directory the two engines disagree.
pub(crate) fn dir_markers(dir: &Path) -> Vec<String> {
    let mut markers: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file() || t.is_symlink()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| {
                    marker_ecosystem(name).is_some()
                        || UNSUPPORTED_MARKERS
                            .iter()
                            .any(|(_, names)| names.contains(&name.as_str()))
                })
                .collect()
        })
        .unwrap_or_default();
    if markers.is_empty() {
        // No lockfile: the manifests say what the project is. Every name
        // here, JVM build files included, must be a regular file: the
        // root-marker report lists files, so it deliberately keeps
        // `is_file` rather than `layout::marker_present` (which lets a
        // directory named like a build file mark a JVM build).
        markers = MANIFEST_MARKERS
            .iter()
            .chain(socket_patch_core::vendor::jvm::layout::JVM_PROJECT_MARKERS)
            .filter(|name| dir.join(name).is_file())
            .map(|name| name.to_string())
            .collect();
    }
    markers.sort();
    markers
}

/// Manifests that stand in as markers for a root with no lockfile (plus
/// every JVM build file, `layout::JVM_PROJECT_MARKERS`).
const MANIFEST_MARKERS: [&str; 6] = [
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
];

#[derive(Default)]
struct Report {
    filtered: Vec<FilteredEntry>,
    retained: Vec<RetainedEntry>,
    retained_purls: BTreeSet<String>,
    filtered_purls: HashSet<String>,
    update_purls: HashSet<String>,
    human_printed: bool,
}

/// One project root's view of the invocation policy (disk scans run one
/// root per `run_scan`).
pub(crate) struct ScanPolicy {
    pub policy: SelectionPolicy,
    pub warnings: Vec<PolicyWarning>,
    /// Print [`Self::warnings`] on the human path (first root only).
    announce_warnings: bool,
    /// Repo-relative root directory (`""` for the repo root).
    pub project: String,
    /// The root filter's verdict (`Ok` for global scans).
    root_verdict: Result<(), FilterReason>,
    /// Recorded patches of this root: canonical purl → uuid.
    recorded: HashMap<String, String>,
    report: Mutex<Report>,
}

impl ScanPolicy {
    /// The policy for the project rooted at `root_dir`.
    pub(crate) fn for_root(
        invocation: &InvocationPolicy,
        root_dir: &Path,
        explicit: bool,
        global: bool,
    ) -> Self {
        let root_dir = std::fs::canonicalize(root_dir).unwrap_or_else(|_| root_dir.to_path_buf());
        let project = repo_relative_checked(&invocation.repo_root, &root_dir).unwrap_or_default();
        let root_verdict = if global {
            Ok(())
        } else {
            let markers = dir_markers(&root_dir);
            invocation.policy.admits_root(&Root {
                rel_dir: &project,
                markers: &markers,
                explicit,
            })
        };
        let mut warnings = invocation.warnings.clone();
        if !invocation.policy.enabled() {
            warnings.push(PolicyWarning {
                code: PATCHES_DISABLED,
                detail: "patches.enabled is false in socket.yml: report only, nothing is written \
                         (existing patches stay in place; the --prune GC is skipped too)"
                    .to_string(),
            });
        }
        let mut report = Report::default();
        // A root filtered as a whole is one entry, whatever it holds.
        if let Err(reason) = &root_verdict {
            report.filtered.push(FilteredEntry {
                purl: None,
                uuid: None,
                project: project.clone(),
                reason: reason.clone(),
                severity: None,
            });
        }
        let announce_warnings = !invocation
            .warned
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        Self {
            policy: invocation.policy.clone(),
            warnings,
            announce_warnings,
            project,
            root_verdict,
            recorded: HashMap::new(),
            report: Mutex::new(report),
        }
    }

    /// Whether selection can filter anything (a floor, or patching
    /// disabled): report-only runs select only for the report then.
    pub(crate) fn reports_selection(&self) -> bool {
        !self.policy.enabled() || self.policy.min_severity().0.is_some()
    }

    /// Whether the policy filtered this whole project root.
    pub(crate) fn root_excluded(&self) -> bool {
        self.root_verdict.is_err()
    }

    fn report(&self) -> std::sync::MutexGuard<'_, Report> {
        self.report.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether anything may be written this run.
    pub(crate) fn writes_allowed(&self) -> bool {
        self.policy.enabled()
    }

    /// Set the merged recorded view (manifest > hosted pins > vendor ledger).
    pub(crate) fn set_recorded(&mut self, merged: Option<&PatchManifest>) {
        self.recorded = merged
            .map(|m| {
                m.patches
                    .iter()
                    .map(|(purl, record)| (canon(purl), record.uuid.clone()))
                    .collect()
            })
            .unwrap_or_default();
    }

    fn recorded_uuid(&self, purl: &str) -> Option<&str> {
        self.recorded.get(&canon(purl)).map(String::as_str)
    }

    /// Step 3: the root, ecosystem and package filters. Returns whether the
    /// package stays in the batch query. A recorded package the filters
    /// exclude stays in the query (so `upgradeAvailable` can be reported)
    /// but joins the retained set, which never reaches a writer.
    pub(crate) fn admit_crawled(&self, purl: &str) -> bool {
        let verdict = self
            .root_verdict
            .clone()
            .and_then(|()| self.policy.admits_purl(purl));
        let reason = match verdict {
            Ok(()) => return true,
            Err(reason) => reason,
        };
        let mut report = self.report();
        if let Some(uuid) = self.recorded_uuid(purl) {
            let key = canon(purl);
            if report.retained_purls.insert(key.clone()) {
                report.retained.push(RetainedEntry {
                    purl: key,
                    project: self.project.clone(),
                    recorded_uuid: uuid.to_string(),
                    reason,
                    upgrade_available: false,
                });
            }
            return true;
        }
        if self.root_verdict.is_err() {
            // Already reported as the root's one entry.
        } else if report.filtered_purls.insert(canon(purl)) {
            report.filtered.push(FilteredEntry {
                purl: Some(canon(purl)),
                uuid: None,
                project: self.project.clone(),
                reason,
                severity: None,
            });
        }
        false
    }

    /// Record the purls with a newer patch (`updates[]`), for
    /// `retained[].upgradeAvailable`.
    pub(crate) fn set_update_purls<'a>(&self, purls: impl IntoIterator<Item = &'a str>) {
        self.report().update_purls = purls.into_iter().map(canon).collect();
    }

    /// Steps 5-6: group the tier-accessible offers, keep retained packages
    /// out, apply the severity floor and pick one patch per package with
    /// the canonical ranking. With no floor the result is exactly today's
    /// top-ranked selection. The floor never moves a package off its
    /// recorded patch unless an admitted patch outranks the recorded one,
    /// and a recorded package with nothing above the floor keeps its patch.
    pub(crate) fn select(&self, accessible: Vec<PatchSearchResult>) -> Offers {
        let mut grouped: BTreeMap<String, Vec<PatchSearchResult>> = BTreeMap::new();
        {
            let report = self.report();
            for offer in accessible {
                if report.retained_purls.contains(&canon(&offer.purl)) {
                    continue;
                }
                grouped.entry(offer.purl.clone()).or_default().push(offer);
            }
        }
        for group in grouped.values_mut() {
            group.sort_by(cmp_search_results);
        }
        let mut offers = Offers {
            unfiltered: BTreeMap::new(),
            selected: BTreeMap::new(),
        };
        let mut report = self.report();
        for (purl, group) in grouped {
            let recorded = self.recorded_uuid(&purl).map(str::to_string);
            if !self.policy.enabled() {
                let reason = FilterReason::Disabled;
                match recorded {
                    Some(uuid) => {
                        let key = canon(&purl);
                        if report.retained_purls.insert(key.clone()) {
                            report.retained.push(RetainedEntry {
                                purl: key,
                                project: self.project.clone(),
                                recorded_uuid: uuid,
                                reason,
                                upgrade_available: false,
                            });
                        }
                    }
                    None => report.filtered.push(FilteredEntry {
                        purl: Some(canon(&purl)),
                        uuid: Some(group[0].uuid.clone()),
                        project: self.project.clone(),
                        severity: Some(patch_severity_order(&group[0])),
                        reason,
                    }),
                }
                continue;
            }
            let floor_winner = group
                .iter()
                .position(|p| self.policy.admits_severity(patch_severity_order(p)).is_ok());
            let recorded_at = recorded
                .as_deref()
                .and_then(|uuid| group.iter().position(|p| p.uuid == uuid));
            let chosen = match (recorded.is_some(), floor_winner, recorded_at) {
                // The recorded patch outranks every admitted one: keep it.
                (true, Some(w), Some(r)) if r < w => Some(r),
                (_, Some(w), _) => Some(w),
                // Nothing above the floor: a recorded package keeps its patch.
                (true, None, Some(r)) => Some(r),
                (_, None, _) => None,
            };
            // What the floor hid is reported: the top-ranked patch it withheld
            // when the package ends up unpatched or held at its recorded patch
            // (not when a lower-ranked admitted patch simply wins).
            let top_withheld = self.policy.admits_severity(patch_severity_order(&group[0]));
            if let Err(reason) = top_withheld {
                let upgrade_withheld =
                    chosen.is_some() && chosen == recorded_at && recorded_at != Some(0);
                if chosen.is_none() || upgrade_withheld {
                    report.filtered.push(FilteredEntry {
                        purl: Some(canon(&purl)),
                        uuid: Some(group[0].uuid.clone()),
                        project: self.project.clone(),
                        severity: Some(patch_severity_order(&group[0])),
                        reason,
                    });
                }
            }
            if let Some(i) = chosen {
                offers.selected.insert(purl.clone(), group[i].clone());
            }
            offers.unfiltered.insert(purl, group);
        }
        offers
    }

    /// The top-level `policy` block (4.7).
    pub(crate) fn json(&self) -> serde_json::Value {
        let report = self.report();
        let retained: Vec<RetainedEntry> = report
            .retained
            .iter()
            .map(|r| RetainedEntry {
                upgrade_available: report.update_purls.contains(&r.purl),
                ..r.clone()
            })
            .collect();
        policy_block(&self.policy, &report.filtered, &retained)
    }

    /// Put the `policy` block and the policy warnings on a scan `--json`
    /// result (idempotent: the block is rebuilt, warnings added once).
    pub(crate) fn fold_into_json(&self, result: &mut serde_json::Value) {
        result["policy"] = self.json();
        let warnings = result
            .as_object_mut()
            .expect("scan JSON result is an object")
            .entry("warnings")
            .or_insert_with(|| serde_json::json!([]));
        if let Some(arr) = warnings.as_array_mut() {
            for w in &self.warnings {
                let present = arr
                    .iter()
                    .any(|e| e["code"] == w.code && e["detail"] == w.detail.as_str());
                if !present {
                    arr.push(serde_json::json!({ "code": w.code, "detail": w.detail }));
                }
            }
            if arr.is_empty() {
                result.as_object_mut().map(|o| o.remove("warnings"));
            }
        }
    }

    /// Print the policy warnings (stderr) once, human path.
    pub(crate) fn print_warnings(&self, silent: bool) {
        if silent || !self.announce_warnings {
            return;
        }
        for w in &self.warnings {
            eprintln!("Warning: {}", w.detail);
        }
    }

    /// The human policy line (stdout), printed at most once per root: the
    /// counts, then every filtered critical/high candidate by name (a
    /// policy must not hide those silently), or every entry with
    /// `--verbose`.
    pub(crate) fn print_human(&self, silent: bool, verbose: bool) {
        let mut report = self.report();
        if silent || std::mem::replace(&mut report.human_printed, true) {
            return;
        }
        let filtered = report.filtered.len();
        let retained = report.retained.len();
        if filtered == 0 && retained == 0 && self.policy.enabled() {
            return;
        }
        let label = match self.policy.source() {
            PolicySource::File { path, .. } => format!("Policy ({path})"),
            PolicySource::Bypassed => "Policy (socket.yml ignored)".to_string(),
            PolicySource::None => "Policy (built-in defaults)".to_string(),
        };
        let mut line = format!(
            "\n{label}: {} skipped by filters, {} held.",
            filtered,
            crate::ui::plural(retained, "patched package", "patched packages")
        );
        if !self.policy.enabled() {
            line.push_str(" Patching is disabled (patches.enabled: false).");
        }
        println!("{line}");
        let mut entries: Vec<&FilteredEntry> = report.filtered.iter().collect();
        entries.sort_by(|a, b| (&a.project, &a.purl).cmp(&(&b.project, &b.purl)));
        for f in entries {
            // A skipped project and a withheld critical/high patch are always
            // named; everything else only with --verbose.
            let severe = f.severity.is_some_and(|s| s <= 1);
            if !(verbose || severe || f.purl.is_none()) {
                continue;
            }
            let what = match &f.purl {
                Some(purl) => sanitize(&normalize_purl(purl)),
                None if self.project.is_empty() => "this project".to_string(),
                None => format!("project {}", sanitize(&self.project)),
            };
            let severity = f
                .severity
                .and_then(severity_name)
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            println!("  skipped {what}{severity}: {}", f.reason.detail());
        }
        if verbose {
            for r in &report.retained {
                println!(
                    "  held {} at {}: {}",
                    sanitize(&normalize_purl(&r.purl)),
                    sanitize(&r.recorded_uuid),
                    r.reason.detail()
                );
            }
        }
    }
}

/// The JSON error object for a policy file that cannot be honored: scan's
/// error shape plus `errorCode`.
pub(crate) fn policy_error_json(err: &PolicyError, paths: &[String]) -> serde_json::Value {
    serde_json::json!({
        "status": "error",
        "error": err.to_string(),
        "errorCode": err.code(),
        "scannedPackages": 0,
        "lockfileOnlyPackages": 0,
        "packagesWithPatches": 0,
        "totalPatches": 0,
        "freePatches": 0,
        "paidPatches": 0,
        "canAccessPaidPatches": false,
        "packages": [],
        "updates": [],
        "paths": paths,
    })
}

/// `get`'s `policy_bypassed` warnings: `get` is explicit intent, so it
/// ignores the policy, but says when the repo's socket.yml would have
/// filtered what it is about to patch. Never fails: an unreadable or
/// invalid file just yields no warning.
pub(crate) fn policy_bypass_warnings(
    common: &crate::args::GlobalArgs,
    patches: &[PatchSearchResult],
) -> Vec<(String, String)> {
    if common.is_global() || patches.is_empty() {
        return Vec::new();
    }
    let cwd = std::fs::canonicalize(&common.cwd).unwrap_or_else(|_| common.cwd.clone());
    let (repo_root, _) = find_repo_root_with_warnings(&cwd);
    let Ok((policy, _)) = SelectionPolicy::load(
        &DiskPolicyFs::new(&repo_root),
        &socket_patch_core::policy::PolicyOverrides::default(),
    ) else {
        return Vec::new();
    };
    if !matches!(policy.source(), PolicySource::File { .. }) {
        return Vec::new();
    }
    let project = repo_relative_checked(&repo_root, &cwd).unwrap_or_default();
    let markers = dir_markers(&cwd);
    let root_verdict = policy.admits_root(&Root {
        rel_dir: &project,
        markers: &markers,
        explicit: true,
    });
    let mut by_purl: BTreeMap<&str, Vec<&PatchSearchResult>> = BTreeMap::new();
    for patch in patches {
        by_purl.entry(patch.purl.as_str()).or_default().push(patch);
    }
    let mut out = Vec::new();
    for (purl, mut group) in by_purl {
        group.sort_by(|a, b| cmp_search_results(a, b));
        let verdict = if !policy.enabled() {
            Err(FilterReason::Disabled)
        } else {
            root_verdict
                .clone()
                .and_then(|()| policy.admits_purl(purl))
                .and_then(|()| {
                    // The floor only hides a package when none of its patches pass.
                    match group
                        .iter()
                        .map(|p| policy.admits_severity(patch_severity_order(p)))
                        .find(Result::is_ok)
                    {
                        Some(ok) => ok,
                        None => policy.admits_severity(patch_severity_order(group[0])),
                    }
                })
        };
        if let Err(reason) = verdict {
            out.push((
                socket_patch_core::policy::POLICY_BYPASSED.to_string(),
                format!(
                    "{} would be skipped by socket.yml ({}: {}); get patches it anyway",
                    normalize_purl(purl),
                    reason.code(),
                    reason.detail()
                ),
            ));
        }
    }
    out
}
