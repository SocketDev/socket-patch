//! Disk `scan`'s side of the socket.yml patch policy: loading it once per
//! invocation, the per-root and per-package filters, the severity floor in
//! selection, the retained set, and the `policy` JSON block / human line.
//! The policy itself lives in `socket_patch_core::policy`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use socket_patch_core::api::ranking::cmp_search_results;
use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::crawlers::types::CrawledPackage;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::policy::{
    find_repo_root_with_warnings, patch_severity_order, policy_block, repo_relative_checked,
    sanitize, severity_name, DiskPolicyFs, FilterReason, FilteredEntry, Offers, PolicyError,
    PolicySource, PolicyWarning, RetainedEntry, Root, SelectionPolicy, PATCHES_DISABLED,
};
use socket_patch_core::utils::purl::normalize_purl;
use socket_patch_core::utils::purl_key::PurlKey;

use super::ScanArgs;
use crate::hosted_memory::roots::{marker_ecosystem, UNSUPPORTED_MARKERS};

/// Why the policy could not be loaded.
pub(crate) enum PolicyLoadError {
    /// A malformed flag or env value: exit 2.
    Usage(String),
    /// A policy file that cannot be honored: exit 1, `error.code`.
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
    let mut markers = lock_markers(dir);
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

/// The lockfile markers in `dir` (unsorted): what makes a directory a
/// project root of its own rather than a member of an enclosing one.
fn lock_markers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
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
        .unwrap_or_default()
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
    /// Admitted purls with a copy under a nested project root the policy
    /// skips: canonical purl -> those roots (see
    /// [`ScanPolicy::admit_crawled_copies`]).
    shared_copies: BTreeMap<String, BTreeSet<String>>,
    /// The [`Self::shared_copies`] entries a patch was selected for.
    shared_selected: BTreeSet<String>,
    human_printed: bool,
}

/// A copy's owning root: its repo-relative dir and the root filter's verdict.
type Owner = (String, Result<(), FilterReason>);

/// The nested project roots under an agent / report-only scan's root
/// (#554): such a scan crawls every nested project's `node_modules` and
/// patches copies in place, so each copy is judged by the root that owns
/// it, not only the scan root.
struct NestedRoots {
    repo_root: PathBuf,
    /// The scan root as given and canonicalized (crawled paths are built
    /// from the former).
    scan_dirs: Vec<PathBuf>,
    /// Owning root per `node_modules` parent directory: `None` for the scan
    /// root, else the root's repo-relative dir and verdict.
    owners: HashMap<PathBuf, Option<Owner>>,
    /// More installed copies per purl ([`ScanPolicy::locate_nested_copies`]):
    /// the crawl keeps one copy per purl.
    more_copies: HashMap<String, Vec<PathBuf>>,
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
    nested: Option<NestedRoots>,
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
            nested: None,
            report: Mutex::new(report),
        }
    }

    /// Judge crawled copies under a nested project's `node_modules` by that
    /// project's own root (agent and report-only scans, which patch the
    /// crawled copies in place, see [`NestedRoots`]). A nested root is a
    /// directory below `scan_dir` holding a lockfile; a member without one
    /// belongs to the enclosing root. Nested roots are discovered, so the
    /// built-in default ignores apply to them.
    pub(crate) fn judge_nested_roots(&mut self, invocation: &InvocationPolicy, scan_dir: &Path) {
        let mut scan_dirs = vec![scan_dir.to_path_buf()];
        if let Ok(canonical) = std::fs::canonicalize(scan_dir) {
            if canonical != scan_dir {
                scan_dirs.push(canonical);
            }
        }
        self.nested = Some(NestedRoots {
            repo_root: invocation.repo_root.clone(),
            scan_dirs,
            owners: HashMap::new(),
            more_copies: HashMap::new(),
        });
    }

    /// Whether [`Self::judge_nested_roots`] is on.
    pub(crate) fn judges_nested_roots(&self) -> bool {
        self.nested.is_some()
    }

    /// The nested root owning the crawled copy at `path` (`None`: the scan
    /// root owns it). A newly seen root filtered as a whole is reported as
    /// one entry, like the scan root.
    fn nested_owner(&mut self, path: &Path) -> Option<Owner> {
        let nested = self.nested.as_mut()?;
        let (scan_dir, rel) = nested
            .scan_dirs
            .iter()
            .find_map(|dir| path.strip_prefix(dir).ok().map(|rel| (dir.clone(), rel)))?;
        // Only the directories above the first `node_modules`: anything
        // inside one is a package, not a project.
        let parts: Vec<&std::ffi::OsStr> = rel
            .components()
            .map_while(|c| match c {
                std::path::Component::Normal(part) => Some(part),
                _ => None,
            })
            .collect();
        let depth = parts.iter().position(|p| *p == "node_modules")?;
        let mut dir = scan_dir.clone();
        dir.extend(&parts[..depth]);
        if let Some(owner) = nested.owners.get(&dir) {
            return owner.clone();
        }
        let owner = (1..=depth).rev().find_map(|k| {
            let mut root = scan_dir.clone();
            root.extend(&parts[..k]);
            if lock_markers(&root).is_empty() {
                return None;
            }
            let canonical = std::fs::canonicalize(&root).unwrap_or(root.clone());
            let project = repo_relative_checked(&nested.repo_root, &canonical)?;
            let markers = dir_markers(&root);
            let verdict = self.policy.admits_root(&Root {
                rel_dir: &project,
                markers: &markers,
                explicit: false,
            });
            Some((project, verdict))
        });
        if let Some((project, Err(reason))) = &owner {
            let mut report = self.report.lock().unwrap_or_else(|e| e.into_inner());
            let known = report
                .filtered
                .iter()
                .any(|f| f.purl.is_none() && &f.project == project);
            if !known {
                report.filtered.push(FilteredEntry {
                    purl: None,
                    uuid: None,
                    project: project.clone(),
                    reason: reason.clone(),
                    severity: None,
                });
            }
        }
        nested.owners.insert(dir, owner.clone());
        owner
    }

    /// The owner of a crawled copy: its nested root, else the scan root.
    fn copy_owner(&mut self, path: &Path) -> Owner {
        self.nested_owner(path)
            .unwrap_or_else(|| (self.project.clone(), self.root_verdict.clone()))
    }

    /// The crawl keeps one installed copy per purl, but a package can be
    /// installed under several roots. When some `node_modules` roots
    /// (`nm_roots`, as the npm crawler walks them) are skipped and others
    /// are not, find the other copies of each npm package whose crawled
    /// copy sits on the other side, so [`Self::admit_crawled_copies`] sees
    /// every root that installs it.
    pub(crate) async fn locate_nested_copies(
        &mut self,
        nm_roots: &[PathBuf],
        pkgs: &[CrawledPackage],
    ) {
        if self.nested.is_none() {
            return;
        }
        let roots: Vec<(PathBuf, bool)> = nm_roots
            .iter()
            .map(|root| (root.clone(), self.copy_owner(root).1.is_ok()))
            .collect();
        if roots.iter().all(|(_, ok)| *ok) || roots.iter().all(|(_, ok)| !*ok) {
            return;
        }
        let mut admitted_purls = Vec::new();
        let mut skipped_purls = Vec::new();
        for pkg in pkgs.iter().filter(|p| p.purl.starts_with("pkg:npm/")) {
            if self.copy_owner(&pkg.path).1.is_ok() {
                admitted_purls.push(pkg.purl.clone());
            } else {
                skipped_purls.push(pkg.purl.clone());
            }
        }
        let crawler = socket_patch_core::crawlers::NpmCrawler::new();
        let mut more: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for (root, ok) in roots {
            // An admitted root may hold a copy of a package crawled under a
            // skipped one, and the reverse.
            let wanted = if ok { &skipped_purls } else { &admitted_purls };
            if wanted.is_empty() {
                continue;
            }
            let Ok(found) = crawler.find_by_purls(&root, wanted).await else {
                continue;
            };
            for (purl, copies) in found {
                more.entry(purl)
                    .or_default()
                    .extend(copies.into_iter().map(|c| c.path));
            }
        }
        if let Some(nested) = self.nested.as_mut() {
            nested.more_copies = more;
        }
    }

    /// Step 3 over the whole crawl: [`Self::admit_crawled`], with each copy
    /// judged by its owning root when nested roots are on. A package stays
    /// when any copy's root admits it: patches are recorded per package
    /// version, so its copies under skipped roots are patched too (noted
    /// once a patch is selected for it). Supplement purls (`supplements`,
    /// no installed copy) belong to the scan root.
    pub(crate) fn admit_crawled_copies(
        &mut self,
        pkgs: Vec<CrawledPackage>,
        supplements: &HashSet<String>,
    ) -> Vec<CrawledPackage> {
        if self.nested.is_none() {
            return pkgs
                .into_iter()
                .filter(|p| self.admit_crawled(&p.purl))
                .collect();
        }
        // Each purl's first admitting root, else its first root.
        let mut owners: BTreeMap<String, Owner> = BTreeMap::new();
        let mut skipped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let more_copies = self
            .nested
            .as_mut()
            .map(|n| std::mem::take(&mut n.more_copies))
            .unwrap_or_default();
        for pkg in &pkgs {
            let mut paths: Vec<&Path> = vec![&pkg.path];
            if supplements.contains(&pkg.purl) {
                paths.clear();
            } else if let Some(more) = more_copies.get(&pkg.purl) {
                paths.extend(more.iter().map(PathBuf::as_path));
            }
            let mut copy_owners: Vec<Owner> = paths
                .into_iter()
                .map(|path| self.copy_owner(path))
                .collect();
            if copy_owners.is_empty() {
                copy_owners.push((self.project.clone(), self.root_verdict.clone()));
            }
            for (project, verdict) in copy_owners {
                if verdict.is_err() {
                    skipped
                        .entry(pkg.purl.clone())
                        .or_default()
                        .insert(project.clone());
                }
                let slot = owners
                    .entry(pkg.purl.clone())
                    .or_insert_with(|| (project.clone(), verdict.clone()));
                if slot.1.is_err() && verdict.is_ok() {
                    *slot = (project, verdict);
                }
            }
        }
        let mut admitted = HashSet::new();
        for (purl, (project, verdict)) in owners {
            let root_ok = verdict.is_ok();
            if !self.admit_in(&purl, &project, verdict) {
                continue;
            }
            if root_ok && self.policy.admits_purl(&purl).is_ok() {
                if let Some(projects) = skipped.remove(&purl) {
                    self.report()
                        .shared_copies
                        .insert(PurlKey::new(&purl).into_string(), projects);
                }
            }
            admitted.insert(purl);
        }
        pkgs.into_iter()
            .filter(|p| admitted.contains(&p.purl))
            .collect()
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
                    .map(|(purl, record)| (PurlKey::new(purl).into_string(), record.uuid.clone()))
                    .collect()
            })
            .unwrap_or_default();
    }

    fn recorded_uuid(&self, purl: &str) -> Option<&str> {
        self.recorded
            .get(&PurlKey::new(purl).into_string())
            .map(String::as_str)
    }

    /// Step 3: the root, ecosystem and package filters. Returns whether the
    /// package stays in the batch query. A recorded package the filters
    /// exclude stays in the query (so `upgradeAvailable` can be reported)
    /// but joins the retained set, which never reaches a writer.
    pub(crate) fn admit_crawled(&self, purl: &str) -> bool {
        self.admit_in(purl, &self.project, self.root_verdict.clone())
    }

    /// [`Self::admit_crawled`] for a copy owned by the root `project`
    /// with the verdict `root_verdict`.
    fn admit_in(&self, purl: &str, project: &str, root_verdict: Result<(), FilterReason>) -> bool {
        let root_excluded = root_verdict.is_err();
        let verdict = root_verdict.and_then(|()| self.policy.admits_purl(purl));
        let reason = match verdict {
            Ok(()) => return true,
            Err(reason) => reason,
        };
        let mut report = self.report();
        if let Some(uuid) = self.recorded_uuid(purl) {
            let key = PurlKey::new(purl).into_string();
            if report.retained_purls.insert(key.clone()) {
                report.retained.push(RetainedEntry {
                    purl: key,
                    project: project.to_string(),
                    recorded_uuid: uuid.to_string(),
                    reason,
                    upgrade_available: false,
                });
            }
            return true;
        }
        if root_excluded {
            // Already reported as the root's one entry.
        } else if report
            .filtered_purls
            .insert(PurlKey::new(purl).into_string())
        {
            report.filtered.push(FilteredEntry {
                purl: Some(PurlKey::new(purl).into_string()),
                uuid: None,
                project: project.to_string(),
                reason,
                severity: None,
            });
        }
        false
    }

    /// Record the purls with a newer patch (`updates[]`), for
    /// `retained[].upgradeAvailable`.
    pub(crate) fn set_update_purls<'a>(&self, purls: impl IntoIterator<Item = &'a str>) {
        self.report().update_purls = purls
            .into_iter()
            .map(|p| PurlKey::new(p).into_string())
            .collect();
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
                if report
                    .retained_purls
                    .contains(&PurlKey::new(&offer.purl).into_string())
                {
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
                        let key = PurlKey::new(&purl).into_string();
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
                        purl: Some(PurlKey::new(&purl).into_string()),
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
                        purl: Some(PurlKey::new(&purl).into_string()),
                        uuid: Some(group[0].uuid.clone()),
                        project: self.project.clone(),
                        severity: Some(patch_severity_order(&group[0])),
                        reason,
                    });
                }
            }
            if let Some(i) = chosen {
                if report
                    .shared_copies
                    .contains_key(&PurlKey::new(&purl).into_string())
                {
                    report
                        .shared_selected
                        .insert(PurlKey::new(&purl).into_string());
                }
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
    /// envelope (idempotent: the block is rebuilt, warnings added once).
    pub(crate) fn fold_into_envelope(&self, env: &mut crate::json_envelope::Envelope) {
        env.set_extra("policy", self.json());
        for w in self.warnings.iter().chain(&self.shared_copy_warnings()) {
            let present = env
                .warnings
                .iter()
                .any(|e| e.code == w.code && e.detail == w.detail);
            if !present {
                env.warn(w.code, w.detail.clone());
            }
        }
    }

    /// One `policy_shared_copy` warning per selected package that is also
    /// installed under a nested root the policy skips.
    fn shared_copy_warnings(&self) -> Vec<PolicyWarning> {
        let report = self.report();
        report
            .shared_selected
            .iter()
            .filter_map(|purl| {
                let projects = report.shared_copies.get(purl)?;
                Some(PolicyWarning {
                    code: POLICY_SHARED_COPY,
                    detail: shared_copy_detail(purl, projects),
                })
            })
            .collect()
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
                None if f.project.is_empty() => "this project".to_string(),
                None => format!("project {}", sanitize(&f.project)),
            };
            let severity = f
                .severity
                .and_then(severity_name)
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            println!("  skipped {what}{severity}: {}", f.reason.detail());
        }
        for purl in &report.shared_selected {
            if let Some(projects) = report.shared_copies.get(purl) {
                println!("  note: {}", shared_copy_detail(purl, projects));
            }
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

/// Warning code: a selected package is also installed under a nested
/// project root the policy skips, and that copy is patched too.
pub(crate) const POLICY_SHARED_COPY: &str = "policy_shared_copy";

fn shared_copy_detail(purl: &str, projects: &BTreeSet<String>) -> String {
    let projects: Vec<String> = projects
        .iter()
        .map(|p| {
            if p.is_empty() {
                "the repo root".to_string()
            } else {
                sanitize(p)
            }
        })
        .collect();
    format!(
        "{} is patched for an included project, so its installed copy under skipped project{} {} \
         is patched too (patches are recorded per package version)",
        sanitize(&normalize_purl(purl)),
        if projects.len() == 1 { "" } else { "s" },
        projects.join(", ")
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation(repo: &Path, yml: &str) -> InvocationPolicy {
        std::fs::write(repo.join("socket.yml"), yml).unwrap();
        let (policy, warnings) = SelectionPolicy::load(
            &DiskPolicyFs::new(repo),
            &socket_patch_core::policy::PolicyOverrides::default(),
        )
        .unwrap();
        InvocationPolicy {
            policy,
            repo_root: repo.to_path_buf(),
            warnings,
            warned: Default::default(),
        }
    }

    fn copy(dir: &Path, name: &str) -> CrawledPackage {
        let path = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            path.join("package.json"),
            format!(r#"{{"name": "{name}", "version": "1.0.0"}}"#),
        )
        .unwrap();
        CrawledPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            namespace: None,
            purl: format!("pkg:npm/{name}@1.0.0"),
            path,
        }
    }

    fn project(dir: &Path, lock: bool) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        if lock {
            std::fs::write(dir.join("package-lock.json"), "{}").unwrap();
        }
    }

    /// #554: copies under a nested project's `node_modules` are judged by
    /// that project's root, not only the scan root.
    #[test]
    fn nested_copies_follow_their_own_root() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap();
        project(&repo, true);
        project(&repo.join("services/legacy"), true);
        project(&repo.join("tests/e2e"), true);
        // A lockless workspace member belongs to the repo root.
        project(&repo.join("packages/member"), false);
        let invocation = invocation(
            &repo,
            "version: 2\npatches:\n  ignorePaths: [\"/services/\"]\n",
        );
        let mut policy = ScanPolicy::for_root(&invocation, &repo, true, false);
        policy.judge_nested_roots(&invocation, &repo);
        let crawl = vec![
            copy(&repo, "shared"),
            copy(&repo.join("services/legacy"), "shared"),
            copy(&repo.join("services/legacy"), "legacy-only"),
            copy(
                &repo.join("services/legacy/node_modules/legacy-only"),
                "deep",
            ),
            copy(&repo.join("tests/e2e"), "fixture-only"),
            copy(&repo.join("packages/member"), "member-dep"),
        ];
        let kept: Vec<String> = policy
            .admit_crawled_copies(crawl, &HashSet::new())
            .into_iter()
            .map(|p| p.purl)
            .collect();
        assert_eq!(
            kept,
            [
                "pkg:npm/shared@1.0.0",
                "pkg:npm/shared@1.0.0",
                "pkg:npm/member-dep@1.0.0"
            ]
        );
        let doc = policy.json();
        let roots: Vec<(&str, &str)> = doc["filtered"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["project"].as_str().unwrap(),
                    f["reason"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            roots,
            [
                ("services/legacy", "policy_path_excluded"),
                ("tests/e2e", "policy_path_excluded")
            ]
        );
        // The shared package is noted only once a patch is selected for it.
        assert!(policy.shared_copy_warnings().is_empty());
        let offer: PatchSearchResult = serde_json::from_value(serde_json::json!({
            "uuid": "11111111-1111-4111-8111-111111111111",
            "purl": "pkg:npm/shared@1.0.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "d",
            "license": "MIT",
            "tier": "free",
            "vulnerabilities": {}
        }))
        .unwrap();
        policy.select(vec![offer]);
        let warnings = policy.shared_copy_warnings();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, POLICY_SHARED_COPY);
        assert!(
            warnings[0].detail.contains("services/legacy"),
            "{}",
            warnings[0].detail
        );
    }

    /// The crawl keeps one copy per purl: when that copy sits under a
    /// skipped root, the copy under an admitted root is looked up.
    #[tokio::test]
    async fn a_package_crawled_under_a_skipped_root_is_found_under_an_admitted_one() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap();
        project(&repo, true);
        project(&repo.join("services/legacy"), true);
        let invocation = invocation(
            &repo,
            "version: 2\npatches:\n  ignorePaths: [\"/services/\"]\n",
        );
        let mut policy = ScanPolicy::for_root(&invocation, &repo, true, false);
        policy.judge_nested_roots(&invocation, &repo);
        copy(&repo, "shared");
        let crawl = vec![
            copy(&repo.join("services/legacy"), "shared"),
            copy(&repo.join("services/legacy"), "legacy-only"),
        ];
        let nm_roots = [
            repo.join("node_modules"),
            repo.join("services/legacy/node_modules"),
        ];
        policy.locate_nested_copies(&nm_roots, &crawl).await;
        let kept: Vec<String> = policy
            .admit_crawled_copies(crawl, &HashSet::new())
            .into_iter()
            .map(|p| p.purl)
            .collect();
        assert_eq!(kept, ["pkg:npm/shared@1.0.0"]);
        assert_eq!(
            policy.report().shared_copies.get("pkg:npm/shared@1.0.0"),
            Some(&BTreeSet::from(["services/legacy".to_string()]))
        );
    }

    /// Without nested roots (hosted / vendored), every copy follows the
    /// scan root as before.
    #[test]
    fn without_nested_roots_every_copy_follows_the_scan_root() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap();
        project(&repo, true);
        project(&repo.join("services/legacy"), true);
        let invocation = invocation(
            &repo,
            "version: 2\npatches:\n  ignorePaths: [\"/services/\"]\n",
        );
        let mut policy = ScanPolicy::for_root(&invocation, &repo, true, false);
        let kept = policy.admit_crawled_copies(
            vec![copy(&repo.join("services/legacy"), "a")],
            &HashSet::new(),
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(policy.json()["counts"]["filtered"], 0);
    }
}
