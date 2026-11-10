//! The gem stale-install refresh as the commands run it: after a hosted
//! redirect (`scan` / `get --mode hosted`) or its unwind (`rollback`,
//! `remove`, a withdrawn-patch restore), the gems Bundler already holds for
//! the project are brought to what the lock now pins
//! ([`socket_patch_core::patch::gem_refresh`]), and whatever is still stale
//! is reported: one `--json` warning per materialization, one human warning
//! for the run. A helper module, not a command. The rules are the "Gem
//! stale-install guard" section of CLI_CONTRACT.md.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::patch::gem_ext::RubyEnv;
use socket_patch_core::patch::gem_refresh::{refresh, Source, Target, Wanted};

use crate::args::GlobalArgs;
use crate::ui::plural;

/// What the lock now pins: the hosted patch, or the upstream registry
/// entry an unwind put back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Patched,
    Upstream,
}

impl Direction {
    /// The build the lock pins.
    fn wanted(self) -> &'static str {
        match self {
            Direction::Patched => "patched",
            Direction::Upstream => "upstream",
        }
    }

    /// The build a stale materialization still holds.
    fn stale(self) -> &'static str {
        match self {
            Direction::Patched => "unpatched",
            Direction::Upstream => "patched",
        }
    }

    fn switched(self) -> &'static str {
        match self {
            Direction::Patched => "was switched to its hosted patch",
            Direction::Upstream => "is back on its upstream registry entry",
        }
    }

    /// The warning code of a materialization that is still stale.
    pub(crate) fn stale_code(self) -> &'static str {
        match self {
            Direction::Patched => "redirect_gem_stale_install",
            Direction::Upstream => "upstream_gem_stale_install",
        }
    }

    /// The `--json` note of a materialization this run refreshed.
    pub(crate) fn refreshed_code(self) -> &'static str {
        match self {
            Direction::Patched => "redirect_gem_install_refreshed",
            Direction::Upstream => "upstream_gem_install_refreshed",
        }
    }

    /// The `--json` note of a materialization a wet run would refresh.
    pub(crate) fn would_refresh_code(self) -> &'static str {
        match self {
            Direction::Patched => "redirect_gem_install_would_refresh",
            Direction::Upstream => "upstream_gem_install_would_refresh",
        }
    }
}

/// The `--json` notes a human run prints as progress lines instead.
pub(crate) const INFO_CODES: &[&str] = &[
    "redirect_gem_install_refreshed",
    "redirect_gem_install_would_refresh",
    "upstream_gem_install_refreshed",
    "upstream_gem_install_would_refresh",
];

/// One gem's stale materialization: an installed copy with, for a
/// project-local one, the stale archive in Bundler's cache dir that the
/// same remedy covers; or that archive alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaleGem {
    pub(crate) purl: String,
    /// `<name>-<version>[-<platform>]`.
    pub(crate) leaf: String,
    /// The installed gem dir, and whether its gem home is the project's
    /// own (as opposed to one other projects share).
    pub(crate) installed: Option<(PathBuf, bool)>,
    /// The stale archive in Bundler's cache dir.
    pub(crate) cache_archive: Option<PathBuf>,
}

/// What the run may refresh.
#[derive(Debug, Clone)]
pub(crate) struct Policy {
    /// `--no-gem-install-refresh` is not set.
    pub(crate) enabled: bool,
    /// `--gem-refresh-shared`: a shared gem home is refreshed too.
    pub(crate) shared: bool,
    pub(crate) dry_run: bool,
    /// The project root: what resolves outside it is only written with
    /// `shared`.
    pub(crate) root: PathBuf,
    pub(crate) ruby: RubyEnv,
}

impl Policy {
    pub(crate) fn of(common: &GlobalArgs) -> Self {
        Policy {
            enabled: !common.no_gem_install_refresh,
            shared: common.gem_refresh_shared,
            dry_run: common.dry_run,
            root: common.cwd.clone(),
            ruby: RubyEnv {
                cwd: common.cwd.clone(),
                rebuild: !common.no_gem_native_rebuild,
            },
        }
    }

    /// Whether this run may replace `path` (an installed gem dir whose
    /// home is, `project_local`, or is not the project's own; an archive in
    /// Bundler's cache dir, always the project's). `Err` is why not.
    ///
    /// The project's own paths can still resolve outside its tree: a
    /// `.bundle/config` `path` or `cache_path` naming another directory, a
    /// `vendor/bundle` that is a symlink. The repository picks those, so
    /// they are written only on the same request as a shared gem home.
    fn may_replace(&self, path: &Path, project_local: bool) -> Result<(), Why> {
        if !project_local && !self.shared {
            return Err(Why::Shared);
        }
        if !self.enabled {
            return Err(Why::Disabled);
        }
        if !self.shared && !resolves_inside(&self.root, path) {
            return Err(Why::Failed(
                "it is outside the project directory; `--gem-refresh-shared` refreshes it too"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Whether `path` is physically inside `root` (both resolved through
/// symlinks). A path that cannot be resolved is not.
fn resolves_inside(root: &Path, path: &Path) -> bool {
    match (std::fs::canonicalize(root), std::fs::canonicalize(path)) {
        (Ok(root), Ok(path)) => path.starts_with(root),
        _ => false,
    }
}

/// Why a materialization is still stale.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Why {
    /// It is in a gem home other projects may load, and those are only
    /// refreshed on request.
    Shared,
    /// `--no-gem-install-refresh`.
    Disabled,
    /// The refresh was tried, or could not be.
    Failed(String),
}

/// What one refresh pass did.
#[derive(Debug, Default)]
pub(crate) struct Attempt {
    /// `(purl, what)` refreshed; on a dry run, what a wet run would try.
    pub(crate) refreshed: Vec<(String, Target)>,
    /// Why a target the pass did not refresh is as it was, by its path.
    left: BTreeMap<PathBuf, Why>,
}

impl Attempt {
    /// Whether the pass changed anything on disk.
    pub(crate) fn changed(&self, policy: &Policy) -> bool {
        !policy.dry_run && !self.refreshed.is_empty()
    }

    /// The archives in Bundler's cache dir the pass replaced.
    pub(crate) fn replaced_archives(&self) -> impl Iterator<Item = &Path> {
        self.refreshed
            .iter()
            .filter_map(|(_, target)| match target {
                Target::CacheArchive(path) => Some(path.as_path()),
                Target::Installed(_) => None,
            })
    }
}

/// One leaf's part of a pass: the archive, and each target with the purl
/// it was found stale for.
struct LeafRefresh<'a> {
    wanted: Option<Wanted>,
    targets: Vec<Target>,
    purls: Vec<&'a str>,
}

/// Refresh what `policy` allows of `gems`. `wanted` names the archive a
/// gem is refreshed from (`None`: nothing pins its sha256). Gems that
/// share a leaf are refreshed from one fetch of it.
pub(crate) async fn attempt(
    gems: &[StaleGem],
    wanted: impl Fn(&StaleGem) -> Option<Wanted>,
    source: &Source<'_>,
    policy: &Policy,
    direction: Direction,
) -> Attempt {
    let mut out = Attempt::default();
    let mut by_leaf: BTreeMap<&str, LeafRefresh<'_>> = BTreeMap::new();
    for gem in gems {
        let mut targets = Vec::new();
        let candidates = [
            gem.installed
                .as_ref()
                .map(|(dir, local)| (Target::Installed(dir.clone()), *local)),
            gem.cache_archive
                .as_ref()
                .map(|path| (Target::CacheArchive(path.clone()), true)),
        ];
        for (target, project_local) in candidates.into_iter().flatten() {
            match policy.may_replace(target.path(), project_local) {
                Ok(()) => targets.push(target),
                Err(why) => {
                    out.left.insert(target.path().to_path_buf(), why);
                }
            }
        }
        if targets.is_empty() {
            continue;
        }
        let slot = by_leaf
            .entry(gem.leaf.as_str())
            .or_insert_with(|| LeafRefresh {
                wanted: wanted(gem),
                targets: Vec::new(),
                purls: Vec::new(),
            });
        for target in targets {
            if !slot.targets.contains(&target) {
                slot.targets.push(target);
                slot.purls.push(gem.purl.as_str());
            }
        }
    }
    for LeafRefresh {
        wanted,
        targets,
        purls,
    } in by_leaf.into_values()
    {
        let Some(mut wanted) = wanted else {
            for target in &targets {
                out.left.insert(
                    target.path().to_path_buf(),
                    Why::Failed(format!(
                        "nothing pins the sha256 of the {} gem",
                        direction.wanted()
                    )),
                );
            }
            continue;
        };
        if policy.dry_run {
            out.refreshed
                .extend(purls.iter().map(|p| p.to_string()).zip(targets));
            continue;
        }
        // An archive another target of this gem holds may already be the
        // wanted one.
        for target in &targets {
            let path = match target {
                Target::Installed(dir) => home_cache_archive(dir),
                Target::CacheArchive(path) => Some(path.clone()),
            };
            wanted.on_disk.extend(path);
        }
        let outcomes = refresh(&wanted, &targets, source, &policy.ruby).await;
        for ((target, purl), outcome) in targets.into_iter().zip(purls).zip(outcomes) {
            match outcome {
                Ok(()) => out.refreshed.push((purl.to_string(), target)),
                Err(why) => {
                    out.left
                        .insert(target.path().to_path_buf(), Why::Failed(why));
                }
            }
        }
    }
    out
}

/// `<home>/cache/<leaf>.gem` of the installed gem dir `<home>/gems/<leaf>`.
pub(crate) fn home_cache_archive(gem_dir: &Path) -> Option<PathBuf> {
    let leaf = gem_dir.file_name()?.to_str()?;
    let home = gem_dir.parent()?.parent()?;
    Some(home.join("cache").join(format!("{leaf}.gem")))
}

/// `<home>/specifications/<leaf>.gemspec` of an installed gem dir.
fn home_spec(gem_dir: &Path) -> Option<PathBuf> {
    let leaf = gem_dir.file_name()?.to_str()?;
    let home = gem_dir.parent()?.parent()?;
    Some(home.join("specifications").join(format!("{leaf}.gemspec")))
}

/// The local-path remedy: Bundler then installs every gem of the project
/// into the project, from the source the lock names.
const LOCAL_PATH_REMEDY: &str = "bundle config set --local path vendor/bundle && bundle install";

/// The files whose removal makes `bundle install` fetch the gem again: the
/// installed copy's `specifications` entry and cached archive (Bundler
/// then counts the gem as missing and has no archive to reinstall from),
/// and the stale archive in Bundler's own cache dir.
fn files_to_remove(gem: &StaleGem) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some((dir, _)) = &gem.installed {
        files.extend(home_spec(dir));
        files.extend(home_cache_archive(dir));
    }
    files.extend(gem.cache_archive.clone());
    files
}

fn display_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// How a refresh that did not happen is retried.
fn retry_hint(direction: Direction, why: Option<&Why>) -> &'static str {
    match (why, direction) {
        (Some(Why::Disabled), _) => "Re-run without `--no-gem-install-refresh`, or ",
        (Some(Why::Failed(_)), Direction::Patched) => "Re-run `socket-patch scan` to retry, or ",
        _ => "",
    }
}

/// `action` after `hint` (which ends mid-sentence), or as a sentence of
/// its own when there is none.
fn after_hint(hint: &str, action: &str) -> String {
    if hint.is_empty() {
        crate::ui::sentence_case(action)
    } else {
        format!("{hint}{action}")
    }
}

fn reason(why: Option<&Why>) -> String {
    match why {
        Some(Why::Failed(reason)) => format!(" ({reason})"),
        Some(Why::Disabled) => " (`--no-gem-install-refresh` is set)".to_string(),
        _ => String::new(),
    }
}

/// The detail of one still-stale materialization (the `--json` warning).
/// `why` is `None` where no refresh was attempted yet.
pub(crate) fn stale_detail(direction: Direction, gem: &StaleGem, why: Option<&Why>) -> String {
    let (purl, switched) = (&gem.purl, direction.switched());
    let (stale, wanted) = (direction.stale(), direction.wanted());
    let reuse =
        format!("`bundle install` reuses an installed gem instead of fetching the {wanted} one");
    match &gem.installed {
        Some((dir, false)) if !matches!(why, Some(Why::Disabled | Why::Failed(_))) => format!(
            "{purl} {switched}, but the shared gem home still holds its {stale} install at \
             {}, and {reuse}. Other projects may load that gem home, so it was left alone. \
             Install the {wanted} gem for this project only with `{LOCAL_PATH_REMEDY}`, or \
             re-run with `--gem-refresh-shared` to replace the shared copy",
            dir.display()
        ),
        Some((dir, _)) => format!(
            "{purl} {switched}, but its {stale} install at {} was not refreshed{}, and \
             {reuse}. {}",
            dir.display(),
            reason(why),
            after_hint(
                retry_hint(direction, why),
                &format!(
                    "remove {} and run `bundle install`",
                    display_list(&files_to_remove(gem))
                )
            ),
        ),
        None => format!(
            "{purl} {switched}, but Bundler's cache dir still holds its {stale} archive at \
             {}, which was not replaced{}. Bundler installs from that dir before it fetches, \
             so an install fails on the pinned checksum or keeps the {stale} gem. {}",
            gem.cache_archive
                .as_deref()
                .unwrap_or(Path::new(""))
                .display(),
            reason(why),
            after_hint(
                retry_hint(direction, why),
                "delete it and run `bundle cache`"
            ),
        ),
    }
}

/// `rack 2.2.3` for `pkg:gem/rack@2.2.3`.
fn gem_label(purl: &str) -> String {
    match socket_patch_core::utils::purl::purl_parts(purl) {
        Some((_, name, version)) => format!("{name} {version}"),
        None => purl.to_string(),
    }
}

fn labels<'a>(purls: impl IntoIterator<Item = &'a str>) -> String {
    let labels: BTreeSet<String> = purls.into_iter().map(gem_label).collect();
    labels.into_iter().collect::<Vec<_>>().join(", ")
}

/// The run's one human warning for everything still stale: what, why, and
/// the remedy as a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) headline: String,
    pub(crate) bullets: Vec<String>,
}

impl Summary {
    /// The warning as one paragraph, for a command that prints each of its
    /// warnings on one line.
    pub(crate) fn paragraph(&self) -> String {
        let mut text = format!("{}.", self.headline);
        for bullet in &self.bullets {
            text.push(' ');
            text.push_str(bullet);
        }
        text.trim_end_matches('.').to_string()
    }
}

/// What a refresh pass leaves to say.
#[derive(Debug, Default)]
pub(crate) struct Report {
    /// The `--json` warnings: a note per refreshed materialization, then
    /// a warning per materialization that is still stale.
    pub(crate) warnings: Vec<(&'static str, String)>,
    /// The human progress lines for what was (or, on a dry run, would be)
    /// refreshed.
    pub(crate) progress: Vec<String>,
    /// The human warning for what is still stale.
    pub(crate) summary: Option<Summary>,
}

/// Why `gem` (its installed copy, else its cache-dir archive) is still
/// stale after `attempt`.
fn why_stale(gem: &StaleGem, attempt: &Attempt) -> Why {
    let path = match (&gem.installed, &gem.cache_archive) {
        (Some((dir, _)), _) => dir.as_path(),
        (None, Some(archive)) => archive.as_path(),
        (None, None) => Path::new(""),
    };
    attempt.left.get(path).cloned().unwrap_or_else(|| {
        // The pass replaced it and the probe after it still calls it stale.
        Why::Failed("it did not verify after the refresh".to_string())
    })
}

/// Report a pass: `attempt` is what it refreshed, `stale` what a probe
/// after it still finds stale. A dry run reports only what it would
/// refresh: it switched nothing, so nothing is stale yet.
pub(crate) fn report(
    direction: Direction,
    stale: &[StaleGem],
    attempt: &Attempt,
    policy: &Policy,
) -> Report {
    let mut out = Report::default();
    let (stale_word, wanted) = (direction.stale(), direction.wanted());
    let (code, would, replaced) = if policy.dry_run {
        (
            direction.would_refresh_code(),
            "would replace",
            "Would replace",
        )
    } else {
        (direction.refreshed_code(), "replaced", "Replaced")
    };
    let (mut installed, mut archives) = (Vec::new(), Vec::new());
    for (purl, target) in &attempt.refreshed {
        let what = match target {
            Target::Installed(_) => {
                installed.push(purl.as_str());
                "install"
            }
            Target::CacheArchive(_) => {
                archives.push(purl.as_str());
                "archive"
            }
        };
        out.warnings.push((
            code,
            format!(
                "{purl}: {would} the {stale_word} {what} at {} with the {wanted} gem",
                target.path().display()
            ),
        ));
    }
    if !installed.is_empty() {
        out.progress.push(format!(
            "{replaced} the installed copy of {} with the {wanted} build: {}.",
            plural(installed.len(), "gem", "gems"),
            labels(installed.iter().copied())
        ));
    }
    if !archives.is_empty() {
        out.progress.push(format!(
            "{replaced} {} in Bundler's cache dir with the {wanted} gem: {}.",
            plural(archives.len(), "archive", "archives"),
            labels(archives.iter().copied())
        ));
    }
    if policy.dry_run || stale.is_empty() {
        return out;
    }

    // gem home → the gems left alone there.
    let mut shared: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    // reason → the gems not refreshed for it.
    let mut local: BTreeMap<Why, Vec<&StaleGem>> = BTreeMap::new();
    for gem in stale {
        let why = why_stale(gem, attempt);
        out.warnings.push((
            direction.stale_code(),
            stale_detail(direction, gem, Some(&why)),
        ));
        match (&why, &gem.installed) {
            (Why::Shared, Some((dir, _))) => {
                let home = dir.parent().and_then(Path::parent).unwrap_or(dir);
                shared
                    .entry(home.display().to_string())
                    .or_default()
                    .push(&gem.purl);
            }
            _ => local.entry(why).or_default().push(gem),
        }
    }
    let count = stale
        .iter()
        .map(|gem| gem.purl.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let headline = match direction {
        Direction::Patched => format!(
            "{} still unpatched on disk after the switch to hosted patches",
            plural(count, "gem is", "gems are")
        ),
        Direction::Upstream => format!(
            "{} the patched build on disk after the switch back to the upstream registry",
            plural(count, "gem still holds", "gems still hold")
        ),
    };
    let mut bullets = Vec::new();
    let shared_gems: usize = shared.values().map(Vec::len).sum();
    for (home, purls) in &shared {
        bullets.push(format!(
            "Shared gem home {home} (left alone, other projects may load it): {}.",
            labels(purls.iter().copied())
        ));
    }
    if shared_gems > 0 {
        let (them, copies) = if shared_gems == 1 {
            ("it", "copy")
        } else {
            ("them", "copies")
        };
        bullets.push(format!(
            "`bundle install` reuses an installed gem instead of fetching the {wanted} one. To \
             install {them} for this project only, run `{LOCAL_PATH_REMEDY}`, or re-run with \
             `--gem-refresh-shared` to replace the shared {copies}."
        ));
    }
    for (why, gems) in &local {
        let files: Vec<PathBuf> = gems.iter().flat_map(|gem| files_to_remove(gem)).collect();
        let files: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
        bullets.push(format!(
            "Not refreshed{}: {}. {}.",
            reason(Some(why)),
            labels(gems.iter().map(|gem| gem.purl.as_str())),
            after_hint(
                retry_hint(direction, Some(why)),
                &format!("run `rm -f {} && bundle install`", files.join(" "))
            ),
        ));
    }
    out.summary = Some(Summary { headline, bullets });
    out
}

/// The stale materializations of the gems a hosted unwind just put back on
/// their upstream entries, judged like the hosted scan's guard, with the
/// roles swapped: an installed copy (ruby platform) is stale when the
/// archive RubyGems installed it from, `<home>/cache/<leaf>.gem`, is
/// readable and is not the upstream one, and so is such an archive in
/// Bundler's cache dir. `upstream` is each purl's upstream sha256; a purl
/// without one is not judged.
async fn stale_after_restore(
    common: &GlobalArgs,
    upstream: &BTreeMap<String, String>,
) -> Vec<StaleGem> {
    use socket_patch_core::crawlers::types::CrawlerOptions;
    use socket_patch_core::crawlers::RubyCrawler;
    use socket_patch_core::vendor::file_sha256_hex;

    let purls: Vec<String> = upstream.keys().cloned().collect();
    let crawler = RubyCrawler::new();
    let options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };
    let app_cache =
        socket_patch_core::crawlers::ruby_crawler::bundler_app_cache_dir(&common.cwd).await;
    let mut out = Vec::new();
    for home in crawler.bundler_install_homes(&options).await {
        let found = crawler.find_each_by_purl(&home.gems_dir, &purls).await;
        for (purl, pkg) in purls.iter().zip(found) {
            let (Some(pkg), Some(sha)) = (pkg, upstream.get(purl)) else {
                continue;
            };
            let Some((_, name, version)) = socket_patch_core::utils::purl::purl_parts(purl) else {
                continue;
            };
            let leaf = format!("{name}-{version}");
            // A platform gem's archive is not the one the lock's
            // ruby-platform checksum names.
            if pkg.path.file_name().and_then(|n| n.to_str()) != Some(leaf.as_str()) {
                continue;
            }
            let Some(archive) = home_cache_archive(&pkg.path) else {
                continue;
            };
            match file_sha256_hex(&archive).await {
                Some(got) if &got != sha => out.push(StaleGem {
                    purl: purl.clone(),
                    leaf,
                    installed: Some((pkg.path.clone(), home.project_local)),
                    cache_archive: None,
                }),
                _ => {}
            }
        }
    }
    for (purl, sha) in upstream {
        let Some((_, name, version)) = socket_patch_core::utils::purl::purl_parts(purl) else {
            continue;
        };
        let leaf = format!("{name}-{version}");
        let archive = app_cache.join(format!("{leaf}.gem"));
        match file_sha256_hex(&archive).await {
            Some(got) if &got != sha => out.push(StaleGem {
                purl: purl.clone(),
                leaf,
                installed: None,
                cache_archive: Some(archive),
            }),
            _ => {}
        }
    }
    out
}

/// What the hosted unwind's refresh did, for [`crate::commands::hosted_unwind`].
#[derive(Debug, Default)]
pub(crate) struct RestoreRefresh {
    pub(crate) report: Report,
    /// The archives in Bundler's cache dir that now hold the upstream gem.
    pub(crate) replaced_archives: Vec<PathBuf>,
    /// The gems whose installed copies were refreshed (on a dry run: would
    /// be) with none left on the patched build: nothing of theirs is left
    /// for a reinstall.
    pub(crate) refreshed_installs: BTreeSet<String>,
}

/// After a hosted unwind restored the gems `restored` to their upstream
/// entries: bring their installed copies and cached archives back to the
/// upstream gem, and report what is still the patched build. `staged` is
/// the restore's staged text (the restored lock). Only installed copies
/// are reported as still stale here: the restore itself names an archive
/// left in Bundler's cache dir (`upstream_gem_stale_cache`).
pub(crate) async fn after_restore(
    common: &GlobalArgs,
    restored: &[String],
    staged: &BTreeMap<String, Option<String>>,
) -> RestoreRefresh {
    use socket_patch_core::patch::redirect::upstream::gem_upstream_archive;

    let policy = Policy::of(common);
    let direction = Direction::Upstream;
    let mut shas: BTreeMap<String, String> = BTreeMap::new();
    let mut urls: BTreeMap<String, Option<String>> = BTreeMap::new();
    for purl in restored
        .iter()
        .filter(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Gem))
    {
        if let Some((sha, url)) =
            gem_upstream_archive(&common.cwd, staged, purl, common.offline).await
        {
            shas.insert(purl.clone(), sha);
            urls.insert(purl.clone(), url);
        }
    }
    if shas.is_empty() {
        return RestoreRefresh::default();
    }
    let stale = stale_after_restore(common, &shas).await;
    if stale.is_empty() {
        return RestoreRefresh::default();
    }
    let wanted = |gem: &StaleGem| {
        Some(Wanted {
            leaf: gem.leaf.clone(),
            kind: direction.wanted(),
            sha256: BTreeSet::from([shas.get(&gem.purl)?.clone()]),
            urls: urls.get(&gem.purl)?.iter().cloned().collect(),
            on_disk: Vec::new(),
        })
    };
    let source = if common.offline {
        Source::DiskOnly
    } else {
        Source::Registry
    };
    let pass = attempt(&stale, wanted, &source, &policy, direction).await;
    let still = if pass.changed(&policy) {
        stale_after_restore(common, &shas).await
    } else {
        stale
    };
    let installed: Vec<StaleGem> = still
        .into_iter()
        .filter(|gem| gem.installed.is_some())
        .collect();
    let refreshed_installs = pass
        .refreshed
        .iter()
        .filter(|(purl, target)| {
            matches!(target, Target::Installed(_)) && !installed.iter().any(|gem| &gem.purl == purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    RestoreRefresh {
        refreshed_installs,
        report: report(direction, &installed, &pass, &policy),
        replaced_archives: if policy.dry_run {
            Vec::new()
        } else {
            pass.replaced_archives().map(Path::to_path_buf).collect()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(root: &Path, enabled: bool, shared: bool, dry_run: bool) -> Policy {
        Policy {
            enabled,
            shared,
            dry_run,
            root: root.to_path_buf(),
            ruby: RubyEnv {
                cwd: root.to_path_buf(),
                rebuild: true,
            },
        }
    }

    /// `<home>/gems/<name>-1.0.0` created on disk, as a stale gem.
    fn installed(name: &str, home: &Path, project_local: bool) -> StaleGem {
        let dir = home.join("gems").join(format!("{name}-1.0.0"));
        std::fs::create_dir_all(&dir).unwrap();
        StaleGem {
            purl: format!("pkg:gem/{name}@1.0.0"),
            leaf: format!("{name}-1.0.0"),
            installed: Some((dir, project_local)),
            cache_archive: None,
        }
    }

    /// An archive that verifies nowhere: an attempt that tries it fails.
    fn unobtainable(gem: &StaleGem) -> Option<Wanted> {
        Some(Wanted {
            leaf: gem.leaf.clone(),
            kind: "patched",
            sha256: BTreeSet::from(["0".repeat(64)]),
            urls: Vec::new(),
            on_disk: Vec::new(),
        })
    }

    async fn pass(gems: &[StaleGem], policy: &Policy) -> Attempt {
        attempt(
            gems,
            unobtainable,
            &Source::DiskOnly,
            policy,
            Direction::Patched,
        )
        .await
    }

    /// Four gems in a shared home are one warning: the home, the gems, why
    /// in a sentence, and the remedy as a command.
    #[tokio::test]
    async fn shared_home_gems_are_one_short_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let (proj, home) = (tmp.path().join("proj"), tmp.path().join("gemhome"));
        std::fs::create_dir_all(&proj).unwrap();
        let stale: Vec<StaleGem> = ["rack", "rexml", "addressable", "jmespath"]
            .iter()
            .map(|name| installed(name, &home, false))
            .collect();
        let policy = policy(&proj, true, false, false);
        let pass = pass(&stale, &policy).await;
        assert!(pass.refreshed.is_empty(), "a shared home is never tried");
        let out = report(Direction::Patched, &stale, &pass, &policy);
        assert_eq!(out.warnings.len(), 4, "one --json warning per gem");
        assert!(out
            .warnings
            .iter()
            .all(|(code, detail)| *code == "redirect_gem_stale_install"
                && detail.contains("--gem-refresh-shared")
                && detail.contains(LOCAL_PATH_REMEDY)));
        let summary = out.summary.expect("a summary");
        assert_eq!(
            summary.headline,
            "4 gems are still unpatched on disk after the switch to hosted patches"
        );
        assert_eq!(
            summary.bullets,
            vec![
                format!(
                    "Shared gem home {} (left alone, other projects may load it): addressable \
                     1.0.0, jmespath 1.0.0, rack 1.0.0, rexml 1.0.0.",
                    home.display()
                ),
                "`bundle install` reuses an installed gem instead of fetching the patched one. \
                 To install them for this project only, run `bundle config set --local path \
                 vendor/bundle && bundle install`, or re-run with `--gem-refresh-shared` to \
                 replace the shared copies."
                    .to_string(),
            ]
        );
        let fixed = summary.paragraph().len() - home.display().to_string().len();
        assert!(fixed < 480, "the whole warning stays short: {fixed}");
    }

    /// A project-local copy the refresh could not fix says why and names
    /// the two files whose removal makes Bundler fetch the gem.
    #[tokio::test]
    async fn a_failed_local_refresh_names_the_reason_and_the_files() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("vendor/bundle/ruby/3.4.0");
        let gem = installed("rack", &home, true);
        let (dir, _) = gem.installed.clone().unwrap();
        let policy = policy(tmp.path(), true, false, false);
        let pass = pass(std::slice::from_ref(&gem), &policy).await;
        let out = report(
            Direction::Patched,
            std::slice::from_ref(&gem),
            &pass,
            &policy,
        );
        let (code, detail) = &out.warnings[0];
        assert_eq!(*code, "redirect_gem_stale_install");
        let spec = home.join("specifications").join("rack-1.0.0.gemspec");
        let cache = home.join("cache").join("rack-1.0.0.gem");
        for needle in [
            "pkg:gem/rack@1.0.0",
            "this run is offline and no verified copy of the patched gem is on disk",
            "Re-run `socket-patch scan` to retry, or remove ",
            "`bundle install`",
            &dir.display().to_string(),
            &spec.display().to_string(),
            &cache.display().to_string(),
        ] {
            assert!(detail.contains(needle), "missing {needle:?}: {detail}");
        }
        let summary = out.summary.unwrap();
        assert_eq!(
            summary.headline,
            "1 gem is still unpatched on disk after the switch to hosted patches"
        );
        assert_eq!(summary.bullets.len(), 1);
        assert!(
            summary.bullets[0].starts_with(
                "Not refreshed (this run is offline and no verified copy of the patched gem is \
                 on disk): rack 1.0.0. Re-run `socket-patch scan` to retry, or run `rm -f "
            ),
            "{}",
            summary.bullets[0]
        );
        assert!(
            summary.bullets[0].ends_with(" && bundle install`."),
            "{}",
            summary.bullets[0]
        );
    }

    #[test]
    fn refreshed_gems_are_notes_and_one_progress_line_each_kind() {
        let pass = Attempt {
            refreshed: vec![
                (
                    "pkg:gem/rack@2.2.3".to_string(),
                    Target::Installed(PathBuf::from("vendor/bundle/ruby/3.4.0/gems/rack-2.2.3")),
                ),
                (
                    "pkg:gem/rexml@3.2.4".to_string(),
                    Target::Installed(PathBuf::from("vendor/bundle/ruby/3.4.0/gems/rexml-3.2.4")),
                ),
                (
                    "pkg:gem/rack@2.2.3".to_string(),
                    Target::CacheArchive(PathBuf::from("vendor/cache/rack-2.2.3.gem")),
                ),
            ],
            left: BTreeMap::new(),
        };
        let root = Path::new(".");
        let out = report(
            Direction::Patched,
            &[],
            &pass,
            &policy(root, true, false, false),
        );
        assert!(out.summary.is_none());
        assert_eq!(
            out.progress,
            vec![
                "Replaced the installed copy of 2 gems with the patched build: rack 2.2.3, \
                 rexml 3.2.4."
                    .to_string(),
                "Replaced 1 archive in Bundler's cache dir with the patched gem: rack 2.2.3."
                    .to_string(),
            ]
        );
        assert_eq!(out.warnings.len(), 3);
        assert!(out
            .warnings
            .iter()
            .all(|(code, _)| *code == "redirect_gem_install_refreshed"));

        // A dry run says what it would do, under its own code.
        let out = report(
            Direction::Upstream,
            &[],
            &pass,
            &policy(root, true, false, true),
        );
        assert!(
            out.progress[0]
                .starts_with("Would replace the installed copy of 2 gems with the upstream build"),
            "{}",
            out.progress[0]
        );
        assert!(out.warnings.iter().all(|(code, detail)| *code
            == "upstream_gem_install_would_refresh"
            && detail.contains("would replace the patched")));
    }

    /// What a pass may replace: the project's own copies; a shared home, or
    /// a project path that resolves outside the project, only with
    /// `--gem-refresh-shared`; nothing with `--no-gem-install-refresh`.
    #[tokio::test]
    async fn the_policy_decides_what_is_tried() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let shared = installed("rack", &tmp.path().join("gemhome"), false);
        let local = installed("rexml", &proj.join("vendor/bundle/ruby/3.4.0"), true);
        // The project's own `.bundle/config` path, outside its tree.
        let outside = installed("puma", &tmp.path().join("elsewhere"), true);
        let gems = vec![shared, local, outside];
        let planned = |enabled: bool, shared: bool| {
            let (gems, policy) = (gems.clone(), policy(&proj, enabled, shared, true));
            async move {
                pass(&gems, &policy)
                    .await
                    .refreshed
                    .into_iter()
                    .map(|(purl, _)| purl)
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(planned(true, false).await, vec!["pkg:gem/rexml@1.0.0"]);
        assert_eq!(
            planned(true, true).await,
            vec![
                "pkg:gem/puma@1.0.0",
                "pkg:gem/rack@1.0.0",
                "pkg:gem/rexml@1.0.0"
            ]
        );
        assert!(planned(false, true).await.is_empty());

        // What is left says why: the shared home keeps its own remedy, the
        // out-of-tree path names the flag that covers it.
        let policy_default = policy(&proj, true, false, false);
        let tried = pass(&gems, &policy_default).await;
        let out = report(Direction::Patched, &gems, &tried, &policy_default);
        let details: Vec<&str> = out.warnings.iter().map(|(_, d)| d.as_str()).collect();
        assert!(
            details[0].contains("the shared gem home still holds"),
            "{}",
            details[0]
        );
        assert!(details[1].contains("this run is offline"), "{}", details[1]);
        assert!(
            details[2].contains("it is outside the project directory")
                && details[2].contains("`--gem-refresh-shared`"),
            "{}",
            details[2]
        );

        // Disabled: the local copy's warning says which flag.
        let policy_off = policy(&proj, false, false, false);
        let tried = pass(&gems, &policy_off).await;
        let out = report(Direction::Patched, &gems, &tried, &policy_off);
        assert!(out.warnings[0]
            .1
            .contains("the shared gem home still holds"));
        assert!(
            out.warnings[1]
                .1
                .contains("`--no-gem-install-refresh` is set")
                && out.warnings[1]
                    .1
                    .contains("Re-run without `--no-gem-install-refresh`"),
            "{}",
            out.warnings[1].1
        );
    }
}
