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
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::gem_ext::RubyEnv;
use socket_patch_core::patch::gem_refresh::{refresh, Source, Target, Wanted};

use crate::args::{GlobalArgs, RunApiClient};
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
    /// The installed files already hold the patch (agent mode patched them
    /// in place); what is stale is the upstream archive RubyGems kept
    /// beside them, `<home>/cache/<leaf>.gem`. Only that archive is
    /// replaced: the gem dir, with what agent mode keeps in it, stays as
    /// it is.
    pub(crate) in_place: bool,
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
                offline: common.offline,
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
    /// Nothing says which build the copy holds: the sha256 of the wanted
    /// gem could not be had, for this reason. It is not known to be stale,
    /// and not known not to be.
    Unverified(String),
}

/// What one refresh pass did.
#[derive(Debug, Default)]
pub(crate) struct Attempt {
    /// `(purl, what)` refreshed; on a dry run, what a wet run would try.
    pub(crate) refreshed: Vec<(String, Target)>,
    /// Why a target the pass did not refresh is as it was, by its path.
    left: BTreeMap<PathBuf, Why>,
    /// The gem-home archives among the targets: the upstream archive
    /// beside an install patched in place ([`StaleGem::in_place`]).
    in_place: BTreeSet<PathBuf>,
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
                Target::CacheArchive(path) if !self.in_place.contains(path) => Some(path.as_path()),
                _ => None,
            })
    }

    /// Whether the pass brought an installed copy in line with the lock:
    /// it replaced the copy, or the archive beside one patched in place.
    pub(crate) fn refreshed_an_install(&self) -> bool {
        self.refreshed.iter().any(|(_, target)| match target {
            Target::Installed(_) => true,
            Target::CacheArchive(path) => self.in_place.contains(path),
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
            match (&gem.installed, gem.in_place) {
                // Patched in place: the archive beside it, never the dir.
                (Some((dir, local)), true) => home_cache_archive(dir).map(|archive| {
                    out.in_place.insert(archive.clone());
                    (Target::CacheArchive(archive), *local)
                }),
                (Some((dir, local)), false) => Some((Target::Installed(dir.clone()), *local)),
                (None, _) => None,
            },
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
///
/// For a copy patched in place it is the cached archive alone: the files
/// are patched, and with no archive a reinstall fetches the gem from the
/// lock's source.
fn files_to_remove(gem: &StaleGem) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some((dir, _)) = &gem.installed {
        if !gem.in_place {
            files.extend(home_spec(dir));
        }
        files.extend(home_cache_archive(dir));
    }
    files.extend(gem.cache_archive.clone());
    files
}

/// What the upstream archive beside an in-place patch does once the lock
/// pins the patched gem.
const IN_PLACE_REINSTALL: &str = "`bundle pristine` and `bundle install --redownload` reinstall \
     from that archive: with a `CHECKSUMS` section in the lock Bundler removes the gem and fails \
     on the checksum, without one it brings the unpatched gem back";

fn display_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// How a refresh that did not happen is retried. An unwind can't be: its
/// first run removed the wiring a second one would look for.
fn retry_hint(direction: Direction, why: Option<&Why>) -> &'static str {
    match (why, direction) {
        (Some(Why::Disabled), Direction::Patched) => {
            "Re-run without `--no-gem-install-refresh`, or "
        }
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
        Some(Why::Failed(reason) | Why::Unverified(reason)) => format!(" ({reason})"),
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
    if let (true, Some((dir, project_local))) = (gem.in_place, &gem.installed) {
        let archive = home_cache_archive(dir).unwrap_or_default();
        let held = format!(
            "{purl} {switched}, but the copy patched in place at {} still has its upstream \
             archive at {}",
            dir.display(),
            archive.display()
        );
        return if !project_local && !matches!(why, Some(Why::Disabled | Why::Failed(_))) {
            format!(
                "{held}. {IN_PLACE_REINSTALL}. Other projects may load that shared gem home, so \
                 it was left alone. Install the {wanted} gem for this project only with \
                 `{LOCAL_PATH_REMEDY}`, or re-run with `--gem-refresh-shared` to replace the \
                 shared archive"
            )
        } else {
            format!(
                "{held}, which was not replaced{}. {IN_PLACE_REINSTALL}. {}",
                reason(why),
                after_hint(
                    retry_hint(direction, why),
                    &format!(
                        "remove {} and run `bundle install`",
                        display_list(&files_to_remove(gem))
                    )
                ),
            )
        };
    }
    match &gem.installed {
        Some((dir, _)) if matches!(why, Some(Why::Unverified(_))) => format!(
            "{purl} {switched}, but its install at {} could not be checked against the \
             {wanted} gem{}. If it was installed before the switch it still holds the {stale} \
             build, and {reuse}. {}",
            dir.display(),
            reason(why),
            after_hint(
                "",
                &format!(
                    "remove {} and run `bundle install`",
                    display_list(&files_to_remove(gem))
                )
            ),
        ),
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
        (Some((dir, _)), _) if gem.in_place => home_cache_archive(dir).unwrap_or_default(),
        (Some((dir, _)), _) => dir.clone(),
        (None, Some(archive)) => archive.clone(),
        (None, None) => PathBuf::new(),
    };
    attempt.left.get(&path).cloned().unwrap_or_else(|| {
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
    let (mut installed, mut archives, mut in_place) = (Vec::new(), Vec::new(), Vec::new());
    for (purl, target) in &attempt.refreshed {
        let what = match target {
            Target::Installed(_) => {
                installed.push(purl.as_str());
                format!("{stale_word} install")
            }
            Target::CacheArchive(path) if attempt.in_place.contains(path) => {
                in_place.push(purl.as_str());
                "upstream archive of the install patched in place".to_string()
            }
            Target::CacheArchive(_) => {
                archives.push(purl.as_str());
                format!("{stale_word} archive")
            }
        };
        out.warnings.push((
            code,
            format!(
                "{purl}: {would} the {what} at {} with the {wanted} gem",
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
    if !in_place.is_empty() {
        out.progress.push(format!(
            "{replaced} the upstream archive beside {} patched in place with the {wanted} gem: \
             {}.",
            plural(in_place.len(), "gem", "gems"),
            labels(in_place.iter().copied())
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
    // The gems left alone in a shared home that are patched in place.
    let mut shared_in_place = 0;
    for gem in stale {
        let why = why_stale(gem, attempt);
        if why == Why::Shared && gem.installed.is_some() && gem.in_place {
            shared_in_place += 1;
        }
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
    // A gem whose copy could not be checked is not known to be stale: it
    // is counted apart from the ones that are. A gem with a copy of each
    // kind (two gem homes) is known to be stale.
    let purls_where = |unverified: bool| {
        local
            .iter()
            .filter(move |(why, _)| matches!(why, Why::Unverified(_)) == unverified)
            .flat_map(|(_, gems)| gems.iter().map(|gem| gem.purl.as_str()))
    };
    let known_stale: BTreeSet<&str> = shared
        .values()
        .flatten()
        .copied()
        .chain(purls_where(false))
        .collect();
    let unchecked: BTreeSet<&str> = purls_where(true)
        .filter(|purl| !known_stale.contains(purl))
        .collect();
    let count = known_stale.len();
    let switch = match direction {
        Direction::Patched => "the switch to hosted patches",
        Direction::Upstream => "the switch back to the upstream registry",
    };
    let known = match direction {
        Direction::Patched if stale.iter().all(|gem| gem.in_place) => format!(
            "{} on disk after {switch}",
            plural(
                count,
                "gem patched in place still has its upstream archive",
                "gems patched in place still have their upstream archives"
            )
        ),
        Direction::Patched if stale.iter().any(|gem| gem.in_place) => format!(
            "{} unpatched files or archives on disk after {switch}",
            plural(count, "gem still has", "gems still have")
        ),
        Direction::Patched => format!(
            "{} still unpatched on disk after {switch}",
            plural(count, "gem is", "gems are")
        ),
        Direction::Upstream => format!(
            "{} the patched build on disk after {switch}",
            plural(count, "gem still holds", "gems still hold")
        ),
    };
    let headline = match (count, unchecked.len()) {
        (_, 0) => known,
        (0, n) => format!(
            "{} on disk could not be checked after {switch}",
            plural(n, "gem", "gems")
        ),
        (_, n) => format!(
            "{known}, and {} could not be checked",
            plural(n, "gem", "gems")
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
        // Why a copy left alone matters: an unpatched one keeps being
        // used, one patched in place is undone by a reinstall.
        let mut why = String::new();
        if shared_in_place < shared_gems {
            why.push_str(&format!(
                "`bundle install` reuses an installed gem instead of fetching the {wanted} one. "
            ));
        }
        if shared_in_place > 0 {
            why.push_str(
                "`bundle pristine` and `bundle install --redownload` reinstall a gem patched in \
                 place from the upstream archive beside it. ",
            );
        }
        bullets.push(format!(
            "{why}To install {them} for this project only, run `{LOCAL_PATH_REMEDY}`, or re-run \
             with `--gem-refresh-shared` to replace the shared {copies}."
        ));
    }
    for (why, gems) in &local {
        let files: Vec<PathBuf> = gems.iter().flat_map(|gem| files_to_remove(gem)).collect();
        let files: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
        let reinstall = format!("run `rm -f {} && bundle install`", files.join(" "));
        let names = labels(gems.iter().map(|gem| gem.purl.as_str()));
        bullets.push(match why {
            Why::Unverified(_) => format!(
                "Not checked against the {wanted} gem{}: {names}. A copy installed before \
                 the switch still holds the {stale_word} build; to be sure, {reinstall}.",
                reason(Some(why)),
            ),
            _ => format!(
                "Not refreshed{}: {names}. {}.",
                reason(Some(why)),
                after_hint(retry_hint(direction, Some(why)), &reinstall),
            ),
        });
    }
    out.summary = Some(Summary { headline, bullets });
    out
}

/// The installed copies (ruby platform) of `purls` in the gem homes Bundler
/// installs the project's gems into, each with the archive RubyGems
/// installed it from, `<home>/cache/<leaf>.gem`.
async fn installed_with_archives(common: &GlobalArgs, purls: &[String]) -> Vec<InstalledCopy> {
    use socket_patch_core::crawlers::types::CrawlerOptions;
    use socket_patch_core::crawlers::RubyCrawler;

    let crawler = RubyCrawler::new();
    let options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };
    let mut out = Vec::new();
    for home in crawler.bundler_install_homes(&options).await {
        let found = crawler.find_each_by_purl(&home.gems_dir, purls).await;
        for (purl, pkg) in purls.iter().zip(found) {
            let Some(pkg) = pkg else {
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
            out.push(InstalledCopy {
                purl: purl.clone(),
                leaf,
                dir: pkg.path.clone(),
                project_local: home.project_local,
                archive,
            });
        }
    }
    out
}

/// One installed copy [`installed_with_archives`] found.
struct InstalledCopy {
    purl: String,
    leaf: String,
    dir: PathBuf,
    project_local: bool,
    archive: PathBuf,
}

/// Which materializations an unwind's refresh covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Installed copies and the archives in Bundler's cache dir.
    All,
    /// Installed copies only.
    Installed,
}

/// The stale materializations of the gems an unwind just put back on
/// their upstream entries, judged like the hosted scan's guard, with the
/// roles swapped: an installed copy (ruby platform) is stale when the
/// archive RubyGems installed it from, `<home>/cache/<leaf>.gem`, is
/// readable and is not the upstream one, and so is (in [`Scope::All`])
/// such an archive in Bundler's cache dir. `upstream` is each purl's
/// upstream sha256; a purl without an entry is not judged. A purl whose
/// sha256 is `None` (the registry that would give it was refused) cannot
/// be judged either, and every installed copy of it is listed.
///
/// `records` holds the patch record of each gem that has one to judge by
/// (a vendored unwind's ledger entry). An installed copy whose files are
/// that record's patched ones is stale whatever its archive says, and
/// whether or not `upstream` has its purl: agent mode patched it in place
/// beside the upstream archive (#2093).
async fn stale_after_restore(
    common: &GlobalArgs,
    upstream: &BTreeMap<String, Option<String>>,
    records: &BTreeMap<String, PatchRecord>,
    scope: Scope,
) -> Vec<StaleGem> {
    use socket_patch_core::vendor::file_sha256_hex;

    let purls: Vec<String> = upstream
        .keys()
        .chain(records.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .cloned()
        .collect();
    let mut out = Vec::new();
    for copy in installed_with_archives(common, &purls).await {
        // With no upstream sha256 (the registry that would give it was
        // refused) nothing can be judged, so the copy is listed whether
        // or not its archive is still in the home's cache. With one,
        // only a readable archive that is not the upstream gem makes
        // the copy stale.
        let listed = match upstream.get(&copy.purl) {
            None => false,
            Some(None) => true,
            Some(Some(sha)) => {
                matches!(file_sha256_hex(&copy.archive).await, Some(got) if &got != sha)
            }
        };
        if listed || holds_patch(&copy, records).await {
            out.push(StaleGem {
                purl: copy.purl,
                leaf: copy.leaf,
                installed: Some((copy.dir, copy.project_local)),
                cache_archive: None,
                in_place: false,
            });
        }
    }
    if scope == Scope::Installed {
        return out;
    }
    // (An archive in Bundler's cache dir that cannot be checked is the
    // restore's own `upstream_gem_stale_cache` to name.)
    let app_cache =
        socket_patch_core::crawlers::ruby_crawler::bundler_app_cache_dir(&common.cwd).await;
    for (purl, sha) in upstream {
        let Some(sha) = sha else {
            continue;
        };
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
                in_place: false,
            }),
            _ => {}
        }
    }
    out
}

/// Whether the files of the installed `copy` are the patched ones of its
/// gem's record in `records`: every file the record lists hashes to its
/// `afterHash`. `false` for a gem with no record.
async fn holds_patch(copy: &InstalledCopy, records: &BTreeMap<String, PatchRecord>) -> bool {
    match records.get(&copy.purl) {
        Some(record) => {
            socket_patch_core::vex::verify::judge_installed_record(&copy.dir, record)
                .await
                .patched
        }
        None => false,
    }
}

/// What an unwind's refresh did, for [`crate::commands::hosted_unwind`]
/// and the vendored unwind ([`crate::commands::vendored_backend`]).
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
///
/// `pins` is the patch uuids each restored gem was pinned to, by purl. An
/// installed copy whose gem home keeps no archive of it (a pruned `cache/`:
/// Bundler 4.1's `prune`, a slim image, `gem cleanup`) is judged by those
/// patches' records, as the hosted scan judges it (#2092): see
/// [`PinJudge`]. `api` is the run's API client, built only if such a copy
/// needs a record.
pub(crate) async fn after_restore(
    common: &GlobalArgs,
    restored: &[String],
    staged: &BTreeMap<String, Option<String>>,
    pins: &BTreeMap<String, Vec<String>>,
    api: &RunApiClient,
) -> RestoreRefresh {
    let judge = PinJudge {
        common,
        api,
        pins,
        fetched: BTreeMap::new(),
        unreachable: false,
    };
    refresh_restored(
        common,
        restored,
        staged,
        &BTreeMap::new(),
        Some(judge),
        Scope::All,
    )
    .await
}

/// The patch record a `/patches/view/<uuid>` response gives for `uuid`;
/// `None` when it has none to judge by (no such patch, another patch's
/// record, or one listing no files).
pub(crate) fn view_record(
    view: Option<socket_patch_core::api::types::PatchResponse>,
    uuid: &str,
) -> Option<PatchRecord> {
    view.map(|view| socket_patch_core::manifest::records::record_from_patch_response(&view).1)
        .filter(|record| record.uuid == uuid && !record.files.is_empty())
}

/// Whether `path` is a file this run can open: an archive
/// [`stale_after_restore`] can judge an installed copy by.
async fn readable_file(path: &Path) -> bool {
    path.is_file() && tokio::fs::File::open(path).await.is_ok()
}

/// What judges the installed copies a hosted unwind's archive check cannot
/// (#2092): those whose gem home keeps no readable `<home>/cache/<leaf>.gem`.
/// Nothing else tells such a copy from the patched build the hosted scan
/// may have replaced it with, and no later `bundle install` replaces it.
/// Each is judged on its own files, by the record of a patch its gem was
/// pinned to (`pins`): a copy whose files all hash to a record's
/// `afterHash` values holds that patch.
struct PinJudge<'a> {
    common: &'a GlobalArgs,
    api: &'a RunApiClient,
    pins: &'a BTreeMap<String, Vec<String>>,
    /// The record fetched for each uuid asked for so far; `None` when there
    /// is none to judge by.
    fetched: BTreeMap<String, Option<PatchRecord>>,
    /// A fetch failed without an answer from the API: no other is tried,
    /// so an unreachable API costs one timeout, not one per gem.
    unreachable: bool,
}

impl PinJudge<'_> {
    /// `uuid`'s patch record, fetched at most once. `--offline` fetches
    /// nothing.
    async fn record(&mut self, uuid: &str) -> Option<&PatchRecord> {
        if !self.fetched.contains_key(uuid) {
            let record = if self.common.offline || self.unreachable {
                None
            } else {
                match self
                    .common
                    .api_client(self.api)
                    .await
                    .fetch_patch(uuid)
                    .await
                {
                    Ok(view) => view_record(view, uuid),
                    Err(_) => {
                        self.unreachable = true;
                        None
                    }
                }
            };
            self.fetched.insert(uuid.to_string(), record);
        }
        self.fetched.get(uuid).and_then(Option::as_ref)
    }

    /// The installed copies of `purls` with no readable archive in their
    /// gem home: those that hold a pinned patch (stale), and those no
    /// record could judge, each with why (the reason completes "could not
    /// be checked against the upstream gem (…)"). A copy every pinned
    /// patch's record judged, and none found patched, is neither. A run
    /// with no such copy fetches nothing.
    async fn probe(&mut self, purls: &[String]) -> (Vec<StaleGem>, Vec<(StaleGem, String)>) {
        let (mut stale, mut unjudged) = (Vec::new(), Vec::new());
        let purls: Vec<String> = purls
            .iter()
            .filter(|purl| self.pins.contains_key(*purl))
            .cloned()
            .collect();
        if purls.is_empty() {
            return (stale, unjudged);
        }
        for copy in installed_with_archives(self.common, &purls).await {
            if readable_file(&copy.archive).await {
                continue;
            }
            let (mut patched, mut missing) = (false, false);
            for uuid in self.pins.get(&copy.purl).into_iter().flatten() {
                match self.record(uuid).await {
                    Some(record) => {
                        if socket_patch_core::vex::verify::judge_installed_record(&copy.dir, record)
                            .await
                            .patched
                        {
                            patched = true;
                            break;
                        }
                    }
                    None => missing = true,
                }
            }
            if !patched && !missing {
                continue;
            }
            let gem = StaleGem {
                purl: copy.purl,
                leaf: copy.leaf,
                installed: Some((copy.dir, copy.project_local)),
                cache_archive: None,
                in_place: false,
            };
            if patched {
                stale.push(gem);
            } else {
                let fetch = if self.common.offline {
                    "`--offline` is set, so its patch record was not fetched"
                } else {
                    "its patch record could not be fetched"
                };
                unjudged.push((
                    gem,
                    format!("its gem home has no archive of it and {fetch}"),
                ));
            }
        }
        (stale, unjudged)
    }
}

/// After a wet vendored unwind put the gems `unwound` back on their
/// upstream entries (the lock on disk says so): Bundler loads their
/// installed copies again, and a copy that a hosted scan replaced with the
/// patched build before the gem was vendored is still that build (#2083).
/// So is a copy agent mode patched in place before the gem was vendored:
/// the takeover moved its manifest record into the vendor ledger and kept
/// the patched files, so once the ledger entry is gone nothing else could
/// undo them (#2093). `records` is each unwound gem's ledger record, by
/// purl; a copy whose files are the record's patched ones is such a copy,
/// whatever archive its gem home holds.
/// Those copies are brought back to the upstream gem exactly as
/// [`after_restore`] does it. An archive in Bundler's cache dir is not
/// touched: the vendored unwind names it (`upstream_gem_stale_cache`).
///
/// Only a gem the lock now resolves from rubygems.org is judged. A gem
/// with no installed copy to judge costs no registry lookup: a vendored
/// unwind then needs no network, as before.
pub(crate) async fn after_vendored_unwind(
    common: &GlobalArgs,
    unwound: &[String],
    records: &BTreeMap<String, PatchRecord>,
) -> RestoreRefresh {
    let mut installed: BTreeSet<String> = BTreeSet::new();
    for copy in installed_with_archives(common, unwound).await {
        if copy.archive.is_file() || holds_patch(&copy, records).await {
            installed.insert(copy.purl);
        }
    }
    if installed.is_empty() {
        return RestoreRefresh::default();
    }
    let installed: Vec<String> = installed.into_iter().collect();
    refresh_restored(
        common,
        &installed,
        &BTreeMap::new(),
        records,
        None,
        Scope::Installed,
    )
    .await
}

async fn refresh_restored(
    common: &GlobalArgs,
    restored: &[String],
    staged: &BTreeMap<String, Option<String>>,
    records: &BTreeMap<String, PatchRecord>,
    mut pin_judge: Option<PinJudge<'_>>,
    scope: Scope,
) -> RestoreRefresh {
    use socket_patch_core::patch::redirect::upstream::{
        gem_resolves_from_rubygems, gem_upstream_archive, UpstreamArchive,
    };
    use socket_patch_core::vendor::registry_fetch::SecureRegistryClient;

    let policy = Policy::of(common);
    let direction = Direction::Upstream;
    let mut shas: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut urls: BTreeMap<String, Option<String>> = BTreeMap::new();
    // The gems whose upstream sha256 the registry is not asked for, each
    // with why: their installed copies are reported, not passed over.
    let mut unverified: BTreeMap<String, String> = BTreeMap::new();
    // The records an installed copy is judged by as well: those of the
    // gems the lock resolves from rubygems.org, which are back on their
    // upstream entries. A copy holding its record's patch is stale even
    // when nothing proves the upstream sha256 (`--offline` or a registry
    // error, under a lock without `CHECKSUMS`): it is then reported, not
    // refreshed.
    let mut judged: BTreeMap<String, PatchRecord> = BTreeMap::new();
    // The gems a hosted unwind's [`PinJudge`] covers: back on their
    // upstream entries, like the ones `judged` holds a record for.
    let mut pinned: Vec<String> = Vec::new();
    for purl in restored
        .iter()
        .filter(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Gem))
    {
        match gem_upstream_archive(&common.cwd, staged, purl, common.offline).await {
            Some(UpstreamArchive::Known { sha256, url }) => {
                // A vendored revert does not prove where the lock resolves
                // the gem from: an entry vendored over hosted wiring before
                // v5 reverts to its hosted pin, whose `CHECKSUMS` sha256 is
                // the patched gem's (the hosted unwind restores that pin
                // next, and refreshes then). Only a gem the lock resolves
                // from rubygems.org is known to be back on its upstream
                // entry.
                if scope == Scope::Installed && url.is_none() {
                    continue;
                }
                shas.insert(purl.clone(), Some(sha256));
                urls.insert(purl.clone(), url);
                if let Some(record) = records.get(purl) {
                    judged.insert(purl.clone(), record.clone());
                }
                pinned.push(purl.clone());
            }
            // (Only a gem the lock resolves from rubygems.org comes back
            // unverified, so the vendored unwind's rule holds for it too.)
            Some(UpstreamArchive::Unverified(why)) => {
                unverified.insert(purl.clone(), why);
            }
            None => {
                if let Some(record) = records.get(purl) {
                    if gem_resolves_from_rubygems(&common.cwd, purl).await {
                        judged.insert(purl.clone(), record.clone());
                    }
                }
                // A wet hosted unwind wrote the restored lock, so the lock
                // on disk says where the gem resolves from.
                if pin_judge.is_some()
                    && !policy.dry_run
                    && gem_resolves_from_rubygems(&common.cwd, purl).await
                {
                    pinned.push(purl.clone());
                }
            }
        }
    }
    if shas.is_empty() && unverified.is_empty() && judged.is_empty() && pinned.is_empty() {
        return RestoreRefresh::default();
    }
    // A hosted unwind's copies with no archive to judge them by: stale
    // when they hold a pinned patch, reported when no record says (#2092).
    let (pin_stale, no_record) = match &mut pin_judge {
        Some(judge) => judge.probe(&pinned).await,
        None => Default::default(),
    };
    let mut stale = stale_after_restore(common, &shas, &judged, scope).await;
    stale.extend(pin_stale);
    let unjudged = unverified.keys().map(|purl| (purl.clone(), None)).collect();
    let unchecked =
        stale_after_restore(common, &unjudged, &BTreeMap::new(), Scope::Installed).await;
    if stale.is_empty() && unchecked.is_empty() && no_record.is_empty() {
        return RestoreRefresh::default();
    }
    let wanted = |gem: &StaleGem| {
        Some(Wanted {
            leaf: gem.leaf.clone(),
            kind: direction.wanted(),
            sha256: BTreeSet::from([shas.get(&gem.purl)?.clone()?]),
            urls: urls.get(&gem.purl)?.iter().cloned().collect(),
            on_disk: Vec::new(),
        })
    };
    // One client for the run's downloads, when there is something to
    // download.
    let registry = (!common.offline && !stale.is_empty()).then(SecureRegistryClient::new);
    let source = match &registry {
        Some(registry) => Source::Registry(registry),
        None => Source::DiskOnly,
    };
    let mut pass = attempt(&stale, wanted, &source, &policy, direction).await;
    let still = if pass.changed(&policy) {
        let mut still = stale_after_restore(common, &shas, &judged, scope).await;
        if let Some(judge) = &mut pin_judge {
            still.extend(judge.probe(&pinned).await.0);
        }
        still
    } else {
        stale
    };
    let mut installed: Vec<StaleGem> = still
        .into_iter()
        .filter(|gem| gem.installed.is_some())
        .collect();
    let refreshed_installs = pass
        .refreshed
        .iter()
        .filter(|(purl, target)| {
            matches!(target, Target::Installed(_))
                && !installed.iter().any(|gem| &gem.purl == purl)
                && !no_record.iter().any(|(gem, _)| &gem.purl == purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    for gem in unchecked {
        if let (Some((dir, _)), Some(why)) = (&gem.installed, unverified.get(&gem.purl)) {
            pass.left
                .insert(dir.clone(), Why::Unverified(why.to_string()));
            installed.push(gem);
        }
    }
    for (gem, why) in no_record {
        if let Some((dir, _)) = &gem.installed {
            pass.left.insert(dir.clone(), Why::Unverified(why));
            installed.push(gem);
        }
    }
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
                offline: true,
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
            in_place: false,
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

    /// A copy that could not be checked against the upstream gem (the
    /// registry that would say is refused) is reported with the reason and
    /// the files to remove, apart from the copies known to be stale: it is
    /// not said to hold the patched build, and it is not passed over. In a
    /// shared gem home too, where nothing was tried either way.
    #[tokio::test]
    async fn a_copy_that_could_not_be_checked_is_reported_with_the_reason() {
        const WHY: &str = "SOCKET_RUBYGEMS_URL is not used as the gem registry: \
                           `http://gemstash:9292` is not an https URL; set it to an https URL";
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("vendor/bundle/ruby/3.4.0");
        let shared = tmp.path().join("elsewhere/gemhome");
        let unchecked = [
            installed("rack", &home, true),
            installed("rexml", &shared, false),
        ];
        let stale = installed("nokogiri", &home, true);
        let policy = policy(tmp.path(), true, false, false);
        let mut pass = attempt(
            std::slice::from_ref(&stale),
            unobtainable,
            &Source::DiskOnly,
            &policy,
            Direction::Upstream,
        )
        .await;
        for gem in &unchecked {
            let (dir, _) = gem.installed.clone().unwrap();
            pass.left.insert(dir, Why::Unverified(WHY.to_string()));
        }

        // Unchecked copies alone.
        let out = report(Direction::Upstream, &unchecked, &pass, &policy);
        assert_eq!(out.warnings.len(), 2);
        for ((code, detail), gem) in out.warnings.iter().zip(&unchecked) {
            let (dir, _) = gem.installed.clone().unwrap();
            assert_eq!(*code, "upstream_gem_stale_install");
            for needle in [
                gem.purl.as_str(),
                "is back on its upstream registry entry",
                "could not be checked against the upstream gem",
                WHY,
                "If it was installed before the switch it still holds the patched build",
                "run `bundle install`",
                &dir.display().to_string(),
                &format!("{}.gemspec", gem.leaf),
            ] {
                assert!(detail.contains(needle), "missing {needle:?}: {detail}");
            }
            assert!(!detail.contains("--gem-refresh-shared"), "{detail}");
            assert!(!detail.contains("its patched install"), "{detail}");
        }
        let summary = out.summary.expect("a summary");
        assert_eq!(
            summary.headline,
            "2 gems on disk could not be checked after the switch back to the upstream registry"
        );
        assert_eq!(summary.bullets.len(), 1, "{:?}", summary.bullets);
        assert!(
            summary.bullets[0].starts_with(&format!(
                "Not checked against the upstream gem ({WHY}): rack 1.0.0, rexml 1.0.0. A copy \
                 installed before the switch still holds the patched build; to be sure, run \
                 `rm -f "
            )),
            "{}",
            summary.bullets[0]
        );

        // Beside a copy that is known to be stale.
        let all = [vec![stale], unchecked.to_vec()].concat();
        let out = report(Direction::Upstream, &all, &pass, &policy);
        assert_eq!(out.warnings.len(), 3);
        let summary = out.summary.expect("a summary");
        assert_eq!(
            summary.headline,
            "1 gem still holds the patched build on disk after the switch back to the upstream \
             registry, and 2 gems could not be checked"
        );
        assert_eq!(summary.bullets.len(), 2, "{:?}", summary.bullets);

        // A dry run switched nothing: nothing is stale or unchecked yet.
        let dry = Policy {
            dry_run: true,
            ..policy
        };
        let out = report(Direction::Upstream, &all, &pass, &dry);
        assert!(out.summary.is_none());
    }

    /// A gem with a copy known to be stale in one gem home and a copy
    /// that could not be checked in another is counted once, as stale:
    /// the headline never drops a copy known to hold the patched build.
    #[tokio::test]
    async fn a_gem_with_a_stale_copy_and_an_unchecked_one_counts_as_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let stale = installed("rack", &tmp.path().join("vendor/bundle/ruby/3.4.0"), true);
        let unchecked = installed("rack", &tmp.path().join("gems/ruby/3.4.0"), true);
        let policy = policy(tmp.path(), true, false, false);
        let mut pass = attempt(
            std::slice::from_ref(&stale),
            unobtainable,
            &Source::DiskOnly,
            &policy,
            Direction::Upstream,
        )
        .await;
        let (dir, _) = unchecked.installed.clone().unwrap();
        pass.left
            .insert(dir, Why::Unverified("no record".to_string()));

        let out = report(Direction::Upstream, &[stale, unchecked], &pass, &policy);
        assert_eq!(out.warnings.len(), 2);
        let summary = out.summary.expect("a summary");
        assert_eq!(
            summary.headline,
            "1 gem still holds the patched build on disk after the switch back to the upstream \
             registry"
        );
        assert_eq!(summary.bullets.len(), 2, "{:?}", summary.bullets);
    }

    /// #2092: [`PinJudge`] judges each installed copy with no archive in
    /// its gem home on its own files, by the record of any patch its gem
    /// was pinned to. A copy with its archive is the archive check's.
    #[tokio::test]
    async fn pin_judge_judges_an_archiveless_copy_by_any_of_its_pins() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes as git_sha;
        use socket_patch_core::manifest::schema::PatchFileInfo;

        const PURL: &str = "pkg:gem/rack@1.0.0";
        let record = |uuid: &str, after: &str| PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files: [(
                "lib/rack.rb".to_string(),
                PatchFileInfo {
                    before_hash: git_sha(b"upstream\n"),
                    after_hash: git_sha(after.as_bytes()),
                },
            )]
            .into(),
            vulnerabilities: Default::default(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        // A project whose own gem home holds `rack 1.0.0` with `lib`.
        let project = |lib: &str, archive: bool| {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("vendor/bundle/ruby/3.4.0");
            let gem = home.join("gems/rack-1.0.0");
            std::fs::create_dir_all(gem.join("lib")).unwrap();
            std::fs::write(gem.join("lib/rack.rb"), lib).unwrap();
            std::fs::create_dir_all(home.join("specifications")).unwrap();
            std::fs::write(
                home.join("specifications/rack-1.0.0.gemspec"),
                "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"1.0.0\"\nend\n",
            )
            .unwrap();
            if archive {
                std::fs::create_dir_all(home.join("cache")).unwrap();
                std::fs::write(home.join("cache/rack-1.0.0.gem"), b"archive").unwrap();
            }
            tmp
        };
        let pins = BTreeMap::from([(
            PURL.to_string(),
            vec!["uuid-a".to_string(), "uuid-b".to_string()],
        )]);
        // `--offline`: only the records seeded below are there to judge by.
        let probe = |tmp: &tempfile::TempDir, fetched: Vec<(&str, Option<PatchRecord>)>| {
            let common = GlobalArgs {
                cwd: tmp.path().to_path_buf(),
                offline: true,
                ..GlobalArgs::default()
            };
            let pins = pins.clone();
            let fetched: BTreeMap<String, Option<PatchRecord>> = fetched
                .into_iter()
                .map(|(uuid, record)| (uuid.to_string(), record))
                .collect();
            async move {
                let api = RunApiClient::new();
                let mut judge = PinJudge {
                    common: &common,
                    api: &api,
                    pins: &pins,
                    fetched,
                    unreachable: false,
                };
                let (stale, unjudged) = judge.probe(&[PURL.to_string()]).await;
                assert!(api.get().is_none(), "an offline probe builds no client");
                (stale.len(), unjudged)
            }
        };
        let (a, b) = (record("uuid-a", "patch a\n"), record("uuid-b", "patch b\n"));
        let both = || vec![("uuid-a", Some(a.clone())), ("uuid-b", Some(b.clone()))];

        // The copy holds the second pin's patch.
        let tmp = project("patch b\n", false);
        let (stale, unjudged) = probe(&tmp, both()).await;
        assert_eq!((stale, unjudged.len()), (1, 0));

        // Every record judged it, and it holds neither patch.
        let tmp = project("upstream\n", false);
        let (stale, unjudged) = probe(&tmp, both()).await;
        assert_eq!((stale, unjudged.len()), (0, 0));

        // One pin has no record, and the other's patch is not the copy's:
        // nothing says the copy is not the first pin's patched build.
        let (stale, unjudged) = probe(&tmp, vec![("uuid-b", Some(b.clone()))]).await;
        assert_eq!((stale, unjudged.len()), (0, 1));
        assert_eq!(
            unjudged[0].1,
            "its gem home has no archive of it and `--offline` is set, so its patch record \
             was not fetched"
        );

        // A record that proves the patch settles it, whatever is missing.
        let tmp = project("patch b\n", false);
        let (stale, unjudged) = probe(&tmp, vec![("uuid-b", Some(b.clone()))]).await;
        assert_eq!((stale, unjudged.len()), (1, 0));

        // A copy with its archive is judged by the archive, not here.
        let tmp = project("patch b\n", true);
        let (stale, unjudged) = probe(&tmp, both()).await;
        assert_eq!((stale, unjudged.len()), (0, 0));
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
            ..Attempt::default()
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

    /// A copy agent mode patched in place is stale by its upstream archive
    /// only (#2089), and every message says so: the dry-run note, the
    /// warning of a copy left alone, and the headline when no gem under it
    /// is actually unpatched.
    #[tokio::test]
    async fn in_place_patched_gems_are_never_called_unpatched() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        // With the archive RubyGems kept beside it.
        let in_place = |name: &str, home: &Path, project_local: bool| {
            std::fs::create_dir_all(home.join("cache")).unwrap();
            std::fs::write(home.join("cache").join(format!("{name}-1.0.0.gem")), b"up").unwrap();
            StaleGem {
                in_place: true,
                ..installed(name, home, project_local)
            }
        };
        let local = in_place("rack", &proj.join("vendor/bundle/ruby/3.4.0"), true);
        let shared_home = tmp.path().join("gemhome");
        let shared = in_place("rexml", &shared_home, false);
        let gems = vec![local.clone(), shared.clone()];

        // A dry run plans the project's own copy.
        let dry = policy(&proj, true, false, true);
        let out = report(Direction::Patched, &[], &pass(&gems, &dry).await, &dry);
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert!(
            out.warnings[0]
                .1
                .contains("would replace the upstream archive of the install patched in place at"),
            "{}",
            out.warnings[0].1
        );
        assert_eq!(
            out.progress,
            [
                "Would replace the upstream archive beside 1 gem patched in place with the \
              patched gem: rack 1.0.0."
            ]
        );

        // Refresh off: both are left, each with its own remedy.
        let off = policy(&proj, false, false, false);
        let out = report(Direction::Patched, &gems, &pass(&gems, &off).await, &off);
        let summary = out.summary.expect("a summary");
        assert_eq!(
            summary.headline,
            "2 gems patched in place still have their upstream archives on disk after the \
             switch to hosted patches"
        );
        assert_eq!(out.warnings.len(), 2);
        for (_, detail) in &out.warnings {
            assert!(
                detail.contains("patched in place")
                    && detail.contains("upstream archive at")
                    && detail.contains("`bundle pristine`")
                    && !detail.contains("unpatched install"),
                "{detail}"
            );
        }
        let of = |gem: &StaleGem| {
            let needle = gem.purl.as_str();
            out.warnings
                .iter()
                .find(|(_, detail)| detail.starts_with(needle))
                .map(|(_, detail)| detail.clone())
                .unwrap()
        };
        let cache = home_cache_archive(&local.installed.as_ref().unwrap().0).unwrap();
        assert!(
            of(&local).contains("`--no-gem-install-refresh` is set")
                && of(&local).contains(&format!("emove {} and run", cache.display()))
                && !of(&local).contains("specifications")
                && of(&local).ends_with("and run `bundle install`"),
            "{}",
            of(&local)
        );
        assert!(
            of(&shared).contains("`--gem-refresh-shared`")
                && of(&shared).contains(LOCAL_PATH_REMEDY)
                && !of(&shared).to_lowercase().contains("remove "),
            "a shared home never gets a delete list: {}",
            of(&shared)
        );

        let shared_why = summary
            .bullets
            .iter()
            .find(|b| b.contains("--gem-refresh-shared"))
            .expect("the shared-home remedy");
        assert!(
            shared_why.starts_with("`bundle pristine` and `bundle install --redownload` reinstall")
                && !shared_why.contains("reuses an installed gem"),
            "{shared_why}"
        );

        // Beside a gem that is unpatched, the headline covers both.
        let mixed = vec![local, installed("puma", &shared_home, false)];
        let out = report(Direction::Patched, &mixed, &pass(&mixed, &off).await, &off);
        assert_eq!(
            out.summary.expect("a summary").headline,
            "2 gems still have unpatched files or archives on disk after the switch to hosted \
             patches"
        );
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

        // An unwind names no re-run: nothing is left for one to unwind.
        let out = report(Direction::Upstream, &gems, &tried, &policy_off);
        assert!(
            out.warnings[1]
                .1
                .contains("`--no-gem-install-refresh` is set")
                && !out.warnings[1].1.contains("Re-run")
                && out.warnings[1].1.contains("and run `bundle install`"),
            "{}",
            out.warnings[1].1
        );
        let summary = out.summary.expect("stale gems").paragraph();
        assert!(
            !summary.contains("Re-run without") && summary.contains("Run `rm -f "),
            "{summary}"
        );
    }
}
