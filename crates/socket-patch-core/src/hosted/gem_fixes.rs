//! Which patches a run selects for a gem the Bundler lock names as
//! platform builds.
//!
//! A native gem such as nokogiri is published as one gem per platform, and
//! a fix for it is published as one patch per platform gem: each patch has
//! its own uuid and its own record, keyed by the gem's package URL with a
//! `platform` qualifier (`pkg:gem/nokogiri@1.19.3?platform=arm64-darwin`;
//! the ruby-platform gem's is `?platform=ruby`). The patches of one fix
//! are one family: every patch but the source states the uuid of the
//! patch it was built from (`rebuiltFromUuid` of its package reference),
//! and the patch registry of any member lists and serves every member.
//!
//! The lock says which of those gems a project uses:
//! `nokogiri (1.19.3-arm64-darwin)`, `nokogiri (1.19.3-x86_64-linux-gnu)`,
//! and the plain `nokogiri (1.19.3)` when it also names the ruby gem.
//! Bundler takes one source per gem, so a run that changes what Bundler
//! installs (hosted and vendored mode) needs ONE fix with a patch for
//! every build the lock names. The per-package selection ranks the patches
//! of each package URL on their own, and two fixes that tie can come out
//! one ahead for one platform and the other for another (their builds are
//! published at different times). So, between the selection and its
//! classification, [`GemLock`]:
//!
//! 1. drops the patches of platform gems the lock does not name
//!    ([`GemLock::narrow`]). Nothing in the project is theirs to patch.
//!    The ruby gem's patch always stays: it is the fix's source, whose
//!    registry a lock of platform builds takes as the gem's source;
//! 2. names the patches whose family it must know
//!    ([`GemLock::reference_uuids`]), for the caller to ask the patch API
//!    about: every patch on offer for a build the lock names;
//! 3. takes one fix for every build ([`GemLock::choose`]): among the
//!    fixes with a usable patch for every locked build, the one the
//!    project is already on, unless the fix the ruby-platform selection
//!    rules rank first supersedes it; else that first-ranked fix. The
//!    builds' rows are then classified together: all already in place, or
//!    all an upgrade.
//!
//! When no fix covers every locked build the selection is left as it is,
//! and the mode's own writer leaves the gem alone and says which builds
//! are missing or belong to another fix.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::api::ranking::search_result_supersedes;
use crate::api::types::{PackageVendorResult, PatchSearchResult};
use crate::policy::Offers;
use crate::rollout::stage::RecordedIndex;
use crate::rollout::Recorded;
use crate::utils::purl::{purl_parts, purl_qualifier};
use crate::vendor::lock_inventory::ProjectView;

/// The builds of one gem version a Bundler lock names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LockedGem {
    /// The plain `name (version)` entry: the ruby-platform gem.
    ruby: bool,
    /// The platform of each `name (version-<platform>)` entry.
    platforms: Vec<String>,
}

impl LockedGem {
    /// Whether the lock names the gem of `platform` (`None`: the ruby gem).
    fn names(&self, platform: Option<&str>) -> bool {
        match platform {
            Some(platform) => self.platforms.iter().any(|p| p == platform),
            None => self.ruby,
        }
    }
}

/// What the Bundler lock a project loads names of each gem version a run
/// has patches on offer for (module docs).
#[derive(Debug, Clone, Default)]
pub struct GemLock {
    /// By `(name, version)`. A gem version the lock does not name at all
    /// has no entry.
    gems: HashMap<(String, String), LockedGem>,
}

/// The patch purls of the builds of one gem version: `(platform, purl)`,
/// the ruby-platform gem's with `None`.
type BuildPurls<'o> = Vec<(Option<String>, &'o str)>;

/// The gem a patch purl is a patch of: its name, its version, and its
/// platform (`None` for the ruby-platform gem, which a purl names with
/// `?platform=ruby` or with no qualifier). `None` for another ecosystem's
/// purl.
fn gem_of(purl: &str) -> Option<((String, String), Option<String>)> {
    let (ecosystem, name, version) = purl_parts(purl)?;
    if ecosystem != "gem" {
        return None;
    }
    let platform = purl_qualifier(purl, "platform")
        .filter(|platform| !platform.is_empty() && !platform.eq_ignore_ascii_case("ruby"))
        .map(str::to_string);
    Some(((name, version), platform))
}

/// The fix a patch belongs to, as its package reference says: the uuid of
/// the patch it was built from, or its own.
fn family_of<'a>(uuid: &'a str, references: &'a HashMap<String, PackageVendorResult>) -> &'a str {
    references
        .get(uuid)
        .and_then(|reference| reference.rebuilt_from_uuid.as_deref())
        .filter(|source| !source.is_empty())
        .unwrap_or(uuid)
}

/// Whether the run can use the patch `uuid`: its reference is granted.
fn usable(uuid: &str, references: &HashMap<String, PackageVendorResult>) -> bool {
    references
        .get(uuid)
        .is_some_and(|reference| matches!(reference.status.as_str(), "granted" | "reused"))
}

impl GemLock {
    /// Read the lock `view`'s project loads for the gems among `purls`
    /// (the package URLs a run has patches on offer for). Empty when
    /// Bundler loads no lock there, or none of `purls` is a gem's.
    pub async fn read<'p>(view: &ProjectView<'_>, purls: impl Iterator<Item = &'p str>) -> Self {
        let mut gems: Vec<(String, String)> =
            purls.filter_map(gem_of).map(|(gem, _)| gem).collect();
        gems.sort();
        gems.dedup();
        if gems.is_empty() {
            return GemLock::default();
        }
        let asked: Vec<String> = gems
            .iter()
            .map(|(name, version)| crate::utils::purl::build_gem_purl(name, version))
            .collect();
        // Every source section: a gem vendored as platform gems holds its
        // platform entries in a `PATH` section, and they are still the
        // builds this project installs.
        let named = crate::vendor::lock_inventory::gem_resolved_builds_in(view, &asked).await;
        let gems = gems
            .into_iter()
            .zip(named)
            .filter(|(_, builds)| !builds.is_empty())
            .map(|(gem, builds)| {
                let locked = LockedGem {
                    ruby: builds.iter().any(|build| build.platform.is_none()),
                    platforms: builds.into_iter().filter_map(|b| b.platform).collect(),
                };
                (gem, locked)
            })
            .collect();
        GemLock { gems }
    }

    /// Whether the lock names no gem a run has patches for: nothing to do.
    pub fn is_empty(&self) -> bool {
        self.gems.is_empty()
    }

    /// Whether the lock names a build of the gem version `purl` is a patch
    /// purl of: which of its patches a run selects is then the lock's to
    /// say, not an installed copy's.
    pub fn names_gem(&self, purl: &str) -> bool {
        gem_of(purl).is_some_and(|(gem, _)| self.gems.contains_key(&gem))
    }

    /// The platforms the lock names of the gem version `purl` is a patch
    /// purl of, in lock order: empty when it names none (the gem is locked
    /// as its ruby-platform gem alone, or not at all).
    pub fn platforms_of(&self, purl: &str) -> &[String] {
        gem_of(purl)
            .and_then(|(gem, _)| self.gems.get(&gem))
            .map_or(&[], |locked| locked.platforms.as_slice())
    }

    /// The platform gem `purl` is a patch purl of: `None` for the
    /// ruby-platform gem's (and for another ecosystem's purl).
    pub fn platform_of(purl: &str) -> Option<String> {
        gem_of(purl).and_then(|(_, platform)| platform)
    }

    /// Whether the patch purl `purl` is a patch of a platform gem the lock
    /// does not name, of a gem version it does name another build of.
    fn unlocked(&self, purl: &str) -> bool {
        let Some((gem, Some(platform))) = gem_of(purl) else {
            return false;
        };
        self.gems
            .get(&gem)
            .is_some_and(|locked| !locked.names(Some(&platform)))
    }

    /// Drop from `offers` the patches of platform gems the lock does not
    /// name (module docs, step 1).
    pub fn narrow(&self, offers: &mut Offers) {
        if self.is_empty() {
            return;
        }
        offers.selected.retain(|purl, _| !self.unlocked(purl));
        offers.unfiltered.retain(|purl, _| !self.unlocked(purl));
        offers.withheld.retain(|(purl, _)| !self.unlocked(purl));
    }

    /// [`Self::narrow`] for a selection that is a list of patches.
    pub fn narrow_selected(&self, selected: Vec<PatchSearchResult>) -> Vec<PatchSearchResult> {
        if self.is_empty() {
            return selected;
        }
        let mut selected = selected;
        selected.retain(|patch| !self.unlocked(&patch.purl));
        selected
    }

    /// The offers a run may take for each patch purl of `offers`: all but
    /// the ones a selection filter withholds, best first.
    fn admitted<'o>(offers: &'o Offers, purl: &str) -> Vec<&'o PatchSearchResult> {
        offers
            .unfiltered
            .get(purl)
            .into_iter()
            .flatten()
            .filter(|offer| {
                !offers
                    .withheld
                    .contains(&(purl.to_string(), offer.uuid.clone()))
            })
            .collect()
    }

    /// The gems of `offers` the lock names as platform builds, each with
    /// the patch purls of the builds it names: `(platform, purl)`, the
    /// ruby-platform gem's (`None`) included whether the lock names it or
    /// not. Sorted by gem, then purl.
    fn platform_locked<'o>(
        &self,
        offers: &'o Offers,
    ) -> BTreeMap<(String, String), BuildPurls<'o>> {
        let mut gems: BTreeMap<(String, String), BuildPurls<'o>> = BTreeMap::new();
        for purl in offers.unfiltered.keys() {
            let Some((gem, platform)) = gem_of(purl) else {
                continue;
            };
            let Some(locked) = self.gems.get(&gem).filter(|l| !l.platforms.is_empty()) else {
                continue;
            };
            if platform.is_none() || locked.names(platform.as_deref()) {
                gems.entry(gem).or_default().push((platform, purl.as_str()));
            }
        }
        gems
    }

    /// The uuids whose package references [`Self::choose`] reads (module
    /// docs, step 2): every patch a run may take for a build the lock
    /// names, of each gem it names as platform builds. Sorted. Empty for a
    /// project with no such gem, which then costs no request.
    pub fn reference_uuids(&self, offers: &Offers) -> Vec<String> {
        let mut uuids: Vec<String> = Vec::new();
        for (gem, purls) in self.platform_locked(offers) {
            let locked = &self.gems[&gem];
            for (platform, purl) in purls {
                if !locked.names(platform.as_deref()) {
                    continue;
                }
                uuids.extend(Self::admitted(offers, purl).iter().map(|o| o.uuid.clone()));
            }
        }
        uuids.sort();
        uuids.dedup();
        uuids
    }

    /// Take one fix for every build of each gem the lock names as platform
    /// builds (module docs, step 3), by the package `references` of
    /// [`Self::reference_uuids`]: `offers.selected` then holds that fix's
    /// patch for each locked build (and its source patch for the ruby gem
    /// when that one is on offer). Returns how the row of each locked
    /// build is classified, by patch purl, for a gem the project already
    /// has a fix recorded for (`recorded`): [`Recorded::Same`] when the
    /// chosen fix is that one, else an upgrade from it. A gem with nothing
    /// recorded, or with no fix that covers every locked build, has no
    /// entry and is classified purl by purl as any package is.
    pub fn choose(
        &self,
        offers: &mut Offers,
        references: &HashMap<String, PackageVendorResult>,
        recorded: &RecordedIndex,
    ) -> HashMap<String, Recorded> {
        let mut classes: HashMap<String, Recorded> = HashMap::new();
        let mut chosen: Vec<(String, PatchSearchResult)> = Vec::new();
        for (gem, purls) in self.platform_locked(offers) {
            let locked = &self.gems[&gem];
            // The usable patches of each locked build, best first, with
            // the fix each belongs to.
            let builds: Vec<(&str, Vec<(&PatchSearchResult, &str)>)> = purls
                .iter()
                .filter(|(platform, _)| locked.names(platform.as_deref()))
                .map(|(_, purl)| {
                    let patches = Self::admitted(offers, purl)
                        .into_iter()
                        .filter(|offer| usable(&offer.uuid, references))
                        .map(|offer| (offer, family_of(&offer.uuid, references)))
                        .collect();
                    (*purl, patches)
                })
                .collect();
            // Every locked build must have a patch purl on offer at all.
            let named = usize::from(locked.ruby) + locked.platforms.len();
            let covered: HashSet<Option<&str>> = purls
                .iter()
                .filter(|(platform, _)| locked.names(platform.as_deref()))
                .map(|(platform, _)| platform.as_deref())
                .collect();
            if covered.len() < named {
                continue;
            }
            // The fixes with a patch for every locked build, in the order
            // they come.
            let mut complete: Vec<&str> = Vec::new();
            for (_, family) in builds.iter().flat_map(|(_, patches)| patches) {
                let everywhere = builds
                    .iter()
                    .all(|(_, patches)| patches.iter().any(|(_, f)| f == family));
                if everywhere && !complete.contains(family) {
                    complete.push(family);
                }
            }
            if complete.is_empty() {
                continue;
            }
            // The ruby gem's patches, best first: a fix is named by its
            // source patch, which is one of them.
            let ruby: Vec<&PatchSearchResult> = purls
                .iter()
                .filter(|(platform, _)| platform.is_none())
                .flat_map(|(_, purl)| Self::admitted(offers, purl))
                .collect();
            let first_ranked = ruby
                .iter()
                .map(|offer| family_of(&offer.uuid, references))
                .find(|family| complete.contains(family));
            // The fix the project is on: one whose source, or whose patch
            // of a locked build, some ledger or lockfile pin records.
            let base = crate::utils::purl::build_gem_purl(&gem.0, &gem.1);
            let pinned = recorded.uuids(&base);
            let on = complete.iter().copied().find(|family| {
                pinned.iter().any(|uuid| uuid == family)
                    || builds.iter().any(|(_, patches)| {
                        patches
                            .iter()
                            .any(|(offer, f)| f == family && pinned.contains(&offer.uuid))
                    })
            });
            // How one fix's patches compare with another's: by their
            // source patches where both are on offer, else by their
            // patches of the first locked build.
            let patch_of = |family: &str| -> Option<&PatchSearchResult> {
                ruby.iter()
                    .copied()
                    .find(|offer| offer.uuid == family)
                    .or_else(|| {
                        let (_, patches) = builds.first()?;
                        let member = patches.iter().find(|(_, f)| *f == family)?;
                        Some(member.0)
                    })
            };
            let supersedes = |newer: &str, older: &str| match (patch_of(newer), patch_of(older)) {
                (Some(newer), Some(older)) => search_result_supersedes(newer, older),
                _ => false,
            };
            let fix = match (on, first_ranked) {
                (Some(on), Some(first)) if on != first && supersedes(first, on) => first,
                (Some(on), _) => on,
                (None, Some(first)) => first,
                (None, None) => complete[0],
            };
            for (purl, patches) in &builds {
                let Some((member, _)) = patches.iter().find(|(_, family)| *family == fix) else {
                    continue;
                };
                chosen.push((purl.to_string(), (*member).clone()));
                let class = match on {
                    Some(on) if on == fix => Recorded::Same,
                    Some(on) => Recorded::Superseded {
                        old_uuid: patches
                            .iter()
                            .find(|(_, family)| *family == on)
                            .map_or_else(|| on.to_string(), |(offer, _)| offer.uuid.clone()),
                    },
                    None => continue,
                };
                classes.insert(purl.to_string(), class);
            }
            // The fix's source patch, for a lock that does not name the
            // ruby gem: its registry is the gem's source.
            if !locked.ruby {
                for (_, purl) in purls.iter().filter(|(platform, _)| platform.is_none()) {
                    if let Some(source) = Self::admitted(offers, purl)
                        .into_iter()
                        .find(|offer| offer.uuid == fix)
                    {
                        chosen.push((purl.to_string(), source.clone()));
                    }
                }
            }
        }
        offers.selected.extend(chosen);
        classes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::VulnerabilityResponse;
    use crate::rollout::stage::offers_from_results;
    use crate::vendor::lock_inventory::MemoryProject;

    const SRC_A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
    const A_LINUX: &str = "aaaaaaaa-0000-4000-8000-000000000002";
    const A_DARWIN: &str = "aaaaaaaa-0000-4000-8000-000000000003";
    const SRC_B: &str = "bbbbbbbb-0000-4000-8000-000000000001";
    const B_LINUX: &str = "bbbbbbbb-0000-4000-8000-000000000002";
    const B_DARWIN: &str = "bbbbbbbb-0000-4000-8000-000000000003";
    const JAVA: &str = "cccccccc-0000-4000-8000-000000000001";

    const RUBY: &str = "pkg:gem/nokogiri@1.19.3?platform=ruby";
    const LINUX: &str = "pkg:gem/nokogiri@1.19.3?platform=x86_64-linux-gnu";
    const DARWIN: &str = "pkg:gem/nokogiri@1.19.3?platform=arm64-darwin";

    fn patch(uuid: &str, purl: &str, published: &str, advisories: &[&str]) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.to_string(),
            purl: purl.to_string(),
            published_at: published.to_string(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
            vulnerabilities: advisories
                .iter()
                .map(|id| {
                    (
                        id.to_string(),
                        VulnerabilityResponse {
                            cves: Vec::new(),
                            summary: String::new(),
                            severity: "high".to_string(),
                            description: String::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn reference(status: &str, source: Option<&str>) -> PackageVendorResult {
        serde_json::from_value(serde_json::json!({
            "status": status,
            "rebuiltFromUuid": source,
        }))
        .unwrap()
    }

    fn granted(pairs: &[(&str, Option<&str>)]) -> HashMap<String, PackageVendorResult> {
        pairs
            .iter()
            .map(|(uuid, source)| (uuid.to_string(), reference("granted", *source)))
            .collect()
    }

    async fn lock_of(specs: &[&str], offers: &Offers) -> GemLock {
        let mut project = MemoryProject::new();
        project.insert_text(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"nokogiri\"\n",
        );
        let specs: String = specs.iter().map(|s| format!("    {s}\n")).collect();
        project.insert_text(
            "Gemfile.lock",
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n{specs}\nPLATFORMS\n  ruby\n\n\
                 DEPENDENCIES\n  nokogiri\n\nBUNDLED WITH\n   2.5.23\n"
            ),
        );
        GemLock::read(
            &ProjectView::Memory(&project),
            offers.unfiltered.keys().map(String::as_str),
        )
        .await
    }

    const PLATFORM_ONLY: [&str; 2] = [
        "nokogiri (1.19.3-arm64-darwin)",
        "nokogiri (1.19.3-x86_64-linux-gnu)",
    ];

    /// The patches of platform gems the lock does not name leave the
    /// selection; the ruby gem's patch stays, also for a lock of platform
    /// builds alone. A gem version the lock does not name keeps them all.
    #[tokio::test]
    async fn the_selection_is_narrowed_to_the_builds_the_lock_names() {
        let java = "pkg:gem/nokogiri@1.19.3?platform=java";
        let other = "pkg:gem/ffi@1.17.0?platform=java";
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(A_LINUX, LINUX, "2026-01-02T00:00:00Z", &["GHSA-a"]),
                patch(JAVA, java, "2026-01-02T00:00:00Z", &["GHSA-a"]),
                patch(JAVA, other, "2026-01-02T00:00:00Z", &["GHSA-a"]),
            ],
            true,
        );
        let lock = lock_of(&PLATFORM_ONLY, &offers).await;
        lock.narrow(&mut offers);
        let kept: Vec<&str> = offers.selected.keys().map(String::as_str).collect();
        assert_eq!(kept, [other, RUBY, LINUX]);
        assert!(!offers.unfiltered.contains_key(java));

        // A lock of the ruby gem alone: only its patch stays.
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(A_LINUX, LINUX, "2026-01-02T00:00:00Z", &["GHSA-a"]),
            ],
            true,
        );
        let lock = lock_of(&["nokogiri (1.19.3)"], &offers).await;
        assert!(lock.reference_uuids(&offers).is_empty(), "no request");
        lock.narrow(&mut offers);
        let kept: Vec<&str> = offers.selected.keys().map(String::as_str).collect();
        assert_eq!(kept, [RUBY]);
        let narrowed = lock.narrow_selected(vec![
            patch(SRC_A, RUBY, "", &[]),
            patch(A_LINUX, LINUX, "", &[]),
        ]);
        assert_eq!(narrowed.len(), 1);
    }

    /// Two fixes that tie on severity and advisory count are ranked by
    /// publication date, patch purl by patch purl, so the newest build of
    /// one platform can be of another fix than the newest of the next. The
    /// fix the ruby-platform selection ranks first is taken for every
    /// build when it has a patch for each.
    #[tokio::test]
    async fn a_tie_between_two_fixes_goes_to_the_one_ranked_first_for_the_ruby_gem() {
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(SRC_B, RUBY, "2026-02-01T00:00:00Z", &["GHSA-b"]),
                // A's linux build was published after B's.
                patch(A_LINUX, LINUX, "2026-03-02T00:00:00Z", &["GHSA-a"]),
                patch(B_LINUX, LINUX, "2026-03-01T00:00:00Z", &["GHSA-b"]),
                patch(A_DARWIN, DARWIN, "2026-03-01T00:00:00Z", &["GHSA-a"]),
                patch(B_DARWIN, DARWIN, "2026-03-02T00:00:00Z", &["GHSA-b"]),
            ],
            true,
        );
        assert_eq!(offers.selected[LINUX].uuid, A_LINUX);
        assert_eq!(offers.selected[DARWIN].uuid, B_DARWIN);
        let lock = lock_of(&PLATFORM_ONLY, &offers).await;
        lock.narrow(&mut offers);
        assert_eq!(
            lock.reference_uuids(&offers),
            [A_LINUX, A_DARWIN, B_LINUX, B_DARWIN],
            "the ruby gem is not locked: its patches' references are not needed"
        );
        let references = granted(&[
            (A_LINUX, Some(SRC_A)),
            (A_DARWIN, Some(SRC_A)),
            (B_LINUX, Some(SRC_B)),
            (B_DARWIN, Some(SRC_B)),
        ]);
        let classes = lock.choose(&mut offers, &references, &RecordedIndex::default());
        assert!(classes.is_empty(), "nothing recorded: the rows are new");
        assert_eq!(offers.selected[RUBY].uuid, SRC_B);
        assert_eq!(offers.selected[LINUX].uuid, B_LINUX);
        assert_eq!(offers.selected[DARWIN].uuid, B_DARWIN);
    }

    /// A newer fix that has no patch for one locked build yet is not
    /// taken: the fix that covers every build is, and the ruby gem's own
    /// selection (not a locked build here) stays the newer one.
    #[tokio::test]
    async fn a_fix_without_a_patch_for_every_locked_build_is_passed_over() {
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(SRC_B, RUBY, "2026-02-01T00:00:00Z", &["GHSA-a", "GHSA-b"]),
                patch(A_LINUX, LINUX, "2026-01-02T00:00:00Z", &["GHSA-a"]),
                patch(
                    B_LINUX,
                    LINUX,
                    "2026-02-02T00:00:00Z",
                    &["GHSA-a", "GHSA-b"],
                ),
                patch(A_DARWIN, DARWIN, "2026-01-02T00:00:00Z", &["GHSA-a"]),
            ],
            true,
        );
        let lock = lock_of(&PLATFORM_ONLY, &offers).await;
        let references = granted(&[
            (A_LINUX, Some(SRC_A)),
            (A_DARWIN, Some(SRC_A)),
            (B_LINUX, Some(SRC_B)),
        ]);
        lock.choose(&mut offers, &references, &RecordedIndex::default());
        assert_eq!(offers.selected[LINUX].uuid, A_LINUX);
        assert_eq!(offers.selected[DARWIN].uuid, A_DARWIN);
        assert_eq!(offers.selected[RUBY].uuid, SRC_A, "the chosen fix's source");

        // With no fix for every build, the selection is left as it was.
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(B_LINUX, LINUX, "2026-02-02T00:00:00Z", &["GHSA-b"]),
                patch(A_DARWIN, DARWIN, "2026-01-02T00:00:00Z", &["GHSA-a"]),
            ],
            true,
        );
        let references = granted(&[(B_LINUX, Some(SRC_B)), (A_DARWIN, Some(SRC_A))]);
        let before = offers.selected.clone();
        assert!(lock
            .choose(&mut offers, &references, &RecordedIndex::default())
            .is_empty());
        assert_eq!(
            offers.selected.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>()
        );
        assert_eq!(offers.selected[LINUX].uuid, B_LINUX);
    }

    /// A patch whose reference is not granted (still building, withdrawn)
    /// covers no build.
    #[tokio::test]
    async fn a_patch_the_run_cannot_use_covers_no_build() {
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(A_LINUX, LINUX, "2026-01-02T00:00:00Z", &["GHSA-a"]),
                patch(A_DARWIN, DARWIN, "2026-01-02T00:00:00Z", &["GHSA-a"]),
            ],
            true,
        );
        let lock = lock_of(&PLATFORM_ONLY, &offers).await;
        for status in ["pending_build", "withdrawn", "forbidden"] {
            let mut references = granted(&[(A_LINUX, Some(SRC_A))]);
            references.insert(A_DARWIN.to_string(), reference(status, Some(SRC_A)));
            let mut again = offers.clone();
            assert!(lock
                .choose(&mut again, &references, &RecordedIndex::default())
                .is_empty());
            let uuids = |offers: &Offers| -> Vec<String> {
                offers.selected.values().map(|p| p.uuid.clone()).collect()
            };
            assert_eq!(uuids(&again), uuids(&offers), "{status}");
        }
        // And one the response left out.
        let references = granted(&[(A_LINUX, Some(SRC_A))]);
        lock.choose(&mut offers, &references, &RecordedIndex::default());
        assert_eq!(offers.selected[RUBY].uuid, SRC_A);
    }

    /// The project's lock names the registry of one patch for the gem (the
    /// fix's source). A re-scan keeps every build on that fix while no fix
    /// supersedes it, and moves every build together when one does.
    #[tokio::test]
    async fn the_builds_of_a_gem_already_on_a_fix_are_classified_together() {
        let results = [
            patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
            patch(A_LINUX, LINUX, "2026-01-05T00:00:00Z", &["GHSA-a"]),
            patch(A_DARWIN, DARWIN, "2026-01-05T00:00:00Z", &["GHSA-a"]),
        ];
        let references = granted(&[
            (A_LINUX, Some(SRC_A)),
            (A_DARWIN, Some(SRC_A)),
            (B_LINUX, Some(SRC_B)),
            (B_DARWIN, Some(SRC_B)),
        ]);
        let pins = [("pkg:gem/nokogiri@1.19.3".to_string(), SRC_A.to_string())];
        let recorded = RecordedIndex::new(None, &pins);

        let mut offers = offers_from_results(&results, true);
        let lock = lock_of(&PLATFORM_ONLY, &offers).await;
        let classes = lock.choose(&mut offers, &references, &recorded);
        assert_eq!(classes.len(), 2);
        assert!(classes.values().all(|class| *class == Recorded::Same));

        // A second fix, as severe, with as many advisories, and older.
        let mut with_b = results.to_vec();
        with_b.extend([
            patch(SRC_B, RUBY, "2025-12-01T00:00:00Z", &["GHSA-b"]),
            patch(B_LINUX, LINUX, "2026-01-09T00:00:00Z", &["GHSA-b"]),
            patch(B_DARWIN, DARWIN, "2026-01-09T00:00:00Z", &["GHSA-b"]),
        ]);
        let mut offers = offers_from_results(&with_b, true);
        assert_eq!(offers.selected[LINUX].uuid, B_LINUX, "the newer build");
        let classes = lock.choose(&mut offers, &references, &recorded);
        assert!(classes.values().all(|class| *class == Recorded::Same));
        assert_eq!(offers.selected[LINUX].uuid, A_LINUX);
        assert_eq!(offers.selected[DARWIN].uuid, A_DARWIN);

        // A fix that fixes more supersedes it for every build at once.
        let mut with_more = results.to_vec();
        with_more.extend([
            patch(SRC_B, RUBY, "2026-02-01T00:00:00Z", &["GHSA-a", "GHSA-b"]),
            patch(
                B_LINUX,
                LINUX,
                "2026-02-02T00:00:00Z",
                &["GHSA-a", "GHSA-b"],
            ),
            patch(
                B_DARWIN,
                DARWIN,
                "2026-02-02T00:00:00Z",
                &["GHSA-a", "GHSA-b"],
            ),
        ]);
        let mut offers = offers_from_results(&with_more, true);
        let classes = lock.choose(&mut offers, &references, &recorded);
        assert_eq!(
            classes[LINUX],
            Recorded::Superseded {
                old_uuid: A_LINUX.to_string()
            }
        );
        assert_eq!(
            classes[DARWIN],
            Recorded::Superseded {
                old_uuid: A_DARWIN.to_string()
            }
        );
        assert_eq!(offers.selected[LINUX].uuid, B_LINUX);
        assert_eq!(offers.selected[RUBY].uuid, SRC_B);
    }

    /// A lock that names the ruby gem beside the platform builds needs the
    /// fix's source patch too, and asks about the ruby gem's patches.
    #[tokio::test]
    async fn a_lock_with_the_ruby_gem_takes_the_source_patch_as_its_build() {
        let mut offers = offers_from_results(
            &[
                patch(SRC_A, RUBY, "2026-01-01T00:00:00Z", &["GHSA-a"]),
                patch(SRC_B, RUBY, "2026-02-01T00:00:00Z", &["GHSA-b"]),
                patch(A_LINUX, LINUX, "2026-01-02T00:00:00Z", &["GHSA-a"]),
            ],
            true,
        );
        let lock = lock_of(
            &["nokogiri (1.19.3)", "nokogiri (1.19.3-x86_64-linux-gnu)"],
            &offers,
        )
        .await;
        assert_eq!(lock.reference_uuids(&offers), [SRC_A, A_LINUX, SRC_B]);
        let references = granted(&[(SRC_A, None), (SRC_B, None), (A_LINUX, Some(SRC_A))]);
        assert_eq!(offers.selected[RUBY].uuid, SRC_B, "the newer ruby patch");
        lock.choose(&mut offers, &references, &RecordedIndex::default());
        assert_eq!(offers.selected[RUBY].uuid, SRC_A);
        assert_eq!(offers.selected[LINUX].uuid, A_LINUX);
    }
}
