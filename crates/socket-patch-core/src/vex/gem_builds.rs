//! Which builds a Bundler lock pins of a gem it takes from a patch
//! registry as platform builds.
//!
//! The registry of a gem's patch lists every gem of the gem's version: the
//! patched ruby gem, a patched build for some platforms, and upstream's own
//! gem for the others (`registryOverride.identifiers.gemBuilds`). A lock
//! that names platform builds takes all of them from that registry, under
//! one `GEM` section, so its wiring says only that the gem is on the
//! registry. Which locked build is a patched one is decided per build, by
//! the one thing a patched gem and upstream's gem never share: the sha256
//! of the archive ([`gem_build_states`]).
//!
//! What a lock installs for a build is the sha256 its `CHECKSUMS` section
//! pins. A lock without that entry installs whatever its own registry
//! serves, which that registry's compact-index document says
//! ([`gem_index_url`]). The list a patch's reference carries is of the
//! registry as it stands when the reference is made, which can be later
//! than the registry the lock names: a build is a patched one only when
//! the archive the lock installs is the one the list names for it.

use crate::formats::gem;
use crate::patch::redirect::upstream::compact_index_checksum;
use crate::patch::redirect::GemPlatformChecksum;

/// One build a Bundler lock names of a gem version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedGemPin {
    /// The build's platform as the lock spells it; `None` for the
    /// ruby-platform gem.
    pub platform: Option<String>,
    /// The sha256 the lock's `CHECKSUMS` section pins for the build;
    /// `None` where the lock has no valid entry for it.
    pub sha256: Option<String>,
}

/// The builds the Bundler lock text `lock` names of the gem `name` at
/// `version`, the ruby-platform gem first, each with its `CHECKSUMS` pin.
/// Without a platform build among them the gem is locked as its
/// ruby-platform gem alone, or not at all.
pub fn locked_gem_pins(lock: &str, name: &str, version: &str) -> Vec<LockedGemPin> {
    let lock = crate::utils::line_endings::to_lf(lock);
    let parsed = gem::parse(&lock);
    let ids = parsed.locked_builds(name, version).ids(name, version);
    ids.iter()
        .map(|id| LockedGemPin {
            platform: id.platform.clone(),
            sha256: parsed.checksum(name, &id.token()).map(str::to_string),
        })
        .collect()
}

/// The compact-index document in which the registry at `remote` (a lock's
/// `remote:`) lists the gems of `name` it serves: the one the hosted scan
/// reads ([`crate::patch::redirect::gem_index_info_url`]), under the same
/// rules for what is a registry URL and a gem name.
pub use crate::patch::redirect::gem_index_info_url as gem_index_url;

/// What a lock installs for one build of a gem on a patch registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GemBuildState {
    /// The patched build of the patch `uuid`: the gem's own patch for the
    /// ruby-platform gem, the platform's for a platform gem.
    Patched { uuid: String },
    /// Upstream's own gem, which the registry lists and hands on for a
    /// platform with no patched build.
    Upstream,
    /// Neither is shown.
    Unknown(GemBuildUnknown),
}

/// Why a locked build is neither shown patched nor shown upstream's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GemBuildUnknown {
    /// Nothing names the archive the lock installs: no `CHECKSUMS` entry,
    /// and no line in the index of the lock's registry.
    Unpinned,
    /// The list does not name the build's platform.
    Unlisted,
    /// The lock installs another archive than the list names: the list is
    /// of a later state of the registry than the one the lock names.
    Differs,
}

/// What a lock installs for each of `pins`, the builds it names of a gem
/// at `version` on the registry of the patch `gem_uuid`.
///
/// `listed` is what that patch's reference lists
/// ([`RegistryOverrideIdentifiers::gem_builds`]); `index` is the
/// compact-index document of the registry the lock names
/// ([`gem_index_url`]), read for a build the lock's `CHECKSUMS` does not
/// pin, and `None` where it was not read.
///
/// A platform build is a patched one only when the sha256 the lock
/// installs for it is the one the list gives beside a patch, and
/// upstream's only when it is the one the list gives beside none. The
/// ruby-platform gem a patch's registry serves is the patch itself, so its
/// entry is the gem's patch by the lock's wiring, as for a gem locked as
/// its ruby-platform gem alone.
///
/// [`RegistryOverrideIdentifiers::gem_builds`]: crate::patch::redirect::RegistryOverrideIdentifiers::gem_builds
pub fn gem_build_states(
    version: &str,
    pins: &[LockedGemPin],
    gem_uuid: &str,
    listed: &[GemPlatformChecksum],
    index: Option<&str>,
) -> Vec<GemBuildState> {
    pins.iter()
        .map(|pin| {
            let Some(platform) = pin.platform.as_deref() else {
                return GemBuildState::Patched {
                    uuid: gem_uuid.to_string(),
                };
            };
            let served = || compact_index_checksum(index?, &format!("{version}-{platform}"));
            let Some(installed) = pin.sha256.clone().or_else(served) else {
                return GemBuildState::Unknown(GemBuildUnknown::Unpinned);
            };
            let Some(build) = listed.iter().find(|build| build.platform == platform) else {
                return GemBuildState::Unknown(GemBuildUnknown::Unlisted);
            };
            if !installed.eq_ignore_ascii_case(&build.gem_checksum_sha256) {
                return GemBuildState::Unknown(GemBuildUnknown::Differs);
            }
            match &build.patch_uuid {
                Some(uuid) => GemBuildState::Patched { uuid: uuid.clone() },
                None => GemBuildState::Upstream,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEM_UUID: &str = "7b1e4f3a-2c5d-4e6f-8a9b-0c1d2e3f4a5b";
    const LINUX_UUID: &str = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
    const ARM: &str = "arm64-darwin";
    const LINUX: &str = "x86_64-linux-gnu";

    fn sha(digit: char) -> String {
        digit.to_string().repeat(64)
    }

    fn pin(platform: Option<&str>, sha256: Option<String>) -> LockedGemPin {
        LockedGemPin {
            platform: platform.map(str::to_string),
            sha256,
        }
    }

    fn listed(platform: &str, sha256: String, patch: Option<&str>) -> GemPlatformChecksum {
        GemPlatformChecksum {
            platform: platform.to_string(),
            gem_checksum_sha256: sha256,
            patch_uuid: patch.map(str::to_string),
        }
    }

    /// `arm64-darwin` on upstream's gem (`a…`), `x86_64-linux-gnu` patched
    /// (`b…`), and the ruby gem (`c…`).
    fn list() -> Vec<GemPlatformChecksum> {
        vec![
            listed(ARM, sha('a'), None),
            listed("ruby", sha('c'), Some(GEM_UUID)),
            listed(LINUX, sha('b'), Some(LINUX_UUID)),
        ]
    }

    fn patched(uuid: &str) -> GemBuildState {
        GemBuildState::Patched {
            uuid: uuid.to_string(),
        }
    }

    /// The builds a lock names come with what its `CHECKSUMS` pins for
    /// each, the ruby-platform gem first; a bare entry and a missing one
    /// pin nothing, and a lock with no platform build names none.
    #[test]
    fn a_locks_builds_come_with_their_checksums() {
        let lock = format!(
            "GEM\n  remote: https://patch.example/patch-registry/gem/t/{GEM_UUID}/s/4f/\n  \
             specs:\n    nokogiri (1.18.10)\n    nokogiri (1.18.10-{ARM})\n    nokogiri \
             (1.18.10-{LINUX})\n    nokogiri (1.18.10-java)\n\nGEM\n  remote: \
             https://rubygems.org/\n  specs:\n    racc (1.8.1)\n\nCHECKSUMS\n  nokogiri (1.18.10) \
             sha256={}\n  nokogiri (1.18.10-{ARM}) sha256={}\n  nokogiri (1.18.10-{LINUX})\n  racc \
             (1.8.1) sha256={}\n",
            sha('c'),
            sha('a'),
            sha('5'),
        );
        assert_eq!(
            locked_gem_pins(&lock, "nokogiri", "1.18.10"),
            [
                pin(None, Some(sha('c'))),
                pin(Some(ARM), Some(sha('a'))),
                pin(Some("java"), None),
                pin(Some(LINUX), None),
            ]
        );
        // CRLF reads the same.
        assert_eq!(
            locked_gem_pins(&lock.replace('\n', "\r\n"), "nokogiri", "1.18.10").len(),
            4
        );
        assert_eq!(
            locked_gem_pins(&lock, "racc", "1.8.1"),
            [pin(None, Some(sha('5')))]
        );
        assert_eq!(locked_gem_pins(&lock, "nokogiri", "1.18.9"), []);
    }

    /// A build is a patched one, under its platform's patch, only on the
    /// sha256 the list gives beside that patch, and upstream's only on the
    /// one it gives beside none. The ruby-platform gem is the gem's patch.
    #[test]
    fn a_build_is_judged_by_the_sha256_the_lock_pins() {
        let pins = [
            pin(None, Some(sha('c'))),
            pin(Some(ARM), Some(sha('a'))),
            pin(Some(LINUX), Some(sha('b').to_uppercase())),
        ];
        assert_eq!(
            gem_build_states("1.18.10", &pins, GEM_UUID, &list(), None),
            [
                patched(GEM_UUID),
                GemBuildState::Upstream,
                patched(LINUX_UUID)
            ]
        );
    }

    /// The list is of a later registry than the lock's: the build it names
    /// patched is not the archive the lock pins, so it is not shown
    /// patched. Nor is a build of a platform the list leaves out.
    #[test]
    fn a_list_later_than_the_lock_shows_nothing_patched_for_a_build_the_lock_pins_otherwise() {
        let mut later = list();
        later[0] = listed(ARM, sha('d'), Some("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"));
        let pins = [
            pin(Some(ARM), Some(sha('a'))),
            pin(Some(LINUX), Some(sha('b'))),
            pin(Some("java"), Some(sha('e'))),
        ];
        assert_eq!(
            gem_build_states("1.18.10", &pins, GEM_UUID, &later, None),
            [
                GemBuildState::Unknown(GemBuildUnknown::Differs),
                patched(LINUX_UUID),
                GemBuildState::Unknown(GemBuildUnknown::Unlisted),
            ]
        );
    }

    /// A lock with no `CHECKSUMS` entry installs what its own registry
    /// lists: the index names the archive, by the build's whole token.
    /// With no index, or none that lists the build, nothing is shown.
    #[test]
    fn a_build_without_a_checksum_is_judged_by_the_index_of_the_locks_registry() {
        let pins = [pin(Some(ARM), None), pin(Some(LINUX), None)];
        let index = format!(
            "---\n1.18.10 racc:~> 1.4|checksum:{}\n1.18.10-{ARM} racc:~> 1.4|checksum:{}\n\
             1.18.10-{LINUX} racc:~> 1.4|checksum:{},ruby:>= 3.1\n",
            sha('c'),
            sha('a'),
            sha('b'),
        );
        assert_eq!(
            gem_build_states("1.18.10", &pins, GEM_UUID, &list(), Some(&index)),
            [GemBuildState::Upstream, patched(LINUX_UUID)]
        );
        let unknown = GemBuildState::Unknown(GemBuildUnknown::Unpinned);
        assert_eq!(
            gem_build_states("1.18.10", &pins, GEM_UUID, &list(), None),
            [unknown.clone(), unknown.clone()]
        );
        // The index of an earlier registry, where linux was upstream's gem.
        let earlier = index.replace(&sha('b'), &sha('9'));
        assert_eq!(
            gem_build_states("1.18.10", &pins, GEM_UUID, &list(), Some(&earlier)),
            [
                GemBuildState::Upstream,
                GemBuildState::Unknown(GemBuildUnknown::Differs)
            ]
        );
        let other_version = index.replace("1.18.10", "1.18.9");
        assert_eq!(
            gem_build_states("1.18.10", &pins, GEM_UUID, &list(), Some(&other_version)),
            [unknown.clone(), unknown]
        );
    }

    #[test]
    fn the_index_of_a_registry_is_under_its_remote() {
        let index = "https://patch.example/patch-registry/gem/t/u/s/4f/info/nokogiri";
        for remote in [
            "https://patch.example/patch-registry/gem/t/u/s/4f/",
            "https://patch.example/patch-registry/gem/t/u/s/4f",
        ] {
            assert_eq!(gem_index_url(remote, "nokogiri").as_deref(), Some(index));
        }
        assert_eq!(
            gem_index_url("file:.socket/vendor/gem/u/", "nokogiri"),
            None
        );
        assert_eq!(
            gem_index_url("https://patch.example/r/", "../versions"),
            None
        );
        // A URL with a query or a fragment is no registry address.
        assert_eq!(
            gem_index_url("https://patch.example/r/?x=1", "nokogiri"),
            None
        );
    }
}
