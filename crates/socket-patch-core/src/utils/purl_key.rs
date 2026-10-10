//! One purl identity: when two purl spellings name the same package release.
//!
//! The same release reaches the CLI under several spellings: the patches API
//! percent-encodes (`pkg:npm/%40scope/x@1`, `pkg:golang/…@v1.0.0%2Bincompatible`)
//! and decorates (`?artifact_id=…`, `#subpath`), crawlers and lockfiles use
//! the literal on-disk names (`pkg:nuget/newtonsoft.json` from the NuGet
//! global cache, `pkg:nuget/Newtonsoft.Json` from the API), PyPI names
//! arrive in any PEP 503 spelling (`typing_extensions` / `typing-extensions`),
//! and a composer release has a pretty tag, a padded SBOM form and a `v`
//! prefix (`3.0.2` / `3.0.2.0` / `v3.0.2`).
//!
//! Every "is this the same package" comparison goes through this module:
//!
//! - [`canonical_base_purl`] is the canonical *spelling*: safe to show and
//!   to carry in reports (VEX product purls), but composer versions keep
//!   their spelling.
//! - [`PurlKey`] is the *identity*: [`canonical_base_purl`] plus the composer
//!   release identity, so two purls are the same package release exactly
//!   when their keys are equal. Use it for every map key, set membership and
//!   equality test; [`PurlKey::qualified`] when a release variant
//!   (`?artifact_id=`, `?platform=`) must still be told apart.
//!
//! Neither form is ever used to build a filesystem path or a download URL:
//! a `%2f` decoding into a name can at worst make two distinct purls compare
//! equal, never change where something is written.

use std::fmt;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::composer_version::composer_version_key;
use crate::utils::purl::{normalize_purl, strip_purl_qualifiers};
use crate::vendor::nuget_feed::normalize_nuget_version;

/// The canonical spelling of a purl's package release: surrounding
/// whitespace trimmed, qualifiers and subpath stripped, components
/// percent-decoded, the type lowercased, and the name folded where the
/// ecosystem's own resolution is insensitive:
///
/// - `pypi`: PEP 503 (case, and runs of `-`/`_`/`.` become one `-`);
/// - `nuget`: case (name and version — NuGet compares both
///   case-insensitively);
/// - `composer`: name case (`vendor/name`); the version keeps its spelling,
///   since a `dev-` branch name is case-sensitive.
///
/// Every other ecosystem keeps its spelling: npm forbids uppercase, and
/// Maven groups and Go module paths are case-sensitive.
///
/// Composer (`3.0.2` vs `3.0.2.0`) and NuGet (`13.0.3` vs `13.0.3.0`)
/// release spellings still differ here; compare with [`PurlKey`], which
/// folds them.
pub fn canonical_base_purl(purl: &str) -> String {
    let base = normalize_purl(strip_purl_qualifiers(purl.trim())).into_owned();
    let Some(rest) = base.strip_prefix("pkg:") else {
        return base;
    };
    let Some((ty, tail)) = rest.split_once('/') else {
        return base;
    };
    let ty = ty.to_ascii_lowercase();
    let (name, version) = match tail.rsplit_once('@').filter(|(name, _)| !name.is_empty()) {
        Some((name, version)) => (name, Some(version)),
        None => (tail, None),
    };
    let (name, version) = match ty.as_str() {
        "pypi" => (canonicalize_pypi_name(name), version.map(str::to_string)),
        "nuget" => (name.to_lowercase(), version.map(str::to_lowercase)),
        "composer" => (name.to_lowercase(), version.map(str::to_string)),
        _ => (name.to_string(), version.map(str::to_string)),
    };
    match version {
        Some(version) => format!("pkg:{ty}/{name}@{version}"),
        None => format!("pkg:{ty}/{name}"),
    }
}

/// The identity of a purl's package release; equal for exactly the
/// spellings that name the same release. See the [module docs](self).
///
/// The string form is [`canonical_base_purl`], with the version replaced by
/// its release identity where the ecosystem defines one:
///
/// - a composer `pkg:composer/<vendor>/<name>@<version>`:
///   [`composer_version_key`] (`v3.0.2` → `3.0.2.0`);
/// - a NuGet `pkg:nuget/<id>@<version>`: [`normalize_nuget_version`], the
///   `NuGetVersion.ToNormalizedString()` form the vendored backend, upstream
///   restore and the lock's `resolved` field use (`13.0.3.0` → `13.0.3`,
///   build metadata dropped).
///
/// It contains no internal sentinels, so rollout and policy reports may show
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PurlKey(String);

impl PurlKey {
    /// The key of `purl`'s package release; qualifiers and subpath are
    /// ignored, so every release variant of one `name@version` shares it.
    pub fn new(purl: &str) -> Self {
        let canonical = canonical_base_purl(purl);
        PurlKey(release_identity(&canonical).unwrap_or(canonical))
    }

    /// [`PurlKey::new`] followed by `purl`'s verbatim `?qualifiers` /
    /// `#subpath`: one release *variant* (a wheel vs its sdist, a gem
    /// platform). Two spellings of the same qualified purl share it; two
    /// variants of one release do not.
    pub fn qualified(purl: &str) -> Self {
        let purl = purl.trim();
        let suffix = purl.find(['?', '#']).map_or("", |i| &purl[i..]);
        let mut key = Self::new(purl).0;
        key.push_str(suffix);
        PurlKey(key)
    }

    /// Whether `a` and `b` name the same package release.
    pub fn same(a: &str, b: &str) -> bool {
        Self::new(a) == Self::new(b)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for PurlKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PurlKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The canonical base with its version replaced by the ecosystem's release
/// identity; `None` where the spelling already is the identity.
fn release_identity(canonical: &str) -> Option<String> {
    composer_identity(canonical).or_else(|| nuget_identity(canonical))
}

/// `pkg:nuget/<id>@<normalized version>` for a canonical NuGet base with an
/// id and a version; `None` for anything else.
fn nuget_identity(canonical: &str) -> Option<String> {
    let rest = canonical.strip_prefix("pkg:nuget/")?;
    let (id, version) = rest.rsplit_once('@')?;
    if id.is_empty() || version.is_empty() {
        return None;
    }
    Some(format!(
        "pkg:nuget/{id}@{}",
        normalize_nuget_version(version)
    ))
}

/// `pkg:composer/<vendor>/<name>@<release identity>` for a canonical
/// composer base with a `vendor/name` coordinate and a version; `None` for
/// anything else (which then keys as its canonical spelling).
fn composer_identity(canonical: &str) -> Option<String> {
    let rest = canonical.strip_prefix("pkg:composer/")?;
    let (name, version) = rest.rsplit_once('@')?;
    let (vendor, package) = name.split_once('/')?;
    if vendor.is_empty() || package.is_empty() || package.contains('/') || version.is_empty() {
        return None;
    }
    Some(format!(
        "pkg:composer/{name}@{}",
        composer_version_key(version)
    ))
}

/// `pkg:pypi/<name>@<v>` purls for every other spelling of `purl`'s pure
/// release (`@1.16` → `@1.16.0`, see
/// [`crate::utils::pep440::equivalent_release_spellings`]): the lockfile
/// spells a pin as the user wrote it (`six==1.16`), while the patch API
/// keys the release as the registry published it (#604). Empty for any
/// other purl.
pub fn pypi_equivalent_purls(purl: &str) -> Vec<String> {
    let canonical = canonical_base_purl(purl);
    let Some((name, version)) = canonical
        .strip_prefix("pkg:pypi/")
        .and_then(|rest| rest.rsplit_once('@'))
    else {
        return Vec::new();
    };
    crate::utils::pep440::equivalent_release_spellings(version)
        .into_iter()
        .map(|spelling| format!("pkg:pypi/{name}@{spelling}"))
        .collect()
}

/// Whether two PyPI purls name the same release under PEP 440 equality
/// (`@1.16` and `@1.16.0`), the way pip resolves an `==` pin. `false` for
/// anything that is not two PyPI purls of one (PEP 503) name.
pub fn pypi_same_release(a: &str, b: &str) -> bool {
    let (a, b) = (canonical_base_purl(a), canonical_base_purl(b));
    let split = |purl: &str| -> Option<(String, String)> {
        let (name, version) = purl.strip_prefix("pkg:pypi/")?.rsplit_once('@')?;
        Some((name.to_string(), version.to_string()))
    };
    match (split(&a), split(&b)) {
        (Some((name_a, version_a)), Some((name_b, version_b))) => {
            name_a == name_b && crate::utils::pep440::versions_equal(&version_a, &version_b)
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "purl_key_nuget_vendor_tests.rs"]
mod nuget_vendor_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::composer_version::composer_versions_equivalent;

    #[test]
    fn canonical_base_purl_folds_only_insensitive_ecosystems() {
        assert_eq!(
            canonical_base_purl("pkg:pypi/Python_Dateutil@2.8.2?artifact_id=py3-none-any-whl"),
            "pkg:pypi/python-dateutil@2.8.2"
        );
        assert_eq!(
            canonical_base_purl("pkg:npm/%40scope/Name@1.0.0"),
            "pkg:npm/@scope/Name@1.0.0"
        );
        assert_eq!(
            canonical_base_purl("pkg:nuget/Newtonsoft.Json@13.0.1-Beta"),
            "pkg:nuget/newtonsoft.json@13.0.1-beta"
        );
        assert_eq!(
            canonical_base_purl("pkg:composer/Monolog/Monolog@dev-Main"),
            "pkg:composer/monolog/monolog@dev-Main"
        );
        assert_eq!(
            canonical_base_purl("pkg:gem/nokogiri@1.16.5?platform=java"),
            "pkg:gem/nokogiri@1.16.5"
        );
        assert_eq!(
            canonical_base_purl("pkg:golang/github.com/Foo/bar@v1.0.0#sub/dir"),
            "pkg:golang/github.com/Foo/bar@v1.0.0"
        );
        assert_eq!(
            canonical_base_purl("pkg:Maven/Org.Foo/Bar@1.0"),
            "pkg:maven/Org.Foo/Bar@1.0"
        );
        assert_eq!(canonical_base_purl("pkg:pypi/Foo_Bar"), "pkg:pypi/foo-bar");
        assert_eq!(canonical_base_purl(" not-a-purl "), "not-a-purl");
    }

    #[test]
    fn composer_identity_bridges_padding_prefix_case_and_encoding() {
        for purl in [
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/log@v3.0.2",
            "pkg:composer/psr/log@3.0.2.0",
            "pkg:composer/Psr/Log@3.0.2",
            "pkg:composer/psr/log@3.0.2.0?repository_url=https://repo.packagist.org",
            "pkg:composer/psr/log@3.0.2#src",
            "pkg:composer/psr/log@3.0.2%2Bbuild.5",
        ] {
            assert_eq!(
                PurlKey::new(purl).as_str(),
                "pkg:composer/psr/log@3.0.2.0",
                "{purl}"
            );
        }
        assert_eq!(
            PurlKey::new("pkg:composer/symfony/http-kernel@v8.1.0-rc.1").as_str(),
            "pkg:composer/symfony/http-kernel@8.1.0.0-RC1"
        );
        assert!(PurlKey::same(
            "pkg:composer/acme/dated@20231001.0.0.0",
            "pkg:composer/acme/dated@20231001"
        ));
        assert!(!PurlKey::same(
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/log@3.0.20"
        ));
        assert!(!PurlKey::same(
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/cache@3.0.2"
        ));
        assert!(!PurlKey::same(
            "pkg:composer/psr/log@1.0.0-RC1",
            "pkg:composer/psr/log@1.0.0"
        ));
        // A dev branch name is case-sensitive.
        assert!(!PurlKey::same(
            "pkg:composer/psr/log@dev-Feature",
            "pkg:composer/psr/log@dev-feature"
        ));
        // Rejected versions key without the internal sentinel.
        assert!(!PurlKey::new("pkg:composer/psr/log@not-a-version")
            .as_str()
            .contains('\u{1}'));
        // Only composer and NuGet get release identity; other types stay
        // version-exact.
        assert!(!PurlKey::same("pkg:npm/x@1.0", "pkg:npm/x@1.0.0.0"));
        // Malformed composer coordinates key as their canonical spelling.
        assert_eq!(
            PurlKey::new("pkg:composer/log@1.0.0").as_str(),
            "pkg:composer/log@1.0.0"
        );
        assert_eq!(
            PurlKey::new("pkg:composer/a/b/c@1.0.0").as_str(),
            "pkg:composer/a/b/c@1.0.0"
        );
    }

    /// #1202: NuGet's package identity is the normalized version, the one
    /// the vendored backend wires (`locked_at`, the feed leaf) and the lock
    /// records as `resolved`. A 4-part `packages.config` spelling, a padded
    /// or zero-led segment, a pre-release case variant and build metadata
    /// all name the same release.
    #[test]
    fn nuget_version_spellings_share_the_normalized_key() {
        for (a, b) in [
            ("pkg:nuget/A@1.0.0.0", "pkg:nuget/a@1.0.0"),
            (
                "pkg:nuget/Newtonsoft.Json@13.0.3.0",
                "pkg:nuget/newtonsoft.json@13.0.3",
            ),
            ("pkg:nuget/A@1.0", "pkg:nuget/A@1.0.0"),
            ("pkg:nuget/A@1.02.3", "pkg:nuget/A@1.2.3"),
            ("pkg:nuget/A@1.0.0-RC1", "pkg:nuget/a@1.0.0-rc1"),
            ("pkg:nuget/A@1.0.0+build.5", "pkg:nuget/A@1.0.0"),
            ("pkg:nuget/A@1.0.0%2Bbuild.5", "pkg:nuget/A@1.0.0"),
            ("pkg:nuget/A@1.0.0.0?repository_url=x", "pkg:nuget/A@1.0.0"),
        ] {
            assert!(PurlKey::same(a, b), "{a} vs {b}");
        }
        assert_eq!(
            PurlKey::new("pkg:nuget/Microsoft.Web.Infrastructure@1.0.0.0").as_str(),
            "pkg:nuget/microsoft.web.infrastructure@1.0.0"
        );
        // A non-zero revision is part of the identity.
        assert!(!PurlKey::same("pkg:nuget/A@1.0.0.1", "pkg:nuget/A@1.0.0"));
        assert!(!PurlKey::same("pkg:nuget/A@1.0.0-rc1", "pkg:nuget/A@1.0.0"));
        // The canonical spelling keeps the as-written version.
        assert_eq!(
            canonical_base_purl("pkg:nuget/A@1.0.0.0"),
            "pkg:nuget/a@1.0.0.0"
        );
        // An id or version that is missing keys as its canonical spelling.
        assert_eq!(PurlKey::new("pkg:nuget/A").as_str(), "pkg:nuget/a");
        assert_eq!(PurlKey::new("pkg:nuget/A@").as_str(), "pkg:nuget/a@");
        // The qualified key still tells release variants apart.
        assert_eq!(
            PurlKey::qualified("pkg:nuget/A@1.0.0.0?x=1").as_str(),
            "pkg:nuget/a@1.0.0?x=1"
        );
    }

    /// One identity rule: two NuGet purls share a [`PurlKey`] exactly when
    /// the vendored backend's version match (`normalize_nuget_version`, as
    /// `locked_at` and upstream restore compare) and NuGet's
    /// case-insensitive id match both say they are the same release.
    #[test]
    fn nuget_key_agrees_with_the_vendored_version_match() {
        let ids = ["Newtonsoft.Json", "newtonsoft.json", "Other"];
        let versions = [
            "13.0.3",
            "13.0.3.0",
            "13.00.3",
            "13.0.3.1",
            "13.0",
            "13.0.0",
            "13.0.3-Beta",
            "13.0.3-beta",
            "13.0.3+meta",
            "13.0.4",
        ];
        for (ia, va) in ids
            .iter()
            .flat_map(|i| versions.iter().map(move |v| (i, v)))
        {
            for (ib, vb) in ids
                .iter()
                .flat_map(|i| versions.iter().map(move |v| (i, v)))
            {
                let vendored = ia.eq_ignore_ascii_case(ib)
                    && normalize_nuget_version(va) == normalize_nuget_version(vb);
                assert_eq!(
                    PurlKey::same(
                        &format!("pkg:nuget/{ia}@{va}"),
                        &format!("pkg:nuget/{ib}@{vb}")
                    ),
                    vendored,
                    "{ia}@{va} vs {ib}@{vb}"
                );
            }
        }
    }

    /// B20 / #553: the NuGet global-cache crawl spells the purl lowercase,
    /// the API mixed-case; B73: a PEP 503 or NuGet case variant names the
    /// same release.
    #[test]
    fn nuget_case_and_pep503_spellings_share_a_key() {
        assert!(PurlKey::same(
            "pkg:nuget/Newtonsoft.Json@13.0.3",
            "pkg:nuget/newtonsoft.json@13.0.3"
        ));
        assert!(PurlKey::same(
            "pkg:pypi/typing_extensions@4.12.2",
            "pkg:pypi/typing-extensions@4.12.2"
        ));
        assert!(PurlKey::same(
            "pkg:pypi/Typing.Extensions@4.12.2",
            "pkg:pypi/typing-extensions@4.12.2"
        ));
        assert!(!PurlKey::same(
            "pkg:nuget/Newtonsoft.Json@13.0.3",
            "pkg:nuget/Newtonsoft.Json@13.0.4"
        ));
        // Case-sensitive ecosystems are not folded.
        assert!(!PurlKey::same(
            "pkg:maven/Org.Foo/bar@1.0",
            "pkg:maven/org.foo/bar@1.0"
        ));
        assert!(!PurlKey::same(
            "pkg:golang/github.com/Foo/bar@v1.0.0",
            "pkg:golang/github.com/foo/bar@v1.0.0"
        ));
    }

    #[test]
    fn qualified_keys_keep_variants_apart() {
        assert_eq!(
            PurlKey::qualified("pkg:pypi/Foo_Bar@1.0?artifact_id=abc"),
            PurlKey::qualified("pkg:pypi/foo-bar@1.0?artifact_id=abc")
        );
        assert_ne!(
            PurlKey::qualified("pkg:pypi/foo@1.0?artifact_id=abc"),
            PurlKey::qualified("pkg:pypi/foo@1.0?artifact_id=def")
        );
        assert_eq!(
            PurlKey::new("pkg:pypi/foo@1.0?artifact_id=abc"),
            PurlKey::new("pkg:pypi/foo@1.0?artifact_id=def")
        );
        assert_eq!(
            PurlKey::qualified("pkg:npm/%40s/x@1#sub").as_str(),
            "pkg:npm/@s/x@1#sub"
        );
        assert_eq!(PurlKey::qualified("pkg:npm/x@1").as_str(), "pkg:npm/x@1");
    }

    /// Every spelling variant of one release maps to one key, and changing
    /// the release (another name or version) never does: the property every
    /// former equality relation (ledger keys, prune, update detection,
    /// redirect matching, VEX, rollout, policy, remove/rollback identifiers)
    /// now inherits from this one type.
    #[test]
    fn every_spelling_variant_shares_one_key_and_no_other_release_does() {
        // (release, spellings of that same release)
        let cases: &[(&str, &[&str])] = &[
            (
                "pkg:npm/@scope/pkg@1.0.0",
                &[
                    "pkg:npm/%40scope/pkg@1.0.0",
                    "pkg:NPM/@scope/pkg@1.0.0",
                    "pkg:npm/@scope/pkg@1.0.0?artifact_id=x",
                    "pkg:npm/%40scope/pkg@1.0.0#lib",
                    " pkg:npm/@scope/pkg@1.0.0 ",
                ],
            ),
            (
                "pkg:pypi/typing-extensions@4.12.2",
                &[
                    "pkg:pypi/typing_extensions@4.12.2",
                    "pkg:pypi/Typing.Extensions@4.12.2",
                    "pkg:pypi/typing__extensions@4.12.2?artifact_id=whl",
                    "pkg:PyPI/TYPING-EXTENSIONS@4.12.2",
                ],
            ),
            (
                "pkg:nuget/Newtonsoft.Json@13.0.3",
                &[
                    "pkg:nuget/newtonsoft.json@13.0.3",
                    "pkg:nuget/NEWTONSOFT.JSON@13.0.3",
                    "pkg:nuget/Newtonsoft.Json@13.0.3?repository_url=x",
                ],
            ),
            (
                "pkg:composer/psr/log@3.0.2",
                &[
                    "pkg:composer/psr/log@v3.0.2",
                    "pkg:composer/PSR/Log@3.0.2.0",
                    "pkg:composer/psr%2Flog@3.0.2",
                ],
            ),
            (
                "pkg:golang/github.com/foo/bar@v1.0.0+incompatible",
                &["pkg:golang/github.com/foo/bar@v1.0.0%2Bincompatible"],
            ),
            (
                "pkg:gem/nokogiri@1.16.5",
                &["pkg:gem/nokogiri@1.16.5?platform=java"],
            ),
        ];
        for (release, spellings) in cases {
            let key = PurlKey::new(release);
            for spelling in *spellings {
                assert_eq!(PurlKey::new(spelling), key, "{spelling} vs {release}");
            }
            for (other, _) in cases.iter().filter(|(other, _)| other != release) {
                assert_ne!(PurlKey::new(other), key, "{other} vs {release}");
            }
            let (name, version) = release.rsplit_once('@').unwrap();
            for bumped in [format!("{name}@{version}9"), format!("{name}x@{version}")] {
                assert_ne!(PurlKey::new(&bumped), key, "{bumped}");
            }
        }
    }

    /// The composer half of [`PurlKey`] is exactly composer release
    /// equivalence, over the whole shared vector file (pairs of accepted
    /// AND rejected spellings), even though the key drops the internal
    /// rejected-version sentinel.
    #[test]
    fn composer_key_equality_is_release_equivalence_over_every_vector_pair() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/composer-version-vectors.json"
        ))
        .unwrap();
        let mut inputs: Vec<&str> = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| case["input"].as_str().unwrap())
            .collect();
        for case in v["equivalence"].as_array().unwrap() {
            inputs.push(case["left"].as_str().unwrap());
            inputs.push(case["right"].as_str().unwrap());
        }
        inputs.retain(|version| {
            !version.is_empty()
                && version.trim() == *version
                && !version.contains(['?', '#', '%', '@', '/'])
        });
        let mut failures = Vec::new();
        for a in &inputs {
            for b in &inputs {
                let keyed = PurlKey::same(
                    &format!("pkg:composer/psr/log@{a}"),
                    &format!("pkg:composer/psr/log@{b}"),
                );
                if keyed != composer_versions_equivalent(a, b) {
                    failures.push(format!("{a:?} vs {b:?}: keyed {keyed}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
