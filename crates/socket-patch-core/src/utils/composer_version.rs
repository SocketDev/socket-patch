//! Composer version identity: when two spellings name the same release.
//!
//! One composer release reaches the CLI under several spellings. Lockfiles
//! and `installed.json` carry the pretty tag (`v3.0.2`, `3.0.2`), while a
//! patch's base purl may carry the padded `version_normalized` form
//! (`3.0.2.0`) that Socket's SBOM ingestion stores. Comparing them as strings
//! made a patch for `@3.0.2.0` "not found" in a project that locks `3.0.2`,
//! and made `scan --prune` delete it.
//!
//! [`composer_version_normalize`] is a port of composer/semver 3.4
//! `VersionParser::normalize`, the function Composer and Packagist key a
//! release by (Packagist keeps `version_normalized` unique per package). It is
//! checked against real Composer 2.10.3 by the shared vector file
//! `tests/fixtures/composer-version-vectors.json`, which depscan's
//! `composerPatchIdentityVersion` twin asserts byte for byte. A spelling
//! Composer rejects keys as itself minus one leading `v`, and is equivalent
//! only to other rejected spellings with the same key.
//!
//! Only comparisons go through this module. Stored spellings (manifest keys,
//! vendored leaf directories, ledger keys, crawler purls) are unchanged.
//!
//! Composer's normalize is not idempotent for a few forms (`2010-01-02` →
//! `2010.01.02` → `2010.01.02.0`; `1.0.0-STABLE` keeps `-stable`), so key raw
//! spellings once and never re-key a key.

use std::sync::LazyLock;

use regex::Regex;

use crate::utils::purl::{canonical_purl, normalize_purl, strip_purl_qualifiers};

/// PCRE `$` also matches before one final `\n`; PHP `\s` includes `\v`.
const MODIFIER: &str =
    r"[._-]?(?:((?i-u:stable|beta|b|RC|alpha|a|patch|pl|p))((?:[.-]?[0-9]+)*)?)?((?i-u:[.-]?dev))?";

static ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^,\t\n\x0B\x0C\r ]+) +as +([^,\t\n\x0B\x0C\r ]+)\n?$").expect("alias regex")
});
static STABILITY_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"@(?i-u:stable|RC|beta|alpha|dev)(\n?)$").expect("stability flag regex")
});
static BUILD_METADATA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^,\t\n\x0B\x0C\r +]+)\+[^\t\n\x0B\x0C\r ]+\n?$").expect("build metadata regex")
});
static CLASSICAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"^(?i-u:v)?([0-9]{{1,5}})(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?{MODIFIER}\n?$"
    ))
    .expect("classical regex")
});
static DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"^(?i-u:v)?([0-9]{{4}}(?:[.:-]?[0-9]{{2}}){{1,6}}(?:[.:-]?[0-9]{{1,3}}){{0,2}}){MODIFIER}\n?$"
    ))
    .expect("date regex")
});
static DEV_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([^\n]*?)[.-]?(?i-u:dev)\n?$").expect("dev suffix regex"));
static BRANCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?i-u:v)?([0-9]+)(\.(?:[0-9]+|[xX*]))?(\.(?:[0-9]+|[xX*]))?(\.(?:[0-9]+|[xX*]))?\n?$",
    )
    .expect("branch regex")
});

/// PHP `trim()`'s default character set.
fn php_trim(value: &str) -> &str {
    value.trim_matches([' ', '\t', '\n', '\r', '\0', '\x0B'])
}

fn non_empty<'a>(caps: &regex::Captures<'a>, index: usize) -> Option<&'a str> {
    caps.get(index)
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())
}

fn expand_stability(stability: &str) -> String {
    let lowered = stability.to_ascii_lowercase();
    match lowered.as_str() {
        "a" => "alpha".to_string(),
        "b" => "beta".to_string(),
        "p" | "pl" => "patch".to_string(),
        "rc" => "RC".to_string(),
        _ => lowered,
    }
}

/// The stability / dev suffix of a classical or date match, whose modifier
/// groups start at `first`.
fn append_modifiers(mut version: String, caps: &regex::Captures<'_>, first: usize) -> String {
    if let Some(stability) = non_empty(caps, first) {
        // Case-sensitive, as in composer: `-STABLE` is kept as `-stable`.
        if stability == "stable" {
            return version;
        }
        version.push('-');
        version.push_str(&expand_stability(stability));
        if let Some(number) = non_empty(caps, first + 1) {
            version.push_str(number.trim_start_matches(['.', '-']));
        }
    }
    if non_empty(caps, first + 2).is_some() {
        version.push_str("-dev");
    }
    version
}

fn normalize_branch(name: &str) -> String {
    let trimmed = php_trim(name);
    let Some(caps) = BRANCH.captures(trimmed) else {
        return format!("dev-{trimmed}");
    };
    let mut version = String::new();
    for index in 1..5 {
        match caps.get(index) {
            Some(part) => version.push_str(&part.as_str().replace(['*', 'X'], "x")),
            None => version.push_str(".x"),
        }
    }
    format!("{}-dev", version.replace('x', "9999999"))
}

/// Composer's `VersionParser::normalize` (composer/semver 3.4.4), or `None`
/// where Composer throws `UnexpectedValueException` (not a version).
pub fn composer_version_normalize(version: &str) -> Option<String> {
    let mut current = php_trim(version);
    if let Some(caps) = ALIAS.captures(current) {
        if let Some(target) = caps.get(1) {
            current = target.as_str();
        }
    }
    if let Some(caps) = STABILITY_FLAG.captures(current) {
        let whole = caps.get(0).map_or(0, |m| m.len());
        let newline = caps.get(1).map_or(0, |m| m.len());
        // PHP cuts strlen($match[0]) bytes off the END, and the PCRE match
        // excludes a final `\n` it matched before.
        current = &current[..current.len() - (whole - newline)];
    }
    let rooted;
    if matches!(current, "master" | "trunk" | "default") {
        rooted = format!("dev-{current}");
        current = &rooted;
    }
    if current.len() >= 4 && current.as_bytes()[..4].eq_ignore_ascii_case(b"dev-") {
        return Some(format!("dev-{}", &current[4..]));
    }
    if let Some(caps) = BUILD_METADATA.captures(current) {
        if let Some(stripped) = caps.get(1) {
            current = stripped.as_str();
        }
    }
    if let Some(caps) = CLASSICAL.captures(current) {
        if let Some(major) = caps.get(1) {
            let mut core = major.as_str().to_string();
            for index in 2..5 {
                core.push_str(non_empty(&caps, index).unwrap_or(".0"));
            }
            return Some(append_modifiers(core, &caps, 5));
        }
    }
    if let Some(caps) = DATE.captures(current) {
        if let Some(date) = caps.get(1) {
            let dotted: String = date
                .as_str()
                .chars()
                .map(|c| if c.is_ascii_digit() { c } else { '.' })
                .collect();
            return Some(append_modifiers(dotted, &caps, 2));
        }
    }
    if let Some(caps) = DEV_SUFFIX.captures(current) {
        if let Some(branch) = caps.get(1) {
            let normalized = normalize_branch(branch.as_str());
            if !normalized.contains("dev-") {
                return Some(normalized);
            }
        }
    }
    None
}

/// One leading `v`/`V` stripped when a digit follows (`v6.4.1` → `6.4.1`).
fn strip_leading_v(version: &str) -> &str {
    let bytes = version.as_bytes();
    if bytes.len() >= 2 && matches!(bytes[0], b'v' | b'V') && bytes[1].is_ascii_digit() {
        &version[1..]
    } else {
        version
    }
}

/// The identity key of a composer version: [`composer_version_normalize`],
/// else the spelling minus one leading `v`.
pub fn composer_version_key(version: &str) -> String {
    composer_version_normalize(version).unwrap_or_else(|| strip_leading_v(version).to_string())
}

/// Whether two composer version spellings name the same release
/// (`3.0.2` ≡ `v3.0.2` ≡ `3.0.2.0`, `8.1.0-RC1` ≡ `v8.1.0-rc.1`). A spelling
/// Composer rejects matches only another rejected spelling with the same
/// `v`-stripped text.
pub fn composer_versions_equivalent(a: &str, b: &str) -> bool {
    match (composer_version_normalize(a), composer_version_normalize(b)) {
        (Some(left), Some(right)) => left == right,
        (None, None) => strip_leading_v(a) == strip_leading_v(b),
        _ => false,
    }
}

/// `(lowercased vendor/name, version)` of an already-decoded,
/// qualifier-free `pkg:composer/<vendor>/<name>@<version>` base.
fn composer_base_parts(base: &str) -> Option<(String, &str)> {
    let rest = base
        .get(..13)
        .filter(|prefix| prefix.eq_ignore_ascii_case("pkg:composer/"))
        .map(|_| &base[13..])?;
    let (name, version) = rest.rsplit_once('@')?;
    let (vendor, package) = name.split_once('/')?;
    if vendor.is_empty() || package.is_empty() || package.contains('/') || version.is_empty() {
        return None;
    }
    Some((name.to_lowercase(), version))
}

/// `pkg:composer/<vendor>/<name>@<key>` for a composer purl in any spelling
/// (qualifiers and subpath stripped, percent-decoded, name lowercased,
/// version through [`composer_version_key`]); `None` for anything else.
pub fn composer_purl_identity(purl: &str) -> Option<String> {
    let base = canonical_purl(purl);
    let (name, version) = composer_base_parts(&base)?;
    Some(format!(
        "pkg:composer/{name}@{}",
        composer_version_key(version)
    ))
}

/// The key ledger and prune bookkeeping compare purls by: the composer
/// identity for composer purls, [`canonical_purl`] for every other type.
pub fn purl_identity_key(purl: &str) -> String {
    composer_purl_identity(purl).unwrap_or_else(|| canonical_purl(purl))
}

/// Whether two already-decoded, qualifier-free composer bases name the same
/// package release. `false` unless both are composer purls.
pub(crate) fn composer_bases_equivalent(a: &str, b: &str) -> bool {
    match (composer_base_parts(a), composer_base_parts(b)) {
        (Some((left_name, left_version)), Some((right_name, right_version))) => {
            left_name == right_name && composer_versions_equivalent(left_version, right_version)
        }
        _ => false,
    }
}

/// Whether two composer purls, in any spelling, name the same package
/// release (qualifiers and subpath ignored). `false` unless both are
/// composer purls.
pub fn composer_purls_equivalent(a: &str, b: &str) -> bool {
    composer_bases_equivalent(
        &normalize_purl(strip_purl_qualifiers(a)),
        &normalize_purl(strip_purl_qualifiers(b)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../tests/fixtures/composer-version-vectors.json");

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).expect("vector file is JSON")
    }

    #[test]
    fn vector_file_pins_the_composer_oracle() {
        let v = vectors();
        assert_eq!(v["composer"], "2.10.3");
        assert_eq!(v["composerSemver"], "3.4.4");
        assert!(v["vectors"].as_array().unwrap().len() >= 60);
        assert!(!v["equivalence"].as_array().unwrap().is_empty());
    }

    #[test]
    fn every_vector_matches_real_composer() {
        let v = vectors();
        let mut failures = Vec::new();
        for case in v["vectors"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let composer = case["composerNormalized"].as_str().map(str::to_string);
            let identity = case["identity"].as_str().unwrap();
            let got = composer_version_normalize(input);
            if got != composer {
                failures.push(format!(
                    "normalize({input:?}) = {got:?}, composer {composer:?}"
                ));
            }
            let key = composer_version_key(input);
            if key != identity {
                failures.push(format!("key({input:?}) = {key:?}, want {identity:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn every_equivalence_vector_holds_both_ways() {
        let v = vectors();
        let mut failures = Vec::new();
        for case in v["equivalence"].as_array().unwrap() {
            let left = case["left"].as_str().unwrap();
            let right = case["right"].as_str().unwrap();
            let want = case["equivalent"].as_bool().unwrap();
            for (a, b) in [(left, right), (right, left)] {
                if composer_versions_equivalent(a, b) != want {
                    failures.push(format!("equivalent({a:?}, {b:?}) != {want}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn purl_identity_bridges_padding_prefix_case_and_encoding() {
        let want = Some("pkg:composer/psr/log@3.0.2.0".to_string());
        for purl in [
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/log@v3.0.2",
            "pkg:composer/psr/log@3.0.2.0",
            "pkg:composer/Psr/Log@3.0.2",
            "pkg:composer/psr/log@3.0.2.0?repository_url=https://repo.packagist.org",
            "pkg:composer/psr/log@3.0.2#src",
            "pkg:composer/psr/log@3.0.2%2Bbuild.5",
        ] {
            assert_eq!(composer_purl_identity(purl), want, "{purl}");
        }
        assert_eq!(
            composer_purl_identity("pkg:composer/symfony/http-kernel@v8.1.0-rc.1").as_deref(),
            Some("pkg:composer/symfony/http-kernel@8.1.0.0-RC1")
        );
        assert_eq!(composer_purl_identity("pkg:npm/left-pad@1.3.0"), None);
        assert_eq!(composer_purl_identity("pkg:composer/log@1.0.0"), None);
        assert_eq!(composer_purl_identity("pkg:composer/a/b/c@1.0.0"), None);
        assert_eq!(composer_purl_identity("pkg:composer/psr/log@"), None);
    }

    #[test]
    fn purl_equivalence_is_composer_only_and_version_exact() {
        assert!(composer_purls_equivalent(
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/log@3.0.2.0"
        ));
        assert!(composer_purls_equivalent(
            "pkg:composer/psr/log@v3.0.2",
            "pkg:composer/PSR/LOG@3.0.2.0?x=y"
        ));
        assert!(composer_purls_equivalent(
            "pkg:composer/psr/log@1.0",
            "pkg:composer/psr/log@1.0.0.0"
        ));
        assert!(!composer_purls_equivalent(
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/log@3.0.20"
        ));
        assert!(!composer_purls_equivalent(
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/cache@3.0.2"
        ));
        assert!(!composer_purls_equivalent(
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/left-pad@1.3.0"
        ));
        assert!(!composer_purls_equivalent(
            "pkg:composer/psr/log@1.0.0-RC1",
            "pkg:composer/psr/log@1.0.0"
        ));
    }

    #[test]
    fn identity_key_falls_back_to_the_canonical_purl() {
        assert_eq!(
            purl_identity_key("pkg:composer/psr/log@v3.0.2?x=1"),
            "pkg:composer/psr/log@3.0.2.0"
        );
        assert_eq!(
            purl_identity_key("pkg:npm/%40scope/x@1.0.0?y=2"),
            "pkg:npm/@scope/x@1.0.0"
        );
    }
}
