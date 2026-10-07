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
//! `composerPatchIdentityVersion` twin asserts byte for byte. A 2-4 part
//! numeric spelling Composer rejects (the SBOM's four-part padding of a date
//! version, `20231001.0.0.0`) is normalized with its trailing `.0` parts
//! dropped, and a date release (6+ digit major) drops its trailing `.0`
//! parts too, since that padding erases whether the lock said `X`, `X.0` or
//! `X.0.0`. Any other spelling Composer rejects keys as itself minus one
//! leading `v`, and is equivalent only to other rejected spellings with the
//! same key.
//!
//! Only comparisons go through this module, and purl comparisons reach it
//! only through [`crate::utils::purl_key::PurlKey`]. Stored spellings
//! (manifest keys, vendored leaf directories, ledger keys, crawler purls)
//! are unchanged.
//!
//! Composer's normalize is not idempotent for a few forms (`2010-01-02` →
//! `2010.01.02` → `2010.01.02.0`; `1.0.0-STABLE` keeps `-stable`), so key raw
//! spellings once and never re-key a key.

use std::sync::LazyLock;

use regex::Regex;

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

/// [`composer_version_normalize`], or for a 2-4 part numeric spelling
/// Composer rejects, the normalized form with its trailing `.0` parts dropped.
/// SBOM rows pad every numeric version to four parts, which Composer rejects
/// for a 6+ digit (date) major (`20231001` → `20231001.0.0.0`).
fn normalize_unpadded(version: &str) -> Option<String> {
    if let Some(normalized) = composer_version_normalize(version) {
        return Some(normalized);
    }
    let stripped = strip_leading_v(version);
    let parts: Vec<&str> = stripped.split('.').collect();
    if !(2..=4).contains(&parts.len())
        || !parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let keep = parts
        .iter()
        .rposition(|part| *part != "0")
        .map_or(1, |index| index + 1);
    if keep == parts.len() {
        return None;
    }
    composer_version_normalize(&parts[..keep].join("."))
}

/// [`normalize_unpadded`], with a date release's trailing `.0` parts dropped:
/// that padding also erases whether the lock said `X`, `X.0` or `X.0.0`, so
/// they cannot tell date releases apart (`20231001.0` ≡ `20231001`).
fn identity_normalize(version: &str) -> Option<String> {
    let normalized = normalize_unpadded(version)?;
    let mut parts = normalized.split('.');
    let date_numeric = parts
        .next()
        .is_some_and(|major| major.len() >= 6 && major.bytes().all(|b| b.is_ascii_digit()))
        && parts.all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if !date_numeric {
        return Some(normalized);
    }
    let mut trimmed = normalized.as_str();
    while let Some(rest) = trimmed.strip_suffix(".0") {
        trimmed = rest;
    }
    Some(trimmed.to_string())
}

/// The identity key of a composer version: its normalized form (see
/// [`identity_normalize`]), else the spelling minus one leading `v`.
pub fn composer_version_key(version: &str) -> String {
    identity_normalize(version).unwrap_or_else(|| strip_leading_v(version).to_string())
}

/// A key two spellings share exactly when [`composer_versions_equivalent`]
/// holds, for map and set lookups: [`identity_normalize`], else the spelling
/// minus one leading `v` behind a `\u{1}` so that versions Composer rejects
/// get their own key space (depscan's `composerVersionIdentityKey`).
pub fn composer_version_identity_key(version: &str) -> String {
    identity_normalize(version).unwrap_or_else(|| format!("\u{1}{}", strip_leading_v(version)))
}

/// Whether two composer version spellings name the same release
/// (`3.0.2` ≡ `v3.0.2` ≡ `3.0.2.0`, `8.1.0-RC1` ≡ `v8.1.0-rc.1`). A spelling
/// Composer rejects matches only another rejected spelling with the same
/// `v`-stripped text.
pub fn composer_versions_equivalent(a: &str, b: &str) -> bool {
    composer_version_identity_key(a) == composer_version_identity_key(b)
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
    fn identity_key_equality_is_equivalence_over_every_vector_pair() {
        let v = vectors();
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
        let mut failures = Vec::new();
        for a in &inputs {
            for b in &inputs {
                let keyed = composer_version_identity_key(a) == composer_version_identity_key(b);
                let rejected = |x: &str| identity_normalize(x).is_none();
                let spec = match (rejected(a), rejected(b)) {
                    (false, false) => composer_version_key(a) == composer_version_key(b),
                    (true, true) => strip_leading_v(a) == strip_leading_v(b),
                    _ => false,
                };
                if keyed != spec || keyed != composer_versions_equivalent(a, b) {
                    failures.push(format!("{a:?} vs {b:?}: key {keyed}, spec {spec}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn sbom_padded_date_versions_match_their_lock_spelling() {
        assert_eq!(composer_version_key("20231001.0.0.0"), "20231001");
        assert!(composer_versions_equivalent("20231001", "20231001.0.0.0"));
        assert!(composer_versions_equivalent("123456.1", "123456.1.0.0"));
        assert!(composer_versions_equivalent("20231001.0", "20231001.0.0.0"));
        assert!(composer_versions_equivalent("202301.1", "202301.1.0"));
        assert!(!composer_versions_equivalent("1.2.3.4.5", "1.2.3.4.5.0"));
    }
}
