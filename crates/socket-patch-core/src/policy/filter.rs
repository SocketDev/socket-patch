//! The scan **selection filter**: a JSON sidecar the caller of `scan`
//! hands over with `--selection-filter <FILE>` (or `SOCKET_SELECTION_FILTER`)
//! to say what this run need not patch. It is an INTERNAL interface, made
//! for Socket's own remediation tooling (`socket fix` pull requests): no
//! `--help` entry, and the file is versioned so it can change shape.
//!
//! The format reference, with every field, the limits, worked examples
//! and how to read the result, is `docs/selection-filter.md`; its JSON
//! Schema is `docs/selection-filter.schema.json`. This module is the
//! parser and the rules.
//!
//! ```json
//! {
//!   "version": 1,
//!   "skip": {
//!     "paths": ["services/legacy/"],
//!     "packages": ["pkg:npm/left-pad", "pkg:pypi/requests@2.31.0"],
//!     "advisories": ["GHSA-jf85-cpcp-j695", "CVE-2021-23337"]
//!   },
//!   "reachability": [
//!     { "advisory": "GHSA-35jh-r3h4-6jhm", "package": "pkg:npm/lodash@4.17.20", "state": "reachable" },
//!     { "advisory": "GHSA-p6mc-m468-83gw", "state": "unreachable" },
//!     { "package": "pkg:npm/minimist@1.2.5", "state": "unreachable" }
//!   ],
//!   "unlistedAdvisories": "patch"
//! }
//! ```
//!
//! Only `version` is required. Unknown keys, a wrong type and an unknown
//! `state` are errors: the file only ever narrows a run, so one that cannot
//! be honored fails the run (`filter_invalid`, exit 2) before any request
//! or write, instead of meaning "no filter".
//!
//! # The rules
//!
//! `skip.paths` leaves project roots alone and `skip.packages` leaves
//! packages alone, like socket.yml's `patches.ignorePaths` and
//! `patches.ignorePackages`. The rest decides which patches are wanted.
//!
//! Every advisory an available patch fixes is judged for the package the
//! patch is for:
//!
//! 1. An id in `skip.advisories` (the advisory id or one of its CVE
//!    aliases) needs no fix.
//! 2. Otherwise the most specific finding decides: one naming the advisory
//!    and the package, else one naming the advisory, else one naming the
//!    package. When several findings of the same specificity apply, the
//!    most cautious wins (`reachable`, then `unknown`, then
//!    `unreachable`): a monorepo that reaches the code from one workspace
//!    needs the fix. `unreachable` needs no fix; `reachable` and `unknown`
//!    do.
//! 3. With no finding, `unlistedAdvisories` decides: `patch` (the default)
//!    treats the advisory as unknown, `skip` as needing no fix.
//!
//! A patch is withheld only when **no** advisory it fixes needs a fix
//! ([`SelectionFilter::withholds`]). A patch that fixes one needed advisory
//! is wanted whole: a merged patch is applied together with its fixes for
//! unreachable or skipped advisories. So a package goes unpatched only when
//! every advisory its patches fix is unreachable or skipped.
//!
//! The filter never changes how patches rank. One patch is applied per
//! package version, and among the wanted ones the usual ranking
//! ([`crate::api::ranking`]) picks it, over everything each patch fixes;
//! the severity floor (`--min-severity`) judges the whole patch too.
//!
//! One preference comes first: when exactly one advisory of the package
//! still needs a fix and a patch fixes that advisory and nothing else, that
//! single-advisory patch is taken instead of a merged one
//! ([`Judgement::sole_fix`]). It is the smallest change that fixes what is
//! reachable. A package already on a merged patch that fixes that advisory
//! is left to the usual ranking: it is not traded for the smaller patch.
//!
//! The filter narrows beside the socket.yml policy (both apply;
//! `--no-socket-yml` drops only the file) and, like it, never removes a
//! patch: a recorded package it skips, or whose patches it all withholds,
//! keeps its recorded patch. One thing differs from the severity floor: a
//! recorded patch the filter withholds gives way to a wanted one even
//! when it ranks higher, so the patch that fixes something reachable lands
//! whether or not the package was patched before.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use super::paths::{PathHit, PathMatcher, MAX_PATTERN_BYTES};
use super::socket_yml::package_spec_error;
use super::{package_spec_matches, sanitize, strip_unsafe};
use crate::api::types::PatchSearchResult;
use crate::utils::target::{is_cve_id, is_ghsa_id};

/// Error code of a selection filter that cannot be honored.
pub const FILTER_INVALID: &str = "filter_invalid";

/// The file `version` this build reads.
pub const FILTER_VERSION: u64 = 1;

/// Largest accepted file, in bytes.
pub const MAX_FILTER_BYTES: u64 = 16 * 1024 * 1024;

/// Most entries in `skip.paths` and in `skip.packages` (socket.yml's cap:
/// both are matched against every project root or crawled package).
const MAX_SKIP_ENTRIES: usize = 1000;

/// Most entries in `skip.advisories` and in `reachability`. Findings that
/// name an advisory are looked up by its id. The ones naming only a
/// package are matched one by one against every package a patch is offered
/// for (about 0.1 µs each: 10,000 of them over 200 patched packages cost a
/// quarter of a second), so a caller with many should name the advisory.
const MAX_ADVISORY_ENTRIES: usize = 100_000;

/// Most advisories named in one `filter_not_needed` detail.
const MAX_DETAIL_ADVISORIES: usize = 5;

/// List label of `skip.paths` (the path matcher names lists by label).
const SKIP_PATHS: &str = "skip.paths";

/// A finding's `state`. Ordered by caution: the greatest of several wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reachability {
    Unreachable,
    Unknown,
    Reachable,
}

/// `unlistedAdvisories`: the fate of an advisory no finding covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unlisted {
    #[default]
    Patch,
    Skip,
}

impl Unlisted {
    fn as_str(self) -> &'static str {
        match self {
            Unlisted::Patch => "patch",
            Unlisted::Skip => "skip",
        }
    }
}

/// A selection filter that cannot be honored. `key` is the path of the
/// offending entry (`reachability[3].package`), empty for the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    pub key: String,
    pub message: String,
}

impl FilterError {
    fn file(message: impl Into<String>) -> Self {
        Self {
            key: String::new(),
            message: message.into(),
        }
    }

    fn at(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.key.is_empty() {
            write!(f, "{}", strip_unsafe(&self.message))
        } else {
            write!(f, "{}: {}", self.key, strip_unsafe(&self.message))
        }
    }
}

impl std::error::Error for FilterError {}

/// A JSON object, and only an object: serde's derived structs also accept
/// an array of their fields in order, which this file never means.
#[derive(Default)]
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapOnly<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for MapOnly<T> {
            type Value = T;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        deserializer
            .deserialize_map(MapOnly(std::marker::PhantomData))
            .map(Object)
    }
}

/// Only the version, read first so a file from a newer writer is refused
/// for its version rather than for its first unknown key.
#[derive(Deserialize)]
struct RawVersion {
    version: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawFilter {
    /// Checked through [`RawVersion`].
    #[serde(rename = "version")]
    _version: serde::de::IgnoredAny,
    #[serde(default)]
    skip: Object<RawSkip>,
    #[serde(default)]
    reachability: Vec<Object<RawFinding>>,
    #[serde(default)]
    unlisted_advisories: Unlisted,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawSkip {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    advisories: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFinding {
    #[serde(default)]
    advisory: Option<String>,
    #[serde(default)]
    package: Option<String>,
    state: Reachability,
}

/// Why the filter does not want one advisory fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropped {
    Skipped,
    Unreachable,
    Unlisted,
}

impl Dropped {
    fn as_str(self) -> &'static str {
        match self {
            Dropped::Skipped => "skipped",
            Dropped::Unreachable => "unreachable",
            Dropped::Unlisted => "unlisted",
        }
    }
}

/// How the filter judges the offers of one package
/// ([`SelectionFilter::judge`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judgement {
    /// Per offer, in order: why it is withheld (no advisory it fixes needs
    /// a fix; the detail names each and why), `None` for one wanted whole.
    pub withheld: Vec<Option<String>>,
    /// The indices of the single-advisory patches for the package's one
    /// advisory that needs a fix: the offers that fix it and nothing else.
    /// Empty unless exactly one advisory across the offers needs a fix.
    pub sole_fix: Vec<usize>,
}

/// A parsed, validated selection filter (see the module docs).
#[derive(Debug, Clone)]
pub struct SelectionFilter {
    sha256: String,
    skip_paths: Option<PathMatcher>,
    skip_path_count: usize,
    skip_packages: Vec<String>,
    skip_advisories: HashSet<String>,
    /// Entries of `skip.advisories` as written (the set drops repeats).
    skip_advisory_count: usize,
    unlisted: Unlisted,
    /// Findings naming an advisory, by its id: the package spec they are
    /// limited to (if any) and the state.
    by_advisory: HashMap<String, Vec<(Option<String>, Reachability)>>,
    /// Findings naming only a package.
    by_package: Vec<(String, Reachability)>,
    finding_count: usize,
}

/// The one spelling advisory ids are compared in: the file's, and the ids
/// and CVE aliases of the advisories a patch fixes.
fn canonical_id(id: &str) -> String {
    id.trim().to_ascii_uppercase()
}

/// The canonical spelling of an advisory id (`GHSA-…` or `CVE-…`), or why
/// it is not one.
fn advisory_id(raw: &str) -> Result<String, String> {
    let id = raw.trim();
    if is_ghsa_id(id) || is_cve_id(id) {
        return Ok(canonical_id(id));
    }
    Err(format!(
        "expected a GHSA or CVE id (`GHSA-xxxx-xxxx-xxxx`, `CVE-2024-1234`): `{}`",
        sanitize(id)
    ))
}

/// Why a `--package`-grammar spec of the file is refused, if it is.
fn spec_error(spec: &str) -> Option<String> {
    if spec.len() > MAX_PATTERN_BYTES {
        return Some(format!("is longer than {MAX_PATTERN_BYTES} bytes"));
    }
    let shown = || sanitize(spec);
    if let Some(message) = package_spec_error(spec) {
        return Some(format!("{message}: `{}`", shown()));
    }
    // A bare name is compared with package names whole, so one written
    // with a version (`lodash@4.17.20`) would never match anything.
    let bare = spec.trim();
    let is_purl = bare
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("pkg:"));
    if !is_purl && bare.chars().skip(1).any(|c| c == '@') {
        return Some(format!(
            "a bare name takes no version; write a purl (`pkg:npm/lodash@4.17.20`): `{}`",
            shown()
        ));
    }
    None
}

/// Why a `skip.paths` pattern would silently skip nothing, if it would:
/// gitignore reads a leading `#` as a comment and a lone `!` as no pattern.
fn inert_pattern_error(pattern: &str) -> Option<&'static str> {
    if pattern.starts_with('#') {
        return Some("a leading `#` makes the line a comment; write `\\#` for a literal one");
    }
    if pattern
        .strip_prefix('!')
        .is_some_and(|rest| rest.trim().is_empty())
    {
        return Some("pattern is empty");
    }
    None
}

fn check_len(key: &str, len: usize, max: usize) -> Result<(), FilterError> {
    if len > max {
        return Err(FilterError::at(key, format!("has more than {max} entries")));
    }
    Ok(())
}

impl SelectionFilter {
    /// Read and validate the file at `path`: a regular file (the open never
    /// blocks on a FIFO), read from the opened handle up to the size cap.
    pub fn read(path: &Path) -> Result<Self, FilterError> {
        use std::io::Read as _;
        let cannot_read =
            |e: std::io::Error| FilterError::file(format!("cannot read the file: {e}"));
        let (file, _) = crate::utils::fs::open_regular_file_sync(path).map_err(cannot_read)?;
        let mut bytes = Vec::new();
        // One byte past the cap, so `parse` refuses a larger file.
        file.take(MAX_FILTER_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(cannot_read)?;
        Self::parse(&bytes)
    }

    /// Validate the file's bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, FilterError> {
        if bytes.len() as u64 > MAX_FILTER_BYTES {
            return Err(FilterError::file(format!(
                "larger than {} MiB",
                MAX_FILTER_BYTES / (1024 * 1024)
            )));
        }
        let sha256 = crate::utils::digest::sha256_hex_of(bytes);
        let text = crate::formats::text::strip_bom_bytes(bytes);
        let invalid = |e: serde_json::Error| FilterError::file(format!("invalid JSON: {e}"));
        let Object(RawVersion { version }) = serde_json::from_slice(text).map_err(invalid)?;
        match version.as_ref().map(serde_json::Value::as_u64) {
            Some(Some(FILTER_VERSION)) => {}
            None => return Err(FilterError::at("version", "is required (1)")),
            Some(_) => {
                return Err(FilterError::at(
                    "version",
                    format!(
                        "only version {FILTER_VERSION} is supported (a newer socket-patch may \
                         read this file)"
                    ),
                ))
            }
        }
        let Object(raw): Object<RawFilter> = serde_json::from_slice(text).map_err(invalid)?;
        let Object(skip) = raw.skip;

        check_len("skip.paths", skip.paths.len(), MAX_SKIP_ENTRIES)?;
        check_len("skip.packages", skip.packages.len(), MAX_SKIP_ENTRIES)?;
        check_len(
            "skip.advisories",
            skip.advisories.len(),
            MAX_ADVISORY_ENTRIES,
        )?;
        check_len("reachability", raw.reachability.len(), MAX_ADVISORY_ENTRIES)?;

        for (i, pattern) in skip.paths.iter().enumerate() {
            if let Some(message) = inert_pattern_error(pattern) {
                return Err(FilterError::at(
                    format!("{SKIP_PATHS}[{i}]"),
                    format!("{message}: `{}`", sanitize(pattern)),
                ));
            }
        }
        let skip_paths = if skip.paths.is_empty() {
            None
        } else {
            let lists = [(SKIP_PATHS, skip.paths.as_slice())];
            Some(PathMatcher::new(&lists).map_err(|(_, pattern, message)| {
                let key = match skip.paths.iter().position(|p| *p == pattern) {
                    Some(i) => format!("{SKIP_PATHS}[{i}]"),
                    None => SKIP_PATHS.to_string(),
                };
                FilterError::at(key, format!("{message}: `{}`", sanitize(&pattern)))
            })?)
        };
        for (i, spec) in skip.packages.iter().enumerate() {
            if let Some(message) = spec_error(spec) {
                return Err(FilterError::at(format!("skip.packages[{i}]"), message));
            }
        }
        let mut skip_advisories = HashSet::with_capacity(skip.advisories.len());
        for (i, id) in skip.advisories.iter().enumerate() {
            let id = advisory_id(id)
                .map_err(|message| FilterError::at(format!("skip.advisories[{i}]"), message))?;
            skip_advisories.insert(id);
        }

        let finding_count = raw.reachability.len();
        let mut by_advisory: HashMap<String, Vec<(Option<String>, Reachability)>> = HashMap::new();
        let mut by_package = Vec::new();
        for (i, Object(finding)) in raw.reachability.into_iter().enumerate() {
            let key = |field: &str| format!("reachability[{i}]{field}");
            if let Some(message) = finding.package.as_deref().and_then(spec_error) {
                return Err(FilterError::at(key(".package"), message));
            }
            match (finding.advisory, finding.package) {
                (Some(id), package) => {
                    let id = advisory_id(&id)
                        .map_err(|message| FilterError::at(key(".advisory"), message))?;
                    by_advisory
                        .entry(id)
                        .or_default()
                        .push((package, finding.state));
                }
                (None, Some(package)) => by_package.push((package, finding.state)),
                (None, None) => {
                    return Err(FilterError::at(
                        key(""),
                        "needs an `advisory`, a `package`, or both",
                    ))
                }
            }
        }

        Ok(Self {
            sha256,
            skip_paths,
            skip_path_count: skip.paths.len(),
            skip_packages: skip.packages,
            skip_advisories,
            skip_advisory_count: skip.advisories.len(),
            unlisted: raw.unlisted_advisories,
            by_advisory,
            by_package,
            finding_count,
        })
    }

    /// SHA-256 of the file's bytes, lowercase hex.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Whether the filter skips any project root by path.
    pub fn has_skip_paths(&self) -> bool {
        self.skip_paths.is_some()
    }

    /// The `policy.selectionFilter` JSON block: which file was honored (its
    /// digest, and its entry counts as written).
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "sha256": self.sha256,
            "skip": {
                "paths": self.skip_path_count,
                "packages": self.skip_packages.len(),
                "advisories": self.skip_advisory_count,
            },
            "reachability": self.finding_count,
            "unlistedAdvisories": self.unlisted.as_str(),
        })
    }

    /// The `skip.paths` pattern that excludes a project root, given its
    /// subjects (repo-relative marker paths, or the directory itself; see
    /// [`super::SelectionPolicy::admits_root`]): a root is skipped iff every
    /// subject is.
    pub(super) fn skips_root(&self, subjects: &[(String, bool)]) -> Option<PathHit> {
        super::ignored_by(self.skip_paths.as_ref()?, subjects)
    }

    /// The `skip.packages` spec that names `purl`.
    pub(super) fn skips_package(&self, purl: &str) -> Option<&str> {
        self.skip_packages
            .iter()
            .map(String::as_str)
            .find(|spec| package_spec_matches(spec, purl))
    }

    /// The most cautious state among the findings that name only a
    /// package and match `purl`.
    fn package_state(&self, purl: &str) -> Option<Reachability> {
        self.by_package
            .iter()
            .filter(|(spec, _)| package_spec_matches(spec, purl))
            .map(|(_, state)| *state)
            .max()
    }

    /// Why the advisory known by `ids` (its id and CVE aliases, canonical
    /// spelling) needs no fix on `purl`; `None` when it does.
    fn dropped(
        &self,
        purl: &str,
        ids: &[String],
        package_state: Option<Reachability>,
    ) -> Option<Dropped> {
        if ids.iter().any(|id| self.skip_advisories.contains(id)) {
            return Some(Dropped::Skipped);
        }
        // `Option`'s order puts `None` below every state.
        let mut for_package: Option<Reachability> = None;
        let mut anywhere: Option<Reachability> = None;
        for (spec, state) in ids
            .iter()
            .filter_map(|id| self.by_advisory.get(id))
            .flatten()
        {
            match spec {
                Some(spec) if package_spec_matches(spec, purl) => {
                    for_package = for_package.max(Some(*state));
                }
                Some(_) => {}
                None => anywhere = anywhere.max(Some(*state)),
            }
        }
        match for_package.or(anywhere).or(package_state) {
            Some(Reachability::Unreachable) => Some(Dropped::Unreachable),
            Some(Reachability::Reachable | Reachability::Unknown) => None,
            None => match self.unlisted {
                Unlisted::Patch => None,
                Unlisted::Skip => Some(Dropped::Unlisted),
            },
        }
    }

    /// Each advisory `offer` fixes, by id, with why it needs no fix
    /// (`None`: it does), sorted by id.
    fn verdicts<'a>(
        &self,
        offer: &'a PatchSearchResult,
        package_state: Option<Reachability>,
    ) -> Vec<(&'a str, Option<Dropped>)> {
        let mut verdicts: Vec<(&str, Option<Dropped>)> = offer
            .vulnerabilities
            .iter()
            .map(|(id, advisory)| {
                let ids: Vec<String> = std::iter::once(id)
                    .chain(&advisory.cves)
                    .map(|id| canonical_id(id))
                    .collect();
                (id.as_str(), self.dropped(&offer.purl, &ids, package_state))
            })
            .collect();
        verdicts.sort_by(|a, b| a.0.cmp(b.0));
        verdicts
    }

    /// Judge one package's `offers` together (see the module docs): which
    /// are withheld, and which the one preference singles out.
    pub fn judge(&self, offers: &[PatchSearchResult]) -> Judgement {
        // Offers of one package share a purl: its package-only findings
        // are matched once, not per offer.
        let mut package: Option<(&str, Option<Reachability>)> = None;
        let mut needed: HashSet<String> = HashSet::new();
        let mut withheld = Vec::with_capacity(offers.len());
        for offer in offers {
            let state = match package {
                Some((purl, state)) if purl == offer.purl => state,
                _ => {
                    let state = self.package_state(&offer.purl);
                    package = Some((&offer.purl, state));
                    state
                }
            };
            let verdicts = self.verdicts(offer, state);
            needed.extend(
                verdicts
                    .iter()
                    .filter(|(_, why)| why.is_none())
                    .map(|(id, _)| canonical_id(id)),
            );
            withheld.push(self.withheld_detail(offer, state, &verdicts));
        }
        let mut needed = needed.into_iter();
        let sole_fix = match (needed.next(), needed.next()) {
            (Some(only), None) => offers
                .iter()
                .enumerate()
                .filter(|(_, offer)| {
                    let mut ids = offer.vulnerabilities.keys();
                    matches!((ids.next(), ids.next()), (Some(id), None) if canonical_id(id) == only)
                })
                .map(|(i, _)| i)
                .collect(),
            _ => Vec::new(),
        };
        Judgement { withheld, sole_fix }
    }

    /// Why `offer` is not wanted: no advisory it fixes still needs a fix
    /// (the detail names each one and why). `None` when at least one does;
    /// the offer is then wanted whole, with whatever else it fixes.
    pub fn withholds(&self, offer: &PatchSearchResult) -> Option<String> {
        let state = self.package_state(&offer.purl);
        self.withheld_detail(offer, state, &self.verdicts(offer, state))
    }

    /// [`Self::withholds`] from the offer's verdicts.
    fn withheld_detail(
        &self,
        offer: &PatchSearchResult,
        package_state: Option<Reachability>,
        verdicts: &[(&str, Option<Dropped>)],
    ) -> Option<String> {
        // A patch that names no advisory has only its package to go by.
        if offer.vulnerabilities.is_empty() {
            return match (package_state, self.unlisted) {
                (Some(Reachability::Unreachable), _) => Some("package unreachable".to_string()),
                (None, Unlisted::Skip) => {
                    Some("names no advisory (unlistedAdvisories: skip)".to_string())
                }
                _ => None,
            };
        }
        let dropped: Vec<(&str, Dropped)> = verdicts
            .iter()
            .map(|(id, why)| why.map(|why| (*id, why)))
            .collect::<Option<_>>()?;
        let mut names: Vec<String> = dropped
            .iter()
            .take(MAX_DETAIL_ADVISORIES)
            .map(|(id, why)| format!("{} {}", sanitize(id), why.as_str()))
            .collect();
        if dropped.len() > MAX_DETAIL_ADVISORIES {
            names.push(format!("{} more", dropped.len() - MAX_DETAIL_ADVISORIES));
        }
        Some(names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::VulnerabilityResponse;

    fn filter(json: &str) -> SelectionFilter {
        SelectionFilter::parse(json.as_bytes()).expect("valid filter")
    }

    fn err(json: &str) -> String {
        SelectionFilter::parse(json.as_bytes())
            .expect_err("invalid filter")
            .to_string()
    }

    /// An offer for `purl` fixing `advisories`: `(id, severity, cves)`.
    fn offer(purl: &str, advisories: &[(&str, &str, &[&str])]) -> PatchSearchResult {
        PatchSearchResult {
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            purl: purl.to_string(),
            published_at: String::new(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
            vulnerabilities: advisories
                .iter()
                .map(|(id, severity, cves)| {
                    (
                        id.to_string(),
                        VulnerabilityResponse {
                            cves: cves.iter().map(|c| c.to_string()).collect(),
                            summary: String::new(),
                            severity: severity.to_string(),
                            description: String::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// The advisory ids `filter` still wants fixed by `offer`, sorted
    /// (the offer is wanted); `Err` is the detail of an offer it withholds.
    fn needed(filter: &SelectionFilter, offer: &PatchSearchResult) -> Result<Vec<String>, String> {
        if let Some(detail) = filter.withholds(offer) {
            return Err(detail);
        }
        let package_state = filter.package_state(&offer.purl);
        Ok(filter
            .verdicts(offer, package_state)
            .into_iter()
            .filter(|(_, why)| why.is_none())
            .map(|(id, _)| id.to_string())
            .collect())
    }

    /// Whether `filter` wants every advisory `offer` fixes.
    fn needs_all(filter: &SelectionFilter, offer: &PatchSearchResult) -> bool {
        needed(filter, offer).is_ok_and(|ids| ids.len() == offer.vulnerabilities.len())
    }

    const A: &str = "GHSA-aaaa-aaaa-aaaa";
    const B: &str = "GHSA-bbbb-bbbb-bbbb";
    const LODASH: &str = "pkg:npm/lodash@4.17.20";

    #[test]
    fn version_alone_filters_nothing() {
        let f = filter(r#"{"version": 1}"#);
        let o = offer(LODASH, &[(A, "high", &[])]);
        assert!(needs_all(&f, &o));
        assert!(f.skips_package(LODASH).is_none());
        assert!(f
            .skips_root(&[("package-lock.json".to_string(), false)])
            .is_none());
        assert_eq!(
            f.summary(),
            serde_json::json!({
                "sha256": crate::utils::digest::sha256_hex_of(br#"{"version": 1}"#),
                "skip": {"paths": 0, "packages": 0, "advisories": 0},
                "reachability": 0,
                "unlistedAdvisories": "patch",
            })
        );
    }

    #[test]
    fn a_bom_is_fine_and_the_digest_covers_the_bytes_as_given() {
        let bytes = b"\xEF\xBB\xBF{\"version\": 1}";
        let f = SelectionFilter::parse(bytes).unwrap();
        assert_eq!(f.sha256(), crate::utils::digest::sha256_hex_of(bytes));
    }

    #[test]
    fn the_version_is_checked_before_the_keys() {
        assert_eq!(err("{}"), "version: is required (1)");
        let newer = err(r#"{"version": 2, "someNewKey": true}"#);
        assert!(
            newer.starts_with("version: only version 1 is supported"),
            "{newer}"
        );
        assert!(err(r#"{"version": "1"}"#).starts_with("version: only version 1"));
        assert!(
            err("[]").starts_with("invalid JSON: invalid type: sequence, expected an object"),
            "{}",
            err("[]")
        );
        assert!(err("{\"version\": 1,").starts_with("invalid JSON: "));
    }

    #[test]
    fn unknown_keys_types_and_states_are_errors() {
        let e = err(r#"{"version": 1, "skips": {}}"#);
        assert!(e.contains("unknown field `skips`"), "{e}");
        let e = err(r#"{"version": 1, "skip": {"ghsas": []}}"#);
        assert!(e.contains("unknown field `ghsas`"), "{e}");
        let e = err(r#"{"version": 1, "skip": {"packages": "lodash"}}"#);
        assert!(e.contains("invalid type"), "{e}");
        // serde's derived structs would read an array as their fields in
        // order; every object of this file must be written as one.
        let e = err(r#"{"version": 1, "skip": [["a/"], ["lodash"], []]}"#);
        assert!(
            e.contains("invalid type: sequence, expected an object"),
            "{e}"
        );
        let e = err(r#"{"version": 1, "reachability": [["GHSA-a", null, "reachable"]]}"#);
        assert!(
            e.contains("invalid type: sequence, expected an object"),
            "{e}"
        );
        let e = err(r#"{"version": 1, "skip": null}"#);
        assert!(e.contains("expected an object"), "{e}");
        let e =
            err(r#"{"version": 1, "reachability": [{"advisory": "GHSA-a", "state": "maybe"}]}"#);
        assert!(e.contains("unknown variant `maybe`"), "{e}");
        let e = err(r#"{"version": 1, "reachability": [{"advisory": "GHSA-a"}]}"#);
        assert!(e.contains("missing field `state`"), "{e}");
        let e = err(r#"{"version": 1, "unlistedAdvisories": "drop"}"#);
        assert!(e.contains("unknown variant `drop`"), "{e}");
        let e = err(r#"{"version": 1, "version": 1}"#);
        assert!(e.contains("duplicate field"), "{e}");
    }

    #[test]
    fn entries_are_validated_with_their_key_path() {
        assert_eq!(
            err(r#"{"version": 1, "reachability": [{"state": "reachable"}]}"#),
            "reachability[0]: needs an `advisory`, a `package`, or both"
        );
        let e = err(r#"{"version": 1, "skip": {"advisories": ["CVE-2021-23337", "lodash"]}}"#);
        assert!(
            e.starts_with("skip.advisories[1]: expected a GHSA or CVE id"),
            "{e}"
        );
        assert!(e.ends_with("`lodash`"), "{e}");
        // A truncated id would match nothing: refused, not ignored.
        for truncated in ["GHSA-35jh-r3h4", "CVE-2021", "GHSA-35jh-r3h4-6jhmx"] {
            let json = serde_json::json!({"version": 1, "skip": {"advisories": [truncated]}});
            let e = err(&json.to_string());
            assert!(e.starts_with("skip.advisories[0]: expected a GHSA"), "{e}");
        }
        let e =
            err(r#"{"version": 1, "reachability": [{"advisory": "GHSA-", "state": "unknown"}]}"#);
        assert!(
            e.starts_with("reachability[0].advisory: expected a GHSA"),
            "{e}"
        );
        let e = err(r#"{"version": 1, "skip": {"packages": ["ok", "pkg:npm"]}}"#);
        assert!(
            e.starts_with("skip.packages[1]: purl spec needs a type"),
            "{e}"
        );
        let e =
            err(r#"{"version": 1, "reachability": [{"package": " ", "state": "unreachable"}]}"#);
        assert!(
            e.starts_with("reachability[0].package: package spec is empty"),
            "{e}"
        );
        // Entries that could never match are refused, not silently inert.
        for spec in ["lodash@4.17.20", "@scope/pkg@1.0.0"] {
            let json = serde_json::json!({"version": 1, "skip": {"packages": [spec]}});
            let e = err(&json.to_string());
            assert!(
                e.starts_with("skip.packages[0]: a bare name takes no version"),
                "{e}"
            );
            let json = serde_json::json!({
                "version": 1,
                "reachability": [{"package": spec, "state": "unreachable"}],
            });
            let e = err(&json.to_string());
            assert!(e.starts_with("reachability[0].package: a bare name"), "{e}");
        }
        filter(r#"{"version": 1, "skip": {"packages": ["@scope/pkg", "pkg:npm/%40s/p@1.0.0"]}}"#);
        let e = err(r##"{"version": 1, "skip": {"paths": ["ok/", "#services/legacy/"]}}"##);
        assert!(
            e.starts_with("skip.paths[1]: a leading `#` makes the line a comment"),
            "{e}"
        );
        let e = err(r#"{"version": 1, "skip": {"paths": ["! "]}}"#);
        assert!(e.starts_with("skip.paths[0]: pattern is empty"), "{e}");
        filter(r#"{"version": 1, "skip": {"paths": ["\\#literal/", "!keep/"]}}"#);
        let e = err(r#"{"version": 1, "skip": {"paths": ["ok/", "../up"]}}"#);
        assert!(
            e.starts_with("skip.paths[1]: pattern contains a `..`"),
            "{e}"
        );
    }

    #[test]
    fn an_oversize_file_is_refused() {
        let mut bytes = br#"{"version": 1}"#.to_vec();
        bytes.resize(MAX_FILTER_BYTES as usize + 1, b' ');
        let e = SelectionFilter::parse(&bytes).unwrap_err();
        assert_eq!(e.to_string(), "larger than 16 MiB");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        std::fs::write(&path, &bytes).unwrap();
        let e = SelectionFilter::read(&path).unwrap_err();
        assert_eq!(e.to_string(), "larger than 16 MiB");
        bytes.truncate(MAX_FILTER_BYTES as usize);
        SelectionFilter::parse(&bytes).unwrap();
    }

    #[test]
    fn list_sizes_are_capped() {
        let specs = vec!["lodash"; MAX_SKIP_ENTRIES + 1];
        let json = serde_json::json!({"version": 1, "skip": {"packages": specs}}).to_string();
        assert_eq!(err(&json), "skip.packages: has more than 1000 entries");
        let ok = vec!["lodash"; MAX_SKIP_ENTRIES];
        let json = serde_json::json!({"version": 1, "skip": {"packages": ok}}).to_string();
        filter(&json);
    }

    #[test]
    fn skip_paths_follow_the_marker_rule_and_negations() {
        let f = filter(r#"{"version": 1, "skip": {"paths": ["apps/*/", "!apps/web/"]}}"#);
        let subject = |p: &str| vec![(p.to_string(), false)];
        let hit = f
            .skips_root(&subject("apps/admin/package-lock.json"))
            .unwrap();
        assert_eq!(hit.pattern, "apps/*/");
        assert!(f
            .skips_root(&subject("apps/web/package-lock.json"))
            .is_none());
        assert!(f.skips_root(&subject("package-lock.json")).is_none());
        // A root is skipped only when every marker is.
        let f = filter(r#"{"version": 1, "skip": {"paths": ["**/yarn.lock"]}}"#);
        assert!(f.skips_root(&subject("yarn.lock")).is_some());
        assert!(f
            .skips_root(&[
                ("yarn.lock".to_string(), false),
                ("Cargo.lock".to_string(), false)
            ])
            .is_none());
    }

    #[test]
    fn skip_packages_use_the_package_grammar() {
        let f = filter(r#"{"version": 1, "skip": {"packages": ["pkg:npm/lodash", "Requests"]}}"#);
        assert_eq!(f.skips_package(LODASH), Some("pkg:npm/lodash"));
        assert_eq!(
            f.skips_package("pkg:pypi/requests@2.31.0"),
            Some("Requests")
        );
        assert!(f.skips_package("pkg:npm/lodash.merge@4.6.2").is_none());
    }

    /// The echo counts entries as written, repeats included.
    #[test]
    fn the_summary_counts_entries_as_written() {
        let f = filter(
            r#"{"version": 1, "skip": {
                "advisories": ["GHSA-aaaa-aaaa-aaaa", "ghsa-AAAA-aaaa-aaaa"],
                "packages": ["lodash", "lodash"]
            }}"#,
        );
        assert_eq!(
            f.summary()["skip"],
            serde_json::json!({"paths": 0, "packages": 2, "advisories": 2})
        );
    }

    #[test]
    fn skipped_advisories_match_by_id_or_cve_alias_in_any_case() {
        let f = filter(
            r#"{"version": 1, "skip": {"advisories": ["ghsa-AAAA-aaaa-aaaa", "cve-2021-23337"]}}"#,
        );
        let o = offer(
            LODASH,
            &[
                (A, "critical", &[]),
                (B, "high", &["CVE-2021-23337"]),
                ("GHSA-cccc-cccc-cccc", "low", &[]),
            ],
        );
        assert_eq!(needed(&f, &o).unwrap(), ["GHSA-cccc-cccc-cccc"]);
        let all = offer(LODASH, &[(A, "critical", &[])]);
        assert_eq!(needed(&f, &all).unwrap_err(), format!("{A} skipped"));
    }

    #[test]
    fn a_patch_is_withheld_only_when_nothing_it_fixes_is_needed() {
        let f = filter(&format!(
            r#"{{"version": 1, "reachability": [
                {{"advisory": "{A}", "state": "unreachable"}},
                {{"advisory": "{B}", "state": "unknown"}}
            ]}}"#
        ));
        // One needed advisory makes the patch wanted, whatever else it fixes.
        let o = offer(LODASH, &[(A, "critical", &[]), (B, "low", &[])]);
        assert_eq!(f.withholds(&o), None);
        assert_eq!(needed(&f, &o).unwrap(), [B]);
        // An advisory no finding covers is unknown: patched.
        let unlisted = offer(LODASH, &[("GHSA-cccc-cccc-cccc", "low", &[])]);
        assert!(needs_all(&f, &unlisted));
        let gone = offer(LODASH, &[(A, "critical", &[])]);
        assert_eq!(needed(&f, &gone).unwrap_err(), format!("{A} unreachable"));
    }

    /// The one preference: a package left with exactly one advisory that
    /// needs a fix prefers the patches that fix it and nothing else.
    #[test]
    fn a_single_needed_advisory_prefers_its_single_advisory_patches() {
        const C: &str = "GHSA-cccc-cccc-cccc";
        let unreachable = |id: &str| {
            filter(&format!(
                r#"{{"version": 1, "reachability": [{{"advisory": "{id}", "state": "unreachable"}}]}}"#
            ))
        };
        let merged = offer(LODASH, &[(A, "critical", &[]), (B, "high", &[])]);
        let single = offer(LODASH, &[(B, "high", &[])]);
        let other = offer(LODASH, &[(A, "critical", &[])]);

        // Only B needs a fix, and two patches fix B alone.
        let f = unreachable(A);
        let sole_fix = |f: &SelectionFilter, offers: &[PatchSearchResult]| f.judge(offers).sole_fix;
        let offers = [
            merged.clone(),
            single.clone(),
            other.clone(),
            single.clone(),
        ];
        let judged = f.judge(&offers);
        assert_eq!(judged.sole_fix, [1, 3]);
        // The same call says what is withheld: only the patch for A alone.
        assert_eq!(
            judged.withheld,
            [None, None, Some(format!("{A} unreachable")), None]
        );
        // No patch fixes B alone: nothing to prefer.
        assert!(sole_fix(&f, &[merged.clone(), other.clone()]).is_empty());
        // The id's letter case does not matter.
        let lower = offer(LODASH, &[(&B.to_lowercase(), "high", &[])]);
        assert_eq!(sole_fix(&f, &[merged.clone(), lower]), [1]);

        // Two advisories need a fix: the usual ranking decides.
        let plain = filter(r#"{"version": 1}"#);
        assert!(sole_fix(&plain, &[merged.clone(), single.clone()]).is_empty());
        let with_c = offer(LODASH, &[(A, "critical", &[]), (C, "low", &[])]);
        assert!(sole_fix(&f, &[with_c, single.clone()]).is_empty());
        // None needs a fix: nothing to prefer either.
        let none = filter(
            r#"{"version": 1, "reachability": [{"package": "lodash", "state": "unreachable"}]}"#,
        );
        assert!(sole_fix(&none, &[merged, single]).is_empty());
        assert_eq!(f.judge(&[]), Judgement::default());
    }

    #[test]
    fn the_most_specific_finding_decides() {
        let f = filter(&format!(
            r#"{{"version": 1, "reachability": [
                {{"package": "pkg:npm/lodash", "state": "unreachable"}},
                {{"advisory": "{A}", "state": "reachable"}},
                {{"advisory": "{A}", "package": "pkg:npm/lodash@4.17.20", "state": "unreachable"}},
                {{"advisory": "{B}", "package": "pkg:npm/lodash@4.17.20", "state": "reachable"}}
            ]}}"#
        ));
        // Advisory + package beats the advisory alone, which beats the package.
        let o = offer(LODASH, &[(A, "high", &[]), (B, "high", &[])]);
        assert_eq!(needed(&f, &o).unwrap(), [B]);
        // Another version: only the advisory-wide and package findings apply.
        let other = offer(
            "pkg:npm/lodash@4.17.19",
            &[(A, "high", &[]), (B, "high", &[])],
        );
        assert_eq!(needed(&f, &other).unwrap(), [A]);
        // Another package: only the advisory-wide finding applies.
        let elsewhere = offer("pkg:npm/underscore@1.0.0", &[(B, "high", &[])]);
        assert!(needs_all(&f, &elsewhere));
    }

    #[test]
    fn among_equally_specific_findings_the_most_cautious_wins() {
        let f = filter(&format!(
            r#"{{"version": 1, "reachability": [
                {{"advisory": "{A}", "package": "lodash", "state": "unreachable"}},
                {{"advisory": "{A}", "package": "pkg:npm/lodash@4.17.20", "state": "unknown"}},
                {{"package": "pkg:npm/minimist", "state": "unreachable"}},
                {{"package": "minimist", "state": "reachable"}}
            ]}}"#
        ));
        assert!(needs_all(&f, &offer(LODASH, &[(A, "high", &[])])));
        assert!(needs_all(
            &f,
            &offer("pkg:npm/minimist@1.2.5", &[(B, "high", &[])])
        ));
    }

    #[test]
    fn an_unreachable_package_needs_no_patch_at_all() {
        let f = filter(
            r#"{"version": 1, "reachability": [{"package": "pkg:npm/lodash", "state": "unreachable"}]}"#,
        );
        let o = offer(LODASH, &[(A, "critical", &[]), (B, "low", &[])]);
        assert_eq!(
            needed(&f, &o).unwrap_err(),
            format!("{A} unreachable, {B} unreachable")
        );
        assert_eq!(
            needed(&f, &offer(LODASH, &[])).unwrap_err(),
            "package unreachable"
        );
    }

    #[test]
    fn unlisted_skip_turns_the_findings_into_an_allowlist() {
        let f = filter(&format!(
            r#"{{"version": 1, "unlistedAdvisories": "skip",
                "reachability": [{{"advisory": "{A}", "state": "reachable"}}]}}"#
        ));
        let o = offer(LODASH, &[(A, "low", &[]), (B, "critical", &[])]);
        assert_eq!(needed(&f, &o).unwrap(), [A]);
        let other = offer(LODASH, &[(B, "critical", &[])]);
        assert_eq!(needed(&f, &other).unwrap_err(), format!("{B} unlisted"));
        assert_eq!(
            needed(&f, &offer(LODASH, &[])).unwrap_err(),
            "names no advisory (unlistedAdvisories: skip)"
        );
        // Without `skip`, a patch naming no advisory is unknown: patched.
        let patch = filter(r#"{"version": 1}"#);
        assert_eq!(patch.withholds(&offer(LODASH, &[])), None);
    }

    #[test]
    fn a_long_not_needed_detail_is_capped() {
        let f = filter(
            r#"{"version": 1, "reachability": [{"package": "lodash", "state": "unreachable"}]}"#,
        );
        let ids: Vec<String> = (0..7).map(|i| format!("GHSA-aaaa-aaaa-aaa{i}")).collect();
        let advisories: Vec<(&str, &str, &[&str])> =
            ids.iter().map(|id| (id.as_str(), "low", &[][..])).collect();
        let detail = needed(&f, &offer(LODASH, &advisories)).unwrap_err();
        assert!(
            detail.ends_with("GHSA-aaaa-aaaa-aaa4 unreachable, 2 more"),
            "{detail}"
        );
        assert!(
            detail.starts_with("GHSA-aaaa-aaaa-aaa0 unreachable, "),
            "{detail}"
        );
    }

    /// The names serde lists after "expected" in an unknown-field or
    /// unknown-variant error: the parser's own key or value set.
    fn expected_names(error: &str) -> Vec<String> {
        let (_, expected) = error.split_once("expected").expect(error);
        let mut names: Vec<String> = expected
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect();
        names.sort();
        names
    }

    /// `docs/selection-filter.schema.json` describes this parser: its
    /// examples parse, and its keys, enumerations, limits and advisory-id
    /// pattern are the parser's own.
    #[test]
    fn the_published_schema_agrees_with_the_parser() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/selection-filter.schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let names = |value: &serde_json::Value| {
            let mut names: Vec<String> = match value {
                serde_json::Value::Object(map) => map.keys().cloned().collect(),
                serde_json::Value::Array(items) => items
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect(),
                other => panic!("{other}"),
            };
            names.sort();
            names
        };

        let examples = schema["examples"].as_array().unwrap();
        assert!(!examples.is_empty());
        for example in examples {
            SelectionFilter::parse(example.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("schema example does not parse: {e}\n{example:#}"));
        }
        assert_eq!(schema["properties"]["version"]["const"], FILTER_VERSION);

        // Keys: what the parser says it expects, level by level.
        let skip = &schema["properties"]["skip"];
        let finding = &schema["$defs"]["finding"];
        assert_eq!(
            names(&schema["properties"]),
            expected_names(&err(r#"{"version": 1, "x": 0}"#))
        );
        assert_eq!(
            names(&skip["properties"]),
            expected_names(&err(r#"{"version": 1, "skip": {"x": 0}}"#))
        );
        assert_eq!(
            names(&finding["properties"]),
            expected_names(&err(r#"{"version": 1, "reachability": [{"x": 0}]}"#))
        );

        // Enumerations.
        assert_eq!(
            names(&finding["properties"]["state"]["enum"]),
            expected_names(&err(
                r#"{"version": 1, "reachability": [{"package": "a", "state": "x"}]}"#
            ))
        );
        assert_eq!(
            names(&schema["properties"]["unlistedAdvisories"]["enum"]),
            expected_names(&err(r#"{"version": 1, "unlistedAdvisories": "x"}"#))
        );
        assert_eq!(
            schema["properties"]["unlistedAdvisories"]["default"],
            Unlisted::default().as_str()
        );

        // Limits.
        let max = |value: &serde_json::Value, key: &str| value[key].as_u64().unwrap() as usize;
        assert_eq!(
            max(&skip["properties"]["paths"], "maxItems"),
            MAX_SKIP_ENTRIES
        );
        assert_eq!(
            max(&skip["properties"]["packages"], "maxItems"),
            MAX_SKIP_ENTRIES
        );
        assert_eq!(
            max(&skip["properties"]["advisories"], "maxItems"),
            MAX_ADVISORY_ENTRIES
        );
        assert_eq!(
            max(&schema["properties"]["reachability"], "maxItems"),
            MAX_ADVISORY_ENTRIES
        );
        for def in ["pathPattern", "packageSpec"] {
            assert_eq!(max(&schema["$defs"][def], "maxLength"), MAX_PATTERN_BYTES);
        }

        // The package-spec and path patterns never refuse what the parser
        // accepts, and refuse the entries that could never match.
        let compiled = |def: &str| {
            regex::Regex::new(schema["$defs"][def]["pattern"].as_str().unwrap()).unwrap()
        };
        let spec = compiled("packageSpec");
        for (text, valid) in [
            ("lodash", true),
            ("@scope/pkg", true),
            (" Requests ", true),
            ("group:artifact", true),
            ("pkg:npm/lodash", true),
            ("PKG:npm/%40scope/pkg@1.0.0?arch=x", true),
            ("lodash@4.17.20", false),
            ("@scope/pkg@1.0.0", false),
            ("", false),
            ("  ", false),
        ] {
            assert_eq!(spec_error(text).is_none(), valid, "{text:?}");
            assert_eq!(spec.is_match(text), valid, "{text:?}");
        }
        let path = compiled("pathPattern");
        for (text, valid) in [
            ("services/legacy/", true),
            ("!apps/web/", true),
            ("**/yarn.lock", true),
            ("\\#literal/", true),
            ("#services/legacy/", false),
            ("", false),
            ("   ", false),
        ] {
            let json = serde_json::json!({"version": 1, "skip": {"paths": [text]}});
            let parsed = SelectionFilter::parse(json.to_string().as_bytes());
            assert_eq!(parsed.is_ok(), valid, "{text:?}: {:?}", parsed.err());
            assert_eq!(path.is_match(text), valid, "{text:?}");
        }

        // The advisory-id pattern accepts exactly what the parser does.
        let pattern = schema["$defs"]["advisoryId"]["pattern"].as_str().unwrap();
        let pattern = regex::Regex::new(pattern).unwrap();
        for id in [
            "GHSA-35jh-r3h4-6jhm",
            "ghsa-35JH-r3h4-6jhm",
            "CVE-2021-23337",
            "cve-1999-1",
            "GHSA-35jh-r3h4",
            "GHSA-35jh-r3h4-6jhmx",
            "GHSA-35jh-r3h4-6jh_",
            "CVE-2021",
            "CVE-21-23337",
            "CVE-2021-",
            "CVE-2021-2333x",
            "pkg:npm/lodash",
            "lodash",
            "",
        ] {
            assert_eq!(pattern.is_match(id), advisory_id(id).is_ok(), "{id:?}");
        }
    }

    #[test]
    fn read_refuses_a_missing_file_and_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let e = SelectionFilter::read(&dir.path().join("none.json")).unwrap_err();
        assert!(e.to_string().starts_with("cannot read the file: "), "{e}");
        let e = SelectionFilter::read(dir.path()).unwrap_err();
        assert!(e.to_string().starts_with("cannot read the file: "), "{e}");
        let path = dir.path().join("filter.json");
        std::fs::write(&path, r#"{"version": 1}"#).unwrap();
        SelectionFilter::read(&path).unwrap();
    }
}
