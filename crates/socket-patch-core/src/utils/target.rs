//! The one package-target grammar.
//!
//! Every verb that takes a "which patch / which package" token — `get`'s
//! positional identifier, `remove`'s identifier, `rollback`'s targets, the
//! root `socket-patch <UUID>` shortcut — classifies it here, so the same
//! token means the same thing everywhere:
//!
//! * a UUID (`8-4-4-4-12` hex, any case) names one patch;
//! * `CVE-YYYY-N…` / `GHSA-xxxx-xxxx-xxxx` (any case) name an advisory;
//! * a `pkg:` token is a purl — with a version it names one release (a base
//!   purl covers every release variant, a `?qualified` one exactly one
//!   variant); without a version it names every installed version of the
//!   same package ([`package_identity`], the [`PurlKey`] identity: case
//!   folds only where the ecosystem folds it, PyPI, NuGet and Composer);
//! * anything else is a package name, matched EXACTLY (full name or last
//!   segment, case-insensitive, PEP 503 for PyPI) by
//!   [`crate::policy::package_spec_matches`] — the matcher `scan --package`
//!   and `socket.yml` already use. There is no fuzzy matching here. A Go
//!   major-version suffix (`v2` in `github.com/x/y/v2`) is never a name.
//!
//! A name's last-segment rule can select several packages (`core` →
//! `@angular/core` and `@babel/core`), and its case-insensitive rule
//! several case-distinct ones (`jsonstream` → npm's `JSONStream` and
//! `jsonstream`, Go's `Sirupsen` and `sirupsen`). `get`, `remove` and
//! `rollback` act on one package per name, so they refuse such a name
//! ([`Target::ambiguity`]) and ask for the full name or a purl;
//! `scan --package` and `socket.yml` keep selecting all of them.
//!
//! Verbs reject the kinds they cannot act on (a CVE matches no manifest
//! entry, for example) rather than reinterpreting them.

use std::fmt;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::policy::package_spec_matches;
use crate::utils::purl::{is_purl, purl_matches_identifier, strip_purl_qualifiers};
use crate::utils::purl_key::{canonical_base_purl, PurlKey};

/// What a target token names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Uuid,
    Cve,
    Ghsa,
    Purl,
    /// A bare package name (`lodash`, `@scope/pkg`, `group:artifact`,
    /// `github.com/org/mod`).
    Name,
}

impl fmt::Display for TargetKind {
    /// User-facing vocabulary ("No patches found for CVE: …").
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TargetKind::Uuid => "UUID",
            TargetKind::Cve => "CVE",
            TargetKind::Ghsa => "GHSA",
            TargetKind::Purl => "PURL",
            TargetKind::Name => "package name",
        })
    }
}

/// One classified target token. The text is kept verbatim (it is what
/// error messages echo and what API searches send).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    kind: TargetKind,
    text: String,
    /// Set by [`Target::settle`] when a name's full-name match won over
    /// last-segment ones, or its exact-case spelling over case-distinct
    /// packages: the name then selects only that package
    /// ([`package_identity`]).
    only: Option<String>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Target {
    /// Classify `token` by shape: UUID, then CVE, then GHSA, then purl;
    /// everything else is a package name. Never fails.
    pub fn parse(token: &str) -> Self {
        let kind = if is_uuid_shaped(token) {
            TargetKind::Uuid
        } else if is_cve_id(token) {
            TargetKind::Cve
        } else if is_ghsa_id(token) {
            TargetKind::Ghsa
        } else if is_purl(token) {
            TargetKind::Purl
        } else {
            TargetKind::Name
        };
        Self::with_kind(token, kind)
    }

    /// A token whose kind the caller forced (`get --id/--cve/--ghsa/
    /// --package`). [`Self::shape_ok`] says whether the text fits it.
    pub fn with_kind(token: &str, kind: TargetKind) -> Self {
        Self {
            kind,
            text: token.to_string(),
            only: None,
        }
    }

    pub fn kind(&self) -> TargetKind {
        self.kind
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Does the text have its kind's shape? Always true for a parsed
    /// target; a forced UUID/CVE/GHSA can fail it. Purls and names are
    /// free-form.
    pub fn shape_ok(&self) -> bool {
        match self.kind {
            TargetKind::Uuid => is_uuid_shaped(&self.text),
            TargetKind::Cve => is_cve_id(&self.text),
            TargetKind::Ghsa => is_ghsa_id(&self.text),
            TargetKind::Purl | TargetKind::Name => true,
        }
    }

    /// A purl target that names an exact version (`pkg:type/name@ver`).
    /// npm scope `@`s don't count: `pkg:npm/@scope/name` is versionless.
    pub fn is_versioned_purl(&self) -> bool {
        self.kind == TargetKind::Purl && purl_has_version(&self.text)
    }

    /// Does this target select the installed package `purl`? Purls and
    /// names only: a versioned purl selects that release ([`PurlKey`],
    /// qualifiers ignored), a versionless purl or a name selects every
    /// version.
    pub fn matches_package(&self, purl: &str) -> bool {
        match self.kind {
            TargetKind::Purl if purl_has_version(&self.text) => PurlKey::same(purl, &self.text),
            TargetKind::Purl => self.same_package(purl),
            TargetKind::Name => self.name_matches(purl),
            TargetKind::Uuid | TargetKind::Cve | TargetKind::Ghsa => false,
        }
    }

    /// A versionless purl target: does `purl` have the target's
    /// [`package_identity`]?
    fn same_package(&self, purl: &str) -> bool {
        package_identity(&self.text)
            .is_some_and(|target| package_identity(purl).is_some_and(|other| other == target))
    }

    /// The name rule: [`package_spec_matches`], except that a Go
    /// major-version suffix (`v2`) never selects a module by its last
    /// segment (`github.com/x/y/v2` is `y`, major version 2).
    fn name_matches(&self, purl: &str) -> bool {
        if is_go_major_suffix(self.text.trim()) && is_golang_purl(purl) {
            return false;
        }
        package_spec_matches(&self.text, purl)
            && self
                .only
                .as_ref()
                .is_none_or(|only| package_identity(purl).as_ref() == Some(only))
    }

    /// For a package name, the distinct packages it selects among `purls`
    /// when there is more than one: `Some(message)` naming each (as a
    /// versionless purl) and how to pick one. `None` for every other kind,
    /// and for a name that selects one package (any number of its
    /// versions) or none.
    pub fn ambiguity<'a>(&self, purls: impl IntoIterator<Item = &'a str>) -> Option<String> {
        self.settle(purls).err()
    }

    /// [`Self::ambiguity`] as the target to act on: `Err(message)` for an
    /// ambiguous name, otherwise the target narrowed to what the check
    /// settled on. A name whose full-name match won over last-segment
    /// ones (`lodash` beside `@types/lodash`) selects only the full name
    /// from then on; every other target comes back unchanged.
    ///
    /// Packages are counted by [`package_identity`], so case-distinct
    /// npm, Go, Maven, cargo and gem packages are two. A name typed with
    /// an uppercase letter settles on its exact-case spelling among them
    /// (`JSONStream`); an all-lowercase name reaching both is ambiguous
    /// (`jsonstream`), since lowercase is how any name may be typed.
    ///
    /// `get`, `remove` and `rollback` refuse an ambiguous name instead of
    /// acting on every package it reaches by last segment, and act on the
    /// settled target so they never select more than the check allowed.
    pub fn settle<'a>(&self, purls: impl IntoIterator<Item = &'a str>) -> Result<Target, String> {
        if self.kind != TargetKind::Name || self.only.is_some() {
            return Ok(self.clone());
        }
        let mut packages: Vec<String> = purls
            .into_iter()
            .filter(|purl| self.name_matches(purl))
            .filter_map(package_identity)
            .collect();
        packages.sort();
        packages.dedup();
        // The full name typed is never ambiguous with packages it only
        // reaches by last segment: `lodash` beside `@types/lodash` names
        // `lodash`.
        let full: Vec<String> = packages
            .iter()
            .filter(|identity| self.is_full_name_of(identity))
            .cloned()
            .collect();
        let mut narrowed = false;
        if !full.is_empty() {
            narrowed = full.len() < packages.len();
            packages = full;
        }
        let typed = self.text.trim();
        if packages.len() > 1 && typed.chars().any(char::is_uppercase) {
            let exact: Vec<String> = packages
                .iter()
                .filter(|identity| identity_name(identity) == Some(&typed.replace(':', "/")))
                .cloned()
                .collect();
            if exact.len() == 1 {
                narrowed = true;
                packages = exact;
            }
        }
        if packages.len() > 1 {
            return Err(format!(
                "\"{}\" is ambiguous: it names {}; use the full name or a purl",
                self.text,
                packages.join(", ")
            ));
        }
        let mut settled = self.clone();
        if narrowed {
            settled.only = packages.pop();
        }
        Ok(settled)
    }

    /// Is this name the full name of the package `identity` (as
    /// [`package_identity`] returns it, in any case), not just its last
    /// segment?
    fn is_full_name_of(&self, identity: &str) -> bool {
        let Some(name) = identity_name(identity) else {
            return false;
        };
        let spec = self.text.trim().to_lowercase();
        if identity.starts_with("pkg:pypi/") {
            return name == canonicalize_pypi_name(&spec);
        }
        name.to_lowercase() == spec.replace(':', "/")
    }

    /// Does this target select the recorded patch `(purl, uuid)` — a
    /// manifest record, a vendor-ledger entry or a hosted pin?
    ///
    /// * UUID: the patch uuid (case-insensitive).
    /// * Versioned or qualified purl: the record's purl, with release-variant
    ///   rules ([`purl_matches_identifier`]: a base purl covers every
    ///   variant, a qualified one exactly one).
    /// * Versionless purl: every recorded version of the same package
    ///   ([`package_identity`]).
    /// * Name: every recorded version of the package.
    ///   A name is also compared to the uuid verbatim, so a non-canonical
    ///   recorded uuid stays addressable.
    /// * CVE / GHSA: nothing (records carry no advisory index).
    pub fn matches_patch(&self, purl: &str, uuid: &str) -> bool {
        match self.kind {
            TargetKind::Uuid => uuid.eq_ignore_ascii_case(&self.text),
            TargetKind::Purl if self.text.contains('?') || purl_has_version(&self.text) => {
                purl_matches_identifier(purl, &self.text)
            }
            TargetKind::Purl => self.same_package(purl),
            TargetKind::Name => uuid == self.text || self.name_matches(purl),
            TargetKind::Cve | TargetKind::Ghsa => false,
        }
    }
}

/// A package's identity: the [`PurlKey`] spelling of its purl
/// ([`canonical_base_purl`]) without the version (`pkg:npm/@babel/core`).
/// Case folds only where the ecosystem folds it (PyPI's PEP 503 form,
/// NuGet and Composer names); npm, Go, Maven, cargo and gem names keep
/// their case, so `JSONStream` and `jsonstream` are two packages. Two
/// purls with the same identity are versions (or release variants) of one
/// package.
pub fn package_identity(purl: &str) -> Option<String> {
    let canonical = canonical_base_purl(purl);
    let rest = canonical.strip_prefix("pkg:")?;
    let (ty, coord) = rest.split_once('/')?;
    let name = match coord.rfind('@').filter(|&i| i > 0) {
        Some(at) => &coord[..at],
        None => coord,
    };
    if name.is_empty() {
        return None;
    }
    Some(format!("pkg:{ty}/{name}"))
}

/// The name part of a [`package_identity`].
fn identity_name(identity: &str) -> Option<&str> {
    identity
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, name)| name)
}

/// `v2`, `v3`, …: a Go module path's major-version suffix.
fn is_go_major_suffix(token: &str) -> bool {
    token
        .strip_prefix(['v', 'V'])
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn is_golang_purl(purl: &str) -> bool {
    purl.get(..11)
        .is_some_and(|p| p.eq_ignore_ascii_case("pkg:golang/"))
}

/// The standard `8-4-4-4-12` hex UUID grouping, any case. The one
/// user-input UUID shape (the stricter lowercase-only on-disk grammar is
/// `patch::path_safety::is_canonical_uuid`).
pub fn is_uuid_shaped(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, len)| p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `CVE-YYYY-N…` (case-insensitive; the sequence number is 1+ digits).
pub fn is_cve_id(s: &str) -> bool {
    let Some(prefix) = s.get(..4) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("cve-") {
        return false;
    }
    let mut parts = s[4..].splitn(2, '-');
    let year = parts.next().unwrap_or_default();
    let seq = parts.next().unwrap_or_default();
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !seq.is_empty()
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// `GHSA-xxxx-xxxx-xxxx` (case-insensitive alphanumeric groups of four).
pub fn is_ghsa_id(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 4
        && parts[0].eq_ignore_ascii_case("ghsa")
        && parts[1..]
            .iter()
            .all(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Is `token` shaped like a filesystem path or glob rather than a package
/// name? (A separator, a glob metacharacter, or absolute.) An npm
/// `@scope/name` is a name, not a path. Only `rollback` has path targets;
/// every other verb treats these tokens as names.
pub fn is_path_shaped(token: &str) -> bool {
    if is_purl(token) || is_npm_scoped_name(token) {
        return false;
    }
    token.contains('/')
        || token.contains('\\')
        || token.contains(['*', '?', '['])
        || std::path::Path::new(token).is_absolute()
}

/// `@scope/name`: exactly one `/`, both halves non-empty, no glob
/// metacharacters or backslashes.
fn is_npm_scoped_name(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('@') else {
        return false;
    };
    let Some((scope, name)) = rest.split_once('/') else {
        return false;
    };
    !scope.is_empty()
        && !name.is_empty()
        && !name.contains('/')
        && !token.contains(['*', '?', '[', '\\'])
}

/// Does this purl carry an exact version (`pkg:type/name@version`)? The
/// candidate version after the last `@` must not contain a `/` (that `@`
/// is an npm scope).
fn purl_has_version(purl: &str) -> bool {
    strip_purl_qualifiers(purl)
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(_, coord)| coord.rsplit_once('@'))
        .is_some_and(|(head, version)| {
            !head.is_empty() && !version.is_empty() && !version.contains('/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "a8b05a61-1e2f-4c5f-a65b-93e71deba1ae";

    #[test]
    fn parse_classifies_every_kind() {
        assert_eq!(Target::parse(UUID).kind(), TargetKind::Uuid);
        assert_eq!(Target::parse(&UUID.to_uppercase()).kind(), TargetKind::Uuid);
        assert_eq!(Target::parse("CVE-2021-44906").kind(), TargetKind::Cve);
        assert_eq!(Target::parse("cve-2021-44906").kind(), TargetKind::Cve);
        assert_eq!(
            Target::parse("GHSA-xvch-5gv4-984h").kind(),
            TargetKind::Ghsa
        );
        assert_eq!(
            Target::parse("ghsa-XVCH-5gv4-984h").kind(),
            TargetKind::Ghsa
        );
        assert_eq!(Target::parse("pkg:npm/lodash").kind(), TargetKind::Purl);
        for name in ["lodash", "@babel/core", "org.apache:commons-text", ""] {
            assert_eq!(Target::parse(name).kind(), TargetKind::Name, "{name}");
        }
        // Near misses stay names.
        for name in ["CVE-21-1", "CVE-2021-", "GHSA-1", "a8b05a61-1e2f-4c5f-a65b"] {
            assert_eq!(Target::parse(name).kind(), TargetKind::Name, "{name}");
        }
    }

    #[test]
    fn uuid_shape() {
        assert!(is_uuid_shaped(UUID));
        assert!(is_uuid_shaped("00000000-0000-0000-0000-000000000000"));
        assert!(!is_uuid_shaped(" a8b05a61-1e2f-4c5f-a65b-93e71deba1ae"));
        assert!(!is_uuid_shaped("a8b05a61-1e2f-4c5f-a65b-93e71deba1a"));
        assert!(!is_uuid_shaped("g8b05a61-1e2f-4c5f-a65b-93e71deba1ae"));
        assert!(!is_uuid_shaped("----"));
        assert!(!is_uuid_shaped(""));
    }

    #[test]
    fn forced_kind_shape_check() {
        assert!(!Target::with_kind("lodash", TargetKind::Uuid).shape_ok());
        assert!(!Target::with_kind("lodash", TargetKind::Cve).shape_ok());
        assert!(!Target::with_kind("GHSA-1", TargetKind::Ghsa).shape_ok());
        assert!(Target::with_kind(UUID, TargetKind::Uuid).shape_ok());
        assert!(Target::with_kind("anything", TargetKind::Name).shape_ok());
        assert!(Target::with_kind("anything", TargetKind::Purl).shape_ok());
    }

    #[test]
    fn versioned_purl() {
        assert!(Target::parse("pkg:npm/lodash@4.17.21").is_versioned_purl());
        assert!(Target::parse("pkg:npm/@s/x@1").is_versioned_purl());
        assert!(!Target::parse("pkg:npm/@s/x").is_versioned_purl());
        assert!(!Target::parse("pkg:npm/lodash").is_versioned_purl());
        assert!(!Target::parse("lodash@1").is_versioned_purl());
    }

    /// The same token selects the same packages and records on every verb:
    /// a name is exact (never a prefix or substring), a versionless purl
    /// covers every version.
    #[test]
    fn name_and_versionless_purl_select_every_version_exactly() {
        let nested = "pkg:npm/lodash@4.17.4";
        let top = "pkg:npm/lodash@4.17.21";
        for token in ["lodash", "LoDash", "pkg:npm/lodash"] {
            let t = Target::parse(token);
            assert!(
                t.matches_package(nested) && t.matches_package(top),
                "{token}"
            );
            assert!(
                t.matches_patch(nested, "u1") && t.matches_patch(top, "u2"),
                "{token}"
            );
            assert!(!t.matches_package("pkg:npm/lodash-es@4.17.21"), "{token}");
            assert!(
                !t.matches_patch("pkg:npm/lodash-es@4.17.21", "u3"),
                "{token}"
            );
        }
        let yaml = Target::parse("yaml");
        assert!(!yaml.matches_package("pkg:npm/yaml-ast-parser@0.0.43"));
        assert!(yaml.matches_package("pkg:npm/yaml@2.0.0"));
        let scoped = Target::parse("@babel/core");
        assert!(scoped.matches_patch("pkg:npm/%40babel/core@7.0.0", "u"));
    }

    #[test]
    fn matches_patch_keeps_variant_rules_and_uuid_identity() {
        let key = "pkg:pypi/six@1.16.0?artifact_id=sdist";
        assert!(Target::parse("pkg:pypi/six@1.16.0").matches_patch(key, "u"));
        assert!(Target::parse(key).matches_patch(key, "u"));
        assert!(!Target::parse("pkg:pypi/six@1.16.0?artifact_id=whl").matches_patch(key, "u"));
        assert!(!Target::parse("pkg:pypi/six@1.17.0").matches_patch(key, "u"));
        assert!(Target::parse(UUID).matches_patch(key, UUID));
        assert!(Target::parse(&UUID.to_uppercase()).matches_patch(key, UUID));
        assert!(!Target::parse(UUID).matches_patch(key, "other"));
        // A name is also compared to the recorded uuid verbatim.
        assert!(Target::parse("uuid-bar").matches_patch("pkg:npm/foo@1", "uuid-bar"));
        // Advisory ids match no record.
        assert!(!Target::parse("CVE-2021-44906").matches_patch(key, "CVE-2021-44906"));
        assert!(!Target::parse("CVE-2021-44906").matches_package(key));
    }

    /// The former `patch_matches` contract, carried over verbatim.
    #[test]
    fn purl_targets_match_only_the_purl_field() {
        const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
        let m = |purl: &str, uuid: &str, id: &str| Target::parse(id).matches_patch(purl, uuid);
        let key = "pkg:pypi/requests@2.28.0?artifact_id=abc";
        assert!(m(key, UUID, "pkg:pypi/requests@2.28.0"));
        assert!(m(key, UUID, key));
        assert!(!m(key, UUID, "pkg:pypi/requests@2.28.0?artifact_id=zzz"));
        assert!(!m(key, UUID, "pkg:pypi/requests@2.29.0"));
        assert!(m(key, UUID, UUID));
        assert!(!m(key, UUID, "not-the-uuid"));
        // A uuid identifier never matches by PURL text, and a PURL
        // identifier is only ever compared against the purl field.
        assert!(!m(
            "pkg:npm/other@1.0.0",
            "pkg:pypi/requests@2.28.0",
            "pkg:pypi/requests@2.28.0"
        ));
        assert!(!m(UUID, "other-uuid", UUID));
        assert!(!m("pkg:npm/a@1", UUID, "pkg:npm/b@1"));
    }

    /// A name that reaches several packages by last segment is ambiguous;
    /// several versions of one package are not.
    #[test]
    fn ambiguity_counts_distinct_packages() {
        let core = Target::parse("core");
        let purls = [
            "pkg:npm/%40angular/core@17.0.0",
            "pkg:npm/@babel/core@7.0.0",
            "pkg:npm/@babel/core@7.1.0",
            "pkg:npm/lodash@4.17.21",
        ];
        let msg = core.ambiguity(purls).expect("ambiguous");
        assert!(
            msg.contains("pkg:npm/@angular/core, pkg:npm/@babel/core"),
            "{msg}"
        );
        assert!(!msg.contains("lodash"), "{msg}");
        // One package, many versions (and variants): not ambiguous.
        assert_eq!(core.ambiguity(purls[1..].iter().copied()), None);
        assert_eq!(
            Target::parse("six")
                .ambiguity(["pkg:pypi/six@1.16.0?artifact_id=a", "pkg:pypi/Six@1.17.0",]),
            None
        );
        // The full name, a purl and a uuid are never ambiguous.
        assert_eq!(Target::parse("@babel/core").ambiguity(purls), None);
        assert_eq!(Target::parse("pkg:npm/core").ambiguity(purls), None);
        assert_eq!(Target::parse(UUID).ambiguity(purls), None);
        // Same name in two ecosystems: ambiguous.
        assert!(Target::parse("six")
            .ambiguity(["pkg:pypi/six@1", "pkg:npm/six@1"])
            .is_some());
        // A full-name match wins over last-segment ones (#1034 review):
        // `lodash` beside `@types/lodash`, `core` beside `@x/core`.
        let typed = ["pkg:npm/lodash@4.17.21", "pkg:npm/@types/lodash@4.17.0"];
        assert_eq!(Target::parse("lodash").ambiguity(typed), None);
        // ...and the settled target selects only the full name, so acting
        // on it leaves `@types/lodash` alone.
        let settled = Target::parse("lodash").settle(typed).unwrap();
        assert!(settled.matches_package(typed[0]));
        assert!(settled.matches_patch(typed[0], "u1"));
        assert!(!settled.matches_package(typed[1]));
        assert!(!settled.matches_patch(typed[1], "u2"));
        // Without a competing last-segment match nothing narrows.
        let alone = Target::parse("lodash").settle([typed[1]]).unwrap();
        assert!(alone.matches_patch(typed[1], "u2"));
        assert_eq!(
            core.ambiguity(["pkg:npm/core@1.0.0", "pkg:npm/@x/core@2.0.0"]),
            None
        );
        // ...but two last-segment-only matches stay ambiguous.
        assert!(Target::parse("lodash")
            .ambiguity(["pkg:npm/@types/lodash@4", "pkg:npm/@x/lodash@1"])
            .is_some());
    }

    #[test]
    fn go_major_suffix_is_never_a_name() {
        let v2 = "pkg:golang/github.com/x/y/v2@v2.0.0";
        for token in ["v2", "V2"] {
            let t = Target::parse(token);
            assert!(!t.matches_package(v2), "{token}");
            assert!(!t.matches_patch(v2, "u"), "{token}");
        }
        assert!(Target::parse("github.com/x/y/v2").matches_package(v2));
        // Outside Go, `v2` is an ordinary name.
        assert!(Target::parse("v2").matches_package("pkg:npm/v2@1.0.0"));
    }

    #[test]
    fn package_identity_drops_version_and_qualifiers() {
        assert_eq!(
            package_identity("pkg:npm/%40babel/core@7.0.0").as_deref(),
            Some("pkg:npm/@babel/core")
        );
        // Case folds only where the ecosystem folds it (#1292).
        assert_eq!(
            package_identity("pkg:npm/JSONStream@1.3.5").as_deref(),
            Some("pkg:npm/JSONStream")
        );
        assert_eq!(
            package_identity("pkg:NuGet/Newtonsoft.Json@13.0.3").as_deref(),
            Some("pkg:nuget/newtonsoft.json")
        );
        assert_eq!(
            package_identity("pkg:pypi/Typing_Extensions@4?artifact_id=x").as_deref(),
            Some("pkg:pypi/typing-extensions")
        );
        assert_eq!(
            package_identity("pkg:golang/github.com/x/y/v2@v2.0.0").as_deref(),
            Some("pkg:golang/github.com/x/y/v2")
        );
        assert_eq!(package_identity("lodash"), None);
    }

    /// Versioned and versionless purl targets share one case rule, the
    /// [`PurlKey`] identity: case-distinct packages stay distinct where
    /// the ecosystem is case-sensitive, and fold where it is not (#1292).
    #[test]
    fn purl_targets_agree_on_case_in_every_ecosystem() {
        // (record, other case spelling, does the ecosystem fold case)
        let cases = [
            ("pkg:npm/JSONStream@1.3.5", "pkg:npm/jsonstream", false),
            (
                "pkg:golang/github.com/Sirupsen/logrus@v1.0.0",
                "pkg:golang/github.com/sirupsen/logrus",
                false,
            ),
            ("pkg:maven/Org.X/y@1.0", "pkg:maven/org.x/y", false),
            ("pkg:cargo/Serde@1.0.0", "pkg:cargo/serde", false),
            ("pkg:gem/Rails@7.0.0", "pkg:gem/rails", false),
            (
                "pkg:pypi/Typing_Extensions@4.0.0",
                "pkg:pypi/typing-extensions",
                true,
            ),
            (
                "pkg:nuget/Newtonsoft.Json@13.0.3",
                "pkg:nuget/newtonsoft.json",
                true,
            ),
            (
                "pkg:composer/Monolog/Monolog@3.0.2",
                "pkg:composer/monolog/monolog",
                true,
            ),
        ];
        for (record, other, folds) in cases {
            let version = &record[record.rfind('@').unwrap()..];
            let versioned = Target::parse(&format!("{other}{version}"));
            let versionless = Target::parse(other);
            for t in [&versioned, &versionless] {
                assert_eq!(t.matches_patch(record, "u"), folds, "{t} vs {record}");
                assert_eq!(t.matches_package(record), folds, "{t} vs {record}");
            }
            // The record's own spelling always selects it.
            let own = Target::parse(&record[..record.rfind('@').unwrap()]);
            assert!(
                own.matches_patch(record, "u") && own.matches_package(record),
                "{record}"
            );
            let own = Target::parse(record);
            assert!(
                own.matches_patch(record, "u") && own.matches_package(record),
                "{record}"
            );
        }
    }

    /// A name reaching case-distinct packages is ambiguous when typed in
    /// lowercase and settles on the exact-case spelling otherwise (#1292).
    #[test]
    fn case_distinct_packages_are_two_packages() {
        let npm = ["pkg:npm/JSONStream@1.3.5", "pkg:npm/jsonstream@0.0.1"];
        let msg = Target::parse("jsonstream")
            .ambiguity(npm)
            .expect("ambiguous");
        assert!(
            msg.contains("pkg:npm/JSONStream, pkg:npm/jsonstream"),
            "{msg}"
        );
        let upper = Target::parse("JSONStream").settle(npm).unwrap();
        assert!(upper.matches_patch(npm[0], "u1"));
        assert!(!upper.matches_patch(npm[1], "u2"));
        assert!(upper.matches_package(npm[0]) && !upper.matches_package(npm[1]));
        // A spelling matching neither exactly stays ambiguous.
        assert!(Target::parse("JsonStream").ambiguity(npm).is_some());
        // Go: last segment and full path alike.
        let go = [
            "pkg:golang/github.com/Sirupsen/logrus@v1.0.0",
            "pkg:golang/github.com/sirupsen/logrus@v1.8.1",
        ];
        assert!(Target::parse("logrus").ambiguity(go).is_some());
        assert!(Target::parse("github.com/sirupsen/logrus")
            .ambiguity(go)
            .is_some());
        let settled = Target::parse("github.com/Sirupsen/logrus")
            .settle(go)
            .unwrap();
        assert!(settled.matches_patch(go[0], "u") && !settled.matches_patch(go[1], "u"));
        // A versionless purl selects its own case only.
        let purl = Target::parse("pkg:npm/jsonstream");
        assert!(!purl.matches_patch(npm[0], "u1") && purl.matches_patch(npm[1], "u2"));
        assert_eq!(purl.ambiguity(npm), None);
        // A name still matches one package typed in any case.
        assert!(Target::parse("LODASH").matches_patch("pkg:npm/lodash@4.17.21", "u"));
        assert_eq!(
            Target::parse("Lodash").ambiguity(["pkg:npm/lodash@4.17.21"]),
            None
        );
        // Case-folding ecosystems still count one package.
        assert_eq!(
            Target::parse("newtonsoft.json").ambiguity([
                "pkg:nuget/Newtonsoft.Json@13.0.3",
                "pkg:nuget/newtonsoft.json@12.0.1"
            ]),
            None
        );
    }

    #[test]
    fn path_shape() {
        for p in [
            "./x",
            "node_modules/lodash",
            "a\\b",
            "*",
            "x?",
            "[ab]",
            "github.com/x/y",
        ] {
            assert!(is_path_shaped(p), "{p}");
        }
        for n in [
            "lodash",
            "@babel/core",
            "pkg:npm/@s/x",
            "org.apache:x",
            UUID,
        ] {
            assert!(!is_path_shaped(n), "{n}");
        }
        assert!(is_path_shaped("@babel/*"));
        assert!(is_path_shaped("@a/b/c"));
    }
}
