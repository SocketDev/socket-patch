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
//!   variant); without a version it names every installed version;
//! * anything else is a package name, matched EXACTLY (full name or last
//!   segment, case-insensitive, PEP 503 for PyPI) by
//!   [`crate::policy::package_spec_matches`] — the matcher `scan --package`
//!   and `socket.yml` already use. There is no fuzzy matching here. A Go
//!   major-version suffix (`v2` in `github.com/x/y/v2`) is never a name.
//!
//! A name's last-segment rule can select several packages (`core` →
//! `@angular/core` and `@babel/core`). `get`, `remove` and `rollback` act
//! on one package per name, so they refuse such a name
//! ([`Target::ambiguity`]) and ask for the full name or a purl;
//! `scan --package` and `socket.yml` keep selecting all of them.
//!
//! Verbs reject the kinds they cannot act on (a CVE matches no manifest
//! entry, for example) rather than reinterpreting them.

use std::fmt;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::policy::package_spec_matches;
use crate::utils::purl::{canonical_purl, is_purl, purl_matches_identifier, strip_purl_qualifiers};

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
    /// names only: a versioned purl selects that release (qualifiers
    /// ignored), a versionless purl or a name selects every version.
    pub fn matches_package(&self, purl: &str) -> bool {
        match self.kind {
            TargetKind::Purl => package_spec_matches(&self.text, purl),
            TargetKind::Name => self.name_matches(purl),
            TargetKind::Uuid | TargetKind::Cve | TargetKind::Ghsa => false,
        }
    }

    /// The name rule: [`package_spec_matches`], except that a Go
    /// major-version suffix (`v2`) never selects a module by its last
    /// segment (`github.com/x/y/v2` is `y`, major version 2).
    fn name_matches(&self, purl: &str) -> bool {
        if is_go_major_suffix(self.text.trim()) && is_golang_purl(purl) {
            return false;
        }
        package_spec_matches(&self.text, purl)
    }

    /// For a package name, the distinct packages it selects among `purls`
    /// when there is more than one: `Some(message)` naming each (as a
    /// versionless purl) and how to pick one. `None` for every other kind,
    /// and for a name that selects one package (any number of its
    /// versions) or none.
    ///
    /// `get`, `remove` and `rollback` refuse an ambiguous name instead of
    /// acting on every package it reaches by last segment.
    pub fn ambiguity<'a>(&self, purls: impl IntoIterator<Item = &'a str>) -> Option<String> {
        if self.kind != TargetKind::Name {
            return None;
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
        if !full.is_empty() {
            packages = full;
        }
        (packages.len() > 1).then(|| {
            format!(
                "\"{}\" is ambiguous: it names {}; use the full name or a purl",
                self.text,
                packages.join(", ")
            )
        })
    }

    /// Is this name the full name of the package `identity` (as
    /// [`package_identity`] returns it), not just its last segment?
    fn is_full_name_of(&self, identity: &str) -> bool {
        let Some((ty, name)) = identity
            .strip_prefix("pkg:")
            .and_then(|rest| rest.split_once('/'))
        else {
            return false;
        };
        let spec = self.text.trim().to_lowercase();
        if ty == "pypi" {
            return name == canonicalize_pypi_name(&spec);
        }
        name == spec.replace(':', "/")
    }

    /// Does this target select the recorded patch `(purl, uuid)` — a
    /// manifest record, a vendor-ledger entry or a hosted pin?
    ///
    /// * UUID: the patch uuid (case-insensitive).
    /// * Versioned or qualified purl: the record's purl, with release-variant
    ///   rules ([`purl_matches_identifier`]: a base purl covers every
    ///   variant, a qualified one exactly one).
    /// * Versionless purl / name: every recorded version of the package.
    ///   A name is also compared to the uuid verbatim, so a non-canonical
    ///   recorded uuid stays addressable.
    /// * CVE / GHSA: nothing (records carry no advisory index).
    pub fn matches_patch(&self, purl: &str, uuid: &str) -> bool {
        match self.kind {
            TargetKind::Uuid => uuid.eq_ignore_ascii_case(&self.text),
            TargetKind::Purl if self.text.contains('?') || purl_has_version(&self.text) => {
                purl_matches_identifier(purl, &self.text)
            }
            TargetKind::Purl => package_spec_matches(&self.text, purl),
            TargetKind::Name => uuid == self.text || self.name_matches(purl),
            TargetKind::Cve | TargetKind::Ghsa => false,
        }
    }
}

/// A package's identity: its purl without version, qualifiers or subpath,
/// decoded and lowercased (`pkg:npm/@babel/core`), the PyPI name in its
/// PEP 503 form. Two purls with the same identity are versions (or
/// release variants) of one package.
pub fn package_identity(purl: &str) -> Option<String> {
    let canonical = canonical_purl(purl).to_lowercase();
    let rest = canonical.strip_prefix("pkg:")?;
    let (ty, coord) = rest.split_once('/')?;
    let name = match coord.rfind('@').filter(|&i| i > 0) {
        Some(at) => &coord[..at],
        None => coord,
    };
    if name.is_empty() {
        return None;
    }
    let name = if ty == "pypi" {
        canonicalize_pypi_name(name)
    } else {
        name.to_string()
    };
    Some(format!("pkg:{ty}/{name}"))
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
            package_identity("pkg:npm/%40Babel/core@7.0.0").as_deref(),
            Some("pkg:npm/@babel/core")
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
