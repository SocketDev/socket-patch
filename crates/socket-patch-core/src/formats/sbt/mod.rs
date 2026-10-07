//! sbt builds (`docs/design/sbt-support.md`): the pure model every sbt mode
//! shares. Text in, answers out; every read stays with the caller.
//!
//! - [`build`] — the build definition: `project/build.properties`'s sbt
//!   version and line, the declared projects, the dependency digest and the
//!   build-source findings (`dependencyOverrides :=`, `resolvers :=`, …).
//! - [`evidence`] — sbt's own resolution records under `target/` (the
//!   update-cache JSON, the Ivy XML reports) parsed into a
//!   [`JvmResolution`].
//! - [`gate`] — whether a patch may be pinned for the whole build, from
//!   that resolution ([`gate::check_new`]) and whether an existing pin still
//!   holds ([`gate::check_existing`]).
//! - [`owned_file`] — the generated `socket-patch.sbt` /
//!   `socket-patch-vendor.sbt` (render, strict parse, value validation).
//!
//! These are `pkg:maven` build shapes, not an ecosystem of their own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub mod build;
pub mod evidence;
pub mod gate;
pub mod owned_file;

/// Maven `(group, artifact)`.
pub type Ga = (String, String);

/// What sbt resolved for a build, as far as its on-disk records tell: the
/// union over every project and configuration with evidence.
///
/// Versions are the raw resolved revisions (a pinned `<base>-socket.<hex8>`
/// stays spelled that way; [`gate`] normalises it). "Evidence ids" name the
/// record a fact came from (a root-relative evidence path plus its
/// configuration), so a refusal can say where to look.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JvmResolution {
    /// (g, a) → raw version → evidence ids.
    pub modules: BTreeMap<Ga, BTreeMap<String, BTreeSet<String>>>,
    /// (g, a, raw version) → absolute artifact paths (from the report's
    /// `file:` URIs / Ivy `location`).
    pub artifacts: BTreeMap<(String, String, String), BTreeSet<PathBuf>>,
    /// (g, a) → the non-empty artifact classifiers resolved for it.
    pub classifiers: BTreeMap<Ga, BTreeSet<String>>,
    /// GAs resolved, not evicted, in one of [`evidence::CONFIGS`] of some
    /// project's library resolution (every other configuration only feeds
    /// [`Self::modules`], for conflict detection).
    pub in_scope: BTreeSet<Ga>,
    /// The projects with evidence, as root-relative base directories (`.`
    /// for the root project), matching [`build::declared_projects`]'s
    /// values.
    pub projects_seen: BTreeSet<String>,
    /// GAs seen only in meta-build (`project/`) evidence: sbt plugins and
    /// the build's own classpath, which no library pin reaches.
    pub meta_build: BTreeSet<Ga>,
}

impl JvmResolution {
    /// No project contributed any evidence.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty() && self.projects_seen.is_empty() && self.meta_build.is_empty()
    }

    /// Every raw version resolved for `(g, a)`, in any configuration.
    pub fn versions(&self, g: &str, a: &str) -> Vec<&str> {
        self.modules
            .get(&(g.to_string(), a.to_string()))
            .map(|v| v.keys().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_resolution_has_no_versions() {
        let res = JvmResolution::default();
        assert!(res.is_empty());
        assert!(res.versions("g", "a").is_empty());
    }

    #[test]
    fn versions_lists_every_raw_revision() {
        let mut res = JvmResolution::default();
        let ga = ("g".to_string(), "a".to_string());
        res.modules.entry(ga.clone()).or_default().insert(
            "1.0".into(),
            BTreeSet::from(["a/target/x:compile".to_string()]),
        );
        res.modules
            .entry(ga)
            .or_default()
            .insert("1.0-socket.abcdef12".into(), BTreeSet::new());
        assert!(!res.is_empty());
        assert_eq!(res.versions("g", "a"), ["1.0", "1.0-socket.abcdef12"]);
    }
}
