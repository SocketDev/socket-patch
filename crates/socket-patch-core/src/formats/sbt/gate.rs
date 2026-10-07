//! Whether a Maven patch may be pinned build-wide in an sbt build, decided
//! from what sbt itself resolved ([`JvmResolution`]), never from the
//! machine-wide cache.
//!
//! The generated `dependencyOverrides` entry forces one version for every
//! project, so a pin is safe only when every project that resolves the GA
//! already resolves the patch's base version (otherwise it is a silent
//! downgrade, or an upgrade the build never asked for). [`check_new`] gates
//! a pin before it is written; [`check_existing`] re-checks a pin already in
//! the generated file against the post-wiring evidence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::JvmResolution;
use crate::formats::maven::split_socket_version;

/// Classifiers a pin may coexist with: they never reach a classpath.
pub const HARMLESS_CLASSIFIERS: &[&str] = &["sources", "javadoc"];

/// Why a pin was not (or is no longer) wired. The first three are
/// run-level (nothing is wired; one warning), the rest per patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateRefusal {
    /// No resolution evidence under any `target/` (fresh clone, cleaned
    /// tree, or no `sbt update` yet).
    Missing,
    /// The declared projects could not be read statically (`missing` is
    /// empty), or these declared base directories left no evidence.
    Incomplete { missing: Vec<String> },
    /// A build source is newer than the evidence.
    Stale,
    /// The GA is not resolved by any library configuration: a silent skip.
    /// `meta_build_only` when the meta-build (sbt plugins) resolves it,
    /// which a library pin never reaches (advisory `*_meta_build_only`).
    NotResolved { meta_build_only: bool },
    /// Some project resolves another version than the patch's base (raw
    /// versions, sorted).
    VersionConflict { found: Vec<String> },
    /// `org.scala-lang` (the compiler and runtime sbt itself pins).
    ScalaRuntime,
    /// A classified artifact (other than [`HARMLESS_CLASSIFIERS`]) of the GA
    /// is resolved, which the pin's plain jar does not replace.
    Classifier { found: Vec<String> },
    /// The pinned version resolves from outside the pin's repository
    /// (another checkout's origin, `~/.ivy2/local`, `mavenLocal`).
    ResolvedElsewhere { paths: Vec<PathBuf> },
}

/// A pin-level advisory that does not by itself refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateWarning {
    /// The evidence still resolves the base version, so the generated
    /// override is shadowed somewhere (a project-level `:=`); `evidence`
    /// names the records.
    OverrideShadowed { evidence: Vec<String> },
    /// Reserved for the meta-build advisory on an accepted pin (unused by
    /// the gate today: a meta-build-only GA is [`GateRefusal::NotResolved`]).
    MetaBuildOnly,
}

/// The base version of `raw`: `<base>-socket.<hex8>` (a pin already in
/// place) counts as `<base>`.
pub fn normalize_version(raw: &str) -> &str {
    split_socket_version(raw).map_or(raw, |(base, _)| base)
}

/// Whether `g` is the Scala runtime / compiler group.
pub fn is_scala_runtime(g: &str) -> bool {
    g == "org.scala-lang" || g.starts_with("org.scala-lang.")
}

/// Gate a NEW pin of `g:a` at upstream version `base` (see the module doc).
/// `res` is the build's resolution (`None` = no evidence found), `declared`
/// the build's project base directories (`None` = unreadable definitions),
/// `stale` whether a build source is newer than the evidence. Checked in
/// this order: missing, incomplete, stale, Scala runtime, not resolved,
/// version conflict, classifier.
pub fn check_new(
    res: Option<&JvmResolution>,
    declared: Option<&BTreeSet<String>>,
    stale: bool,
    g: &str,
    a: &str,
    base: &str,
) -> Result<Vec<GateWarning>, GateRefusal> {
    let res = match res {
        Some(res) if !res.is_empty() => res,
        _ => return Err(GateRefusal::Missing),
    };
    let Some(declared) = declared else {
        return Err(GateRefusal::Incomplete {
            missing: Vec::new(),
        });
    };
    let missing: Vec<String> = declared
        .iter()
        .filter(|dir| !res.projects_seen.contains(*dir))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(GateRefusal::Incomplete { missing });
    }
    if stale {
        return Err(GateRefusal::Stale);
    }
    if is_scala_runtime(g) {
        return Err(GateRefusal::ScalaRuntime);
    }
    let ga = (g.to_string(), a.to_string());
    if !res.in_scope.contains(&ga) {
        return Err(GateRefusal::NotResolved {
            meta_build_only: res.meta_build.contains(&ga),
        });
    }
    let raw: Vec<String> = res
        .modules
        .get(&ga)
        .map(|versions| versions.keys().cloned().collect())
        .unwrap_or_default();
    let normalized: BTreeSet<&str> = raw.iter().map(|v| normalize_version(v)).collect();
    if normalized.len() != 1 || !normalized.contains(base) {
        return Err(GateRefusal::VersionConflict { found: raw });
    }
    let classifiers: Vec<String> = res
        .classifiers
        .get(&ga)
        .into_iter()
        .flatten()
        .filter(|c| !c.is_empty() && !HARMLESS_CLASSIFIERS.contains(&c.as_str()))
        .cloned()
        .collect();
    if !classifiers.is_empty() {
        return Err(GateRefusal::Classifier { found: classifiers });
    }
    Ok(Vec::new())
}

/// Re-check a pin already in the generated file, `g:a` forced to the
/// suffixed `sv`, served from `repo_abs` (the absolute, canonical
/// `<root>/.socket/<dir>/maven2`; evidence paths are compared as sbt wrote
/// them). No evidence for the GA proves nothing either way: `Ok` with no
/// warning.
///
/// The check is on content, like the generated file's own load-time
/// verifier and VEX: an artifact outside `repo_abs` is fine when
/// `pinned_bytes(path)` holds (its sha256 is the pin's jar sha256, as the
/// IO layer hashed it: [`super::evidence::ResolutionDoc::artifact_sha256`]).
/// Ivy legitimately serves a second checkout of the same build from the
/// first checkout's cached copy.
pub fn check_existing(
    res: Option<&JvmResolution>,
    g: &str,
    a: &str,
    sv: &str,
    repo_abs: &Path,
    pinned_bytes: &dyn Fn(&Path) -> bool,
) -> Result<Vec<GateWarning>, GateRefusal> {
    let Some(res) = res else {
        return Ok(Vec::new());
    };
    let (g, a) = (g.to_string(), a.to_string());
    let elsewhere: Vec<PathBuf> = res
        .artifacts
        .get(&(g.clone(), a.clone(), sv.to_string()))
        .into_iter()
        .flatten()
        .filter(|p| !p.starts_with(repo_abs) && !pinned_bytes(p))
        .cloned()
        .collect();
    if !elsewhere.is_empty() {
        return Err(GateRefusal::ResolvedElsewhere { paths: elsewhere });
    }
    let base = normalize_version(sv);
    let shadowed: Vec<String> = res
        .modules
        .get(&(g, a))
        .and_then(|versions| versions.get(base))
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    Ok(if base != sv && !shadowed.is_empty() {
        vec![GateWarning::OverrideShadowed { evidence: shadowed }]
    } else {
        Vec::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SV: &str = "3.11-socket.abcdef12";

    fn ga(g: &str, a: &str) -> (String, String) {
        (g.to_string(), a.to_string())
    }

    /// Projects `.`, `a` resolved; lang3 at `versions` in compile.
    fn res(versions: &[&str]) -> JvmResolution {
        let mut r = JvmResolution {
            projects_seen: [".", "a"].map(String::from).into(),
            ..Default::default()
        };
        let lang3 = ga("org.apache.commons", "commons-lang3");
        for v in versions {
            r.modules
                .entry(lang3.clone())
                .or_default()
                .entry(v.to_string())
                .or_default()
                .insert(format!("a/target/out:compile@{v}"));
        }
        if !versions.is_empty() {
            r.in_scope.insert(lang3);
        }
        r.modules
            .entry(ga("org.scala-lang", "scala-library"))
            .or_default()
            .insert("2.12.18".into(), Default::default());
        r.in_scope.insert(ga("org.scala-lang", "scala-library"));
        r
    }

    fn dirs(d: &[&str]) -> BTreeSet<String> {
        d.iter().map(|s| s.to_string()).collect()
    }

    fn new(
        r: Option<&JvmResolution>,
        declared: Option<&BTreeSet<String>>,
        stale: bool,
        g: &str,
        a: &str,
    ) -> Result<Vec<GateWarning>, GateRefusal> {
        check_new(r, declared, stale, g, a, "3.11")
    }

    const G: &str = "org.apache.commons";
    const A: &str = "commons-lang3";

    #[test]
    fn check_new_refuses_in_order() {
        let declared = dirs(&[".", "a"]);
        let good = res(&["3.11"]);
        assert_eq!(new(Some(&good), Some(&declared), false, G, A), Ok(vec![]));
        assert_eq!(
            new(None, Some(&declared), false, G, A),
            Err(GateRefusal::Missing)
        );
        assert_eq!(
            new(
                Some(&JvmResolution::default()),
                Some(&declared),
                false,
                G,
                A
            ),
            Err(GateRefusal::Missing)
        );
        assert_eq!(
            new(Some(&good), None, true, G, A),
            Err(GateRefusal::Incomplete { missing: vec![] })
        );
        assert_eq!(
            new(Some(&good), Some(&dirs(&[".", "a", "b", "c"])), true, G, A),
            Err(GateRefusal::Incomplete {
                missing: vec!["b".into(), "c".into()]
            })
        );
        assert_eq!(
            new(Some(&good), Some(&declared), true, G, A),
            Err(GateRefusal::Stale)
        );
        assert_eq!(
            new(
                Some(&good),
                Some(&declared),
                false,
                "org.scala-lang",
                "scala-library"
            ),
            Err(GateRefusal::ScalaRuntime)
        );
        assert_eq!(
            new(
                Some(&good),
                Some(&declared),
                false,
                "org.scala-lang.modules",
                "x"
            ),
            Err(GateRefusal::ScalaRuntime)
        );
        assert_eq!(
            new(
                Some(&good),
                Some(&declared),
                false,
                "com.google.code.gson",
                "gson"
            ),
            Err(GateRefusal::NotResolved {
                meta_build_only: false
            })
        );
    }

    #[test]
    fn meta_build_only_is_a_flagged_silent_skip() {
        let mut r = res(&[]);
        r.meta_build.insert(ga(G, A));
        assert_eq!(
            new(Some(&r), Some(&dirs(&["."])), false, G, A),
            Err(GateRefusal::NotResolved {
                meta_build_only: true
            })
        );
    }

    #[test]
    fn every_config_version_must_be_the_base() {
        let declared = dirs(&["."]);
        // c's direct 3.12.0 evicts a's transitive 3.11 for c only: both
        // versions are resolved somewhere in the build.
        assert_eq!(
            new(
                Some(&res(&["3.11", "3.12.0"])),
                Some(&declared),
                false,
                G,
                A
            ),
            Err(GateRefusal::VersionConflict {
                found: vec!["3.11".into(), "3.12.0".into()]
            })
        );
        assert_eq!(
            new(Some(&res(&["3.12.0"])), Some(&declared), false, G, A),
            Err(GateRefusal::VersionConflict {
                found: vec!["3.12.0".into()]
            })
        );
        // A pin already in place resolves the suffixed version: it is ours.
        assert_eq!(
            new(Some(&res(&["3.11", SV])), Some(&declared), false, G, A),
            Ok(vec![])
        );
    }

    #[test]
    fn classifiers_other_than_sources_and_javadoc_refuse() {
        let declared = dirs(&["."]);
        let mut r = res(&["3.11"]);
        r.classifiers.insert(
            ga(G, A),
            ["sources", "javadoc", ""].map(String::from).into(),
        );
        assert_eq!(new(Some(&r), Some(&declared), false, G, A), Ok(vec![]));
        r.classifiers
            .get_mut(&ga(G, A))
            .unwrap()
            .insert("tests".into());
        assert_eq!(
            new(Some(&r), Some(&declared), false, G, A),
            Err(GateRefusal::Classifier {
                found: vec!["tests".into()]
            })
        );
    }

    #[test]
    fn check_existing_flags_shadowing_and_foreign_origins() {
        let repo = Path::new("/w/.socket/sbt-hosted/maven2");
        let no = |_: &Path| false;
        let mut r = res(&[SV]);
        let key = (G.to_string(), A.to_string(), SV.to_string());
        r.artifacts
            .entry(key.clone())
            .or_default()
            .insert(repo.join("org/apache/commons/commons-lang3/x.jar"));
        assert_eq!(check_existing(Some(&r), G, A, SV, repo, &no), Ok(vec![]));
        assert_eq!(check_existing(None, G, A, SV, repo, &no), Ok(vec![]));
        assert_eq!(
            check_existing(Some(&JvmResolution::default()), G, A, SV, repo, &no),
            Ok(vec![])
        );

        let shadowed = res(&["3.11", SV]);
        assert_eq!(
            check_existing(Some(&shadowed), G, A, SV, repo, &no),
            Ok(vec![GateWarning::OverrideShadowed {
                evidence: vec!["a/target/out:compile@3.11".into()]
            }])
        );

        let other = PathBuf::from("/w2/.socket/sbt-hosted/maven2/x.jar");
        r.artifacts.get_mut(&key).unwrap().insert(other.clone());
        assert_eq!(
            check_existing(Some(&r), G, A, SV, repo, &no),
            Err(GateRefusal::ResolvedElsewhere { paths: vec![other] })
        );
        // A lexical prefix of the repo path is not inside it.
        let mut sibling = res(&[SV]);
        let near = PathBuf::from("/w/.socket/sbt-hosted/maven2x/a.jar");
        sibling
            .artifacts
            .entry(key)
            .or_default()
            .insert(near.clone());
        assert_eq!(
            check_existing(Some(&sibling), G, A, SV, repo, &no),
            Err(GateRefusal::ResolvedElsewhere {
                paths: vec![near.clone()]
            })
        );
    }

    #[test]
    fn check_existing_accepts_the_pinned_bytes_anywhere() {
        // Ivy's second checkout: the pinned version served from the first
        // checkout's cached copy, which holds the pinned bytes.
        let repo = Path::new("/w2/.socket/sbt-hosted/maven2");
        let ivy = PathBuf::from("/home/u/.ivy2/cache/org.apache.commons/commons-lang3/jars/x.jar");
        let mut r = res(&[SV]);
        r.artifacts
            .entry((G.to_string(), A.to_string(), SV.to_string()))
            .or_default()
            .insert(ivy.clone());
        let same = |p: &Path| p == ivy.as_path();
        assert_eq!(check_existing(Some(&r), G, A, SV, repo, &same), Ok(vec![]));
        // Other bytes there are still another origin.
        let other = |_: &Path| false;
        assert_eq!(
            check_existing(Some(&r), G, A, SV, repo, &other),
            Err(GateRefusal::ResolvedElsewhere { paths: vec![ivy] })
        );
    }

    #[test]
    fn normalize_version_strips_only_a_socket_suffix() {
        assert_eq!(normalize_version(SV), "3.11");
        assert_eq!(normalize_version("3.11"), "3.11");
        assert_eq!(normalize_version("3.11-socket.XYZ"), "3.11-socket.XYZ");
    }
}
