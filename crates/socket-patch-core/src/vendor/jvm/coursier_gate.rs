//! The vendored scala-cli gate: the `formats::sbt::gate` rules over a
//! scala-cli build's own resolution (`crawlers::scala_evidence`), plus the
//! conditions under which the same-GAV tree would not win, before planning.
//!
//! Run-level conditions skip the patch (a `skipped` event, exit 0):
//! `vendor_scala_cli_resolution_missing` (no Bloop project of this
//! workspace), `vendor_scala_cli_resolution_stale` (a source changed since)
//! and `vendor_scala_cli_not_resolved` (the build does not resolve the GA).
//! A GAV the committed tree already serves ([`coursier_tree::INDEX_REL`]
//! lists it) is never skipped for missing or stale evidence: `.scala-build`
//! is gitignored, so a fresh clone has none, and the vendored wiring keeps
//! serving the patch; the planner re-plans it idempotently.
//! Per-patch refusals: `vendor_scala_cli_version_conflict`,
//! `vendor_scala_cli_classifier_unsupported`,
//! `vendor_scala_cli_scala_runtime_unsupported`,
//! `vendor_scala_cli_repository_shadowed` (another input declares a
//! repository, which scala-cli consults before the tree, or the post-wiring
//! evidence resolves the GA elsewhere), `vendor_scala_cli_path_unsupported`
//! (a project path the `file://${.}` URL cannot carry) and
//! `vendor_scala_cli_windows_unsupported` (`file://${.}` is unverified on
//! Windows).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::sbt_gate::GateStop;
use super::{coursier_tree, scala_cli, JvmRefusal, JvmWarning};
use crate::crawlers::scala_evidence::{self, ScalaEvidence};
use crate::formats::sbt::gate::{check_new, GateRefusal};
use crate::utils::fs::read_regular_to_bytes_sync;

/// Largest source file scanned for repository directives.
const MAX_SOURCE_BYTES: u64 = 4 << 20;

/// Gate vendoring `g:a` at upstream `base` into the scala-cli build at
/// `project_root`.
pub fn check(
    project_root: &Path,
    g: &str,
    a: &str,
    base: &str,
) -> Result<Vec<JvmWarning>, GateStop> {
    if cfg!(windows) {
        return Err(refuse(
            "vendor_scala_cli_windows_unsupported",
            "scala-cli's `file://${.}` repository URL is unverified on Windows; use hosted or \
             agent mode there"
                .to_string(),
        ));
    }
    check_path(project_root)?;
    let evidence = scala_evidence::discover(project_root);
    gate(project_root, evidence.as_ref(), g, a, base)
}

/// [`check`] over already discovered `evidence` (platform checks aside).
pub(crate) fn gate(
    project_root: &Path,
    evidence: Option<&ScalaEvidence>,
    g: &str,
    a: &str,
    base: &str,
) -> Result<Vec<JvmWarning>, GateStop> {
    let vendored = already_vendored(project_root, g, a, base);
    // An already vendored GAV skips the evidence checks below, but a
    // repository directive needs only the sources, so it is checked first:
    // adding one must refuse even before the next build refreshes evidence.
    let early_directive = || {
        let sources = evidence.map(|e| e.sources.as_slice()).unwrap_or_default();
        directive_refusal(project_root, sources, g, a)
    };
    let Some(e) = evidence.filter(|e| !e.resolution.is_empty()) else {
        if vendored {
            return early_directive().map_or(Ok(Vec::new()), Err);
        }
        return Err(skip(
            "vendor_scala_cli_resolution_missing",
            format!(
                "no scala-cli resolution under {}; run `scala-cli compile --test .` (with the \
                 default Bloop server: `--server=false` records none) and re-run",
                scala_evidence::BLOOP_DIR
            ),
        ));
    };
    if e.stale && vendored {
        return early_directive().map_or(Ok(Vec::new()), Err);
    }
    if e.stale {
        return Err(skip(
            "vendor_scala_cli_resolution_stale",
            format!(
                "a source changed after the last Bloop build ({}); run `scala-cli compile \
                 --test .` (a plain compile leaves the test project's evidence behind) and \
                 re-run",
                e.files.join(", ")
            ),
        ));
    }
    let root_only = BTreeSet::from([".".to_string()]);
    match check_new(Some(&e.resolution), Some(&root_only), false, g, a, base) {
        Ok(_) => {}
        Err(GateRefusal::NotResolved { .. }) => {
            return Err(skip(
                "vendor_scala_cli_not_resolved",
                format!("the scala-cli build does not resolve {g}:{a}; nothing to vendor"),
            ))
        }
        Err(GateRefusal::VersionConflict { found }) => {
            return Err(refuse(
                "vendor_scala_cli_version_conflict",
                format!(
                    "the scala-cli build resolves {g}:{a} at {}, not the patched {base}",
                    found.join(", ")
                ),
            ))
        }
        Err(GateRefusal::Classifier { found }) => {
            return Err(refuse(
                "vendor_scala_cli_classifier_unsupported",
                format!(
                    "the scala-cli build also resolves {g}:{a} with classifier {}, which the \
                     vendored tree (the plain jar only) cannot serve",
                    found.join(", ")
                ),
            ))
        }
        Err(GateRefusal::ScalaRuntime) => {
            return Err(refuse(
                "vendor_scala_cli_scala_runtime_unsupported",
                format!("{g}:{a} is the Scala runtime, which `//> using scala` selects"),
            ))
        }
        Err(other) => {
            return Err(skip(
                "vendor_scala_cli_resolution_missing",
                format!(
                    "the scala-cli resolution is unusable ({other:?}); run `scala-cli compile \
                     --test .`"
                ),
            ))
        }
    }
    if let Some(stop) = directive_refusal(project_root, &e.sources, g, a) {
        return Err(stop);
    }
    if let Some(path) = resolved_elsewhere(project_root, e, g, a, base) {
        return Err(refuse(
            "vendor_scala_cli_repository_shadowed",
            format!(
                "the last build after vendoring resolved {g}:{a}:{base} from {} instead of {}; \
                 a repository passed on the command line (`-r`) or declared elsewhere wins",
                path.display(),
                coursier_tree::TREE_ROOT
            ),
        ));
    }
    Ok(Vec::new())
}

/// `vendor_scala_cli_repository_shadowed` when an input declares a
/// repository or pins `g` to a direct `url=`.
fn directive_refusal(
    project_root: &Path,
    sources: &[PathBuf],
    g: &str,
    a: &str,
) -> Option<GateStop> {
    let (file, found) = repository_directive(project_root, sources, g)?;
    let detail = match found {
        Directive::Repository => format!(
            "{file} declares a repository; scala-cli consults it before the vendored tree, so \
             a copy of {g}:{a} there would win silently. Move it to COURSIER_REPOSITORIES \
             (consulted after the tree) or use hosted mode"
        ),
        Directive::DepUrl => format!(
            "{file} pins a {g} dependency to a direct `url=`, which scala-cli fetches \
             instead of resolving it from any repository, so the vendored tree would never \
             serve it. Drop the `url=` or use hosted mode"
        ),
    };
    Some(refuse("vendor_scala_cli_repository_shadowed", detail))
}

/// Whether the committed tree's index already lists `g:a:base` (under any
/// patch uuid: an update re-plans it too). FIFO-safe; an unreadable index
/// lists nothing (the planner refuses it).
fn already_vendored(project_root: &Path, g: &str, a: &str, base: &str) -> bool {
    let gav = format!("{g}:{a}:{base}");
    read_regular_to_bytes_sync(&project_root.join(coursier_tree::INDEX_REL))
        .ok()
        .and_then(|bytes| coursier_tree::parse_index(&bytes).ok())
        .is_some_and(|rows| rows.iter().any(|r| r.gav == gav))
}

fn skip(code: &'static str, detail: String) -> GateStop {
    GateStop::Skip(JvmWarning { code, detail })
}

fn refuse(code: &'static str, detail: String) -> GateStop {
    GateStop::Refuse(JvmRefusal { code, detail })
}

/// The project path must survive `file://${.}`: scala-cli percent-decodes
/// the URL (a `%` in the path points elsewhere, silently) and fails the
/// whole build on a non-ASCII one (probed: `Bad escape`).
fn check_path(project_root: &Path) -> Result<(), GateStop> {
    let canonical = std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.into());
    for p in [project_root, canonical.as_path()] {
        let s = p.to_string_lossy();
        if !s.is_ascii() || s.contains('%') {
            return Err(refuse(
                "vendor_scala_cli_path_unsupported",
                format!(
                    "the project path {} holds a non-ASCII character or `%`, which scala-cli's \
                     `file://${{.}}` repository URL cannot carry; move the checkout",
                    p.display()
                ),
            ));
        }
    }
    Ok(())
}

/// The first input (other than socket-patch's own files) that declares a
/// repository: `//> using repository|repositories|repo` or a `-r` /
/// `--repository` option. The inputs are every source the evidence lists,
/// inside the root or not (a `//> using file ../shared.scala` is as much an
/// input as a root file), plus the directory input's own source files (a
/// `.sc` script is listed only as its generated wrapper). Named
/// root-relative when under the root, absolute otherwise.
fn repository_directive(root: &Path, sources: &[PathBuf], g: &str) -> Option<(String, Directive)> {
    let directive = regex::Regex::new(
        r"(?m)^[ \t]*//>[ \t]*using[ \t]+(?:(?:repository|repositories|repo|repos)\b|options?\b[^\n]*?[ \t](?:-r|--repo|--repository)(?:[ \t=]|$))",
    )
    .expect("static regex");
    // `//> using dep "g:a:v,url=https://…/a.jar"` bypasses every repository.
    let dep_url = regex::Regex::new(&format!(
        r"(?m)^[ \t]*//>[ \t]*using[ \t]+(?:[A-Za-z]+\.)?(?:dep|deps|dependency|dependencies)\b[^\n]*{}:[^\n]*,[ \t]*url[ \t]*=",
        regex::escape(g)
    ))
    .ok()?;
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.into());
    let walked = scala_evidence::input_files(root).unwrap_or_default();
    let inputs = sources.iter().chain(walked.iter().map(|(_, p)| p));
    for src in inputs {
        let canonical = std::fs::canonicalize(src).unwrap_or_else(|_| src.clone());
        let rel = canonical
            .strip_prefix(&canonical_root)
            .ok()
            .map(|rel| rel.to_string_lossy().replace('\\', "/"));
        if rel.as_deref().is_some_and(scala_cli::is_wiring_file) {
            continue;
        }
        let small = std::fs::metadata(&canonical).is_ok_and(|m| m.len() <= MAX_SOURCE_BYTES);
        let Some(bytes) = small
            .then(|| read_regular_to_bytes_sync(&canonical).ok())
            .flatten()
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let found = if directive.is_match(&text) {
            Directive::Repository
        } else if dep_url.is_match(&text) {
            Directive::DepUrl
        } else {
            continue;
        };
        return Some((
            rel.unwrap_or_else(|| canonical.display().to_string()),
            found,
        ));
    }
    None
}

/// What [`repository_directive`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    /// A repository, consulted before the tree.
    Repository,
    /// A direct `url=` on a dependency of the patched group.
    DepUrl,
}

/// A path the build resolved `g:a:base` from outside the tree, when the
/// evidence was recorded after wiring (it lists the root file) and the tree
/// already holds that GAV.
fn resolved_elsewhere(
    root: &Path,
    e: &ScalaEvidence,
    g: &str,
    a: &str,
    base: &str,
) -> Option<PathBuf> {
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.into());
    let wired_build = e.sources.iter().any(|s| {
        s.file_name().is_some_and(|n| n == scala_cli::ROOT_FILE)
            && s.parent().is_some_and(|d| {
                d == root || std::fs::canonicalize(d).ok().as_deref() == Some(&canonical_root)
            })
    });
    let reader = super::apply::ProjectReader::new(root);
    let in_tree = coursier_tree::parse_index(&reader.read(coursier_tree::INDEX_REL)?)
        .ok()?
        .iter()
        .any(|r| r.gav == format!("{g}:{a}:{base}"));
    if !wired_build || !in_tree {
        return None;
    }
    let tree = [root, canonical_root.as_path()].map(|r| r.join(coursier_tree::TREE_ROOT));
    e.resolution
        .artifacts
        .get(&(g.to_string(), a.to_string(), base.to_string()))
        .into_iter()
        .flatten()
        .find(|p| {
            let canonical = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
            !tree
                .iter()
                .any(|t| p.starts_with(t) || canonical.starts_with(t))
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::sbt::JvmResolution;

    type TestModule<'a> = (&'a str, &'a str, &'a str, &'a [(&'a str, &'a str)]);

    fn evidence(modules: &[TestModule<'_>], sources: &[PathBuf]) -> ScalaEvidence {
        let mut res = JvmResolution::default();
        res.projects_seen.insert(".".into());
        for (g, a, v, arts) in modules {
            let ga = (g.to_string(), a.to_string());
            res.modules
                .entry(ga.clone())
                .or_default()
                .entry(v.to_string())
                .or_default()
                .insert("p.json:main".into());
            res.in_scope.insert(ga.clone());
            for (c, p) in *arts {
                if c.is_empty() {
                    res.artifacts
                        .entry((g.to_string(), a.to_string(), v.to_string()))
                        .or_default()
                        .insert(PathBuf::from(p));
                } else {
                    res.classifiers
                        .entry(ga.clone())
                        .or_default()
                        .insert(c.to_string());
                }
            }
        }
        ScalaEvidence {
            files: vec![".scala-build/.bloop/p.json".into()],
            resolution: res,
            sources: sources.to_vec(),
            stale: false,
        }
    }

    fn code(r: Result<Vec<JvmWarning>, GateStop>) -> (&'static str, bool) {
        match r {
            Ok(_) => ("ok", false),
            Err(GateStop::Skip(w)) => (w.code, true),
            Err(GateStop::Refuse(r)) => (r.code, false),
            Err(GateStop::Silent) => ("silent", false),
        }
    }

    const CONFIG: (&str, &str, &str, &[(&str, &str)]) = (
        "com.typesafe",
        "config",
        "1.4.3",
        &[("", "/cache/config-1.4.3.jar")],
    );

    #[test]
    fn run_level_conditions_skip() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert_eq!(
            code(gate(root, None, "com.typesafe", "config", "1.4.3")),
            ("vendor_scala_cli_resolution_missing", true)
        );
        assert_eq!(
            code(gate(
                root,
                Some(&evidence(&[], &[])),
                "com.typesafe",
                "config",
                "1.4.3"
            )),
            ("vendor_scala_cli_not_resolved", true),
            "a build with no dependencies resolves nothing"
        );
        let mut stale = evidence(&[CONFIG], &[]);
        stale.stale = true;
        assert_eq!(
            code(gate(root, Some(&stale), "com.typesafe", "config", "1.4.3")),
            ("vendor_scala_cli_resolution_stale", true)
        );
        assert_eq!(
            code(gate(
                root,
                Some(&evidence(&[CONFIG], &[])),
                "org.x",
                "y",
                "1"
            )),
            ("vendor_scala_cli_not_resolved", true)
        );
    }

    #[test]
    fn a_vendored_gav_is_replanned_without_fresh_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let row = coursier_tree::IndexRow {
            gav: "com.typesafe:config:1.4.3".into(),
            rel: "com/typesafe/config/1.4.3/config-1.4.3.jar".into(),
            sha256: "a".repeat(64),
            uuid: "5b7a0000-0000-4000-8000-000000000001".into(),
        };
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::write(
            root.join(coursier_tree::INDEX_REL),
            coursier_tree::render_index(&[row]),
        )
        .unwrap();
        // A fresh clone (no `.scala-build`), or a source edit since.
        assert_eq!(
            code(gate(root, None, "com.typesafe", "config", "1.4.3")),
            ("ok", false)
        );
        let mut stale = evidence(&[CONFIG], &[]);
        stale.stale = true;
        assert_eq!(
            code(gate(root, Some(&stale), "com.typesafe", "config", "1.4.3")),
            ("ok", false)
        );
        // Another GAV still needs the evidence.
        assert_eq!(
            code(gate(root, None, "com.typesafe", "config", "1.4.4")),
            ("vendor_scala_cli_resolution_missing", true)
        );
        // A repository directive needs no evidence to refuse: adding one
        // (which also makes the evidence stale) is caught before a rebuild.
        std::fs::write(
            root.join("Main.scala"),
            "//> using repository https://nexus.corp/maven\nobject Main\n",
        )
        .unwrap();
        assert_eq!(
            code(gate(root, None, "com.typesafe", "config", "1.4.3")),
            ("vendor_scala_cli_repository_shadowed", false)
        );
        assert_eq!(
            code(gate(root, Some(&stale), "com.typesafe", "config", "1.4.3")),
            ("vendor_scala_cli_repository_shadowed", false)
        );
    }

    #[test]
    fn per_patch_refusals() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let e = evidence(&[CONFIG], &[]);
        assert_eq!(
            code(gate(root, Some(&e), "com.typesafe", "config", "1.4.3")),
            ("ok", false)
        );
        assert_eq!(
            code(gate(root, Some(&e), "com.typesafe", "config", "1.4.2")),
            ("vendor_scala_cli_version_conflict", false)
        );
        let two = evidence(&[CONFIG, ("com.typesafe", "config", "1.4.2", &[])], &[]);
        assert_eq!(
            code(gate(root, Some(&two), "com.typesafe", "config", "1.4.3")),
            ("vendor_scala_cli_version_conflict", false)
        );
        let classified = evidence(
            &[(
                "com.typesafe",
                "config",
                "1.4.3",
                &[("", "/c/x.jar"), ("natives", "/c/n.jar")],
            )],
            &[],
        );
        assert_eq!(
            code(gate(
                root,
                Some(&classified),
                "com.typesafe",
                "config",
                "1.4.3"
            )),
            ("vendor_scala_cli_classifier_unsupported", false)
        );
        let sources = evidence(
            &[(
                "com.typesafe",
                "config",
                "1.4.3",
                &[("", "/c/x.jar"), ("sources", "/c/s.jar")],
            )],
            &[],
        );
        assert_eq!(
            code(gate(
                root,
                Some(&sources),
                "com.typesafe",
                "config",
                "1.4.3"
            )),
            ("ok", false)
        );
        let scala = evidence(&[("org.scala-lang", "scala3-library_3", "3.3.6", &[])], &[]);
        assert_eq!(
            code(gate(
                root,
                Some(&scala),
                "org.scala-lang",
                "scala3-library_3",
                "3.3.6"
            )),
            ("vendor_scala_cli_scala_runtime_unsupported", false)
        );
    }

    #[test]
    fn repository_directives_in_inputs_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let write = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            p
        };
        let main = write(
            "main.scala",
            "//> using dep com.typesafe:config:1.4.3\n@main def m() = ()\n",
        );
        let ours = write(scala_cli::ROOT_FILE, scala_cli::ROOT_BYTES);
        let guard = write(scala_cli::GUARD_REL, scala_cli::GUARD_BYTES);
        let clean = vec![main.clone(), ours.clone(), guard.clone()];
        let e = evidence(&[CONFIG], &clean);
        assert_eq!(
            code(gate(&root, Some(&e), "com.typesafe", "config", "1.4.3")),
            ("ok", false),
            "socket-patch's own directive never counts"
        );
        // An input outside the root (`//> using file ../shared.scala`) is
        // still an input: its repository shadows the tree too.
        let outside = tempfile::tempdir().unwrap();
        let foreign = outside.path().canonicalize().unwrap().join("x.scala");
        std::fs::write(&foreign, "//> using repository central\n").unwrap();
        let mut with = clean.clone();
        with.push(foreign.clone());
        let r = gate(
            &root,
            Some(&evidence(&[CONFIG], &with)),
            "com.typesafe",
            "config",
            "1.4.3",
        );
        let Err(GateStop::Refuse(r)) = r else {
            panic!("an outside input's repository must refuse: {r:?}")
        };
        assert_eq!(r.code, "vendor_scala_cli_repository_shadowed");
        assert!(
            r.detail.starts_with(&foreign.display().to_string()),
            "{}",
            r.detail
        );
        // A `.sc` script is listed only as its generated wrapper, so the
        // script itself is scanned from the directory input.
        let script = write("tools/gen.sc", "//> using repository jitpack\nprintln(1)\n");
        let r = gate(
            &root,
            Some(&evidence(&[CONFIG], &clean)),
            "com.typesafe",
            "config",
            "1.4.3",
        );
        let Err(GateStop::Refuse(r)) = r else {
            panic!("a script's repository must refuse: {r:?}")
        };
        assert!(
            r.detail.starts_with("tools/gen.sc declares"),
            "{}",
            r.detail
        );
        std::fs::remove_file(script).unwrap();
        for body in [
            "//> using repository https://repo1.maven.org/maven2\n",
            "  //>  using repositories central sonatype:snapshots\n",
            "//> using repo jitpack\n",
            "//> using options -r https://example.com/m2\n",
            "//> using option --repository=https://example.com/m2\n",
        ] {
            let src = write("src/a.scala", body);
            let mut with = clean.clone();
            with.push(src);
            let e = evidence(&[CONFIG], &with);
            let r = gate(&root, Some(&e), "com.typesafe", "config", "1.4.3");
            assert_eq!(
                code(r.clone()),
                ("vendor_scala_cli_repository_shadowed", false),
                "{body}"
            );
            let Err(GateStop::Refuse(r)) = r else {
                unreachable!()
            };
            assert!(r.detail.starts_with("src/a.scala declares"), "{}", r.detail);
        }
        // A direct `url=` on a dependency of the patched group bypasses
        // every repository; one on another group does not matter.
        for (body, refused) in [
            (
                "//> using dep \"com.typesafe:config:1.4.3,url=https://x/c.jar\"\n",
                true,
            ),
            (
                "//> using test.dep com.typesafe::config:1.4.3,url=https://x/c.jar\n",
                true,
            ),
            (
                "//> using dep \"org.other:lib:1,url=https://x/l.jar\"\n",
                false,
            ),
            ("//> using dep com.typesafe:config:1.4.3\n", false),
        ] {
            let src = write("src/a.scala", body);
            let mut with = clean.clone();
            with.push(src);
            let r = gate(
                &root,
                Some(&evidence(&[CONFIG], &with)),
                "com.typesafe",
                "config",
                "1.4.3",
            );
            match r {
                Err(GateStop::Refuse(r)) if refused => {
                    assert_eq!(r.code, "vendor_scala_cli_repository_shadowed");
                    assert!(r.detail.contains("url="), "{}", r.detail);
                }
                Ok(_) if !refused => {}
                other => panic!("{body}: {other:?}"),
            }
        }
        for harmless in [
            "//> using dep com.example:repository:1\n",
            "// using repository x\n",
            "//> using options -release 17\n",
        ] {
            let src = write("src/a.scala", harmless);
            let mut with = clean.clone();
            with.push(src);
            let e = evidence(&[CONFIG], &with);
            assert_eq!(
                code(gate(&root, Some(&e), "com.typesafe", "config", "1.4.3")),
                ("ok", false),
                "{harmless}"
            );
        }
    }

    #[test]
    fn post_wiring_evidence_must_resolve_from_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let root_file = root.join(scala_cli::ROOT_FILE);
        std::fs::write(&root_file, scala_cli::ROOT_BYTES).unwrap();
        let sha = "a".repeat(64);
        let index = format!(
            "{}\ncom.typesafe:config:1.4.3\tcom/typesafe/config/1.4.3/config-1.4.3.jar\t{sha}\tabcdef12-3456-4789-8abc-def012345678\n",
            coursier_tree::INDEX_HEADER
        );
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::write(root.join(coursier_tree::INDEX_REL), index).unwrap();
        let tree_jar = root
            .join(coursier_tree::TREE_ROOT)
            .join("com/typesafe/config/1.4.3/config-1.4.3.jar");
        let tree_jar = tree_jar.to_string_lossy().into_owned();
        let in_tree: (&str, &str, &str, &[(&str, &str)]) = (
            "com.typesafe",
            "config",
            "1.4.3",
            &[("", tree_jar.as_str())],
        );
        let e = evidence(&[in_tree], std::slice::from_ref(&root_file));
        assert_eq!(
            code(gate(&root, Some(&e), "com.typesafe", "config", "1.4.3")),
            ("ok", false)
        );
        let e = evidence(&[CONFIG], std::slice::from_ref(&root_file));
        assert_eq!(
            code(gate(&root, Some(&e), "com.typesafe", "config", "1.4.3")),
            ("vendor_scala_cli_repository_shadowed", false)
        );
        // Evidence from before the wiring proves nothing either way.
        let e = evidence(&[CONFIG], &[]);
        assert_eq!(
            code(gate(&root, Some(&e), "com.typesafe", "config", "1.4.3")),
            ("ok", false)
        );
        // A GA the tree does not hold yet is not checked.
        assert_eq!(
            code(gate(
                &root,
                Some(&evidence(
                    &[("g", "a", "1", &[("", "/c/a.jar")])],
                    &[root_file]
                )),
                "g",
                "a",
                "1"
            )),
            ("ok", false)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn project_paths_scala_cli_cannot_carry_are_refused() {
        for name in ["a%20b", "ü-proj"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join(name);
            std::fs::create_dir_all(&root).unwrap();
            assert_eq!(
                code(check(&root, "g", "a", "1")),
                ("vendor_scala_cli_path_unsupported", false),
                "{name}"
            );
        }
        for name in ["my proj", "a#b", "a[b]+c"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join(name);
            std::fs::create_dir_all(&root).unwrap();
            assert_eq!(
                code(check(&root, "g", "a", "1")),
                ("vendor_scala_cli_resolution_missing", true),
                "{name}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            code(check(tmp.path(), "g", "a", "1")),
            ("vendor_scala_cli_windows_unsupported", false)
        );
    }
}
