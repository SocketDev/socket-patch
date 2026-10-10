//! scala-cli resolution evidence: what a scala-cli directory build
//! resolved, read from the Bloop project files scala-cli writes under
//! `<root>/.scala-build/.bloop/<project>.json` (Bloop config 1.4.0), as a
//! [`JvmResolution`] for `vendor::jvm::coursier_gate`. Never runs scala-cli.
//!
//! Probed on scala-cli 1.17.1 (`docs/design/sbt-support.md`, "scala-cli
//! evidence"):
//! - the files are written only when Bloop compiles (the default); a
//!   `--server=false` build writes and refreshes none;
//! - each input set gets its own project (`<dir>_<hash>[-<hash>]`, plus a
//!   `-test` twin once test sources exist), and the old ones stay behind, so
//!   only the newest project (and its `-test` twin) of this workspace
//!   counts;
//! - `project.resolution.modules[]` lists every resolved module with its
//!   artifacts' absolute paths (`classifier` for non-main artifacts), and
//!   `project.sources` the absolute input files.
//!
//! Reads are FIFO-safe and capped ([`MAX_FILES`], [`MAX_FILE_BYTES`]);
//! `.scala-build` and `.bloop` must be real directories (a symlink there is
//! no evidence), and symlinked project files are skipped. A project file
//! that is over the cap, unreadable or not a Bloop project fails closed (no
//! evidence at all), as the sbt reader does: it could be the record naming
//! a conflicting version.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;

use super::jvm_cache::debug_log;
use crate::formats::sbt::JvmResolution;
use crate::utils::fs::read_regular_to_bytes_sync;

/// The Bloop project directory, root-relative.
pub const BLOOP_DIR: &str = ".scala-build/.bloop";
/// Most project files read; over it there is no evidence at all.
pub const MAX_FILES: usize = 256;
/// Largest project file read; a bigger one means no evidence at all.
pub const MAX_FILE_BYTES: u64 = 8 << 20;
/// Source extensions scala-cli compiles from a directory input.
const SOURCE_EXTENSIONS: &[&str] = &["scala", "sc", "java"];

/// One resolved module: `(group, artifact, version, [(classifier, path)])`;
/// classifier `""` for the main artifact.
pub type BloopModule = (String, String, String, Vec<(String, PathBuf)>);

/// One parsed Bloop project file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BloopProject {
    pub name: String,
    /// `project.workspaceDir`: the directory scala-cli was pointed at.
    pub workspace_dir: Option<PathBuf>,
    /// The test twin (`-test` name or a `test` tag).
    pub test: bool,
    pub sources: Vec<PathBuf>,
    pub modules: Vec<BloopModule>,
}

/// What the newest Bloop project of a workspace recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScalaEvidence {
    /// Root-relative paths of the project files used.
    pub files: Vec<String>,
    pub resolution: JvmResolution,
    /// Every input file the projects list (absolute, as scala-cli wrote it).
    pub sources: Vec<PathBuf>,
    /// A listed source is gone or newer than the evidence, or a top-level
    /// source the projects do not list is newer: the build changed since.
    pub stale: bool,
}

/// Parse one Bloop project file; `None` when it is not one.
pub fn parse_bloop(bytes: &[u8]) -> Option<BloopProject> {
    let doc: Value = serde_json::from_slice(bytes).ok()?;
    let p = doc.get("project")?.as_object()?;
    let name = p.get("name")?.as_str()?.to_string();
    let tags: Vec<&str> = p
        .get("tags")
        .and_then(Value::as_array)
        .map(|t| t.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let paths = |v: Option<&Value>| -> Vec<PathBuf> {
        v.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(PathBuf::from)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut modules = Vec::new();
    let listed = p
        .get("resolution")
        .and_then(|r| r.get("modules"))
        .and_then(Value::as_array);
    for m in listed.into_iter().flatten() {
        let s = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
        let (Some(g), Some(a), Some(v)) = (s("organization"), s("name"), s("version")) else {
            return None;
        };
        let artifacts = m
            .get("artifacts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|art| {
                let path = art.get("path")?.as_str()?;
                let classifier = art.get("classifier").and_then(Value::as_str).unwrap_or("");
                Some((classifier.to_string(), PathBuf::from(path)))
            })
            .collect();
        modules.push((g, a, v, artifacts));
    }
    Some(BloopProject {
        test: name.ends_with("-test") || tags.contains(&"test"),
        name,
        workspace_dir: p
            .get("workspaceDir")
            .and_then(Value::as_str)
            .map(PathBuf::from),
        sources: paths(p.get("sources")),
        modules,
    })
}

/// The resolution of `projects` (the newest main project and its test
/// twin), each fact tagged `<file>:<main|test>`.
pub fn resolution_of(projects: &[(String, BloopProject)]) -> JvmResolution {
    let mut res = JvmResolution::default();
    for (file, p) in projects {
        let id = format!("{file}:{}", if p.test { "test" } else { "main" });
        res.projects_seen.insert(".".to_string());
        for (g, a, v, artifacts) in &p.modules {
            let ga = (g.clone(), a.clone());
            res.modules
                .entry(ga.clone())
                .or_default()
                .entry(v.clone())
                .or_default()
                .insert(id.clone());
            res.in_scope.insert(ga.clone());
            for (classifier, path) in artifacts {
                if classifier.is_empty() {
                    res.artifacts
                        .entry((g.clone(), a.clone(), v.clone()))
                        .or_default()
                        .insert(path.clone());
                } else {
                    res.classifiers
                        .entry(ga.clone())
                        .or_default()
                        .insert(classifier.clone());
                }
            }
        }
    }
    res
}

/// The evidence under `root`, `None` when there is none.
pub fn discover(root: &Path) -> Option<ScalaEvidence> {
    let dir = root.join(BLOOP_DIR);
    for d in [
        root.join(crate::vendor::jvm::layout::SCALA_CLI_DIR),
        dir.clone(),
    ] {
        match std::fs::symlink_metadata(&d) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                debug_log(&format!(
                    "scala-cli evidence: {} is not a directory",
                    d.display()
                ));
                return None;
            }
            Err(_) => return None,
        }
    }
    let canonical_root = std::fs::canonicalize(root).ok();
    let same_workspace = |ws: &Path| {
        ws == root
            || canonical_root
                .as_deref()
                .is_some_and(|c| std::fs::canonicalize(ws).ok().as_deref() == Some(c))
    };
    let mut found: Vec<(SystemTime, String, BloopProject)> = Vec::new();
    let entries = std::fs::read_dir(&dir).ok()?;
    for (n, entry) in entries.flatten().enumerate() {
        if n >= MAX_FILES {
            debug_log(&format!(
                "scala-cli evidence: over {MAX_FILES} files in {BLOOP_DIR}"
            ));
            return None;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        // A project file that cannot be read whole (over the cap, a read
        // error, a truncated or foreign record) could be the one naming a
        // conflicting version: no evidence at all, as for sbt
        // (`formats::sbt::evidence::resolution`), never a partial one.
        if meta.len() > MAX_FILE_BYTES {
            debug_log(&format!(
                "scala-cli evidence: {} is over the {MAX_FILE_BYTES}-byte cap",
                path.display()
            ));
            return None;
        }
        let (Ok(bytes), Ok(written)) = (read_regular_to_bytes_sync(&path), meta.modified()) else {
            debug_log(&format!(
                "scala-cli evidence: cannot read {}",
                path.display()
            ));
            return None;
        };
        let mtime = compiled_at(&dir.join(name.trim_end_matches(".json")), written);
        let Some(project) = parse_bloop(&bytes) else {
            debug_log(&format!(
                "scala-cli evidence: {} is not a Bloop project",
                path.display()
            ));
            return None;
        };
        if !project.workspace_dir.as_deref().is_some_and(same_workspace) {
            continue;
        }
        found.push((mtime, format!("{BLOOP_DIR}/{name}"), project));
    }
    let base = |p: &BloopProject| p.name.strip_suffix("-test").unwrap_or(&p.name).to_string();
    let newest = found
        .iter()
        .max_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(&y.1)))?;
    let group = base(&newest.2);
    let mut chosen: Vec<&(SystemTime, String, BloopProject)> =
        found.iter().filter(|f| base(&f.2) == group).collect();
    chosen.sort_by(|x, y| x.1.cmp(&y.1));
    let oldest = chosen.iter().map(|f| f.0).min()?;
    let projects: Vec<(String, BloopProject)> =
        chosen.iter().map(|f| (f.1.clone(), f.2.clone())).collect();
    let mut sources: Vec<PathBuf> = projects
        .iter()
        .flat_map(|(_, p)| p.sources.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    sources.sort();
    let stale = is_stale(root, &sources, oldest);
    Some(ScalaEvidence {
        files: projects.iter().map(|(f, _)| f.clone()).collect(),
        resolution: resolution_of(&projects),
        sources,
        stale,
    })
}

/// When the Bloop project whose output directory is `out` (`.bloop/<name>/`)
/// last compiled: the newest of `written` (its project file's mtime) and
/// the mtimes of `out` and its direct entries (`<name>-analysis.bin`,
/// `bloop-internal-classes`). Probed on scala-cli 1.17.1: the project file
/// is rewritten only when its content (sources, resolution) changes, while
/// every compile of the project, even of touched-only sources, refreshes
/// `bloop-internal-classes`; so a source edited and then compiled is not
/// newer than the evidence. A symlinked `out` is ignored.
fn compiled_at(out: &Path, written: SystemTime) -> SystemTime {
    let mtime = |p: &Path| std::fs::symlink_metadata(p).and_then(|m| m.modified()).ok();
    if !std::fs::symlink_metadata(out).is_ok_and(|m| m.is_dir()) {
        return written;
    }
    let children = std::fs::read_dir(out)
        .into_iter()
        .flatten()
        .flatten()
        .take(MAX_FILES)
        .filter_map(|e| mtime(&e.path()));
    children.chain(mtime(out)).fold(written, std::cmp::max)
}

/// The resolution recorded under `root/.scala-build`, `None` when none.
pub fn resolution(root: &Path) -> Option<JvmResolution> {
    discover(root).map(|e| e.resolution)
}

/// Most entries [`input_files`] walks under the root; past it the evidence
/// counts as stale (no vendoring over a tree too big to check).
pub const MAX_WALK_ENTRIES: usize = 20_000;
/// Deepest directory [`input_files`] walks into; deeper counts as stale too.
const MAX_WALK_DEPTH: usize = 32;

/// Whether a listed source is gone or newer than `evidence_time`, a source
/// file anywhere in the directory input the evidence does not list is newer
/// (scala-cli compiles every non-hidden source below the root, so a file
/// added in a subdirectory changes the build as much as one at the top), or
/// the root's `project.scala` is not listed at all (the evidence is from a
/// single-file run, not this directory build). The files socket-patch owns
/// never count: vendoring writes them after the build.
fn is_stale(root: &Path, sources: &[PathBuf], evidence_time: SystemTime) -> bool {
    // Without Windows' verbatim prefix, which bloop's paths never carry.
    let canonical_root = std::fs::canonicalize(root)
        .map(|c| super::sbt_evidence::strip_verbatim(&c))
        .unwrap_or_else(|_| root.to_path_buf());
    let rel_of = |p: &Path| {
        p.strip_prefix(root)
            .or_else(|_| p.strip_prefix(&canonical_root))
            .ok()
            .map(|rel| rel.to_string_lossy().replace('\\', "/"))
    };
    let owned =
        |p: &Path| rel_of(p).is_some_and(|rel| crate::vendor::jvm::scala_cli::is_wiring_file(&rel));
    // scala-cli's own generated wrappers (a `.sc` script's) track the script,
    // which the walk below checks.
    let generated = |p: &Path| rel_of(p).is_some_and(|rel| rel.starts_with(".scala-build/"));
    let newer = |p: &Path| match std::fs::metadata(p).and_then(|m| m.modified()) {
        Ok(t) => t > evidence_time,
        Err(_) => true,
    };
    if sources
        .iter()
        .any(|p| !owned(p) && !generated(p) && newer(p))
    {
        return true;
    }
    let listed: BTreeSet<String> = sources.iter().filter_map(|p| rel_of(p)).collect();
    let project = crate::vendor::jvm::layout::SCALA_CLI_FILE;
    if !listed.contains(project) && std::fs::symlink_metadata(root.join(project)).is_ok() {
        debug_log("scala-cli evidence: the newest project does not list project.scala");
        return true;
    }
    let Some(inputs) = input_files(root) else {
        return true;
    };
    inputs
        .iter()
        .any(|(rel, path)| !owned(path) && !listed.contains(rel) && newer(path))
}

/// The source files of the directory input at `root` as `(rel, path)`:
/// every `.scala` / `.sc` / `.java` file below it, skipping hidden entries
/// (`.scala-build`, `.socket`, `.git`: scala-cli skips them too) and not
/// following symlinked directories. `None` past [`MAX_WALK_ENTRIES`] or
/// [`MAX_WALK_DEPTH`]. Probed on scala-cli 1.17.1: subdirectories are inputs,
/// hidden ones are not, and a `.sc` script is listed in the Bloop project
/// only as its generated wrapper under `.scala-build`, so the script itself
/// is found here, not in the evidence.
pub fn input_files(root: &Path) -> Option<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    let mut seen = 0usize;
    while let Some((dir, prefix, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            seen += 1;
            if seen > MAX_WALK_ENTRIES {
                debug_log(&format!(
                    "scala-cli evidence: over {MAX_WALK_ENTRIES} entries under the root"
                ));
                return None;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let rel = format!("{prefix}{name}");
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if depth + 1 > MAX_WALK_DEPTH {
                    debug_log(&format!("scala-cli evidence: {rel} is too deep"));
                    return None;
                }
                stack.push((e.path(), format!("{rel}/"), depth + 1));
            } else if name
                .rsplit_once('.')
                .is_some_and(|(_, ext)| SOURCE_EXTENSIONS.contains(&ext))
            {
                out.push((rel, e.path()));
            }
        }
    }
    out.sort();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    type TestModule<'a> = (&'a str, &'a str, &'a str, &'a [(&'a str, &'a str)]);

    /// A Bloop project file the way scala-cli 1.17.1 writes it.
    pub(crate) fn bloop_json(
        name: &str,
        workspace: &Path,
        sources: &[&Path],
        modules: &[TestModule<'_>],
    ) -> String {
        let mods: Vec<Value> = modules
            .iter()
            .map(|(g, a, v, arts)| {
                let arts: Vec<Value> = arts
                    .iter()
                    .map(|(c, p)| {
                        if c.is_empty() {
                            serde_json::json!({ "name": a, "path": p })
                        } else {
                            serde_json::json!({ "name": a, "classifier": c, "path": p })
                        }
                    })
                    .collect();
                serde_json::json!({ "organization": g, "name": a, "version": v, "artifacts": arts })
            })
            .collect();
        serde_json::json!({
            "version": "1.4.0",
            "project": {
                "name": name,
                "directory": workspace.join(".scala-build"),
                "workspaceDir": workspace,
                "sources": sources,
                "dependencies": [],
                "classpath": [],
                "out": workspace.join(".scala-build/.bloop").join(name),
                "classesDir": workspace.join(".scala-build/.bloop").join(name).join("classes"),
                "resolution": { "modules": mods },
                "tags": if name.ends_with("-test") { vec!["test"] } else { vec!["library"] },
            }
        })
        .to_string()
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn set_mtime(path: &Path, t: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    fn ga(g: &str, a: &str) -> (String, String) {
        (g.into(), a.into())
    }

    #[test]
    fn parses_the_probed_shape() {
        let ws = Path::new("/sc");
        let json = bloop_json(
            "sc_baeca91196-ec0aa7af9f",
            ws,
            &[Path::new("/sc/main.scala")],
            &[
                (
                    "com.typesafe",
                    "config",
                    "1.4.3",
                    &[("", "/c/config-1.4.3.jar")],
                ),
                (
                    "org.slf4j",
                    "slf4j-api",
                    "2.0.9",
                    &[("", "/c/s.jar"), ("sources", "/c/s-sources.jar")],
                ),
            ],
        );
        let p = parse_bloop(json.as_bytes()).unwrap();
        assert_eq!(p.name, "sc_baeca91196-ec0aa7af9f");
        assert!(!p.test);
        assert_eq!(p.workspace_dir.as_deref(), Some(ws));
        assert_eq!(p.modules.len(), 2);
        let res = resolution_of(&[("f.json".into(), p)]);
        assert_eq!(res.versions("com.typesafe", "config"), ["1.4.3"]);
        assert!(res.in_scope.contains(&ga("com.typesafe", "config")));
        assert_eq!(
            res.artifacts[&("com.typesafe".into(), "config".into(), "1.4.3".into())],
            BTreeSet::from([PathBuf::from("/c/config-1.4.3.jar")])
        );
        assert_eq!(
            res.classifiers[&ga("org.slf4j", "slf4j-api")],
            BTreeSet::from(["sources".to_string()])
        );
        assert_eq!(res.projects_seen, BTreeSet::from([".".to_string()]));
    }

    #[test]
    fn rejects_non_bloop_json() {
        assert_eq!(parse_bloop(b"{}"), None);
        assert_eq!(parse_bloop(b"not json"), None);
        assert_eq!(
            parse_bloop(br#"{"project":{"name":"x","resolution":{"modules":[{"name":"a"}]}}}"#),
            None
        );
        // No resolution at all is a project with no modules.
        let p = parse_bloop(br#"{"project":{"name":"x-test"}}"#).unwrap();
        assert!(p.test && p.modules.is_empty());
    }

    #[test]
    fn no_scala_build_is_no_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(discover(tmp.path()), None);
        std::fs::create_dir_all(tmp.path().join(BLOOP_DIR)).unwrap();
        assert_eq!(discover(tmp.path()), None, "an empty .bloop is no evidence");
    }

    #[test]
    fn newest_project_and_its_test_twin_win() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let main = root.join("main.scala");
        write(&main, "//> using dep com.typesafe:config:1.4.3\n");
        let t0 = SystemTime::now() - Duration::from_secs(600);
        set_mtime(&main, t0);
        let old = root.join(BLOOP_DIR).join("sc_old.json");
        let new = root.join(BLOOP_DIR).join("sc_new.json");
        let test = root.join(BLOOP_DIR).join("sc_new-test.json");
        let other_ws = root.join(BLOOP_DIR).join("sub_x.json");
        write(
            &old,
            &bloop_json(
                "sc_old",
                &root,
                &[&main],
                &[("com.typesafe", "config", "1.4.2", &[("", "/c/old.jar")])],
            ),
        );
        write(
            &new,
            &bloop_json(
                "sc_new",
                &root,
                &[&main],
                &[("com.typesafe", "config", "1.4.3", &[("", "/c/new.jar")])],
            ),
        );
        write(
            &test,
            &bloop_json(
                "sc_new-test",
                &root,
                &[&main],
                &[("org.scalameta", "munit_3", "1.0.0", &[("", "/c/m.jar")])],
            ),
        );
        write(
            &other_ws,
            &bloop_json("sub_x", &root.join("sub"), &[], &[("x", "y", "9", &[])]),
        );
        set_mtime(&old, t0 + Duration::from_secs(10));
        set_mtime(&new, t0 + Duration::from_secs(100));
        set_mtime(&test, t0 + Duration::from_secs(90));
        set_mtime(&other_ws, t0 + Duration::from_secs(200));
        let e = discover(&root).unwrap();
        assert_eq!(
            e.files,
            [
                format!("{BLOOP_DIR}/sc_new-test.json"),
                format!("{BLOOP_DIR}/sc_new.json")
            ]
        );
        assert_eq!(e.resolution.versions("com.typesafe", "config"), ["1.4.3"]);
        assert!(e
            .resolution
            .in_scope
            .contains(&ga("org.scalameta", "munit_3")));
        assert!(!e.resolution.in_scope.contains(&ga("x", "y")));
        assert_eq!(
            e.resolution.modules[&ga("org.scalameta", "munit_3")]["1.0.0"],
            BTreeSet::from([format!("{BLOOP_DIR}/sc_new-test.json:test")])
        );
        assert!(!e.stale);
        assert_eq!(resolution(&root), Some(e.resolution));
    }

    #[test]
    fn staleness_follows_sources_but_not_owned_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let main = root.join("main.scala");
        write(&main, "x");
        let ev = root.join(BLOOP_DIR).join("p.json");
        write(
            &ev,
            &bloop_json("p", &root, &[&main], &[("g", "a", "1", &[])]),
        );
        let t0 = SystemTime::now() - Duration::from_secs(600);
        set_mtime(&main, t0);
        set_mtime(&ev, t0 + Duration::from_secs(5));
        assert!(!discover(&root).unwrap().stale);
        // socket-patch's own files are written after the build.
        write(
            &root.join("socket-patch.scala"),
            "// managed by socket-patch\n",
        );
        assert!(!discover(&root).unwrap().stale);
        // A listed source edited since.
        set_mtime(&main, t0 + Duration::from_secs(50));
        assert!(discover(&root).unwrap().stale);
        set_mtime(&main, t0);
        // A new top-level source the build never saw.
        write(&root.join("extra.sc"), "x");
        assert!(discover(&root).unwrap().stale);
        std::fs::remove_file(root.join("extra.sc")).unwrap();
        // A hidden or non-source file never counts.
        write(&root.join("README.md"), "x");
        write(&root.join(".hidden.scala"), "x");
        assert!(!discover(&root).unwrap().stale);
        // A listed source deleted since.
        std::fs::remove_file(&main).unwrap();
        assert!(discover(&root).unwrap().stale);
    }

    #[test]
    fn staleness_covers_subdirectories_scripts_and_single_file_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let t0 = SystemTime::now() - Duration::from_secs(600);
        let main = root.join("main.scala");
        let project = root.join("project.scala");
        let script = root.join("tools/gen.sc");
        let wrapper = root.join(".scala-build/p/src_generated/main/gen.scala");
        for f in [&main, &project, &script, &wrapper] {
            write(f, "x");
            set_mtime(f, t0);
        }
        let ev = root.join(BLOOP_DIR).join("p.json");
        let listed: [&Path; 3] = [&main, &project, &wrapper];
        write(
            &ev,
            &bloop_json("p", &root, &listed, &[("g", "a", "1", &[])]),
        );
        set_mtime(&ev, t0 + Duration::from_secs(5));
        assert!(!discover(&root).unwrap().stale);
        // scala-cli rewrites a script's wrapper; only the script counts.
        set_mtime(&wrapper, t0 + Duration::from_secs(50));
        assert!(!discover(&root).unwrap().stale);
        set_mtime(&script, t0 + Duration::from_secs(50));
        assert!(discover(&root).unwrap().stale, "an edited script");
        set_mtime(&script, t0);
        // A new source in a subdirectory is part of the directory build.
        let nested = root.join("src/deep/b.scala");
        write(&nested, "//> using dep g:a:2\n");
        assert!(discover(&root).unwrap().stale, "a new nested source");
        set_mtime(&nested, t0);
        assert!(!discover(&root).unwrap().stale);
        // Hidden directories are not inputs.
        write(&root.join(".hid/c.scala"), "x");
        assert!(!discover(&root).unwrap().stale);
        // Evidence of a single-file run never lists project.scala.
        let single: [&Path; 1] = [&main];
        write(
            &ev,
            &bloop_json("p", &root, &single, &[("g", "a", "1", &[])]),
        );
        set_mtime(&ev, t0 + Duration::from_secs(5));
        assert!(discover(&root).unwrap().stale, "single-file evidence");
        let inputs: Vec<String> = input_files(&root)
            .unwrap()
            .into_iter()
            .map(|(r, _)| r)
            .collect();
        assert_eq!(
            inputs,
            [
                "main.scala",
                "project.scala",
                "src/deep/b.scala",
                "tools/gen.sc"
            ]
        );
    }

    #[test]
    fn a_compile_that_keeps_the_project_file_still_refreshes_the_evidence() {
        // scala-cli 1.17.1 leaves `<name>.json` alone when its content is
        // unchanged; the compile shows in `.bloop/<name>/` instead.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let t0 = SystemTime::now() - Duration::from_secs(600);
        let main = root.join("main.scala");
        write(&main, "x");
        let ev = root.join(BLOOP_DIR).join("p.json");
        write(
            &ev,
            &bloop_json("p", &root, &[&main], &[("g", "a", "1", &[])]),
        );
        let classes = root.join(BLOOP_DIR).join("p/bloop-internal-classes");
        std::fs::create_dir_all(&classes).unwrap();
        // Windows opens a directory only with backup semantics, and dates
        // it only through a handle with write access.
        let set_dir_mtime = |d: &Path, t: SystemTime| {
            let mut opts = std::fs::OpenOptions::new();
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
                opts.write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
            }
            #[cfg(not(windows))]
            opts.read(true);
            opts.open(d).unwrap().set_modified(t).unwrap();
        };
        set_mtime(&ev, t0);
        set_dir_mtime(&classes, t0);
        set_dir_mtime(&root.join(BLOOP_DIR).join("p"), t0);
        set_mtime(&main, t0 + Duration::from_secs(50));
        assert!(discover(&root).unwrap().stale, "edited, not compiled");
        set_dir_mtime(&classes, t0 + Duration::from_secs(60));
        assert!(!discover(&root).unwrap().stale, "edited, then compiled");
    }

    #[test]
    fn caps_and_special_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let dir = root.join(BLOOP_DIR);
        write(
            &dir.join("big.json"),
            &" ".repeat(MAX_FILE_BYTES as usize + 1),
        );
        assert_eq!(discover(&root), None, "an oversized file is no evidence");
        write(
            &dir.join("p.json"),
            &bloop_json("p", &root, &[], &[("g", "a", "1", &[])]),
        );
        assert_eq!(
            discover(&root),
            None,
            "an oversized project file fails closed beside a readable one"
        );
        std::fs::remove_file(dir.join("big.json")).unwrap();
        assert!(discover(&root).is_some());
        for n in 0..=MAX_FILES {
            write(&dir.join(format!("p{n}.txt")), "");
        }
        write(
            &dir.join("p.json"),
            &bloop_json("p", &root, &[], &[("g", "a", "1", &[])]),
        );
        assert_eq!(
            discover(&root),
            None,
            "over the file cap there is no evidence"
        );
    }

    /// #1270: a truncated, oversized or foreign `-test` twin (or newest
    /// project) used to be skipped, so the gate judged the main project's
    /// resolution alone and passed a `test.dep` at another version. Every
    /// unreadable record now fails closed, as the sbt reader does.
    #[test]
    fn an_unreadable_project_file_hides_no_conflict() {
        use crate::vendor::jvm::coursier_gate::gate;
        use crate::vendor::jvm::sbt_gate::GateStop;
        let code = |e: Option<&ScalaEvidence>, root: &Path| match gate(root, e, "g", "a", "1.0.0") {
            Ok(_) => "ok",
            Err(GateStop::Skip(w)) => w.code,
            Err(GateStop::Refuse(r)) => r.code,
            Err(GateStop::Silent) => "silent",
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let main = root.join("main.scala");
        let test_src = root.join("main.test.scala");
        write(&main, "//> using dep g:a:1.0.0\n");
        write(&test_src, "//> using test.dep g:a:2.0.0\n");
        let t0 = SystemTime::now() - Duration::from_secs(600);
        set_mtime(&main, t0);
        set_mtime(&test_src, t0);
        let dir = root.join(BLOOP_DIR);
        let p = dir.join("sc_p.json");
        let twin = dir.join("sc_p-test.json");
        let twin_body = bloop_json(
            "sc_p-test",
            &root,
            &[&main, &test_src],
            &[("g", "a", "2.0.0", &[("", "/c/a-2.jar")])],
        );
        write(
            &p,
            &bloop_json(
                "sc_p",
                &root,
                &[&main],
                &[("g", "a", "1.0.0", &[("", "/c/a-1.jar")])],
            ),
        );
        let reset = |body: &str| {
            write(&twin, body);
            set_mtime(&p, t0 + Duration::from_secs(100));
            set_mtime(&twin, t0 + Duration::from_secs(90));
        };

        reset(&twin_body);
        let e = discover(&root).unwrap();
        assert_eq!(e.files.len(), 2);
        assert_eq!(e.resolution.versions("g", "a"), ["1.0.0", "2.0.0"]);
        assert_eq!(code(Some(&e), &root), "vendor_scala_cli_version_conflict");

        let oversized = format!("{twin_body}{}", " ".repeat(MAX_FILE_BYTES as usize));
        for (why, body) in [
            ("truncated", &twin_body[..twin_body.len() / 2]),
            ("not a Bloop project", "{\"version\":\"1.4.0\"}"),
            ("oversized", oversized.as_str()),
        ] {
            reset(body);
            let e = discover(&root);
            assert_eq!(e, None, "a {why} -test twin is no evidence");
            assert_eq!(
                code(e.as_ref(), &root),
                "vendor_scala_cli_resolution_missing",
                "a {why} -test twin never lets the gate pass"
            );
        }
        // The newest main project unreadable: no older project stands in.
        reset(&twin_body);
        write(&p, "{");
        set_mtime(&p, t0 + Duration::from_secs(100));
        assert_eq!(discover(&root), None);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_fifos_are_not_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(
            &outside.path().join(".bloop/p.json"),
            &bloop_json("p", &root, &[], &[("g", "a", "1", &[])]),
        );
        std::os::unix::fs::symlink(outside.path(), root.join(".scala-build")).unwrap();
        assert_eq!(
            discover(&root),
            None,
            "a symlinked .scala-build is no evidence"
        );
        std::fs::remove_file(root.join(".scala-build")).unwrap();
        let dir = root.join(BLOOP_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(outside.path().join(".bloop/p.json"), dir.join("p.json"))
            .unwrap();
        assert_eq!(discover(&root), None, "a symlinked project file is skipped");
        let fifo = dir.join("q.json");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert_eq!(discover(&root), None, "a FIFO never wedges the read");
    }

    /// The committed scala-cli 1.17.1 probe files (lane L2's fixture,
    /// `tests/fixtures/sbt/evidence/scala-cli-1.17.1/directory`) parse,
    /// whatever directory they were recorded in.
    #[test]
    fn the_probe_fixture_parses() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbt/evidence/scala-cli-1.17.1/directory")
            .join(BLOOP_DIR);
        let projects: Vec<(String, BloopProject)> =
            ["sc-server_baeca91196", "sc-server_baeca91196-test"]
                .iter()
                .map(|n| {
                    let bytes = std::fs::read(dir.join(format!("{n}.json"))).unwrap();
                    (
                        format!("{n}.json"),
                        parse_bloop(&bytes).expect("a Bloop project"),
                    )
                })
                .collect();
        assert!(!projects[0].1.test && projects[1].1.test);
        let res = resolution_of(&projects);
        assert_eq!(
            res.versions("org.apache.commons", "commons-lang3"),
            ["3.11"]
        );
        let junit = &res.modules[&("junit".to_string(), "junit".to_string())]["4.13.2"];
        assert!(junit.iter().all(|id| id.ends_with(":test")), "{junit:?}");
        assert!(res.artifacts[&(
            "com.google.code.gson".to_string(),
            "gson".to_string(),
            "2.8.9".to_string()
        )]
            .iter()
            .all(|p| p.starts_with("/root/.cache/coursier/v1/https/repo1.maven.org/maven2")));
    }
}
