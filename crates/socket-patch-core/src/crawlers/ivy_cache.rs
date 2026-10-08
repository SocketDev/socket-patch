//! Ivy's resolution cache (sbt 0.13, 1.0–1.2, and 1.3+ under
//! `useCoursier := false`): where it is, crawling it, and finding a
//! package's pristine pom in it.
//!
//! Layout: `<ivy home>/cache/<org>/<module>/ivy-<rev>.xml` beside
//! `jars/` / `bundles/` / `orbits/<module>-<rev>.jar`; the crawled package
//! directory is the artifact directory, whose `<module>-<rev>.jar` has the
//! same basename as in Maven2, so apply's variant selection is unchanged.
//! Every revision of a module shares that directory; file names carry the
//! revision, so a patch keyed `<module>-<rev>.jar` touches only its own.
//! sbt plugins sit one level down, under `scala_<sv>/sbt_<sbtv>/`.
//!
//! The pristine upstream pom is `ivy-<rev>.xml.original` (when the origin
//! repository was Maven-pattern); Ivy keeps no checksum sidecars beside its
//! artifacts, so an in-place patch needs no sidecar resync.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::coursier_cache::{existing_dedup, jvm_option_values, log_source, TargetOs};
use super::maven_crawler::parse_pom_group_artifact_version;
use super::types::CrawledPackage;
use crate::utils::fs::{open_regular_file_sync, read_regular_to_bytes_sync};
use crate::vendor::jvm::layout::is_path_safe;

/// The artifact directories Ivy files a module's jar under, in lookup order
/// (`bundles/` holds OSGi-packaged jars such as guava 19.0's).
const ARTIFACT_DIRS: &[&str] = &["jars", "bundles", "orbits"];

/// Every artifact type directory of a module: [`ARTIFACT_DIRS`] plus the
/// classifier ones (`srcs/` holds `<module>-<rev>-sources.jar`, `docs/`
/// the javadoc jar). The gradle_cache `installed_copies` expansion looks a
/// patch key up in each.
const TYPE_DIRS: &[&str] = &["jars", "bundles", "orbits", "srcs", "docs"];

/// How much of an `ivy-<rev>.xml` the `<info>` cross-check reads.
const INFO_PREFIX_BYTES: u64 = 4096;

/// Every existing Ivy cache directory, in precedence order:
/// `-Dsbt.ivy.home=<h>` / `-Divy.home=<h>` (the same option sources as
/// Coursier's) → `<h>/cache`, then `~/.ivy2/cache`. The location is the
/// same on every OS.
pub fn ivy_cache_dirs(
    os: TargetOs,
    env: &dyn Fn(&str) -> Option<String>,
    home: Option<&Path>,
    cwd: &Path,
) -> Vec<PathBuf> {
    ivy_cache_dirs_with_source(os, env, home, cwd)
        .into_iter()
        .map(|(dir, _)| dir)
        .collect()
}

fn ivy_cache_dirs_with_source(
    _os: TargetOs,
    env: &dyn Fn(&str) -> Option<String>,
    home: Option<&Path>,
    cwd: &Path,
) -> Vec<(PathBuf, &'static str)> {
    let mut candidates = Vec::new();
    for key in ["sbt.ivy.home", "ivy.home"] {
        for (value, source) in jvm_option_values(env, cwd, key) {
            candidates.push((cwd.join(value).join("cache"), source));
        }
    }
    if let Some(home) = home {
        candidates.push((home.join(".ivy2/cache"), "default"));
    }
    existing_dedup(candidates)
}

/// [`ivy_cache_dirs`] for this process (host OS, real environment and
/// home).
pub fn process_cache_dirs(cwd: &Path) -> Vec<PathBuf> {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let home = crate::utils::fs::home_dir();
    ivy_cache_dirs_with_source(TargetOs::host(), &env, home.as_deref(), cwd)
        .into_iter()
        .map(|(dir, source)| {
            log_source("Ivy cache", &dir, source);
            dir
        })
        .collect()
}

/// Every package in the Ivy cache at `root` (`seen` dedups PURLs across
/// roots: the first root wins), in name order.
pub fn scan(root: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
    let mut out = Vec::new();
    for org_root in org_roots(root) {
        for (org, org_dir) in children(&org_root, true) {
            for (module, module_dir) in children(&org_dir, true) {
                for (file, _) in children(&module_dir, false) {
                    let Some(rev) = file
                        .strip_prefix("ivy-")
                        .and_then(|f| f.strip_suffix(".xml"))
                    else {
                        continue;
                    };
                    if let Some(pkg) = package(&module_dir, &org, &module, rev) {
                        if seen.insert(pkg.purl.clone()) {
                            out.push(pkg);
                        }
                    }
                }
            }
        }
    }
    out
}

/// The packages among `purls` present in the Ivy cache at `root`.
pub fn find_by_purls(root: &Path, purls: &[String]) -> HashMap<String, CrawledPackage> {
    let org_roots = org_roots(root);
    let mut out = HashMap::new();
    for purl in purls {
        let Some((g, a, v)) = crate::utils::purl::parse_maven_purl(purl) else {
            continue;
        };
        // SECURITY: untrusted coordinates are joined onto the cache root and
        // the result is patched in place.
        if !is_path_safe(&g, &a, &v) {
            continue;
        }
        let found = org_roots.iter().find_map(|org_root| {
            let module_dir = org_root.join(g.as_ref()).join(a.as_ref());
            package(&module_dir, &g, &a, &v)
        });
        if let Some(mut pkg) = found {
            pkg.purl = purl.clone();
            out.insert(purl.clone(), pkg);
        }
    }
    out
}

/// Whether `path` is an Ivy package directory as [`scan`] and
/// [`find_by_purls`] report it: one of a module's [`ARTIFACT_DIRS`], a real
/// directory, beside at least one `ivy-<rev>.xml`.
pub fn is_artifact_dir(path: &Path) -> bool {
    let named = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| ARTIFACT_DIRS.contains(&n));
    named
        && is_real_dir(path)
        && path.parent().is_some_and(|module_dir| {
            children(module_dir, false)
                .iter()
                .any(|(name, _)| name.starts_with("ivy-") && name.ends_with(".xml"))
        })
}

/// The artifact type directories ([`TYPE_DIRS`]) present under
/// `module_dir`, real directories only, in [`TYPE_DIRS`] order.
pub fn type_dirs(module_dir: &Path) -> Vec<String> {
    TYPE_DIRS
        .iter()
        .filter(|d| is_real_dir(&module_dir.join(d)))
        .map(|d| d.to_string())
        .collect()
}

/// The pristine upstream pom of `g:a:v` for a package crawled at
/// `installed_dir`: `<dir>/<a>-<v>.pom`, else an `ivy-<v>.xml.original`
/// that is a pom for exactly `g:a:v`; `None` (fetch upstream) otherwise.
/// An `.original` from an Ivy-pattern origin is an `ivy.xml`, not a pom,
/// and is never returned.
pub fn installed_pom(installed_dir: &Path, g: &str, a: &str, v: &str) -> Option<Vec<u8>> {
    if !is_path_safe(g, a, v) {
        return None;
    }
    if let Ok(bytes) = read_regular_to_bytes_sync(&installed_dir.join(format!("{a}-{v}.pom"))) {
        return Some(bytes);
    }
    // The `.original` fallback walks to the parent, so only an Ivy artifact
    // directory (`jars/` etc. beside an `ivy-<rev>.xml`) may take it: a
    // Maven2 / Coursier version dir or any other path would otherwise read
    // a sibling of an unrelated parent.
    if !is_artifact_dir(installed_dir) {
        return None;
    }
    let original = installed_dir
        .parent()?
        .join(format!("ivy-{v}.xml.original"));
    let bytes = read_regular_to_bytes_sync(&original).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let gav = (g.to_string(), a.to_string(), v.to_string());
    (is_pom_root(&text) && parse_pom_group_artifact_version(&text) == Some(gav)).then_some(bytes)
}

/// `root` itself plus every sbt-plugin level below it
/// (`scala_<sv>/sbt_<sbtv>/`): each holds `<org>/<module>/` trees.
fn org_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![root.to_path_buf()];
    for (name, scala_dir) in children(root, true) {
        if !name.starts_with("scala_") {
            continue;
        }
        for (sbt, sbt_dir) in children(&scala_dir, true) {
            if sbt.starts_with("sbt_") {
                roots.push(sbt_dir);
            }
        }
    }
    roots
}

/// The package `org:module:rev` whose `ivy-<rev>.xml` sits in `module_dir`
/// with its jar in one of the [`ARTIFACT_DIRS`], or `None`: unsafe
/// coordinates, no regular `ivy-<rev>.xml`, an `<info>` naming other
/// coordinates, or no jar.
fn package(module_dir: &Path, org: &str, module: &str, rev: &str) -> Option<CrawledPackage> {
    if !is_path_safe(org, module, rev) {
        return None;
    }
    // Neither the module nor the organisation directory may be a link out
    // of the cache (the walk never follows one; a PURL lookup joins them).
    if !is_real_dir(module_dir) || !module_dir.parent().is_some_and(is_real_dir) {
        return None;
    }
    let ivy = module_dir.join(format!("ivy-{rev}.xml"));
    if !is_regular(&ivy) || !info_agrees(&ivy, org, module, rev) {
        return None;
    }
    let jar = format!("{module}-{rev}.jar");
    let dir = ARTIFACT_DIRS
        .iter()
        .map(|d| module_dir.join(d))
        .find(|dir| is_real_dir(dir) && is_regular(&dir.join(&jar)))?;
    Some(CrawledPackage {
        name: module.to_string(),
        version: rev.to_string(),
        namespace: Some(org.to_string()),
        purl: crate::utils::purl::build_maven_purl(org, module, rev),
        path: dir,
    })
}

/// Whether the `<info organisation module revision>` in the first 4 KiB
/// of `ivy` (read FIFO-safe) agrees with the path's coordinates. An
/// unreadable file disagrees; a prefix without a complete `<info …>` tag
/// (an unusually long header) trusts the path.
fn info_agrees(ivy: &Path, org: &str, module: &str, rev: &str) -> bool {
    let Ok((file, _)) = open_regular_file_sync(ivy) else {
        return false;
    };
    let mut prefix = Vec::new();
    if file
        .take(INFO_PREFIX_BYTES)
        .read_to_end(&mut prefix)
        .is_err()
    {
        return false;
    }
    let text = String::from_utf8_lossy(&prefix);
    let Some(start) = text.find("<info") else {
        return true;
    };
    let Some(len) = text[start..].find('>') else {
        return true;
    };
    let tag = &text[start..start + len];
    [("organisation", org), ("module", module), ("revision", rev)]
        .iter()
        .all(|(attr, want)| attribute(tag, attr).is_none_or(|got| got == *want))
}

/// The value of `name="…"` (or `'…'`) inside one tag's text.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = tag;
    while let Some(at) = rest.find(name) {
        let before = rest[..at].chars().last();
        let after = rest[at + name.len()..].trim_start();
        rest = &rest[at + name.len()..];
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(after) = after.strip_prefix('=') else {
            continue;
        };
        let after = after.trim_start();
        let quote = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let body = &after[1..];
        return body.find(quote).map(|end| &body[..end]);
    }
    None
}

/// Whether `text`'s root element is `<project` (after a BOM, the XML
/// declaration, comments and a doctype).
fn is_pom_root(text: &str) -> bool {
    let mut rest = text.trim_start_matches('\u{feff}');
    loop {
        rest = rest.trim_start();
        let skip_to = if rest.starts_with("<?") {
            "?>"
        } else if rest.starts_with("<!--") {
            "-->"
        } else if rest.starts_with("<!") {
            ">"
        } else {
            break;
        };
        match rest.find(skip_to) {
            Some(end) => rest = &rest[end + skip_to.len()..],
            None => return false,
        }
    }
    rest.strip_prefix("<project")
        .and_then(|r| r.chars().next())
        .is_some_and(|c| c == '>' || c == '/' || c.is_whitespace())
}

/// The children of `dir` that are real directories (`dirs`) or regular
/// files, never symbolic links or dot-names, as `(name, path)` in name
/// order.
fn children(dir: &Path, dirs: bool) -> Vec<(String, PathBuf)> {
    let Some((entries, _complete)) = crate::utils::fs::read_dir_entries_sync(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathBuf)> = entries
        .into_iter()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let kind = e.file_type().ok()?;
            let wanted = if dirs { kind.is_dir() } else { kind.is_file() };
            (wanted && !name.starts_with('.')).then(|| (name, e.path()))
        })
        .collect();
    out.sort();
    out
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn is_regular(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn ivy_xml(org: &str, module: &str, rev: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ivy-module version=\"2.0\" xmlns:e=\"http://ant.apache.org/ivy/extra\">\n\t<info organisation=\"{org}\"\n\t\tmodule=\"{module}\"\n\t\trevision=\"{rev}\"\n\t\tstatus=\"release\"\n\t>\n\t</info>\n</ivy-module>\n"
        )
    }

    fn pom(g: &str, a: &str, v: &str) -> String {
        format!("<?xml version=\"1.0\"?>\n<!-- c -->\n<project xmlns=\"x\">\n<groupId>{g}</groupId>\n<artifactId>{a}</artifactId>\n<version>{v}</version>\n</project>\n")
    }

    /// Write `org:module:rev` into the cache at `root`, its jar under `kind`
    /// (`None` = no jar); the module directory.
    fn module(root: &Path, org: &str, m: &str, rev: &str, kind: Option<&str>) -> PathBuf {
        let dir = root.join(org).join(m);
        write(
            &dir.join(format!("ivy-{rev}.xml")),
            ivy_xml(org, m, rev).as_bytes(),
        );
        write(
            &dir.join(format!("ivy-{rev}.xml.original")),
            pom(org, m, rev).as_bytes(),
        );
        write(&dir.join(format!("ivy-{rev}.xml.sha1")), b"0000");
        write(&dir.join(format!("ivydata-{rev}.properties")), b"#x\n");
        if let Some(kind) = kind {
            write(&dir.join(kind).join(format!("{m}-{rev}.jar")), b"jar");
        }
        dir
    }

    fn rows(pkgs: &[CrawledPackage]) -> Vec<(String, PathBuf)> {
        pkgs.iter()
            .map(|p| (p.purl.clone(), p.path.clone()))
            .collect()
    }

    #[test]
    fn cache_dirs_precedence_and_default() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let cwd = t.path().join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        let mk = |p: PathBuf| {
            std::fs::create_dir_all(&p).unwrap();
            p
        };
        let sbt_home = mk(t.path().join("sbt-ivy/cache"));
        let ivy_home = mk(t.path().join("plain-ivy/cache"));
        let file_home = mk(t.path().join("file-ivy/cache"));
        let default = mk(home.join(".ivy2/cache"));
        write(
            &cwd.join(".sbtopts"),
            format!("-J-Dsbt.ivy.home={}\n", t.path().join("file-ivy").display()).as_bytes(),
        );
        let opts = format!(
            "-Dsbt.ivy.home={} -Divy.home={}",
            t.path().join("sbt-ivy").display(),
            t.path().join("plain-ivy").display()
        );
        let env = move |name: &str| (name == "SBT_OPTS").then(|| opts.clone());
        for os in [TargetOs::Linux, TargetOs::MacOs, TargetOs::Windows] {
            assert_eq!(
                ivy_cache_dirs(os, &env, Some(&home), &cwd),
                vec![
                    sbt_home.clone(),
                    file_home.clone(),
                    ivy_home.clone(),
                    default.clone()
                ]
            );
        }
        // Empty = unset.
        let empty = |name: &str| (name == "SBT_OPTS").then(|| "-Dsbt.ivy.home=".to_string());
        std::fs::remove_file(cwd.join(".sbtopts")).unwrap();
        assert!(ivy_cache_dirs(TargetOs::Linux, &|_| None, None, &cwd).is_empty());
        assert_eq!(
            ivy_cache_dirs(TargetOs::Linux, &empty, Some(&home), &cwd),
            vec![default]
        );
    }

    #[test]
    fn scan_finds_jars_bundles_orbits_and_skips_missing_jars() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join(".ivy2/cache");
        let a = module(
            &root,
            "org.apache.commons",
            "commons-text",
            "1.9",
            Some("jars"),
        );
        let g = module(&root, "com.google.guava", "guava", "19.0", Some("bundles"));
        let o = module(
            &root,
            "org.eclipse.jetty.orbit",
            "javax.servlet",
            "3.0.0",
            Some("orbits"),
        );
        module(&root, "org.apache", "apache", "23", None); // a parent pom, no jar
                                                           // A jar under the wrong directory name does not count.
        module(&root, "x.y", "z", "1", Some("srcs"));
        let mut seen = HashSet::new();
        let found = scan(&root, &mut seen);
        assert_eq!(
            rows(&found),
            vec![
                (
                    "pkg:maven/com.google.guava/guava@19.0".into(),
                    g.join("bundles")
                ),
                (
                    "pkg:maven/org.apache.commons/commons-text@1.9".into(),
                    a.join("jars")
                ),
                (
                    "pkg:maven/org.eclipse.jetty.orbit/javax.servlet@3.0.0".into(),
                    o.join("orbits")
                ),
            ]
        );
        let p = &found[1];
        assert_eq!(
            (p.name.as_str(), p.version.as_str()),
            ("commons-text", "1.9")
        );
        assert_eq!(p.namespace.as_deref(), Some("org.apache.commons"));
        // A second root sees nothing new.
        assert!(scan(&root, &mut seen).is_empty());
    }

    #[test]
    fn shared_revisions_share_the_artifact_dir() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ivy2/cache");
        let dir = module(&root, "org.slf4j", "slf4j-api", "1.7.36", Some("jars"));
        module(&root, "org.slf4j", "slf4j-api", "2.0.9", Some("jars"));
        // An ivy.xml for a revision whose jar is missing.
        write(
            &dir.join("ivy-1.7.0.xml"),
            ivy_xml("org.slf4j", "slf4j-api", "1.7.0").as_bytes(),
        );
        let found = scan(&root, &mut HashSet::new());
        assert_eq!(
            rows(&found),
            vec![
                (
                    "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
                    dir.join("jars")
                ),
                (
                    "pkg:maven/org.slf4j/slf4j-api@2.0.9".into(),
                    dir.join("jars")
                ),
            ]
        );
        let hits = find_by_purls(
            &root,
            &[
                "pkg:maven/org.slf4j/slf4j-api@2.0.9".into(),
                "pkg:maven/org.slf4j/slf4j-api@1.7.0".into(),
                "pkg:maven/org.slf4j/slf4j-api@9".into(),
            ],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits["pkg:maven/org.slf4j/slf4j-api@2.0.9"].path,
            dir.join("jars")
        );
    }

    #[test]
    fn plugins_one_level_down() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ivy2/cache");
        let plugin = module(
            &root.join("scala_2.12/sbt_1.0"),
            "com.eed3si9n",
            "sbt-assembly",
            "0.14.10",
            Some("jars"),
        );
        let found = scan(&root, &mut HashSet::new());
        assert_eq!(
            rows(&found),
            vec![(
                "pkg:maven/com.eed3si9n/sbt-assembly@0.14.10".into(),
                plugin.join("jars")
            )]
        );
        let purl = "pkg:maven/com.eed3si9n/sbt-assembly@0.14.10".to_string();
        assert_eq!(
            find_by_purls(&root, std::slice::from_ref(&purl))[&purl].path,
            plugin.join("jars")
        );
    }

    #[test]
    fn info_must_agree_with_the_path() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ivy2/cache");
        let dir = module(&root, "org.a", "b", "1", Some("jars"));
        write(
            &dir.join("ivy-1.xml"),
            ivy_xml("org.evil", "b", "1").as_bytes(),
        );
        assert!(scan(&root, &mut HashSet::new()).is_empty());
        assert!(find_by_purls(&root, &["pkg:maven/org.a/b@1".into()]).is_empty());
        // No complete `<info>` in the first 4 KiB: the path decides.
        let mut long = "<!--".to_string() + &"x".repeat(5000) + "-->";
        long.push_str(&ivy_xml("org.evil", "b", "1"));
        write(&dir.join("ivy-1.xml"), long.as_bytes());
        assert_eq!(scan(&root, &mut HashSet::new()).len(), 1);
    }

    #[test]
    fn unsafe_coordinates_are_never_joined() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ivy2/cache");
        module(&root, "org.a", "b", "1", Some("jars"));
        // `..` as a revision would escape `jars/`; `C:x` is drive-relative.
        write(
            &root.join("org.a/b/ivy-...xml"),
            ivy_xml("org.a", "b", "..").as_bytes(),
        );
        for purl in [
            "pkg:maven/org.a/b@..",
            "pkg:maven/../b@1",
            "pkg:maven/org.a/C:b@1",
            "pkg:maven/org..a/b@1",
        ] {
            assert!(find_by_purls(&root, &[purl.into()]).is_empty(), "{purl}");
        }
        assert_eq!(scan(&root, &mut HashSet::new()).len(), 1);
        assert_eq!(installed_pom(&root, "org.a", "b", ".."), None);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let outside = t.path().join("outside");
        let real = module(&outside, "org.x", "y", "1", Some("jars"));
        let root = t.path().join("ivy2/cache");
        std::fs::create_dir_all(root.join("org.x")).unwrap();
        // A module directory that is a link out of the cache.
        std::os::unix::fs::symlink(&real, root.join("org.x/y")).unwrap();
        assert!(scan(&root, &mut HashSet::new()).is_empty());
        assert!(find_by_purls(&root, &["pkg:maven/org.x/y@1".into()]).is_empty());
        // A jars/ directory that is a link.
        let m = module(&root, "org.p", "q", "1", None);
        std::os::unix::fs::symlink(real.join("jars"), m.join("jars")).unwrap();
        assert!(find_by_purls(&root, &["pkg:maven/org.p/q@1".into()]).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn readers_are_fifo_safe() {
        fn mkfifo(p: &Path) {
            let _ = std::fs::remove_file(p);
            let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ivy2/cache");
        let dir = module(&root, "org.a", "b", "1", Some("jars"));
        mkfifo(&dir.join("ivy-1.xml"));
        mkfifo(&dir.join("ivy-1.xml.original"));
        mkfifo(&dir.join("jars/b-1.pom"));
        let (tx, rx) = std::sync::mpsc::channel();
        let (r, d) = (root.clone(), dir.clone());
        std::thread::spawn(move || {
            let scanned = scan(&r, &mut HashSet::new()).len();
            let found = find_by_purls(&r, &["pkg:maven/org.a/b@1".into()]).len();
            let pom = installed_pom(&d.join("jars"), "org.a", "b", "1");
            let _ = tx.send((scanned, found, pom));
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a FIFO must not wedge the Ivy readers");
        assert_eq!(got, (0, 0, None));
        // And `info_agrees` itself.
        assert!(!info_agrees(&dir.join("ivy-1.xml"), "org.a", "b", "1"));
    }

    #[test]
    fn installed_pom_prefers_a_real_pom_then_a_pom_origin_original() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ivy2/cache");
        let dir = module(&root, "org.a", "b", "1", Some("jars"));
        let jars = dir.join("jars");
        let original = pom("org.a", "b", "1").into_bytes();
        assert_eq!(installed_pom(&jars, "org.a", "b", "1"), Some(original));
        // Wrong coordinates: not this package's pom.
        assert_eq!(installed_pom(&jars, "org.a", "b", "2"), None);
        assert_eq!(installed_pom(&jars, "org.z", "b", "1"), None);
        // An ivy-pattern origin's `.original` is an ivy.xml.
        write(
            &dir.join("ivy-1.xml.original"),
            ivy_xml("org.a", "b", "1").as_bytes(),
        );
        assert_eq!(installed_pom(&jars, "org.a", "b", "1"), None);
        // A `<project` that is not the root element does not count.
        write(
            &dir.join("ivy-1.xml.original"),
            format!("<ivy-module>{}</ivy-module>", pom("org.a", "b", "1")).as_bytes(),
        );
        assert_eq!(installed_pom(&jars, "org.a", "b", "1"), None);
        // A Maven2 / Coursier version dir: `<a>-<v>.pom` wins.
        let m2 = t.path().join("m2/org/a/b/1");
        write(&m2.join("b-1.pom"), b"pom bytes");
        assert_eq!(
            installed_pom(&m2, "org.a", "b", "1"),
            Some(b"pom bytes".to_vec())
        );
        // A non-Ivy dir never falls back to a parent's `.original`, even one
        // that is a pom for exactly this GAV.
        let other = t.path().join("staging/org/a/b/1");
        std::fs::create_dir_all(&other).unwrap();
        write(
            &other.parent().unwrap().join("ivy-1.xml.original"),
            pom("org.a", "b", "1").as_bytes(),
        );
        assert_eq!(installed_pom(&other, "org.a", "b", "1"), None);
        // Nor does an Ivy-named dir with no `ivy-<rev>.xml` beside it.
        let bare = t.path().join("bare/org.a/b");
        std::fs::create_dir_all(bare.join("jars")).unwrap();
        write(
            &bare.join("ivy-1.xml.original"),
            pom("org.a", "b", "1").as_bytes(),
        );
        assert_eq!(installed_pom(&bare.join("jars"), "org.a", "b", "1"), None);
        assert_eq!(
            installed_pom(&t.path().join("absent/x"), "org.a", "b", "1"),
            None
        );
    }

    #[test]
    fn pom_root_detection() {
        assert!(is_pom_root("<project>"));
        assert!(is_pom_root(
            "\u{feff}<?xml version=\"1.0\"?>\n<!-- a -->\n<!DOCTYPE x>\n<project xmlns=\"y\">"
        ));
        assert!(!is_pom_root("<projects>"));
        assert!(!is_pom_root("<ivy-module><project>"));
        assert!(!is_pom_root("<!-- unterminated"));
        assert!(!is_pom_root(""));
    }

    #[test]
    fn attribute_parsing() {
        let tag = "<info organisation=\"o\" xmodule=\"no\" module = 'm' revision=\"r\"";
        assert_eq!(attribute(tag, "organisation"), Some("o"));
        assert_eq!(attribute(tag, "module"), Some("m"));
        assert_eq!(attribute(tag, "revision"), Some("r"));
        assert_eq!(attribute(tag, "status"), None);
    }
}
