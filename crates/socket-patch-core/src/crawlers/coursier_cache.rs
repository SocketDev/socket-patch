//! Coursier's download cache (sbt 1.3+, sbt 2, Mill, scala-cli, Bloop):
//! where it is, and the per-repository Maven2 roots inside it.
//!
//! A cache directory holds one tree per repository URL,
//! `<cache>/<https|http>/<host>/<repo path…>/<g/path>/<a>/<v>/<a>-<v>.{pom,jar}`,
//! each a plain Maven2 layout once its root is known. [`repo_roots`] finds
//! those roots; [`MavenCrawler`](super::MavenCrawler) crawls each with its
//! Maven2 logic. Checksum sidecars sit beside each file
//! (`.<file>__sha1`, …), resynced after a patch by
//! `patch::sidecars::coursier`.
//!
//! Locations are a pure function of the target OS, an environment lookup,
//! the home directory and the project directory ([`coursier_cache_dirs`]),
//! with a thin adapter for this process ([`process_cache_dirs`]), so every
//! OS's table is testable on any host. The JVM option sources it reads
//! (`$JAVA_OPTS`, `$SBT_OPTS`, `<cwd>/.jvmopts`, `<cwd>/.sbtopts`) are
//! shared with the Ivy cache lookup through [`jvm_option_values`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::jvm_cache::debug_log;
use super::maven_crawler::{is_safe_maven_coordinate, parse_pom_group_artifact_version};
use crate::utils::fs::read_regular_to_bytes_sync;

/// The OS whose default cache locations apply (a parameter so every OS's
/// table is testable on any host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    Linux,
    MacOs,
    Windows,
}

impl TargetOs {
    /// The OS this binary runs on (other Unixes use the Linux table).
    pub fn host() -> Self {
        if cfg!(windows) {
            TargetOs::Windows
        } else if cfg!(target_os = "macos") {
            TargetOs::MacOs
        } else {
            TargetOs::Linux
        }
    }
}

/// How deep below a host directory [`repo_roots`] looks for a pom.
const MAX_DEPTH: usize = 24;

/// How many directory entries [`repo_roots`] reads per host before giving
/// up on the rest of that host's tree.
const MAX_ENTRIES_PER_HOST: usize = 200_000;

/// Every existing Coursier cache directory, deduplicated canonically, with
/// the source that named it (`"COURSIER_CACHE"`, `".jvmopts"`, `"default"`,
/// …), in precedence order: `$COURSIER_CACHE`; `-Dcoursier.cache=` in
/// `$JAVA_OPTS`, `$SBT_OPTS`, `<cwd>/.jvmopts`, `<cwd>/.sbtopts` (`-J`
/// prefix allowed); `-Dsbt.coursier.home=<h>` → `<h>/cache`; the OS default;
/// the legacy `~/.coursier/cache/v1`. An empty variable counts as unset.
///
/// Every source is kept, not only the first: sbt, Mill and scala-cli on the
/// same machine may each have been pointed at a different cache, and each
/// cache's packages must be discoverable, and `apply` / `rollback` act on
/// a GAV's copy in every root (the Maven every-copy fan-out over
/// `MavenCrawler::get_maven_copy_paths`). A relative value resolves
/// against `cwd` (the JVM's working directory when the build runs there).
pub fn coursier_cache_dirs(
    os: TargetOs,
    env: &dyn Fn(&str) -> Option<String>,
    home: Option<&Path>,
    cwd: &Path,
) -> Vec<(PathBuf, &'static str)> {
    let mut candidates: Vec<(PathBuf, &'static str)> = Vec::new();
    if let Some(dir) = non_empty(env, "COURSIER_CACHE") {
        candidates.push((cwd.join(dir), "COURSIER_CACHE"));
    }
    for (value, source) in jvm_option_values(env, cwd, "coursier.cache") {
        candidates.push((cwd.join(value), source));
    }
    for (value, source) in jvm_option_values(env, cwd, "sbt.coursier.home") {
        candidates.push((cwd.join(value).join("cache"), source));
    }
    match os {
        TargetOs::Linux => match non_empty(env, "XDG_CACHE_HOME") {
            Some(xdg) => candidates.push((PathBuf::from(xdg).join("coursier/v1"), "default")),
            None => {
                if let Some(home) = home {
                    candidates.push((home.join(".cache/coursier/v1"), "default"));
                }
            }
        },
        TargetOs::MacOs => {
            if let Some(home) = home {
                candidates.push((home.join("Library/Caches/Coursier/v1"), "default"));
            }
        }
        TargetOs::Windows => {
            let local = non_empty(env, "LOCALAPPDATA")
                .map(PathBuf::from)
                .or_else(|| home.map(|h| h.join("AppData").join("Local")));
            if let Some(local) = local {
                for cache in ["Cache", "cache"] {
                    candidates.push((local.join("Coursier").join(cache).join("v1"), "default"));
                }
            }
        }
    }
    if let Some(home) = home {
        candidates.push((home.join(".coursier/cache/v1"), "legacy"));
    }
    existing_dedup(candidates)
}

/// The per-repository Maven2 roots under `cache_dir`: a bounded DFS (depth
/// 24, no dot-names, no symlinks, 200 000 entries per host) accepting a
/// root only where a pom's own coordinates spell the path below it.
///
/// For each `<a>-<v>.pom` in a directory `<…>/<a>/<v>/`, the pom's content
/// coordinates `(g, a, v)` must match its directory names and the path must
/// end in `<g as path>/<a>/<v>`; what is left above is the root, accepted
/// only at or below the host directory. The walk then skips everything
/// below an accepted root (the Maven2 crawl covers it). An Ivy-pattern
/// subtree (`…/ivy-releases/<org>/<module>/<rev>/jars/…`, no pom) and a
/// pom whose content names other coordinates than its path yield no root.
pub fn repo_roots(cache_dir: &Path) -> Vec<PathBuf> {
    repo_roots_capped(cache_dir, MAX_ENTRIES_PER_HOST)
}

fn repo_roots_capped(cache_dir: &Path, cap: usize) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for scheme in ["https", "http"] {
        let scheme_dir = cache_dir.join(scheme);
        if !is_real_dir(&scheme_dir) {
            continue;
        }
        for host in sorted_children(&scheme_dir)
            .into_iter()
            .filter(|(_, is_dir)| *is_dir)
        {
            roots.extend(host_roots(&host.0, cap));
        }
    }
    roots
}

/// [`repo_roots`] for one host directory.
fn host_roots(host: &Path, cap: usize) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(host.to_path_buf(), 0)];
    let mut read = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let children = sorted_children(&dir);
        read += children.len();
        if read > cap {
            debug_log(&format!(
                "Coursier cache host {} has more than {cap} entries; not looking further",
                host.display()
            ));
            break;
        }
        let mut subdirs = Vec::new();
        let mut accepted = None;
        for (path, is_dir) in children {
            if is_dir {
                if depth < MAX_DEPTH {
                    subdirs.push(path);
                }
                continue;
            }
            if let Some(root) = pom_root(&path, host) {
                accepted = Some(root);
                break;
            }
        }
        if let Some(root) = accepted {
            // Everything below the root is the Maven2 crawl's.
            stack.retain(|(pending, _)| !pending.starts_with(&root));
            roots.push(root);
            continue;
        }
        // Reverse so the stack pops in name order.
        for sub in subdirs.into_iter().rev() {
            if !roots.iter().any(|r| sub.starts_with(r)) {
                stack.push((sub, depth + 1));
            }
        }
    }
    roots
}

/// The repository root `pom` (a regular file) proves, if any.
fn pom_root(pom: &Path, host: &Path) -> Option<PathBuf> {
    let file = pom.file_name()?.to_str()?;
    let version_dir = pom.parent()?;
    let version = version_dir.file_name()?.to_str()?;
    let artifact_dir = version_dir.parent()?;
    let artifact = artifact_dir.file_name()?.to_str()?;
    if file != format!("{artifact}-{version}.pom") {
        return None;
    }
    let bytes = read_regular_to_bytes_sync(pom).ok()?;
    let (g, a, v) = parse_pom_group_artifact_version(&String::from_utf8_lossy(&bytes))?;
    if a != artifact || v != version || !is_safe_maven_coordinate(&g, &a, &v) {
        return None;
    }
    let mut root = artifact_dir.parent()?;
    for segment in g.split('.').rev() {
        if root.file_name()?.to_str()? != segment {
            return None;
        }
        root = root.parent()?;
    }
    root.starts_with(host).then(|| root.to_path_buf())
}

/// Whether `p` is a Coursier cache directory (holds `https/` or `http/`
/// host trees) rather than one repository root inside it.
pub fn is_coursier_cache_dir(p: &Path) -> bool {
    ["https", "http"]
        .iter()
        .any(|scheme| is_real_dir(&p.join(scheme)))
}

/// [`coursier_cache_dirs`] for this process (host OS, real environment and
/// home), paths only. A source the repository controls (`.jvmopts`,
/// `.sbtopts`) is named in the `SOCKET_DEBUG` log.
pub fn process_cache_dirs(cwd: &Path) -> Vec<PathBuf> {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let home = process_home();
    coursier_cache_dirs(TargetOs::host(), &env, home.as_deref(), cwd)
        .into_iter()
        .map(|(dir, source)| {
            log_source("Coursier cache", &dir, source);
            dir
        })
        .collect()
}

/// This process's home directory, only when absolute: the shared
/// `home_dir()` fallback (`~`) would resolve every default location
/// against the process's working directory.
pub(crate) fn process_home() -> Option<PathBuf> {
    Some(crate::utils::fs::home_dir()).filter(|h| h.is_absolute())
}

/// Debug-log a cache location and the source that named it; a location a
/// repository file chose is called out as such.
pub(crate) fn log_source(what: &str, dir: &Path, source: &str) {
    if REPO_SOURCES.contains(&source) {
        debug_log(&format!(
            "{what} {} named by the repository's {source}",
            dir.display()
        ));
    } else {
        debug_log(&format!("{what} {} (from {source})", dir.display()));
    }
}

/// The option sources a checkout itself controls.
const REPO_SOURCES: &[&str] = &[".jvmopts", ".sbtopts"];

/// The value of every `-D<key>=<value>` in the JVM option sources, in
/// precedence order (`$JAVA_OPTS`, `$SBT_OPTS`, `<cwd>/.jvmopts`,
/// `<cwd>/.sbtopts`), the last one per source winning as on a JVM command
/// line. A `-J` prefix (the sbt launcher's pass-through) is accepted
/// everywhere; `#` comment lines and empty values are skipped; one layer
/// of matching quotes around a value is removed. Files are read FIFO-safe.
pub(crate) fn jvm_option_values(
    env: &dyn Fn(&str) -> Option<String>,
    cwd: &Path,
    key: &str,
) -> Vec<(String, &'static str)> {
    let mut sources: Vec<(String, &'static str)> = Vec::new();
    for var in ["JAVA_OPTS", "SBT_OPTS"] {
        if let Some(value) = non_empty(env, var) {
            sources.push((value, var));
        }
    }
    for (file, source) in [(".jvmopts", ".jvmopts"), (".sbtopts", ".sbtopts")] {
        if let Ok(bytes) = read_regular_to_bytes_sync(&cwd.join(file)) {
            sources.push((String::from_utf8_lossy(&bytes).into_owned(), source));
        }
    }
    let prefix = format!("-D{key}=");
    sources
        .into_iter()
        .filter_map(|(text, source)| {
            text.lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .flat_map(str::split_whitespace)
                .filter_map(|token| {
                    let token = token.strip_prefix("-J").unwrap_or(token);
                    let value = unquote(token.strip_prefix(&prefix)?);
                    (!value.is_empty()).then(|| value.to_string())
                })
                .next_back()
                .map(|value| (value, source))
        })
        .collect()
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|v| v.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// `env(name)`, an empty value counting as unset.
pub(crate) fn non_empty(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name).filter(|v| !v.is_empty())
}

/// The candidates that are existing directories, first occurrence of each
/// canonical path kept.
pub(crate) fn existing_dedup<T>(candidates: Vec<(PathBuf, T)>) -> Vec<(PathBuf, T)> {
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|(dir, _)| {
            std::fs::canonicalize(dir).is_ok_and(|real| real.is_dir() && seen.insert(real))
        })
        .collect()
}

/// `path` is a directory and not a symbolic link.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// The children of `dir` that are directories or regular files (never
/// symbolic links, never dot-names), sorted by name, each with whether it
/// is a directory.
fn sorted_children(dir: &Path) -> Vec<(PathBuf, bool)> {
    let Some((entries, _complete)) = crate::utils::fs::read_dir_entries_sync(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, bool)> = entries
        .into_iter()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|e| {
            let kind = e.file_type().ok()?;
            (kind.is_dir() || kind.is_file()).then(|| (e.path(), kind.is_dir()))
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn mkdir(p: &Path) -> PathBuf {
        std::fs::create_dir_all(p).unwrap();
        p.to_path_buf()
    }

    fn write(p: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn pom(g: &str, a: &str, v: &str) -> String {
        format!("<project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></project>")
    }

    /// Write `g:a:v` (pom, jar, a hidden sidecar) under `root`.
    fn artifact(root: &Path, g: &str, a: &str, v: &str) -> PathBuf {
        let dir = root.join(g.replace('.', "/")).join(a).join(v);
        write(&dir.join(format!("{a}-{v}.pom")), pom(g, a, v).as_bytes());
        write(&dir.join(format!("{a}-{v}.jar")), b"jar");
        write(&dir.join(format!(".{a}-{v}.jar__sha1")), b"0000");
        dir
    }

    #[test]
    fn host_os_is_one_of_the_tables() {
        let os = TargetOs::host();
        assert!(matches!(
            os,
            TargetOs::Linux | TargetOs::MacOs | TargetOs::Windows
        ));
        assert_eq!(
            TargetOs::host() == TargetOs::Windows,
            cfg!(windows),
            "host table"
        );
    }

    #[test]
    fn os_default_tables() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let cwd = mkdir(&t.path().join("proj"));
        let linux = mkdir(&home.join(".cache/coursier/v1"));
        let mac = mkdir(&home.join("Library/Caches/Coursier/v1"));
        let legacy = mkdir(&home.join(".coursier/cache/v1"));
        let local = t.path().join("local");
        let win = mkdir(&local.join("Coursier/Cache/v1"));
        let none = env_of(&[]);
        assert_eq!(
            coursier_cache_dirs(TargetOs::Linux, &none, Some(&home), &cwd),
            vec![(linux.clone(), "default"), (legacy.clone(), "legacy")]
        );
        assert_eq!(
            coursier_cache_dirs(TargetOs::MacOs, &none, Some(&home), &cwd),
            vec![(mac, "default"), (legacy.clone(), "legacy")]
        );
        let windows = env_of(&[("LOCALAPPDATA", local.to_str().unwrap())]);
        let found = coursier_cache_dirs(TargetOs::Windows, &windows, Some(&home), &cwd);
        assert_eq!(found[0], (win.clone(), "default"));
        assert_eq!(found.last().unwrap(), &(legacy.clone(), "legacy"));
        // `\cache\v1` is the second spelling (a distinct directory on a
        // case-sensitive file system, the same one elsewhere).
        let lower = local.join("Coursier/cache/v1");
        if std::fs::canonicalize(&lower).ok() != std::fs::canonicalize(&win).ok() {
            mkdir(&lower);
            let found = coursier_cache_dirs(TargetOs::Windows, &windows, Some(&home), &cwd);
            assert_eq!(found[1], (lower, "default"));
        }
        // No LOCALAPPDATA: `~/AppData/Local`.
        let fallback = mkdir(&home.join("AppData/Local/Coursier/Cache/v1"));
        let found = coursier_cache_dirs(TargetOs::Windows, &none, Some(&home), &cwd);
        assert_eq!(found[0], (fallback, "default"));
        // No home, no env: nothing.
        assert!(coursier_cache_dirs(TargetOs::Linux, &none, None, &cwd).is_empty());
    }

    #[test]
    fn xdg_cache_home_replaces_dot_cache_on_linux() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        mkdir(&home.join(".cache/coursier/v1"));
        let xdg = mkdir(&t.path().join("xdg/coursier/v1"));
        let env = env_of(&[("XDG_CACHE_HOME", t.path().join("xdg").to_str().unwrap())]);
        assert_eq!(
            coursier_cache_dirs(TargetOs::Linux, &env, Some(&home), t.path()),
            vec![(xdg, "default")]
        );
        // Empty = unset.
        let env = env_of(&[("XDG_CACHE_HOME", "")]);
        assert_eq!(
            coursier_cache_dirs(TargetOs::Linux, &env, Some(&home), t.path()),
            vec![(home.join(".cache/coursier/v1"), "default")]
        );
    }

    #[test]
    fn precedence_and_every_source_kept() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let cwd = mkdir(&t.path().join("proj"));
        let d = |n: &str| mkdir(&t.path().join(n));
        let (env_cache, java, sbt, jvmopts, sbtopts, cs_home, default) = (
            d("env"),
            d("java"),
            d("sbt"),
            d("jvmopts"),
            d("sbtopts"),
            d("cshome/cache"),
            mkdir(&home.join(".cache/coursier/v1")),
        );
        write(
            &cwd.join(".jvmopts"),
            format!(
                "# comment -Dcoursier.cache=/nope\n-Xmx1g\n-Dcoursier.cache={}\n",
                jvmopts.display()
            )
            .as_bytes(),
        );
        write(
            &cwd.join(".sbtopts"),
            format!("-J-Dcoursier.cache={}\n", sbtopts.display()).as_bytes(),
        );
        let env = env_of(&[
            ("COURSIER_CACHE", env_cache.to_str().unwrap()),
            (
                "JAVA_OPTS",
                &format!(
                    "-Dcoursier.cache=/missing -Dcoursier.cache={}",
                    java.display()
                ),
            ),
            (
                "SBT_OPTS",
                &format!(
                    "-Dcoursier.cache=\"{}\" -Dsbt.coursier.home={}",
                    sbt.display(),
                    t.path().join("cshome").display()
                ),
            ),
        ]);
        assert_eq!(
            coursier_cache_dirs(TargetOs::Linux, &env, Some(&home), &cwd),
            vec![
                (env_cache, "COURSIER_CACHE"),
                (java, "JAVA_OPTS"),
                (sbt, "SBT_OPTS"),
                (jvmopts, ".jvmopts"),
                (sbtopts, ".sbtopts"),
                (cs_home, "SBT_OPTS"),
                (default, "default"),
            ]
        );
    }

    #[test]
    fn empty_values_count_as_unset_and_duplicates_collapse() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let default = mkdir(&home.join(".cache/coursier/v1"));
        let env = env_of(&[
            ("COURSIER_CACHE", ""),
            ("JAVA_OPTS", "-Dcoursier.cache= -Dcoursier.cache=\"\""),
            (
                "SBT_OPTS",
                &format!("-Dcoursier.cache={}", default.display()),
            ),
        ]);
        // The SBT_OPTS value is the default dir: listed once, first source.
        assert_eq!(
            coursier_cache_dirs(TargetOs::Linux, &env, Some(&home), t.path()),
            vec![(default, "SBT_OPTS")]
        );
    }

    #[test]
    fn relative_values_resolve_against_the_project() {
        let t = tempfile::tempdir().unwrap();
        let cwd = mkdir(&t.path().join("proj"));
        mkdir(&cwd.join("cs"));
        write(&cwd.join(".jvmopts"), b"-Dcoursier.cache=cs\n");
        assert_eq!(
            coursier_cache_dirs(TargetOs::Linux, &env_of(&[]), None, &cwd),
            vec![(cwd.join("cs"), ".jvmopts")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn option_files_are_read_fifo_safe() {
        let t = tempfile::tempdir().unwrap();
        for name in [".jvmopts", ".sbtopts"] {
            let path = t.path().join(name);
            let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let cwd = t.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(jvm_option_values(&|_| None, &cwd, "coursier.cache"));
        });
        let found = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a FIFO option file must not wedge the lookup");
        assert!(found.is_empty());
    }

    #[test]
    fn repo_roots_two_hosts_and_nested_repository_paths() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        let central = cache.join("https/repo1.maven.org/maven2");
        let nexus = cache.join("https/nexus.corp/content/repositories/releases");
        let plain = cache.join("http/plain.host");
        artifact(&central, "org.slf4j", "slf4j-api", "1.7.36");
        artifact(&central, "com.google.code.gson", "gson", "2.8.9");
        artifact(&nexus, "com.corp", "lib", "1.0");
        artifact(&plain, "io.x", "y", "2");
        assert!(is_coursier_cache_dir(&cache));
        assert!(!is_coursier_cache_dir(&central));
        assert_eq!(repo_roots(&cache), vec![nexus, central, plain]);
    }

    #[test]
    fn repo_roots_skip_ivy_pattern_hidden_and_mismatched_poms() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        let host = cache.join("https/repo.scala-sbt.org");
        // Ivy pattern: no pom.
        write(
            &host.join("scalasbt/ivy-releases/org.scala-sbt/sbt/1.2.8/jars/sbt.jar"),
            b"jar",
        );
        write(
            &host.join("scalasbt/ivy-releases/org.scala-sbt/sbt/1.2.8/ivys/ivy.xml"),
            b"<ivy-module/>",
        );
        // A hidden pom-named sidecar is never read.
        write(&host.join("x/a/1/.a-1.pom"), pom("x", "a", "1").as_bytes());
        // groupId disagrees with the path.
        write(
            &host.join("evil/org/b/2/b-2.pom"),
            pom("com.other", "b", "2").as_bytes(),
        );
        // artifact disagrees.
        write(&host.join("m/c/3/c-3.pom"), pom("m", "zz", "3").as_bytes());
        assert!(repo_roots(&cache).is_empty());
        // A correct one beside them is found.
        let good = host.join("maven2");
        artifact(&good, "org.ok", "fine", "1");
        assert_eq!(repo_roots(&cache), vec![good]);
    }

    #[test]
    fn repo_roots_accept_parent_group_poms_and_host_level_roots() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        let host = cache.join("https/host.example");
        // The repository is the host itself; the pom inherits its group.
        write(
            &host.join("org/acme/core/1.0/core-1.0.pom"),
            b"<project>\n  <parent>\n    <groupId>org.acme</groupId>\n    <artifactId>p</artifactId>\n    <version>1.0</version>\n  </parent>\n  <artifactId>core</artifactId>\n  <version>1.0</version>\n</project>\n",
        );
        assert_eq!(repo_roots(&cache), vec![host]);
    }

    #[test]
    fn repo_roots_never_reach_above_the_host() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        // `https/<host>` spelled as the group: the root would be `https/`.
        write(
            &cache.join("https/org/a/1/a-1.pom"),
            pom("org", "a", "1").as_bytes(),
        );
        assert!(repo_roots(&cache).is_empty());
    }

    #[test]
    fn repo_roots_prune_after_the_entry_cap() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        let host = cache.join("https/big.host");
        for i in 0..20 {
            mkdir(&host.join(format!("junk{i:02}")));
        }
        artifact(&host.join("zz/maven2"), "org.ok", "fine", "1");
        assert_eq!(repo_roots_capped(&cache, 10), Vec::<PathBuf>::new());
        assert_eq!(
            repo_roots_capped(&cache, 1000),
            vec![host.join("zz/maven2")]
        );
    }

    #[test]
    fn repo_roots_respect_the_depth_cap() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        let host = cache.join("https/deep.host");
        let mut repo = host.clone();
        for i in 0..MAX_DEPTH {
            repo = repo.join(format!("d{i}"));
        }
        artifact(&repo, "g", "a", "1");
        assert!(repo_roots(&cache).is_empty(), "pom below depth 24");
        let shallow = host.join("r");
        artifact(&shallow, "g", "a", "1");
        assert_eq!(repo_roots(&cache), vec![shallow]);
    }

    #[cfg(unix)]
    #[test]
    fn repo_roots_follow_no_symlinks() {
        let t = tempfile::tempdir().unwrap();
        let outside = t.path().join("outside");
        artifact(&outside.join("maven2"), "org.x", "a", "1");
        let cache = t.path().join("v1");
        let host = mkdir(&cache.join("https/host"));
        std::os::unix::fs::symlink(outside.join("maven2"), host.join("maven2")).unwrap();
        assert!(repo_roots(&cache).is_empty());
        // A symlinked scheme directory is not followed either.
        let cache2 = mkdir(&t.path().join("v2"));
        std::os::unix::fs::symlink(cache.join("https"), cache2.join("https")).unwrap();
        assert!(!is_coursier_cache_dir(&cache2));
    }

    #[cfg(unix)]
    #[test]
    fn repo_roots_read_poms_fifo_safe() {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("v1");
        let dir = mkdir(&cache.join("https/h/r/g/a/1"));
        let c = std::ffi::CString::new(dir.join("a-1.pom").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(repo_roots(&cache));
        });
        let found = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a FIFO pom must not wedge the walk");
        assert!(found.is_empty());
    }

    #[test]
    fn missing_dirs_find_nothing() {
        let t = tempfile::tempdir().unwrap();
        assert!(repo_roots(&t.path().join("absent")).is_empty());
        assert!(!is_coursier_cache_dir(t.path()));
    }
}
