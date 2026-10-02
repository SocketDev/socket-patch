//! The Gradle user home and the dependency caches in it, resolved from an
//! explicit environment (the process-env adapter lives in
//! `crawlers::gradle_cache`).
//!
//! Gradle picks its user home from, in order: the `gradle.user.home`
//! system property (`-Dgradle.user.home=…` in `GRADLE_OPTS`, which the
//! launcher places after `JAVA_OPTS`, so it wins), `GRADLE_USER_HOME`, and
//! `<JVM user.home>/.gradle`. The JVM's `user.home` on Linux and macOS is
//! the account's passwd entry, not `$HOME` (they differ in, for example,
//! container CI jobs that set `HOME`). Downloaded modules live in
//! `<user home>/caches/modules-2/files-2.1`; a read-only shared cache can
//! sit beside it at `$GRADLE_RO_DEP_CACHE/modules-2/files-2.1`.

use std::path::{Path, PathBuf};

use super::{Env, Os};

/// A resolved Gradle user home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradleHome {
    pub user_home: PathBuf,
    /// `<user_home>/caches/modules-2/files-2.1`.
    pub files21: PathBuf,
    /// `$GRADLE_RO_DEP_CACHE/modules-2/files-2.1`; scanned, never written.
    pub ro_files21: Option<PathBuf>,
    /// `$GRADLE_HOME` (a Gradle distribution), for its `init.d`. A wrapper
    /// build runs its own distribution's instead (see
    /// [`GradleHome::wrapper_init_dirs`]).
    pub gradle_home: Option<PathBuf>,
}

/// The `files-2.1` directory of a cache root (a user home or the
/// read-only cache): `<root>/caches/modules-2/files-2.1` for a user
/// home.
pub fn files21_of_user_home(user_home: &Path) -> PathBuf {
    user_home.join("caches").join("modules-2").join("files-2.1")
}

/// A non-empty variable.
fn var(env: &dyn Env, k: &str) -> Option<String> {
    env.var(k).filter(|v| !v.is_empty())
}

impl GradleHome {
    /// Resolve the user home from `env`. `home_dir` must be what the JVM
    /// would report as `user.home`: on Unix the passwd entry's home
    /// directory (`getpwuid(getuid())->pw_dir`), NOT `$HOME`. When neither
    /// system property nor `GRADLE_USER_HOME` names the home, it is
    /// `<home>/.gradle` with `<home>` = on Unix `home_dir`, else `$HOME`;
    /// on Windows `USERPROFILE`, else `HOME`, else `home_dir`. `None` when
    /// no home can be found.
    pub fn resolve(env: &dyn Env, os: Os, home_dir: Option<&Path>) -> Option<Self> {
        let user_home = ["GRADLE_OPTS", "JAVA_OPTS"]
            .iter()
            .find_map(|k| {
                var(env, k)
                    .and_then(|opts| system_property(&opts, "gradle.user.home", os))
                    .filter(|v| !v.is_empty())
            })
            .map(PathBuf::from)
            .or_else(|| var(env, "GRADLE_USER_HOME").map(PathBuf::from))
            .or_else(|| {
                let home = match os {
                    Os::Windows => var(env, "USERPROFILE")
                        .or_else(|| var(env, "HOME"))
                        .map(PathBuf::from)
                        .or_else(|| home_dir.map(Path::to_path_buf)),
                    Os::Unix => home_dir
                        .filter(|h| !h.as_os_str().is_empty())
                        .map(Path::to_path_buf)
                        .or_else(|| var(env, "HOME").map(PathBuf::from)),
                };
                home.map(|h| h.join(".gradle"))
            })?;
        Some(Self {
            files21: files21_of_user_home(&user_home),
            ro_files21: var(env, "GRADLE_RO_DEP_CACHE")
                .map(|ro| PathBuf::from(ro).join("modules-2").join("files-2.1")),
            gradle_home: var(env, "GRADLE_HOME").map(PathBuf::from),
            user_home,
        })
    }

    /// The fixed init-script files: `<user home>/init.gradle` and
    /// `<user home>/init.gradle.kts`.
    pub fn init_script_paths(&self) -> Vec<PathBuf> {
        vec![
            self.user_home.join("init.gradle"),
            self.user_home.join("init.gradle.kts"),
        ]
    }

    /// The init-script directories: `<user home>/init.d` and
    /// `$GRADLE_HOME/init.d`. Every `*.gradle` / `*.gradle.kts` in them
    /// runs (see [`is_init_script_name`]).
    pub fn init_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![self.user_home.join("init.d")];
        if let Some(g) = &self.gradle_home {
            dirs.push(g.join("init.d"));
        }
        dirs
    }

    /// Where the wrapper unpacks distributions in this user home
    /// (`distributionBase=GRADLE_USER_HOME`, `distributionPath=wrapper/dists`).
    pub fn wrapper_dists_dir(&self) -> PathBuf {
        self.user_home.join("wrapper").join("dists")
    }

    /// The `init.d` directories of the wrapper distributions unpacked in
    /// this user home: `<dists>/<name>/<url hash>/<unpacked dir>/init.d`.
    /// A wrapper build runs the `init.d` of its own distribution (custom
    /// corporate distributions ship scripts there). `distribution_url`
    /// (the `distributionUrl` of `gradle-wrapper.properties`, `\:`
    /// escapes allowed) narrows the search to that distribution's `<name>`
    /// (the URL's file name without `.zip`); `None` searches them all.
    /// Only directories `list` shows are returned.
    pub fn wrapper_init_dirs(
        &self,
        list: &dyn Fn(&Path) -> Vec<String>,
        distribution_url: Option<&str>,
    ) -> Vec<PathBuf> {
        let dists = self.wrapper_dists_dir();
        let wanted = distribution_url.map(|u| {
            let u = u.trim().replace('\\', "");
            let file = u.rsplit('/').next().unwrap_or(&u).to_string();
            file.strip_suffix(".zip")
                .map_or(file.clone(), str::to_string)
        });
        let subdirs = |d: &Path| -> Vec<String> {
            let mut names: Vec<String> = list(d)
                .into_iter()
                .filter_map(|n| n.strip_suffix('/').map(str::to_string))
                .filter(|n| !n.is_empty())
                .collect();
            names.sort();
            names
        };
        let mut out = Vec::new();
        for name in subdirs(&dists) {
            if wanted.as_ref().is_some_and(|w| *w != name) {
                continue;
            }
            let dist = dists.join(&name);
            for hash in subdirs(&dist) {
                let unpacked = dist.join(&hash);
                for top in subdirs(&unpacked) {
                    let dir = unpacked.join(&top);
                    if list(&dir).iter().any(|c| c == "init.d/") {
                        out.push(dir.join("init.d"));
                    }
                }
            }
        }
        out
    }

    /// Every init-script candidate in Gradle's order: the fixed files,
    /// then each init directory's scripts sorted by name: the user home's
    /// `init.d`, every unpacked wrapper distribution's `init.d` (see
    /// [`Self::init_scripts_for`] to narrow that to the build's own) and
    /// `$GRADLE_HOME/init.d`. `list` returns a directory's child names
    /// (directories ending in `/`); whether the fixed files exist is the
    /// caller's to check.
    pub fn init_scripts_with(&self, list: &dyn Fn(&Path) -> Vec<String>) -> Vec<PathBuf> {
        self.init_scripts_for(list, None)
    }

    /// [`Self::init_scripts_with`] with the wrapper distributions narrowed
    /// to `distribution_url`'s (see [`Self::wrapper_init_dirs`]).
    pub fn init_scripts_for(
        &self,
        list: &dyn Fn(&Path) -> Vec<String>,
        distribution_url: Option<&str>,
    ) -> Vec<PathBuf> {
        let mut out = self.init_script_paths();
        let mut dirs = vec![self.user_home.join("init.d")];
        dirs.extend(self.wrapper_init_dirs(list, distribution_url));
        dirs.extend(self.gradle_home.as_ref().map(|g| g.join("init.d")));
        for dir in dirs {
            let mut names: Vec<String> = list(&dir)
                .into_iter()
                .filter(|n| is_init_script_name(n))
                .collect();
            names.sort();
            out.extend(names.into_iter().map(|n| dir.join(n)));
        }
        out
    }
}

/// Whether a file in an `init.d` directory is an init script.
pub fn is_init_script_name(name: &str) -> bool {
    !name.ends_with('/') && (name.ends_with(".gradle") || name.ends_with(".gradle.kts"))
}

/// The value of `-D<name>=…` in a JVM option string; the last one wins.
/// `-D<name>` without a value is the empty string.
pub fn system_property(opts: &str, name: &str, os: Os) -> Option<String> {
    let flag = format!("-D{name}");
    split_opts(opts, os).into_iter().rev().find_map(|arg| {
        let rest = arg.strip_prefix(&flag)?;
        if rest.is_empty() {
            Some(String::new())
        } else {
            rest.strip_prefix('=').map(str::to_string)
        }
    })
}

/// Split a JVM option string into arguments the way the launcher does:
/// on Unix like `xargs` (single and double quotes group, a backslash
/// escapes the next character outside single quotes); on Windows only
/// double quotes group and backslashes are literal (they are path
/// separators there).
pub fn split_opts(opts: &str, os: Os) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_arg = false;
    let mut quote: Option<char> = None;
    let mut chars = opts.chars();
    while let Some(ch) = chars.next() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some('"') if ch == '\\' && os == Os::Unix => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            Some(_) => cur.push(ch),
            None if ch.is_whitespace() => {
                if in_arg {
                    out.push(std::mem::take(&mut cur));
                    in_arg = false;
                }
            }
            None => {
                in_arg = true;
                match ch {
                    '"' => quote = Some('"'),
                    '\'' if os == Os::Unix => quote = Some('\''),
                    '\\' if os == Os::Unix => {
                        if let Some(next) = chars.next() {
                            cur.push(next);
                        }
                    }
                    _ => cur.push(ch),
                }
            }
        }
    }
    if in_arg {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    struct VecEnv(Vec<(String, String)>);

    impl Env for VecEnv {
        fn var(&self, k: &str) -> Option<String> {
            self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn user_home_precedence_table() {
        let fallback = Path::new("/fallback");
        // (env, os, expected user home)
        type Row<'a> = (&'a [(&'a str, &'a str)], Os, Option<&'a str>);
        let table: &[Row<'_>] = &[
            // Unix: the passwd home (`home_dir`) beats `$HOME`, like the
            // JVM's user.home.
            (&[("HOME", "/h")], Os::Unix, Some("/fallback/.gradle")),
            (&[], Os::Unix, Some("/fallback/.gradle")),
            (&[("HOME", "")], Os::Unix, Some("/fallback/.gradle")),
            (
                &[("GRADLE_USER_HOME", "/g"), ("HOME", "/h")],
                Os::Unix,
                Some("/g"),
            ),
            (
                &[("GRADLE_USER_HOME", ""), ("HOME", "/h")],
                Os::Unix,
                Some("/fallback/.gradle"),
            ),
            (
                &[
                    ("GRADLE_OPTS", "-Xmx1g -Dgradle.user.home=/o"),
                    ("GRADLE_USER_HOME", "/g"),
                ],
                Os::Unix,
                Some("/o"),
            ),
            (
                &[(
                    "GRADLE_OPTS",
                    "-Dgradle.user.home=\"/with space/gh\" -Xmx1g",
                )],
                Os::Unix,
                Some("/with space/gh"),
            ),
            (
                &[("GRADLE_OPTS", "'-Dgradle.user.home=/single q'")],
                Os::Unix,
                Some("/single q"),
            ),
            (
                &[("GRADLE_OPTS", "-Dgradle.user.home=/with\\ esc")],
                Os::Unix,
                Some("/with esc"),
            ),
            (
                &[("GRADLE_OPTS", "-Dgradle.user.home=/a -Dgradle.user.home=/b")],
                Os::Unix,
                Some("/b"),
            ),
            (
                &[
                    ("JAVA_OPTS", "-Dgradle.user.home=/j"),
                    ("GRADLE_USER_HOME", "/g"),
                ],
                Os::Unix,
                Some("/j"),
            ),
            (
                &[
                    ("GRADLE_OPTS", "-Dgradle.user.home=/o"),
                    ("JAVA_OPTS", "-Dgradle.user.home=/j"),
                ],
                Os::Unix,
                Some("/o"),
            ),
            (
                &[
                    ("GRADLE_OPTS", "-Dgradle.user.home="),
                    ("JAVA_OPTS", "-Dgradle.user.home=/j"),
                ],
                Os::Unix,
                Some("/j"),
            ),
            (
                &[("GRADLE_OPTS", "-Dgradle.user.homeX=/x"), ("HOME", "/h")],
                Os::Unix,
                Some("/fallback/.gradle"),
            ),
            (
                &[("USERPROFILE", "C:\\Users\\u"), ("HOME", "/h")],
                Os::Windows,
                Some("C:\\Users\\u/.gradle"),
            ),
            (
                &[("USERPROFILE", ""), ("HOME", "/h")],
                Os::Windows,
                Some("/h/.gradle"),
            ),
            (
                &[("USERPROFILE", "C:\\Users\\u"), ("HOME", "/h")],
                Os::Unix,
                Some("/fallback/.gradle"),
            ),
            (
                &[("GRADLE_OPTS", "\"-Dgradle.user.home=C:\\Gradle Home\"")],
                Os::Windows,
                Some("C:\\Gradle Home"),
            ),
            (
                &[("GRADLE_OPTS", "-Dgradle.user.home=C:\\g\\h")],
                Os::Windows,
                Some("C:\\g\\h"),
            ),
        ];
        for (pairs, os, want) in table {
            let e = VecEnv(env(pairs));
            let got = GradleHome::resolve(&e, *os, Some(fallback)).map(|h| h.user_home);
            let want = want.map(|w| {
                // `<home>/.gradle` is a host-OS join.
                match w.strip_suffix("/.gradle") {
                    Some(base) => PathBuf::from(base).join(".gradle"),
                    None => PathBuf::from(w),
                }
            });
            assert_eq!(got, want, "{pairs:?} on {os:?}");
        }
        assert_eq!(
            GradleHome::resolve(&VecEnv(Vec::new()), Os::Unix, None),
            None
        );
    }

    #[test]
    fn unix_home_prefers_the_passwd_entry() {
        // A container CI job: HOME=/github/home, passwd home /root.
        let e = VecEnv(env(&[("HOME", "/github/home")]));
        let user_home = |os, home_dir: Option<&str>| {
            GradleHome::resolve(&e, os, home_dir.map(Path::new)).map(|h| h.user_home)
        };
        assert_eq!(
            user_home(Os::Unix, Some("/root")),
            Some(Path::new("/root").join(".gradle"))
        );
        // `$HOME` only stands in when the passwd home is unknown.
        assert_eq!(
            user_home(Os::Unix, None),
            Some(Path::new("/github/home").join(".gradle"))
        );
        assert_eq!(
            user_home(Os::Unix, Some("")),
            Some(Path::new("/github/home").join(".gradle"))
        );
        // Windows keeps USERPROFILE, then HOME, then the account home.
        assert_eq!(
            user_home(Os::Windows, Some("C:\\Users\\u")),
            Some(Path::new("/github/home").join(".gradle"))
        );
        let none = VecEnv(Vec::new());
        assert_eq!(
            GradleHome::resolve(&none, Os::Windows, Some(Path::new("C:\\U"))).map(|h| h.user_home),
            Some(Path::new("C:\\U").join(".gradle"))
        );
    }

    #[test]
    fn wrapper_distribution_init_dirs() {
        let e = VecEnv(env(&[("GRADLE_USER_HOME", "/g")]));
        let h = GradleHome::resolve(&e, Os::Unix, None).unwrap();
        let dists = Path::new("/g").join("wrapper").join("dists");
        let corp = dists.join("gradle-8.14.3-corp-bin");
        let stock = dists.join("gradle-8.14.3-bin");
        let list = |d: &Path| -> Vec<String> {
            let names: &[&str] = if d == dists {
                &["gradle-8.14.3-corp-bin/", "gradle-8.14.3-bin/", "x.lck"]
            } else if d == corp {
                &["abc123/"]
            } else if d == corp.join("abc123") {
                &["gradle-8.14.3/", "gradle-8.14.3-corp-bin.zip.ok"]
            } else if d == corp.join("abc123").join("gradle-8.14.3") {
                &["bin/", "init.d/", "lib/"]
            } else if d == corp.join("abc123").join("gradle-8.14.3").join("init.d") {
                &["repos.gradle", "README"]
            } else if d == stock {
                &["def456/"]
            } else if d == stock.join("def456") {
                &["gradle-8.14.3/"]
            } else if d == stock.join("def456").join("gradle-8.14.3") {
                &["bin/", "lib/"]
            } else {
                &[]
            };
            names.iter().map(|n| n.to_string()).collect()
        };
        let corp_init = corp.join("abc123").join("gradle-8.14.3").join("init.d");
        assert_eq!(
            h.wrapper_init_dirs(&list, None),
            std::slice::from_ref(&corp_init)
        );
        assert_eq!(
            h.wrapper_init_dirs(
                &list,
                Some("https\\://corp.example/dist/gradle-8.14.3-corp-bin.zip")
            ),
            std::slice::from_ref(&corp_init)
        );
        assert!(h
            .wrapper_init_dirs(
                &list,
                Some("https://services.gradle.org/distributions/gradle-8.14.3-bin.zip")
            )
            .is_empty());
        let scripts = h.init_scripts_with(&list);
        assert_eq!(
            scripts,
            [
                Path::new("/g").join("init.gradle"),
                Path::new("/g").join("init.gradle.kts"),
                corp_init.join("repos.gradle"),
            ]
        );
        assert_eq!(
            h.init_scripts_for(&list, Some("https://x/gradle-8.14.3-bin.zip"))
                .len(),
            2
        );
    }

    #[test]
    fn caches_and_ro_cache() {
        let e = VecEnv(env(&[
            ("GRADLE_USER_HOME", "/g"),
            ("GRADLE_RO_DEP_CACHE", "/ro"),
            ("GRADLE_HOME", "/dist"),
        ]));
        let h = GradleHome::resolve(&e, Os::Unix, None).unwrap();
        assert_eq!(
            h.files21,
            Path::new("/g").join("caches/modules-2/files-2.1")
        );
        assert_eq!(
            h.ro_files21.as_deref(),
            Some(Path::new("/ro").join("modules-2/files-2.1").as_path())
        );
        assert_eq!(h.gradle_home.as_deref(), Some(Path::new("/dist")));
        let e = VecEnv(env(&[
            ("GRADLE_USER_HOME", "/g"),
            ("GRADLE_RO_DEP_CACHE", ""),
        ]));
        assert_eq!(
            GradleHome::resolve(&e, Os::Unix, None).unwrap().ro_files21,
            None
        );
    }

    #[test]
    fn init_script_locations() {
        let e = VecEnv(env(&[("GRADLE_USER_HOME", "/g"), ("GRADLE_HOME", "/dist")]));
        let h = GradleHome::resolve(&e, Os::Unix, None).unwrap();
        assert_eq!(
            h.init_script_paths(),
            [
                Path::new("/g").join("init.gradle"),
                Path::new("/g").join("init.gradle.kts")
            ]
        );
        assert_eq!(
            h.init_dirs(),
            [
                Path::new("/g").join("init.d"),
                Path::new("/dist").join("init.d")
            ]
        );
        let list = |d: &Path| -> Vec<String> {
            if d == Path::new("/g").join("init.d") {
                vec![
                    "z.gradle".into(),
                    "a.gradle.kts".into(),
                    "notes.txt".into(),
                    "sub.gradle/".into(),
                ]
            } else {
                vec!["mirror.gradle".into()]
            }
        };
        assert_eq!(
            h.init_scripts_with(&list),
            [
                Path::new("/g").join("init.gradle"),
                Path::new("/g").join("init.gradle.kts"),
                Path::new("/g").join("init.d").join("a.gradle.kts"),
                Path::new("/g").join("init.d").join("z.gradle"),
                Path::new("/dist").join("init.d").join("mirror.gradle"),
            ]
        );
        let no_dist = VecEnv(env(&[("GRADLE_USER_HOME", "/g")]));
        assert_eq!(
            GradleHome::resolve(&no_dist, Os::Unix, None)
                .unwrap()
                .init_dirs()
                .len(),
            1
        );
    }

    #[test]
    fn opts_splitting() {
        assert_eq!(
            split_opts("  -a  \"b c\" 'd e' f\\ g ", Os::Unix),
            ["-a", "b c", "d e", "f g"]
        );
        assert_eq!(
            split_opts("-a \"b c\" 'd e' x\\y", Os::Windows),
            ["-a", "b c", "'d", "e'", "x\\y"]
        );
        assert_eq!(split_opts("\"\"", Os::Unix), [""]);
        assert_eq!(
            system_property("-Dgradle.user.home", "gradle.user.home", Os::Unix).as_deref(),
            Some("")
        );
    }
}
