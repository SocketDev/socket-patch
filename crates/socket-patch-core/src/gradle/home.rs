//! The Gradle user home and the dependency caches in it, resolved from an
//! explicit environment (the process-env adapter lives in
//! `crawlers::gradle_cache`).
//!
//! Gradle picks its user home from, in order: the `gradle.user.home`
//! system property (`-Dgradle.user.home=…` in `GRADLE_OPTS`, which the
//! launcher places after `JAVA_OPTS`, so it wins), `GRADLE_USER_HOME`, and
//! `<home>/.gradle`. Downloaded modules live in
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
    /// `$GRADLE_HOME` (a Gradle distribution), for its `init.d`.
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
    /// Resolve the user home from `env`. `home_dir` is the account's home
    /// directory, used when the environment names none (`HOME`; on
    /// Windows `USERPROFILE` first). `None` when no home can be found.
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
                    Os::Windows => var(env, "USERPROFILE").or_else(|| var(env, "HOME")),
                    Os::Unix => var(env, "HOME"),
                };
                home.map(PathBuf::from)
                    .or_else(|| home_dir.map(Path::to_path_buf))
                    .map(|h| h.join(".gradle"))
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

    /// Every init-script candidate in Gradle's order: the fixed files,
    /// then each init directory's scripts sorted by name. `list` returns a
    /// directory's child names (directories ending in `/`); whether the
    /// fixed files exist is the caller's to check.
    pub fn init_scripts_with(&self, list: &dyn Fn(&Path) -> Vec<String>) -> Vec<PathBuf> {
        let mut out = self.init_script_paths();
        for dir in self.init_dirs() {
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
            (&[("HOME", "/h")], Os::Unix, Some("/h/.gradle")),
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
                Some("/h/.gradle"),
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
                Some("/h/.gradle"),
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
                Some("/h/.gradle"),
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
