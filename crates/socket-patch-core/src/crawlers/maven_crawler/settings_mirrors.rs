//! The mirrors Maven is configured with on this machine, for the project it
//! would build: what hosted mode weighs before it adds a repository to a
//! pom ([`crate::formats::maven::mirror`]).
//!
//! Maven merges two settings files, the user's over the installation's:
//!
//! * the user settings: `-s` / `--settings` on the command line, which
//!   here is `MAVEN_ARGS` (Maven 3.9+) and then the project's
//!   `.mvn/maven.config`; else `<user.home>/.m2/settings.xml`;
//! * the global settings: `-gs` / `--global-settings` likewise; else
//!   `conf/settings.xml` of the Maven that would run: the Maven Wrapper's
//!   distribution when the project has a wrapper and that distribution is
//!   unpacked, else the `mvn` on `PATH` (since Maven 3.5 the launcher
//!   takes its home from where it stands and ignores `$MAVEN_HOME` /
//!   `$M2_HOME`), else, with no `mvn` on `PATH`, the installation those
//!   two variables name (a build that calls `$MAVEN_HOME/bin/mvn`).
//!
//! A `.mvn/settings.xml` in the project is read as well, as a second way
//! the build may be started: Maven 4 loads it as the project settings, and
//! a Maven 3 build is commonly given it with `-s` on a command line this
//! scan cannot see.
//!
//! What a build machine is configured with is not known here; only what
//! this one is.

use std::path::{Path, PathBuf};

use super::{character_data, interpolate};
use crate::formats::maven::maven_config_line_args;
use crate::formats::maven::mirror::{merge, Mirror};
use crate::gradle::home::{split_opts, system_property};
use crate::gradle::{Env, Os};

/// The `<mirror>`s the settings file text `raw` declares, in order. A
/// mirror without a `<mirrorOf>` is one Maven rejects, and is left out;
/// one without an `<id>` has Maven's default id, `default`, and is a
/// mirror like any other. Values are trimmed and `${…}` placeholders
/// resolved through `lookup` (one that is undefined stays as written), as
/// Maven reads them.
pub(crate) fn parse_mirrors(
    raw: &str,
    source: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<Mirror> {
    use crate::formats::xml;
    let Ok(text) = xml::blank_non_markup(raw) else {
        return Vec::new();
    };
    let Some(settings) = xml::elements(&text, "settings")
        .ok()
        .and_then(|found| found.first().copied())
    else {
        return Vec::new();
    };
    let value = |parent: &xml::Element, name: &str| -> Option<String> {
        let element = *xml::children(&text, parent, name).ok()?.first()?;
        let data = character_data(&raw[element.inner_start..element.inner_end])?;
        let data = data.trim();
        let data = interpolate(data, lookup).unwrap_or_else(|| data.to_string());
        (!data.is_empty()).then_some(data)
    };
    let mut out = Vec::new();
    for mirrors in xml::children(&text, &settings, "mirrors").unwrap_or_default() {
        for mirror in xml::children(&text, &mirrors, "mirror").unwrap_or_default() {
            let Some(mirror_of) = value(&mirror, "mirrorOf") else {
                continue;
            };
            out.push(Mirror {
                id: value(&mirror, "id").unwrap_or_else(|| DEFAULT_MIRROR_ID.to_string()),
                mirror_of,
                layouts: value(&mirror, "mirrorOfLayouts"),
                source: source.to_string(),
            });
        }
    }
    out
}

/// The id Maven's settings model gives a `<mirror>` that declares none.
const DEFAULT_MIRROR_ID: &str = "default";

/// The value of the option `short` / `long` in `args`, in the spellings
/// Maven takes (measured on 3.8.9, 3.9.9 and 4.0.0-rc-7): `-s path`,
/// `--settings path` (the value is the next argument), `--settings=path`,
/// and `-spath`, the value joined to the short option. A joined value is
/// taken as Maven takes it when it begins with a blank (`-s path` held in
/// ONE argument, which is what a Maven that reads one argument per line
/// makes of such a line: it then looks for a file whose name begins with
/// that blank, finds none, and does not start). Any other joined value is
/// taken only when `is_file` says it names a file: other options begin
/// with the same letters, and a name taken by mistake would stand in for
/// the settings Maven really reads. The first one wins, as in Maven.
fn option_value(
    args: &[String],
    short: &str,
    long: &str,
    is_file: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == short || arg == long {
            return args.next().cloned();
        }
        if let Some(value) = arg
            .strip_prefix(long)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value.to_string());
        }
        if let Some(value) = arg
            .strip_prefix(short)
            .filter(|value| !arg.starts_with("--") && !value.is_empty())
        {
            if value.starts_with(char::is_whitespace) || is_file(value) {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// The arguments of a `.mvn/maven.config`, as the project's Maven reads
/// the file: one per line, so a path may hold spaces (Maven 3.9 and later,
/// Maven 4: [`maven_config_line_args`]), or split on whitespace, where it
/// may not (before 3.9). `#` lines are comments.
///
/// `maven` is the release the project's Maven Wrapper pins, which decides
/// the reading. With no wrapper nothing says which Maven reads the file,
/// so where the two readings differ both are weighed, each a way the
/// build may be started (the whitespace one first: a line it splits is
/// one a Maven 3.9 does not start with).
fn config_readings(config: &str, maven: Option<(u32, u32, u32)>) -> Vec<Vec<String>> {
    let by_line: Vec<String> = maven_config_line_args(config).map(str::to_string).collect();
    let by_whitespace: Vec<String> = config
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect();
    match maven {
        Some(release) if release >= (3, 9, 0) => vec![by_line],
        Some(_) => vec![by_whitespace],
        None if by_line == by_whitespace => vec![by_line],
        None => vec![by_whitespace, by_line],
    }
}

/// The merged mirrors of each way Maven may be started for the project at
/// `root` on this machine (see the module docs): the user settings over
/// the global ones, and, when the project keeps a `.mvn/settings.xml`,
/// that file over the global ones. Sets with no mirror are left out.
/// `home_dir` is the account's home, for when the environment names none.
pub(crate) fn settings_mirror_sets(
    env: &dyn Env,
    os: Os,
    home_dir: Option<&Path>,
    root: &Path,
    maven_config: Option<&str>,
) -> Vec<Vec<Mirror>> {
    use crate::utils::fs::is_usable_home;
    let set = |k: &str| env.var(k).filter(|v| !v.is_empty());
    let property = |name: &str| {
        ["MAVEN_ARGS", "MAVEN_OPTS"].iter().find_map(|k| {
            set(k)
                .and_then(|opts| system_property(&opts, name, os))
                .filter(|v| !v.is_empty())
        })
    };
    let user_home = set("MAVEN_OPTS")
        .and_then(|opts| system_property(&opts, "user.home", os))
        .map(PathBuf::from)
        .filter(|h| is_usable_home(h))
        .or_else(|| match os {
            Os::Windows => ["USERPROFILE", "HOME"]
                .iter()
                .filter_map(|k| set(k).map(PathBuf::from))
                .find(|h| is_usable_home(h)),
            Os::Unix => crate::utils::fs::home_from_env(|k| set(k).map(Into::into)),
        })
        .or_else(|| {
            home_dir
                .filter(|h| is_usable_home(h))
                .map(Path::to_path_buf)
        });
    let lookup = |name: &str| match name {
        "user.home" => user_home.as_ref().map(|h| h.display().to_string()),
        _ => match name.strip_prefix("env.") {
            Some(var) => set(var),
            None => property(name),
        },
    };
    let read = |path: &Path| -> Vec<Mirror> {
        // FIFO-safe: a FIFO planted as a settings file is refused.
        match crate::utils::fs::read_regular_to_string_sync(path) {
            Ok(raw) => parse_mirrors(&raw, &path.display().to_string(), &lookup),
            Err(_) => Vec::new(),
        }
    };
    let rooted = |path: &str| {
        let path = PathBuf::from(path);
        if path.has_root() {
            path
        } else {
            root.join(path)
        }
    };
    let is_file = |path: &str| rooted(path).is_file();
    let project = root.join(".mvn").join("settings.xml");
    // The command line (MAVEN_ARGS) wins over `.mvn/maven.config`, which
    // is read both ways a Maven reads it.
    let command_line = set("MAVEN_ARGS")
        .map(|opts| split_opts(&opts, os))
        .unwrap_or_default();
    let wrapper_maven = crate::utils::fs::read_regular_to_bytes_sync(
        &root
            .join(".mvn")
            .join("wrapper")
            .join("maven-wrapper.properties"),
    )
    .ok()
    .and_then(|props| crate::crawlers::gradle_cache::wrapper_distribution_version(&props, "maven"));
    let readings = match maven_config {
        Some(config) => config_readings(config, wrapper_maven),
        None => vec![Vec::new()],
    };
    let mut sets = Vec::new();
    for reading in readings {
        let mut args = command_line.clone();
        args.extend(reading);
        let named = |short: &str, long: &str| {
            option_value(&args, short, long, &is_file).map(|p| rooted(&p))
        };
        let user = named("-s", "--settings").or_else(|| {
            user_home
                .as_ref()
                .map(|h| h.join(".m2").join("settings.xml"))
        });
        let global = named("-gs", "--global-settings").or_else(|| {
            wrapper_settings(root, set("MAVEN_USER_HOME"), user_home.as_deref())
                .or_else(|| path_settings(set("PATH"), os))
                .or_else(|| {
                    set("MAVEN_HOME")
                        .or_else(|| set("M2_HOME"))
                        .map(|home| PathBuf::from(home).join("conf").join("settings.xml"))
                })
        });
        let global = global.as_deref().map(&read).unwrap_or_default();
        sets.push(merge(
            user.as_deref().map(&read).unwrap_or_default(),
            global.clone(),
        ));
        if project.is_file() && user.as_deref() != Some(project.as_path()) {
            sets.push(merge(read(&project), global));
        }
    }
    sets.retain(|mirrors| !mirrors.is_empty());
    sets.dedup();
    sets
}

/// `conf/settings.xml` of the Maven distribution the project's Maven
/// Wrapper runs, when it is unpacked on this machine, under
/// `<maven user home>/wrapper/dists/`. The wrapper has two layouts:
///
/// * the `only-script` wrapper (the default since Maven Wrapper 3.3)
///   unpacks to `<archive name without -bin>/<hash>/conf/`, e.g.
///   `apache-maven-3.9.6/1a2b3c/conf/`;
/// * the wrapper jar unpacks to `<archive name>/<hash>/<dir>/conf/`, e.g.
///   `apache-maven-3.9.6-bin/1a2b3c/apache-maven-3.9.6/conf/`.
fn wrapper_settings(
    root: &Path,
    maven_user_home: Option<String>,
    user_home: Option<&Path>,
) -> Option<PathBuf> {
    let props = root
        .join(".mvn")
        .join("wrapper")
        .join("maven-wrapper.properties");
    let props = crate::utils::fs::read_regular_to_bytes_sync(&props).ok()?;
    let url = crate::crawlers::gradle_cache::parse_properties(&props).remove("distributionUrl")?;
    let archive = url.trim().rsplit('/').next()?;
    let name = archive
        .strip_suffix(".zip")
        .or_else(|| archive.strip_suffix(".tar.gz"))?;
    let dists = maven_user_home
        .map(PathBuf::from)
        .or_else(|| user_home.map(|h| h.join(".m2")))?
        .join("wrapper")
        .join("dists");
    let mut found: Vec<PathBuf> = Vec::new();
    let mut names = vec![name];
    names.extend(name.strip_suffix("-bin"));
    for name in names {
        let Ok(hashes) = std::fs::read_dir(dists.join(name)) else {
            continue;
        };
        for hash in hashes.flatten() {
            // The script's layout: the distribution is the hash directory.
            let direct = hash.path().join("conf").join("settings.xml");
            if direct.is_file() {
                found.push(direct);
                continue;
            }
            let Ok(unpacked) = std::fs::read_dir(hash.path()) else {
                continue;
            };
            for dir in unpacked.flatten() {
                let settings = dir.path().join("conf").join("settings.xml");
                if settings.is_file() {
                    found.push(settings);
                }
            }
        }
    }
    found.sort();
    found.into_iter().next()
}

/// `conf/settings.xml` of the Maven whose launcher is first on `path`. A
/// package manager's launcher may sit beside a `libexec` that holds the
/// distribution (Homebrew), so that is looked in too.
fn path_settings(path: Option<String>, os: Os) -> Option<PathBuf> {
    let (separator, launcher) = match os {
        Os::Windows => (';', "mvn.cmd"),
        Os::Unix => (':', "mvn"),
    };
    let launcher = path?
        .split(separator)
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(launcher))
        .find(|candidate| candidate.is_file())?;
    let home = std::fs::canonicalize(launcher)
        .ok()?
        .parent()?
        .parent()?
        .to_path_buf();
    [home.join("conf"), home.join("libexec").join("conf")]
        .into_iter()
        .map(|conf| conf.join("settings.xml"))
        .find(|settings| settings.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const ID: &str = "socket-patch-77777777-7777-7777-7777-777777777777";
    const URL: &str = "https://patch.socket.dev/patch-registry/maven/t/u/maven2";

    fn settings(mirrors: &[(&str, &str)]) -> String {
        let mut body = String::from("<settings>\n  <mirrors>\n");
        for (id, of) in mirrors {
            body.push_str(&format!(
                "    <mirror>\n      <id>{id}</id>\n      <mirrorOf>{of}</mirrorOf>\n      \
                 <url>https://nexus.example/repo</url>\n    </mirror>\n"
            ));
        }
        body.push_str("  </mirrors>\n</settings>\n");
        body
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn env(pairs: &[(&str, &Path)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.display().to_string()))
            .collect()
    }

    /// What captures the Socket repository in `sets`, by mirror id.
    fn captured(sets: &[Vec<Mirror>]) -> Option<&str> {
        crate::formats::maven::mirror::capturing(sets, ID, URL).map(|m| m.id.as_str())
    }

    #[test]
    fn mirrors_are_read_as_maven_reads_them() {
        let none = |_: &str| None;
        let raw = "<?xml version=\"1.0\"?>\n<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">\n  \
            <!-- <mirrors><mirror><id>commented</id><mirrorOf>*</mirrorOf></mirror></mirrors> -->\n  \
            <mirrors>\n    <mirror>\n      <id> corp </id>\n      <mirrorOf> * </mirrorOf>\n      \
            <url>https://nexus.example/repo</url>\n      <mirrorOfLayouts>default</mirrorOfLayouts>\n    \
            </mirror>\n    <mirror>\n      <id>no-pattern</id>\n      <url>https://x.example</url>\n    \
            </mirror>\n    <mirror>\n      <id>by-env</id>\n      <mirrorOf>${env.MIRROR_OF}</mirrorOf>\n      \
            <url>https://y.example</url>\n    </mirror>\n  </mirrors>\n  <profiles>\n    <profile>\n      \
            <id>p</id>\n    </profile>\n  </profiles>\n</settings>\n";
        let mirrors = parse_mirrors(raw, "settings.xml", &none);
        let read: Vec<(&str, &str, Option<&str>)> = mirrors
            .iter()
            .map(|m| (m.id.as_str(), m.mirror_of.as_str(), m.layouts.as_deref()))
            .collect();
        assert_eq!(
            read,
            [
                ("corp", "*", Some("default")),
                ("by-env", "${env.MIRROR_OF}", None)
            ]
        );
        let lookup = |name: &str| (name == "env.MIRROR_OF").then(|| "central".to_string());
        let mirrors = parse_mirrors(raw, "settings.xml", &lookup);
        assert_eq!(mirrors[1].mirror_of, "central");
        assert!(mirrors.iter().all(|m| m.source == "settings.xml"));
        for broken in ["", "<settings>", "<project><mirrors/></project>"] {
            assert_eq!(parse_mirrors(broken, "s", &none), Vec::new(), "{broken}");
        }
        // A mirror with no <id> is one Maven accepts, under the id
        // `default`: it takes repositories like any other, and a user's
        // one shadows a global one of that id.
        let anonymous = "<settings><mirrors><mirror><mirrorOf>*</mirrorOf>\
                         <url>https://nexus.example/repo</url></mirror></mirrors></settings>";
        let mirrors = parse_mirrors(anonymous, "settings.xml", &none);
        assert_eq!(mirrors.len(), 1);
        assert_eq!(
            (mirrors[0].id.as_str(), mirrors[0].mirror_of.as_str()),
            ("default", "*")
        );
        assert_eq!(captured(&[mirrors.clone()]), Some("default"));
        let global = parse_mirrors(
            &settings(&[("default", "central"), ("corp", "*")]),
            "global.xml",
            &none,
        );
        let merged = merge(mirrors, global);
        assert_eq!(
            merged.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["default", "corp"]
        );
    }

    #[test]
    fn the_user_settings_are_found_where_maven_finds_them() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = tmp.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        write(&home.join(".m2/settings.xml"), &settings(&[("home", "*")]));
        write(
            &tmp.path().join("ci/settings.xml"),
            &settings(&[("ci", "*")]),
        );
        write(&root.join("conf/team.xml"), &settings(&[("team", "*")]));
        let sets = |env: &BTreeMap<String, String>, config: Option<&str>| {
            settings_mirror_sets(env, Os::current(), None, &root, config)
        };

        // `~/.m2/settings.xml`.
        let base = env(&[("HOME", &home)]);
        assert_eq!(captured(&sets(&base, None)), Some("home"));
        // `-s` in `.mvn/maven.config`, relative to the project, in every
        // spelling; then `MAVEN_ARGS`, which wins.
        for config in [
            "-s\nconf/team.xml\n",
            "-s conf/team.xml\n",
            "--settings=conf/team.xml\n",
            "-B --settings conf/team.xml\n",
        ] {
            assert_eq!(
                captured(&sets(&base, Some(config))),
                Some("team"),
                "{config}"
            );
        }
        let mut args = base.clone();
        args.insert(
            "MAVEN_ARGS".into(),
            format!("-B -s {}", tmp.path().join("ci/settings.xml").display()),
        );
        assert_eq!(
            captured(&sets(&args, Some("-s conf/team.xml\n"))),
            Some("ci")
        );
        // A settings file that is named but missing mirrors nothing, and
        // the default one is then not read either.
        let mut missing = base.clone();
        missing.insert("MAVEN_ARGS".into(), "-s /nonexistent/settings.xml".into());
        assert_eq!(sets(&missing, None), Vec::<Vec<Mirror>>::new());
        // No home at all: nothing to read.
        assert_eq!(sets(&BTreeMap::new(), None), Vec::<Vec<Mirror>>::new());
    }

    /// `.mvn/maven.config` is read both ways a Maven reads it. Maven 3.9
    /// and later take one argument per line, so a settings path may hold
    /// a space; before 3.9 the file is split on whitespace. Measured on
    /// Maven 3.8.9, 3.9.9 and 4.0.0-rc-7. A path the line reading names is
    /// opened whole: read split, it would name no file, the mirror in it
    /// would go unseen, and the pin would be written into a build that
    /// cannot resolve it.
    #[test]
    fn maven_config_is_read_one_argument_per_line_and_split_on_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = tmp.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        write(
            &root.join("my settings/team settings.xml"),
            &settings(&[("spaced", "*")]),
        );
        write(&root.join("conf/team.xml"), &settings(&[("team", "*")]));
        let base = env(&[("HOME", &home)]);
        let sets =
            |config: &str| settings_mirror_sets(&base, Os::current(), None, &root, Some(config));
        // One argument per line: every spelling Maven 3.9+ takes.
        for config in [
            "-s\nmy settings/team settings.xml\n",
            "--settings\nmy settings/team settings.xml\n",
            "--settings=my settings/team settings.xml\n",
            "-smy settings/team settings.xml\n",
            "\"-s\"\n\"my settings/team settings.xml\"\n",
            "-B\n# the team's settings\n  -s  \n  my settings/team settings.xml  \n-o\n",
            // The global settings are named the same way.
            "-gs\nmy settings/team settings.xml\n",
            "--global-settings=my settings/team settings.xml\n",
        ] {
            assert_eq!(captured(&sets(config)), Some("spaced"), "{config:?}");
        }
        // Split on whitespace: what a Maven before 3.9 makes of one line.
        for config in [
            "-B -s conf/team.xml\n",
            "-B --settings conf/team.xml -o\n",
            "-o -gs conf/team.xml\n",
        ] {
            assert_eq!(captured(&sets(config)), Some("team"), "{config:?}");
        }
        // An option that only begins like `-s` names no settings file, and
        // does not stand in for the ones Maven reads.
        write(&home.join(".m2/settings.xml"), &settings(&[("home", "*")]));
        assert_eq!(captured(&sets("-sadp\n-ntp\n")), Some("home"));
        // `-s path` on one line: a Maven that reads one argument per line
        // looks for a file whose name begins with the blank and does not
        // start, so that reading names no settings (and the default ones
        // are not read instead); split on whitespace it names the file.
        assert_eq!(captured(&sets("-s conf/team.xml\n")), Some("team"));
        std::fs::remove_file(root.join("conf/team.xml")).unwrap();
        assert_eq!(captured(&sets("-s conf/team.xml\n")), None);
        // The arguments themselves. With no wrapper nothing says which
        // Maven reads the file, so both readings are weighed where they
        // differ; a wrapper's Maven decides.
        let (line, split) = (
            vec!["-s".to_string(), "my settings/x.xml".to_string()],
            vec![
                "-s".to_string(),
                "my".to_string(),
                "settings/x.xml".to_string(),
            ],
        );
        let spaced = "-s\nmy settings/x.xml\n";
        assert_eq!(config_readings(spaced, None), [split.clone(), line.clone()]);
        assert_eq!(config_readings(spaced, Some((3, 9, 0))), [line.clone()]);
        assert_eq!(config_readings(spaced, Some((4, 0, 0))), [line]);
        assert_eq!(config_readings(spaced, Some((3, 8, 9))), [split]);
        assert_eq!(
            config_readings("-B\n-ntp\n", None),
            [vec!["-B".to_string(), "-ntp".to_string()]]
        );

        // The same through the settings lookup. Under a wrapper that pins
        // a Maven before 3.9 a path with a space names no file (and that
        // Maven does not start); under one that pins 3.9 or later a line
        // of several options names none.
        std::fs::remove_file(home.join(".m2/settings.xml")).unwrap();
        write(&root.join("conf/team.xml"), &settings(&[("team", "*")]));
        let wrapper = |version: &str| {
            write(
                &root.join(".mvn/wrapper/maven-wrapper.properties"),
                &format!(
                    "distributionUrl=https\\://repo.maven.apache.org/maven2/org/apache/maven/\
                     apache-maven/{version}/apache-maven-{version}-bin.zip\n"
                ),
            );
        };
        let spaced = "-s\nmy settings/team settings.xml\n";
        let several = "-B -s conf/team.xml\n";
        wrapper("3.9.9");
        assert_eq!(captured(&sets(spaced)), Some("spaced"));
        assert_eq!(captured(&sets(several)), None);
        wrapper("3.8.9");
        assert_eq!(captured(&sets(spaced)), None);
        assert_eq!(captured(&sets(several)), Some("team"));
    }

    #[test]
    fn the_global_and_project_settings_are_weighed_too() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = tmp.path().join("proj");
        let maven = tmp.path().join("maven");
        std::fs::create_dir_all(&root).unwrap();
        write(
            &maven.join("conf/settings.xml"),
            &settings(&[("corp", "*"), ("blocker", "external:http:*")]),
        );
        let base = env(&[("HOME", &home), ("MAVEN_HOME", &maven)]);
        let sets = |env: &BTreeMap<String, String>, config: Option<&str>| {
            settings_mirror_sets(env, Os::current(), None, &root, config)
        };
        // The installation's settings alone.
        assert_eq!(captured(&sets(&base, None)), Some("corp"));
        // The user's mirror of the same id replaces it.
        write(
            &home.join(".m2/settings.xml"),
            &settings(&[("corp", "central")]),
        );
        assert_eq!(captured(&sets(&base, None)), None);
        // `-gs` names other global settings.
        write(
            &root.join("global.xml"),
            &settings(&[("other", "external:*")]),
        );
        assert_eq!(
            captured(&sets(&base, Some("-gs\nglobal.xml\n"))),
            Some("other")
        );
        // The Maven on PATH is the one that runs, whatever `MAVEN_HOME`
        // says: the launcher takes its home from where it stands.
        let bin = tmp.path().join("dist/bin");
        let launcher = if cfg!(windows) { "mvn.cmd" } else { "mvn" };
        write(&bin.join(launcher), "#!/bin/sh\n");
        write(
            &tmp.path().join("dist/conf/settings.xml"),
            &settings(&[("on-path", "*")]),
        );
        let on_path = env(&[("HOME", &home), ("PATH", &bin)]);
        assert_eq!(captured(&sets(&on_path, None)), Some("on-path"));
        let both = env(&[("HOME", &home), ("PATH", &bin), ("MAVEN_HOME", &maven)]);
        assert_eq!(captured(&sets(&both, None)), Some("on-path"));
        // The wrapper's distribution, once unpacked, is the Maven that runs.
        write(
            &root.join(".mvn/wrapper/maven-wrapper.properties"),
            "distributionUrl=https\\://repo.example/apache-maven-3.9.6-bin.zip\n",
        );
        assert_eq!(captured(&sets(&on_path, None)), Some("on-path"));
        // The wrapper jar's layout: <archive name>/<hash>/<dir>/conf.
        let jar_layout = home.join(
            ".m2/wrapper/dists/apache-maven-3.9.6-bin/abc123/apache-maven-3.9.6/conf/settings.xml",
        );
        write(&jar_layout, &settings(&[("wrapped", "*")]));
        assert_eq!(captured(&sets(&on_path, None)), Some("wrapped"));
        // The script's layout (the default since Maven Wrapper 3.3): the
        // archive name without `-bin`, and the distribution in the hash
        // directory itself.
        std::fs::remove_file(&jar_layout).unwrap();
        assert_eq!(captured(&sets(&on_path, None)), Some("on-path"));
        write(
            &home.join(".m2/wrapper/dists/apache-maven-3.9.6/def456/conf/settings.xml"),
            &settings(&[("only-script", "*")]),
        );
        assert_eq!(captured(&sets(&on_path, None)), Some("only-script"));
        // The properties file is read as Java reads one (`:` separator,
        // a continued line).
        write(
            &root.join(".mvn/wrapper/maven-wrapper.properties"),
            "distributionType=only-script\ndistributionUrl: https\\://repo.example/\\\n  apache-maven-3.9.6-bin.zip\n",
        );
        assert_eq!(captured(&sets(&on_path, None)), Some("only-script"));
        // A settings file the project keeps is a second way to be started.
        let quiet = env(&[("HOME", &home)]);
        std::fs::remove_file(root.join(".mvn/wrapper/maven-wrapper.properties")).unwrap();
        assert_eq!(captured(&sets(&quiet, None)), None);
        write(
            &root.join(".mvn/settings.xml"),
            &settings(&[("project", "*")]),
        );
        assert_eq!(captured(&sets(&quiet, None)), Some("project"));
    }
}
