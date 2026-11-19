//! Maven Resolver's remote repository filtering, as hosted mode uses it to
//! keep Maven from asking a Socket repository for anything but the one
//! artifact it serves. Pure: text in, text out. The hosted rewriter and its
//! unwind both judge the files through here.
//!
//! A `<repository>` in a pom is asked, in declaration order and before
//! Maven Central, for every artifact and parent pom the local repository
//! does not hold yet. The resolver's `prefixes` filter restricts one
//! repository to the paths a file lists:
//!
//! * `<basedir>/prefixes-<repository id>.txt`, one path prefix per line,
//!   `#` comments. Maven 4 (Resolver 2) reads a file only when its first
//!   line is [`MAGIC`]; Maven 3.9 (Resolver 1.9) takes that line for a
//!   comment.
//! * A repository with no file is not filtered, on every Maven: the filter
//!   abstains. So a file named for a Socket repository restricts that
//!   repository and no other.
//! * `<basedir>` defaults to a directory in the local repository. The two
//!   lines of [`config_args`] switch the filter on (it is off by default on
//!   Maven 3.9, on from Maven 4) and move the basedir into the checkout.
//!
//! The basedir line has to name the checkout through a property, and no
//! property is right on every Maven ([`RootDirectory`], where the
//! measurements are). So the line takes the property the Trusted Checksums
//! directory takes, by the same rule ([`RootDirectory::for_maven`]): the
//! launcher's, which breaks no build, unless the project declares Maven 4.
//!
//! Measured with real Maven (3.6.3, 3.8.9, 3.9.0 to 3.9.4, 3.9.16,
//! 4.0.0-rc-7): from 3.9.2 on the Socket repository is asked for the
//! pinned version's jar and pom only, wherever the build is started
//! (`-f <project>/pom.xml` from outside the project included). Before 3.9
//! the properties mean nothing, and 3.9.0 / 3.9.1 interpolate neither
//! root-directory property, so the file is never found; both build as they
//! did, unfiltered. So does Maven 4 under the launcher's property, which it
//! does not interpolate: it filters under the session's.
//!
//! The basedir is one per build, not one per repository: a build that
//! switches the filter on from outside the checkout and keeps its own
//! files in the local repository's default directory stops reading them
//! once these lines are in `.mvn/maven.config`. Hence [`merge_config`]
//! writes nothing over a setting the checkout already holds, and the
//! directory is one only hosted mode uses, so its lines can be told from a
//! user's, respelled ([`heal_basedir`]) and taken out again.
//!
//! A file that does not list the pinned version's path FAILS the build
//! (`Prefix … NOT allowed from socket-patch-…`): it is written with the pin
//! it belongs to, from the same coordinates, or not at all.

use super::declared_maven::{launcher_root, session_root, DeclaredMaven, Reads, RootDirectory};
use super::{maven_config_line_properties, maven_config_properties};

// The directory, under the project's root directory, as a literal: the
// path and the two spellings of the line that names it cannot drift apart.
macro_rules! dir {
    () => {
        ".mvn/socket-patch"
    };
}
macro_rules! filter {
    () => {
        "aether.remoteRepositoryFilter.prefixes"
    };
}
// The two lines, with the project's root directory named through the
// property `$root` expands to: one definition for both spellings.
macro_rules! config_args {
    ($root:ident) => {
        &[
            concat!("-D", filter!(), "=true"),
            concat!("-D", filter!(), ".basedir=", $root!(), "/", dir!()),
        ]
    };
}

/// The directory, under the project root, that holds the filter files.
pub(crate) const DIR: &str = dir!();

const SWITCH_KEY: &str = filter!();
pub(crate) const BASEDIR_KEY: &str = concat!(filter!(), ".basedir");

/// Where the directory line stands among the two.
const BASEDIR_AT: usize = 1;

/// The first Maven release that reads the filter files from the checkout:
/// 3.9.0 and 3.9.1 interpolate neither root-directory property, and older
/// lines have no such filter.
const MIN_MAVEN: [u32; 3] = [3, 9, 2];

const FORMS: [RootDirectory; 2] = [RootDirectory::Launcher, RootDirectory::Session];

/// The directory setting's value under `form`.
pub(crate) const fn basedir_value(form: RootDirectory) -> &'static str {
    match form {
        RootDirectory::Launcher => concat!(launcher_root!(), "/", dir!()),
        RootDirectory::Session => concat!(session_root!(), "/", dir!()),
    }
}

/// The form whose value is `value`.
fn basedir_of_value(value: &str) -> Option<RootDirectory> {
    FORMS.into_iter().find(|form| basedir_value(*form) == value)
}

/// The `.mvn/maven.config` lines hosted mode writes for a project whose
/// form is `form`, one argument each: the prefixes filter on, reading its
/// files from [`DIR`].
pub(crate) fn config_args(form: RootDirectory) -> &'static [&'static str] {
    match form {
        RootDirectory::Launcher => config_args!(launcher_root),
        RootDirectory::Session => config_args!(session_root),
    }
}

/// The first line of a prefix file Maven 4 accepts.
const MAGIC: &str = "## repository-prefixes/2.0";

/// The filter file of the repository `repository_id`, project-relative.
pub(crate) fn file_rel(repository_id: &str) -> String {
    format!("{DIR}/prefixes-{repository_id}.txt")
}

/// The Socket repository id whose filter the file `file_name` of [`DIR`]
/// is, when the name is one hosted mode writes:
/// `prefixes-socket-patch-<canonical uuid>.txt`. Any other name (a file of
/// the user's, another filter's) is none of hosted mode's.
pub(crate) fn owned(file_name: &str) -> Option<&str> {
    let id = file_name.strip_prefix("prefixes-")?.strip_suffix(".txt")?;
    crate::patch::redirect::generation::pin_name_uuid(id, false).map(|_| id)
}

/// The Socket repository id whose filter the project-relative path `rel`
/// is: a file of [`DIR`] under a name hosted mode writes ([`owned`]).
pub(crate) fn owned_rel(rel: &str) -> Option<&str> {
    rel.strip_prefix(DIR)?.strip_prefix('/').and_then(owned)
}

/// The path prefix of one version of an artifact, as the maven2 layout
/// spells it: `/<group/path>/<artifact>/<version>`.
pub(crate) fn prefix(group_id: &str, artifact_id: &str, version: &str) -> String {
    format!(
        "/{}",
        crate::vendor::jvm::layout::version_dir(group_id, artifact_id, version)
    )
}

/// The filter file that restricts `repository_id` to one version of one
/// artifact. Call only with coordinates that passed
/// [`crate::vendor::jvm::layout::safe_coordinates`].
pub(crate) fn file_text(
    repository_id: &str,
    group_id: &str,
    artifact_id: &str,
    version: &str,
) -> String {
    format!(
        "{MAGIC}\n# Written by socket-patch: Maven asks the {repository_id} repository for this \
         path only.\n{}\n",
        prefix(group_id, artifact_id, version)
    )
}

/// Whether the filter file `text` lets its repository serve `prefix` on
/// every Maven that reads such a file: its first line is the header Maven 4
/// requires, and one of its lines is the path. Read as Maven reads it, line
/// by line with the line ending off, so a file checked out with CRLF line
/// endings, or one someone added a comment or another path to, says the
/// same as the bytes hosted mode wrote.
pub(crate) fn lists(text: &str, prefix: &str) -> bool {
    let mut lines = text.lines();
    lines.next() == Some(MAGIC) && lines.any(|line| line == prefix)
}

/// What `.mvn/maven.config` needs for Maven to read the filter files.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Config {
    /// Both settings are there, on and naming [`DIR`], in either spelling
    /// of the directory ([`form`]).
    InPlace,
    /// Neither setting is there: the config with both lines appended.
    Appended(String),
    /// The checkout already configures the filter another way (why).
    Conflict(String),
}

/// The spelling of the directory under which `config` makes Maven read the
/// filter files of [`DIR`]: the filter on and its basedir that directory,
/// as Maven 3.9 and later read the file (one argument per line). `None`
/// when the config does not.
pub(crate) fn form(config: &str) -> Option<RootDirectory> {
    let lines = maven_config_line_properties(config);
    lines.get(SWITCH_KEY).filter(|on| *on == "true")?;
    lines.get(BASEDIR_KEY).and_then(|dir| basedir_of_value(dir))
}

/// What the Maven the project declares (`maven`) makes of the filter as
/// `config` sets it: whether a Socket repository is filtered there. `None`
/// when the config does not point Maven at [`DIR`] at all ([`form`]).
pub(crate) fn read_by(config: &str, maven: &DeclaredMaven) -> Option<Reads> {
    form(config).map(|form| form.read_by(maven, MIN_MAVEN))
}

/// `existing` with the two lines of `form` appended, unless the checkout
/// already sets either property.
///
/// The two settings in place, naming [`DIR`] in either spelling, are
/// hosted mode's own and no conflict: both spellings name the same
/// directory (what the project's Maven makes of the one in place is
/// [`read_by`]'s to say). A setting found in any spelling some Maven
/// reads, with any other value (or only one of the two), is the user's own
/// filter configuration: moving its basedir would stop Maven reading the
/// files they keep, so nothing is written and the Socket repository stays
/// unfiltered.
///
/// The lines are appended in the file's own shape: a file that ends
/// without a line break still does, so [`strip_config`] gives back its
/// bytes.
pub(crate) fn merge_config(existing: &str, form: RootDirectory) -> Config {
    if self::form(existing).is_some() {
        return Config::InPlace;
    }
    let any = maven_config_properties(existing);
    for key in [SWITCH_KEY, BASEDIR_KEY] {
        if let Some(value) = any.get(key) {
            return Config::Conflict(format!("-D{key}={value}"));
        }
    }
    Config::Appended(super::append_config_args(existing, config_args(form), true))
}

/// Whether `text` (a `.mvn/jvm.config`, or any other argument list) names
/// one of the two properties: a JVM-level setting of the same filter,
/// which a `maven.config` line would override.
pub(crate) fn mentions_filter(text: &str) -> bool {
    text.contains(SWITCH_KEY)
}

/// A line of a config without its line ending: the argument it holds.
fn arg(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

/// `config` with the directory line spelled as `form`, wherever it stands
/// in the other spelling: that line is rewritten in place, every other
/// byte kept. `None` when there is nothing to change.
///
/// The line is hosted mode's wherever it stands, with or without the
/// switch beside it: it names [`DIR`], which nothing else uses. (The
/// Trusted Checksums directory is one Maven's own documentation names, so
/// only the whole block is respelled there:
/// [`super::trusted_checksums::heal_basedir`].)
///
/// This is how a project whose line names the directory through
/// `${session.rootDirectory}`, which stops Maven 3.9.2 to 3.9.8 from
/// starting with `-f` from outside the project, is healed; and how a
/// project that has since declared Maven 4 gets the spelling Maven 4
/// reads.
pub(crate) fn heal_basedir(config: &str, form: RootDirectory) -> Option<String> {
    let written = config_args(form.other())[BASEDIR_AT];
    // The cheap test first: almost no config holds the other spelling.
    if !config.contains(written) {
        return None;
    }
    let mut healed = false;
    let mut out = String::with_capacity(config.len() + 32);
    for line in config.split_inclusive('\n') {
        let body = arg(line);
        if body == written {
            healed = true;
            out.push_str(config_args(form)[BASEDIR_AT]);
            out.push_str(&line[body.len()..]);
        } else {
            out.push_str(line);
        }
    }
    healed.then_some(out)
}

/// Whether `config` holds the directory line hosted mode writes, in either
/// spelling: whether some project is healed out of it ([`heal_basedir`]).
/// A substring test for nearly every config, so a caller asks this before
/// it reads anything else to find out which spelling the project takes.
pub(crate) fn holds_written_line(config: &str) -> bool {
    FORMS
        .into_iter()
        .any(|form| heal_basedir(config, form).is_some())
}

/// `config` without the lines hosted mode wrote ([`config_args`] in either
/// spelling, each a whole line): `None` when they are not there. A file
/// whose last line was one of them, with no line break after it, gets back
/// the ending it had before [`merge_config`] appended to it.
///
/// What marks the pair as hosted mode's is the directory line: it names
/// [`DIR`], which nothing else uses. The switch on its own
/// (`…prefixes=true`) is a line anyone may have written, and
/// [`merge_config`] never adds it to a config that holds it: without the
/// directory line beside it, it is the user's and is left alone.
pub(crate) fn strip_config(config: &str) -> Option<String> {
    let names_dir = |line: &str| {
        FORMS
            .into_iter()
            .any(|form| arg(line) == config_args(form)[BASEDIR_AT])
    };
    // (The switch is spelled alike under both forms.)
    let is_ours = |line: &str| names_dir(line) || arg(line) == config_args!(launcher_root)[0];
    if !config.split_inclusive('\n').any(names_dir) {
        return None;
    }
    let ended_on_ours = config
        .split_inclusive('\n')
        .next_back()
        .is_some_and(|last| !last.ends_with('\n') && is_ours(last));
    let mut rest: String = config
        .split_inclusive('\n')
        .filter(|line| !is_ours(line))
        .collect();
    if ended_on_ours && rest.ends_with('\n') {
        rest.pop();
        if rest.ends_with('\r') {
            rest.pop();
        }
    }
    Some(rest)
}

#[cfg(test)]
mod tests {
    use super::RootDirectory::{Launcher, Session};
    use super::*;

    const ID: &str = "socket-patch-77777777-7777-7777-7777-777777777777";

    /// The two lines under `form`, as one block.
    fn block(form: RootDirectory) -> String {
        config_args(form).join("\n")
    }

    fn wrapper(version: &str) -> String {
        format!(
            "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/\
             {version}/apache-maven-{version}-bin.zip\n"
        )
    }

    #[test]
    fn the_file_names_its_repository_and_lists_one_version() {
        let rel = file_rel(ID);
        assert_eq!(
            rel,
            ".mvn/socket-patch/prefixes-socket-patch-77777777-7777-7777-7777-777777777777.txt"
        );
        assert_eq!(owned(rel.rsplit('/').next().unwrap()), Some(ID));
        // Only the names hosted mode writes are its own.
        for theirs in [
            "groupId-central.txt",
            "prefixes-central.txt",
            "prefixes-socket-patch-not-a-uuid.txt",
            "prefixes-socket-patch-77777777-7777-7777-7777-777777777777.txt.bak",
        ] {
            assert_eq!(owned(theirs), None, "{theirs}");
        }
        assert_eq!(owned_rel(&rel), Some(ID));
        for theirs in [
            ".mvn/socket-patch/prefixes-central.txt",
            ".mvn/socket-patchy/prefixes-socket-patch-77777777-7777-7777-7777-777777777777.txt",
            "prefixes-socket-patch-77777777-7777-7777-7777-777777777777.txt",
            ".mvn/socket-patch",
        ] {
            assert_eq!(owned_rel(theirs), None, "{theirs}");
        }
        let text = file_text(ID, "org.slf4j", "slf4j-api", "1.7.36-socket.77777777");
        let mut lines = text.lines();
        // Maven 4 discards a file whose first line is anything else.
        assert_eq!(lines.next(), Some("## repository-prefixes/2.0"));
        let listed: Vec<&str> = lines.filter(|l| !l.starts_with('#')).collect();
        assert_eq!(listed, ["/org/slf4j/slf4j-api/1.7.36-socket.77777777"]);
        assert!(text.ends_with('\n'));
    }

    /// A file is judged by what Maven reads in it, not by its bytes: the
    /// header first, and the pinned path on a line of its own.
    #[test]
    fn a_file_lists_a_path_whatever_its_line_endings_and_comments() {
        let path = "/org/slf4j/slf4j-api/1.7.36-socket.77777777";
        let written = file_text(ID, "org.slf4j", "slf4j-api", "1.7.36-socket.77777777");
        assert!(lists(&written, path));
        for same in [
            written.replace('\n', "\r\n"),
            written.trim_end().to_string(),
            format!("{written}# kept for the audit\n"),
            format!("{written}/com/example/other/1.0\n"),
            format!("## repository-prefixes/2.0\n\n{path}\n"),
        ] {
            assert!(lists(&same, path), "{same:?}");
        }
        for other in [
            String::new(),
            // No header: Maven 4 discards the file.
            format!("{path}\n"),
            format!("# mine\n{written}"),
            // Another version, a longer path, the path commented out.
            written.replace("77777777", "88888888"),
            written.replace(path, &format!("{path}/extra")),
            written.replace(path, &format!("# {path}")),
            written.replace(path, &format!("{path} ")),
        ] {
            assert!(!lists(&other, path), "{other:?}");
        }
    }

    /// The directory is named through the property the project's Maven
    /// reads, the one rule the Trusted Checksums directory follows.
    #[test]
    fn the_directory_line_takes_the_projects_root_directory_property() {
        assert_eq!(
            config_args(Launcher),
            [
                "-Daether.remoteRepositoryFilter.prefixes=true",
                "-Daether.remoteRepositoryFilter.prefixes.basedir=\
                 ${maven.multiModuleProjectDirectory}/.mvn/socket-patch",
            ]
        );
        assert_eq!(
            config_args(Session),
            [
                "-Daether.remoteRepositoryFilter.prefixes=true",
                "-Daether.remoteRepositoryFilter.prefixes.basedir=\
                 ${session.rootDirectory}/.mvn/socket-patch",
            ]
        );
        for form in FORMS {
            let value = basedir_value(form);
            assert_eq!(value, format!("{}/{DIR}", form.property()));
            assert_eq!(basedir_of_value(value), Some(form));
            assert!(config_args(form)[BASEDIR_AT].ends_with(value));
            // The form a project takes is the one its checksums take.
            assert_eq!(self::form(&block(form)), Some(form));
        }
        assert_eq!(basedir_of_value("${session.rootDirectory}/.mvn/rrf"), None);
    }

    #[test]
    fn the_lines_are_appended_once_in_the_shape_of_the_file() {
        for form in FORMS {
            let block = block(form);
            assert_eq!(
                merge_config("", form),
                Config::Appended(format!("{block}\n"))
            );
            assert_eq!(
                merge_config("-B\n", form),
                Config::Appended(format!("-B\n{block}\n"))
            );
            assert_eq!(
                merge_config("-B", form),
                Config::Appended(format!("-B\n{block}"))
            );
            let [switch, dir] = config_args(form) else {
                panic!("two lines");
            };
            for written in [
                format!("{block}\n"),
                format!("-B\n{block}"),
                format!("{dir}\n-B\n{switch}\n"),
            ] {
                // In place whichever spelling this project would write:
                // both name the one directory.
                for wanted in FORMS {
                    assert_eq!(merge_config(&written, wanted), Config::InPlace, "{written}");
                }
            }
        }
    }

    #[test]
    fn a_filter_the_checkout_configures_is_never_written_over() {
        for theirs in [
            // Switched on with the files left in the local repository.
            "-Daether.remoteRepositoryFilter.prefixes=true\n",
            // Another directory, the one Maven's own documentation names.
            "-Daether.remoteRepositoryFilter.prefixes=true\n\
             -Daether.remoteRepositoryFilter.prefixes.basedir=${session.rootDirectory}/.mvn/rrf\n",
            // Switched off.
            "-Daether.remoteRepositoryFilter.prefixes=false\n",
            // Only the directory.
            "-Daether.remoteRepositoryFilter.prefixes.basedir=/srv/filters\n",
            // The spelling Maven before 3.9 reads.
            "-B -Daether.remoteRepositoryFilter.prefixes=true\n",
            "--define aether.remoteRepositoryFilter.prefixes=true\n",
        ] {
            for form in FORMS {
                assert!(
                    matches!(merge_config(theirs, form), Config::Conflict(_)),
                    "{theirs}"
                );
            }
            assert_eq!(self::form(theirs), None, "{theirs}");
            assert!(!holds_written_line(theirs), "{theirs}");
        }
        // Another filter of the resolver is not this one.
        let group = "-Daether.remoteRepositoryFilter.groupId=true\n";
        assert!(matches!(merge_config(group, Launcher), Config::Appended(_)));
        assert!(mentions_filter(
            "-Xmx2g -Daether.remoteRepositoryFilter.prefixes=true"
        ));
        assert!(!mentions_filter("-Xmx2g"));
    }

    /// A line written under the other property is respelled in place, and
    /// nothing else in the file moves.
    #[test]
    fn the_directory_line_is_healed_in_place_to_the_projects_form() {
        for form in FORMS {
            let other = form.other();
            for (before, after) in [
                (format!("{}\n", block(other)), format!("{}\n", block(form))),
                // No final line break, CRLF, lines around it.
                (
                    format!("-B\r\n{}", block(other).replace('\n', "\r\n")),
                    format!("-B\r\n{}", block(form).replace('\n', "\r\n")),
                ),
                (
                    format!("# mine\n{}\n-T1C\n", block(other)),
                    format!("# mine\n{}\n-T1C\n", block(form)),
                ),
                // The line alone (its switch since removed): the property
                // it names is what stops a Maven from starting.
                (
                    format!("-B\n{}\n", config_args(other)[BASEDIR_AT]),
                    format!("-B\n{}\n", config_args(form)[BASEDIR_AT]),
                ),
            ] {
                assert_eq!(heal_basedir(&before, form).as_deref(), Some(after.as_str()));
                assert!(holds_written_line(&before) && holds_written_line(&after));
                // Healed once: the result is this form's own.
                assert_eq!(heal_basedir(&after, form), None, "{after:?}");
                assert_eq!(heal_basedir(&before, other), None, "{before:?}");
            }
        }
        // A line that is not the one hosted mode writes stays as written:
        // another directory, another spelling of the argument, a comment.
        for theirs in [
            "-Daether.remoteRepositoryFilter.prefixes.basedir=${session.rootDirectory}/.mvn/rrf\n"
                .to_string(),
            format!("  {}\n", config_args(Session)[BASEDIR_AT]),
            format!("# {}\n", config_args(Session)[BASEDIR_AT]),
            format!("-B {}\n", config_args(Session)[BASEDIR_AT]),
            String::new(),
        ] {
            assert_eq!(heal_basedir(&theirs, Launcher), None, "{theirs:?}");
            assert!(!holds_written_line(&theirs), "{theirs:?}");
        }
    }

    /// Whether a Socket repository is filtered is judged for the Maven the
    /// project declares, by the rule the Trusted Checksums pin is judged
    /// by, with this filter's own first release.
    #[test]
    fn the_filter_is_judged_for_the_maven_the_project_declares() {
        let declares = |wrapper: Option<String>| DeclaredMaven::of(wrapper.as_deref(), None);
        let none = declares(None);
        let maven_4 = declares(Some(wrapper("4.0.0-rc-7")));
        let reads = |form, maven: &DeclaredMaven| read_by(&format!("{}\n", block(form)), maven);
        // No Maven declared: the launcher's form filters on Maven 3 only.
        assert_eq!(reads(Launcher, &none), Some(Reads::Maven3Only));
        assert_eq!(reads(Session, &none), Some(Reads::Read));
        // The first release that finds the directory is 3.9.2.
        for (version, read) in [("3.8.9", false), ("3.9.1", false), ("3.9.2", true)] {
            let maven = declares(Some(wrapper(version)));
            let expected = if read {
                Reads::Read
            } else {
                Reads::TooOld(version.to_string())
            };
            assert_eq!(reads(Launcher, &maven), Some(expected), "{version}");
        }
        // Maven 4 reads the session's property only.
        assert_eq!(reads(Launcher, &maven_4), Some(Reads::UnreadByMaven4));
        assert_eq!(reads(Session, &maven_4), Some(Reads::Read));
        // A config that does not point Maven at the directory says nothing.
        for config in [
            "",
            "-Daether.remoteRepositoryFilter.prefixes=true\n",
            "-Daether.remoteRepositoryFilter.prefixes=false\n\
             -Daether.remoteRepositoryFilter.prefixes.basedir=\
             ${session.rootDirectory}/.mvn/socket-patch\n",
        ] {
            assert_eq!(read_by(config, &maven_4), None, "{config}");
        }
    }

    #[test]
    fn stripping_gives_back_the_bytes_the_lines_were_appended_to() {
        for form in FORMS {
            for original in [
                "",
                "-B\n",
                "-B",
                "-B\r\n-T1C\r\n",
                "-B\r\n-T1C",
                "# note\n\n-B\n",
            ] {
                let Config::Appended(written) = merge_config(original, form) else {
                    panic!("{original:?} takes the lines");
                };
                assert_eq!(
                    strip_config(&written).as_deref(),
                    Some(original),
                    "{original:?}"
                );
                assert_eq!(strip_config(original), None, "{original:?}");
            }
            // Lines the user added after ours stay, in place.
            let block = block(form);
            assert_eq!(
                strip_config(&format!("-B\n{block}\n-T1C\n")).as_deref(),
                Some("-B\n-T1C\n")
            );
            // The directory line alone (its switch since removed) still
            // goes.
            assert_eq!(
                strip_config(&format!("-B\n{}\n", config_args(form)[BASEDIR_AT])).as_deref(),
                Some("-B\n")
            );
        }
        // A line that only resembles ours is not ours.
        let other = "-Daether.remoteRepositoryFilter.prefixes=true # mine\n";
        assert_eq!(strip_config(other), None);
        // The switch alone is the user's own (hosted mode writes it only
        // together with its directory, and never into a config that holds
        // it): a rollback must not take it.
        let theirs = format!("-B\n{}\n", config_args(Launcher)[0]);
        assert!(matches!(
            merge_config(&theirs, Launcher),
            Config::Conflict(_)
        ));
        assert_eq!(strip_config(&theirs), None);
    }
}
