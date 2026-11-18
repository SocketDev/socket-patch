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
//!   [`CONFIG_ARGS`] switch the filter on (it is off by default on Maven
//!   3.9, on from Maven 4) and move the basedir into the checkout.
//!
//! Measured with real Maven (3.6.3, 3.8.9, 3.9.0 to 3.9.4, 3.9.16,
//! 4.0.0-rc-7): from 3.9.2 on, and on Maven 4, the Socket repository is
//! asked for the pinned version's jar and pom only. Before 3.9 the
//! properties mean nothing, and 3.9.0 / 3.9.1 do not interpolate
//! `${session.rootDirectory}`, so the file is never found; both build as
//! they did, unfiltered.
//!
//! The basedir is one per build, not one per repository: a build that
//! switches the filter on from outside the checkout and keeps its own
//! files in the local repository's default directory stops reading them
//! once these lines are in `.mvn/maven.config`. Hence [`merge_config`]
//! writes nothing over a setting the checkout already holds, and the
//! directory is one only hosted mode uses, so its lines can be told from a
//! user's and taken out again.
//!
//! A file that does not list the pinned version's path FAILS the build
//! (`Prefix … NOT allowed from socket-patch-…`): it is written with the pin
//! it belongs to, from the same coordinates, or not at all.

use super::{maven_config_line_properties, maven_config_properties};

/// The directory, under the project root, that holds the filter files.
pub(crate) const DIR: &str = ".mvn/socket-patch";

macro_rules! filter {
    () => {
        "aether.remoteRepositoryFilter.prefixes"
    };
}
macro_rules! basedir {
    () => {
        "${session.rootDirectory}/.mvn/socket-patch"
    };
}

const SWITCH_KEY: &str = filter!();
const BASEDIR_KEY: &str = concat!(filter!(), ".basedir");

/// The `.mvn/maven.config` lines hosted mode writes, one argument each:
/// the prefixes filter on, reading its files from [`DIR`].
pub(crate) const CONFIG_ARGS: &[&str] = &[
    concat!("-D", filter!(), "=true"),
    concat!("-D", filter!(), ".basedir=", basedir!()),
];

/// The first line of a prefix file Maven 4 accepts.
const MAGIC: &str = "## repository-prefixes/2.0";

/// The filter file of the repository `repository_id`, project-relative.
pub(crate) fn file_rel(repository_id: &str) -> String {
    format!("{DIR}/prefixes-{repository_id}.txt")
}

/// The repository id a file name in [`DIR`] filters (`prefixes-<id>.txt`).
pub(crate) fn repository_of(file_name: &str) -> Option<&str> {
    file_name.strip_prefix("prefixes-")?.strip_suffix(".txt")
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

/// What `.mvn/maven.config` needs for Maven to read the filter files.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Config {
    /// Both lines are there, as hosted mode writes them.
    InPlace,
    /// Neither setting is there: the config with both lines appended.
    Appended(String),
    /// The checkout already configures the filter another way (why).
    Conflict(String),
}

/// `existing` with [`CONFIG_ARGS`] appended, unless the checkout already
/// sets either property.
///
/// A setting found in any spelling some Maven reads, with any other value
/// (or only one of the two), is the user's own filter configuration:
/// moving its basedir would stop Maven reading the files they keep, so
/// nothing is written and the Socket repository stays unfiltered.
///
/// The lines are appended in the file's own shape: a file that ends
/// without a line break still does, so [`strip_config`] gives back its
/// bytes.
pub(crate) fn merge_config(existing: &str) -> Config {
    let lines = maven_config_line_properties(existing);
    let any = maven_config_properties(existing);
    let ours = |key: &str, value: &str| lines.get(key).is_some_and(|v| v == value);
    if ours(SWITCH_KEY, "true") && ours(BASEDIR_KEY, basedir!()) {
        return Config::InPlace;
    }
    for key in [SWITCH_KEY, BASEDIR_KEY] {
        if let Some(value) = any.get(key) {
            return Config::Conflict(format!("-D{key}={value}"));
        }
    }
    let block = CONFIG_ARGS.join("\n");
    Config::Appended(if existing.is_empty() {
        format!("{block}\n")
    } else if existing.ends_with('\n') {
        format!("{existing}{block}\n")
    } else {
        format!("{existing}\n{block}")
    })
}

/// Whether `text` (a `.mvn/jvm.config`, or any other argument list) names
/// one of the two properties: a JVM-level setting of the same filter,
/// which a `maven.config` line would override.
pub(crate) fn mentions_filter(text: &str) -> bool {
    text.contains(SWITCH_KEY)
}

/// `config` without the lines hosted mode wrote ([`CONFIG_ARGS`], each a
/// whole line): `None` when it holds neither. A file whose last line was
/// one of them, with no line break after it, gets back the ending it had
/// before [`merge_config`] appended to it.
pub(crate) fn strip_config(config: &str) -> Option<String> {
    let is_ours = |line: &str| {
        let arg = line.trim_end_matches(['\r', '\n']);
        CONFIG_ARGS.contains(&arg)
    };
    if !config.split_inclusive('\n').any(is_ours) {
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
    use super::*;

    const ID: &str = "socket-patch-77777777-7777-7777-7777-777777777777";

    #[test]
    fn the_file_names_its_repository_and_lists_one_version() {
        let rel = file_rel(ID);
        assert_eq!(
            rel,
            ".mvn/socket-patch/prefixes-socket-patch-77777777-7777-7777-7777-777777777777.txt"
        );
        assert_eq!(repository_of(rel.rsplit('/').next().unwrap()), Some(ID));
        assert_eq!(repository_of("groupId-central.txt"), None);
        let text = file_text(ID, "org.slf4j", "slf4j-api", "1.7.36-socket.77777777");
        let mut lines = text.lines();
        // Maven 4 discards a file whose first line is anything else.
        assert_eq!(lines.next(), Some("## repository-prefixes/2.0"));
        let listed: Vec<&str> = lines.filter(|l| !l.starts_with('#')).collect();
        assert_eq!(listed, ["/org/slf4j/slf4j-api/1.7.36-socket.77777777"]);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn the_lines_are_appended_once_in_the_shape_of_the_file() {
        let block = CONFIG_ARGS.join("\n");
        assert_eq!(merge_config(""), Config::Appended(format!("{block}\n")));
        assert_eq!(
            merge_config("-B\n"),
            Config::Appended(format!("-B\n{block}\n"))
        );
        assert_eq!(merge_config("-B"), Config::Appended(format!("-B\n{block}")));
        for written in [
            format!("{block}\n"),
            format!("-B\n{block}"),
            format!("{}\n-B\n{}\n", CONFIG_ARGS[1], CONFIG_ARGS[0]),
        ] {
            assert_eq!(merge_config(&written), Config::InPlace, "{written}");
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
            assert!(
                matches!(merge_config(theirs), Config::Conflict(_)),
                "{theirs}"
            );
        }
        // Another filter of the resolver is not this one.
        let group = "-Daether.remoteRepositoryFilter.groupId=true\n";
        assert!(matches!(merge_config(group), Config::Appended(_)));
        assert!(mentions_filter(
            "-Xmx2g -Daether.remoteRepositoryFilter.prefixes=true"
        ));
        assert!(!mentions_filter("-Xmx2g"));
    }

    #[test]
    fn stripping_gives_back_the_bytes_the_lines_were_appended_to() {
        for original in [
            "",
            "-B\n",
            "-B",
            "-B\r\n-T1C\r\n",
            "-B\r\n-T1C",
            "# note\n\n-B\n",
        ] {
            let Config::Appended(written) = merge_config(original) else {
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
        let block = CONFIG_ARGS.join("\n");
        assert_eq!(
            strip_config(&format!("-B\n{block}\n-T1C\n")).as_deref(),
            Some("-B\n-T1C\n")
        );
        // A line that only resembles ours is not ours.
        let other = "-Daether.remoteRepositoryFilter.prefixes=true # mine\n";
        assert_eq!(strip_config(other), None);
    }
}
