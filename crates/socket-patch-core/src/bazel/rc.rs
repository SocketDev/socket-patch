//! What the files beside a Bazel workspace say about the Bazel that builds
//! it.

use super::workspace::Entry;

/// A Bazel release as three numbers: `9.3.2` is `(9, 3, 2)`.
pub type Release = (u32, u32, u32);

/// The release the files at the Bazel root name for a launcher, read as
/// bazelisk reads them (v1.30.0: `parseFileConfig` in config/config.go,
/// `GetBazelVersion` in core/core.go): the value of the last
/// `USE_BAZEL_VERSION` line of `.bazeliskrc`, without the blanks around
/// the key and the value, and when there is none or it is empty the first
/// line of `.bazelversion`, as it is written.
///
/// `None` unless that is exactly three numbers (`releasePattern` in
/// versions/versions.go): `latest`, `8.x`, a release candidate, a commit
/// and a fork's `name/7.7.2` name no release that the checkout can tell,
/// and neither does a file that cannot be read. So `None` is no promise
/// of an old Bazel or a new one.
///
/// Not read: `USE_BAZEL_VERSION` in the environment and in the
/// `.bazeliskrc` of the home directory, which bazelisk asks before
/// `.bazelversion`. socket-patch does not run in the environment that a
/// build's bazelisk has. And a Bazel that is started without a launcher
/// reads neither file.
pub fn declared_release(view: &dyn Fn(&str) -> Entry) -> Option<Release> {
    let setting = |line: &str| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "USE_BAZEL_VERSION").then(|| value.trim().to_string())
    };
    let set = match view(".bazeliskrc") {
        Entry::Text(rc) => rc.split('\n').filter_map(setting).next_back(),
        Entry::Absent => None,
        Entry::Unreadable(_) => return None,
    };
    let named = match set.filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => match view(".bazelversion") {
            // The line as Go's `bufio.Scanner` gives it.
            Entry::Text(text) => {
                let line = text.split('\n').next()?;
                line.strip_suffix('\r').unwrap_or(line).to_string()
            }
            _ => return None,
        },
    };
    let number = |part: &str| -> Option<u32> {
        let digits = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        part.parse().ok().filter(|_| digits)
    };
    let numbers: Option<Vec<u32>> = named.split('.').map(number).collect();
    match numbers?[..] {
        [major, minor, patch] => Some((major, minor, patch)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The release of a workspace with the files `files`.
    fn release(files: &[(&str, &str)]) -> Option<Release> {
        declared_release(&|path| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        })
    }

    /// The rows whose text does not give its release, with what `files`
    /// puts around it: every wrong row in one message.
    fn wrong<'a>(
        rows: &[(&'a str, Option<Release>)],
        files: impl Fn(&'a str) -> Vec<(&'a str, &'a str)>,
    ) -> Vec<&'a str> {
        let differs = |row: &&(&'a str, Option<Release>)| release(&files(row.0)) != row.1;
        rows.iter().filter(differs).map(|row| row.0).collect()
    }

    /// `.bazelversion`, as `GetBazelVersion` reads it (bazelisk v1.30.0,
    /// core/core.go): the first line of a `bufio.Scanner` (lines 424 to
    /// 426), which ends at the line feed and drops one carriage return
    /// before it, taken as it is, and passed over when it is empty (line
    /// 431). The forms are those of versions/versions.go.
    #[test]
    fn a_release_is_three_numbers_or_nothing() {
        let rows = [
            ("7.7.2\n", Some((7, 7, 2))),
            ("9.3.2\r\nanything below the first line\n", Some((9, 3, 2))),
            ("10.0.0", Some((10, 0, 0))),
            ("9.3.2\r", Some((9, 3, 2))),
            // No blank is taken off the line: bazelisk asks for a release
            // of that name, and fails.
            ("  9.3.2  \n", None),
            ("9.3.2\t\n", None),
            ("9.3.2\r\r\n", None),
            // An empty first line names nothing, whatever stands below:
            // the fallback, `latest`, is used (lines 436 to 443).
            ("\n9.3.2\n", None),
            ("", None),
            // `releasePattern` alone is one release (versions.go line 20).
            // A track (line 21), a patch (22), a candidate (23), a rolling
            // release (25), `latest` (26), a commit (27), `last_rc`,
            // `last_green` and `rolling` (72 to 83) are none.
            ("8.x\n", None),
            ("8.*\n", None),
            ("7.7.2-patch1\n", None),
            ("7.7.2rc1\n", None),
            ("9.0.0-pre.20250101.1\n", None),
            ("latest\n", None),
            ("latest-1\n", None),
            ("0123456789abcdef0123456789abcdef01234567\n", None),
            ("last_rc\n", None),
            ("last_green\n", None),
            ("rolling\n", None),
            // The release of a fork (`parseBazelForkAndVersion`, core.go
            // lines 457 to 471) is not Bazel's.
            ("a-fork/7.7.2\n", None),
            ("7.7\n", None),
            ("7.7.2.1\n", None),
            ("+7.7.2\n", None),
            ("7..2\n", None),
            ("\u{feff}7.7.2\n", None),
        ];
        assert_eq!(
            wrong(&rows, |named| vec![(".bazelversion", named)]),
            [""; 0]
        );
        assert_eq!(release(&[]), None);
    }

    /// `.bazeliskrc`, as `parseFileConfig` reads it (config/config.go lines
    /// 62 to 73): split at each line feed, then at the first `=` of a
    /// line; the blanks around the key and around the value are dropped;
    /// a later line of a key replaces an earlier one; nothing is unquoted
    /// and no comment ends a value. `USE_BAZEL_VERSION` there outranks
    /// `.bazelversion` (core.go lines 406 to 409), unless it is empty
    /// (`layered.Get`, config.go line 110).
    #[test]
    fn bazeliskrc_is_read_as_bazelisk_reads_it() {
        let rows = [
            ("USE_BAZEL_VERSION=8.8.2\n", Some((8, 8, 2))),
            ("# a launcher's settings\nBAZELISK_BASE_URL=https://mirror.example\nUSE_BAZEL_VERSION=8.8.2", Some((8, 8, 2))),
            // Blanks around the key and the value, and a carriage return.
            (" USE_BAZEL_VERSION = 8.8.2 \r\n", Some((8, 8, 2))),
            ("\tUSE_BAZEL_VERSION\t=\t8.8.2\n", Some((8, 8, 2))),
            // The last line of the key wins.
            ("USE_BAZEL_VERSION=9.3.2\nUSE_BAZEL_VERSION=8.8.2\n", Some((8, 8, 2))),
            ("USE_BAZEL_VERSION=8.8.2\nUSE_BAZEL_VERSION=latest\n", None),
            // A value that is no release names none, and `.bazelversion`
            // is not asked.
            ("USE_BAZEL_VERSION=latest\n", None),
            ("USE_BAZEL_VERSION=8.x\n", None),
            ("USE_BAZEL_VERSION=\"8.8.2\"\n", None),
            ("USE_BAZEL_VERSION=8.8.2 # pinned\n", None),
            ("USE_BAZEL_VERSION=8.8.2=\n", None),
            // An empty value, also as the last of two, leaves it to
            // `.bazelversion`.
            ("USE_BAZEL_VERSION=\n", Some((7, 7, 2))),
            ("USE_BAZEL_VERSION=8.8.2\nUSE_BAZEL_VERSION= \n", Some((7, 7, 2))),
            // Another key: a comment (line 63) and what looks like one,
            // a line without `=`, a shell's `export`, another case.
            ("#USE_BAZEL_VERSION=8.8.2\n", Some((7, 7, 2))),
            (" # USE_BAZEL_VERSION=8.8.2\n", Some((7, 7, 2))),
            ("USE_BAZEL_VERSION 8.8.2\n", Some((7, 7, 2))),
            ("export USE_BAZEL_VERSION=8.8.2\n", Some((7, 7, 2))),
            ("use_bazel_version=8.8.2\n", Some((7, 7, 2))),
            ("BAZELISK_BASE_URL=https://mirror.example/USE_BAZEL_VERSION=8.8.2\n", Some((7, 7, 2))),
            ("", Some((7, 7, 2))),
        ];
        let beside = |rc| vec![(".bazeliskrc", rc), (".bazelversion", "7.7.2\n")];
        assert_eq!(wrong(&rows, beside), [""; 0]);
        // Alone it is enough, and a file that cannot be read may name any
        // release.
        assert_eq!(
            release(&[(".bazeliskrc", "USE_BAZEL_VERSION=9.3.2")]),
            Some((9, 3, 2))
        );
        let unreadable = |path: &str| match path {
            ".bazeliskrc" => Entry::Unreadable("it is not UTF-8".to_string()),
            _ => Entry::Text("7.7.2\n".to_string()),
        };
        assert_eq!(declared_release(&unreadable), None);
    }
}
