//! What the files beside a Bazel workspace say about the Bazel that builds
//! it.

use super::workspace::Entry;

/// A Bazel release as three numbers: `9.3.2` is `(9, 3, 2)`.
pub type Release = (u32, u32, u32);

/// The release the workspace names for a launcher, as bazelisk reads it:
/// `USE_BAZEL_VERSION` in `.bazeliskrc`, else the first line of
/// `.bazelversion`. `None` unless that is exactly three numbers: `latest`,
/// `8.x`, a release candidate and a fork's `name/7.7.2` name no release
/// that the checkout can tell. A variable of the user's shell outranks
/// both files, and a Bazel started without a launcher reads neither.
pub fn declared_release(view: &dyn Fn(&str) -> Entry) -> Option<Release> {
    let text = |path: &str| match view(path) {
        Entry::Text(text) => Some(text),
        _ => None,
    };
    let setting = |line: &str| Some(line.trim().strip_prefix("USE_BAZEL_VERSION=")?.to_string());
    let named = text(".bazeliskrc")
        .and_then(|rc| rc.lines().find_map(setting))
        .or_else(|| Some(text(".bazelversion")?.lines().next()?.to_string()))?;
    let number = |part: &str| -> Option<u32> {
        let digits = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        part.parse().ok().filter(|_| digits)
    };
    let numbers: Option<Vec<u32>> = named.trim().split('.').map(number).collect();
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

    #[test]
    fn a_release_is_three_numbers_or_nothing() {
        for (named, release_of) in [
            ("7.7.2\n", Some((7, 7, 2))),
            (
                "  9.3.2  \nanything below the first line\n",
                Some((9, 3, 2)),
            ),
            ("10.0.0", Some((10, 0, 0))),
            ("8.x\n", None),
            ("latest\n", None),
            ("7.7.2rc1\n", None),
            ("7.7\n", None),
            ("7.7.2.1\n", None),
            ("+7.7.2\n", None),
            ("7..2\n", None),
            ("a-fork/7.7.2\n", None),
            ("", None),
        ] {
            assert_eq!(
                release(&[(".bazelversion", named)]),
                release_of,
                "{named:?}"
            );
        }
        assert_eq!(release(&[]), None);
        // `.bazeliskrc` is asked first, and wins also when it names no
        // release that can be told; without the setting it says nothing.
        let rc = "# a launcher's settings\nBAZELISK_BASE_URL=https://mirror.example\n";
        for (rc, release_of) in [
            (format!("{rc}USE_BAZEL_VERSION=8.8.2\n"), Some((8, 8, 2))),
            (format!("{rc} USE_BAZEL_VERSION=latest \n"), None),
            (rc.to_string(), Some((7, 7, 2))),
        ] {
            let files = [(".bazeliskrc", rc.as_str()), (".bazelversion", "7.7.2\n")];
            assert_eq!(release(&files), release_of, "{rc:?}");
        }
    }
}
