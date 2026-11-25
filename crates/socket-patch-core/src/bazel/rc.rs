//! What the files beside a Bazel workspace say about the Bazel that builds
//! it.

use std::path::Path;

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

/// Whether the Bazel that builds the checkout may read a `WORKSPACE` file
/// ([`super::workspace::Workspace::legacy`]). Bazel 7 reads one beside
/// `MODULE.bazel`, Bazel 8 when it is told to, and Bazel 9 and later
/// never. So it does not where the checkout names a release of 9 or later
/// ([`declared_release`]), and it may where the checkout names an older
/// one or none: `latest`, a release candidate and a missing file name no
/// release.
pub fn reads_workspace_file(view: &dyn Fn(&str) -> Entry) -> bool {
    declared_release(view).is_none_or(|release| release < (9, 0, 0))
}

/// What `MODULE.bazel.lock` says of the Bazel that wrote it and of the
/// modules it selected. Bazel writes the file at a build, so a checkout
/// that was built has it whether it is committed or not.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ModuleLock {
    /// 11 from Bazel 7.2.0 to 7.4.1 and 13 from 7.5.0 (read in Bazel's
    /// source); 13 on 7.7.2 and 28 on 8.8.2 and 9.3.2 (measured).
    #[serde(rename = "lockFileVersion")]
    pub version: Option<u64>,
    /// The registry files the resolution read, by URL.
    #[serde(default, rename = "registryFileHashes")]
    files: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
}

impl ModuleLock {
    /// The lock `text`, or an empty one when it is no JSON of this shape.
    pub fn parse(text: &str) -> ModuleLock {
        serde_json::from_str(text).unwrap_or_default()
    }

    /// The releases of `module` whose `source.json` the resolution read.
    /// Bazel reads that file for the release it selects and for no other,
    /// and the `MODULE.bazel` of every release it considers (measured on
    /// 7.4.0, 7.7.2, 8.8.2 and 9.3.2). None for a module that an override
    /// takes from somewhere else than a registry.
    pub fn selected(&self, module: &str) -> Vec<&str> {
        fn release<'a>(url: &'a str, of: &str) -> Option<&'a str> {
            let (_, rest) = url.split_once(of)?;
            let release = rest.strip_suffix("/source.json")?;
            (!release.contains('/')).then_some(release)
        }
        let of = format!("/modules/{module}/");
        let urls = self.files.keys();
        urls.filter_map(|url| release(url, &of)).collect()
    }
}

/// How many rc files of one workspace are read.
const MAX_RC_FILES: usize = 32;

/// The words of one line of an rc file, as Bazel's `Tokenize` splits it
/// (src/main/cpp/util/strings.cc lines 181 to 242, the same text at 7.4.0,
/// 7.7.2, 8.8.2 and 9.3.2): at a blank outside quotes, without the quotes,
/// with the character after a `\` as it is, and up to a `#` outside
/// quotes. `None` for a line whose reading Bazel's source calls an
/// oversight ("silently ignores dangling backslash escapes and missing
/// end-quotes"): a quote that is never closed, and a `\` with nothing
/// after it.
fn words(line: &str) -> Option<Vec<String>> {
    let (mut words, mut word, mut quote) = (Vec::new(), String::new(), None);
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => word.push(chars.next()?),
            _ if quote == Some(c) => quote = None,
            _ if quote.is_some() => word.push(c),
            '#' => break,
            '\'' | '"' => quote = Some(c),
            // `strchr` also finds the NUL that ends its list of blanks.
            ' ' | '\t' | '\r' | '\n' | '\0' => {
                words.extend((!word.is_empty()).then(|| std::mem::take(&mut word)));
            }
            _ => word.push(c),
        }
    }
    words.extend((!word.is_empty()).then_some(word));
    quote.is_none().then_some(words)
}

/// Where the rc files of the checkout give an option that names one of
/// `flags`: the file, the line, and the option as Bazel reads it
/// (`--noenable_bzlmod`, `--vendor_dir=third_party`). The files are
/// `.bazelrc` at the Bazel root and what it imports, up to
/// [`MAX_RC_FILES`], read as Bazel's `RcFile::ParseFile` reads one
/// (src/main/cpp/rc_file.cc at 7.4.0, 7.7.2, 8.8.2 and 9.3.2): a `\` before
/// a line break joins two lines (one that ends the file goes, as Bazel
/// passes over it), each line loses the blanks around it and is split
/// into [`words`], the first word is the command, and every other word is
/// an option. The commands `import` and `try-import` take the file
/// their second word names, and `try-import-if-bazel-version` (8.7.0 and
/// later) the one after its condition, which is not evaluated here. A path
/// under `%workspace%/` is the workspace's, and any other path that is not
/// absolute is one Bazel opens from where it runs: it is read from the
/// Bazel root. An rc file that is there and cannot be read, a line that
/// [`words`] does not read, and one file more than the bound are an error:
/// the path, with the line.
///
/// Not seen: the rc files of the machine and of the home directory, an
/// import of an absolute path, and the command line.
pub fn mentions(
    view: &dyn Fn(&str) -> Entry,
    flags: &[&str],
) -> Result<Vec<(String, usize, String)>, String> {
    let (mut todo, mut read) = (vec![".bazelrc".to_string()], Vec::new());
    let mut found = Vec::new();
    while let Some(file) = todo.pop() {
        if read.contains(&file) {
            continue;
        }
        if read.len() == MAX_RC_FILES {
            return Err(file);
        }
        let text = match view(&file) {
            Entry::Text(text) => text,
            Entry::Absent => continue,
            Entry::Unreadable(_) => return Err(file),
        };
        // Each line with the number of its first line in the file. A line
        // that ends in `\` goes on in the next one.
        let (mut lines, mut open) = (Vec::<(usize, String)>::new(), false);
        for (at, line) in text.split('\n').enumerate() {
            let more = line.strip_suffix("\\\r").or(line.strip_suffix('\\'));
            match lines.last_mut().filter(|_| open) {
                Some((_, whole)) => whole.push_str(more.unwrap_or(line)),
                None => lines.push((at + 1, more.unwrap_or(line).to_string())),
            }
            open = more.is_some();
        }
        for (at, line) in lines {
            let blank = ['\t', '\n', '\x0b', '\x0c', '\r', ' '];
            let Some(words) = words(line.trim_matches(blank)) else {
                return Err(format!("{file}:{at}"));
            };
            let mut words = words.into_iter();
            match words.next().as_deref() {
                Some(import @ ("import" | "try-import" | "try-import-if-bazel-version")) => {
                    let Some(path) = words.nth(usize::from(import.ends_with("version"))) else {
                        continue;
                    };
                    let inside = path.strip_prefix("%workspace%/");
                    let path = inside.map_or(&*path, |path| path.trim_start_matches('/'));
                    todo.extend((!Path::new(path).has_root()).then(|| path.to_string()));
                }
                _ => {
                    let names = |word: &String| flags.iter().any(|flag| word.contains(flag));
                    found.extend(words.filter(names).map(|word| (file.clone(), at, word)));
                }
            }
        }
        read.push(file);
    }
    Ok(found)
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

    /// A `WORKSPACE` file may be read unless the checkout names a Bazel of
    /// 9 or later: one that names an older release, none, or something
    /// that is no release may be built by a Bazel that reads it.
    #[test]
    fn a_workspace_file_may_be_read_unless_bazel_9_or_later_is_named() {
        let reads = |files: &[(&str, &str)]| {
            reads_workspace_file(&|path| match files.iter().find(|(name, _)| *name == path) {
                Some((_, text)) => Entry::Text(text.to_string()),
                None => Entry::Absent,
            })
        };
        for named in ["9.0.0", "9.3.2\n", "10.0.0\n"] {
            assert!(!reads(&[(".bazelversion", named)]), "{named:?}");
        }
        let unnamed = ["8.8.2\n", "7.7.2\n", "", "latest\n", "9.x\n", "9.3.2rc1\n"];
        for named in unnamed {
            assert!(reads(&[(".bazelversion", named)]), "{named:?}");
        }
        assert!(reads(&[]));
        // `.bazeliskrc` outranks `.bazelversion`, as for a launcher.
        let rc = (".bazeliskrc", "USE_BAZEL_VERSION=9.3.2\n");
        assert!(!reads(&[rc, (".bazelversion", "7.7.2\n")]));
        let rc = (".bazeliskrc", "USE_BAZEL_VERSION=7.7.2\n");
        assert!(reads(&[rc, (".bazelversion", "9.3.2\n")]));
    }

    /// The view of the files `files`, where a file whose text is `\0`
    /// cannot be read.
    fn view<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Entry + 'a {
        move |path| match files.iter().find(|(name, _)| *name == path) {
            Some((_, "\0")) => Entry::Unreadable("it is not UTF-8".to_string()),
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        }
    }

    /// The lock Bazel 9.3.2 wrote for a workspace that asks for
    /// rules_jvm_external 6.5 beside a module that needs 6.7, cut down to
    /// the files of that ruleset and one of another: the `MODULE.bazel` of
    /// each release the resolution looked at, and the `source.json` of the
    /// one it selected.
    #[test]
    fn a_module_lock_names_the_release_bazel_selected() {
        let bcr = "https://bcr.bazel.build/modules";
        let lock = format!(
            r#"{{
  "lockFileVersion": 28,
  "registryFileHashes": {{
    "{bcr}/rules_jvm_external/6.3/MODULE.bazel": "a",
    "{bcr}/rules_jvm_external/6.5/MODULE.bazel": "b",
    "{bcr}/rules_jvm_external/6.7/MODULE.bazel": "c",
    "{bcr}/rules_jvm_external/6.7/source.json": "d",
    "{bcr}/rules_java/9.3.0/source.json": "e",
    "{bcr}/not_rules_jvm_external/1.0/source.json": "f",
    "{bcr}/rules_jvm_external/6.7/patches/source.json": "g"
  }},
  "selectedYankedVersions": {{}},
  "moduleExtensions": {{}}
}}"#
        );
        let lock = ModuleLock::parse(&lock);
        assert_eq!(lock.version, Some(28));
        assert_eq!(lock.selected("rules_jvm_external"), ["6.7"]);
        assert_eq!(lock.selected("rules_java"), ["9.3.0"]);
        assert_eq!(lock.selected("rules_python"), [""; 0]);
        // A lock that is empty, cut off or of another shape says nothing.
        for unread in ["", "{", "[]", "{\"lockFileVersion\": \"13\"}"] {
            let lock = ModuleLock::parse(unread);
            assert_eq!(
                (lock.version, lock.selected("rules_jvm_external").len()),
                (None, 0)
            );
        }
        let old = ModuleLock::parse("{\"lockFileVersion\": 11}");
        assert_eq!(
            (old.version, old.selected("rules_jvm_external").len()),
            (Some(11), 0)
        );
    }

    /// One line, word by word as Bazel's `Tokenize` and `GetNextToken`
    /// read it: src/main/cpp/util/strings.cc, whose lines 43 and 181 to
    /// 242 are the same text at 7.4.0, 7.7.2, 8.8.2 and 9.3.2.
    #[test]
    fn a_line_is_split_into_words_as_bazel_splits_it() {
        let rows: [(&str, Option<&[&str]>); 14] = [
            // Line 43 and lines 234 to 236: a space, a tab, a carriage
            // return and a line feed stand between words.
            (
                "common  --a\t--b\r--c",
                Some(&["common", "--a", "--b", "--c"]),
            ),
            // Line 187, whose `strchr` also finds the NUL that ends that
            // list.
            ("common --a\0--b", Some(&["common", "--a", "--b"])),
            // Lines 237 to 239: a `#` between two words ends the line.
            ("build --a # --b", Some(&["build", "--a"])),
            ("# build --a", Some(&[])),
            // Lines 207 to 210: and so does one inside a word.
            ("build --a#b --c", Some(&["build", "--a"])),
            // Lines 211 to 213 and 198 to 205: a quote of either kind is
            // taken off, and what it holds is taken as it is: a blank, a
            // `#`, the other quote.
            (
                "build \"--a\" '--b' --c=\"d e\" --f='#' --g=\"'\"",
                Some(&["build", "--a", "--b", "--c=d e", "--f=#", "--g='"]),
            ),
            (
                "common --noenable_\"bzl\"mod",
                Some(&["common", "--noenable_bzlmod"]),
            ),
            // Lines 189 to 196: the character after a `\` is taken as it
            // is, inside a quote too, before anything else is asked of it.
            (
                "common --no\\enable_bzlmod --a=\\\"b --c=\"\\\"\" \\#d",
                Some(&["common", "--noenable_bzlmod", "--a=\"b", "--c=\"", "#d"]),
            ),
            ("common a\\ b \\\\", Some(&["common", "a b", "\\"])),
            // Lines 220 to 222: a word of nothing is no word.
            ("common \"\" '' --a", Some(&["common", "--a"])),
            ("", Some(&[])),
            // What Bazel's own source calls an oversight (rc_file.cc lines
            // 89 and 90 at 7.4.0 and 7.7.2, 122 and 123 at 8.8.2 and
            // 9.3.2) is not read: a quote that is never closed (the loop
            // of line 187 runs to the end of the line), and a `\` that
            // ends the line (lines 191 to 193).
            ("common \"--noenable_bzlmod", None),
            ("common --a 'b c", None),
            ("common --a \\", None),
        ];
        // Every wrong row in one message.
        let read = |words: &[&str]| words.iter().map(|word| word.to_string()).collect();
        let wrong = |row: &&(&str, Option<&[&str]>)| words(row.0) != row.1.map(read);
        let wrong: Vec<_> = rows.iter().filter(wrong).map(|row| row.0).collect();
        assert_eq!(wrong, [""; 0]);
    }

    /// The files, as `RcFile::ParseFile` reads them: src/main/cpp/rc_file.cc,
    /// by its lines at 7.4.0 and 7.7.2 and, after the `/`, at 8.8.2 and
    /// 9.3.2.
    #[test]
    fn an_option_is_found_in_the_rc_files_of_the_workspace() {
        let flags = ["enable_bzlmod", "vendor_dir"];
        let found = |files: &[(&str, &str)]| mentions(&view(files), &flags);
        let at = |file: &str, line, word: &str| (file.to_string(), line, word.to_string());
        assert_eq!(found(&[]), Ok(vec![]));
        let rc = "# common --noenable_bzlmod\n\
                  common --enable_bzlmod --lockfile_mode=error\n  \
                  build:ci --vendor_dir=third_party # --enable_bzlmod=false\n\
                  import %workspace%/tools/ci.bazelrc\n\
                  try-import %workspace%/user.bazelrc\n\
                  try-import /etc/bazel.bazelrc\n\
                  import ../outside.bazelrc\n\
                  try-import-if-bazel-version >=8.0.0 %workspace%/new.bazelrc\n\
                  try-import-if-bazel-version\n\
                  import\n";
        let ci = "import %workspace%/.bazelrc\nfetch --noexperimental_enable_bzlmod\n\
                  import tools/more.bazelrc\n";
        let files = [
            (".bazelrc", rc),
            ("tools/ci.bazelrc", ci),
            ("tools/more.bazelrc", "build --vendor_dir=v\n"),
            ("new.bazelrc", "common --noenable_bzlmod\n"),
            ("../outside.bazelrc", "common --enable_bzlmod=0\n"),
            ("/etc/bazel.bazelrc", "common --enable_bzlmod=f\n"),
            (">=8.0.0", "common --enable_bzlmod=n\n"),
        ];
        // Every option of a line, and nothing behind a `#`: a comment is
        // none (line 91 / 124). A file that is imported twice is read once, and one that is not there is passed
        // over. The file of a conditional import is the word after its
        // condition. A path that is not absolute is asked for from the
        // root, also one that leads out of it, which the view of a
        // checkout refuses; an absolute one is not asked for. The last
        // file a file imports is read first.
        let expected = vec![
            at(".bazelrc", 2, "--enable_bzlmod"),
            at(".bazelrc", 3, "--vendor_dir=third_party"),
            at("new.bazelrc", 1, "--noenable_bzlmod"),
            at("../outside.bazelrc", 1, "--enable_bzlmod=0"),
            at("tools/ci.bazelrc", 2, "--noexperimental_enable_bzlmod"),
            at("tools/more.bazelrc", 1, "--vendor_dir=v"),
        ];
        assert_eq!(found(&files), Ok(expected));
        // The path of an import is a word like any other (line 126 / 148):
        // without its quotes, joined over a line break, and `%workspace%/`
        // joined to the root however many `/` follow it (`JoinPath`,
        // workspace_layout.cc line 80 / 79).
        let ci = ("tools/c i.bazelrc", "common --noenable_bzlmod\n");
        for import in [
            "import \"%workspace%/tools/c i.bazelrc\"\n",
            "try-import 'tools/c i.bazelrc'\n",
            "import \\\n%workspace%/tools/c\\ i.bazelrc\n",
            "import %workspace%//tools/c\\ i.bazelrc\n",
        ] {
            let found = found(&[(".bazelrc", import), ci]);
            let expected = vec![at(ci.0, 1, "--noenable_bzlmod")];
            assert_eq!(found, Ok(expected), "{import:?}");
        }
        // A `\` before a line break joins two lines, whichever line break
        // it is, before anything else is read (lines 72 and 73 / 107 and
        // 108): inside a word, between two, behind a `#`. The line of an option is the
        // one its line starts on, and the lines after it keep their own.
        // The last line of a file has no line break to join over: Bazel
        // passes over its `\`.
        let joined = "common --noenable_\\\nbzlmod\nbuild \\\r\n  --vendor_dir=v\r\n\
                      # a comment \\\ncommon --enable_bzlmod=0\ncommon --enable_bzlmod\\";
        let expected = vec![
            at(".bazelrc", 1, "--noenable_bzlmod"),
            at(".bazelrc", 3, "--vendor_dir=v"),
            at(".bazelrc", 7, "--enable_bzlmod"),
        ];
        assert_eq!(found(&[(".bazelrc", joined)]), Ok(expected));
        // Of two `\` before a line break the second joins the lines, and
        // the first then stands before the next line's first character.
        let two = "common \\\\\n--enable_bzlmod\n";
        let expected = vec![at(".bazelrc", 1, "--enable_bzlmod")];
        assert_eq!(found(&[(".bazelrc", two)]), Ok(expected));
        // The blanks around a line go first (line 77 / 112: also a
        // vertical tab and a form feed, which stand in a word elsewhere),
        // and the first word of a line is its command, never an option
        // (lines 98 and 144 to 148 / 129 to 134).
        let stripped = "\x0b common --enable_bzlmod\x0c\n--noenable_bzlmod\n";
        let expected = vec![at(".bazelrc", 1, "--enable_bzlmod")];
        assert_eq!(found(&[(".bazelrc", stripped)]), Ok(expected));
        // A line that is not read as Bazel reads it for certain may hold
        // anything: the file and the line.
        for (unread, line) in [
            ("common --a\ncommon \"--noenable_bzlmod\n", 2),
            ("common --noenable_bzlmod \\ \n", 1),
            // Bazel joins three lines here; the second is not looked at.
            ("common \\\\\r\n\n--noenable_bzlmod\n", 1),
        ] {
            let said = found(&[(".bazelrc", unread)]);
            assert_eq!(said, Err(format!(".bazelrc:{line}")), "{unread:?}");
        }
        // What cannot be read may hold anything, and so may the file after
        // the last one that is read.
        let unreadable = [
            (".bazelrc", "import %workspace%/a.bazelrc\n"),
            ("a.bazelrc", "\0"),
        ];
        assert_eq!(found(&unreadable), Err("a.bazelrc".to_string()));
        let chain = |at: usize| format!("import %workspace%/{}.bazelrc\n", at + 1);
        let texts: Vec<(String, String)> = (0..MAX_RC_FILES)
            .map(|at| (format!("{at}.bazelrc"), chain(at)))
            .collect();
        let mut files = vec![(".bazelrc", "import %workspace%/1.bazelrc\n")];
        files.extend(
            texts
                .iter()
                .map(|(path, text)| (path.as_str(), text.as_str())),
        );
        assert_eq!(found(&files), Err(format!("{MAX_RC_FILES}.bazelrc")));
        assert_eq!(found(&files[..MAX_RC_FILES]), Ok(vec![]));
    }
}
