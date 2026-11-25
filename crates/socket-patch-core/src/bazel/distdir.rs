//! The `.bazelrc` lines that make Bazel take a patched wheel from the
//! checkout, and what a workspace must show before one is written.
//!
//! rules_python's `pip.parse` fetches a requirement that names a wheel by
//! its URL with Bazel's downloader, by the sha256 of the line. Before
//! Bazel downloads a file that has a checksum, it looks in each
//! `--distdir` for a file of the download's name with that checksum, and
//! takes it. So where vendored mode pins the patched wheel by its URL on
//! the patch host, as hosted mode does, and commits the wheel under
//! `.socket/vendor/pypi/<uuid>/`, one line of the `.bazelrc` at the Bazel
//! root, `common --distdir=<that directory>`, makes the build take the
//! committed copy and ask no host ([`crate::vendor::pypi_distdir`]).
//!
//! Measured with rules_python 2.5.0-rc4 on Bazel 9.3.2, 8.8.2 and 7.7.2: a
//! fresh clone builds the patched package with the patch host stopped, a
//! new output base and no copy in the repository cache, also from a
//! sub-directory and beside a `--distdir` of the user's own. Bazel reads a
//! relative path from the workspace root, and takes `%workspace%` in this
//! option literally, so the line holds the path from the Bazel root. With
//! the host stopped a changed or missing copy fails the build. With the
//! host up, Bazel passes over such a copy without a message and downloads
//! the wheel of the pin, never other bytes. A downloader config that
//! blocks the patch host fails the build although the copy is there:
//! Bazel refuses before it looks in a `--distdir`.
//!
//! A `--distdir` is one flat directory, searched by file name. Each patch
//! gets a line for its own directory: two patches of one release have
//! wheels of one name, and the directory of a patch is the unit that
//! vendored mode writes, checks and removes.

use std::path::PathBuf;

use super::built::workspace_as_built;
use super::ignore::{content, edited, settled, update, Kept};
use super::maven::{asked, known_release};
use super::rc::{declared_release, mentions, ModuleLock};
use super::workspace::{disk, disk_up_to, Entry};
use super::BazelRoot;

/// The warning code of a `.bazelrc` that [`sync`] could not update.
pub const NOT_UPDATED: &str = "bazelrc_not_updated";

/// The line above every line [`sync`] writes.
const COMMENT: &str = "# socket-patch: the committed copy of a patched wheel, for Bazel's \
                       downloads (to opt out, comment out the next line)";

/// What every line of [`sync`] is about, for the one comment line they
/// share.
const WHEEL: &str = "wheel";

/// How a line of [`sync`] starts: the directory follows, from the Bazel
/// root.
const OPTION: &str = "common --distdir=";

const LINES: Kept = Kept {
    file: ".bazelrc",
    comment: |_| COMMENT.to_string(),
    // Only the line itself: a `--distdir` above the copy's is not searched
    // below itself.
    covers: |old, line| {
        let mut lines = old.split_inclusive(|byte| *byte == b'\n');
        lines.any(|own| content(own) == line.as_bytes())
    },
};

/// The module of the ruleset whose hub reads a requirements file.
const RULESET: &str = "rules_python";

/// The releases of [`RULESET`] whose hub is shown to fetch a wheel that a
/// requirement names by its URL with Bazel's downloader, under the name
/// the URL ends in and with the sha256 of the line: 2.5.0-rc4 was measured,
/// and 2.5.0 is the same commit. The releases before it fetch through
/// other code, which no build here has run.
const RULESETS: [&str; 2] = ["2.5.0-rc4", "2.5.0"];

/// The options of an rc file under which Bazel does not take a download
/// from a `--distdir`, or was not measured to.
const AGAINST: [&str; 3] = [
    "downloader_config",
    "repository_disable_download",
    "remote_downloader",
];

/// The path of the project of `root` from the Bazel root, as a line of
/// [`sync`] starts after [`OPTION`]: empty, or ending in `/`.
fn below(root: &BazelRoot) -> String {
    let parts = root.project.components();
    parts
        .map(|part| format!("{}/", part.as_os_str().to_string_lossy()))
        .collect()
}

/// Whether a line of an rc file takes `project`, a path from the Bazel
/// root, as it is: Bazel splits a line at blanks and reads quotes, `\` and
/// `#` otherwise.
fn plain(project: &str) -> bool {
    !project.contains(|c: char| c.is_whitespace() || "\"'\\#".contains(c))
}

/// Make the `.bazelrc` at the Bazel root `root` agree with `dirs`, the
/// directories of the project's committed wheels, each by its path from
/// the project (`.socket/vendor/pypi/<uuid>`): one line under [`COMMENT`]
/// for each while it exists and the file neither has nor declines the line
/// ([`settled`]), and no such pair for a directory of the project under
/// `.socket/vendor/pypi` that is gone. Without `add`, and for a project
/// whose path a line does not take as it is ([`plain`]), pairs are only
/// taken away. A directory that cannot be probed keeps what the file says of it,
/// and a file left empty is deleted. The edit is made as the one of
/// [`super::ignore`] is: under a lock of the root, never through a link.
///
/// `Ok(Some)` is the file, when it was changed. `Err` is the detail of a
/// [`NOT_UPDATED`] warning.
pub fn sync(root: &BazelRoot, dirs: &[String], add: bool) -> Result<Option<PathBuf>, String> {
    let from_root = below(root);
    // A project that was moved to a path no line can hold as it is (a
    // blank would start a second word for Bazel) gets no line: the build
    // then downloads the wheel, as without the pair.
    let add = add && plain(&from_root);
    let project = root.dir.join(&root.project);
    // `None`: it cannot be told. Only a directory that is not found is gone.
    let exists = |dir: &str| match std::fs::metadata(project.join(dir)) {
        Ok(meta) => Some(meta.is_dir()),
        Err(e) => (e.kind() == std::io::ErrorKind::NotFound).then_some(false),
    };
    let line = |dir: &str| format!("{OPTION}{from_root}{dir}");
    // The lines to have, and the lines the file has for a directory of
    // this project that is gone.
    let wanted = |old: &[u8]| {
        // A copy that is there gets its line only from a run that adds.
        let state = |dir: &str| exists(dir).filter(|there| add || !there);
        let mut wanted: Vec<_> = (dirs.iter())
            .map(|dir| (line(dir), state(dir), WHEEL))
            .collect();
        let lines = old.split_inclusive(|byte| *byte == b'\n').map(content);
        for had in lines.filter_map(|had| std::str::from_utf8(had).ok()) {
            let dir = had.strip_prefix(&line(""));
            let dir = dir.filter(|dir| dir.starts_with(".socket/vendor/pypi/"));
            let gone = dir.is_some_and(|dir| exists(dir) == Some(false));
            if gone && !wanted.iter().any(|(line, ..)| line == had) {
                wanted.push((had.to_string(), Some(false), WHEEL));
            }
        }
        wanted
    };
    let mut edit = |old: &[u8]| edited(&LINES, old, &wanted(old));
    let (shown, failed, old) = match update(&LINES, &root.dir, &mut edit) {
        Ok(changed) => return Ok(changed.map(|(file, ..)| file)),
        Err(failed) => failed,
    };
    let missing: Vec<String> = wanted(&old)
        .iter()
        .filter(|(line, exists, _)| *exists == Some(true) && !settled(&LINES, &old, line))
        .map(|(line, ..)| format!("`{line}`"))
        .collect();
    let advice = if !missing.is_empty() {
        format!(
            "add {} to it on a line of its own, so that Bazel takes the committed copy of the \
             patched wheel; without the line the build downloads the wheel from the patch host",
            missing.join(" and ")
        )
    } else {
        "the lines under socket-patch's comment in it name directories that no longer exist \
         and can be deleted"
            .to_string()
    };
    Err(format!(
        "could not update {}: {failed}; {advice}",
        shown.display()
    ))
}

/// Why the files of the workspace `root` do not show that a build takes a
/// wheel from a line of [`sync`], for a project whose `locks` (each by its
/// path from the project) a run could rewrite and whose `lock` is the one
/// that holds the pin. `Ok` when they show all of it:
///
/// - the hub hands Bazel `lock` and no other file of `locks`, in calls
///   that are read with certainty ([`super::built::alone`]), and no
///   `WORKSPACE` file that the Bazel of the checkout reads is there
///   ([`workspace_as_built`]);
/// - Bazel selected a release of [`RULESETS`], by what `MODULE.bazel.lock`
///   says it selected and the root module asks for, as the Maven lane
///   reads its ruleset's ([`known_release`]);
/// - the checkout names a Bazel 7, 8 or 9 (`.bazeliskrc`, `.bazelversion`),
///   or names none and has a lock that 7.5.0 to 9.3.2 write (measured:
///   7.7.2, 8.8.2 and 9.3.2);
/// - no rc file of the checkout names an option of [`AGAINST`], all of
///   them can be read, and none imports a file from outside the checkout,
///   which is not read;
/// - the line can be written: the project's path holds nothing that an rc
///   file reads otherwise, and `.bazelrc` is no link and not read-only.
pub fn ready(root: &BazelRoot, lock: &str, locks: &[String]) -> Result<(), String> {
    let project = below(root);
    if !plain(&project) {
        return Err(format!(
            "the path of the project from the Bazel root, {project}, holds a character that a \
             line of .bazelrc does not take as it is"
        ));
    }
    let rc = root.dir.join(LINES.file);
    if crate::utils::containment::is_link(&rc) {
        let link = "is a symbolic link, which socket-patch does not write through";
        return Err(format!("{} {link}", LINES.file));
    }
    // The line editor reads only a regular file. A FIFO or device there
    // would also block the append probe below in open(2).
    if std::fs::metadata(&rc).is_ok_and(|m| !m.is_file()) {
        return Err(format!("{} is not a regular file", LINES.file));
    }
    // As the write itself asks: a file that is there opens for appending.
    // Non-blocking on Unix, so a FIFO swapped in after the check above
    // fails the open (ENXIO) instead of waiting for a reader.
    let mut probe = std::fs::OpenOptions::new();
    probe.append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut probe, libc::O_NONBLOCK);
    let denied = |e: std::io::Error| e.kind() == std::io::ErrorKind::PermissionDenied;
    if probe.open(&rc).is_err_and(denied) {
        let closed = "is read-only, so the line that makes Bazel take the committed wheel \
                      cannot be written to it";
        return Err(format!("{} {closed}", LINES.file));
    }
    let view = disk(&root.dir);
    let view: &dyn Fn(&str) -> Entry = &view;
    let workspace = workspace_as_built(view);
    let read = |file: &str| super::built::lock_text(&root.dir, file);
    let hub = ("requirements_lock", lock);
    super::built::alone(&workspace, root, "pypi", hub, locks, &read)?;

    let written = match disk_up_to(&root.dir, 64 << 20)("MODULE.bazel.lock") {
        Entry::Text(lock) => ModuleLock::parse(&lock),
        _ => ModuleLock::default(),
    };
    let beyond = |selected: &str| {
        format!(
            "Bazel selected {RULESET} {selected}, and that the hub takes a committed wheel in \
             the place of a download is shown for {RULESET} 2.5.0 alone"
        )
    };
    let asked = asked(&workspace, RULESET);
    known_release(&asked, &written, RULESET, &RULESETS, "", &beyond)?;
    match declared_release(view) {
        Some((major, minor, patch)) if !(7..=9).contains(&major) => {
            return Err(format!(
                "the checkout names Bazel {major}.{minor}.{patch} (`.bazeliskrc` or \
                 `.bazelversion`), and this is shown for Bazel 7, 8 and 9"
            ))
        }
        None if !written.version.is_some_and(|v| (13..=28).contains(&v)) => {
            let why = "no file of the checkout says that Bazel 7, 8 or 9 builds it: name the \
                       release in `.bazelversion`";
            return Err(why.to_string());
        }
        _ => {}
    }
    match mentions(view, &AGAINST, true).map(|found| found.into_iter().next()) {
        Ok(None) => Ok(()),
        Ok(Some((file, line, word))) => Err(format!(
            "{file}:{line} names `{word}`, under which Bazel is not shown to take a download \
             from the checkout"
        )),
        Err(file) => Err(format!(
            "the rc file {file} cannot be read, and may name a downloader config"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "33333333-3333-4333-8333-333333333333";

    fn dir(uuid: &str) -> String {
        format!(".socket/vendor/pypi/{uuid}")
    }

    fn pair(line: &str) -> String {
        format!("{COMMENT}\n{OPTION}{line}\n")
    }

    /// A checkout whose root has the workspace files `files` and whose
    /// project `project` has the committed directories `dirs`.
    fn checkout(
        project: &str,
        files: &[(&str, &str)],
        dirs: &[&str],
    ) -> (tempfile::TempDir, BazelRoot) {
        let tmp = tempfile::tempdir().unwrap();
        let top = fs::canonicalize(tmp.path()).unwrap();
        let all = [
            (".git/HEAD", "ref: refs/heads/main\n"),
            ("MODULE.bazel", ""),
        ];
        for (path, text) in all.iter().chain(files) {
            let path = top.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        for uuid in dirs {
            fs::create_dir_all(top.join(project).join(dir(uuid))).unwrap();
        }
        fs::create_dir_all(top.join(project)).unwrap();
        let root = crate::bazel::bazel_root(&top.join(project)).unwrap();
        (tmp, root)
    }

    fn rc(root: &BazelRoot) -> Option<String> {
        fs::read_to_string(root.dir.join(".bazelrc")).ok()
    }

    /// A project at a path that a line of the file does not take as it is
    /// gets no line, however it came to hold a committed wheel: a blank in
    /// the line would be a second word on every Bazel command.
    #[test]
    fn a_project_whose_path_a_line_does_not_take_gets_no_line() {
        let user = "build --jobs=4\n";
        let (_tmp, root) = checkout("my svc", &[(".bazelrc", user)], &[UUID]);
        assert_eq!(sync(&root, &[dir(UUID)], true), Ok(None));
        assert_eq!(rc(&root).unwrap(), user);
    }

    /// The line follows the directory: added for a directory that is
    /// there, from the Bazel root, after the lines the file has; taken
    /// away with the directory, and the file is then the one of before.
    #[test]
    fn a_line_is_kept_for_each_directory_and_taken_away_with_it() {
        let user = "build --jobs=4\n";
        for (project, from_root) in [("", ""), ("svc/api", "svc/api/")] {
            let (_tmp, root) = checkout(project, &[(".bazelrc", user)], &[UUID, OTHER]);
            let both = [dir(UUID), dir(OTHER)];
            let lines = both
                .each_ref()
                .map(|dir| pair(&format!("{from_root}{dir}")));
            let changed = sync(&root, &both, true).unwrap();
            // The file is reported as a person reads a path: on Windows
            // without the verbatim prefix the root's own path carries.
            let file =
                crate::utils::pnpm_workspace::without_verbatim_prefix(root.dir.join(".bazelrc"));
            assert_eq!(changed, Some(file));
            assert_eq!(
                rc(&root).unwrap(),
                format!("{user}{}{}", lines[0], lines[1])
            );
            // Nothing to change: no write.
            assert_eq!(sync(&root, &both, true), Ok(None));
            // One directory is gone, with whatever the ledger says.
            fs::remove_dir(root.dir.join(project).join(dir(UUID))).unwrap();
            for dirs in [&both[..], &both[1..]] {
                sync(&root, dirs, false).unwrap();
                assert_eq!(
                    rc(&root).unwrap(),
                    format!("{user}{}", lines[1]),
                    "{project}"
                );
            }
            fs::remove_dir(root.dir.join(project).join(dir(OTHER))).unwrap();
            sync(&root, &[], true).unwrap();
            assert_eq!(rc(&root).unwrap(), user, "{project}");
        }
        // A file that socket-patch made is gone with its last line, and
        // one whose last line had no line break is the file of before.
        for user in [None, Some("build --jobs=4")] {
            let files = user.map(|user| (".bazelrc", user));
            let (_tmp, root) = checkout("", files.as_slice(), &[UUID]);
            sync(&root, &[dir(UUID)], true).unwrap();
            let line = pair(&dir(UUID));
            let with = match user {
                Some(user) => format!("{user}\n{}", line.trim_end()),
                None => line,
            };
            assert_eq!(rc(&root).unwrap(), with);
            fs::remove_dir(root.dir.join(dir(UUID))).unwrap();
            sync(&root, &[dir(UUID)], true).unwrap();
            assert_eq!(rc(&root), files.map(|(_, user)| user.to_string()));
        }
    }

    /// Only a directory that the caller names gets a line, only a line of
    /// this project under socket-patch's comment is taken away, and a line
    /// that the user commented out is declined: nothing is added.
    #[test]
    fn other_lines_stay_and_a_commented_line_declines() {
        let own = format!("{OPTION}{}", dir(UUID));
        let (_tmp, root) = checkout("", &[], &[OTHER]);
        // A directory with no entry of the ledger, and without `add`.
        assert_eq!(sync(&root, &[], true), Ok(None));
        assert_eq!(sync(&root, &[dir(OTHER)], false), Ok(None));
        assert_eq!(rc(&root), None);
        // Lines that are not socket-patch's to remove, for directories
        // that are gone: the user's own, another project's, and a
        // `--distdir` elsewhere.
        let kept = format!(
            "{own}\n{}{}{}",
            pair(&format!("svc/{}", dir(UUID))),
            pair("third_party/distdir"),
            pair(&format!("{}/sub", dir(UUID))).replace("common", "build"),
        );
        fs::write(root.dir.join(".bazelrc"), &kept).unwrap();
        assert_eq!(sync(&root, &[], true), Ok(None));
        // The user's own line is the line: no second one.
        fs::create_dir_all(root.dir.join(dir(UUID))).unwrap();
        assert_eq!(sync(&root, &[dir(UUID)], true), Ok(None));
        // A line above the directory is not: Bazel does not look below.
        let above = format!("{OPTION}.socket/vendor/pypi\n");
        fs::write(root.dir.join(".bazelrc"), &above).unwrap();
        sync(&root, &[dir(UUID)], true).unwrap();
        assert_eq!(rc(&root).unwrap(), format!("{above}{}", pair(&dir(UUID))));
        // Declined, in each spelling, also once the directory is gone.
        for declined in [format!("#{own}"), format!("#  {own}")] {
            let declined = format!("{COMMENT}\n{declined}\n");
            fs::write(root.dir.join(".bazelrc"), &declined).unwrap();
            assert_eq!(
                sync(&root, &[dir(UUID), dir(OTHER)], true).map(|_| ()),
                Ok(())
            );
            let with_other = format!("{declined}{}", pair(&dir(OTHER)));
            assert_eq!(rc(&root).unwrap(), with_other);
            fs::remove_dir_all(root.dir.join(".socket")).unwrap();
            sync(&root, &[], true).unwrap();
            assert_eq!(rc(&root).unwrap(), declined);
            fs::create_dir_all(root.dir.join(dir(UUID))).unwrap();
            fs::create_dir_all(root.dir.join(dir(OTHER))).unwrap();
        }
    }

    /// A file that cannot be written is reported with the line to add,
    /// and stays: a link is not written through.
    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_updated_is_reported_with_the_line() {
        let (_tmp, root) = checkout("", &[("elsewhere", "build --jobs=4\n")], &[UUID]);
        std::os::unix::fs::symlink("elsewhere", root.dir.join(".bazelrc")).unwrap();
        let why = sync(&root, &[dir(UUID)], true).unwrap_err();
        let line = format!("add `{OPTION}{}` to it", dir(UUID));
        for part in ["could not update", "symbolic link", &line, "patch host"] {
            assert!(why.contains(part), "{why}");
        }
        assert_eq!(rc(&root).unwrap(), "build --jobs=4\n");
    }

    const MODULE: &str = r#"bazel_dep(name = "rules_python", version = "2.5.0")
pip = use_extension("@rules_python//python/extensions:pip.bzl", "pip")
pip.parse(hub_name = "pip", python_version = "3.11", requirements_lock = "//:requirements.txt")
use_repo(pip, "pip")
"#;

    /// The lock of a Bazel that selected `release` of the ruleset.
    fn lock(version: u32, release: &str) -> String {
        format!(
            "{{\"lockFileVersion\": {version}, \"registryFileHashes\": {{\
             \"https://bcr.bazel.build/modules/rules_python/{release}/source.json\": \"x\"}}}}"
        )
    }

    /// [`ready`] for the root project of a checkout with `files`.
    fn asked_of(files: &[(&str, &str)]) -> Result<(), String> {
        let (_tmp, root) = checkout("", files, &[]);
        ready(&root, "requirements.txt", &["requirements.txt".to_string()])
    }

    fn declined(files: &[(&str, &str)], names: &str) {
        let why = asked_of(files).unwrap_err();
        assert!(why.contains(names), "{names:?} is not in {why:?}");
    }

    #[test]
    fn a_workspace_that_shows_all_of_it_is_ready() {
        let module = ("MODULE.bazel", MODULE);
        for (version, release) in [(28, "2.5.0"), (28, "2.5.0-rc4"), (13, "2.5.0")] {
            let lock = lock(version, release);
            let asks = MODULE.replace("2.5.0", release);
            let files = [("MODULE.bazel", &*asks), ("MODULE.bazel.lock", &*lock)];
            assert_eq!(asked_of(&files), Ok(()), "{release}");
        }
        // A Bazel that the checkout names, with any lock version; rc lines
        // that are the user's own; another hub that reads another file.
        let unknown = lock(99, "2.5.0");
        let lock = ("MODULE.bazel.lock", &*unknown);
        for release in ["7.4.1", "8.8.2", "9.3.2"] {
            assert_eq!(
                asked_of(&[module, lock, (".bazelversion", release)]),
                Ok(())
            );
        }
        let rc =
            "build --jobs=4\ncommon --distdir=third_party/distdir\ncommon --lockfile_mode=error\n";
        let good = super::tests::lock(28, "2.5.0");
        let lock = ("MODULE.bazel.lock", &*good);
        assert_eq!(asked_of(&[module, lock, (".bazelrc", rc)]), Ok(()));
        let more = format!(
            "{MODULE}pip.parse(hub_name = \"tools\", python_version = \"3.11\", \
             requirements_lock = \"//tools:requirements.txt\")\n"
        );
        assert_eq!(asked_of(&[("MODULE.bazel", &more), lock]), Ok(()));
    }

    #[test]
    fn a_ruleset_or_a_bazel_that_is_not_shown_declines() {
        let module = ("MODULE.bazel", MODULE);
        let good = lock(28, "2.5.0");
        let good = ("MODULE.bazel.lock", &*good);
        // No lock, a lock that names no release, and an unmeasured release.
        declined(&[module], "does not say which release of rules_python");
        declined(&[module, ("MODULE.bazel.lock", "{}")], "does not say which");
        for release in ["2.4.6", "2.5.0-rc3", "2.5.1", "1.9.2"] {
            let lock = lock(28, release);
            let names = format!("Bazel selected rules_python {release}");
            declined(&[module, ("MODULE.bazel.lock", &lock)], &names);
        }
        // The root asks for a newer release than the lock holds, or takes
        // the ruleset from somewhere that names no release.
        let newer = MODULE.replace("2.5.0", "2.6.0");
        declined(
            &[("MODULE.bazel", &newer), good],
            "build once so that Bazel updates its lock",
        );
        let local =
            format!("{MODULE}local_path_override(module_name = \"rules_python\", path = \"x\")\n");
        declined(
            &[("MODULE.bazel", &local), good],
            "with this `local_path_override`",
        );
        // A Bazel outside 7 to 9, or none that the checkout shows.
        for release in ["6.5.0", "10.0.0"] {
            let names = format!("names Bazel {release}");
            declined(&[module, good, (".bazelversion", release)], &names);
        }
        for version in [11, 29] {
            let lock = lock(version, "2.5.0");
            declined(
                &[module, ("MODULE.bazel.lock", &lock)],
                "name the release in `.bazelversion`",
            );
        }
    }

    #[test]
    fn an_rc_file_that_names_a_downloader_setting_declines() {
        let module = ("MODULE.bazel", MODULE);
        let good = lock(28, "2.5.0");
        let good = ("MODULE.bazel.lock", &*good);
        for (option, word) in [
            ("--downloader_config=ci/downloads.cfg", "downloader_config"),
            ("--experimental_downloader_config=x", "downloader_config"),
            (
                "--repository_disable_download",
                "repository_disable_download",
            ),
            (
                "--experimental_remote_downloader=grpc://x",
                "remote_downloader",
            ),
        ] {
            let rc = format!("build --jobs=4\ncommon {option}\n");
            let names = format!(".bazelrc:2 names `{option}`");
            declined(&[module, good, (".bazelrc", &rc)], &names);
            assert!(option.contains(word));
            // In a file the root one imports, too.
            let files = [
                module,
                good,
                (".bazelrc", "import %workspace%/ci.bazelrc\n"),
                ("ci.bazelrc", &*rc),
            ];
            declined(&files, &format!("ci.bazelrc:2 names `{option}`"));
        }
        // One that cannot be read may name any, and so may one that an
        // import brings in from outside the checkout, which is not read.
        let files = [module, good, (".bazelrc", "build 'unclosed\n")];
        declined(&files, "the rc file .bazelrc:1 cannot be read");
        let outside = "build --jobs=4\ntry-import /etc/bazel/site.bazelrc\n";
        let imported = [
            (".bazelrc", "import %workspace%/ci.bazelrc\n"),
            ("ci.bazelrc", outside),
        ];
        for (rc, from) in [
            (&[(".bazelrc", outside)][..], ".bazelrc"),
            (&imported[..], "ci.bazelrc"),
        ] {
            let names = format!(
                "the rc file /etc/bazel/site.bazelrc, which {from}:2 imports from outside the \
                 checkout, cannot be read"
            );
            declined(&[&[module, good][..], rc].concat(), &names);
        }
    }

    #[test]
    fn a_hub_that_is_not_read_with_certainty_declines() {
        let good = lock(28, "2.5.0");
        let good = ("MODULE.bazel.lock", &*good);
        let call = "requirements_lock = \"//:requirements.txt\")";
        for (with, names) in [
            // Another file of the build's platform, a file not written
            // out, a call that may not run, and a hub that is not read.
            (
                "requirements_lock = \"//:requirements.txt\", requirements_windows = \"//:win.txt\")",
                "names more than `requirements_lock = \"requirements.txt\"`",
            ),
            ("requirements_lock = LOCK)", "are not all written out"),
            ("**ARGS)", "are not all written out"),
            ("requirements_lock = \"//:requirements.txt\") if ON else None", "may not run"),
            ("requirements_lock = \"//:requirements.txt\")\nother(pip)", "MODULE.bazel:"),
        ] {
            let module = MODULE.replace(call, with);
            assert_ne!(module, MODULE);
            declined(&[("MODULE.bazel", &module), good], names);
        }
        // A second hub whose file brings the project's in with `-r`: it is
        // judged although the first call names the file itself.
        let second = "pip.parse(hub_name = \"all\", python_version = \"3.11\", \
                      requirements_lock = \"//:all.txt\")\n";
        let both = format!("{MODULE}{second}");
        let module = ("MODULE.bazel", &*both);
        declined(
            &[module, good, ("all.txt", "-r requirements.txt\n")],
            "names all.txt, which brings a file of this project in with `-r`",
        );
        // Without the include that file stands against nothing.
        let other = ("all.txt", "y==1.0.0\n");
        assert_eq!(asked_of(&[module, good, other]), Ok(()));
        // A `WORKSPACE` file that defines repositories, and a module file
        // with a byte that is not UTF-8.
        let legacy = ("WORKSPACE", "pip_parse(name = \"pip\")\n");
        declined(&[("MODULE.bazel", MODULE), good, legacy], "WORKSPACE");
        // Bazel 9 reads no `WORKSPACE` file: where the checkout names it,
        // the file stands against nothing. An older release reads it.
        let module = ("MODULE.bazel", MODULE);
        for release in ["9.0.0", "9.3.2"] {
            let files = [module, good, legacy, (".bazelversion", release)];
            assert_eq!(asked_of(&files), Ok(()), "{release}");
        }
        for release in ["7.7.2", "8.8.2"] {
            let files = [module, good, legacy, (".bazelversion", release)];
            declined(&files, "WORKSPACE");
        }
        let (_tmp, root) = checkout("", &[good], &[]);
        fs::write(
            root.dir.join("MODULE.bazel"),
            [MODULE.as_bytes(), b"# caf\xe9\n"].concat(),
        )
        .unwrap();
        let locks = ["requirements.txt".to_string()];
        let why = ready(&root, "requirements.txt", &locks).unwrap_err();
        assert!(why.contains("MODULE.bazel"), "{why}");
    }

    /// The line itself: a project whose path an rc file would read
    /// otherwise, and a `.bazelrc` that is a link or read-only.
    #[test]
    fn a_line_that_cannot_be_written_declines() {
        let good = lock(28, "2.5.0");
        let files = [("MODULE.bazel", MODULE), ("MODULE.bazel.lock", &*good)];
        let (_tmp, root) = checkout("my app", &files, &[]);
        let locks = ["requirements.txt".to_string()];
        let why = ready(&root, "requirements.txt", &locks).unwrap_err();
        assert!(why.contains("my app/, holds a character"), "{why}");
        #[cfg(unix)]
        {
            let (_tmp, root) = checkout("", &files, &[]);
            std::os::unix::fs::symlink("elsewhere", root.dir.join(".bazelrc")).unwrap();
            let why = ready(&root, "requirements.txt", &locks).unwrap_err();
            assert!(why.contains(".bazelrc is a symbolic link"), "{why}");
            // A FIFO declines at once instead of hanging the probe.
            let (_tmp, root) = checkout("", &files, &[]);
            let fifo = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                root.dir.join(".bazelrc").as_os_str(),
            ))
            .unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
            let why = ready(&root, "requirements.txt", &locks).unwrap_err();
            assert!(why.contains(".bazelrc is not a regular file"), "{why}");
        }
        // A directory there is no file to write the line into either.
        let (_tmp, root) = checkout("", &files, &[]);
        fs::create_dir(root.dir.join(".bazelrc")).unwrap();
        let why = ready(&root, "requirements.txt", &locks).unwrap_err();
        assert!(why.contains(".bazelrc is not a regular file"), "{why}");
        let (_tmp, root) = checkout("", &[files[0], files[1], (".bazelrc", "")], &[]);
        assert_eq!(ready(&root, "requirements.txt", &locks), Ok(()));
        let rc = root.dir.join(".bazelrc");
        let mut bits = fs::metadata(&rc).unwrap().permissions();
        bits.set_readonly(true);
        fs::set_permissions(&rc, bits).unwrap();
        // Root writes a read-only file all the same.
        if fs::OpenOptions::new().append(true).open(&rc).is_err() {
            let why = ready(&root, "requirements.txt", &locks).unwrap_err();
            assert!(why.contains(".bazelrc is read-only"), "{why}");
        }
    }
}
