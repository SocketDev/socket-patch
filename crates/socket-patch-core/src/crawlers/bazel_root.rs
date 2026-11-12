//! The stat-only upward root probe (design 2.2).
//!
//! Bazel takes the nearest ancestor of its working directory that holds a
//! boundary file for the workspace root, and a boundary file further down
//! does not cut its directory out of the workspace above it (probe B3 on
//! six Bazel lines, B5 on 7.7.2 and 9.3.2). So every root at or above a
//! project governs it: the one Bazel picks when it runs in the project,
//! and each outer one when it runs there. This module records them all,
//! from the project up to the read boundary, and says whether another is
//! in sight above the boundary, where socket-patch reads nothing.
//!
//! The walk makes two kinds of call, `symlink_metadata` and, for a link,
//! `metadata`. It opens no file and lists no directory. In a project with
//! no boundary file the cost is four `symlink_metadata` calls per
//! directory walked and nothing else: no read, no warning, no request.
//! The calls block: run them where `crawlers::bazel_output` runs its own.
//!
//! A boundary file is what the Bazel client takes for one
//! (`bazel@9.3.2:src/main/cpp/workspace_layout.cc:34-40`): the name
//! exists and is not a directory, with a link followed. A directory named
//! `workspace` on a case-insensitive disk is none.
//!
//! What a failed `stat` means depends on the side of the boundary:
//!
//! - at or below it, a name that cannot be judged counts as a boundary
//!   file. The reader that follows says the file is unreadable, and
//!   unreadable is not absent;
//! - above it, only a name that was seen counts, as in
//!   `ReadBoundary::marker_above`, which every other "a governing file
//!   lies above the repository" check uses. A sandbox that denies
//!   metadata outside the checkout fails every `stat` there, and taking
//!   that for a Bazel root would refuse every project run inside it.
//!
//! The walk above the boundary is `marker_above`'s, with the same stop
//! below the home directory, and is written out here for three reasons:
//! `marker_above` takes a directory for a marker, it stops at the nearest
//! marker, where a stray file must not hide the workspace above it, and
//! its calls cannot be counted by a test.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::bazel::model::{Probe, RootRef};
use crate::bazel::module_lock::MODULE_LOCK;
use crate::utils::repo_root::{self, ReadBoundary, ReadScope};

/// The files that make a directory a Bazel root, in the order the Bazel
/// client tests them. Bazel below 6.3.0 knows only the last two. Which
/// names count on a proven Bazel line is the reader's decision: the line
/// is read from files, and this module opens none.
pub const BOUNDARY_FILES: [&str; 4] =
    ["MODULE.bazel", "REPO.bazel", "WORKSPACE.bazel", "WORKSPACE"];

/// Files that say a boundary file above the read boundary belongs to a
/// workspace somebody builds. An rc file and a version pin are written by
/// hand, the lock by Bazel 7 and later on its first build.
const SIGNAL_FILES: [&str; 3] = [".bazelversion", ".bazelrc", MODULE_LOCK];

/// The convenience links Bazel leaves under its default prefix. A fourth
/// is named after the workspace directory.
const SIGNAL_LINKS: [&str; 3] = ["bazel-out", "bazel-bin", "bazel-testlogs"];

/// What one `stat` of a name saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Absent,
    Dir,
    /// A symbolic link or a junction. Only `lstat` answers it.
    Link,
    /// Anything else: a regular file, a FIFO, a device.
    File,
    /// The call failed for a reason other than absence.
    Unknown,
}

/// The two calls the probe makes. It is a trait so that a test can count
/// them, and it has no third method: nothing here can read.
trait StatFs {
    /// `symlink_metadata`: the name itself.
    fn lstat(&self, path: &Path) -> Seen;
    /// `metadata`: what a link leads to. Asked only of a link.
    fn stat(&self, path: &Path) -> Seen;
}

struct Disk;

impl StatFs for Disk {
    fn lstat(&self, path: &Path) -> Seen {
        seen(std::fs::symlink_metadata(path))
    }

    fn stat(&self, path: &Path) -> Seen {
        seen(std::fs::metadata(path))
    }
}

fn seen(meta: std::io::Result<std::fs::Metadata>) -> Seen {
    match meta {
        Ok(meta) if meta.file_type().is_symlink() => Seen::Link,
        Ok(meta) if meta.is_dir() => Seen::Dir,
        Ok(_) => Seen::File,
        // A missing entry, a parent that is a file, a name that cannot
        // exist.
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::InvalidFilename
            ) =>
        {
            Seen::Absent
        }
        Err(_) => Seen::Unknown,
    }
}

/// Whether `path` is a file to the Bazel client. `Some(false)` when it is
/// absent, a directory, or a link to either (the client asks `access` and
/// `stat`, which follow links); `None` when a call failed.
fn is_file(fs: &dyn StatFs, path: &Path) -> Option<bool> {
    let seen = match fs.lstat(path) {
        Seen::Link => fs.stat(path),
        seen => seen,
    };
    match seen {
        Seen::Absent | Seen::Dir => Some(false),
        Seen::File => Some(true),
        // A link `stat` did not resolve is as unknown as a failed call.
        Seen::Link | Seen::Unknown => None,
    }
}

/// The boundary files of one directory.
#[derive(Debug, Clone, Copy, Default)]
struct Marks {
    /// The first name, in Bazel's order, that is a file.
    seen: Option<&'static str>,
    /// The first name that could not be judged, among those tested before
    /// one was seen.
    unknown: Option<&'static str>,
}

impl Marks {
    fn of(fs: &dyn StatFs, dir: &Path) -> Self {
        let mut marks = Self::default();
        for name in BOUNDARY_FILES {
            match is_file(fs, &dir.join(name)) {
                Some(true) => {
                    marks.seen = Some(name);
                    break;
                }
                Some(false) => {}
                None => marks.unknown = marks.unknown.or(Some(name)),
            }
        }
        marks
    }

    /// The file that makes the directory a root where socket-patch reads
    /// (module docs: a name that cannot be judged counts there).
    fn inside(self) -> Option<&'static str> {
        self.seen.or(self.unknown)
    }
}

/// Whether a second sign of Bazel sits beside the boundary file of `dir`.
/// Only what was seen counts (module docs).
fn second_signal(fs: &dyn StatFs, dir: &Path) -> bool {
    let own_link = dir.file_name().map(|name| {
        let mut link = OsString::from("bazel-");
        link.push(name);
        link
    });
    let mut links = SIGNAL_LINKS.iter().map(OsString::from).chain(own_link);
    let file = |name: &&str| is_file(fs, &dir.join(name)) == Some(true);
    // A link is not followed: `bazel clean --expunge` removes the target
    // and leaves the link, which still says Bazel ran here.
    SIGNAL_FILES.iter().any(file) || links.any(|name| fs.lstat(&dir.join(name)) == Seen::Link)
}

/// What one run has seen. A directory is judged once, so the projects of
/// a monorepo share the cost of their common ancestors.
#[derive(Debug, Default)]
struct Memo {
    marks: HashMap<PathBuf, Marks>,
    confirmed: HashMap<PathBuf, bool>,
    /// [`RootProbe::probe`] answers, by project directory as given.
    probes: HashMap<PathBuf, Probe>,
}

impl Memo {
    fn marks(&mut self, fs: &dyn StatFs, dir: &Path) -> Marks {
        if let Some(known) = self.marks.get(dir) {
            return *known;
        }
        let marks = Marks::of(fs, dir);
        self.marks.insert(dir.to_path_buf(), marks);
        marks
    }

    fn confirmed(&mut self, fs: &dyn StatFs, dir: &Path) -> bool {
        if let Some(known) = self.confirmed.get(dir) {
            return *known;
        }
        let confirmed = second_signal(fs, dir);
        self.confirmed.insert(dir.to_path_buf(), confirmed);
        confirmed
    }
}

/// A boundary file above the read boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerAbove {
    /// The file, not its directory: the first of [`BOUNDARY_FILES`] there.
    pub marker: PathBuf,
    /// A second sign of Bazel sits beside it (`.bazelversion`, `.bazelrc`,
    /// `MODULE.bazel.lock` or a convenience link), so this is a workspace
    /// somebody builds and not a stray file.
    pub confirmed: bool,
}

/// Both halves of what the probe found. [`Probe`] holds one of them, so a
/// caller that needs both asks for this: the warning for a stray marker
/// when roots lie inside the boundary, and the inner roots for a remedy
/// when a confirmed root lies above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survey {
    /// Every root from the project up to the read boundary, nearest the
    /// project first.
    pub roots: Vec<RootRef>,
    /// The nearest confirmed marker above the boundary, else the nearest
    /// marker. The walk does not stop at a stray one, because a nested
    /// boundary file hides nothing above it either.
    pub above: Option<MarkerAbove>,
}

impl Survey {
    /// The one value the gate asks about. A confirmed root above the
    /// boundary outranks the roots inside it: it governs the project too
    /// and its hubs cannot be read. A stray marker above is the answer
    /// only when nothing is inside, and changes nothing otherwise.
    pub fn probe(&self) -> Probe {
        match (&self.above, self.roots.as_slice()) {
            (Some(above), _) if above.confirmed => Self::outside(above),
            (_, [root]) => Probe::Workspace(root.clone()),
            (Some(above), []) => Self::outside(above),
            (None, []) => Probe::NotBazel,
            (_, roots) => Probe::Nested(roots.to_vec()),
        }
    }

    fn outside(above: &MarkerAbove) -> Probe {
        Probe::RootOutsideBoundary {
            marker: above.marker.clone(),
            confirmed: above.confirmed,
        }
    }

    /// The answer when the project cannot be placed under a root: the one
    /// value that refuses every write and withholds every attestation.
    fn refusing(marker: PathBuf) -> Self {
        let above = MarkerAbove {
            marker,
            confirmed: true,
        };
        Self {
            roots: Vec::new(),
            above: Some(above),
        }
    }
}

/// `path`, relative, as a [`RootRef::project_rel`]: forward slashes, `""`
/// for the root itself. `None` when a segment is not UTF-8.
fn rel(path: &Path) -> Option<String> {
    let names: Option<Vec<&str>> = path
        .components()
        .map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    Some(names?.join("/"))
}

/// The walk. `project` is absolute and resolved, `floor` is the read
/// boundary (the project or one of its ancestors; `None` when every
/// ancestor may be read), and `home` is where the walk above the boundary
/// ends, as it does in `ReadBoundary::marker_above`: a stray `~/WORKSPACE`
/// beside the user's own `~/.bazelrc` governs nothing.
fn survey_with(
    fs: &dyn StatFs,
    memo: &mut Memo,
    project: &Path,
    floor: Option<&Path>,
    home: Option<&Path>,
) -> Survey {
    let mut found: Vec<(&Path, &'static str)> = Vec::new();
    let mut dirs = project.ancestors();
    for dir in dirs.by_ref() {
        if let Some(name) = memo.marks(fs, dir).inside() {
            found.push((dir, name));
        }
        if floor == Some(dir) {
            break;
        }
    }
    let mut above: Option<MarkerAbove> = None;
    for dir in dirs.take_while(|dir| !repo_root::at_or_above_home(dir, home)) {
        let Some(name) = memo.marks(fs, dir).seen else {
            continue;
        };
        let confirmed = memo.confirmed(fs, dir);
        if confirmed || above.is_none() {
            let marker = dir.join(name);
            above = Some(MarkerAbove { marker, confirmed });
        }
        if confirmed {
            break;
        }
    }
    // With no boundary every ancestor is readable, up to the last one.
    let top = floor.or_else(|| project.ancestors().last());
    let root = |dir: &Path| {
        Some(RootRef {
            root: dir.to_path_buf(),
            project_rel: rel(project.strip_prefix(dir).ok()?)?,
            boundary_levels: dir.strip_prefix(top?).ok()?.components().count(),
        })
    };
    match found.iter().map(|(dir, _)| root(dir)).collect() {
        Some(roots) => Survey { roots, above },
        // A segment between a root and the project is not UTF-8, so the
        // pure layer cannot name the project under that root. From the
        // outermost root the same walk has nothing to name, so that root
        // is the place the refusal sends the user to.
        None => {
            let outermost = found.last().map(|(dir, name)| dir.join(name));
            Survey::refusing(outermost.unwrap_or_else(|| project.to_path_buf()))
        }
    }
}

/// The probe for one run. It remembers every directory it judged, so make
/// one per run: a boundary file created later is not seen by it.
#[derive(Debug)]
pub struct RootProbe {
    home: Option<PathBuf>,
    memo: Mutex<Memo>,
}

impl Default for RootProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl RootProbe {
    pub fn new() -> Self {
        Self::with_home(repo_root::home())
    }

    /// A probe whose walk above the boundary ends below `home`.
    fn with_home(home: Option<PathBuf>) -> Self {
        Self {
            home,
            memo: Mutex::default(),
        }
    }

    fn memo(&self) -> MutexGuard<'_, Memo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The roots that govern `project_dir` in a project run, whose read
    /// boundary is the checkout around the project, or the project itself
    /// outside any checkout. Finding that boundary costs the `.git` stats
    /// every command already pays; a caller that holds the boundary calls
    /// [`RootProbe::survey`] and pays for the walk alone.
    pub fn probe(&self, project_dir: &Path) -> Probe {
        if let Some(known) = self.memo().probes.get(project_dir) {
            return known.clone();
        }
        let boundary = ReadBoundary::of(ReadScope::Workspace, project_dir);
        let probe = self.survey(project_dir, &boundary).probe();
        let key = project_dir.to_path_buf();
        self.memo().probes.insert(key, probe.clone());
        probe
    }

    /// The roots at or below `boundary` and the marker above it. A relative
    /// `project_dir` is read from the working directory. The roots are
    /// reported resolved, because Bazel looks for its workspace from the
    /// resolved working directory. A project directory that does not exist
    /// yet is judged by where it would be created.
    pub fn survey(&self, project_dir: &Path, boundary: &ReadBoundary) -> Survey {
        let resolved =
            std::fs::canonicalize(project_dir).or_else(|_| std::path::absolute(project_dir));
        let Ok(project) = resolved else {
            return Survey::refusing(project_dir.to_path_buf());
        };
        let floor = match boundary {
            ReadBoundary::Unbounded => None,
            ReadBoundary::Workspace { root } if project.starts_with(root) => Some(root.as_path()),
            // A boundary that does not hold the project permits no read
            // above the project.
            ReadBoundary::Workspace { .. } => Some(project.as_path()),
        };
        // Held across the stats: two tasks that walked the same ancestors
        // at once would only repeat them.
        let mut memo = self.memo();
        survey_with(&Disk, &mut memo, &project, floor, self.home.as_deref())
    }
}

/// The boundary file that makes `dir` itself a Bazel root, when one is
/// seen there: the test a walker makes of a directory it has entered, so
/// that a root with no native lock beside it is still a project. It looks
/// neither up nor down and remembers nothing.
pub fn boundary_file_in(dir: &Path) -> Option<&'static str> {
    Marks::of(&Disk, dir).seen
}

/// The Bazel roots that govern `project_dir`, for a caller with one
/// project to ask about. A run that asks about several keeps a
/// [`RootProbe`].
pub fn probe(project_dir: &Path) -> Probe {
    RootProbe::new().probe(project_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const HOME: &str = "/home/u";
    const REPO: &str = "/home/u/src/repo";

    /// A disk that answers from a table and records every call.
    #[derive(Default)]
    struct Fake {
        names: HashMap<PathBuf, Seen>,
        leads: HashMap<PathBuf, Seen>,
        /// Whether the call followed links, and its path.
        calls: RefCell<Vec<(bool, PathBuf)>>,
    }

    impl Fake {
        /// One entry per line: `<path>` is a file, `<path>/` a directory,
        /// `<path> ?` a name whose `lstat` fails, and
        /// `<path> -> file|dir|gone|?` a link with what `stat` says of it.
        fn lay(spec: &str) -> Self {
            let mut fs = Self::default();
            for line in spec.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if let Some((path, to)) = line.split_once(" -> ") {
                    let leads = match to {
                        "file" => Seen::File,
                        "dir" => Seen::Dir,
                        "gone" => Seen::Absent,
                        _ => Seen::Unknown,
                    };
                    fs.names.insert(path.into(), Seen::Link);
                    fs.leads.insert(path.into(), leads);
                } else if let Some(path) = line.strip_suffix(" ?") {
                    fs.names.insert(path.into(), Seen::Unknown);
                } else if let Some(path) = line.strip_suffix('/') {
                    fs.names.insert(path.into(), Seen::Dir);
                } else {
                    fs.names.insert(line.into(), Seen::File);
                }
            }
            fs
        }

        /// The survey of `project` in the checkout [`REPO`] of the user
        /// whose home is [`HOME`], by a run that has seen nothing yet.
        fn survey(&self, project: &str) -> Survey {
            let (repo, home) = (Path::new(REPO), Path::new(HOME));
            let mut memo = Memo::default();
            survey_with(self, &mut memo, Path::new(project), Some(repo), Some(home))
        }

        fn probe(&self, project: &str) -> Probe {
            self.survey(project).probe()
        }
    }

    impl StatFs for Fake {
        fn lstat(&self, path: &Path) -> Seen {
            self.calls.borrow_mut().push((false, path.to_path_buf()));
            self.names.get(path).copied().unwrap_or(Seen::Absent)
        }

        fn stat(&self, path: &Path) -> Seen {
            self.calls.borrow_mut().push((true, path.to_path_buf()));
            self.leads.get(path).copied().unwrap_or(Seen::Absent)
        }
    }

    fn root(dir: &str, project_rel: &str, boundary_levels: usize) -> RootRef {
        RootRef {
            root: dir.into(),
            project_rel: project_rel.into(),
            boundary_levels,
        }
    }

    fn outside(marker: &str, confirmed: bool) -> Probe {
        Probe::RootOutsideBoundary {
            marker: marker.into(),
            confirmed,
        }
    }

    #[test]
    fn a_project_with_no_boundary_file_costs_four_lstats_per_directory() {
        // An rc file is no boundary file, and the user's own rc file and
        // a file in the home directory are never looked at.
        let fs = Fake::lay(
            "/home/u/src/repo/svc/api/package.json
             /home/u/src/repo/.bazelrc
             /home/u/.bazelrc
             /home/u/WORKSPACE",
        );
        let (repo, home) = (Path::new(REPO), Path::new(HOME));
        let mut memo = Memo::default();
        let mut run = |project: &str| {
            fs.calls.borrow_mut().clear();
            let got = survey_with(&fs, &mut memo, Path::new(project), Some(repo), Some(home));
            assert_eq!(got.probe(), Probe::NotBazel, "{project}");
            assert_eq!((got.roots.len(), got.above), (0, None), "{project}");
            fs.calls.borrow().clone()
        };
        // The directories from the project to the boundary, then the one
        // above it that is below the home directory. No link is followed
        // and the trait has no way to read.
        let walked = [
            "/home/u/src/repo/svc/api",
            "/home/u/src/repo/svc",
            REPO,
            "/home/u/src",
        ];
        let four = |dir: &str| BOUNDARY_FILES.map(|name| (false, Path::new(dir).join(name)));
        let want: Vec<_> = walked.iter().flat_map(|dir| four(dir)).collect();
        assert_eq!(run("/home/u/src/repo/svc/api"), want);
        // One run judges a directory once: the same project is free, and
        // a sibling costs its own directory.
        assert_eq!(run("/home/u/src/repo/svc/api"), []);
        assert_eq!(
            run("/home/u/src/repo/svc/web"),
            four("/home/u/src/repo/svc/web")
        );
    }

    #[test]
    fn one_root_is_a_workspace_wherever_the_project_sits() {
        let fs = Fake::lay("/home/u/src/repo/MODULE.bazel");
        assert_eq!(fs.probe(REPO), Probe::Workspace(root(REPO, "", 0)));
        assert_eq!(
            fs.probe("/home/u/src/repo/svc/api"),
            Probe::Workspace(root(REPO, "svc/api", 0))
        );
        // The first name found ends a directory: one `lstat` per probe.
        let at_root = |call: &&(bool, PathBuf)| call.1.parent() == Some(Path::new(REPO));
        assert_eq!(fs.calls.borrow().iter().filter(at_root).count(), 2);

        // A root below the boundary says how far up a reader may look
        // for a `.bazelversion` (`RootRef::dirs_to_boundary`).
        let fs = Fake::lay("/home/u/src/repo/tools/ws/WORKSPACE");
        let Probe::Workspace(found) = fs.probe("/home/u/src/repo/tools/ws/pkg") else {
            panic!("one root");
        };
        assert_eq!(found, root("/home/u/src/repo/tools/ws", "pkg", 2));
        assert_eq!(found.dirs_to_boundary(), ["pkg", "", "..", "../.."]);
    }

    #[test]
    fn nested_roots_are_all_recorded_nearest_first() {
        // Probes B3 and B5: the inner boundary file hides nothing of the
        // outer workspace, so the outer hubs still govern the project.
        let fs = Fake::lay(
            "/home/u/src/repo/MODULE.bazel
             /home/u/src/repo/svc/WORKSPACE.bazel
             /home/u/src/repo/svc/api/REPO.bazel",
        );
        assert_eq!(
            fs.probe("/home/u/src/repo/svc/api"),
            Probe::Nested(vec![
                root("/home/u/src/repo/svc/api", "", 2),
                root("/home/u/src/repo/svc", "api", 1),
                root(REPO, "svc/api", 0),
            ])
        );
        // A project beside the inner roots is governed by the outer one.
        assert_eq!(
            fs.probe("/home/u/src/repo/lib"),
            Probe::Workspace(root(REPO, "lib", 0))
        );
    }

    #[test]
    fn a_boundary_file_is_what_the_bazel_client_takes_for_one() {
        for name in BOUNDARY_FILES {
            for (entry, is_root, follows) in [
                ("", true, 0),
                // `workspace/` on a case-insensitive disk.
                ("/", false, 0),
                (" -> file", true, 1),
                (" -> dir", false, 1),
                (" -> gone", false, 1),
                // Where socket-patch reads, a name it cannot judge is a
                // root: the reader then says what it could not read.
                (" ?", true, 0),
                (" -> ?", true, 1),
            ] {
                let fs = Fake::lay(&format!("{REPO}/{name}{entry}"));
                let want = match is_root {
                    true => Probe::Workspace(root(REPO, "", 0)),
                    false => Probe::NotBazel,
                };
                assert_eq!(fs.probe(REPO), want, "{name}{entry}");
                let followed = fs.calls.borrow().iter().filter(|call| call.0).count();
                assert_eq!(followed, follows, "{name}{entry}");
            }
        }
    }

    #[test]
    fn a_marker_above_the_boundary_needs_a_second_signal() {
        let marker = "/home/u/src/WORKSPACE";
        // A stray file is reported and decides nothing else.
        assert_eq!(Fake::lay(marker).probe(REPO), outside(marker, false));
        for (beside, confirmed) in [
            (".bazelversion", true),
            (".bazelrc", true),
            (".bazelrc -> file", true),
            ("MODULE.bazel.lock", true),
            // A link whose target `clean --expunge` removed still counts.
            ("bazel-out -> gone", true),
            ("bazel-bin -> dir", true),
            ("bazel-testlogs -> dir", true),
            // The execroot link is named after the directory.
            ("bazel-src -> dir", true),
            ("bazel-repo -> dir", false),
            // A directory with a link's name, a directory with a file's
            // name, a dead link, an unrelated file.
            ("bazel-bin/", false),
            (".bazelrc/", false),
            (".bazelversion -> gone", false),
            ("BUILD.bazel", false),
            // Above the boundary only what was seen counts.
            (".bazelrc ?", false),
            ("bazel-out ?", false),
        ] {
            let fs = Fake::lay(&format!("{marker}\n/home/u/src/{beside}"));
            assert_eq!(fs.probe(REPO), outside(marker, confirmed), "{beside}");
        }
        // The marker is the first boundary file in Bazel's order.
        let fs = Fake::lay(&format!("{marker}\n/home/u/src/REPO.bazel"));
        assert_eq!(fs.probe(REPO), outside("/home/u/src/REPO.bazel", false));
    }

    #[test]
    fn a_failed_stat_above_the_boundary_is_not_a_root() {
        // A sandbox that denies metadata outside the checkout.
        let denied = BOUNDARY_FILES.map(|name| format!("/home/u/src/{name} ?"));
        assert_eq!(Fake::lay(&denied.join("\n")).probe(REPO), Probe::NotBazel);
        // A marker that was seen behind names that were not.
        let fs = Fake::lay(
            "/home/u/src/MODULE.bazel ?
             /home/u/src/WORKSPACE.bazel -> file
             /home/u/src/.bazelrc",
        );
        assert_eq!(fs.probe(REPO), outside("/home/u/src/WORKSPACE.bazel", true));
    }

    #[test]
    fn the_home_directory_and_what_is_above_it_are_never_examined() {
        let fs = Fake::lay(
            "/home/u/WORKSPACE
             /home/u/.bazelrc
             /home/MODULE.bazel
             /home/.bazelversion",
        );
        assert_eq!(fs.probe(REPO), Probe::NotBazel);
        let examined = |fs: &Fake, dir: &str| {
            let calls = fs.calls.borrow();
            calls
                .iter()
                .any(|call| call.1.parent() == Some(Path::new(dir)))
        };
        assert!(examined(&fs, "/home/u/src"));
        assert!(!examined(&fs, HOME) && !examined(&fs, "/home") && !examined(&fs, "/"));
        // With no home directory to stop at, the walk ends at the top.
        let mut memo = Memo::default();
        let repo = Path::new(REPO);
        let got = survey_with(&fs, &mut memo, repo, Some(repo), None);
        assert_eq!(got.probe(), outside("/home/u/WORKSPACE", true));
        assert!(!examined(&fs, "/home"), "a confirmed root ends the walk");
    }

    #[test]
    fn a_confirmed_root_above_outranks_the_roots_inside_and_a_stray_one_does_not() {
        let stray = "/home/u/src/repo/MODULE.bazel\n/home/u/src/WORKSPACE";
        let inner = root(REPO, "svc", 0);
        let got = Fake::lay(stray).survey("/home/u/src/repo/svc");
        assert_eq!(got.probe(), Probe::Workspace(inner.clone()));
        let marker = PathBuf::from("/home/u/src/WORKSPACE");
        let confirmed = false;
        assert_eq!(got.above, Some(MarkerAbove { marker, confirmed }));

        // The outer hubs cannot be read and still govern the project. The
        // inner roots stay in the survey, for the remedy.
        let got = Fake::lay(&format!("{stray}\n/home/u/src/.bazelversion"))
            .survey("/home/u/src/repo/svc");
        assert_eq!(got.probe(), outside("/home/u/src/WORKSPACE", true));
        assert_eq!(got.roots, [inner]);

        // A stray marker hides nothing above it, as a nested boundary
        // file hides nothing: the workspace two levels up is found.
        let (repo, deep) = (Path::new("/w/mono/x/repo"), "/w/mono/x/repo/a");
        let fs = Fake::lay(
            "/w/mono/x/WORKSPACE
             /w/mono/MODULE.bazel
             /w/mono/bazel-mono -> dir
             /w/REPO.bazel",
        );
        let mut memo = Memo::default();
        let got = survey_with(&fs, &mut memo, Path::new(deep), Some(repo), None);
        assert_eq!(got.probe(), outside("/w/mono/MODULE.bazel", true));
        // Two stray markers: the nearest is the one reported.
        let fs = Fake::lay("/w/mono/x/WORKSPACE\n/w/REPO.bazel");
        let got = survey_with(&fs, &mut Memo::default(), Path::new(deep), Some(repo), None);
        assert_eq!(got.probe(), outside("/w/mono/x/WORKSPACE", false));
    }

    #[test]
    fn a_run_with_no_boundary_reads_every_ancestor() {
        let fs = Fake::lay("/home/u/src/repo/MODULE.bazel\n/home/WORKSPACE\n/home/u/.bazelrc");
        let mut memo = Memo::default();
        let got = survey_with(&fs, &mut memo, Path::new(REPO), None, Some(Path::new(HOME)));
        assert_eq!(got.above, None);
        assert_eq!(
            got.roots,
            [root(REPO, "", 4), root("/home", "u/src/repo", 1)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_project_the_pure_layer_cannot_name_is_refused_at_the_outermost_root() {
        use std::os::unix::ffi::OsStrExt as _;
        let latin1 = Path::new(REPO).join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
        let (repo, home) = (Path::new(REPO), Path::new(HOME));
        let survey = |fs: &Fake, project: &Path| {
            survey_with(fs, &mut Memo::default(), project, Some(repo), Some(home))
        };
        // `project_rel` is a string, and a lossy one would name another
        // directory. Run from the root, the same walk has nothing to name.
        let mut fs = Fake::lay("/home/u/src/repo/MODULE.bazel");
        let refused = outside("/home/u/src/repo/MODULE.bazel", true);
        assert_eq!(survey(&fs, &latin1.join("api")).probe(), refused);
        // With a root of its own below that segment the project has a
        // name there, and still none under the outer root.
        fs.names.insert(latin1.join("WORKSPACE"), Seen::File);
        assert_eq!(survey(&fs, &latin1.join("api")).probe(), refused);
        // Such a segment above every root is in no relative path.
        fs.names.remove(Path::new("/home/u/src/repo/MODULE.bazel"));
        let inner = RootRef {
            root: latin1.clone(),
            project_rel: "api".into(),
            boundary_levels: 1,
        };
        assert_eq!(survey(&fs, &latin1.join("api")).roots, [inner]);
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }

    /// A scratch directory, resolved, and a probe whose walk above a
    /// boundary ends below it: nothing of this machine is in a result.
    fn scratch() -> (tempfile::TempDir, PathBuf, RootProbe) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let run = RootProbe::with_home(Some(dir.clone()));
        (tmp, dir, run)
    }

    #[test]
    fn the_disk_walk_ends_at_the_checkout_and_one_probe_is_one_run() {
        let (_tmp, dir, run) = scratch();
        let repo = dir.join("outer/repo");
        let api = repo.join("svc/api");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&api).unwrap();
        // A directory with a boundary file's name.
        std::fs::create_dir_all(repo.join("svc/WORKSPACE")).unwrap();
        touch(&repo.join("MODULE.bazel"));
        touch(&dir.join("outer/WORKSPACE"));
        let at = |project_rel: &str| {
            Probe::Workspace(RootRef {
                root: repo.clone(),
                project_rel: project_rel.into(),
                boundary_levels: 0,
            })
        };
        assert_eq!(run.probe(&api), at("svc/api"));
        assert_eq!(boundary_file_in(&repo), Some("MODULE.bazel"));
        assert_eq!(boundary_file_in(&repo.join("svc")), None);
        let boundary = ReadBoundary::of(ReadScope::Workspace, &api);
        assert_eq!(boundary.root(), Some(repo.as_path()));
        let marker = dir.join("outer/WORKSPACE");
        let stray = MarkerAbove {
            marker: marker.clone(),
            confirmed: false,
        };
        assert_eq!(run.survey(&api, &boundary).above, Some(stray));
        // A project directory that does not exist yet.
        let new = repo.join("svc/new/dir");
        assert_eq!(run.probe(&new), at("svc/new/dir"));
        // A boundary that does not hold the project permits no read above
        // the project, so the checkout's own root is only a marker.
        let elsewhere = ReadBoundary::Workspace {
            root: dir.join("elsewhere"),
        };
        let got = run.survey(&api, &elsewhere);
        let own = repo.join("MODULE.bazel");
        assert_eq!(
            got.probe(),
            Probe::RootOutsideBoundary {
                marker: own,
                confirmed: false
            }
        );

        // The outer workspace gets a version pin. The run that has
        // judged the directory keeps its answer; the next run sees it.
        touch(&dir.join("outer/.bazelversion"));
        assert_eq!(run.probe(&api), at("svc/api"));
        let next = RootProbe::with_home(Some(dir.clone()));
        let confirmed = true;
        assert_eq!(
            next.probe(&api),
            Probe::RootOutsideBoundary { marker, confirmed }
        );
        // One probe serves every task of a run.
        fn shared<T: Send + Sync>(_: &T) {}
        shared(&next);
    }

    #[cfg(unix)]
    #[test]
    fn the_disk_follows_links_as_the_bazel_client_does() {
        use std::os::unix::fs::symlink;
        let (_tmp, dir, run) = scratch();
        let ws = dir.join("ws");
        std::fs::create_dir_all(ws.join("a/b/c")).unwrap();
        touch(&ws.join("shared/MODULE.bazel"));
        symlink(ws.join("shared/MODULE.bazel"), ws.join("a/MODULE.bazel")).unwrap();
        symlink(ws.join("shared"), ws.join("a/b/WORKSPACE")).unwrap();
        symlink(ws.join("nowhere"), ws.join("a/b/c/WORKSPACE.bazel")).unwrap();
        // Bazel resolves its working directory before it looks upward, so
        // a project reached through a link is governed where it really is.
        symlink(ws.join("a/b/c"), dir.join("alias")).unwrap();
        assert_eq!(boundary_file_in(&ws.join("a")), Some("MODULE.bazel"));
        assert_eq!(boundary_file_in(&ws.join("a/b")), None);
        assert_eq!(boundary_file_in(&ws.join("a/b/c")), None);
        let boundary = ReadBoundary::Workspace { root: ws.clone() };
        let got = run.survey(&dir.join("alias"), &boundary);
        let found = RootRef {
            root: ws.join("a"),
            project_rel: "b/c".into(),
            boundary_levels: 1,
        };
        assert_eq!((got.roots, got.above), (vec![found], None));
    }

    #[test]
    fn the_facade_probe_finds_the_root_of_a_checkout() {
        let (_tmp, dir, _) = scratch();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        touch(&dir.join("WORKSPACE.bazel"));
        touch(&dir.join("pkg/BUILD.bazel"));
        // What lies above the scratch directory is this machine's, so
        // only the half below the boundary is asserted.
        match crate::bazel::probe(&dir.join("pkg")) {
            Probe::Workspace(found) => {
                assert_eq!((found.root, found.project_rel.as_str()), (dir, "pkg"));
            }
            other => assert!(
                matches!(
                    other,
                    Probe::RootOutsideBoundary {
                        confirmed: true,
                        ..
                    }
                ),
                "{other:?}"
            ),
        }
        // A path that names nothing cannot be placed, and is refused.
        let nowhere = RootProbe::new().survey(Path::new(""), &ReadBoundary::Unbounded);
        assert_eq!(
            nowhere.probe(),
            Probe::RootOutsideBoundary {
                marker: PathBuf::new(),
                confirmed: true
            }
        );
    }
}
