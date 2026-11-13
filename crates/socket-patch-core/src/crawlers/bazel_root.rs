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
//! The read boundary is the one every other upward lookup has
//! (`repo_root::upward_bound`): the checkout around the project, and none
//! outside any checkout. With none, every ancestor may be read, so a root
//! above the project is its workspace and not a marker out of reach. A
//! stray `~/WORKSPACE` above a project outside any checkout is such a
//! root: Bazel run in that project takes it too, and the reader that
//! follows reads the file and decides what it governs.
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
//! What a failed `stat` means depends on where the directory lies:
//!
//! - at or below the boundary, a name that cannot be judged counts as a
//!   boundary file. The reader that follows says the file is unreadable,
//!   and unreadable is not absent;
//! - above it, only a name that was seen counts, as in
//!   `ReadBoundary::marker_above`, which every other "a governing file
//!   lies above the repository" check uses. A sandbox that denies
//!   metadata outside the checkout fails every `stat` there, and taking
//!   that for a Bazel root would refuse every project run inside it;
//! - with no boundary, such a name counts at the project directory and
//!   nowhere above it: the same sandbox would make a root of every
//!   ancestor.
//!
//! The walk goes to the top of the disk on either side of the boundary.
//! It does not end below the home directory, where `marker_above` ends,
//! and neither does Bazel's (`workspace_layout.cc:45-56`, the same in
//! 7.7.2), so a workspace at the home directory or above it is found from
//! a checkout below it. The two differ at the last directory. Bazel tests
//! the filesystem root, on Windows the root of a drive, only when it is
//! the working directory: started anywhere below, its loop ends before
//! that directory (`workspace_layout.cc:53-54`). This walk tests it for
//! every project. A boundary file there is a root here, where Bazel run
//! in the project finds no workspace. It is an outer root as the first
//! paragraph has it: Bazel run at the top of the disk tests its working
//! directory first and takes it (line 50 of that file; read from the
//! source, no probe ran Bazel there), and every directory below is then
//! inside its workspace.
//!
//! What keeps a stray `~/WORKSPACE` from refusing anything is
//! the second signal, and at the home directory `.bazelrc` is not one:
//! there it is the user's own rc file, which Bazel reads wherever it
//! runs. The cost is a home directory in which Bazel once ran
//! (`~/WORKSPACE` beside `~/MODULE.bazel.lock` or a `~/bazel-*` link): it
//! is a confirmed root for every checkout below it, so a refusal has to
//! name the marker file.
//!
//! `marker_above` is not used for the walk above the boundary. It ends
//! below the home directory, it takes a directory for a marker, it stops
//! at the nearest marker, where a stray file must not hide the workspace
//! above it, and its calls cannot be counted by a test.

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

/// The workspace rc file. In the home directory the same name is the
/// user's own rc file, which says nothing about that directory.
const RC_FILE: &str = ".bazelrc";

/// Files that say a boundary file above the read boundary belongs to a
/// workspace somebody builds. An rc file and a version pin are written by
/// hand, the lock by Bazel 7 and later on its first build.
const SIGNAL_FILES: [&str; 3] = [".bazelversion", RC_FILE, MODULE_LOCK];

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
/// them and keep this machine's files out of a result, and it has no
/// third method: nothing here can read.
trait StatFs: std::fmt::Debug {
    /// `symlink_metadata`: the name itself.
    fn lstat(&self, path: &Path) -> Seen;
    /// `metadata`: what a link leads to. Asked only of a link.
    fn stat(&self, path: &Path) -> Seen;
}

#[derive(Debug)]
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
/// Only what was seen counts, and in the home directory the rc file is
/// not asked about (module docs).
fn second_signal(fs: &dyn StatFs, dir: &Path, is_home: bool) -> bool {
    let own_link = dir.file_name().map(|name| {
        let mut link = OsString::from("bazel-");
        link.push(name);
        link
    });
    let mut links = SIGNAL_LINKS.iter().map(OsString::from).chain(own_link);
    let own_rc = |name: &&str| is_home && *name == RC_FILE;
    let mut files = SIGNAL_FILES.iter().filter(|name| !own_rc(name));
    // A link is not followed: `bazel clean --expunge` removes the target
    // and leaves the link, which still says Bazel ran here.
    files.any(|name| is_file(fs, &dir.join(name)) == Some(true))
        || links.any(|name| fs.lstat(&dir.join(name)) == Seen::Link)
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

    /// One run has one home directory, so the answer is kept by `dir`.
    fn confirmed(&mut self, fs: &dyn StatFs, dir: &Path, home: Option<&Path>) -> bool {
        if let Some(known) = self.confirmed.get(dir) {
            return *known;
        }
        let confirmed = second_signal(fs, dir, home == Some(dir));
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
    /// somebody builds and not a stray file. In the home directory
    /// `.bazelrc` is the user's own rc file and is no such sign.
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
/// ancestor may be read), and `home` is the user's home directory, whose
/// `.bazelrc` confirms nothing: a stray `~/WORKSPACE` beside it is
/// reported and governs nothing. Every ancestor is examined, the home
/// directory and what is above it included (module docs).
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
        let marks = memo.marks(fs, dir);
        // With no boundary this loop reaches the top of the disk, and a
        // name that cannot be judged counts only where the run was sent.
        let name = match floor.is_some() || dir == project {
            true => marks.inside(),
            false => marks.seen,
        };
        if let Some(name) = name {
            found.push((dir, name));
        }
        if floor == Some(dir) {
            break;
        }
    }
    let mut above: Option<MarkerAbove> = None;
    for dir in dirs {
        let Some(name) = memo.marks(fs, dir).seen else {
            continue;
        };
        let confirmed = memo.confirmed(fs, dir, home);
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

/// The empty path is the working directory, as it is to
/// `ReadBoundary::of` and to a caller that took the parent of a bare file
/// name.
fn or_cwd(dir: &Path) -> &Path {
    match dir.as_os_str().is_empty() {
        true => Path::new("."),
        false => dir,
    }
}

/// `project_dir` absolute and resolved the way `repo_root` resolves the
/// boundary it is compared with. A directory that exists is resolved by
/// the OS. One that does not is resolved level by level: each level that
/// exists is resolved before the next name applies, so a `..` climbs from
/// where a link leads, and what lies past the deepest existing level is
/// folded as written. The only error is a relative path when the working
/// directory cannot be read.
fn resolve(project_dir: &Path) -> std::io::Result<PathBuf> {
    let abs = std::path::absolute(or_cwd(project_dir))?;
    if let Ok(real) = std::fs::canonicalize(&abs) {
        return Ok(real);
    }
    let mut out = PathBuf::new();
    for part in abs.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => out.push(part.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if let Ok(real) = std::fs::canonicalize(&out) {
                    out = real;
                }
            }
        }
    }
    Ok(out)
}

/// The probe for one run. It remembers every directory it judged, so make
/// one per run: a boundary file created later is not seen by it.
#[derive(Debug)]
pub struct RootProbe {
    fs: Box<dyn StatFs + Send + Sync>,
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
        Self::on(Box::new(Disk), repo_root::home())
    }

    /// A probe of the disk `fs` for the user whose home directory is
    /// `home`.
    fn on(fs: Box<dyn StatFs + Send + Sync>, home: Option<PathBuf>) -> Self {
        Self {
            fs,
            home,
            memo: Mutex::default(),
        }
    }

    fn memo(&self) -> MutexGuard<'_, Memo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The roots that govern `project_dir` in a project run. Its read
    /// boundary is the one every upward lookup has
    /// ([`ReadBoundary::upward`]): the checkout around the project, and
    /// none outside any checkout, where the root above a project is its
    /// workspace (module docs). The boundary is found per project, so a
    /// root above a nested checkout or a submodule stays out of reach for
    /// a project inside it. Finding it costs the `.git` stats every
    /// command already pays; a caller that holds the boundary calls
    /// [`RootProbe::survey`] and pays for the walk alone.
    pub fn probe(&self, project_dir: &Path) -> Probe {
        if let Some(known) = self.memo().probes.get(project_dir) {
            return known.clone();
        }
        let boundary = ReadBoundary::upward(ReadScope::Workspace, or_cwd(project_dir));
        let probe = self.survey(project_dir, &boundary).probe();
        let key = project_dir.to_path_buf();
        self.memo().probes.insert(key, probe.clone());
        probe
    }

    /// The roots at or below `boundary` and the marker above it. A relative
    /// `project_dir` is read from the working directory, and the empty
    /// path is that directory. The roots are reported resolved, because
    /// Bazel looks for its workspace from the resolved working directory.
    /// A project directory that does not exist yet is judged by where it
    /// would be created, through a link or a `..` in its spelling too.
    pub fn survey(&self, project_dir: &Path, boundary: &ReadBoundary) -> Survey {
        let Ok(project) = resolve(project_dir) else {
            return Survey::refusing(or_cwd(project_dir).to_path_buf());
        };
        let floor = match boundary {
            ReadBoundary::Unbounded => None,
            ReadBoundary::Workspace { root } if root.is_absolute() && project.starts_with(root) => {
                Some(root.as_path())
            }
            // A boundary that does not hold the project permits no read
            // above the project. Neither does one that is not absolute,
            // which no ancestor of the project equals: every path starts
            // with the empty one.
            ReadBoundary::Workspace { .. } => Some(project.as_path()),
        };
        // Held across the stats: two tasks that walked the same ancestors
        // at once would only repeat them.
        let mut memo = self.memo();
        survey_with(&*self.fs, &mut memo, &project, floor, self.home.as_deref())
    }
}

/// The boundary file that makes `dir` itself a Bazel root, when one is
/// seen there or a name there cannot be judged, as for a directory at or
/// below the read boundary: the test a walker makes of a directory it has
/// entered, so that a root with no native lock beside it is still a
/// project, and one whose boundary file cannot be judged is not dropped
/// in silence. It looks neither up nor down and remembers nothing.
pub fn boundary_file_in(dir: &Path) -> Option<&'static str> {
    Marks::of(&Disk, dir).inside()
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
    #[derive(Debug, Default)]
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

        /// The survey of `project` outside any checkout, where the run
        /// has no boundary, for the same user.
        fn unbounded(&self, project: &str) -> Survey {
            let home = Path::new(HOME);
            let mut memo = Memo::default();
            survey_with(self, &mut memo, Path::new(project), None, Some(home))
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
        // An rc file is no boundary file, the user's own included, and
        // with no boundary file beside it none is asked about.
        let fs = Fake::lay(
            "/home/u/src/repo/svc/api/package.json
             /home/u/src/repo/.bazelrc
             /home/u/.bazelrc",
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
        // The directories from the project to the boundary, then every
        // one above it, the home directory and the top of the disk
        // included. No link is followed and the trait has no way to read.
        let walked = [
            "/home/u/src/repo/svc/api",
            "/home/u/src/repo/svc",
            REPO,
            "/home/u/src",
            HOME,
            "/home",
            "/",
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
    fn the_users_own_rc_file_confirms_nothing_in_the_home_directory() {
        // Bazel reads `~/.bazelrc` wherever it runs, so beside a stray
        // `~/WORKSPACE` the file says nothing about the home directory.
        // The marker is reported and refuses nothing.
        let (marker, rc) = ("/home/u/WORKSPACE", "/home/u/.bazelrc");
        for (beside, confirmed) in [
            (".bazelrc -> file", false),
            ("BUILD.bazel", false),
            // Bazel ran there, or somebody pinned a version for it.
            (".bazelversion", true),
            ("MODULE.bazel.lock", true),
            ("bazel-out -> gone", true),
            ("bazel-u -> dir", true),
        ] {
            let fs = Fake::lay(&format!("{marker}\n{rc}\n/home/u/{beside}"));
            assert_eq!(fs.probe(REPO), outside(marker, confirmed), "{beside}");
        }
        // Anywhere else the name is a workspace's rc file: it confirms
        // when the home directory is another one, lies inside the
        // workspace, or is not known.
        let fs = Fake::lay(&format!("{marker}\n{rc}"));
        let repo = Path::new(REPO);
        for home in [Some("/home/v"), Some("/home/u/src"), None] {
            let mut memo = Memo::default();
            let got = survey_with(&fs, &mut memo, repo, Some(repo), home.map(Path::new));
            assert_eq!(got.probe(), outside(marker, true), "{home:?}");
        }
    }

    #[test]
    fn a_root_at_or_above_the_home_directory_is_found_from_a_checkout_below_it() {
        // Bazel's walk does not end at the home directory, so a workspace
        // there governs a nested checkout or a submodule below it.
        let fs = Fake::lay(
            "/home/u/MODULE.bazel
             /home/u/MODULE.bazel.lock
             /home/u/.bazelrc",
        );
        assert_eq!(fs.probe(REPO), outside("/home/u/MODULE.bazel", true));
        // A stray marker in the home directory hides nothing above it,
        // and the rc file up there is not the user's own.
        let fs = Fake::lay(
            "/home/u/WORKSPACE
             /home/u/.bazelrc
             /home/MODULE.bazel
             /home/.bazelrc",
        );
        assert_eq!(fs.probe(REPO), outside("/home/MODULE.bazel", true));
        let examined = |dir: &str| {
            let calls = fs.calls.borrow();
            calls
                .iter()
                .any(|call| call.1.parent() == Some(Path::new(dir)))
        };
        assert!(examined("/home/u/src") && examined(HOME) && examined("/home"));
        assert!(!examined("/"), "a confirmed root ends the walk");
        // A home directory inside the workspace ends nothing either.
        let fs = Fake::lay("/home/u/src/MODULE.bazel\n/home/u/src/.bazelversion");
        let (repo, home) = (Path::new(REPO), Path::new("/home/u/src/.home"));
        let got = survey_with(&fs, &mut Memo::default(), repo, Some(repo), Some(home));
        assert_eq!(got.probe(), outside("/home/u/src/MODULE.bazel", true));
    }

    #[test]
    fn a_root_at_the_top_of_the_disk_is_found_from_every_project_below_it() {
        // Where this walk and Bazel's differ (module docs). Started below
        // the filesystem root, Bazel never tests that directory and finds
        // no workspace. Started there, it takes the root and every
        // directory below, so the probe reports it like any outer root.
        let top = "/MODULE.bazel";
        let stray = Fake::lay(top);
        assert_eq!(stray.probe(REPO), outside(top, false));
        // The top of the disk has no name, so no link is named after it:
        // the marker, the signal files and the default links are asked.
        let at_top = |call: &&(bool, PathBuf)| call.1.parent() == Some(Path::new("/"));
        let asked = stray.calls.borrow().iter().filter(at_top).count();
        assert_eq!(asked, 1 + SIGNAL_FILES.len() + SIGNAL_LINKS.len());
        let fs = Fake::lay(&format!("{top}\n/.bazelversion"));
        assert_eq!(fs.probe(REPO), outside(top, true));
        // Outside any checkout it is the project's workspace, and the
        // boundary is that directory.
        let found = Probe::Workspace(root("/", "srv/app", 0));
        assert_eq!(fs.unbounded("/srv/app").probe(), found);
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

    #[test]
    fn outside_a_checkout_the_root_above_the_project_is_its_workspace() {
        // A project below a home directory that is a checkout and a Bazel
        // root. Git's home rule finds no checkout from the project, so
        // the run has no boundary, and the root is the one Bazel takes.
        let fs = Fake::lay(
            "/home/u/MODULE.bazel
             /home/u/MODULE.bazel.lock
             /home/u/.bazelrc",
        );
        let found = Probe::Workspace(root(HOME, "svc/api", 2));
        let got = fs.unbounded("/home/u/svc/api");
        assert_eq!((got.probe(), got.above), (found.clone(), None));
        // A stray `~/WORKSPACE` above a project outside any checkout is
        // such a root too. The reader that reads it decides what it
        // governs.
        let fs = Fake::lay("/home/u/WORKSPACE\n/home/u/.bazelrc");
        assert_eq!(fs.unbounded("/home/u/svc/api").probe(), found);
    }

    #[test]
    fn with_no_boundary_a_name_that_cannot_be_judged_counts_only_at_the_project() {
        // A sandbox that denies metadata outside the project. The walk
        // goes to the top of the disk, and no ancestor is a root for it.
        let project = "/home/u/work/app";
        let denied: Vec<String> = Path::new(project)
            .ancestors()
            .skip(1)
            .flat_map(|dir| BOUNDARY_FILES.map(|name| dir.join(name)))
            .map(|path| format!("{} ?", path.display()))
            .collect();
        let denied = denied.join("\n");
        let got = Fake::lay(&denied).unbounded(project);
        assert_eq!((got.probe(), got.above), (Probe::NotBazel, None));
        // The project is where the run was sent: unreadable is not
        // absent there.
        let fs = Fake::lay(&format!("{denied}\n{project}/WORKSPACE ?"));
        let own = root(project, "", 4);
        assert_eq!(fs.unbounded(project).probe(), Probe::Workspace(own));
        // A name that was seen above it counts behind those that were
        // not.
        let fs = Fake::lay(&format!("{denied}\n/home/u/work/WORKSPACE"));
        let seen = root("/home/u/work", "app", 3);
        assert_eq!(fs.unbounded(project).probe(), Probe::Workspace(seen));
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

    /// The disk below one directory. Every name outside it is absent, so
    /// nothing of this machine is in a result.
    #[derive(Debug)]
    struct DiskBelow(PathBuf);

    impl StatFs for DiskBelow {
        fn lstat(&self, path: &Path) -> Seen {
            match path.starts_with(&self.0) {
                true => Disk.lstat(path),
                false => Seen::Absent,
            }
        }

        fn stat(&self, path: &Path) -> Seen {
            match path.starts_with(&self.0) {
                true => Disk.stat(path),
                false => Seen::Absent,
            }
        }
    }

    /// A new run that sees the disk below `dir` and nothing else.
    fn below(dir: &Path) -> RootProbe {
        RootProbe::on(Box::new(DiskBelow(dir.to_path_buf())), None)
    }

    /// A scratch directory, resolved, and a run that sees nothing else.
    fn scratch() -> (tempfile::TempDir, PathBuf, RootProbe) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let run = below(&dir);
        (tmp, dir, run)
    }

    fn at(root: &Path, project_rel: &str) -> Probe {
        Probe::Workspace(RootRef {
            root: root.to_path_buf(),
            project_rel: project_rel.into(),
            boundary_levels: 0,
        })
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
        assert_eq!(run.probe(&api), at(&repo, "svc/api"));
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
        assert_eq!(run.probe(&new), at(&repo, "svc/new/dir"));
        // A boundary that does not hold the project permits no read above
        // the project, so the checkout's own root is only a marker. The
        // empty path is such a boundary: `ReadBoundary::of` returns it
        // for the working directory, and no ancestor is equal to it.
        for root in [dir.join("elsewhere"), PathBuf::new()] {
            let got = run.survey(&api, &ReadBoundary::Workspace { root });
            let own = MarkerAbove {
                marker: repo.join("MODULE.bazel"),
                confirmed: false,
            };
            assert_eq!((got.roots, got.above), (vec![], Some(own)));
        }

        // The outer workspace gets a version pin. The run that has
        // judged the directory keeps its answer; the next run sees it.
        touch(&dir.join("outer/.bazelversion"));
        assert_eq!(run.probe(&api), at(&repo, "svc/api"));
        let next = below(&dir);
        let confirmed = true;
        assert_eq!(
            next.probe(&api),
            Probe::RootOutsideBoundary { marker, confirmed }
        );
        // One probe serves every task of a run.
        fn shared<T: Send + Sync>(_: &T) {}
        shared(&next);
    }

    #[test]
    fn outside_a_checkout_the_disk_walk_reads_the_root_above_the_project() {
        let (_tmp, dir, run) = scratch();
        let mono = dir.join("mono");
        let api = mono.join("svc/api");
        std::fs::create_dir_all(&api).unwrap();
        touch(&mono.join("MODULE.bazel"));
        touch(&mono.join(".bazelversion"));
        // No `.git` below the scratch directory. Its ancestors are this
        // machine's: one of them may be a checkout, which is then the
        // boundary, with the root inside it. So the root and the project's
        // place under it are asserted, and the distance to the boundary
        // is not.
        let placed = |found: &RootRef| (found.root.clone(), found.project_rel.clone());
        let want = |project_rel: &str| (mono.clone(), project_rel.to_string());
        for (project, project_rel) in [(&api, "svc/api"), (&mono, "")] {
            let Probe::Workspace(found) = run.probe(project) else {
                panic!("{:?}", run.probe(project));
            };
            assert_eq!(placed(&found), want(project_rel));
        }
        // The same on the whole disk, where only the nearest root is
        // known to be the scratch directory's.
        let boundary = ReadBoundary::upward(ReadScope::Workspace, &api);
        let survey = RootProbe::new().survey(&api, &boundary);
        assert_eq!(survey.roots.first().map(placed), Some(want("svc/api")));
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

        // A link that leads back to itself cannot be judged, which is not
        // absent: the walker's test and the probe both keep the root.
        std::fs::create_dir_all(ws.join("loop")).unwrap();
        symlink("MODULE.bazel", ws.join("loop/MODULE.bazel")).unwrap();
        assert_eq!(boundary_file_in(&ws.join("loop")), Some("MODULE.bazel"));
        let found = RootRef {
            root: ws.join("loop"),
            project_rel: String::new(),
            boundary_levels: 1,
        };
        assert_eq!(run.survey(&ws.join("loop"), &boundary).roots, [found]);
    }

    #[cfg(unix)]
    #[test]
    fn a_convenience_link_on_disk_confirms_and_a_directory_of_its_name_does_not() {
        use std::os::unix::fs::symlink;
        let (_tmp, dir, run) = scratch();
        let outside = |outer: &str, confirmed: bool| Probe::RootOutsideBoundary {
            marker: dir.join(outer).join("WORKSPACE"),
            confirmed,
        };
        for outer in ["built", "plain"] {
            std::fs::create_dir_all(dir.join(outer).join("repo/.git")).unwrap();
            touch(&dir.join(outer).join("WORKSPACE"));
        }
        // What `bazel clean --expunge` leaves: the link, and no target.
        symlink(dir.join("built/gone"), dir.join("built/bazel-out")).unwrap();
        std::fs::create_dir(dir.join("plain/bazel-bin")).unwrap();
        assert_eq!(run.probe(&dir.join("built/repo")), outside("built", true));
        assert_eq!(run.probe(&dir.join("plain/repo")), outside("plain", false));
    }

    #[cfg(unix)]
    #[test]
    fn a_project_that_does_not_exist_yet_is_placed_where_it_would_be_created() {
        use std::os::unix::fs::symlink;
        let (_tmp, dir, run) = scratch();
        let repo = dir.join("real/s2/repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("svc")).unwrap();
        touch(&repo.join("MODULE.bazel"));
        touch(&repo.join(".bazelrc"));
        symlink(dir.join("real"), dir.join("link")).unwrap();
        symlink(repo.join("svc"), dir.join("svc-link")).unwrap();
        for (project, project_rel) in [
            ("real/s2/repo/new/dir", "new/dir"),
            // Below a linked ancestor, as under `/tmp` and `/var` on macOS.
            ("link/s2/repo/new/dir", "new/dir"),
            ("real/s2/repo/svc/../new", "new"),
            ("real/s2/repo/new/./dir/..", "new"),
            // `..` climbs from where the link leads, not from its name.
            ("svc-link/../new", "new"),
            // A directory that exists, by the same spellings.
            ("link/s2/repo/svc", "svc"),
            ("svc-link/../svc", "svc"),
        ] {
            let got = run.probe(&dir.join(project));
            assert_eq!(got, at(&repo, project_rel), "{project}");
        }
    }

    #[test]
    fn the_facade_probe_finds_the_root_of_a_checkout() {
        let (_tmp, dir, _) = scratch();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        touch(&dir.join("WORKSPACE.bazel"));
        touch(&dir.join("pkg/BUILD.bazel"));
        // What lies above the scratch directory is this machine's. A
        // confirmed root there outranks the one below, and its marker is
        // not in the scratch directory.
        match crate::bazel::probe(&dir.join("pkg")) {
            Probe::Workspace(found) => {
                assert_eq!((found.root, found.project_rel.as_str()), (dir, "pkg"));
            }
            Probe::RootOutsideBoundary {
                marker,
                confirmed: true,
            } => assert!(!marker.starts_with(&dir), "{marker:?}"),
            other => panic!("{other:?}"),
        }
        // A checkout with no boundary file has no root, whatever lies
        // above it.
        let (_tmp, plain, _) = scratch();
        std::fs::create_dir_all(plain.join(".git")).unwrap();
        touch(&plain.join("pkg/package.json"));
        match crate::bazel::probe(&plain.join("pkg")) {
            Probe::NotBazel => {}
            Probe::RootOutsideBoundary { marker, .. } => {
                assert!(!marker.starts_with(&plain), "{marker:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    // Other tests move the working directory, and they are `serial` too.
    #[test]
    #[serial_test::serial]
    fn the_empty_path_is_the_working_directory() {
        // What the parent of a bare file name is.
        let empty = Path::new("package.json").parent().unwrap();
        let here = std::env::current_dir().unwrap();
        let run = RootProbe::new();
        let unbounded = ReadBoundary::Unbounded;
        let want = run.survey(&here, &unbounded);
        // Not the answer that refuses every write: that one has a marker.
        assert_eq!(want.above, None);
        assert_eq!(run.survey(empty, &unbounded), want);
        assert_eq!(run.survey(Path::new("."), &unbounded), want);
        // The boundary of a project run is found from that directory too.
        assert_eq!(run.probe(empty), RootProbe::new().probe(&here));
    }
}
