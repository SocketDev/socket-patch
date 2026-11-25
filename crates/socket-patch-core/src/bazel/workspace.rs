//! The files of a Bazel workspace that say which locks its rules read, and
//! the calls in them: `MODULE.bazel` and the files it includes.
//!
//! [`Workspace::read`] reads those files through a view, so the same code
//! serves a checkout on disk ([`disk`]) and files held in memory, and
//! [`Workspace::tags`] answers "which calls of this tag of this module
//! extension does the workspace make". An extension is known by the module
//! and the `.bzl` file that define it, never by the name a file gives its
//! proxy: `go_sdk.from_file` and `go_deps.from_file` take the same `go_mod`.
//!
//! Nothing is evaluated ([`super::starlark`]), so an answer comes with
//! [`Doubt`]s: what could not be read, and so may hide a call or change
//! one. They are the workspace's ([`Workspace::doubts`]) and the answer's
//! own ([`Tags::doubts`]). With neither, the calls listed are the calls
//! of that tag which the files of a workspace Bazel accepts can make; the
//! tests name every way found so far to write one that would not be
//! listed. Whether a listed call runs is told by [`Call::whole`] alone,
//! and what Bazel is told outside these files (`--ignore_dev_dependency`,
//! an override on the command line) is not known here.
//!
//! The repositories of a `WORKSPACE` file are in no answer. Bazel 7 reads
//! that file beside `MODULE.bazel`, Bazel 8 only when it is told to and
//! Bazel 9 never, and which Bazel runs is not known here, so such a file
//! is reported apart ([`Workspace::legacy`]) with its calls: an answer
//! is certain only for a caller who finds none there or knows that Bazel
//! does not read the file. The `.bzl` files it loads are not read yet.
//!
//! Reading and each query look at every byte, call, binding and use a
//! bounded number of times, and what is read is bounded: [`MAX_BYTES`]
//! for a file, 256 files, 8 MiB of text and [`MAX_TOKENS`] tokens for a
//! workspace, 1,024 doubts for a list. Past a bound there is a doubt. So
//! no workspace takes long, and none makes a reader hold more than a few
//! tens of MiB. Two files Bazel builds are refused: one with a byte that
//! is not UTF-8, also in a comment, and one over a bound.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read};
use std::path::{Component, Path};

use super::starlark::{self, Bound, Call, File, How, Value, MAX_BYTES, MAX_TOKENS};
use crate::utils::fs::open_regular_file_sync;
use crate::utils::group_commit;
use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

/// How many files of one workspace are asked for, beside the names of its
/// `WORKSPACE` file, and how many bytes are read in all.
const MAX_FILES: usize = 256;
const MAX_TOTAL: usize = 8 << 20;
const OVER_TOTAL: &str = "the files of the workspace are larger than 8 MiB in all";

/// How many doubts a list keeps, the first ones: one more says nothing
/// new. And how long the label of an included file may be: no file
/// system has a longer path, and a doubt names the path of its file.
const MAX_DOUBTS: usize = 1024;
const MAX_LABEL: usize = 4096;

/// The names of the file of the older `WORKSPACE` system, in the order
/// Bazel takes one: `WorkspaceFileFunction` and `ExternalPackageHelper` at
/// 7.7.2 and 8.8.2. 9.3.2 has neither.
pub(super) const LEGACY: [&str; 3] = ["WORKSPACE.bzlmod", "WORKSPACE.bazel", "WORKSPACE"];

/// What [`disk`] says of a directory, a FIFO or a device.
const NOT_A_FILE: &str = "it is not a regular file";

/// What a view of the workspace has at a path. The path is from the Bazel
/// root, with `/` between its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Text(String),
    Absent,
    /// There is something, and this is why it is not text to read.
    Unreadable(String),
}

/// The view of the checkout at `root`, the Bazel root. It opens nothing
/// outside it: a path or a link that leads out is unreadable, like a
/// directory, a file that is not UTF-8 and one over [`MAX_BYTES`]. A file
/// that this run has written or removed and not committed yet
/// ([`group_commit`]) reads as the run left it. The root is resolved once
/// and each path when it is asked for, so this holds for a tree that no
/// other process changes meanwhile: one that swaps a directory for a link
/// between the two steps of a read is not seen.
pub fn disk(root: &Path) -> impl Fn(&str) -> Entry + '_ {
    disk_up_to(root, MAX_BYTES)
}

/// [`disk`] for files of up to `max` bytes: a lock that a tag names is
/// data, and can be larger than a file of Starlark.
pub fn disk_up_to(root: &Path, max: usize) -> impl Fn(&str) -> Entry + '_ {
    let top = std::fs::canonicalize(root);
    move |path| {
        let read = || -> std::io::Result<String> {
            let top = top.as_ref().map_err(|e| std::io::Error::from(e.kind()))?;
            let plain = |part| matches!(part, Component::Normal(_));
            if Path::new(path).components().all(plain) {
                if let Some(pending) = group_commit::read(&top.join(path)) {
                    return text(&pending?[..], max);
                }
            }
            let real = std::fs::canonicalize(top.join(path))?;
            if !real.starts_with(top) {
                return Err(std::io::Error::other("it leads out of the Bazel workspace"));
            }
            // Windows refuses to open a directory ("Access is denied"),
            // so the opener's own check never sees one there.
            if real.is_dir() {
                return Err(ErrorKind::InvalidInput.into());
            }
            text(open_regular_file_sync(&real)?.0, max)
        };
        let unreadable = |why: &str| Entry::Unreadable(why.to_string());
        match read() {
            Ok(text) => Entry::Text(text),
            Err(e) => match e.kind() {
                ErrorKind::NotFound | ErrorKind::NotADirectory => Entry::Absent,
                ErrorKind::InvalidData => unreadable("it is not UTF-8"),
                // The opener's own words for a directory or a FIFO name
                // the path on this machine.
                ErrorKind::InvalidInput => unreadable(NOT_A_FILE),
                _ => unreadable(&e.to_string()),
            },
        }
    }
}

/// The view of the files handed over in memory, for a project that is its
/// own Bazel root. It holds none for a user who switched the Bazel support
/// off ([`super::off`]): whatever judges a workspace from this view then
/// finds none, as [`super::bazel_root`] finds none on disk.
pub fn memory(project: &MemoryProject) -> impl Fn(&str) -> Entry + '_ {
    let off = super::off();
    move |path| match project.get(path).filter(|_| !off) {
        Some(MemoryEntry::Text(text)) => Entry::Text(text.to_string()),
        Some(_) => Entry::Unreadable("it was not handed in as text".to_string()),
        None => Entry::Absent,
    }
}

/// The text of `from`, read to its end. One byte more than `max` is
/// asked for: a file that grew since its size was taken is refused, not
/// cut there and read as if it were whole.
fn text(from: impl Read, max: usize) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    from.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        let why = format!("it is larger than {} MiB", max >> 20);
        return Err(std::io::Error::other(why));
    }
    String::from_utf8(bytes).map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
}

/// The index of `text`, taken from the `room` of its workspace, or the
/// line and the reason it has none.
fn indexed(text: &str, room: &mut usize) -> Result<File, (usize, String)> {
    let index = starlark::index_within(text.as_bytes(), room);
    index.map_err(|unreadable| (unreadable.line, unreadable.why.to_string()))
}

/// The repository a label is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repo {
    /// The main repository: no `@`, `@//` or `@@//`.
    Main,
    /// `@name//`: a name the workspace gives a repository. It is the main
    /// repository when it is the root module's own ([`Workspace::label`]).
    Apparent(String),
    /// `@@name//`: another repository by its canonical name.
    Canonical(String),
}

/// A label that names a file of a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub repo: Repo,
    /// Empty for the package at the root.
    pub package: String,
    pub name: String,
}

impl Label {
    /// `text` as a label written in `package`: `//pkg:name`, `//pkg` (the
    /// name is its last part), `:name` and `name` (in `package`), each
    /// after `@repo` or `@@repo` or not, and `@repo` alone. `None` when it
    /// is none of them or a part of it is empty, `.` or `..`: the path of
    /// a label never leaves its repository.
    pub fn parse(text: &str, package: &str) -> Option<Label> {
        let Some(at) = text.strip_prefix('@') else {
            return match text.strip_prefix("//") {
                Some(rest) => Self::absolute(Repo::Main, rest),
                None => Self::checked(Repo::Main, package, text.strip_prefix(':').unwrap_or(text)),
            };
        };
        let (canonical, at) = at.strip_prefix('@').map_or((false, at), |at| (true, at));
        let (repo, rest) = at
            .split_once("//")
            .map_or((at, None), |(repo, rest)| (repo, Some(rest)));
        let name = |b: u8| b.is_ascii_alphanumeric() || b"_-.+~".contains(&b);
        let repo = match repo {
            "" => Repo::Main,
            _ if !repo.bytes().all(name) => return None,
            _ if canonical => Repo::Canonical(repo.to_string()),
            _ => Repo::Apparent(repo.to_string()),
        };
        match rest {
            Some(rest) => Self::absolute(repo, rest),
            // `@repo` is `@repo//:repo`.
            None => Self::checked(repo, "", at),
        }
    }

    fn absolute(repo: Repo, rest: &str) -> Option<Label> {
        let last = rest.rsplit('/').next().unwrap_or(rest);
        let (package, name) = rest.split_once(':').unwrap_or((rest, last));
        Self::checked(repo, package, name)
    }

    fn checked(repo: Repo, package: &str, name: &str) -> Option<Label> {
        let part = |part: &str| {
            !matches!(part, "" | "." | "..")
                && !part.bytes().any(|b| b < b' ' || b":\\".contains(&b))
        };
        let sound = |path: &str| path.split('/').all(part);
        ((package.is_empty() || sound(package)) && sound(name)).then(|| Label {
            repo,
            package: package.to_string(),
            name: name.to_string(),
        })
    }

    /// The file the label names, from the root of its repository. A label
    /// can also name a target of a BUILD file, which is no file: whether
    /// the file exists is for the caller to ask.
    pub fn path(&self) -> String {
        match self.package.as_str() {
            "" => self.name.clone(),
            package => format!("{package}/{}", self.name),
        }
    }
}

/// Something that could not be read, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doubt {
    /// The file, from the Bazel root.
    pub file: String,
    /// The line, from 1; 0 when it is about the whole file.
    pub line: usize,
    pub why: String,
}

/// A module extension, by where its ruleset defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    /// The Bazel module of the ruleset: `rules_python`.
    pub module: &'a str,
    /// The `.bzl` file, as a label in that module:
    /// `//python/extensions:pip.bzl`.
    pub file: &'a str,
    /// The name of the extension in that file: `pip`.
    pub name: &'a str,
}

/// One call of a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a> {
    /// The file the call is in, from the Bazel root.
    pub file: &'a str,
    pub call: &'a Call,
    /// Whether the proxy it is called on was made with `dev_dependency =
    /// True`: Bazel then drops the call under `--ignore_dev_dependency`.
    /// `None` when that argument is not written as `True` or `False`. A
    /// file included with `dev_dependency`, which 9.3.2 takes, is not
    /// read at all.
    pub dev_dependency: Option<bool>,
    /// Whether that proxy was made with `isolate = True`: such a use has
    /// tags and repositories of its own, apart from the use of the
    /// extension that every module shares. `None` when that argument is
    /// not written as `True` or `False`.
    pub isolate: Option<bool>,
}

/// The calls of one tag of one extension in a workspace.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tags<'a> {
    pub calls: Vec<Tag<'a>>,
    /// The `use_repo` and `inject_repo` calls that take a proxy of the
    /// extension, by its name, as their first argument: each as a tag is,
    /// with the use its proxy was made by.
    pub handed: Vec<Tag<'a>>,
    /// Why there may be other calls of this extension than these, beyond
    /// what [`Workspace::doubts`] says of every answer. Empty: the
    /// extension's proxies are only ever called and handed to `use_repo`
    /// or `inject_repo`. The first 1,024 are kept.
    pub doubts: Vec<Doubt>,
}

/// The Bzlmod files of a workspace.
#[derive(Debug, Default)]
pub struct Workspace {
    /// The files read, each with its path from the Bazel root:
    /// `MODULE.bazel`, then each file it includes, followed by what that
    /// one includes. Empty when there is no `MODULE.bazel`.
    pub files: Vec<(String, File)>,
    /// What could not be read of the files and of the names in them: a
    /// doubt about every answer of [`Self::tags`], which does not repeat
    /// them. The first 1,024 are kept.
    pub doubts: Vec<Doubt>,
    /// The first doubt about a file that is there and was not read as a
    /// whole: one that cannot be read or parsed, one past a bound, which
    /// is not asked for, and the file of an `include` that is not
    /// followed, which may be there (9.3.2 takes `dev_dependency` as a
    /// second argument, and such a file is not read). What such a file
    /// says is not known, the name of a ruleset included. A file that an
    /// `include` names and that does not exist says nothing, and is none.
    pub unread: Option<Doubt>,
    /// The file of the older `WORKSPACE` system at the Bazel root, when
    /// it says more than `workspace(...)`: its name (`WORKSPACE.bzlmod`,
    /// else `WORKSPACE.bazel`, else `WORKSPACE`, as Bazel takes one) and
    /// its calls, or why it could not be read. `None` without such a
    /// file, and for one that is empty or only names the workspace.
    ///
    /// The repositories it defines are in no answer of [`Self::tags`].
    /// It is no entry of [`Self::doubts`], because whether Bazel reads it
    /// is not in these files: 7.x does by default, 8.x under
    /// `--enable_workspace`, 9.x never. A caller that knows the release
    /// can pass over it, and one that looks for a ruleset can see whether
    /// the file calls it. Without either, an answer is certain only when
    /// this is `None` too.
    pub legacy: Option<Result<(String, File), Doubt>>,
    /// The name of the root module, and the name the main repository has
    /// for itself.
    module: String,
    own: Option<String>,
    /// The module behind each repository name a `bazel_dep` gives.
    deps: BTreeMap<String, String>,
    /// What [`handed`] finds in each of `files`.
    handed: Vec<BTreeMap<(usize, usize), usize>>,
}

/// The functions a proxy may be handed to. `override_repo` is none: it
/// puts another repository in the place of one the extension makes.
const TAKE_A_PROXY: [&str; 2] = ["use_repo", "inject_repo"];

/// The other names Bazel predeclares that this reader gives a meaning to.
/// A file that uses one of either list other than to call it may do
/// anything under another name: `getattr`, as the variable `use_repo` of
/// a comprehension, calls a tag.
const PREDECLARED: [&str; 4] = ["bazel_dep", "include", "module", "use_extension"];

/// The bytes of the first argument of each `use_repo` and `inject_repo`
/// of `file`, with the call: an index into [`File::calls`]. To be the
/// whole of one is the one use of a proxy, besides calling a tag on it,
/// that is read.
fn handed(file: &File) -> BTreeMap<(usize, usize), usize> {
    let takes = |call: &Call| call.bind.is_none() && TAKE_A_PROXY.contains(&call.callee.as_str());
    let first = |(at, call): (usize, &Call)| {
        let first = call.args.first().filter(|arg| arg.how == How::Positional);
        let first = first.filter(|_| takes(call));
        first.map(|arg| ((arg.span.start, arg.span.end), at))
    };
    file.calls.iter().enumerate().filter_map(first).collect()
}

fn string(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::Str(string)) => Some(string),
        _ => None,
    }
}

/// The file and the name a `use_extension` call gives its extension by:
/// two strings by position, as Bazel takes them, the first a label whose
/// repository can be told. `None` when they are not written so.
fn extension(call: &Call) -> Option<(Label, &str)> {
    let file = string(call.positional(0))?;
    let name = string(call.positional(1))?;
    let file = Label::parse(file, "").filter(|file| !matches!(file.repo, Repo::Canonical(_)))?;
    (!call.unpacks()).then_some((file, name))
}

impl Workspace {
    /// Reads `MODULE.bazel` and the files it includes through `view`.
    ///
    /// Each file is asked for once. `include` is a statement of its own
    /// with one string that starts with `//` and ends in `.MODULE.bazel`
    /// (`CompiledModuleFile.checkModuleFileSyntax` and
    /// `ModuleFileFunction.advanceHorizon` at 7.7.2, 8.8.2 and 9.3.2;
    /// Bazel has it from 7.2.0), and what it names is a label of the main
    /// repository. A file that is missing, cannot be read or includes
    /// itself, and an `include` of another form, is a doubt. Bazel fails
    /// on each but one: 9.3.2 takes `dev_dependency` as a second argument.
    /// A name that starts with a dot is read, as 7.7.2 reads it.
    ///
    /// Then the `WORKSPACE` file is asked for ([`Self::legacy`]), with or
    /// without a `MODULE.bazel`. Bazel takes the first of the three names
    /// that is a file, so a directory of that name is passed over: a disk
    /// that folds case has one for `workspace`.
    pub fn read(view: &dyn Fn(&str) -> Entry) -> Workspace {
        let mut ws = Workspace::default();
        // The files to read, last first: the path, the file that includes
        // it (an index into `ws.files`) and the line it does so on.
        let mut todo = vec![("MODULE.bazel".to_string(), None::<usize>, 0)];
        // The file that includes each of `ws.files`.
        let mut includers: Vec<Option<usize>> = Vec::new();
        let (mut budget, mut failed) = (MAX_TOTAL, BTreeSet::new());
        let mut room = MAX_TOKENS;
        while let Some((path, includer, line)) = todo.pop() {
            // One doubt has said that it cannot be had.
            if failed.contains(&path) {
                continue;
            }
            let by = includer.map(|file| format!("; {}:{line} includes it", ws.files[file].0));
            let by = by.unwrap_or_default();
            if let Some(read) = ws.files.iter().position(|(read, _)| *read == path) {
                // Read before. That is a cycle when it is one of the files
                // that led here: 9.3.2 fails on it, and 7.7.2 and 8.8.2
                // have no check for it.
                let mut up = includer;
                while let Some(file) = up.filter(|file| *file != read) {
                    up = includers[file];
                }
                if up.is_some() {
                    ws.doubt(&path, 0, format!("it includes itself{by}"));
                }
                continue;
            }
            // Past a bound nothing more is asked for, and one doubt says so.
            if ws.files.len() + failed.len() == MAX_FILES {
                let why =
                    format!("it is one more than the {MAX_FILES} files that are asked for{by}");
                ws.left_unread(&path, 0, why);
                break;
            }
            // What is wrong with the file, and on which line of it: 0 for
            // the file as a whole.
            let entry = view(&path);
            let there = entry != Entry::Absent;
            let file = match entry {
                Entry::Absent if includer.is_none() => break,
                Entry::Absent => Err((0, "it does not exist".to_string())),
                Entry::Unreadable(why) => Err((0, format!("it cannot be read: {why}"))),
                Entry::Text(text) if text.len() > budget => {
                    ws.left_unread(&path, 0, format!("{OVER_TOTAL}{by}"));
                    break;
                }
                Entry::Text(text) => {
                    budget -= text.len();
                    indexed(&text, &mut room)
                }
            };
            match file {
                Err((line, why)) => {
                    match there {
                        true => ws.left_unread(&path, line, format!("{why}{by}")),
                        false => ws.doubt(&path, line, format!("{why}{by}")),
                    }
                    failed.insert(path);
                }
                Ok(file) => {
                    let includes = ws.learn(&path, &file).into_iter().rev();
                    todo.extend(includes.map(|(path, line)| (path, Some(ws.files.len()), line)));
                    includers.push(includer);
                    ws.files.push((path, file));
                }
            }
        }
        // The `WORKSPACE` file Bazel would take, within the same bounds.
        for name in LEGACY {
            let read = match view(name) {
                Entry::Absent => continue,
                // Bazel takes a file only, and goes on to the next name.
                Entry::Unreadable(why) if why == NOT_A_FILE => continue,
                Entry::Unreadable(why) => Err((0, format!("it cannot be read: {why}"))),
                Entry::Text(text) if text.len() > budget => Err((0, OVER_TOTAL.to_string())),
                Entry::Text(text) => indexed(&text, &mut room),
            };
            let file = name.to_string();
            let says = |call: &Call| call.bind.is_some() || call.callee != "workspace";
            ws.legacy = match read {
                Ok(read) => read.calls.iter().any(says).then_some(Ok((file, read))),
                Err((line, why)) => Some(Err(Doubt { file, line, why })),
            };
            break;
        }
        ws
    }

    fn doubt(&mut self, file: &str, line: usize, why: impl Into<String>) {
        if self.doubts.len() < MAX_DOUBTS {
            let (file, why) = (file.to_string(), why.into());
            self.doubts.push(Doubt { file, line, why });
        }
    }

    /// [`Self::doubt`] about a file that is there and is not read as a
    /// whole: the first of them is kept as such ([`Self::unread`]).
    fn left_unread(&mut self, file: &str, line: usize, why: impl Into<String>) {
        let (file, why) = (file.to_string(), why.into());
        self.doubt(&file, line, why.as_str());
        self.unread.get_or_insert(Doubt { file, line, why });
    }

    /// Takes from `file` what it says of the workspace itself: the names
    /// of the root module and of its dependencies, and the files it
    /// includes, which are returned with the line of each. Whatever of
    /// that is not written out plainly is a doubt.
    fn learn(&mut self, path: &str, file: &File) -> Vec<(String, usize)> {
        let mut includes = Vec::new();
        let handed = handed(file);
        // The calls an assignment gives a name: such an `include` is none.
        let named = |bind: &starlark::Bind| match bind.to {
            Bound::Call(call) => Some(call),
            _ => None,
        };
        let named: BTreeSet<usize> = file.binds.iter().filter_map(named).collect();
        // What Bazel predeclares, where the file has not bound the name.
        let predeclared = |(_, call): &(usize, &Call)| call.bind.is_none();
        for (at, call) in file.calls.iter().enumerate().filter(predeclared) {
            let read = match call.callee.as_str() {
                "include" => {
                    let alone = call.whole && call.args.len() == 1 && !named.contains(&at);
                    let label = string(call.positional(0)).filter(|label| {
                        let form = label.starts_with("//") && label.ends_with(".MODULE.bazel");
                        alone && form && label.len() <= MAX_LABEL
                    });
                    let label = label.and_then(|label| Label::parse(label, ""));
                    includes.extend(label.iter().map(|label| (label.path(), call.line)));
                    label.is_some()
                }
                "module" | "bazel_dep" => self.name(call),
                // The proxy gets a name, goes to `use_repo`, or is dropped.
                "use_extension" => {
                    let span = (call.span.start, call.span.end);
                    let placed = call.whole || handed.contains_key(&span);
                    placed && extension(call).is_some()
                }
                // Bazel takes none here, and what it binds is not followed.
                "load" => false,
                _ => true,
            };
            if !read {
                let why = format!("this `{}` cannot be read", call.callee);
                // The file of an `include` that is not followed may be there.
                match call.callee == "include" {
                    true => self.left_unread(path, call.line, why),
                    false => self.doubt(path, call.line, why),
                }
            }
        }
        for used in &file.uses {
            let mut meant = PREDECLARED.iter().chain(&TAKE_A_PROXY);
            if used.bind.is_none() && meant.any(|name| *name == used.name) {
                let why = format!("`{}` is used other than to call it", used.name);
                self.doubt(path, used.line, why);
            }
        }
        // `repo_name = None` and `dev_dependency = True` are read by the
        // names: they are Bazel's unless the file gives them a value.
        let bound = file.binds.iter().map(|bind| (&bind.name, bind.line));
        let assigned = file.uses.iter().filter(|used| used.assigned);
        for (name, line) in bound.chain(assigned.map(|used| (&used.name, used.line))) {
            if ["True", "False", "None"].contains(&name.as_str()) {
                self.doubt(path, line, format!("`{name}` may be given another value"));
            }
        }
        // What stands below one of these may not run, or run often
        // (`DotBazelFileSyntaxChecker`, as `load` above).
        for (line, word) in &file.blocks {
            let why = format!("`{word}` starts a statement, which Bazel refuses here");
            self.doubt(path, *line, why);
        }
        self.handed.push(handed);
        includes
    }

    /// Takes the name a `module` or `bazel_dep` call gives a module in the
    /// workspace: the module's own, unless `repo_name` gives another or,
    /// with `None`, none. `false` when that name cannot be read, or the
    /// call gives one and may not run.
    fn name(&mut self, call: &Call) -> bool {
        let module = call.callee == "module";
        let repo = call.arg("repo_name");
        let renamed = string(repo).filter(|repo| !repo.is_empty());
        let name = match call.arg("name") {
            None if module => Some(""),
            name => string(name),
        };
        let plain = match repo {
            None | Some(Value::Str(_)) => true,
            Some(Value::Name(none)) => none == "None" && !module,
            Some(_) => false,
        };
        // A dependency that is not renamed has its own name, whatever it is
        // and whether the call runs or not.
        let names = module || renamed.is_some();
        if !plain || call.unpacks() || (names && !(call.whole && name.is_some())) {
            return false;
        }
        let name = name.unwrap_or_default();
        if module {
            self.module = name.to_string();
            let own = renamed.unwrap_or(name);
            self.own = (!own.is_empty()).then(|| own.to_string());
        } else if let Some(repo) = renamed {
            self.deps.insert(repo.to_string(), name.to_string());
        }
        true
    }

    /// The label `text` as it reads in a tag of this workspace. Bazel
    /// resolves the labels of a tag from the root package of the module's
    /// repository, whichever file the tag is written in
    /// (`StarlarkBazelModule.create`: lines 114 to 118 at 7.7.2 and 8.8.2,
    /// 117 to 121 at 9.3.2), and the name the root module has for itself
    /// is the main repository.
    pub fn label(&self, text: &str) -> Option<Label> {
        let mut label = Label::parse(text, "")?;
        if matches!(&label.repo, Repo::Apparent(repo) if Some(repo) == self.own.as_ref()) {
            label.repo = Repo::Main;
        }
        Some(label)
    }

    /// Whether the `use_extension` call `call` asks for `wanted`.
    fn asks_for(&self, call: &Call, wanted: &Extension) -> bool {
        let Some((file, name)) = extension(call) else {
            return false;
        };
        // The module the label's repository is: the root module, or the
        // dependency a `bazel_dep` gave that name, or one of that name.
        let module = match &file.repo {
            Repo::Apparent(repo) if Some(repo) != self.own.as_ref() => {
                self.deps.get(repo).unwrap_or(repo)
            }
            _ => &self.module,
        };
        let same = |wanted: Label| wanted.package == file.package && wanted.name == file.name;
        let file = Label::parse(wanted.file, "").is_some_and(same);
        file && module == wanted.module && name == wanted.name
    }

    /// The calls of the tag `tag` of `extension` in the workspace, with
    /// what makes the list uncertain.
    ///
    /// A proxy is a name bound to `use_extension(...)` of that extension,
    /// in the file that binds it and from that statement on: an included
    /// file does not see the names of the file that includes it. A proxy
    /// that is used other than to call a tag on it, or as the first
    /// argument of `use_repo` or `inject_repo`, is a doubt.
    pub fn tags(&self, extension: &Extension, tag: &str) -> Tags<'_> {
        let mut tags = Tags::default();
        for ((path, file), handed) in self.files.iter().zip(&self.handed) {
            // The `use_extension` calls that ask for the extension, and
            // whether each makes a dev dependency and an isolated use. Each
            // call is looked at once, however many names it has.
            let mut asked = BTreeMap::new();
            for (at, call) in file.calls.iter().enumerate() {
                let asks = call.bind.is_none() && call.callee == "use_extension";
                if asks && self.asks_for(call, extension) {
                    let said = |name| match call.arg(name) {
                        None => Some(false),
                        Some(Value::Name(said)) if said == "True" => Some(true),
                        Some(Value::Name(said)) if said == "False" => Some(false),
                        Some(_) => None,
                    };
                    asked.insert(at, (said("dev_dependency"), said("isolate")));
                }
            }
            if asked.is_empty() {
                continue;
            }
            // The bindings that stand for the extension.
            let mut proxies = BTreeMap::new();
            for (at, bind) in file.binds.iter().enumerate() {
                if let Bound::Call(call) = bind.to {
                    proxies.extend(asked.get(&call).map(|said| (at, *said)));
                }
            }
            let of = |call, (dev_dependency, isolate)| Tag {
                file: path,
                call,
                dev_dependency,
                isolate,
            };
            let mut doubt = |line, why: String| {
                if tags.doubts.len() < MAX_DOUBTS {
                    let file = path.clone();
                    tags.doubts.push(Doubt { file, line, why });
                }
            };
            for used in &file.uses {
                let Some(said) = used.bind.and_then(|bind| proxies.get(&bind)) else {
                    continue;
                };
                match handed.get(&(used.at, used.at + used.name.len())) {
                    Some(call) => tags.handed.push(of(&file.calls[*call], *said)),
                    None => {
                        let why = format!("`{}` is used other than to call a tag", used.name);
                        doubt(used.line, why);
                    }
                }
            }
            for call in &file.calls {
                let Some(said) = call.bind.and_then(|bind| proxies.get(&bind)) else {
                    continue;
                };
                match call.callee.split('.').collect::<Vec<_>>()[..] {
                    [_, name] if name == tag => tags.calls.push(of(call, *said)),
                    [_, _] => {}
                    _ => doubt(call.line, format!("`{}` is no call of a tag", call.callee)),
                }
            }
        }
        tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPM: Extension = Extension {
        module: "aspect_rules_js",
        file: "//npm:extensions.bzl",
        name: "npm",
    };
    const PIP: Extension = Extension {
        module: "rules_python",
        file: "//python/extensions:pip.bzl",
        name: "pip",
    };
    const RUBY: Extension = Extension {
        module: "rules_ruby",
        file: "//ruby:extensions.bzl",
        name: "ruby",
    };
    const GO_DEPS: Extension = Extension {
        module: "gazelle",
        file: "//:extensions.bzl",
        name: "go_deps",
    };
    const GO_SDK: Extension = Extension {
        module: "rules_go",
        file: "//go:extensions.bzl",
        name: "go_sdk",
    };

    /// A workspace as teams write them: the hubs of four ecosystems, two of
    /// them in files the root includes, two rulesets under older names.
    const ROOT: &str = r#"module(
    name = "shop",
    version = "0.0.0",
)

bazel_dep(name = "aspect_rules_js", version = "3.6.0")
bazel_dep(name = "rules_python", version = "2.5.0-rc4")
bazel_dep(name = "rules_ruby", version = "1.0.0-rc2")
bazel_dep(name = "rules_go", version = "0.65.0", repo_name = "io_bazel_rules_go")
bazel_dep(name = "gazelle", version = "0.54.0", repo_name = "bazel_gazelle")

npm = use_extension("@aspect_rules_js//npm:extensions.bzl", "npm", dev_dependency = True)
npm.npm_translate_lock(
    name = "npm",
    data = [
        "//:package.json",
        "//:pnpm-workspace.yaml",
    ],
    npmrc = "//:.npmrc",
    pnpm_lock = "//:pnpm-lock.yaml",
    update_pnpm_lock = True,
    verify_node_modules_ignored = "//:.bazelignore",
)
use_repo(npm, "npm")

# The pnpm that Bazel runs: another extension of the same file.
pnpm = use_extension("@aspect_rules_js//npm:extensions.bzl", "pnpm")
pnpm.pnpm(
    name = "pnpm",
    pnpm_version_from = "//:package.json",
)
use_repo(pnpm, "pnpm")

include("//tools/bazel:python.MODULE.bazel")

include("//tools/bazel:go.MODULE.bazel")

ruby = use_extension("@rules_ruby//ruby:extensions.bzl", "ruby")
ruby.toolchain(
    name = "ruby",
    version_file = "//:.ruby-version",
)
ruby.bundle_fetch(
    name = "bundle",
    gem_checksums = {
        "ast-2.4.2": "1e280232e6a33754cde542bc5ef85520b74db2aac73ec14acef453784447cc12",
        "date-3.5.1-java": "12e09477dc932afe45bf768cd362bf73026804e0db1e6c314186d6cd0bee3344",
    },
    gemfile = "//services/billing:Gemfile",
    gemfile_lock = "//services/billing:Gemfile.lock",
)
use_repo(ruby, "bundle", "ruby", "ruby_toolchains")
"#;

    const PYTHON: &str = r#"python = use_extension("@rules_python//python/extensions:python.bzl", "python")
python.toolchain(
    is_default = True,
    python_version = "3.11",
)

pip = use_extension("@rules_python//python/extensions:pip.bzl", "pip")

[
    pip.parse(
        hub_name = "pypi",
        python_version = version,
        requirements_lock = "//services/api:requirements.txt",
    )
    for version in [
        "3.11",
        "3.12",
    ]
]

pip.parse(
    hub_name = "tools",
    python_version = "3.11",
    requirements_by_platform = {
        "//tools:requirements_linux.txt": "linux_*",
        "//tools:requirements_darwin.txt": "osx_*",
        "requirements_windows.txt": "windows_x86_64",
    },
)
use_repo(pip, "pypi", "tools")
"#;

    const GO: &str = r#"go_sdk = use_extension("@io_bazel_rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//services/gateway:go.mod")

go_deps = use_extension("@bazel_gazelle//:extensions.bzl", "go_deps")
go_deps.config(check_direct_dependencies = "error")
go_deps.from_file(go_mod = "//services/gateway:go.mod")
use_repo(go_deps, "com_github_google_uuid", "org_golang_x_net")
"#;

    const SHOP: [(&str, &str); 3] = [
        ("MODULE.bazel", ROOT),
        ("tools/bazel/python.MODULE.bazel", PYTHON),
        ("tools/bazel/go.MODULE.bazel", GO),
    ];

    /// The workspace of the files `files`, held in memory.
    fn workspace(files: &[(&str, &str)]) -> Workspace {
        Workspace::read(&|path| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        })
    }

    /// The workspace of one `MODULE.bazel`.
    fn module(text: &str) -> Workspace {
        workspace(&[("MODULE.bazel", text)])
    }

    /// The file a label argument names, from the Bazel root.
    fn file(ws: &Workspace, label: &str) -> String {
        let label = ws.label(label).unwrap();
        assert_eq!(label.repo, Repo::Main);
        label.path()
    }

    fn string(value: Option<&Value>) -> &str {
        super::string(value).unwrap_or_else(|| panic!("{value:?} is no string"))
    }

    /// The doubts of an answer, each as `file:line: why`.
    fn doubts(doubts: &[Doubt]) -> Vec<String> {
        let show = |doubt: &Doubt| format!("{}:{}: {}", doubt.file, doubt.line, doubt.why);
        doubts.iter().map(show).collect()
    }

    /// Where the calls of an answer are: `file:line`.
    fn sites(tags: &Tags) -> Vec<String> {
        let site = |tag: &Tag| format!("{}:{}", tag.file, tag.call.line);
        tags.calls.iter().map(site).collect()
    }

    #[test]
    fn the_pnpm_lock_of_npm_translate_lock() {
        let ws = workspace(&SHOP);
        let tags = ws.tags(&NPM, "npm_translate_lock");
        assert_eq!(sites(&tags), ["MODULE.bazel:13"]);
        // Certain: no doubt about the workspace, and none about the answer.
        assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]));
        let tag = tags.calls[0];
        assert_eq!(
            file(&ws, string(tag.call.arg("pnpm_lock"))),
            "pnpm-lock.yaml"
        );
        assert_eq!(
            tag.call.arg("update_pnpm_lock"),
            Some(&Value::Name("True".into()))
        );
        assert_eq!(tag.call.arg("npm_package_lock"), None);
        assert_eq!(tag.dev_dependency, Some(true));
        assert!(!tag.call.unpacks());
        // The other extension of the same file is another extension.
        assert_eq!(sites(&ws.tags(&NPM, "pnpm")), [""; 0]);
        let pnpm = Extension {
            name: "pnpm",
            ..NPM
        };
        assert_eq!(sites(&ws.tags(&pnpm, "pnpm")), ["MODULE.bazel:28"]);
    }

    #[test]
    fn the_requirements_of_pip_parse() {
        let ws = workspace(&SHOP);
        let tags = ws.tags(&PIP, "parse");
        let python = "tools/bazel/python.MODULE.bazel";
        assert_eq!(
            sites(&tags),
            [format!("{python}:10"), format!("{python}:21")]
        );
        assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]));
        // One call per Python version, each reading the same lock.
        let each = tags.calls[0].call;
        assert!(each.in_comprehension);
        assert_eq!(
            each.arg("python_version"),
            Some(&Value::Name("version".into()))
        );
        let lock = string(each.arg("requirements_lock"));
        assert_eq!(file(&ws, lock), "services/api/requirements.txt");
        assert_eq!(tags.calls[0].dev_dependency, Some(false));
        // One file per platform; a relative label is read from the root of
        // the repository, not from the package of the included file.
        let tools = tags.calls[1].call;
        assert!(!tools.in_comprehension);
        assert_eq!(tools.arg("requirements_lock"), None);
        let Some(Value::Dict(platforms)) = tools.arg("requirements_by_platform") else {
            panic!("{:?}", tools.arg("requirements_by_platform"));
        };
        let files: Vec<(String, &Value)> = (platforms.iter())
            .map(|(label, platform)| (file(&ws, label), platform))
            .collect();
        let platform = |platform: &str| Value::Str(platform.to_string());
        assert_eq!(
            files,
            [
                (
                    "tools/requirements_linux.txt".to_string(),
                    &platform("linux_*")
                ),
                (
                    "tools/requirements_darwin.txt".to_string(),
                    &platform("osx_*")
                ),
                (
                    "requirements_windows.txt".to_string(),
                    &platform("windows_x86_64")
                ),
            ]
        );
    }

    #[test]
    fn the_lock_and_the_checksums_of_bundle_fetch() {
        let ws = workspace(&SHOP);
        let tags = ws.tags(&RUBY, "bundle_fetch");
        assert_eq!(sites(&tags), ["MODULE.bazel:43"]);
        assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]));
        let call = tags.calls[0].call;
        let lock = string(call.arg("gemfile_lock"));
        assert_eq!(file(&ws, lock), "services/billing/Gemfile.lock");
        assert_eq!(
            file(&ws, string(call.arg("gemfile"))),
            "services/billing/Gemfile"
        );
        let digest = |digest: &str| Value::Str(digest.to_string());
        let ast = "1e280232e6a33754cde542bc5ef85520b74db2aac73ec14acef453784447cc12";
        let date = "12e09477dc932afe45bf768cd362bf73026804e0db1e6c314186d6cd0bee3344";
        let checksums = [
            ("ast-2.4.2", digest(ast)),
            ("date-3.5.1-java", digest(date)),
        ];
        let checksums = checksums.map(|(gem, digest)| (gem.to_string(), digest));
        assert_eq!(
            call.arg("gem_checksums"),
            Some(&Value::Dict(checksums.to_vec()))
        );
        // `ruby.toolchain` is another tag of the same proxy.
        assert_eq!(sites(&ws.tags(&RUBY, "toolchain")), ["MODULE.bazel:39"]);
    }

    #[test]
    fn the_go_mod_of_go_deps_from_file() {
        let ws = workspace(&SHOP);
        let tags = ws.tags(&GO_DEPS, "from_file");
        // gazelle's, not the `go_sdk.from_file` of rules_go two lines up,
        // and found under the name the workspace gives gazelle.
        assert_eq!(sites(&tags), ["tools/bazel/go.MODULE.bazel:6"]);
        assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]));
        let call = tags.calls[0].call;
        assert_eq!(
            file(&ws, string(call.arg("go_mod"))),
            "services/gateway/go.mod"
        );
        assert_eq!(call.arg("go_work"), None);
        assert_eq!(
            sites(&ws.tags(&GO_SDK, "from_file")),
            ["tools/bazel/go.MODULE.bazel:2"]
        );
        assert_eq!(
            sites(&ws.tags(&GO_DEPS, "config")),
            ["tools/bazel/go.MODULE.bazel:5"]
        );
        // The files, in the order Bazel runs them.
        let read: Vec<&str> = ws.files.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            read,
            [
                "MODULE.bazel",
                "tools/bazel/python.MODULE.bazel",
                "tools/bazel/go.MODULE.bazel"
            ]
        );
        assert_eq!(ws.doubts, []);
    }

    #[test]
    fn a_label_names_a_file_of_a_repository() {
        let label = |repo: Repo, package: &str, name: &str| {
            let (package, name) = (package.to_string(), name.to_string());
            Some(Label {
                repo,
                package,
                name,
            })
        };
        let other = |repo: &str| Repo::Apparent(repo.to_string());
        let exact = |repo: &str| Repo::Canonical(repo.to_string());
        for (text, package, want, path) in [
            (
                "//pkg:name",
                "at",
                label(Repo::Main, "pkg", "name"),
                "pkg/name",
            ),
            (
                "//a/b:c/d.txt",
                "at",
                label(Repo::Main, "a/b", "c/d.txt"),
                "a/b/c/d.txt",
            ),
            // Without a name, the last part of the package.
            ("//a/b", "at", label(Repo::Main, "a/b", "b"), "a/b/b"),
            ("//:name", "at", label(Repo::Main, "", "name"), "name"),
            // Relative: in the package it is written in.
            (":name", "at", label(Repo::Main, "at", "name"), "at/name"),
            ("name", "at", label(Repo::Main, "at", "name"), "at/name"),
            (
                "dir/name",
                "",
                label(Repo::Main, "", "dir/name"),
                "dir/name",
            ),
            // The main repository by its empty name.
            (
                "@//pkg:name",
                "at",
                label(Repo::Main, "pkg", "name"),
                "pkg/name",
            ),
            (
                "@@//pkg:name",
                "at",
                label(Repo::Main, "pkg", "name"),
                "pkg/name",
            ),
            // Another repository.
            (
                "@repo//pkg:name",
                "at",
                label(other("repo"), "pkg", "name"),
                "pkg/name",
            ),
            (
                "@repo//pkg",
                "at",
                label(other("repo"), "pkg", "pkg"),
                "pkg/pkg",
            ),
            ("@repo", "at", label(other("repo"), "", "repo"), "repo"),
            (
                "@@repo+//:name",
                "at",
                label(exact("repo+"), "", "name"),
                "name",
            ),
            (
                "@@rules_python~1.0.0//python:pip.bzl",
                "",
                label(exact("rules_python~1.0.0"), "python", "pip.bzl"),
                "python/pip.bzl",
            ),
        ] {
            let got = Label::parse(text, package);
            assert_eq!(got, want, "{text}");
            assert_eq!(got.unwrap().path(), path, "{text}");
        }
        // Not a label, or one whose path would leave its repository.
        for text in [
            "",
            "//",
            ":",
            "//pkg:",
            "//pkg/",
            "//a//b:c",
            "//a:b//c",
            "/abs",
            "//:/abs",
            "..",
            "../x",
            "//..:x",
            "//a/../b:c",
            "//a:../b",
            "//a:b/./c",
            "//.:x",
            "pkg:name",
            "//a:b:c",
            "a\\b",
            "C:\\x",
            "//a\0:b",
            "//a:b\n",
            "@",
            "@@",
            "@repo//",
            "@re po//:x",
            "@repo/x",
            "@@@repo//:x",
        ] {
            assert_eq!(Label::parse(text, "at"), None, "{text:?}");
        }
    }

    /// `requirements_lock = "//:requirements"` can name a rule of the root
    /// BUILD file. The reader says which path the label has; that no such
    /// file exists is for the caller to see.
    #[test]
    fn a_label_that_names_a_target_has_a_path_and_no_file() {
        let files = [
            ("MODULE.bazel", "module(name = 'm')\n"),
            ("requirements.txt", ""),
        ];
        let ws = workspace(&files);
        let has = |path: &str| files.iter().any(|(name, _)| *name == path);
        assert_eq!(file(&ws, "//:requirements"), "requirements");
        assert!(!has("requirements"));
        assert!(has(&file(&ws, "//:requirements.txt")));
    }

    #[test]
    fn the_name_the_root_module_has_for_itself_is_the_main_repository() {
        let main =
            |ws: &Workspace, label: &str| ws.label(label).map(|label| label.repo == Repo::Main);
        let named = module("module(name = 'app', version = '1.0')\n");
        assert_eq!(main(&named, "@app//:pnpm-lock.yaml"), Some(true));
        assert_eq!(main(&named, "@other//:pnpm-lock.yaml"), Some(false));
        // A canonical name is never the module's own.
        assert_eq!(main(&named, "@@app//:pnpm-lock.yaml"), Some(false));
        // With `repo_name`, that is the name, and the module's is not.
        let renamed = module("module(name = 'app', repo_name = 'com_example_app')\n");
        assert_eq!(
            main(&renamed, "@com_example_app//:pnpm-lock.yaml"),
            Some(true)
        );
        assert_eq!(main(&renamed, "@app//:pnpm-lock.yaml"), Some(false));
        let unnamed = module("bazel_dep(name = 'app', version = '1.0')\n");
        assert_eq!(main(&unnamed, "@app//:pnpm-lock.yaml"), Some(false));
        assert_eq!(main(&unnamed, "@//:pnpm-lock.yaml"), Some(true));
        assert_eq!(main(&unnamed, "//..:x"), None);
        for ws in [named, renamed, unnamed] {
            assert_eq!(ws.doubts, []);
        }
    }

    /// A label in a tag is read from the root package even when the tag is
    /// written in a file of another package.
    #[test]
    fn a_relative_label_in_an_included_file_is_read_from_the_root() {
        let ws = workspace(&[
            (
                "MODULE.bazel",
                "module(name = 'app')\ninclude('//tools:npm.MODULE.bazel')\n",
            ),
            (
                "tools/npm.MODULE.bazel",
                "npm = use_extension('@aspect_rules_js//npm:extensions.bzl', 'npm')\n\
                 npm.npm_translate_lock(name = 'npm', pnpm_lock = ':pnpm-lock.yaml')\n",
            ),
        ]);
        let tags = ws.tags(&NPM, "npm_translate_lock");
        assert_eq!(sites(&tags), ["tools/npm.MODULE.bazel:2"]);
        let lock = string(tags.calls[0].call.arg("pnpm_lock"));
        assert_eq!(file(&ws, lock), "pnpm-lock.yaml");
        assert_eq!(tags.doubts, []);
    }

    /// 7.7.2 takes an included file whose name starts with a dot; 8.8.2
    /// and 9.3.2 refuse the workspace (`ModuleFileFunction.advanceHorizon`).
    /// It is read, like a file in a directory below its package.
    #[test]
    fn an_included_file_may_start_with_a_dot_or_lie_below_its_package() {
        let pip =
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n";
        let ws = workspace(&[
            (
                "MODULE.bazel",
                "include('//tools:.pip.MODULE.bazel')\ninclude('//tools:more/pip.MODULE.bazel')\n",
            ),
            ("tools/.pip.MODULE.bazel", pip),
            ("tools/more/pip.MODULE.bazel", pip),
        ]);
        assert_eq!(ws.doubts, []);
        assert_eq!(
            sites(&ws.tags(&PIP, "parse")),
            ["tools/.pip.MODULE.bazel:2", "tools/more/pip.MODULE.bazel:2"]
        );
    }

    #[test]
    fn an_extension_is_known_by_its_module_and_file() {
        let found = |text: &str| {
            let ws = module(text);
            let tags = ws.tags(&PIP, "parse");
            assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]), "{text}");
            tags.calls.len()
        };
        for (text, want) in [
            // Whatever the proxy is called.
            ("p = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\np.parse()\n", 1),
            // Under the name a `bazel_dep` gives the module, wherever in the
            // file that is written.
            (
                "pip = use_extension('@rp//python/extensions:pip.bzl', 'pip')\npip.parse()\n\
                 bazel_dep(name = 'rules_python', version = '1.0', repo_name = 'rp')\n",
                1,
            ),
            // In the ruleset's own repository.
            (
                "module(name = 'rules_python')\n\
                 pip = use_extension('//python/extensions:pip.bzl', 'pip')\npip.parse()\n\
                 dev = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\ndev.parse()\n\
                 at = use_extension('@//python/extensions:pip.bzl', 'pip')\nat.parse()\n",
                3,
            ),
            // A proxy called `pip` of another extension, file, or module.
            ("pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip_internal')\npip.parse()\n", 0),
            ("pip = use_extension('@rules_python//python:extensions.bzl', 'pip')\npip.parse()\n", 0),
            ("pip = use_extension('@rules_uv//python/extensions:pip.bzl', 'pip')\npip.parse()\n", 0),
            ("pip = use_extension('//python/extensions:pip.bzl', 'pip')\npip.parse()\n", 0),
            (
                "bazel_dep(name = 'my_python', version = '1.0', repo_name = 'rules_python')\n\
                 pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n",
                0,
            ),
            // Another tag, and a name that is not bound at all.
            ("pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.override()\n", 0),
            ("pip.parse()\n", 0),
            // A `use_extension` the file has redefined is not Bazel's.
            (
                "use_extension = other\n\
                 pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n",
                0,
            ),
        ] {
            assert_eq!(found(text), want, "{text}");
        }
    }

    #[test]
    fn a_proxy_is_seen_in_the_file_that_binds_it_only() {
        let pip = "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n";
        let ws = workspace(&[
            (
                "MODULE.bazel",
                &format!("{pip}include('//:a.MODULE.bazel')\npip.parse(hub_name = 'root')\n"),
            ),
            (
                "a.MODULE.bazel",
                "pip.parse(hub_name = 'unbound')\ninclude('//:b.MODULE.bazel')\n",
            ),
            (
                "b.MODULE.bazel",
                &format!("{pip}pip.parse(hub_name = 'b')\n"),
            ),
        ]);
        let tags = ws.tags(&PIP, "parse");
        assert_eq!(sites(&tags), ["MODULE.bazel:3", "b.MODULE.bazel:2"]);
        assert_eq!(tags.doubts, []);
    }

    #[test]
    fn a_name_bound_again_means_the_new_extension() {
        let ws = module(
            "hub = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
             hub.parse(hub_name = 'pip')\n\
             hub = use_extension('@aspect_rules_js//npm:extensions.bzl', 'npm')\n\
             hub.parse(hub_name = 'npm')\n\
             hub.npm_translate_lock(name = 'npm')\n",
        );
        assert_eq!(sites(&ws.tags(&PIP, "parse")), ["MODULE.bazel:2"]);
        assert_eq!(sites(&ws.tags(&NPM, "parse")), ["MODULE.bazel:4"]);
        assert_eq!(
            sites(&ws.tags(&NPM, "npm_translate_lock")),
            ["MODULE.bazel:5"]
        );
    }

    #[test]
    fn a_tag_called_in_a_comprehension_or_a_condition_is_found() {
        let ws = module(
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
             [pip.parse(hub_name = 'a', requirements_lock = '//:a.txt') for _ in range(1)]\n\
             pip.parse(hub_name = 'b', requirements_lock = '//:b.txt') if False else None\n\
             [[pip.parse(hub_name = v + w) for v in ['c']] for w in ['d']]\n",
        );
        let tags = ws.tags(&PIP, "parse");
        assert_eq!(
            sites(&tags),
            ["MODULE.bazel:2", "MODULE.bazel:3", "MODULE.bazel:4"]
        );
        let stands: Vec<(bool, bool)> = (tags.calls.iter())
            .map(|tag| (tag.call.in_comprehension, tag.call.whole))
            .collect();
        assert_eq!(stands, [(true, false), (false, false), (true, false)]);
        assert_eq!(tags.calls[2].call.arg("hub_name"), Some(&Value::Other));
        assert_eq!(tags.doubts, []);
    }

    #[test]
    fn an_argument_that_is_computed_is_not_guessed() {
        let ws = module(
            "LOCK = '//:requirements.txt'\n\
             pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
             pip.parse(hub_name = 'a', requirements_lock = LOCK)\n\
             pip.parse(hub_name = 'b', requirements_lock = '//:' + 'requirements.txt')\n\
             pip.parse(hub_name = 'c', requirements_lock = '//:requirements_{}.txt'.format(v))\n\
             pip.parse(hub_name = 'd', requirements_lock = select({'//conditions:default': '//:r.txt'}))\n\
             pip.parse(hub_name = 'e', **{'requirements_lock': '//:requirements.txt'})\n\
             pip.parse(hub_name = 'f', requirements_by_platform = {\n\
                 '//:requirements_' + os + '.txt': os + '_*'\n\
                 for os in ['linux', 'osx']\n\
             })\n\
             pip.parse(hub_name = 'g', requirements_lock = '//:requirements # not a comment.txt')\n",
        );
        let tags = ws.tags(&PIP, "parse");
        let locks: Vec<Option<&Value>> = (tags.calls.iter())
            .map(|tag| tag.call.arg("requirements_lock"))
            .collect();
        let odd = Value::Str("//:requirements # not a comment.txt".to_string());
        assert_eq!(
            locks,
            [
                Some(&Value::Name("LOCK".into())),
                Some(&Value::Other),
                Some(&Value::Other),
                Some(&Value::Other),
                None,
                None,
                Some(&odd),
            ]
        );
        // The call that unpacks a dict says so, and what the dict holds.
        let unpacked = tags.calls[4].call;
        assert!(unpacked.unpacks());
        let lock = (
            "requirements_lock".to_string(),
            Value::Str("//:requirements.txt".into()),
        );
        assert_eq!(unpacked.args[1].value, Value::Dict(vec![lock]));
        assert_eq!(
            tags.calls[5].call.arg("requirements_by_platform"),
            Some(&Value::Other)
        );
        // None of this hides a call: the list is certain.
        assert_eq!(tags.doubts, []);
    }

    #[test]
    fn a_hub_in_a_comment_or_a_string_is_no_hub() {
        let ws = module(
            "# pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
             # pip.parse(requirements_lock = '//:a.txt')\n\
             \"\"\"pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
             pip.parse(requirements_lock = '//:b.txt')\"\"\"\n\
             pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')  # pip.parse()\n\
             note = \"pip.parse(requirements_lock = '//:c.txt')\"\n",
        );
        let tags = ws.tags(&PIP, "parse");
        assert_eq!((sites(&tags), tags.doubts), (Vec::new(), Vec::new()));
    }

    #[test]
    fn a_proxy_handed_to_use_repo_or_given_another_name_is_read() {
        let ws = module(
            "npm = use_extension('@aspect_rules_js//npm:extensions.bzl', 'npm')\n\
             npm.npm_translate_lock(name = 'npm_app', pnpm_lock = '//:pnpm-lock.yaml')\n\
             use_repo(npm, npm = 'npm_app')\n\
             use_repo(npm, 'other', **{'a.b': 'c'})\n\
             inject_repo(npm, 'tools')\n\
             same = npm\n\
             same.npm_translate_lock(name = 'second', pnpm_lock = '//web:pnpm-lock.yaml')\n\
             use_repo(same, 'second')\n\
             use_repo(use_extension('@aspect_rules_js//npm:extensions.bzl', 'npm'), 'third')\n\
             use_extension('@aspect_rules_js//npm:extensions.bzl', 'npm')\n",
        );
        let tags = ws.tags(&NPM, "npm_translate_lock");
        assert_eq!(sites(&tags), ["MODULE.bazel:2", "MODULE.bazel:7"]);
        assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]));
        // The calls that take the proxy by a name are listed, in the order
        // of the file: not the one that takes the `use_extension` itself.
        let handed = |tag: &Tag| format!("{}:{}", tag.call.callee, tag.call.line);
        assert_eq!(
            tags.handed.iter().map(handed).collect::<Vec<_>>(),
            ["use_repo:3", "use_repo:4", "inject_repo:5", "use_repo:8"]
        );
        // And none of another extension's proxy.
        assert_eq!(ws.tags(&PIP, "parse").handed, []);
    }

    #[test]
    fn any_other_use_of_a_proxy_is_a_doubt_about_its_extension() {
        let used = "`pip` is used other than to call a tag";
        for (line, why) in [
            ("f(pip)", used),
            ("use_repo(npm, pip)", used),
            ("use_repo(pip = pip)", used),
            ("use_repo(pip if x else y, 'hub')", used),
            ("use_repo(pip.parse, 'hub')", used),
            ("tags = [pip]", used),
            ("parse = pip.parse", used),
            ("x = pip if y else None", used),
            ("pip += 1", used),
            ("[p.parse() for p in [pip]]", used),
            ("[pip.parse() for pip in hubs]", used),
            ("override_repo(pip, pypi = 'vendored')", used),
            ("pip()", "`pip` is no call of a tag"),
            ("pip.parse.again()", "`pip.parse.again` is no call of a tag"),
        ] {
            let ws = module(&format!(
                "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
                 npm = use_extension('@aspect_rules_js//npm:extensions.bzl', 'npm')\n\
                 pip.parse(hub_name = 'a')\n{line}\n"
            ));
            let tags = ws.tags(&PIP, "parse");
            assert_eq!(
                doubts(&tags.doubts),
                [format!("MODULE.bazel:4: {why}")],
                "{line}"
            );
            assert!(!tags.calls.is_empty(), "{line}");
            // It is no doubt about another extension, nor about the files.
            assert_eq!(ws.tags(&NPM, "npm_translate_lock").doubts, [], "{line}");
            assert_eq!(ws.doubts, [], "{line}");
        }
    }

    #[test]
    fn what_a_file_says_of_the_workspace_in_a_way_that_cannot_be_read_is_a_doubt() {
        let pip =
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n";
        let dep = "this `bazel_dep` cannot be read";
        let root = "this `module` cannot be read";
        let extension = "this `use_extension` cannot be read";
        let include = "this `include` cannot be read";
        let long = format!("include('//:{}.MODULE.bazel')", "a".repeat(MAX_LABEL));
        for (text, why) in [
            // The name a module has in the workspace.
            ("bazel_dep(name = NAME, repo_name = 'rules_python')", dep),
            ("bazel_dep(name = 'rules_python', repo_name = NAME)", dep),
            (
                "bazel_dep(name = 'rules_python', repo_name = 'r' + 'p')",
                dep,
            ),
            (
                "bazel_dep(**{'name': 'rules_python', 'repo_name': 'rp'})",
                dep,
            ),
            ("module(name = 'a' + 'b')", root),
            ("module(name = 'app', repo_name = None)", root),
            ("module(name = 'app', repo_name = NAME)", root),
            ("module(**{'name': 'app'})", root),
            // Which extension a proxy stands for, and where the proxy goes.
            ("x = use_extension(FILE, 'pip')", extension),
            (
                "x = use_extension('@rules_python//python/extensions:pip.bzl', NAME)",
                extension,
            ),
            (
                "x = use_extension('@rules_python//python/extensions:pip.bzl')",
                extension,
            ),
            (
                "x = use_extension('@@rules_python+//python/extensions:pip.bzl', 'pip')",
                extension,
            ),
            ("x = use_extension('//..:pip.bzl', 'pip')", extension),
            ("x = use_extension(*ARGS)", extension),
            // Bazel takes the file and the name by position only.
            (
                "x = use_extension(extension_bzl_file = '//:a.bzl', extension_name = 'a')",
                extension,
            ),
            (
                "x = [use_extension('@rules_python//python/extensions:pip.bzl', 'pip')]",
                extension,
            ),
            (
                "x, y = use_extension('//:a.bzl', 'a'), use_extension('//:b.bzl', 'b')",
                extension,
            ),
            ("use_extension('//:a.bzl', 'a').tag()", extension),
            ("f(use_extension('//:a.bzl', 'a'))", extension),
            ("use_repo(npm, use_extension('//:a.bzl', 'a'))", extension),
            (
                "use_repo(use_extension('//:a.bzl', 'a').tag() or npm, 'hub')",
                extension,
            ),
            // A directive under another name.
            (
                "ext = use_extension",
                "`use_extension` is used other than to call it",
            ),
            (
                "f(use_extension)",
                "`use_extension` is used other than to call it",
            ),
            (
                "dep = bazel_dep",
                "`bazel_dep` is used other than to call it",
            ),
            (
                "x = [module, include]",
                "`module` is used other than to call it",
            ),
            // `getattr(pip, 'parse')(...)` calls a tag: under the name of
            // `use_repo` it would pass for handing the proxy over.
            (
                "[use_repo(pip, 'parse')(hub_name = 'hidden') for use_repo in [getattr]]",
                "`use_repo` is used other than to call it",
            ),
            (
                "inject_repo, x = getattr, 1",
                "`inject_repo` is used other than to call it",
            ),
            // An include Bazel does not take.
            ("include(':a.MODULE.bazel')", include),
            ("include('@//:a.MODULE.bazel')", include),
            ("include('//:a.bazel')", include),
            ("include('//:a.MODULE.bazel' + '')", include),
            ("include(FILE)", include),
            ("include(label = '//:a.MODULE.bazel')", include),
            ("include('//..:a.MODULE.bazel')", include),
            ("include()", include),
            // One statement of its own with one argument, at every release;
            // `dev_dependency`, which 9.3.2 takes, is not read.
            ("include('//:a.MODULE.bazel', '//:b.MODULE.bazel')", include),
            // A name longer than any path: a doubt names its file.
            (long.as_str(), include),
            ("x = include('//:a.MODULE.bazel')", include),
            ("[include('//:a.MODULE.bazel') for _ in [1]]", include),
            ("None if x else include('//:a.MODULE.bazel')", include),
            (
                "include('//:a.MODULE.bazel', dev_dependency = True)",
                include,
            ),
        ] {
            let ws = module(&format!("{pip}{text}\n"));
            let tags = ws.tags(&PIP, "parse");
            let want = format!("MODULE.bazel:3: {why}");
            assert_eq!(doubts(&ws.doubts)[0], want, "{text}");
            // It is a doubt about every answer, and the answer about `pip`
            // has none of its own; no include of the row is followed.
            assert_eq!((tags.calls.len(), &tags.doubts), (1, &vec![]), "{text}");
            assert_eq!(ws.files.len(), 1, "{text}");
        }
        // What reads the same whatever the value is, is no doubt.
        for text in [
            "[bazel_dep(name = name, version = '1.0') for name in ['a', 'b']]",
            "bazel_dep(name = NAME, version = '1.0', repo_name = None)",
            "bazel_dep(name = 'rules_python', version = '1.0', repo_name = '')",
            "bazel_dep(name = 'rules_python', dev_dependency = IS_DEV)",
            "module()",
            "module(name = 'app', repo_name = '')",
            "x = use_extension('//:a.bzl', 'a', dev_dependency = IS_DEV, isolate = True)",
            "use_extension('//:a.bzl', 'a')",
            "use_repo(use_extension('//:a.bzl', 'a'), 'repo')",
            "include = 1\nx = include",
            "use_extension = other\nx = use_extension(FILE)",
            "x = other.use_extension(FILE)",
            "x = f(include = 1, module = 2)",
        ] {
            let ws = module(&format!("{pip}{text}\n"));
            let tags = ws.tags(&PIP, "parse");
            assert_eq!((&ws.doubts, &tags.doubts), (&vec![], &vec![]), "{text}");
        }
    }

    /// Bazel reads a name that ends a line and a parenthesis that starts
    /// the next one as two statements: the second calls the tag.
    #[test]
    fn a_tag_called_on_the_line_after_a_bare_name_is_not_hidden() {
        for (bare, name) in [
            ("use_repo", "use_repo"),
            ("x = use_repo", "use_repo"),
            ("inject_repo", "inject_repo"),
            ("use_repo  # comment", "use_repo"),
        ] {
            let ws = module(&format!(
                "module(name = 'shop')\n\
                 bazel_dep(name = 'rules_python', version = '1.0.0')\n\
                 pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
                 {bare}\n\
                 (pip).parse(hub_name = 'pypi', requirements_lock = '//:hidden.txt')\n"
            ));
            let tags = ws.tags(&PIP, "parse");
            let want = "MODULE.bazel:5: `pip` is used other than to call a tag";
            assert_eq!(doubts(&tags.doubts), [want], "{bare}");
            // And the bare name is one this reader gives a meaning to.
            let want = format!("MODULE.bazel:4: `{name}` is used other than to call it");
            assert_eq!(doubts(&ws.doubts), [want], "{bare}");
        }
    }

    /// Bazel names a module when it calls `module` or `bazel_dep`
    /// (`ModuleFileGlobals.bazelDep`): a call behind `False and`, in a
    /// comprehension or in a conditional may never come.
    #[test]
    fn a_module_or_a_dependency_that_may_not_run_gives_no_name() {
        let pip =
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n";
        let other = "bazel_dep(name = 'other', version = '1', repo_name = 'rules_python')";
        for line in [
            format!("False and {other}"),
            format!("[{other} for _ in []]"),
            format!("{other} if False else None"),
        ] {
            let ws = module(&format!("module(name = 'shop')\n{line}\n{pip}"));
            let want = "MODULE.bazel:2: this `bazel_dep` cannot be read";
            assert_eq!(doubts(&ws.doubts), [want], "{line}");
            assert_eq!(sites(&ws.tags(&PIP, "parse")), ["MODULE.bazel:4"], "{line}");
        }
        // And a `module` that may not run does not make the file its ruleset's.
        let ws = module(
            "False and module(name = 'rules_python')\n\
             pip = use_extension('//python/extensions:pip.bzl', 'pip')\npip.parse()\n",
        );
        let want = "MODULE.bazel:1: this `module` cannot be read";
        assert_eq!(doubts(&ws.doubts), [want]);
        assert_eq!(sites(&ws.tags(&PIP, "parse")), [""; 0]);
    }

    /// `None`, `True` and `False` are names a file may give another value
    /// (entries of `Starlark.UNIVERSE`, no keywords of the lexer; a target
    /// binds every name in it, `Identifier.boundIdentifiers`): Bazel then
    /// reads `repo_name = None` and `dev_dependency = True` otherwise.
    #[test]
    fn none_true_and_false_given_another_value_are_a_doubt() {
        let dep = "bazel_dep(name = 'rules_python', version = '1', repo_name = None)";
        for (given, name) in [
            ("None = 'rp'".to_string(), "None"),
            ("True = False".to_string(), "True"),
            ("False, x = True, 1".to_string(), "False"),
            ("(None) = 'rp'".to_string(), "None"),
            ("[x, [True]] = [1, [0]]".to_string(), "True"),
            (format!("[{dep} for None in ['rp']]"), "None"),
            ("[f(True) and 0for True in [False]]".to_string(), "True"),
            // After an `in`, and a comprehension, inside an item it indexes.
            ("[f(None) for d[0 in d], None in z]".to_string(), "None"),
            (
                "[f(None) for d[[y for y in z][0]], None in w]".to_string(),
                "None",
            ),
            // An index is read, not given a value: one doubt too many.
            ("d[None] = 1".to_string(), "None"),
        ] {
            let ws = module(&format!(
                "{given}\n{dep}\n\
                 pip = use_extension('@rp//python/extensions:pip.bzl', 'pip', dev_dependency = True)\n\
                 pip.parse()\n"
            ));
            let want = format!("MODULE.bazel:1: `{name}` may be given another value");
            assert_eq!(doubts(&ws.doubts), [want], "{given}");
        }
        // To use them is none.
        let ws = module(&format!(
            "IS_DEV = True\n{dep}\nd = {{None: True}}\n\
             x = [y for y in [True, False] if y != None and y in d]\n"
        ));
        assert_eq!(ws.doubts, []);
    }

    /// A file that cannot be had is asked for once, however many includes
    /// name it, and counts as one of the files of the workspace.
    #[test]
    fn a_file_that_cannot_be_had_is_asked_for_once() {
        let asked = std::cell::RefCell::new(Vec::new());
        let view = |path: &str| {
            asked.borrow_mut().push(path.to_string());
            match path {
                "MODULE.bazel" => Entry::Text(
                    "include('//:bad.MODULE.bazel')\ninclude('//:gone.MODULE.bazel')\n".repeat(3),
                ),
                "bad.MODULE.bazel" => Entry::Unreadable("it is not UTF-8".to_string()),
                _ => Entry::Absent,
            }
        };
        let ws = Workspace::read(&view);
        // Each once, and then the three names of a `WORKSPACE` file.
        let mut all = vec!["MODULE.bazel", "bad.MODULE.bazel", "gone.MODULE.bazel"];
        all.extend(LEGACY);
        assert_eq!(*asked.borrow(), all);
        assert_eq!(
            doubts(&ws.doubts),
            [
                "bad.MODULE.bazel:0: it cannot be read: it is not UTF-8; MODULE.bazel:1 includes it",
                "gone.MODULE.bazel:0: it does not exist; MODULE.bazel:2 includes it",
            ]
        );
        // 300 files that are not there: 255 are asked for after the root.
        let asked = std::cell::Cell::new(0);
        let ws = Workspace::read(&|path| {
            asked.set(asked.get() + 1);
            let includes = (0..300).map(|at| format!("include('//:{at}.MODULE.bazel')\n"));
            match path {
                "MODULE.bazel" => Entry::Text(includes.collect()),
                _ => Entry::Absent,
            }
        });
        assert_eq!((asked.get(), ws.doubts.len()), (256 + 3, 256));
        let want = "255.MODULE.bazel:0: it is one more than the 256 files that are asked for; \
                    MODULE.bazel:256 includes it";
        assert_eq!(doubts(&ws.doubts)[255], want);
    }

    /// One query looks at each call, binding and use of a file once. A
    /// proxy with as many names as a file has room for, made by a call
    /// with many arguments or a long label, is the shape that a query
    /// which looked at the call again for each name takes long on.
    #[test]
    fn a_query_grows_with_the_size_of_the_files() {
        let label = "@rules_python//python/extensions:pip.bzl";
        let fill = |head: String| {
            let names = "a=p\n".repeat(MAX_TOKENS / 6);
            module(&format!("{head}{names}a.parse()\n"))
        };
        let started = std::time::Instant::now();
        let many = ",x".repeat(MAX_TOKENS / 8);
        let many = fill(format!("p = use_extension('{label}', 'pip'{many})\n"));
        let long = "x".repeat(MAX_BYTES / 2);
        let long = fill(format!("p = use_extension('{label}{long}', 'pip')\n"));
        for (ws, calls) in [(many, 1), (long, 0)] {
            assert_eq!((ws.files.len(), &ws.doubts), (1, &vec![]));
            assert!(ws.files[0].1.binds.len() > MAX_TOKENS / 8);
            let tags = ws.tags(&PIP, "parse");
            assert_eq!((tags.calls.len(), doubts(&tags.doubts)), (calls, vec![]));
        }
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(120), "{took:?}");
    }

    #[test]
    fn dev_dependency_is_told_when_it_is_written_out() {
        for (written, want) in [
            ("", Some(false)),
            (", dev_dependency = False", Some(false)),
            (", dev_dependency = True", Some(true)),
            (", dev_dependency = IS_RELEASE", None),
            (", dev_dependency = not CI", None),
        ] {
            let ws = module(&format!(
                "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip'{written})\n\
                 pip.parse()\n"
            ));
            let tags = ws.tags(&PIP, "parse");
            assert_eq!(tags.calls[0].dev_dependency, want, "{written}");
            assert_eq!(tags.doubts, [], "{written}");
        }
    }

    /// `isolate` is told as `dev_dependency` is, and a call that takes the
    /// proxy is told both of the use its proxy was made by, as a tag is.
    #[test]
    fn isolate_is_told_when_it_is_written_out_and_a_handed_proxy_has_its_use() {
        for (written, want) in [
            ("", Some(false)),
            (", isolate = False", Some(false)),
            (", isolate = True", Some(true)),
            (", isolate = ISOLATED", None),
        ] {
            let ws = module(&format!(
                "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip', \
                 dev_dependency = True{written})\n\
                 pip.parse()\nuse_repo(pip, 'hub')\n"
            ));
            let tags = ws.tags(&PIP, "parse");
            assert_eq!(tags.handed[0].call.callee, "use_repo", "{written}");
            for tag in [tags.calls[0], tags.handed[0]] {
                let said = (tag.dev_dependency, tag.isolate);
                assert_eq!(said, (Some(true), want), "{written}");
            }
            assert_eq!(tags.doubts, [], "{written}");
        }
    }

    #[test]
    fn a_file_that_cannot_be_had_is_a_doubt_and_never_a_silent_skip() {
        let pip =
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n";
        let root = format!("{pip}include('//:a.MODULE.bazel')\ninclude('//sub:b.MODULE.bazel')\n");
        let by = |line: usize| format!("; MODULE.bazel:{line} includes it");
        let cases: [(&[(&str, &str)], Vec<String>); 7] = [
            // Both files are there.
            (
                &[("a.MODULE.bazel", pip), ("sub/b.MODULE.bazel", pip)],
                vec![],
            ),
            // One is missing.
            (
                &[("a.MODULE.bazel", pip)],
                vec![format!("sub/b.MODULE.bazel:0: it does not exist{}", by(4))],
            ),
            // One cannot be tokenized: the line is the one in that file.
            (
                &[
                    ("a.MODULE.bazel", "x = 1\ny = 'never closed\n"),
                    ("sub/b.MODULE.bazel", pip),
                ],
                vec![format!(
                    "a.MODULE.bazel:2: a string is never closed{}",
                    by(3)
                )],
            ),
            // A file that includes itself, and one that includes the root.
            (
                &[
                    ("a.MODULE.bazel", "include('//:a.MODULE.bazel')\n"),
                    ("sub/b.MODULE.bazel", pip),
                ],
                vec![
                    "a.MODULE.bazel:0: it includes itself; a.MODULE.bazel:1 includes it"
                        .to_string(),
                ],
            ),
            (
                &[
                    ("a.MODULE.bazel", "include('//sub:b.MODULE.bazel')\n"),
                    ("sub/b.MODULE.bazel", "include('//:MODULE.bazel')\n"),
                ],
                // Bazel takes only names that end in `.MODULE.bazel`.
                vec!["sub/b.MODULE.bazel:1: this `include` cannot be read".to_string()],
            ),
            (
                &[
                    ("a.MODULE.bazel", "include('//sub:b.MODULE.bazel')\n"),
                    ("sub/b.MODULE.bazel", "include('//:c.MODULE.bazel')\n"),
                    ("c.MODULE.bazel", "include('//:a.MODULE.bazel')\n"),
                ],
                vec![
                    "a.MODULE.bazel:0: it includes itself; c.MODULE.bazel:1 includes it"
                        .to_string(),
                ],
            ),
            // Two files include a third: it is read once, and that is all.
            (
                &[
                    ("a.MODULE.bazel", "include('//:c.MODULE.bazel')\n"),
                    ("sub/b.MODULE.bazel", "include('//:c.MODULE.bazel')\n"),
                    ("c.MODULE.bazel", pip),
                ],
                vec![],
            ),
        ];
        for (included, want) in cases {
            let mut files = vec![("MODULE.bazel", root.as_str())];
            files.extend(included);
            let ws = workspace(&files);
            assert_eq!(doubts(&ws.doubts), want, "{included:?}");
            // An answer still lists what was read, and adds no doubt.
            let tags = ws.tags(&PIP, "parse");
            assert_eq!(tags.doubts, []);
            let read = |name: &str| ws.files.iter().filter(|(path, _)| path == name).count();
            assert_eq!(read("MODULE.bazel"), 1);
            let pips = included
                .iter()
                .filter(|(name, text)| *text == pip && read(name) == 1);
            assert_eq!(tags.calls.len(), 1 + pips.count(), "{included:?}");
            assert!(included.iter().all(|(name, _)| read(name) <= 1));
        }
    }

    #[test]
    fn what_the_view_cannot_give_is_a_doubt() {
        let view = |path: &str| match path {
            "MODULE.bazel" => Entry::Text("include('//:a.MODULE.bazel')\n".to_string()),
            _ => Entry::Unreadable("the host did not provide it".to_string()),
        };
        let ws = Workspace::read(&view);
        let want = "a.MODULE.bazel:0: it cannot be read: the host did not provide it; \
                    MODULE.bazel:1 includes it";
        assert_eq!(doubts(&ws.doubts), [want]);
        let ws = Workspace::read(&|_| Entry::Unreadable("no".to_string()));
        assert_eq!(
            doubts(&ws.doubts),
            ["MODULE.bazel:0: it cannot be read: no"]
        );
        assert_eq!(ws.files.len(), 0);
        // Without a MODULE.bazel there is nothing to read and nothing to doubt.
        let ws = workspace(&[("WORKSPACE", "workspace(name = 'old')\n")]);
        assert_eq!((ws.files.len(), ws.doubts.len()), (0, 0));
        assert_eq!(ws.tags(&PIP, "parse"), Tags::default());
    }

    /// A file that is there and is not read as a whole is told from one
    /// that an include names and that does not exist: what the first says
    /// is not known ([`Workspace::unread`]), and its doubt is kept as the
    /// one about such a file, whatever doubt came before it.
    #[test]
    fn a_file_that_is_there_and_not_read_is_told_from_one_that_is_missing() {
        // The file that the second line of the root includes, after a
        // statement that the reader does not follow.
        let root = "load('//:defs.bzl', 'deps')\ninclude('//:a.MODULE.bazel')\n";
        let unread = |included: Entry| {
            let view = |path: &str| match path {
                "MODULE.bazel" => Entry::Text(root.to_string()),
                "a.MODULE.bazel" => included.clone(),
                _ => Entry::Absent,
            };
            let ws = Workspace::read(&view);
            let first = doubts(&ws.doubts[..1]);
            assert_eq!(first, ["MODULE.bazel:1: this `load` cannot be read"]);
            ws.unread.map(|doubt| (doubt.file, doubt.line))
        };
        assert_eq!(unread(Entry::Absent), None);
        assert_eq!(unread(Entry::Text("x = 1\n".to_string())), None);
        // One that includes itself was read.
        let cycle = "include('//:a.MODULE.bazel')\n";
        assert_eq!(unread(Entry::Text(cycle.to_string())), None);
        let (binary, open) = ("it is not UTF-8", "x = 'never closed\n");
        let at = |line| Some(("a.MODULE.bazel".to_string(), line));
        assert_eq!(unread(Entry::Unreadable(binary.to_string())), at(0));
        assert_eq!(unread(Entry::Text(open.to_string())), at(1));
        // The root file, and a workspace with none.
        let no_root = Workspace::read(&|_| Entry::Unreadable("no".to_string()));
        let file = no_root.unread.map(|doubt| doubt.file);
        assert_eq!(file.as_deref(), Some("MODULE.bazel"));
        assert_eq!(Workspace::read(&|_| Entry::Absent).unread, None);
        // An `include` that is not followed names a file that may be there
        // and is never asked for: 9.3.2 takes the first of these.
        for unfollowed in [
            "include('//:a.MODULE.bazel', dev_dependency = True)\n",
            "include(NAME)\n",
            "x = include('//:a.MODULE.bazel')\n",
        ] {
            let asked = std::cell::Cell::new(false);
            let ws = Workspace::read(&|path| match path {
                "MODULE.bazel" => Entry::Text(unfollowed.to_string()),
                "a.MODULE.bazel" => {
                    asked.set(true);
                    Entry::Text("x = 1\n".to_string())
                }
                _ => Entry::Absent,
            });
            assert_eq!(ws.unread.as_ref(), ws.doubts.first(), "{unfollowed}");
            assert!(!asked.get(), "{unfollowed}");
            assert_eq!(ws.doubts.len(), 1, "{unfollowed}");
        }
        // A statement that is no `include` leaves no file unread.
        let load = "load('//:defs.bzl', 'deps')\n";
        let view = |path: &str| match path {
            "MODULE.bazel" => Entry::Text(load.to_string()),
            _ => Entry::Absent,
        };
        let ws = Workspace::read(&view);
        assert_eq!((ws.unread, ws.doubts.len()), (None, 1));
    }

    /// The view of files handed over in memory holds what was handed over,
    /// a file that is no text as one that cannot be read.
    #[test]
    fn the_view_of_a_project_in_memory_holds_its_files() {
        let mut project = MemoryProject::new();
        project.insert_text("MODULE.bazel", "x = 1\n");
        project.insert_present("WORKSPACE");
        let view = memory(&project);
        assert_eq!(view("MODULE.bazel"), Entry::Text("x = 1\n".to_string()));
        assert!(matches!(view("WORKSPACE"), Entry::Unreadable(_)));
        assert_eq!(view("WORKSPACE.bazel"), Entry::Absent);
    }

    #[test]
    fn the_files_of_a_workspace_are_bounded() {
        // 300 files in a chain: the first 256 are read, and no other is
        // asked for.
        let chain = |at: usize| format!("{at}.MODULE.bazel");
        let asked = std::cell::Cell::new(0);
        let ws = Workspace::read(&|path| {
            asked.set(asked.get() + 1);
            let at: Option<usize> = path.split('.').next().and_then(|at| at.parse().ok());
            match at.or((path == "MODULE.bazel").then_some(0)) {
                Some(at) if at < 300 => Entry::Text(format!("include('//:{}')\n", chain(at + 1))),
                _ => Entry::Absent,
            }
        });
        assert_eq!((ws.files.len(), asked.get()), (256, 256 + 3));
        let want = "256.MODULE.bazel:0: it is one more than the 256 files that are asked for; \
                    255.MODULE.bazel:1 includes it";
        assert_eq!(doubts(&ws.doubts), [want]);
        // The file past the bound may be there.
        assert_eq!(ws.unread.as_ref(), ws.doubts.first());
        // Nine files of nearly 1 MiB: the ninth is past 8 MiB.
        let big = format!("#{}\n", "x".repeat(MAX_BYTES - 64));
        let ws = Workspace::read(&|path| match path {
            "MODULE.bazel" => {
                let includes = (0..9).map(|at| format!("include('//:{}')\n", chain(at)));
                Entry::Text(includes.collect())
            }
            _ => Entry::Text(big.clone()),
        });
        assert_eq!(ws.files.len(), 9);
        let want = "8.MODULE.bazel:0: the files of the workspace are larger than 8 MiB in all; \
                    MODULE.bazel:9 includes it";
        assert_eq!(doubts(&ws.doubts), [want]);
        // The ninth file is there.
        assert_eq!(ws.unread.as_ref(), ws.doubts.first());
        // The `WORKSPACE` file is one of the files of the workspace.
        let (file, why) = ("WORKSPACE.bzlmod".to_string(), OVER_TOTAL.to_string());
        assert_eq!(ws.legacy, Some(Err(Doubt { file, line: 0, why })));
        // One file over the limit of a file.
        let ws = module(&" ".repeat(MAX_BYTES + 1));
        assert_eq!(
            doubts(&ws.doubts),
            ["MODULE.bazel:1: it is larger than 1 MiB"]
        );
    }

    /// How many calls, arguments, bindings and uses a workspace holds.
    fn held(ws: &Workspace) -> usize {
        let args = |call: &Call| 1 + call.args.len();
        let of = |file: &File| {
            file.calls.iter().map(args).sum::<usize>() + file.binds.len() + file.uses.len()
        };
        let legacy = ws.legacy.iter().flatten().map(|(_, file)| of(file));
        ws.files
            .iter()
            .map(|(_, file)| of(file))
            .chain(legacy)
            .sum()
    }

    const TOO_LARGE: &str =
        "it is too large to read with certainty: more tokens, with the files before it, than are read";

    /// The files of a workspace share the tokens of one file. A file that
    /// has more than are left is a doubt, and takes none: a smaller one
    /// after it is read.
    #[test]
    fn the_tokens_of_a_workspace_are_bounded() {
        let names = "a\n".repeat(60_000);
        let pip =
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n";
        let ws = Workspace::read(&|path| match path {
            "MODULE.bazel" => {
                let includes = (0..4).map(|at| format!("include('//:{at}.MODULE.bazel')\n"));
                Entry::Text(includes.collect())
            }
            "3.MODULE.bazel" => Entry::Text(pip.to_string()),
            "WORKSPACE" => Entry::Text(format!("{names}pip_parse()\n")),
            path if path.ends_with(".MODULE.bazel") => Entry::Text(names.clone()),
            _ => Entry::Absent,
        });
        let read: Vec<&str> = ws.files.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            read,
            [
                "MODULE.bazel",
                "0.MODULE.bazel",
                "1.MODULE.bazel",
                "3.MODULE.bazel"
            ]
        );
        // 16 tokens in the root, 60,000 in each of two files: 11,056 are left.
        let line = MAX_TOKENS - 16 - 120_000 + 1;
        let want = format!("2.MODULE.bazel:{line}: {TOO_LARGE}; MODULE.bazel:3 includes it");
        assert_eq!(doubts(&ws.doubts), [want]);
        assert_eq!(sites(&ws.tags(&PIP, "parse")), ["3.MODULE.bazel:2"]);
        // The `WORKSPACE` file is read last, in what the others left.
        let (file, why) = ("WORKSPACE".to_string(), TOO_LARGE.to_string());
        let line = line - 13;
        assert_eq!(ws.legacy, Some(Err(Doubt { file, line, why })));
        assert!(held(&ws) <= MAX_TOKENS);
    }

    /// Files in the shapes that an index holds most of: at 1 MiB each,
    /// seven of them made a reader hold hundreds of MiB. Now a file that
    /// does not fit in the tokens of a workspace is a doubt, and what is
    /// held of the others is bounded by their tokens.
    #[test]
    fn no_workspace_makes_a_reader_hold_much() {
        let read = |unit: &str, tail: &str, files: usize, size: usize| {
            let times = size / (unit.len() + tail.len());
            let text = [unit.repeat(times), tail.repeat(times)].concat();
            let includes = (0..files).map(|at| format!("include('//:{at}.MODULE.bazel')\n"));
            let root: String = includes.collect();
            let ws = Workspace::read(&|path| match path {
                "MODULE.bazel" => Entry::Text(root.clone()),
                path if path.ends_with(".MODULE.bazel") => Entry::Text(text.clone()),
                _ => Entry::Absent,
            });
            assert!(held(&ws) <= MAX_TOKENS, "{unit:?}: {}", held(&ws));
            // Every file is read or is a doubt, and the first doubt says why.
            assert_eq!(ws.files.len() + ws.doubts.len(), files + 1, "{unit:?}");
            assert!(ws.doubts[0].why.starts_with(TOO_LARGE), "{unit:?}");
            ws.files.len() - 1
        };
        let started = std::time::Instant::now();
        // Many calls, arguments, uses and bindings; deep nesting; the
        // strings of a list and of a dict.
        for (unit, tail) in [
            ("f(a,b,c,d)\n", ""),
            ("f(a,", ")"),
            ("f(a=b,", ")"),
            ("a ", ""),
            ("a=b\n", ""),
            ("f(", ")"),
            ("[", "]"),
            ("f([\"\",", "])"),
            ("f({\"\":\"\",", "})"),
        ] {
            // Of three files of 120 KiB one fits, or two.
            assert!(read(unit, tail, 3, 120 << 10) >= 1, "{unit:?}");
        }
        // Seven files of 1 MiB: none fits. And of many small files, four.
        assert_eq!(read("f(a,b,c,d)\n", "", 7, MAX_BYTES - 64), 0);
        assert_eq!(read("f(a,b,c,d)\n", "", 40, 32_000), 4);
        // A doubt for each use would be as large as the index: a list
        // keeps the first ones. So does the list of an answer.
        let pip = "p = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n";
        let ws = module(&format!("{pip}{}", "use_repo p ".repeat(MAX_TOKENS / 4)));
        assert_eq!(ws.files[0].1.uses.len(), MAX_TOKENS / 2);
        assert_eq!(ws.doubts.len(), MAX_DOUBTS);
        assert_eq!(ws.tags(&PIP, "parse").doubts.len(), MAX_DOUBTS);
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(60), "{took:?}");
    }

    /// Bazel refuses a `MODULE.bazel` that holds an `if`, a `for` or a
    /// `def` statement, or a `load` (`DotBazelFileSyntaxChecker`, the same
    /// at 7.7.2, 8.8.2 and 9.3.2). The calls below one are listed as
    /// statements that run, so each is a doubt about every answer.
    #[test]
    fn a_statement_bazel_refuses_in_a_module_file_is_a_doubt() {
        let pip = "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n";
        let refused = |word: &str| format!("`{word}` starts a statement, which Bazel refuses here");
        for (text, why, calls, whole) in [
            (
                "if False:\n    pip.parse(hub_name = 'never')\n",
                refused("if"),
                1,
                1,
            ),
            (
                "for hub in []:\n    pip.parse(hub_name = hub)\n",
                refused("for"),
                1,
                1,
            ),
            (
                "def hubs():\n    pip.parse(hub_name = 'uncalled')\n",
                refused("def"),
                1,
                1,
            ),
            ("x = 1; if x: pip.parse()\n", refused("if"), 1, 0),
            // What a `load` binds is not followed: this is not Bazel's
            // `use_extension`.
            (
                "load('//:defs.bzl', 'use_extension')\n",
                "this `load` cannot be read".to_string(),
                0,
                0,
            ),
        ] {
            for files in [
                vec![("MODULE.bazel", format!("{pip}{text}"))],
                vec![
                    ("MODULE.bazel", "include('//:a.MODULE.bazel')\n".to_string()),
                    ("a.MODULE.bazel", format!("{pip}{text}")),
                ],
            ] {
                let files: Vec<(&str, &str)> = (files.iter())
                    .map(|(path, text)| (*path, text.as_str()))
                    .collect();
                let ws = workspace(&files);
                let want = format!("{}:2: {why}", files[files.len() - 1].0);
                assert_eq!(doubts(&ws.doubts), [want], "{text}");
                // The call in the body is listed, on a line of its own as
                // a statement that runs: only the doubt says otherwise.
                let tags = ws.tags(&PIP, "parse");
                let runs = tags.calls.iter().filter(|tag| tag.call.whole).count();
                assert_eq!((tags.calls.len(), runs), (calls, whole), "{text}");
            }
        }
        // A conditional expression and a comprehension are no statements.
        let ws = module(&format!(
            "{pip}pip.parse() if x else None\n[pip.parse(hub_name = hub) for hub in hubs if hub]\n"
        ));
        assert_eq!(ws.doubts, []);
    }

    /// Bazel 7 takes repositories from a `WORKSPACE` file beside
    /// `MODULE.bazel`, Bazel 8 when it is told to, Bazel 9 never. The file
    /// it would take is reported apart from the doubts, with its calls,
    /// when it says more than `workspace(...)`.
    #[test]
    fn a_workspace_file_that_defines_something_is_reported_apart() {
        let root = "module(name = 'shop')\n";
        let pip_parse = "load('@rules_python//python:pip.bzl', 'pip_parse')\n\
                         pip_parse(name = 'pypi', requirements_lock = '//:requirements.txt')\n";
        let legacy = |files: &[(&str, &str)]| {
            let ws = workspace(files);
            // No call of the tag and no doubt: the answer from MODULE.bazel.
            assert_eq!(ws.tags(&PIP, "parse"), Tags::default(), "{files:?}");
            assert_eq!(ws.doubts, [], "{files:?}");
            ws.legacy.map(|legacy| match legacy {
                Ok((file, read)) => {
                    let callees: Vec<&str> =
                        read.calls.iter().map(|call| call.callee.as_str()).collect();
                    format!("{file}: {}", callees.join(" "))
                }
                Err(doubt) => format!("{}:{}: {}", doubt.file, doubt.line, doubt.why),
            })
        };
        let hub = Some("WORKSPACE: load pip_parse".to_string());
        assert_eq!(
            legacy(&[("MODULE.bazel", root), ("WORKSPACE", pip_parse)]),
            hub
        );
        // Without a MODULE.bazel too.
        assert_eq!(legacy(&[("WORKSPACE", pip_parse)]), hub);
        // The first of the three names is the file Bazel takes: an empty
        // `WORKSPACE.bzlmod` is how a workspace turns the old file off.
        let other = "http_archive(name = 'x')\n";
        for (files, want) in [
            (
                vec![("WORKSPACE", pip_parse), ("WORKSPACE.bazel", other)],
                Some("WORKSPACE.bazel: http_archive"),
            ),
            (
                vec![("WORKSPACE.bazel", pip_parse), ("WORKSPACE.bzlmod", other)],
                Some("WORKSPACE.bzlmod: http_archive"),
            ),
            (
                vec![("WORKSPACE", pip_parse), ("WORKSPACE.bzlmod", "")],
                None,
            ),
            // A file that defines nothing says nothing.
            (vec![("WORKSPACE", "")], None),
            (vec![("WORKSPACE", "# pip_parse(name = 'pypi')\n")], None),
            (vec![("WORKSPACE", "workspace(name = 'shop')\n")], None),
            (
                vec![("WORKSPACE", "NAME = 'shop'\nworkspace(name = NAME)\n")],
                None,
            ),
            // Any other call does, also one under the name of `workspace`.
            (
                vec![("WORKSPACE", "workspace(name = name())\n")],
                Some("WORKSPACE: workspace name"),
            ),
            (
                vec![(
                    "WORKSPACE",
                    "workspace = pip_parse\nworkspace(name = 'pypi')\n",
                )],
                Some("WORKSPACE: workspace"),
            ),
            // And a file that cannot be read may define anything.
            (
                vec![("WORKSPACE", "workspace(name = 'shop')\npip_parse(\n")],
                Some("WORKSPACE:2: a bracket is never closed"),
            ),
        ] {
            let mut all = vec![("MODULE.bazel", root)];
            all.extend(files);
            assert_eq!(legacy(&all).as_deref(), want, "{all:?}");
        }
        // What the view cannot give is told apart from a file that is
        // read; a directory of that name is passed over, as Bazel does.
        let ws = Workspace::read(&|path| match path {
            "MODULE.bazel" => Entry::Text(root.to_string()),
            "WORKSPACE.bazel" => Entry::Unreadable(NOT_A_FILE.to_string()),
            "WORKSPACE" => Entry::Unreadable("it is not UTF-8".to_string()),
            _ => Entry::Absent,
        });
        let (file, why) = (
            "WORKSPACE".to_string(),
            "it cannot be read: it is not UTF-8".to_string(),
        );
        assert_eq!(ws.legacy, Some(Err(Doubt { file, line: 0, why })));
        assert_eq!(ws.doubts, []);
    }

    /// A file that grows after it was opened is refused: cut at the bound
    /// it would be read as if it ended there.
    #[test]
    fn a_file_that_grows_past_the_bound_is_not_cut_there() {
        let read = |len: u64| text(std::io::repeat(b'#').take(len), MAX_BYTES);
        assert_eq!(read(MAX_BYTES as u64).unwrap().len(), MAX_BYTES);
        for len in [MAX_BYTES as u64 + 1, u64::MAX] {
            let refused = read(len).unwrap_err();
            assert_eq!(refused.to_string(), "it is larger than 1 MiB", "{len}");
        }
        assert_eq!(
            text(&b"caf\xe9"[..], MAX_BYTES).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(text(&b"caf\xc3\xa9"[..], MAX_BYTES).unwrap(), "caf\u{e9}");
    }

    /// A command that has written `MODULE.bazel` in a group commit reads
    /// what it wrote, before the commit puts it on disk.
    #[tokio::test]
    async fn a_write_the_run_still_holds_is_what_is_read() {
        use crate::utils::fs::{atomic_write_bytes, remove_file};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let hub = |name: &str| {
            let pip = "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')";
            format!("{pip}\npip.parse(hub_name = '{name}')\n")
        };
        let include = |name: &str| format!("include('//tools:{name}.MODULE.bazel')\n");
        std::fs::create_dir(root.join("tools")).unwrap();
        let on_disk = [include("kept"), include("gone")].concat();
        std::fs::write(root.join("MODULE.bazel"), &on_disk).unwrap();
        std::fs::write(root.join("tools/kept.MODULE.bazel"), hub("disk")).unwrap();
        std::fs::write(root.join("tools/gone.MODULE.bazel"), hub("gone")).unwrap();
        let hubs = || {
            let ws = Workspace::read(&disk(root));
            let tags = ws.tags(&PIP, "parse");
            let name = |tag: &Tag| string(tag.call.arg("hub_name")).to_string();
            (
                tags.calls.iter().map(name).collect::<Vec<_>>(),
                doubts(&ws.doubts),
            )
        };
        assert_eq!(
            hubs(),
            (vec!["disk".to_string(), "gone".to_string()], vec![])
        );

        // The run rewrites the root and one included file, adds a file
        // and removes one. Nothing of it is on disk.
        let run = crate::utils::group_commit::GroupCommit::begin(root);
        let pending = [on_disk.as_str(), &include("new"), &hub("root")].concat();
        let write = |path: &str, text: String| {
            let path = root.join(path);
            async move { atomic_write_bytes(&path, text.as_bytes()).await.unwrap() }
        };
        write("MODULE.bazel", pending).await;
        write("tools/kept.MODULE.bazel", hub("rewritten")).await;
        write("tools/new.MODULE.bazel", hub("new")).await;
        remove_file(&root.join("tools/gone.MODULE.bazel"))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("MODULE.bazel")).unwrap(),
            on_disk
        );
        assert!(!root.join("tools/new.MODULE.bazel").exists());
        let gone = "tools/gone.MODULE.bazel:0: it does not exist; MODULE.bazel:2 includes it";
        assert_eq!(
            hubs(),
            (
                vec![
                    "root".to_string(),
                    "rewritten".to_string(),
                    "new".to_string()
                ],
                vec![gone.to_string()]
            )
        );
        // A write that is held is bounded and checked like a file.
        let view = disk(root);
        write("tools/new.MODULE.bazel", "#".repeat(MAX_BYTES + 1)).await;
        let big = Entry::Unreadable("it is larger than 1 MiB".to_string());
        assert_eq!(view("tools/new.MODULE.bazel"), big);
        let lock = disk_up_to(root, 2 * MAX_BYTES);
        assert!(matches!(lock("tools/new.MODULE.bazel"), Entry::Text(_)));
        atomic_write_bytes(&root.join("tools/new.MODULE.bazel"), b"# caf\xe9\n")
            .await
            .unwrap();
        let latin1 = Entry::Unreadable("it is not UTF-8".to_string());
        assert_eq!(view("tools/new.MODULE.bazel"), latin1);
        // And none is read from outside the root that is asked.
        let out = Entry::Unreadable("it leads out of the Bazel workspace".to_string());
        let below = root.join("tools");
        assert_eq!(disk(&below)("../MODULE.bazel"), out);
        assert_eq!(
            disk(&below)(root.join("MODULE.bazel").to_str().unwrap()),
            out
        );

        // The run is dropped without a commit: the disk is what is read.
        drop(run);
        assert_eq!(
            hubs(),
            (vec!["disk".to_string(), "gone".to_string()], vec![])
        );
    }

    #[test]
    fn the_checkout_on_disk_is_read_through_the_same_code() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        for (path, text) in SHOP {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let ws = Workspace::read(&disk(&root));
        assert_eq!(ws.doubts, []);
        assert_eq!(ws.files.len(), 3);
        assert_eq!(ws.legacy, None);
        let memory = workspace(&SHOP);
        for (extension, tag) in [
            (NPM, "npm_translate_lock"),
            (PIP, "parse"),
            (GO_DEPS, "from_file"),
        ] {
            assert_eq!(ws.tags(&extension, tag), memory.tags(&extension, tag));
        }
        // What is not a file of text to read.
        let view = disk(&root);
        assert_eq!(view("MODULE.bazel"), Entry::Text(ROOT.to_string()));
        assert_eq!(view("missing.MODULE.bazel"), Entry::Absent);
        assert_eq!(view("MODULE.bazel/below"), Entry::Absent);
        assert!(matches!(view("tools"), Entry::Unreadable(_)), "a directory");
        // A path that leaves the root, with or without a link, has one
        // reason, and no reason names a path of this machine.
        let out = Entry::Unreadable("it leads out of the Bazel workspace".to_string());
        std::fs::write(tmp.path().join("outside.MODULE.bazel"), "").unwrap();
        assert_eq!(view("../outside.MODULE.bazel"), out);
        let outside = tmp.path().join("outside.MODULE.bazel");
        assert_eq!(view(outside.to_str().unwrap()), out);
        #[cfg(unix)]
        {
            let irregular = Entry::Unreadable("it is not a regular file".to_string());
            assert_eq!(view("tools"), irregular);
            let fifo = std::ffi::CString::new(root.join("fifo.MODULE.bazel").to_str().unwrap());
            assert_eq!(unsafe { libc::mkfifo(fifo.unwrap().as_ptr(), 0o600) }, 0);
            assert_eq!(view("fifo.MODULE.bazel"), irregular);
        }
        std::fs::write(root.join("latin1.MODULE.bazel"), b"# caf\xe9\n").unwrap();
        let latin1 = Entry::Unreadable("it is not UTF-8".to_string());
        assert_eq!(view("latin1.MODULE.bazel"), latin1);
        std::fs::write(root.join("big.MODULE.bazel"), vec![b'#'; MAX_BYTES + 1]).unwrap();
        let big = Entry::Unreadable("it is larger than 1 MiB".to_string());
        assert_eq!(view("big.MODULE.bazel"), big);
        std::fs::write(root.join("full.MODULE.bazel"), vec![b'#'; MAX_BYTES]).unwrap();
        assert!(matches!(view("full.MODULE.bazel"), Entry::Text(_)));
        // A `WORKSPACE` file beside them, under a directory that has
        // another of its names: Bazel takes the first that is a file.
        std::fs::create_dir(root.join("WORKSPACE.bazel")).unwrap();
        std::fs::write(root.join("WORKSPACE"), "maven_install(artifacts = [])\n").unwrap();
        let ws = Workspace::read(&disk(&root));
        let Some(Ok((file, read))) = &ws.legacy else {
            panic!("{:?}", ws.legacy);
        };
        assert_eq!(
            (file.as_str(), read.calls[0].callee.as_str()),
            ("WORKSPACE", "maven_install")
        );
        assert_eq!((ws.files.len(), &ws.doubts), (3, &vec![]));
        // The same view with the bound of a lock, which is larger.
        let lock = disk_up_to(&root, 2 * MAX_BYTES);
        assert!(matches!(lock("big.MODULE.bazel"), Entry::Text(_)));
        std::fs::write(root.join("huge.json"), vec![b' '; 2 * MAX_BYTES + 1]).unwrap();
        let huge = Entry::Unreadable("it is larger than 2 MiB".to_string());
        assert_eq!(lock("huge.json"), huge);
        assert_eq!(lock("../outside.MODULE.bazel"), out);
        // And a root that is not there at all.
        assert_eq!(
            disk(&tmp.path().join("gone"))("MODULE.bazel"),
            Entry::Absent
        );
        assert_eq!(
            Workspace::read(&disk(&tmp.path().join("gone"))).files.len(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_that_leads_out_of_the_bazel_root_is_not_followed() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let (root, outside) = (
            tmp.path().join("checkout/app"),
            tmp.path().join("checkout/shared"),
        );
        std::fs::create_dir_all(root.join("tools")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let pip =
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\npip.parse()\n";
        std::fs::write(outside.join("pip.MODULE.bazel"), pip).unwrap();
        std::fs::write(root.join("tools/pip.MODULE.bazel"), pip).unwrap();
        // A link to a file of the root, a link to one outside it, a
        // directory that is a link out, and a link to nothing.
        symlink("tools/pip.MODULE.bazel", root.join("in.MODULE.bazel")).unwrap();
        symlink(
            outside.join("pip.MODULE.bazel"),
            root.join("out.MODULE.bazel"),
        )
        .unwrap();
        symlink("../shared", root.join("shared")).unwrap();
        symlink("nowhere", root.join("dangling.MODULE.bazel")).unwrap();
        let includes = ["//:in", "//:out", "//shared:pip", "//:dangling"];
        let includes = includes.map(|label| format!("include('{label}.MODULE.bazel')\n"));
        std::fs::write(root.join("MODULE.bazel"), includes.concat()).unwrap();

        let ws = Workspace::read(&disk(&root));
        let out = "it cannot be read: it leads out of the Bazel workspace";
        assert_eq!(
            doubts(&ws.doubts),
            [
                format!("out.MODULE.bazel:0: {out}; MODULE.bazel:2 includes it"),
                format!("shared/pip.MODULE.bazel:0: {out}; MODULE.bazel:3 includes it"),
                "dangling.MODULE.bazel:0: it does not exist; MODULE.bazel:4 includes it"
                    .to_string(),
            ]
        );
        assert_eq!(sites(&ws.tags(&PIP, "parse")), ["in.MODULE.bazel:2"]);
        // The root itself may be reached through a link.
        symlink(&root, tmp.path().join("alias")).unwrap();
        let ws = Workspace::read(&disk(&tmp.path().join("alias")));
        assert_eq!(ws.files.len(), 2);
    }
}
