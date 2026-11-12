//! Lock check detection (hazard HZ-09; design 2.10, "lock check tests").
//!
//! A lock check is a target that regenerates a lock, or hashes its bytes,
//! and fails when the committed file differs. After a hosted rewrite its
//! test goes red, and for three of the five kinds the update command that
//! makes it green again erases the pin. So a lane refuses a lock that a
//! check covers, and the refusal prints the manual procedure where a probe
//! ran one.
//!
//! [`scan`] looks in the two places a check shows without running Bazel:
//!
//! - the lock's own header. pip-compile and uv both record the command
//!   that wrote the file, and the rulesets pass them `bazel run <label>`
//!   (read at `rules_python@2.5.0-rc4:python/private/pypi/dependency_resolver/dependency_resolver.py:169-174`,
//!   `python/uv/private/lock.bzl:321` and `rules_uv@v0.90.0:uv/private/pip.bzl:52-57`).
//!   The header finds a check that a wrapper macro of the project
//!   declares, which no scan for the ruleset's own macro name would;
//! - the `BUILD.bazel` or `BUILD` file of the lock's directory and of
//!   each directory above it: a call of `compile_pip_requirements`,
//!   rules_uv `pip_compile`, rules_python `lock`, `gazelle_python_manifest`
//!   or a `diff_test` over a checked-in `requirements.bzl`.
//!
//! Only the `compile_pip_requirements` half ran on real Bazel (probe Y6:
//! rules_python 2.5.0-rc4 on 9.3.2 and 1.4.1 on 7.7.2). The other four
//! detectors rest on reading the macros' sources, and they err on the
//! side of a check: a rules_python `lock` over a `uv.lock` is reported
//! like one over a requirements file, although its update reads the
//! paired `pyproject.toml` and it has no test target, because no cell
//! has shown that the pin survives it.
//!
//! What cannot be read is not "no check": a BUILD file that cannot be
//! parsed, a check macro used where the statement reader has no model and
//! a computed lock argument are each reported as [`Unread`], and the
//! recognizer turns them into gaps, which refuse.

use super::rules_python::LABEL_NOT_LITERAL;
use crate::bazel::derived::LockCheckKind;
use crate::bazel::label::Label;
use crate::bazel::model::{DerivedState, FileText, FileView, Gap};
use crate::bazel::starlark::{self, Call, Dialect, File, Lookup, StmtKind, Value, ValueKind};
use crate::bazel::version::Tri;
use crate::formats::text::strip_bom_bytes;

/// The names of a package's BUILD file. Bazel reads `BUILD.bazel` when a
/// directory holds both.
const BUILD_FILES: [&str; 2] = ["BUILD.bazel", "BUILD"];

/// How many leading lines of a lock may hold its header comment.
const HEADER_LINES: usize = 16;

/// How many directories, the lock's own first, are searched for a BUILD
/// file. A lock nested deeper is reported as not fully scanned.
const MAX_DIRECTORIES: usize = 32;

/// The file name of a checked-in copy of the file `pip_parse` generates.
const REQUIREMENTS_BZL: &str = "requirements.bzl";

/// The locks that are not requirements files, by name. The generated
/// `requirements.bzl` embeds requirement lines, so a diff test of its
/// checked-in copy covers none of these.
const OTHER_FORMATS: [&str; 4] = ["uv.lock", "poetry.lock", "pdm.lock", "pylock.toml"];

/// Where a lock check was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckSource {
    /// The `bazel run` line of the lock's own header comment.
    Header,
    /// A macro call in a BUILD file, by root-relative path and line.
    Build { file: String, line: usize },
}

/// One lock check over one lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockCheck {
    pub kind: LockCheckKind,
    /// The label of the macro's `name`: `//third_party/py:requirements`.
    /// The targets it expands to (`.test`, `_test`, `.update`) are
    /// derived from it where a message names one.
    pub target: String,
    pub source: CheckSource,
}

/// A place where a lock check could stand unseen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    /// Root-relative path of the file to fix.
    pub file: String,
    pub line: usize,
    pub why: String,
}

/// The lock checks found over one lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipCompileDetail {
    /// The lock, relative to the Bazel root.
    pub lock: String,
    pub checks: Vec<LockCheck>,
    /// Non-empty when the scan cannot vouch that `checks` is complete.
    pub unread: Vec<Unread>,
}

impl PipCompileDetail {
    /// The checks as the rows a recognizer declares in `Hub::derived`: an
    /// edit of the lock leaves each of them stale.
    pub fn derived(&self) -> Vec<DerivedState> {
        let row = |check: &LockCheck| DerivedState::LockCheck {
            target: check.target.clone(),
            input: self.lock.clone(),
            kind: check.kind,
        };
        self.checks.iter().map(row).collect()
    }

    /// What kept the scan from being complete, as the gaps that leave the
    /// ecosystem undetermined.
    pub fn gaps(&self) -> Vec<Gap> {
        let gap = |unread: &Unread| Gap {
            token: LABEL_NOT_LITERAL,
            file: unread.file.clone(),
            detail: format!(
                "{}:{}: {}, so a lock check over `{}` cannot be ruled out",
                unread.file, unread.line, unread.why, self.lock
            ),
        };
        self.unread.iter().map(gap).collect()
    }

    fn add(&mut self, check: LockCheck) {
        let same = |seen: &LockCheck| {
            seen.target == check.target
                && std::mem::discriminant(&seen.kind) == std::mem::discriminant(&check.kind)
        };
        if !self.checks.iter().any(same) {
            self.checks.push(check);
        }
    }

    fn unread(&mut self, file: &str, line: usize, why: impl Into<String>) {
        let (file, why) = (file.to_string(), why.into());
        self.unread.push(Unread { file, line, why });
    }
}

/// What a macro's regeneration does with the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Made {
    /// `compile_pip_requirements`: a test, and an update that keeps only
    /// what the `.in` source names.
    PipCompile,
    /// rules_uv `pip_compile` and rules_python `lock`: the update resolves
    /// the lock again from its source.
    Regenerated,
    /// `gazelle_python_manifest`: its manifest holds a digest of the lock.
    Manifest,
    /// A `diff_test` over a checked-in `requirements.bzl`.
    DiffTest,
}

/// One macro that declares a lock check, by the name it has in the file
/// that defines it. A project that loads it under another local name is
/// followed; one that wraps it in a macro of its own shows in the lock's
/// header only.
struct Macro {
    symbol: &'static str,
    made: Made,
    /// The arguments that name a covered file: a label, a list of labels,
    /// or for `lock` a path relative to the package.
    files: &'static [&'static str],
}

/// `compile_pip_requirements(name, requirements_txt = name + ".txt",
/// requirements_{linux,darwin,windows})`
/// (`rules_python@2.5.0-rc4:python/private/pypi/pip_compile.bzl:35-107`);
/// `pip_compile(name, requirements_txt = "//:requirements.txt")`
/// (`rules_uv@v0.90.0:uv/pip.bzl:54-55`); `lock(name, srcs, out)`
/// (`rules_python@2.5.0-rc4:python/uv/private/lock.bzl:613`);
/// `gazelle_python_manifest(name, requirements | lockfiles)`
/// (`gazelle/manifest/defs.bzl:23`); bazel_skylib `diff_test(file1, file2)`.
const MACROS: [Macro; 5] = [
    Macro {
        symbol: "compile_pip_requirements",
        made: Made::PipCompile,
        files: &[
            "requirements_txt",
            "requirements_linux",
            "requirements_darwin",
            "requirements_windows",
        ],
    },
    Macro {
        symbol: "pip_compile",
        made: Made::Regenerated,
        files: &["requirements_txt"],
    },
    Macro {
        symbol: "lock",
        made: Made::Regenerated,
        files: &["out"],
    },
    Macro {
        symbol: "gazelle_python_manifest",
        made: Made::Manifest,
        files: &["requirements", "lockfiles"],
    },
    Macro {
        symbol: "diff_test",
        made: Made::DiffTest,
        files: &["file1", "file2"],
    },
];

impl Macro {
    fn kind(&self, dot_test: Tri) -> LockCheckKind {
        match self.made {
            Made::PipCompile => LockCheckKind::PipCompile { dot_test },
            Made::Regenerated => LockCheckKind::Erasing,
            Made::Manifest => LockCheckKind::GazelleManifest,
            Made::DiffTest => LockCheckKind::RequirementsBzl,
        }
    }

    /// The file an absent argument stands for, relative to the Bazel root.
    fn default(&self, argument: &str, package: &str, name: Option<&str>) -> Option<String> {
        match (self.symbol, argument) {
            ("compile_pip_requirements", "requirements_txt") => {
                Some(join(package, &format!("{}.txt", name?)))
            }
            ("pip_compile", "requirements_txt") => Some("requirements.txt".to_string()),
            _ => None,
        }
    }

    /// Whether the call covers `lock`. `None` when an argument that would
    /// decide it cannot be read.
    fn covers(
        &self,
        file: &File<'_>,
        call: &Call,
        package: &str,
        name: Option<&str>,
        lock: &str,
    ) -> Option<bool> {
        // A diff test of a generated `requirements.bzl` covers every lock
        // the hub reads: the generated file embeds their lines.
        let names = |path: &str| match self.made {
            Made::DiffTest => path.rsplit('/').next() == Some(REQUIREMENTS_BZL),
            _ => path == lock,
        };
        let path = |label: &str| Label::parse(label, Some(package)).ok()?.path();
        let (mut hit, mut unread) = (false, false);
        for argument in self.files {
            match strings(file, call, argument) {
                Ok(Some(labels)) => {
                    let mut paths = labels.iter().filter_map(|label| path(label));
                    hit |= paths.any(|path| names(&path));
                }
                Ok(None) => match self.default(argument, package, name) {
                    Some(default) => hit |= names(&default),
                    // The default is built from a name that was not read.
                    None => unread |= self.default(argument, package, Some("")).is_some(),
                },
                Err(()) => unread = true,
            }
        }
        match (hit, unread) {
            (true, _) => Some(true),
            (false, true) => None,
            (false, false) => Some(false),
        }
    }
}

/// `dir/name`, for a root-relative `dir` that is `""` at the root.
fn join(dir: &str, name: &str) -> String {
    match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    }
}

/// The strings the argument `name` gives after one level of constants: a
/// string, or the items of a list. `Ok(None)` when it is absent or `None`;
/// `Err` when it is computed, or a `*` or `**` argument may supply it.
fn strings<'f>(file: &'f File<'_>, call: &'f Call, name: &str) -> Result<Option<Vec<&'f str>>, ()> {
    let resolve = |value: &'f Value| match &value.kind {
        ValueKind::Ident(constant) => {
            let bound = file.constant(constant, value.span.0).exact().flatten();
            bound.unwrap_or(value)
        }
        _ => value,
    };
    let value = match call.arg(name) {
        Lookup::Absent => return Ok(None),
        Lookup::Found(value) => resolve(value),
        Lookup::Unknown => return Err(()),
    };
    match &value.kind {
        ValueKind::None => Ok(None),
        ValueKind::Str { text, .. } => Ok(Some(vec![text.as_str()])),
        ValueKind::List(items) => {
            let item = |item: &'f Value| resolve(item).as_str().ok_or(());
            items.iter().map(item).collect::<Result<_, _>>().map(Some)
        }
        _ => Err(()),
    }
}

/// The check the header comment of a lock records, when Bazel ran the
/// tool that wrote it.
///
/// pip-compile writes `# This file is autogenerated by pip-compile ...`
/// and, two lines down, `#    bazel run //:requirements.update` (probe Y6,
/// `rules-python/y6/rp2.5.0-index-b9.3.2/snap/c1-compiled.txt`). uv writes
/// `# This file was autogenerated by uv via the following command:` and
/// `#    bazel run @@//:name` (rules_uv) or `//pkg:name.update`
/// (rules_python `lock`). A header whose command is not `bazel run` names
/// no Bazel target, and no Bazel test compares the file.
fn header(src: &[u8], dot_test: Tri) -> Option<LockCheck> {
    let (mut pip_compile, mut command) = (false, None);
    for line in strip_bom_bytes(src)
        .split(|b| *b == b'\n')
        .take(HEADER_LINES)
    {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        // The first requirement or option line ends the header.
        let Some(comment) = line.strip_prefix(b"#") else {
            break;
        };
        let comment = comment.trim_ascii();
        pip_compile |= comment.windows(11).any(|word| word == b"pip-compile");
        let ran = |launcher: &[u8]| comment.strip_prefix(launcher);
        command = command.or(ran(b"bazel run ").or(ran(b"bazelisk run ")));
    }
    let command = std::str::from_utf8(command?).ok()?;
    let is_label = |word: &&str| word.starts_with("//") || word.starts_with('@');
    let written = command.split_whitespace().find(is_label)?;
    // The update target of a macro is `<name>.update`; rules_uv runs the
    // macro's own target.
    let target = match Label::parse(written, None) {
        Ok(label) if label.path().is_some() => {
            let name = label.name.strip_suffix(".update").unwrap_or(&label.name);
            format!("//{}:{name}", label.package)
        }
        _ => written
            .strip_suffix(".update")
            .unwrap_or(written)
            .to_string(),
    };
    let kind = match pip_compile {
        true => LockCheckKind::PipCompile { dot_test },
        // uv, or a generator this reader does not know: its update writes
        // the file again from its source.
        false => LockCheckKind::Erasing,
    };
    let source = CheckSource::Header;
    Some(LockCheck {
        kind,
        target,
        source,
    })
}

/// One BUILD file to scan.
struct Package<'p> {
    /// The BUILD file, relative to the Bazel root.
    path: &'p str,
    /// Its directory, which is its package.
    dir: &'p str,
    dot_test: Tri,
    /// A `requirements.bzl` stands in the directory, or the directory
    /// cannot be listed.
    copy_here: bool,
}

/// The checks the BUILD file of `package` declares over the lock.
fn build_file(package: &Package<'_>, src: &[u8], found: &mut PipCompileDetail) {
    let (path, dot_test) = (package.path, package.dot_test);
    let requirements = !OTHER_FORMATS.contains(&found.lock.rsplit('/').next().unwrap_or(""));
    let file = match starlark::read(src, Dialect::Build) {
        Ok(file) => file,
        Err(e) => {
            let line = 1 + src.iter().take(e.at).filter(|b| **b == b'\n').count();
            return found.unread(path, line, e.kind.describe());
        }
    };
    for stmt in &file.stmts {
        let StmtKind::Load(load) = &stmt.kind else {
            continue;
        };
        for symbol in &load.symbols {
            let Some(made) = MACROS.iter().find(|made| made.symbol == symbol.name) else {
                continue;
            };
            let diff_test = made.made == Made::DiffTest;
            if diff_test && !requirements {
                continue;
            }
            // `diff_test` compares any two files, and most of its calls
            // have nothing to do with a lock. One that was not read is a
            // doubt only where a checked-in copy stands beside the BUILD
            // file; a call that was read is judged by the files it names.
            let doubted = !diff_test || package.copy_here;
            // Every call must be a statement that was read: one under an
            // `if`, in a comprehension or behind a second binding of the
            // name could cover the lock unseen.
            let calls = file.calls(&symbol.local);
            for reason in calls.reasons().iter().filter(|_| doubted) {
                let why = format!(
                    "`{}` is used where it is not read ({})",
                    symbol.local,
                    reason.why.describe()
                );
                found.unread(path, file.line_of(reason.span.0), why);
            }
            for stmt in calls.seen() {
                let (StmtKind::Call(call) | StmtKind::Bind { call, .. }) = &stmt.kind else {
                    continue;
                };
                let line = file.line_of(stmt.span.0);
                let name = match strings(&file, call, "name") {
                    Ok(Some(name)) if name.len() == 1 => Some(name[0]),
                    _ => None,
                };
                match (
                    made.covers(&file, call, package.dir, name, &found.lock),
                    name,
                ) {
                    (Some(false), _) => {}
                    (Some(true), Some(name)) => found.add(LockCheck {
                        kind: made.kind(dot_test),
                        target: format!("//{}:{name}", package.dir),
                        source: CheckSource::Build {
                            file: path.to_string(),
                            line,
                        },
                    }),
                    _ if doubted => {
                        let why = format!(
                            "an argument of this `{}` call is computed; write its name and \
                             its files as literals",
                            symbol.local
                        );
                        found.unread(path, line, why);
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The lock checks over `lock`, a path relative to the Bazel root.
/// `dot_test` says whether rules_python is proven at or above 1.5.0, which
/// names the test of a `compile_pip_requirements` macro `<name>.test`
/// (`<name>_test` below).
pub fn scan(files: &dyn FileView, lock: &str, dot_test: Tri) -> PipCompileDetail {
    let mut found = PipCompileDetail {
        lock: lock.to_string(),
        checks: Vec::new(),
        unread: Vec::new(),
    };
    match files.read(lock) {
        FileText::Bytes(bytes) => found.checks.extend(header(&bytes, dot_test)),
        // A lock that is not there has no header; a BUILD rule can still
        // name it.
        FileText::Absent => {}
        FileText::Unreadable => found.unread(lock, 1, "the lock cannot be read"),
    }
    let parent = |path: &str| path.rsplit_once('/').map(|(dir, _)| dir.to_string());
    let mut dir = parent(lock).unwrap_or_default();
    for scanned in 0.. {
        if scanned == MAX_DIRECTORIES {
            let why = format!("the BUILD files more than {MAX_DIRECTORIES} levels up are not read");
            found.unread(&dir, 1, why);
            break;
        }
        for name in BUILD_FILES {
            let path = join(&dir, name);
            match files.read(&path) {
                FileText::Absent => continue,
                FileText::Unreadable => found.unread(&path, 1, "the file cannot be read"),
                FileText::Bytes(bytes) => {
                    let listed = files.list(&dir);
                    let copy = |names: &Vec<String>| names.iter().any(|n| n == REQUIREMENTS_BZL);
                    let package = Package {
                        path: &path,
                        dir: &dir,
                        dot_test,
                        copy_here: listed.as_ref().is_none_or(copy),
                    };
                    build_file(&package, &bytes, &mut found);
                }
            }
            break;
        }
        match parent(&dir) {
            Some(above) => dir = above,
            None if dir.is_empty() => break,
            None => dir.clear(),
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::rc::testing::Files;

    /// The header pip-compile wrote in probe Y6
    /// (`rules-python/y6/rp2.5.0-index-b9.3.2/snap/c1-compiled.txt`).
    const PIP_COMPILE_LOCK: &str = "#\n\
        # This file is autogenerated by pip-compile with Python 3.11\n\
        # by the following command:\n\
        #\n\
        #    bazel run //:requirements.update\n\
        #\n\
        --index-url http://127.0.0.1:47291/simple\n\
        \n\
        spvictim==1.0.0 \\\n    --hash=sha256:cecf23d2e612215c6512613873a29337301ed66f92a1e81810ce20d8f3bab993\n    \
        # via -r requirements.in\n";

    fn pip_compile(dot_test: Tri) -> LockCheckKind {
        LockCheckKind::PipCompile { dot_test }
    }

    fn checks(files: &[(&str, &str)], lock: &str) -> PipCompileDetail {
        scan(&Files::of(files), lock, Tri::Maybe)
    }

    /// `(kind, target)` of every check, and whether the scan was complete.
    fn found(files: &[(&str, &str)], lock: &str) -> (Vec<(LockCheckKind, String)>, bool) {
        let detail = checks(files, lock);
        let pairs = detail.checks.iter();
        let pairs = pairs.map(|check| (check.kind, check.target.clone()));
        (pairs.collect(), detail.unread.is_empty())
    }

    fn one(kind: LockCheckKind, target: &str) -> (Vec<(LockCheckKind, String)>, bool) {
        (vec![(kind, target.to_string())], true)
    }

    #[test]
    fn the_pip_compile_header_names_the_update_target() {
        let lock = "requirements_lock.txt";
        let detail = scan(&Files::of(&[(lock, PIP_COMPILE_LOCK)]), lock, Tri::Yes);
        assert_eq!(
            detail.checks,
            [LockCheck {
                kind: pip_compile(Tri::Yes),
                target: "//:requirements".to_string(),
                source: CheckSource::Header,
            }]
        );
        assert!(detail.unread.is_empty());
        // The row a recognizer declares: an edit of the lock stales it.
        assert_eq!(
            detail.derived(),
            [DerivedState::LockCheck {
                target: "//:requirements".to_string(),
                input: lock.to_string(),
                kind: pip_compile(Tri::Yes),
            }]
        );

        // The header of pip-tools before 7 has the same command line, and
        // a sub-package label keeps its package.
        let older = "#\n# This file is autogenerated by pip-compile with python 3.9\n\
                     # To update, run:\n#\n#    bazel run //third_party/py:reqs.update\n#\n";
        let lock = "third_party/py/requirements.txt";
        assert_eq!(
            found(&[(lock, older)], lock),
            one(pip_compile(Tri::Maybe), "//third_party/py:reqs")
        );
    }

    #[test]
    fn a_uv_header_is_a_check_whose_update_erases_the_pin() {
        // rules_uv runs the macro's own target and prints its canonical
        // label; rules_python `lock` prints `<name>.update`.
        for (command, target) in [
            (
                "bazel run @@//:generate_requirements_txt",
                "//:generate_requirements_txt",
            ),
            ("bazel run @//tools:requirements", "//tools:requirements"),
            ("bazel run //py:lock.update", "//py:lock"),
            ("bazelisk run --config=ci //py:lock.update", "//py:lock"),
        ] {
            let text = format!(
                "# This file was autogenerated by uv via the following command:\n\
                 #    {command}\nsix==1.16.0 \\\n    --hash=sha256:8abb\n"
            );
            assert_eq!(
                found(&[("requirements.txt", &text)], "requirements.txt"),
                one(LockCheckKind::Erasing, target),
                "{command}"
            );
        }
    }

    #[test]
    fn the_header_is_read_through_a_bom_and_crlf_and_only_at_the_top() {
        let crlf = format!("\u{feff}{}", PIP_COMPILE_LOCK.replace('\n', "\r\n"));
        assert_eq!(
            found(&[("requirements.txt", &crlf)], "requirements.txt"),
            one(pip_compile(Tri::Maybe), "//:requirements")
        );

        // A tool the user ran by hand names no Bazel target.
        let by_hand = "#\n# This file is autogenerated by pip-compile with Python 3.11\n\
                       # by the following command:\n#\n#    pip-compile --generate-hashes requirements.in\n#\n\
                       six==1.16.0\n";
        assert_eq!(found(&[("r.txt", by_hand)], "r.txt"), (vec![], true));

        // A comment below the first requirement is no header, and neither
        // is one past the header's length.
        let below = "six==1.16.0\n#    bazel run //:requirements.update\n";
        assert_eq!(found(&[("r.txt", below)], "r.txt"), (vec![], true));
        let far = format!(
            "{}#    bazel run //:requirements.update\n",
            "# x\n".repeat(HEADER_LINES)
        );
        assert_eq!(found(&[("r.txt", &far)], "r.txt"), (vec![], true));

        // No file, no header: a lock label can name a file that is not
        // committed yet.
        assert_eq!(found(&[], "requirements.txt"), (vec![], true));
    }

    #[test]
    fn compile_pip_requirements_covers_its_named_and_default_files() {
        // The fixture of the lock-check canary
        // (`heavy/rules_python/bzlmod/e9-compile/BUILD.bazel`).
        let build = "load(\"@rules_python//python:pip.bzl\", \"compile_pip_requirements\")\n\
                     \n\
                     compile_pip_requirements(\n    name = \"requirements\",\n    src = \"requirements.in\",\n    \
                     extra_args = [\"--no-emit-index-url\"],\n    requirements_txt = \"requirements_lock.txt\",\n)\n";
        let detail = checks(&[("BUILD.bazel", build)], "requirements_lock.txt");
        assert_eq!(
            detail.checks,
            [LockCheck {
                kind: pip_compile(Tri::Maybe),
                target: "//:requirements".to_string(),
                source: CheckSource::Build {
                    file: "BUILD.bazel".to_string(),
                    line: 3,
                },
            }]
        );
        // Another file of the package is not covered.
        assert_eq!(
            found(&[("BUILD.bazel", build)], "requirements.txt"),
            (vec![], true)
        );

        // With no `requirements_txt` the macro writes `<name>.txt`, and
        // the per-OS outputs are compared by the same test.
        let build = "load(\"@rules_python//python:pip.bzl\", \"compile_pip_requirements\")\n\
                     compile_pip_requirements(\n    name = \"requirements\",\n    \
                     requirements_darwin = \"requirements_darwin.txt\",\n    \
                     requirements_windows = \":requirements_windows.txt\",\n)\n";
        for lock in [
            "requirements.txt",
            "requirements_darwin.txt",
            "requirements_windows.txt",
        ] {
            let files = [("third_party/py/BUILD", build)];
            assert_eq!(
                found(&files, &format!("third_party/py/{lock}")),
                one(pip_compile(Tri::Maybe), "//third_party/py:requirements"),
                "{lock}"
            );
        }
        assert_eq!(
            found(
                &[("third_party/py/BUILD", build)],
                "third_party/py/requirements_linux.txt"
            ),
            (vec![], true)
        );
    }

    #[test]
    fn a_check_in_a_package_above_the_lock_is_found_by_its_label() {
        // The root package names a file of a directory with no BUILD file
        // by path, and one of another package by label.
        let build = "load(\"@rules_python//python:pip.bzl\", cpr = \"compile_pip_requirements\")\n\
                     LOCK = \"//third_party/py:requirements.txt\"\n\
                     cpr(name = \"by_path\", requirements_txt = \"locks/requirements.txt\")\n\
                     cpr(name = \"by_label\", requirements_txt = LOCK)\n";
        assert_eq!(
            found(&[("BUILD.bazel", build)], "locks/requirements.txt"),
            one(pip_compile(Tri::Maybe), "//:by_path")
        );
        let files = [
            ("BUILD.bazel", build),
            (
                "third_party/py/BUILD.bazel",
                "exports_files([\"requirements.txt\"])\n",
            ),
        ];
        assert_eq!(
            found(&files, "third_party/py/requirements.txt"),
            one(pip_compile(Tri::Maybe), "//:by_label")
        );

        // Bazel reads `BUILD.bazel` when a directory has both.
        let files = [
            ("BUILD.bazel", "filegroup(name = \"x\")\n"),
            ("BUILD", build),
        ];
        assert_eq!(found(&files, "locks/requirements.txt"), (vec![], true));
    }

    #[test]
    fn the_other_generators_and_the_manifest_are_found() {
        // rules_uv: both files default to the root package.
        let uv = "load(\"@rules_uv//uv:pip.bzl\", \"pip_compile\")\n\
                  pip_compile(name = \"generate\")\n\
                  pip_compile(name = \"linux\", requirements_txt = \"//py:requirements_linux.txt\")\n";
        assert_eq!(
            found(&[("BUILD", uv)], "requirements.txt"),
            one(LockCheckKind::Erasing, "//:generate")
        );
        let files = [("BUILD", uv), ("py/BUILD", "")];
        assert_eq!(
            found(&files, "py/requirements_linux.txt"),
            one(LockCheckKind::Erasing, "//:linux")
        );

        // rules_python `lock`: `out` is a path in the macro's package.
        let lock = "load(\"@rules_python//python/uv:lock.bzl\", \"lock\")\n\
                    lock(name = \"requirements\", srcs = [\"pyproject.toml\"], out = \"requirements.txt\")\n";
        assert_eq!(
            found(&[("py/BUILD.bazel", lock)], "py/requirements.txt"),
            one(LockCheckKind::Erasing, "//py:requirements")
        );
        assert_eq!(
            found(&[("py/BUILD.bazel", lock)], "py/uv.lock"),
            (vec![], true)
        );

        // The gazelle manifest hashes the lock: one label before 2.4.0,
        // `lockfiles` from it, a `uv.lock` among them.
        let manifest = "load(\"@rules_python_gazelle_plugin//manifest:defs.bzl\", \"gazelle_python_manifest\")\n\
                        gazelle_python_manifest(\n    name = \"gazelle_python_manifest\",\n    \
                        modules_mapping = \":modules_map\",\n    pip_repository_name = \"pip\",\n    \
                        requirements = \"//:requirements_lock.txt\",\n)\n\
                        gazelle_python_manifest(\n    name = \"uv_manifest\",\n    \
                        lockfiles = [\"uv.lock\", \"//:requirements_lock.txt\"],\n    \
                        modules_mapping = \":modules_map\",\n    pip_repository_name = \"pypi\",\n)\n";
        assert_eq!(
            found(&[("BUILD.bazel", manifest)], "uv.lock"),
            one(LockCheckKind::GazelleManifest, "//:uv_manifest")
        );
        let both = found(&[("BUILD.bazel", manifest)], "requirements_lock.txt");
        let manifests = ["//:gazelle_python_manifest", "//:uv_manifest"];
        let manifests =
            manifests.map(|target| (LockCheckKind::GazelleManifest, target.to_string()));
        assert_eq!(both, (manifests.to_vec(), true));
    }

    #[test]
    fn a_diff_test_over_requirements_bzl_covers_every_lock_of_the_package() {
        // `rules_python@2.5.0-rc4:examples/pip_parse_vendored/BUILD.bazel`.
        let build = "load(\"@bazel_skylib//rules:diff_test.bzl\", \"diff_test\")\n\
                     diff_test(\n    name = \"test_vendored\",\n    \
                     failure_message = \"Please run:  bazel run //:vendor_requirements\",\n    \
                     file1 = \"requirements.bzl\",\n    file2 = \"make_platform_agnostic\",\n)\n\
                     diff_test(name = \"other\", file1 = \"a.txt\", file2 = \"b.txt\")\n";
        assert_eq!(
            found(&[("BUILD.bazel", build)], "requirements.txt"),
            one(LockCheckKind::RequirementsBzl, "//:test_vendored")
        );
        // The copy embeds requirement lines: a lock of another format is
        // not what it is generated from.
        assert_eq!(found(&[("BUILD.bazel", build)], "uv.lock"), (vec![], true));

        // `diff_test` compares any two files. Calls that were not read
        // are a doubt only where a checked-in copy stands beside them.
        let unrelated = "load(\"@bazel_skylib//rules:diff_test.bzl\", \"diff_test\")\n\
                         [diff_test(name = n + \"_test\", file1 = n, file2 = n + \".golden\") for n in NAMES]\n\
                         diff_test(name = \"docs\", file1 = generated(), file2 = \"README.md\")\n";
        assert_eq!(
            found(&[("BUILD.bazel", unrelated)], "requirements.txt"),
            (vec![], true)
        );
        let beside = [("BUILD.bazel", unrelated), ("requirements.bzl", "")];
        let detail = checks(&beside, "requirements.txt");
        assert!(detail.checks.is_empty());
        assert_eq!(detail.unread.len(), 2, "{:?}", detail.unread);
    }

    #[test]
    fn the_header_and_the_rule_of_one_target_are_one_check() {
        let build = "load(\"@rules_python//python:pip.bzl\", \"compile_pip_requirements\")\n\
                     compile_pip_requirements(name = \"requirements\", requirements_txt = \"requirements_lock.txt\")\n\
                     load(\"@rules_python_gazelle_plugin//manifest:defs.bzl\", \"gazelle_python_manifest\")\n\
                     gazelle_python_manifest(name = \"requirements\", requirements = \"requirements_lock.txt\")\n";
        let files = [
            ("requirements_lock.txt", PIP_COMPILE_LOCK),
            ("BUILD.bazel", build),
        ];
        // The same target as another kind of check is a second row.
        let expected = vec![
            (pip_compile(Tri::Maybe), "//:requirements".to_string()),
            (
                LockCheckKind::GazelleManifest,
                "//:requirements".to_string(),
            ),
        ];
        assert_eq!(found(&files, "requirements_lock.txt"), (expected, true));
    }

    #[test]
    fn what_cannot_be_read_is_reported_and_never_taken_for_no_check() {
        let load = "load(\"@rules_python//python:pip.bzl\", \"compile_pip_requirements\")\n";
        let unread = |build: &str| {
            let detail = checks(&[("BUILD.bazel", build)], "requirements.txt");
            assert!(detail.checks.is_empty(), "{build}");
            let gaps = detail.gaps();
            assert_eq!(gaps.len(), detail.unread.len());
            assert!(gaps.iter().all(|gap| gap.token == LABEL_NOT_LITERAL));
            let first = gaps.first().unwrap_or_else(|| panic!("no gap for {build}"));
            assert_eq!(first.file, "BUILD.bazel");
            first.detail.clone()
        };
        // A computed output, a computed name with the default output, and
        // arguments behind `**`.
        let computed =
            "compile_pip_requirements(name = \"r\", requirements_txt = lock_for(\"r\"))\n";
        assert!(unread(&format!("{load}{computed}")).starts_with("BUILD.bazel:2: an argument"));
        unread(&format!(
            "{load}compile_pip_requirements(name = NAME + \"_lock\")\n"
        ));
        unread(&format!("{load}compile_pip_requirements(**ARGS)\n"));
        // A call the statement reader does not model.
        let looped = "[compile_pip_requirements(name = n) for n in [\"a\", \"b\"]]\n";
        assert!(unread(&format!("{load}{looped}")).contains("is used where it is not read"));
        // A file Bazel itself rejects.
        assert!(unread("\tcompile_pip_requirements()\n").contains("tab"));

        // A computed argument that could only name another file is no gap:
        // the literal output is what the test compares.
        let other = "compile_pip_requirements(name = \"r\", requirements_txt = \"other.txt\", extra_args = ARGS)\n";
        assert_eq!(
            found(
                &[("BUILD.bazel", &format!("{load}{other}"))],
                "requirements.txt"
            ),
            (vec![], true)
        );
        // A macro that is loaded and never called declares nothing.
        assert_eq!(
            found(&[("BUILD.bazel", load)], "requirements.txt"),
            (vec![], true)
        );

        // An unreadable BUILD file or lock is not an absent one.
        let files = Files::of(&[]).with("py/BUILD.bazel", FileText::Unreadable);
        let detail = scan(&files, "py/requirements.txt", Tri::Maybe);
        assert_eq!(detail.unread.len(), 1);
        assert_eq!(detail.unread[0].file, "py/BUILD.bazel");
        let files = Files::of(&[]).with("requirements.txt", FileText::Unreadable);
        assert_eq!(scan(&files, "requirements.txt", Tri::Maybe).unread.len(), 1);
    }

    #[test]
    fn the_scan_is_bounded_and_says_when_it_stopped() {
        let deep = format!("{}requirements.txt", "d/".repeat(MAX_DIRECTORIES + 1));
        let detail = checks(&[], &deep);
        assert_eq!(detail.unread.len(), 1);
        assert!(detail.unread[0].why.contains("levels up"));
        // One level less reaches the root.
        let reached = format!("{}requirements.txt", "d/".repeat(MAX_DIRECTORIES - 1));
        let build = "load(\"@rules_uv//uv:pip.bzl\", \"pip_compile\")\n\
                     pip_compile(name = \"deep\", requirements_txt = \"//PKG:requirements.txt\")\n";
        let package = reached.rsplit_once('/').unwrap().0;
        let build = build.replace("PKG", package);
        assert_eq!(
            found(
                &[("BUILD", &build), (&format!("{package}/BUILD"), "")],
                &reached
            ),
            one(LockCheckKind::Erasing, "//:deep")
        );
    }
}
