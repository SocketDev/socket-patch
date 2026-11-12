//! `.bazelrc` reader (design 2.6): what the tracked rc files make Bazel do.
//!
//! [`read`] lexes `<root>/.bazelrc` and the files it imports exactly as
//! the Bazel client does: a port of `rc_file.cc` and `Tokenize`, checked
//! against the words real Bazel 6.2.1 to 10.0.0rc3 reported (probe S8).
//! Two behaviours a hand-rolled reader gets wrong are kept on purpose: a
//! BOM makes Bazel drop the first line, and a comment that ends in `\`
//! swallows the next line. [`RcFiles::effective`] then applies the
//! server's rules for one Bazel line: the `always` / `common` / inherited
//! / command chain, `--config` expanded in place, last value wins.
//!
//! The answer per flag is a [`FlagState`], and it is built to escalate
//! only (an rc file can add a hazard and never remove one):
//!
//! - the final value decides, never an earlier occurrence;
//! - a value that only some reading reaches is `Possible`: a `--config`,
//!   a release of the line (the `always` section exists from 6.3.0,
//!   `fetch` inherits `test` from 7.0.0, `startup:<os>` applies from
//!   9.0.0, `try-import-if-bazel-version`), or an import path Bazel
//!   resolves against the directory it is started in;
//! - a file Bazel loads and this reader cannot read is a gap, never
//!   "not set".
//!
//! Only tracked, in-repository rc files are read. The home and system rc,
//! `$BAZELRC`, `--bazelrc` and the command line are a documented blind
//! spot: they must not steer what socket-patch commits.
//!
//! One limit is inherited from the reference port: the value of an option
//! this reader does not track is not skipped, so `--some_option
//! --lockfile_mode=error` reads as a lock mode although Bazel takes the
//! second token as the first one's value.

use std::collections::BTreeMap;
use std::fmt;

use super::model::{FileText, FileView};
use super::version::{ApiShape, BazelLine, BazelVersion, Tri};

/// The [`FlagState::Possible`] key of the command with no `--config`,
/// when its value is the same on every release and from every directory.
pub const PLAIN: &str = "";
/// The [`FlagState::Possible`] key of the command with no `--config`, on
/// the readings none of the bracketed keys covers.
pub const OTHERWISE: &str = "[otherwise]";

/// What the tracked rc files say about one flag on one command chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagState<T> {
    /// The final value on every reading: no config, release of the line
    /// or working directory changes it.
    Set(T),
    /// The value depends on the reading. Keys: a config name (the value
    /// under `--config=<name>`), [`PLAIN`], or a bracketed condition such
    /// as `[Bazel 6.3.0 or newer]` or `ci [import user.bazelrc]`. A
    /// reading no key covers leaves the flag unset.
    Possible(BTreeMap<String, T>),
    /// Not set in what was read, and a file Bazel is sure to load could
    /// not be read: hosted writes are refused and VEX is withheld.
    UnknowableHard(String),
    /// Not set in what was read, and an optional file (an absent
    /// `try-import` target, a path that depends on the working directory)
    /// may set it: an advisory.
    UnknowableSoft(String),
    NotSeen,
}

impl<T> FlagState<T> {
    /// Every value the flag may take. A hazard flag is hazardous when any
    /// of them is.
    pub fn values(&self) -> Vec<&T> {
        match self {
            Self::Set(value) => vec![value],
            Self::Possible(by_reading) => by_reading.values().collect(),
            _ => Vec::new(),
        }
    }

    /// The value of the command with no `--config`, when every reading
    /// agrees on it. This is what "set unconditionally" means for the
    /// lock-refresh policy (owner decision D5).
    pub fn plain(&self) -> Option<&T> {
        match self {
            Self::Set(value) => Some(value),
            Self::Possible(by_reading) => by_reading.get(PLAIN),
            _ => None,
        }
    }

    /// Whether some reading of the plain command leaves the flag unset,
    /// so that Bazel's default applies.
    pub fn may_be_unset(&self) -> bool {
        match self {
            Self::Set(_) => false,
            Self::Possible(by_reading) => {
                !by_reading.contains_key(PLAIN) && !by_reading.contains_key(OTHERWISE)
            }
            _ => true,
        }
    }
}

/// A value of `--lockfile_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileMode {
    Off,
    Update,
    /// From Bazel 7.2.0.
    Refresh,
    Error,
}

impl LockfileMode {
    /// `None` for a value no Bazel accepts.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "off" => Self::Off,
            "update" => Self::Update,
            "refresh" => Self::Refresh,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

/// The `--repo_env` variables that decide how gazelle's `go_repository`
/// fetches a Go module: the proxy list, and the two switches that make it
/// build from the host module cache, where no sum check catches an edited
/// copy.
pub const GO_REPO_ENV: [&str; 6] = [
    "GOPROXY",
    "GONOPROXY",
    "GOPRIVATE",
    "GOFLAGS",
    "GO_REPOSITORY_USE_HOST_MODCACHE",
    "GO_REPOSITORY_USE_HOST_CACHE",
];

/// The value of one `--repo_env` variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoEnv {
    /// `--repo_env=NAME=VALUE`.
    Value(String),
    /// `--repo_env=NAME`: the client environment decides.
    Inherit,
    /// `--repo_env==NAME`: removed from the environment.
    Unset,
}

// ── Flags and command chains ─────────────────────────────────────────

/// The flags of design 2.6. A flag has one entry however many spellings
/// Bazel accepts for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Flag {
    LockfileMode,
    /// `--enable_bzlmod` and its old name `--experimental_enable_bzlmod`.
    EnableBzlmod,
    EnableWorkspace,
    OverrideRepository,
    InjectRepository,
    OverrideModule,
    VendorDir,
    /// `--fetch`; `--nofetch` is the hazard.
    Fetch,
    /// `--downloader_config` and `--experimental_downloader_config`.
    DownloaderConfig,
    RepositoryDisableDownload,
    Distdir,
    Registry,
    ModuleMirrors,
    RemoteDownloader,
    CheckDirectDependencies,
    IgnoreDevDependency,
    RepoContentsCache,
    CheckExternalRepositoryFiles,
    RepositoryCacheHardlinks,
    /// Read one variable with [`EffectiveFlags::repo_env`].
    RepoEnv,
    StrictRepoEnv,
    SymlinkPrefix,
    ConvenienceSymlinks,
    /// `--enable_platform_specific_config`: with it a `<command>:<os>`
    /// section applies on that OS without any `--config`.
    PlatformSpecificConfig,
    /// Startup options: read them on [`Chain::Startup`].
    OutputBase,
    OutputUserRoot,
    DigestFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    /// One value; the last one wins.
    Value,
    /// One value of a fixed set, matched without regard to case.
    Enum,
    /// Repeatable: every occurrence counts.
    Multi,
}

/// Every flag with its kind and current name, in [`Flag`] order.
const FLAGS: &[(Flag, Kind, &str)] = {
    use Flag as F;
    use Kind::{Bool, Enum, Multi, Value};
    &[
        (F::LockfileMode, Enum, "lockfile_mode"),
        (F::EnableBzlmod, Bool, "enable_bzlmod"),
        (F::EnableWorkspace, Bool, "enable_workspace"),
        (F::OverrideRepository, Multi, "override_repository"),
        (F::InjectRepository, Multi, "inject_repository"),
        (F::OverrideModule, Multi, "override_module"),
        (F::VendorDir, Value, "vendor_dir"),
        (F::Fetch, Bool, "fetch"),
        (F::DownloaderConfig, Value, "downloader_config"),
        (
            F::RepositoryDisableDownload,
            Bool,
            "repository_disable_download",
        ),
        (F::Distdir, Multi, "distdir"),
        (F::Registry, Multi, "registry"),
        (F::ModuleMirrors, Multi, "module_mirrors"),
        (F::RemoteDownloader, Value, "experimental_remote_downloader"),
        (
            F::CheckDirectDependencies,
            Enum,
            "check_direct_dependencies",
        ),
        (F::IgnoreDevDependency, Bool, "ignore_dev_dependency"),
        (F::RepoContentsCache, Value, "repo_contents_cache"),
        (
            F::CheckExternalRepositoryFiles,
            Bool,
            "experimental_check_external_repository_files",
        ),
        (
            F::RepositoryCacheHardlinks,
            Bool,
            "experimental_repository_cache_hardlinks",
        ),
        (F::RepoEnv, Multi, "repo_env"),
        (F::StrictRepoEnv, Bool, "experimental_strict_repo_env"),
        (F::SymlinkPrefix, Value, "symlink_prefix"),
        (
            F::ConvenienceSymlinks,
            Enum,
            "experimental_convenience_symlinks",
        ),
        (
            F::PlatformSpecificConfig,
            Bool,
            "enable_platform_specific_config",
        ),
        (F::OutputBase, Value, "output_base"),
        (F::OutputUserRoot, Value, "output_user_root"),
        (F::DigestFunction, Value, "digest_function"),
    ]
};

/// Old option names Bazel still accepts: `(old, current)`. Bazel 5 knows
/// `enable_bzlmod` only under its old name, and Bazel before 8.2 the
/// downloader config only under its old one.
const OLD_NAMES: &[(&str, &str)] = &[
    ("experimental_enable_bzlmod", "enable_bzlmod"),
    ("experimental_downloader_config", "downloader_config"),
    (
        "experimental_repository_disable_download",
        "repository_disable_download",
    ),
    ("experimental_distdir", "distdir"),
    ("repository_contents_cache", "repo_contents_cache"),
];

/// The flag an option name sets, with the name as it was written.
fn lookup(name: &str) -> Option<(Flag, Kind, &'static str)> {
    let old = OLD_NAMES.iter().find(|(old, _)| *old == name);
    let current = old.map_or(name, |(_, current)| current);
    let (flag, kind, current) = FLAGS.iter().find(|row| row.2 == current)?;
    Some((*flag, *kind, old.map_or(*current, |(old, _)| old)))
}

/// The commands whose rc chains are evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Chain {
    Build,
    Test,
    Run,
    Coverage,
    Query,
    Cquery,
    Aquery,
    Fetch,
    Vendor,
    Mod,
    Sync,
    Info,
    /// The `startup` sections: no `common`, no `--config`.
    Startup,
}

impl Chain {
    /// Every chain but [`Chain::Startup`]; the build chain, which governs,
    /// comes first. `query`, `mod` and `sync` inherit nothing from
    /// `build`, so a `build --flag` line does not reach them.
    pub const COMMANDS: &'static [Chain] = &[
        Chain::Build,
        Chain::Test,
        Chain::Run,
        Chain::Coverage,
        Chain::Query,
        Chain::Cquery,
        Chain::Aquery,
        Chain::Fetch,
        Chain::Vendor,
        Chain::Mod,
        Chain::Sync,
        Chain::Info,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Chain::Build => "build",
            Chain::Test => "test",
            Chain::Run => "run",
            Chain::Coverage => "coverage",
            Chain::Query => "query",
            Chain::Cquery => "cquery",
            Chain::Aquery => "aquery",
            Chain::Fetch => "fetch",
            Chain::Vendor => "vendor",
            Chain::Mod => "mod",
            Chain::Sync => "sync",
            Chain::Info => "info",
            Chain::Startup => "startup",
        }
    }
}

/// The command each command inherits rc lines from.
const PARENTS: &[(&str, &str)] = &[
    ("test", "build"),
    ("run", "build"),
    ("info", "build"),
    ("clean", "build"),
    ("aquery", "build"),
    ("config", "build"),
    ("print_action", "build"),
    ("mobile-install", "build"),
    ("canonicalize-flags", "build"),
    ("cquery", "test"),
    ("coverage", "test"),
    ("vendor", "test"),
    ("fetch", "test"),
];

/// The configs a `startup:<name>` section may be written for.
const OS_CONFIGS: [&str; 5] = ["linux", "macos", "windows", "freebsd", "openbsd"];

const ALWAYS_SINCE: BazelVersion = BazelVersion::new(6, 3, 0);
const FETCH_INHERITS_SINCE: BazelVersion = BazelVersion::new(7, 0, 0);
/// Observed on 9.0.2 and not on 8.8.2 (probe S8).
const STARTUP_OS_SINCE: BazelVersion = BazelVersion::new(9, 0, 0);

/// One rc section of a command's chain, and whether it applies on the
/// line.
struct Section<'a> {
    name: &'a str,
    gate: Gate,
}

/// The rc sections Bazel applies for `command`, least specific first.
fn sections<'a>(command: &'a str, line: &BazelLine) -> Vec<Section<'a>> {
    let mut out = vec![Section {
        name: command,
        gate: Gate::open(),
    }];
    if command == "startup" {
        return out;
    }
    let (mut at, mut gate) = (command, Gate::open());
    while let Some((_, parent)) = PARENTS.iter().find(|(child, _)| *child == at) {
        if at == "fetch" {
            let since = line.at_least(FETCH_INHERITS_SINCE);
            gate = gate.and(since, "Bazel 7.0.0 or newer");
        }
        let section = Section {
            name: parent,
            gate: gate.clone(),
        };
        out.insert(0, section);
        at = parent;
    }
    let always = Gate::open().and(line.at_least(ALWAYS_SINCE), "Bazel 6.3.0 or newer");
    let common = Section {
        name: "common",
        gate: Gate::open(),
    };
    out.insert(0, common);
    out.insert(
        0,
        Section {
            name: "always",
            gate: always,
        },
    );
    out
}

// ── Lexer ────────────────────────────────────────────────────────────

/// `blaze_util::kSeparator`. NUL is one too: the client tests with
/// `strchr`, which finds the terminator.
const SEPARATORS: &[u8] = b" \n\t\r\0";
/// What `StripWhitespace` removes from both ends of a line.
const SPACE: &[u8] = b" \t\n\x0b\x0c\r";

/// `blaze_util::Tokenize`: the words of one logical line. `\` escapes the
/// next byte everywhere, quotes may open in the middle of a word, an
/// unquoted `#` ends the line even inside a word, an empty word is
/// dropped and an unterminated quote runs to the end of the line.
fn tokenize(line: &[u8]) -> Vec<Vec<u8>> {
    let (mut words, mut at) = (Vec::new(), 0);
    while at < line.len() {
        while at < line.len() && SEPARATORS.contains(&line[at]) {
            at += 1;
        }
        if line.get(at).is_none_or(|b| *b == b'#') {
            break;
        }
        let (mut word, mut quote) = (Vec::new(), None);
        while at < line.len() && (quote.is_some() || !SEPARATORS.contains(&line[at])) {
            let byte = line[at];
            at += 1;
            if byte == b'\\' {
                // A dangling backslash is dropped.
                word.extend(line.get(at));
                at += 1;
            } else if quote == Some(byte) {
                quote = None;
            } else if quote.is_some() {
                word.push(byte);
            } else if byte == b'#' {
                at = line.len();
            } else if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
            } else {
                word.push(byte);
            }
        }
        if !word.is_empty() {
            words.push(word);
        }
    }
    words
}

/// The first two steps of `RcFile::ParseFile`: every `\`-newline pair is
/// deleted before anything else (so a comment ending in `\` continues
/// onto the next line), then the text is split at LF and each line is
/// stripped. Returns the non-empty lines, each with the number of the
/// physical line it starts on.
fn logical_lines(bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut number = 1u32;
    let mut text: Vec<(u8, u32)> = Vec::with_capacity(bytes.len());
    for byte in bytes {
        text.push((*byte, number));
        number += u32::from(*byte == b'\n');
    }
    for pair in [&b"\\\r\n"[..], &b"\\\n"[..]] {
        let mut kept = Vec::with_capacity(text.len());
        let mut at = 0;
        while at < text.len() {
            let here = text[at..].iter().map(|(byte, _)| byte);
            if text.len() - at >= pair.len() && here.take(pair.len()).eq(pair) {
                at += pair.len();
            } else {
                kept.push(text[at]);
                at += 1;
            }
        }
        text = kept;
    }
    let lines = text.split(|(byte, _)| *byte == b'\n');
    let stripped = lines.filter_map(|line| {
        let start = line.iter().position(|(byte, _)| !SPACE.contains(byte))?;
        let end = line.iter().rposition(|(byte, _)| !SPACE.contains(byte))?;
        let bytes = line[start..=end].iter().map(|(byte, _)| *byte).collect();
        Some((line[start].1 as usize, bytes))
    });
    stripped.collect()
}

// ── Parsed rc files ──────────────────────────────────────────────────

/// A position in an rc file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcSite {
    /// Root-relative path of the rc file.
    pub file: String,
    /// 1-based line.
    pub line: usize,
}

impl fmt::Display for RcSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// A file Bazel loads, or may load, that this reader could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcGap {
    /// `true`: Bazel is sure to load the file (a plain `import`, the
    /// root `.bazelrc`) or stops on the statement. `false`: an optional
    /// file.
    pub hard: bool,
    /// Root-relative path of the file that was not read, or the
    /// `file:line` of an import statement Bazel stops on.
    pub file: String,
    pub detail: String,
}

/// A comparison of `try-import-if-bazel-version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    Tilde,
}

/// The condition of a `try-import-if-bazel-version`: an operator and a
/// strict semantic version (`~` also takes `8` and `8.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionCond {
    op: Op,
    at: (u32, u32, u32),
    /// The version has a prerelease part, so it is below `at` itself.
    prerelease: bool,
    /// `~8`: the range is the whole major, not one minor.
    whole_major: bool,
}

impl VersionCond {
    fn parse(text: &str) -> Option<Self> {
        let ops = [
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("==", Op::Eq),
            ("!=", Op::Ne),
            ("<", Op::Lt),
            (">", Op::Gt),
            ("~", Op::Tilde),
        ];
        let (op, version) = ops
            .iter()
            .find_map(|(sign, op)| Some((*op, text.strip_prefix(sign)?)))?;
        let dots = version.matches('.').count();
        let padded = match (op, dots) {
            (Op::Tilde, 0) => format!("{version}.0.0"),
            (Op::Tilde, 1) => format!("{version}.0"),
            _ => version.to_string(),
        };
        let (core, build) = padded
            .split_once('+')
            .map_or((&padded[..], None), |(c, b)| (c, Some(b)));
        let (core, prerelease) = core
            .split_once('-')
            .map_or((core, None), |(c, p)| (c, Some(p)));
        // semver.org's grammar, as `SemVer::Parse` applies it.
        let numeric = |part: &str| {
            let plain = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            (plain && (part == "0" || !part.starts_with('0'))).then(|| part.parse::<i32>().ok())?
        };
        let word = |part: &str| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        };
        // A numeric prerelease identifier has no leading zero.
        let padded_number = |part: &str| {
            part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| b.is_ascii_digit())
        };
        let pre_ok = |pre: &str| pre.split('.').all(|p| word(p) && !padded_number(p));
        let build_ok = |build: &str| build.split('.').all(word);
        if !prerelease.is_none_or(pre_ok) || !build.is_none_or(build_ok) {
            return None;
        }
        let mut parts = core.split('.');
        let mut next = || numeric(parts.next()?).and_then(|n| u32::try_from(n).ok());
        let at = (next()?, next()?, next()?);
        parts.next().is_none().then_some(Self {
            op,
            at,
            prerelease: prerelease.is_some(),
            whole_major: dots == 0,
        })
    }

    /// Whether the condition holds on the final releases of `line`. Bazel
    /// compares its own build label, so candidates never get here: on one
    /// every such import is skipped.
    fn holds(&self, line: &BazelLine) -> Tri {
        let triple = |v: BazelVersion| (v.major, v.minor, v.patch);
        // "release >= t" for a version `t` without a prerelease part.
        let ge = |t: (u32, u32, u32)| {
            if line.lo.is_some_and(|lo| triple(lo) >= t) {
                Tri::Yes
            } else if line.hi.is_some_and(|hi| triple(hi) < t) {
                Tri::No
            } else {
                Tri::Maybe
            }
        };
        let (major, minor, patch) = self.at;
        let above = (major, minor, patch.saturating_add(1));
        // A final release is above every prerelease of its own version.
        let gt = if self.prerelease {
            ge(self.at)
        } else {
            ge(above)
        };
        let eq = match self.prerelease {
            true => Tri::No,
            false => ge(self.at).and(!ge(above)),
        };
        match self.op {
            Op::Ge => ge(self.at),
            Op::Lt => !ge(self.at),
            Op::Gt => gt,
            Op::Le => !gt,
            Op::Eq => eq,
            Op::Ne => !eq,
            Op::Tilde => {
                let end = match self.whole_major {
                    true => (major.saturating_add(1), 0, 0),
                    false => (major, minor.saturating_add(1), 0),
                };
                ge(self.at).and(!ge(end))
            }
        }
    }
}

/// One thing a token's presence depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    /// Reached through an import path Bazel resolves against the
    /// directory it is started in: read only when that is the root.
    Cwd(String),
    /// Reached through `try-import-if-bazel-version <condition>`; `None`
    /// when the condition does not parse.
    VersionIf(String, Option<VersionCond>),
}

/// One option token of an rc file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// The statement keyword as written: `build`, `common:ci`.
    key: String,
    token: String,
    /// Index into [`RcFiles::files`].
    file: usize,
    line: usize,
    /// Index into `RcFiles::conds`.
    cond: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Import {
    Plain,
    Try,
    IfVersion,
}

/// The tracked rc files of one root, lexed and with imports expanded in
/// place. Nothing here depends on the Bazel line: [`RcFiles::effective`]
/// applies one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcFiles {
    /// The rc files read, root-relative, in first-read order. Empty when
    /// the root has no `.bazelrc`.
    pub files: Vec<String>,
    entries: Vec<Entry>,
    /// The conditions tokens and gaps hang on; `conds[0]` is "always".
    conds: Vec<Vec<Atom>>,
    gaps: Vec<(RcGap, usize)>,
    /// Files parsed so far, repeats included.
    reads: usize,
}

impl Default for RcFiles {
    /// A root with no rc file.
    fn default() -> Self {
        Self {
            files: Vec::new(),
            entries: Vec::new(),
            conds: vec![Vec::new()],
            gaps: Vec::new(),
            reads: 0,
        }
    }
}

/// Bazel before 10 has no import depth limit; this reader is bounded like
/// the other script readers.
const MAX_DEPTH: usize = 8;
const MAX_FILES: usize = 512;
const MAX_CONFIG_DEPTH: usize = 50;
/// Nested configs can expand without bound (`a` twice in `b`, `b` twice
/// in `c`); past this many tokens a chain is not evaluated.
const MAX_OPTIONS: usize = 20_000;

/// Reads `<root>/.bazelrc` and what it imports, inside the read boundary
/// only.
pub fn read(files: &dyn FileView) -> RcFiles {
    read_tops(files, &[".bazelrc"])
}

/// Reads rc files in the client's order. Production reads the workspace
/// file alone; the conformance tests add the files a recorded invocation
/// had (home rc, `--bazelrc`).
fn read_tops(view: &dyn FileView, tops: &[&str]) -> RcFiles {
    let mut rc = RcFiles::default();
    for top in tops {
        match view.read(top) {
            FileText::Bytes(bytes) => rc.parse(view, top, &bytes, 0, &mut vec![top.to_string()]),
            FileText::Absent => {}
            FileText::Unreadable => rc.gap(true, top, "cannot be read", 0),
        }
    }
    rc
}

/// A path Bazel resolves against the workspace root, as a [`FileView`]
/// path: no empty or `.` segment, `..` folded where it can be and kept
/// where it leads above the root. `None` for an absolute or empty path.
pub(super) fn root_relative(path: &str) -> Option<String> {
    let drive = path
        .split('/')
        .next()
        .is_some_and(|first| first.contains(':'));
    if path.starts_with('/') || drive {
        return None;
    }
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." if out.last().is_some_and(|last| *last != "..") => {
                out.pop();
            }
            segment => out.push(segment),
        }
    }
    (!out.is_empty()).then(|| out.join("/"))
}

impl RcFiles {
    /// Whether the root has no tracked rc file at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.gaps.is_empty()
    }

    fn gap(&mut self, hard: bool, file: &str, detail: &str, cond: usize) {
        let gap = RcGap {
            hard,
            file: file.to_string(),
            detail: detail.to_string(),
        };
        self.gaps.push((gap, cond));
    }

    fn with(&mut self, cond: usize, atom: Atom) -> usize {
        let mut atoms = self.conds[cond].clone();
        atoms.push(atom);
        self.conds.push(atoms);
        self.conds.len() - 1
    }

    fn parse(
        &mut self,
        view: &dyn FileView,
        path: &str,
        bytes: &[u8],
        cond: usize,
        stack: &mut Vec<String>,
    ) {
        let known = self.files.iter().position(|file| file == path);
        let file = known.unwrap_or_else(|| {
            self.files.push(path.to_string());
            self.files.len() - 1
        });
        self.reads += 1;
        for (line, text) in logical_lines(bytes) {
            let words: Vec<String> = tokenize(&text)
                .iter()
                .map(|word| String::from_utf8_lossy(word).into_owned())
                .collect();
            let Some((keyword, args)) = words.split_first() else {
                continue;
            };
            let import = match keyword.as_str() {
                "import" => Import::Plain,
                "try-import" => Import::Try,
                "try-import-if-bazel-version" => Import::IfVersion,
                // Any other first word names a section, known to Bazel or
                // not: an unknown one is dropped with a warning.
                _ => {
                    self.entries.extend(args.iter().map(|token| Entry {
                        key: keyword.clone(),
                        token: token.clone(),
                        file,
                        line,
                        cond,
                    }));
                    continue;
                }
            };
            self.import(view, import, args, cond, stack, &format!("{path}:{line}"));
        }
    }

    fn import(
        &mut self,
        view: &dyn FileView,
        kind: Import,
        args: &[String],
        mut cond: usize,
        stack: &mut Vec<String>,
        here: &str,
    ) {
        let target = match (kind, args) {
            (Import::IfVersion, [condition, target]) => {
                let parsed = VersionCond::parse(condition);
                cond = self.with(cond, Atom::VersionIf(condition.clone(), parsed));
                if parsed.is_none() {
                    let detail = "has a version condition Bazel stops on";
                    return self.gap(true, here, detail, cond);
                }
                target
            }
            (Import::IfVersion, _) => {
                cond = self.with(cond, Atom::VersionIf(String::new(), None));
                let detail = "is not `try-import-if-bazel-version <condition> <path>`";
                return self.gap(true, here, detail, cond);
            }
            (_, [target]) => target,
            _ => {
                return self.gap(
                    true,
                    here,
                    "is not `import <path>`; Bazel stops on it",
                    cond,
                )
            }
        };
        let hard = kind == Import::Plain;
        let rel = match target.strip_prefix("%workspace%/") {
            Some(rest) => root_relative(rest),
            None if target.starts_with('/') => None,
            None => {
                // Bazel resolves this against the directory it is started
                // in. From the root it is the file read here; from
                // anywhere else it is a file nobody can name.
                let detail = "is read relative to the directory Bazel is started in";
                self.gap(false, target, detail, cond);
                cond = self.with(cond, Atom::Cwd(target.clone()));
                root_relative(target)
            }
        };
        let Some(rel) = rel else {
            return self.gap(hard, target, "is outside the repository", cond);
        };
        if stack.contains(&rel) {
            return self.gap(true, &rel, "imports itself; Bazel stops on the loop", cond);
        }
        if stack.len() > MAX_DEPTH || self.reads >= MAX_FILES {
            return self.gap(true, &rel, "is nested deeper than socket-patch reads", cond);
        }
        match view.read(&rel) {
            FileText::Bytes(bytes) => {
                stack.push(rel.clone());
                self.parse(view, &rel, &bytes, cond, stack);
                stack.pop();
            }
            FileText::Absent if hard => {
                self.gap(
                    true,
                    &rel,
                    "is missing; Bazel stops on a missing `import`",
                    cond,
                );
            }
            FileText::Absent => self.gap(false, &rel, "is not in the repository", cond),
            FileText::Unreadable => self.gap(hard, &rel, "cannot be read", cond),
        }
    }

    /// Whether what hangs on `cond` is read on `line`.
    fn presence(&self, cond: usize, line: &BazelLine) -> Tri {
        let atom = |atom: &Atom| match atom {
            Atom::Cwd(_) => Tri::Maybe,
            Atom::VersionIf(_, parsed) => {
                let holds = parsed.map_or(Tri::Yes, |parsed| parsed.holds(line));
                version_imports(line).and(holds)
            }
        };
        let atoms = self.conds[cond].iter().map(atom);
        atoms.fold(Tri::Yes, Tri::and)
    }

    /// What `cond` depends on, for a [`FlagState::Possible`] key.
    fn describe(&self, cond: usize) -> String {
        let atom = |atom: &Atom| match atom {
            Atom::Cwd(path) => format!("import {path}"),
            Atom::VersionIf(condition, _) => format!("try-import-if-bazel-version {condition}"),
        };
        let parts: Vec<String> = self.conds[cond].iter().map(atom).collect();
        parts.join(", ")
    }

    /// The flags as `line` reads them.
    pub fn effective(&self, line: &BazelLine) -> EffectiveFlags {
        let mut by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, entry) in self.entries.iter().enumerate() {
            by_key.entry(entry.key.clone()).or_default().push(index);
        }
        EffectiveFlags {
            rc: self.clone(),
            line: line.clone(),
            by_key,
        }
    }

    /// The options every build passes that an older Bazel stops on: row 3
    /// of the line ladder. Only a token present on every reading counts,
    /// in either polarity and whatever overrides it later, because Bazel
    /// parses every token it reads.
    pub fn api_shapes(&self) -> Vec<ApiShape> {
        let flags = self.effective(&BazelLine::unknown());
        let mut shapes = Vec::new();
        for setting in settings(&flags.plain("build").items) {
            let shape = match setting.flag {
                Flag::EnableWorkspace => ApiShape::EnableWorkspaceFlag,
                Flag::LockfileMode if setting.value == "refresh" => ApiShape::LockfileModeRefresh,
                _ => continue,
            };
            if setting.gate.applies == Tri::Yes && !shapes.contains(&shape) {
                shapes.push(shape);
            }
        }
        shapes
    }
}

/// Whether `try-import-if-bazel-version` imports anything on `line`.
///
/// The directive exists from 8.7.0 and 9.0.0. It was run on 9.0.2 (it
/// imports), on 6.2.1, 6.6.0 and 7.7.2 (`invalid command name`, nothing
/// imported) and on 10.0.0rc3 (every import skipped: a candidate's build
/// label is not a semantic version). So it is proven only on an exact
/// final release from 9.0.2, and ruled out only on a candidate and up to
/// the newest audited 7.x; anything else is `Maybe`.
fn version_imports(line: &BazelLine) -> Tri {
    match line.exact() {
        Some(version) if !version.is_final() => Tri::No,
        Some(version) if version >= BazelVersion::new(9, 0, 2) => Tri::Yes,
        _ if line.hi.is_some_and(|hi| hi <= BazelVersion::new(7, 7, 2)) => Tri::No,
        _ => Tri::Maybe,
    }
}

// ── Evaluation ───────────────────────────────────────────────────────

/// Whether a token is read, and what a `Maybe` depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gate {
    applies: Tri,
    /// Empty unless `applies` is `Maybe`.
    when: String,
}

impl Gate {
    fn open() -> Self {
        Self {
            applies: Tri::Yes,
            when: String::new(),
        }
    }

    /// This gate narrowed by one more condition.
    fn and(&self, applies: Tri, when: &str) -> Self {
        let joined = match (self.when.as_str(), applies) {
            (_, Tri::Yes) => self.when.clone(),
            ("", _) => when.to_string(),
            (mine, _) if when.is_empty() => mine.to_string(),
            (mine, _) => format!("{mine}, {when}"),
        };
        let applies = self.applies.and(applies);
        let when = if applies == Tri::Maybe {
            joined
        } else {
            String::new()
        };
        Self { applies, when }
    }
}

/// One token of an effective option sequence.
struct Item<'a> {
    entry: &'a Entry,
    gate: Gate,
}

/// An effective option sequence, lowest priority first.
#[derive(Default)]
struct Options<'a> {
    items: Vec<Item<'a>>,
    /// Tokens visited while expanding configs, the ones that expand to
    /// nothing included.
    work: usize,
}

impl Options<'_> {
    /// Whether the expansion was abandoned: the sequence is incomplete.
    fn cut_short(&self) -> bool {
        self.work > MAX_OPTIONS
    }
}

/// One occurrence of a tracked flag in an effective option sequence.
struct Setting<'a> {
    flag: Flag,
    spelling: &'static str,
    /// Booleans are `true` / `false`; enum values are lower-cased; a
    /// value Bazel would reject is kept as written.
    value: String,
    gate: Gate,
    entry: &'a Entry,
}

fn bool_word(text: &str) -> Option<bool> {
    match text.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "t" | "y" => Some(true),
        "false" | "0" | "no" | "f" | "n" => Some(false),
        _ => None,
    }
}

/// The tracked flags among `items`: `--name=value`, `--name value` (the
/// next token is the value, whatever it looks like), `--name` and
/// `--noname` for booleans.
fn settings<'a>(items: &[Item<'a>]) -> Vec<Setting<'a>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < items.len() {
        let item = &items[at];
        at += 1;
        let Some(body) = item.entry.token.strip_prefix("--") else {
            continue;
        };
        let (name, inline) = match body.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (body, None),
        };
        let negated = || {
            let positive = name.strip_prefix("no").filter(|_| inline.is_none());
            positive
                .and_then(lookup)
                .filter(|found| found.1 == Kind::Bool)
        };
        let ((flag, kind, spelling), value) = match (lookup(name), inline) {
            (Some(found @ (_, Kind::Bool, _)), None) => (found, "true".to_string()),
            (Some(found @ (_, Kind::Bool, _)), Some(text)) => {
                let word = bool_word(text).map(|b| b.to_string());
                (found, word.unwrap_or_else(|| text.to_string()))
            }
            (Some(found), Some(text)) => (found, text.to_string()),
            (Some(found), None) => {
                let Some(next) = items.get(at) else { continue };
                at += 1;
                (found, next.entry.token.clone())
            }
            (None, _) => match negated() {
                Some(found) => (found, "false".to_string()),
                None => continue,
            },
        };
        out.push(Setting {
            flag,
            spelling,
            value: if kind == Kind::Enum {
                value.to_ascii_lowercase()
            } else {
                value
            },
            gate: item.gate.clone(),
            entry: item.entry,
        });
    }
    out
}

/// One occurrence of a flag, for the repeatable flags and for messages.
/// For `--override_repository`, `--inject_repository` and
/// `--override_module` the raw `<name>=<path>` is kept and nothing is
/// matched here: only a canonical name takes effect on Bazel 6 to 8, and
/// the gate owns that match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// The option name as written, without `--` or `no`.
    pub spelling: &'static str,
    pub value: String,
    /// The config whose expansion holds it; [`PLAIN`] for the rc lines
    /// every command of the chain reads.
    pub config: String,
    /// `false` when only some release of the line, or only some working
    /// directory, reads it.
    pub certain: bool,
    pub site: RcSite,
}

impl Occurrence {
    /// The value split at its first `=`: the raw name and path of an
    /// override flag.
    pub fn name_and_path(&self) -> Option<(&str, &str)> {
        self.value.split_once('=')
    }
}

/// The tracked rc files of one root as one Bazel line reads them: one
/// [`FlagState`] per flag and command chain.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveFlags {
    rc: RcFiles,
    line: BazelLine,
    /// The tokens of each section keyword, in parse order.
    by_key: BTreeMap<String, Vec<usize>>,
}

impl EffectiveFlags {
    /// The tokens of `key`'s sections, each gated by `gate` and by its
    /// own import conditions. Tokens no reading reaches are left out.
    fn section(&self, key: &str, gate: &Gate) -> Vec<Item<'_>> {
        let indices = self.by_key.get(key).map_or(&[][..], Vec::as_slice);
        let items = indices.iter().map(|index| {
            let entry = &self.rc.entries[*index];
            let own = self.rc.presence(entry.cond, &self.line);
            let when = if own == Tri::Maybe {
                self.rc.describe(entry.cond)
            } else {
                String::new()
            };
            Item {
                entry,
                gate: gate.and(own, &when),
            }
        });
        items.filter(|item| item.gate.applies != Tri::No).collect()
    }

    /// `ConfigExpander`: each `--config=<name>` is replaced, in place, by
    /// the `<section>:<name>` tokens of every section of the chain, and
    /// the result is expanded again.
    fn expand<'a>(
        &'a self,
        items: Vec<Item<'a>>,
        sections: &[Section<'_>],
        stack: &mut Vec<String>,
        out: &mut Options<'a>,
    ) {
        let top = stack.is_empty();
        let mut items = items.into_iter();
        while let Some(item) = items.next() {
            out.work += 1;
            if out.cut_short() {
                return;
            }
            let token = item.entry.token.as_str();
            let name = match token.strip_prefix("--config=") {
                Some(name) => name.to_string(),
                // Inside a config's own definition Bazel takes only the
                // one-token form.
                None if top && token == "--config" => match items.next() {
                    Some(value) => value.entry.token.clone(),
                    None => continue,
                },
                None => {
                    out.items.push(item);
                    continue;
                }
            };
            // Bazel stops on a config that expands to itself.
            if stack.contains(&name) || stack.len() >= MAX_CONFIG_DEPTH {
                continue;
            }
            stack.push(name.clone());
            for section in sections {
                let gate = item.gate.and(section.gate.applies, &section.gate.when);
                let nested = self.section(&format!("{}:{name}", section.name), &gate);
                self.expand(nested, sections, stack, out);
            }
            stack.pop();
        }
    }

    /// The options every `command` gets from the rc files, lowest
    /// priority first.
    fn plain(&self, command: &str) -> Options<'_> {
        let sections = sections(command, &self.line);
        let mut out = Options::default();
        for section in &sections {
            let items = self.section(section.name, &section.gate);
            // `startup:<config>` is never expanded.
            if command == "startup" {
                out.items.extend(items);
            } else {
                self.expand(items, &sections, &mut Vec::new(), &mut out);
            }
        }
        out
    }

    /// What `--config=<name>` on the command line adds after the options
    /// of [`Self::plain`]. For `startup` the only configs are the OS
    /// names, which Bazel 9 applies by itself on that OS.
    fn under_config(&self, command: &str, name: &str) -> Options<'_> {
        let mut out = Options::default();
        if command == "startup" {
            let since = self.line.at_least(STARTUP_OS_SINCE);
            let gate = Gate::open().and(since, "Bazel 9.0.0 or newer");
            out.items = self.section(&format!("startup:{name}"), &gate);
            return out;
        }
        let sections = sections(command, &self.line);
        let mut stack = vec![name.to_string()];
        for section in &sections {
            let nested = self.section(&format!("{}:{name}", section.name), &section.gate);
            self.expand(nested, &sections, &mut stack, &mut out);
        }
        out
    }

    /// The configs the rc files define for `command`.
    fn configs(&self, command: &str) -> Vec<String> {
        let sections = sections(command, &self.line);
        let mut names: Vec<String> = Vec::new();
        // In the order the rc files first define them.
        let mut keys: Vec<(&usize, &str)> = Vec::new();
        for (key, indices) in &self.by_key {
            keys.extend(indices.first().map(|first| (first, key.as_str())));
        }
        keys.sort();
        for (_, key) in keys {
            let Some((section, name)) = key.split_once(':') else {
                continue;
            };
            // `build:` names no config: its key would be the plain one.
            let defined = !name.is_empty()
                && sections.iter().any(|s| s.name == section)
                && (command != "startup" || OS_CONFIGS.contains(&name));
            if defined && !names.iter().any(|seen| seen == name) {
                names.push(name.to_string());
            }
        }
        names
    }

    /// The state of the value `pick` extracts, last one wins: under no
    /// config, then under each config in turn. A flag set under two
    /// configs at once takes one of the values found here, because the
    /// last token wins whatever the combination.
    fn resolve<T: Clone + PartialEq>(
        &self,
        chain: Chain,
        pick: impl Fn(&Setting<'_>) -> Option<T>,
    ) -> FlagState<T> {
        let command = chain.name();
        let mut cut_short = false;
        let mut picked = |options: Options<'_>| -> Vec<(T, Gate)> {
            cut_short |= options.cut_short();
            let found = settings(&options.items);
            let values = found
                .iter()
                .filter_map(|s| Some((pick(s)?, s.gate.clone())));
            values.collect()
        };
        let plain = picked(self.plain(command));
        let mut by_reading = BTreeMap::new();
        finals(&plain, &[], PLAIN, &mut by_reading);
        for config in self.configs(command) {
            let own = picked(self.under_config(command, &config));
            if !own.is_empty() {
                finals(&plain, &own, &config, &mut by_reading);
            }
        }
        if cut_short {
            let why = "the rc configs expand to more options than socket-patch reads";
            return FlagState::UnknowableHard(why.to_string());
        }
        match by_reading.get(PLAIN) {
            _ if by_reading.is_empty() => self.unseen(),
            Some(plain) if by_reading.values().all(|value| value == plain) => {
                FlagState::Set(plain.clone())
            }
            _ => FlagState::Possible(by_reading),
        }
    }

    /// The state of a flag nothing sets: what could not be read decides.
    fn unseen<T>(&self) -> FlagState<T> {
        let gaps = self.gaps();
        let text = |gap: &&RcGap| format!("{} {}", gap.file, gap.detail);
        match (gaps.iter().find(|gap| gap.hard), gaps.first()) {
            (Some(hard), _) => FlagState::UnknowableHard(text(hard)),
            (None, Some(soft)) => FlagState::UnknowableSoft(text(soft)),
            (None, None) => FlagState::NotSeen,
        }
    }

    /// The state of `flag` on `chain`. Booleans read `true` / `false`,
    /// enum values are lower-cased, a value Bazel would reject is kept as
    /// written. For a repeatable flag this is its last value: use
    /// [`Self::occurrences`].
    pub fn state(&self, flag: Flag, chain: Chain) -> FlagState<String> {
        self.resolve(chain, |setting| {
            (setting.flag == flag).then(|| setting.value.clone())
        })
    }

    /// The state of the repository-rule environment variable `name`:
    /// the last `--repo_env` that names it wins.
    pub fn repo_env(&self, name: &str, chain: Chain) -> FlagState<RepoEnv> {
        self.resolve(chain, |setting| {
            let value = match setting.value.split_once('=') {
                Some(("", unset)) => (unset, RepoEnv::Unset),
                Some((variable, value)) => (variable, RepoEnv::Value(value.to_string())),
                None => (setting.value.as_str(), RepoEnv::Inherit),
            };
            (setting.flag == Flag::RepoEnv && value.0 == name).then_some(value.1)
        })
    }

    /// Every occurrence of `flag` some reading of `chain` reaches: the
    /// rc lines of the chain itself, then each config's expansion.
    pub fn occurrences(&self, flag: Flag, chain: Chain) -> Vec<Occurrence> {
        let command = chain.name();
        let mut out = Vec::new();
        let mut collect = |options: Options<'_>, config: &str| {
            for setting in settings(&options.items).iter().filter(|s| s.flag == flag) {
                out.push(Occurrence {
                    spelling: setting.spelling,
                    value: setting.value.clone(),
                    config: config.to_string(),
                    certain: setting.gate.applies == Tri::Yes,
                    site: RcSite {
                        file: self.rc.files[setting.entry.file].clone(),
                        line: setting.entry.line,
                    },
                });
            }
        };
        collect(self.plain(command), PLAIN);
        for config in self.configs(command) {
            collect(self.under_config(command, &config), &config);
        }
        out
    }

    /// The files this line may load that could not be read, hard ones
    /// included. An unread file is never "not set": a hard gap refuses
    /// hosted writes whatever the flags that were read say.
    pub fn gaps(&self) -> Vec<&RcGap> {
        let reached = |(_, cond): &&(RcGap, usize)| self.rc.presence(*cond, &self.line) != Tri::No;
        let gaps = self.rc.gaps.iter().filter(reached);
        gaps.map(|(gap, _)| gap).collect()
    }
}

/// The values a last-wins flag may end with: `upper` (a config's
/// expansion) is applied after `lower` (the chain's own lines). Walking
/// back from the end, every token that only some reading reaches adds a
/// possible value, and the first token every reading reaches ends the
/// walk.
fn finals<T: Clone>(
    lower: &[(T, Gate)],
    upper: &[(T, Gate)],
    config: &str,
    by_reading: &mut BTreeMap<String, T>,
) {
    let mut maybes: Vec<(&str, &T)> = Vec::new();
    let mut definite = None;
    for (value, gate) in upper.iter().rev().chain(lower.iter().rev()) {
        if gate.applies == Tri::Yes {
            definite = Some(value);
            break;
        }
        // A later token under the same condition shadows this one.
        if !maybes.iter().any(|(when, _)| *when == gate.when) {
            maybes.push((&gate.when, value));
        }
    }
    let key = |when: Option<&str>| match (config, when) {
        (config, None) => config.to_string(),
        (PLAIN, Some(when)) => format!("[{when}]"),
        (config, Some(when)) => format!("{config} [{when}]"),
    };
    let rest = if maybes.is_empty() {
        None
    } else {
        Some("otherwise")
    };
    for (when, value) in maybes {
        by_reading.insert(key(Some(when)), value.clone());
    }
    if let Some(value) = definite {
        by_reading.insert(key(rest), value.clone());
    }
}

/// An in-memory [`FileView`] for the reader tests of this layer.
#[cfg(test)]
pub(super) mod testing {
    use std::collections::BTreeMap;

    use crate::bazel::model::{FileText, FileView};

    /// Files by root-relative path. A directory exists where a path has
    /// it as a prefix.
    #[derive(Default)]
    pub struct Files(pub BTreeMap<String, FileText>);

    impl Files {
        pub fn of(files: &[(&str, &str)]) -> Self {
            let bytes = |text: &str| FileText::Bytes(text.as_bytes().to_vec());
            Self(
                files
                    .iter()
                    .map(|(path, text)| (path.to_string(), bytes(text)))
                    .collect(),
            )
        }

        pub fn with(mut self, path: &str, text: FileText) -> Self {
            self.0.insert(path.to_string(), text);
            self
        }
    }

    impl FileView for Files {
        fn read(&self, rel: &str) -> FileText {
            self.0.get(rel).cloned().unwrap_or(FileText::Absent)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            let mut names: Vec<String> = Vec::new();
            for rest in self.0.keys().filter_map(|path| path.strip_prefix(&prefix)) {
                let name = match rest.split_once('/') {
                    Some((child, _)) => format!("{child}/"),
                    None => rest.to_string(),
                };
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            Some(names)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::testing::Files;
    use super::*;
    use crate::test_rng::Rng;

    const LEXER: &str = include_str!("../../tests/fixtures/bazel/rc/s8-lexer.json");
    const INVOCATIONS: &str = include_str!("../../tests/fixtures/bazel/rc/s8-invocations.json");

    fn exact(version: &str) -> BazelLine {
        BazelLine::of(BazelVersion::parse(version).expect("a release"))
    }

    /// `lo.x` through `hi.x`, as a floating label or a lock token gives.
    fn majors(lo: u32, hi: u32) -> BazelLine {
        BazelLine {
            lo: Some(BazelVersion::new(lo, 0, 0)),
            hi: Some(BazelVersion::ceiling(hi)),
            evidence: Vec::new(),
        }
    }

    fn flags_of(files: &[(&str, &str)], line: &BazelLine) -> EffectiveFlags {
        read(&Files::of(files)).effective(line)
    }

    fn flags(rc: &str, line: &BazelLine) -> EffectiveFlags {
        flags_of(&[(".bazelrc", rc)], line)
    }

    fn set(value: &str) -> FlagState<String> {
        FlagState::Set(value.to_string())
    }

    fn possible(readings: &[(&str, &str)]) -> FlagState<String> {
        let pair = |(key, value): &(&str, &str)| (key.to_string(), value.to_string());
        FlagState::Possible(readings.iter().map(pair).collect())
    }

    fn lock_mode(rc: &str, line: &BazelLine, chain: Chain) -> FlagState<String> {
        flags(rc, line).state(Flag::LockfileMode, chain)
    }

    /// The `/sp/<tag>` tags of the options `command` gets, in order.
    fn tags(flags: &EffectiveFlags, command: &str) -> Vec<String> {
        let tag = |item: &Item<'_>| item.entry.token.replace("--distdir=/sp/", "");
        flags.plain(command).items.iter().map(tag).collect()
    }

    fn strings(value: &Value) -> Vec<&str> {
        let items = value.as_array().expect("an array").iter();
        items.map(|item| item.as_str().expect("a string")).collect()
    }

    fn vector_files(case: &Value) -> Files {
        let files = case["files"].as_object().expect("files").iter();
        let bytes =
            |text: &Value| FileText::Bytes(text.as_str().expect("text").as_bytes().to_vec());
        Files(
            files
                .map(|(path, text)| (path.clone(), bytes(text)))
                .collect(),
        )
    }

    /// The fixtures are reductions of what real Bazel did: an edit that
    /// misses its checksum turns an observation into an invention.
    #[test]
    fn the_fixture_files_match_their_checksums() {
        use sha2::{Digest, Sha256};
        macro_rules! fixture {
            ($name:literal) => {
                (
                    $name,
                    &include_bytes!(concat!("../../tests/fixtures/bazel/rc/", $name))[..],
                )
            };
        }
        let files = [
            fixture!(".gitattributes"),
            fixture!("README.md"),
            fixture!("bazelversion.json"),
            fixture!("reduce.py"),
            fixture!("s8-invocations.json"),
            fixture!("s8-lexer.json"),
            fixture!("url-rewriter-cases.json"),
            fixture!("version-order.json"),
        ];
        let sums = include_str!("../../tests/fixtures/bazel/rc/SHA256SUMS");
        let listed: Vec<(&str, &str)> = sums.lines().filter_map(|l| l.split_once("  ")).collect();
        assert_eq!(listed.len(), files.len());
        for (name, bytes) in files {
            let digest = hex::encode(Sha256::digest(bytes));
            assert!(
                listed.contains(&(digest.as_str(), name)),
                "{name} is {digest}"
            );
        }
    }

    // ── Conformance with real Bazel (probe S8) ───────────────────────

    #[test]
    fn the_lexer_reproduces_every_s8_token_vector() {
        let vectors: Value = serde_json::from_str(LEXER).expect("fixture");
        let cases = vectors["cases"].as_array().expect("cases");
        assert_eq!(cases.len(), 31);
        assert_eq!(strings(&vectors["bep_releases"]).len(), 6);
        for case in cases {
            let id = case["id"].as_str().expect("id");
            let rc = hex::decode(case["rc_hex"].as_str().expect("hex")).expect("hex");
            let mut mine: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
            for (_, line) in logical_lines(&rc) {
                let words = tokenize(&line);
                if let Some((keyword, args @ [_, ..])) = words.split_first() {
                    mine.entry(keyword.clone())
                        .or_default()
                        .extend(args.iter().cloned());
                }
            }
            // Each character of a fixture string is one byte.
            let latin1 = |text: &str| -> Vec<u8> {
                text.chars()
                    .map(|c| u8::try_from(u32::from(c)).expect("a byte"))
                    .collect()
            };
            let observed = case["tokens"].as_object().expect("tokens").iter();
            let expected: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = observed
                .map(|(section, words)| {
                    (
                        latin1(section),
                        strings(words).into_iter().map(latin1).collect(),
                    )
                })
                .collect();
            assert_eq!(mine, expected, "{id}");

            // Bazel 10.0.0rc3 prints the words of a section joined.
            let announced = case["announce_rc_10.0.0rc3"]
                .as_object()
                .expect("announce_rc");
            for (section, joined) in announced {
                let words: Vec<_> = mine[section.as_bytes()]
                    .iter()
                    .map(|word| String::from_utf8_lossy(word))
                    .collect();
                assert_eq!(
                    words.join(" "),
                    joined.as_str().expect("text"),
                    "{id} on 10"
                );
            }
        }
    }

    #[test]
    fn one_invocation_applies_the_rc_lines_in_bazels_order() {
        let vectors: Value = serde_json::from_str(INVOCATIONS).expect("fixture");
        let mut ran = Vec::new();
        for case in vectors["order"].as_array().expect("order") {
            let (id, bazel) = (
                case["id"].as_str().unwrap(),
                case["bazel"].as_str().unwrap(),
            );
            let rc = read_tops(&vector_files(case), &strings(&case["tops"]));
            let flags = rc.effective(&exact(bazel));
            // `--announce_rc` prints a `--config` token where the build
            // event protocol shows its expansion (C_query, same rc).
            let expected: Vec<&str> = strings(&case["observed_order"])
                .into_iter()
                .map(|tag| {
                    if tag == "--config=cc" {
                        "common_cc"
                    } else {
                        tag
                    }
                })
                .collect();
            let command = case["command"].as_str().unwrap();
            assert_eq!(tags(&flags, command), expected, "{id} on Bazel {bazel}");
            ran.push(format!("{id} {bazel}"));
        }
        // The cells the design names: the version imports on a release
        // without the directive, with it, and on a candidate; the
        // `always` gate; commands that inherit nothing.
        for cell in [
            "G_version_import 6.2.1",
            "G_version_import 7.7.2",
            "G_version_import 9.0.2",
            "G_version_import 10.0.0rc3",
            "C_build 6.2.1",
            "C_build 6.6.0",
            "C_build 10.0.0rc3",
            "C_query 9.0.2",
            "C_version 6.2.1",
            "C_mod 9.0.2",
        ] {
            assert!(
                ran.iter().any(|seen| seen == cell),
                "{cell} is not in the fixture"
            );
        }
    }

    #[test]
    fn startup_os_sections_apply_from_bazel_9_and_startup_configs_never() {
        let vectors: Value = serde_json::from_str(INVOCATIONS).expect("fixture");
        let cases = vectors["startup"].as_array().expect("startup");
        assert_eq!(cases.len(), 4);
        for case in cases {
            let bazel = case["bazel"].as_str().unwrap();
            let flags = read(&vector_files(case)).effective(&exact(bazel));
            // The probe ran on macOS.
            let mut mine = flags.plain("startup").items;
            mine.extend(flags.under_config("startup", "macos").items);
            let values: Vec<_> = mine
                .iter()
                .map(|item| item.entry.token.replace("--host_jvm_args=", ""))
                .collect();
            assert_eq!(
                values,
                strings(&case["observed_host_jvm_args"]),
                "Bazel {bazel}"
            );
            assert_eq!(
                flags.configs("startup"),
                ["macos", "linux"],
                "`startup:ci` is no config"
            );
        }

        let rc = "startup --output_base=/x\nstartup:linux --output_base=/y\n";
        let base = |line: &BazelLine| flags(rc, line).state(Flag::OutputBase, Chain::Startup);
        assert_eq!(base(&exact("8.8.2")), set("/x"));
        assert_eq!(
            base(&exact("9.3.2")),
            possible(&[("", "/x"), ("linux", "/y")])
        );
        let spanning = [
            ("", "/x"),
            ("linux [Bazel 9.0.0 or newer]", "/y"),
            ("linux [otherwise]", "/x"),
        ];
        assert_eq!(base(&majors(8, 9)), possible(&spanning));
        // A startup option is not a build option.
        assert_eq!(
            flags(rc, &exact("9.3.2")).state(Flag::OutputBase, Chain::Build),
            FlagState::NotSeen
        );
    }

    /// The rules_js preset: `error` exists as a token and is never the
    /// final value. Refusing on the occurrence would refuse 51 of the 303
    /// workspaces of the research corpus for nothing.
    #[test]
    fn the_final_value_under_a_config_decides_not_an_occurrence() {
        let vectors: Value = serde_json::from_str(INVOCATIONS).expect("fixture");
        let cases = vectors["effective"].as_array().expect("effective");
        let case = |id: &str| cases.iter().find(|case| case["id"] == id).expect("case");

        let shape = case("R_rulesjs_shape_ci");
        assert_eq!(
            shape["files"][".bazelrc"],
            "common:ci --lockfile_mode=\"error\"\ncommon:ci --lockfile_mode=off\n"
        );
        assert_eq!(strings(&shape["cli"]), ["--config=ci"]);
        let line = exact(shape["bazel"].as_str().unwrap());
        let state = read(&vector_files(shape))
            .effective(&line)
            .state(Flag::LockfileMode, Chain::Build);
        assert_eq!(state, possible(&[("ci", "off")]));
        // What Bazel reported with `--config=ci` on the command line.
        assert_eq!(state.values(), [shape["observed"].as_str().unwrap()]);
        assert_eq!(state.plain(), None);
        assert!(state.may_be_unset());

        // The repin order: the config alone leaves `error`; the flag
        // after it on the command line is outside the rc files.
        let repin = case("R_repin_config_then_flag");
        let state = read(&vector_files(repin))
            .effective(&line)
            .state(Flag::LockfileMode, Chain::Build);
        assert_eq!(state, possible(&[("ci", "error")]));
    }

    // ── Flag states ──────────────────────────────────────────────────

    #[test]
    fn a_flag_is_set_only_when_every_reading_agrees() {
        let line = exact("7.7.2");
        let build = |rc: &str| lock_mode(rc, &line, Chain::Build);
        assert_eq!(build(""), FlagState::NotSeen);
        assert_eq!(build("common --lockfile_mode=error\n"), set("error"));
        // The last token wins inside a section, and a more specific
        // section wins whatever the file order.
        assert_eq!(
            build("build --lockfile_mode=off\nbuild --lockfile_mode=error\n"),
            set("error")
        );
        assert_eq!(
            build("build --lockfile_mode=error\ncommon --lockfile_mode=off\n"),
            set("error")
        );

        // A config that changes the value: both are reported, and the
        // plain command's value stays readable (owner decision D5).
        let split = build("common --lockfile_mode=update\ncommon:ci --lockfile_mode=error\n");
        assert_eq!(split, possible(&[("", "update"), ("ci", "error")]));
        assert_eq!(split.plain().map(String::as_str), Some("update"));
        assert!(!split.may_be_unset());
        assert_eq!(split.values(), ["update", "error"]);

        // A config that repeats the value changes nothing.
        let same = "common --lockfile_mode=error\ncommon:ci --lockfile_mode=error\n";
        assert_eq!(build(same), set("error"));
        // `common --config=ci` makes the config unconditional.
        let always_on = "common --config=ci\ncommon:ci --lockfile_mode=error\n";
        assert_eq!(build(always_on), set("error"));
        // A config defined for another command only is no config here,
        // and neither is an empty name.
        for rc in [
            "query:ci --lockfile_mode=error\n",
            "build: --lockfile_mode=error\n",
        ] {
            assert_eq!(build(rc), FlagState::NotSeen, "{rc}");
        }
        // The values Bazel accepts, as the lock-refresh policy reads them.
        for (text, mode) in [
            ("off", LockfileMode::Off),
            ("update", LockfileMode::Update),
            ("refresh", LockfileMode::Refresh),
            ("error", LockfileMode::Error),
        ] {
            let state = build(&format!("common --lockfile_mode={}\n", text.to_uppercase()));
            assert_eq!(
                state.plain().and_then(|v| LockfileMode::parse(v)),
                Some(mode)
            );
        }
        assert_eq!(LockfileMode::parse("frozen"), None);
    }

    #[test]
    fn configs_expand_in_place_and_nest() {
        let rc = "build --lockfile_mode=update\n\
                  build --config=a\n\
                  build:a --config=b\n\
                  build:a --vendor_dir=from_a\n\
                  build:b --lockfile_mode=error\n\
                  build:b --vendor_dir=from_b\n\
                  build:loop --config=loop --lockfile_mode=off\n";
        let flags = flags(rc, &exact("7.7.2"));
        // `b` expands where `--config=b` stands, before the rest of `a`,
        // so `a` ends with its own value and `--config=b` alone with b's.
        assert_eq!(
            flags.state(Flag::VendorDir, Chain::Build),
            possible(&[("", "from_a"), ("a", "from_a"), ("b", "from_b")])
        );
        // A config that expands to itself is not followed twice.
        assert_eq!(
            flags.state(Flag::LockfileMode, Chain::Build),
            possible(&[
                ("", "error"),
                ("a", "error"),
                ("b", "error"),
                ("loop", "off")
            ])
        );
        // The two-token form is read at the top level only: inside a
        // config's definition Bazel rejects it.
        let two = "build --config a\nbuild:a --lockfile_mode=error\nbuild:c --config a\n";
        assert_eq!(lock_mode(two, &exact("7.7.2"), Chain::Build), set("error"));
        let nested = "build:c --config a\nbuild:a --lockfile_mode=error\n";
        assert_eq!(
            lock_mode(nested, &exact("7.7.2"), Chain::Build),
            possible(&[("a", "error")])
        );
    }

    #[test]
    fn each_command_reads_its_own_chain() {
        let rc = "build --lockfile_mode=error\ntest --vendor_dir=v\ncommon --registry=r\n";
        let flags = flags(rc, &exact("7.7.2"));
        let mode = |chain| flags.state(Flag::LockfileMode, chain);
        // `mod`, `query` and `sync` inherit nothing: the repin command
        // `bazel mod deps` does not see a `build` line.
        for chain in [
            Chain::Build,
            Chain::Test,
            Chain::Run,
            Chain::Coverage,
            Chain::Info,
        ] {
            assert_eq!(mode(chain), set("error"), "{chain:?}");
        }
        for chain in [Chain::Query, Chain::Mod, Chain::Sync] {
            assert_eq!(mode(chain), FlagState::NotSeen, "{chain:?}");
        }
        for chain in [Chain::Cquery, Chain::Aquery, Chain::Fetch, Chain::Vendor] {
            let expected = if chain == Chain::Aquery {
                FlagState::NotSeen
            } else {
                set("v")
            };
            assert_eq!(flags.state(Flag::VendorDir, chain), expected, "{chain:?}");
        }
        for chain in Chain::COMMANDS {
            assert_eq!(flags.state(Flag::Registry, *chain), set("r"), "{chain:?}");
        }
        assert_eq!(Chain::COMMANDS[0], Chain::Build);
        assert!(!Chain::COMMANDS.contains(&Chain::Startup));
    }

    #[test]
    fn a_behaviour_that_depends_on_the_release_is_possible_on_a_range() {
        // `always` exists from 6.3.0.
        let always = "always --lockfile_mode=error\n";
        let build = |line: &BazelLine| lock_mode(always, line, Chain::Build);
        assert_eq!(build(&exact("6.2.1")), FlagState::NotSeen);
        assert_eq!(build(&exact("6.3.0")), set("error"));
        assert_eq!(build(&exact("6.6.0")), set("error"));
        let on_six = build(&majors(6, 6));
        assert_eq!(on_six, possible(&[("[Bazel 6.3.0 or newer]", "error")]));
        assert!(on_six.may_be_unset() && on_six.plain().is_none());
        assert_eq!(build(&BazelLine::unknown()), on_six);
        // `always` comes first in the chain, so any `common` line wins.
        let both = "always --lockfile_mode=error\ncommon --lockfile_mode=off\n";
        assert_eq!(lock_mode(both, &majors(6, 6), Chain::Build), set("off"));

        // `fetch` inherits `test` (and with it `build`) from 7.0.0.
        let inherited = "test --lockfile_mode=error\nbuild --vendor_dir=v\n";
        let fetch = |line: &BazelLine| lock_mode(inherited, line, Chain::Fetch);
        assert_eq!(fetch(&exact("6.6.0")), FlagState::NotSeen);
        assert_eq!(fetch(&exact("7.7.2")), set("error"));
        assert_eq!(
            fetch(&majors(6, 7)),
            possible(&[("[Bazel 7.0.0 or newer]", "error")])
        );
        let vendor = flags(inherited, &majors(6, 7)).state(Flag::VendorDir, Chain::Fetch);
        assert_eq!(vendor, possible(&[("[Bazel 7.0.0 or newer]", "v")]));
    }

    #[test]
    fn a_version_import_is_decided_only_where_the_directive_is_proven() {
        let files = [
            (
                ".bazelrc",
                "try-import-if-bazel-version >=8.0.0 %workspace%/new.rc\n",
            ),
            ("new.rc", "common --lockfile_mode=error\n"),
        ];
        let state =
            |line: &BazelLine| flags_of(&files, line).state(Flag::LockfileMode, Chain::Build);
        let maybe = possible(&[("[try-import-if-bazel-version >=8.0.0]", "error")]);
        // Run and seen to import: an exact final release from 9.0.2.
        assert_eq!(state(&exact("9.0.2")), set("error"));
        assert_eq!(state(&exact("9.3.2")), set("error"));
        // Not run (8.x, 9.0.0, 9.0.1), or not one release: possible.
        for line in [
            exact("8.8.2"),
            exact("9.0.0"),
            majors(9, 9),
            BazelLine::unknown(),
        ] {
            assert_eq!(state(&line), maybe, "{line}");
        }
        // Run and seen to import nothing: releases without the
        // directive, and a candidate, whose label is no semantic version.
        for line in [
            exact("6.6.0"),
            exact("7.7.2"),
            majors(7, 7),
            exact("10.0.0rc3"),
        ] {
            assert_eq!(state(&line), FlagState::NotSeen, "{line}");
        }

        // A condition that is false on every release of the line.
        let old = [
            (
                ".bazelrc",
                "try-import-if-bazel-version <9.0.0 %workspace%/old.rc\n",
            ),
            ("old.rc", "common --lockfile_mode=error\n"),
        ];
        assert_eq!(
            flags_of(&old, &exact("9.3.2")).state(Flag::LockfileMode, Chain::Build),
            FlagState::NotSeen
        );
        let older = possible(&[("[try-import-if-bazel-version <9.0.0]", "error")]);
        // A condition that holds: on 7.7.2 the keyword is still unknown
        // and nothing is imported; 8.x was not run; a floating 7.x may
        // reach a release nobody audited.
        for (line, expected) in [
            (exact("7.7.2"), FlagState::NotSeen),
            (exact("6.2.1"), FlagState::NotSeen),
            (exact("8.6.0"), older.clone()),
            (majors(7, 7), older.clone()),
            (majors(8, 9), older),
        ] {
            let state = flags_of(&old, &line).state(Flag::LockfileMode, Chain::Build);
            assert_eq!(state, expected, "{line}");
        }
    }

    #[test]
    fn version_conditions_compare_as_bazel_does() {
        let holds = |condition: &str, line: &BazelLine| {
            VersionCond::parse(condition).expect(condition).holds(line)
        };
        let nine = exact("9.0.2");
        for (condition, expected) in [
            (">=9.0.0", Tri::Yes),
            ("<9.0.0", Tri::No),
            ("~8", Tri::No),
            ("~9", Tri::Yes),
            ("~9.0", Tri::Yes),
            ("~9.1", Tri::No),
            ("~9.0.3", Tri::No),
            ("~10", Tri::No),
            // A release is above every prerelease of its own version.
            (">=10.0.0-0", Tri::No),
            (">9.0.2-rc1", Tri::Yes),
            ("<=9.0.2-rc1", Tri::No),
            ("==9.0.2", Tri::Yes),
            ("==9.0.2-rc1", Tri::No),
            ("!=9.0.2", Tri::No),
            (">9.0.2", Tri::No),
            ("<=9.0.2+build.7", Tri::Yes),
        ] {
            assert_eq!(holds(condition, &nine), expected, "{condition}");
        }
        assert_eq!(holds(">=9.0.0", &majors(8, 9)), Tri::Maybe);
        assert_eq!(holds("==9.0.2", &majors(9, 9)), Tri::Maybe);
        assert_eq!(holds("~8.2", &majors(9, 9)), Tri::No);
        // What Bazel stops on: no operator, a partial version outside
        // `~`, a leading zero, a `v`.
        for bad in [
            "9.0.0",
            "=9.0.0",
            ">=9",
            ">=9.0",
            ">=09.0.0",
            ">=v9.0.0",
            "~",
            "~9.x",
            ">=9.0.0-01",
        ] {
            assert_eq!(VersionCond::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_unreadable_import_is_a_gap_and_never_not_set() {
        let line = exact("7.7.2");
        let hard = |files: &[(&str, &str)]| {
            let flags = flags_of(files, &line);
            let gaps: Vec<(bool, String)> = flags
                .gaps()
                .iter()
                .map(|gap| (gap.hard, gap.file.clone()))
                .collect();
            (flags.state(Flag::LockfileMode, Chain::Build), gaps)
        };
        // A missing plain import stops Bazel; what it would set is
        // unknowable, and what was read still counts.
        let missing = [(
            ".bazelrc",
            "import %workspace%/ci.rc\ncommon --vendor_dir=v\n",
        )];
        let (state, gaps) = hard(&missing);
        assert!(matches!(&state, FlagState::UnknowableHard(why) if why.starts_with("ci.rc ")));
        assert_eq!(gaps, [(true, "ci.rc".to_string())]);
        assert_eq!(
            flags_of(&missing, &line).state(Flag::VendorDir, Chain::Build),
            set("v")
        );

        // An absent `try-import` target is the usual per-user file.
        let (state, gaps) = hard(&[(".bazelrc", "try-import %workspace%/user.bazelrc\n")]);
        assert!(matches!(state, FlagState::UnknowableSoft(_)));
        assert_eq!(gaps, [(false, "user.bazelrc".to_string())]);

        // A loop, a wrong word count and an absolute path.
        let looped = [
            (".bazelrc", "import %workspace%/a.rc\n"),
            ("a.rc", "import %workspace%/./tools/../.bazelrc\n"),
        ];
        assert_eq!(hard(&looped).1, [(true, ".bazelrc".to_string())]);
        assert_eq!(
            hard(&[(".bazelrc", "import a.rc b.rc\n")]).1,
            [(true, ".bazelrc:1".to_string())]
        );
        assert_eq!(
            hard(&[(".bazelrc", "import /etc/ci.rc\n")]).1,
            [(true, "/etc/ci.rc".to_string())]
        );
        assert_eq!(
            hard(&[(".bazelrc", "try-import /etc/ci.rc\n")]).1,
            [(false, "/etc/ci.rc".to_string())]
        );

        // A file between the root and the read boundary is read; one past
        // the boundary is unreadable, which is never absent.
        let outside = Files::of(&[(
            ".bazelrc",
            "import %workspace%/../shared.rc\ntry-import %workspace%/../../home.rc\n",
        )])
        .with(
            "../shared.rc",
            FileText::Bytes(b"common --lockfile_mode=error\n".to_vec()),
        )
        .with("../../home.rc", FileText::Unreadable);
        let flags = read(&outside).effective(&line);
        assert_eq!(flags.state(Flag::LockfileMode, Chain::Build), set("error"));
        assert_eq!(flags.gaps().len(), 1);
        assert!(!flags.gaps()[0].hard);
        let beyond = Files::of(&[(".bazelrc", "import %workspace%/../x.rc\n")])
            .with("../x.rc", FileText::Unreadable);
        assert!(read(&beyond).effective(&line).gaps()[0].hard);

        // The root file itself.
        let unreadable = Files::default().with(".bazelrc", FileText::Unreadable);
        let rc = read(&unreadable);
        assert!(!rc.is_empty());
        let state = rc.effective(&line).state(Flag::Fetch, Chain::Build);
        assert!(matches!(state, FlagState::UnknowableHard(_)));
        assert!(read(&Files::default()).is_empty());
        assert!(RcFiles::default().effective(&line).gaps().is_empty());
    }

    #[test]
    fn a_path_relative_to_the_working_directory_is_possible_and_a_gap() {
        let files = [
            (
                ".bazelrc",
                "build --lockfile_mode=off\ntry-import user.bazelrc\n",
            ),
            (
                "user.bazelrc",
                "build --lockfile_mode=error\nbuild --vendor_dir=v\n",
            ),
        ];
        let flags = flags_of(&files, &exact("7.7.2"));
        // Started in the root Bazel reads the file; started anywhere
        // else it reads another file or none.
        let mode = flags.state(Flag::LockfileMode, Chain::Build);
        assert_eq!(
            mode,
            possible(&[("[import user.bazelrc]", "error"), (OTHERWISE, "off")])
        );
        assert!(mode.plain().is_none() && !mode.may_be_unset());
        assert_eq!(
            flags.state(Flag::VendorDir, Chain::Build),
            possible(&[("[import user.bazelrc]", "v")])
        );
        let gaps = flags.gaps();
        assert_eq!(
            (gaps.len(), gaps[0].hard, gaps[0].file.as_str()),
            (1, false, "user.bazelrc")
        );
        // A plain import of a file that is not at the root stops Bazel
        // there.
        let absent = flags_of(&[(".bazelrc", "import ci/ci.rc\n")], &exact("7.7.2"));
        assert_eq!(absent.gaps().iter().filter(|gap| gap.hard).count(), 1);
    }

    #[test]
    fn the_two_traps_of_the_grammar_are_kept() {
        let line = exact("7.7.2");
        // A BOM is part of the first keyword, which no command has.
        let bom = "\u{feff}common --lockfile_mode=error\ncommon --vendor_dir=v\n";
        assert_eq!(lock_mode(bom, &line, Chain::Build), FlagState::NotSeen);
        assert_eq!(
            flags(bom, &line).state(Flag::VendorDir, Chain::Build),
            set("v")
        );
        // A comment that ends in a backslash continues onto the next line.
        let swallowed = "# set in CI \\\ncommon --lockfile_mode=error\ncommon --vendor_dir=v\n";
        assert_eq!(
            lock_mode(swallowed, &line, Chain::Build),
            FlagState::NotSeen
        );
        assert_eq!(
            flags(swallowed, &line).state(Flag::VendorDir, Chain::Build),
            set("v")
        );
        // Quotes, CRLF and a `#` inside a word.
        let quoted = "common --lockfile_mode=\"error\"\r\ncommon --vendor_dir='a b'#c\r\n";
        assert_eq!(lock_mode(quoted, &line, Chain::Build), set("error"));
        assert_eq!(
            flags(quoted, &line).state(Flag::VendorDir, Chain::Build),
            set("a b")
        );
        // NUL separates words, as it does in the client.
        assert_eq!(
            tokenize(b"build\0--a"),
            [b"build".to_vec(), b"--a".to_vec()]
        );
    }

    #[test]
    fn option_spellings_follow_bazels_parser() {
        let line = exact("7.7.2");
        let on = |rc: &str, flag| flags(&format!("common {rc}\n"), &line).state(flag, Chain::Build);
        for (rc, expected) in [
            ("--enable_bzlmod", "true"),
            ("--noenable_bzlmod", "false"),
            ("--enable_bzlmod=false", "false"),
            ("--enable_bzlmod=0", "false"),
            ("--enable_bzlmod=YES", "true"),
            ("--experimental_enable_bzlmod", "true"),
            // Both spellings are one option: the last one wins.
            ("--experimental_enable_bzlmod --noenable_bzlmod", "false"),
            ("--noenable_bzlmod --experimental_enable_bzlmod=1", "true"),
            // Not a boolean: kept as written, for the caller to refuse.
            ("--enable_bzlmod=maybe", "maybe"),
        ] {
            assert_eq!(on(rc, Flag::EnableBzlmod), set(expected), "{rc}");
        }
        assert_eq!(on("--nofetch", Flag::Fetch), set("false"));
        assert_eq!(on("--fetch=false", Flag::Fetch), set("false"));
        // `--noname=value` and `--no_name` are not negations.
        assert_eq!(on("--nofetch=true", Flag::Fetch), FlagState::NotSeen);
        // An enum value matches without regard to case; a path does not.
        assert_eq!(
            on("--lockfile_mode=ERROR", Flag::LockfileMode),
            set("error")
        );
        assert_eq!(
            on("--vendor_dir=Third_Party", Flag::VendorDir),
            set("Third_Party")
        );
        // `--name value`: the next token is the value.
        assert_eq!(
            on("--lockfile_mode error", Flag::LockfileMode),
            set("error")
        );
        assert_eq!(
            on("--vendor_dir --nofetch", Flag::VendorDir),
            set("--nofetch")
        );
        assert_eq!(
            on("--vendor_dir --nofetch", Flag::Fetch),
            FlagState::NotSeen
        );
        assert_eq!(
            on("--lockfile_mode", Flag::LockfileMode),
            FlagState::NotSeen
        );
        // The old and new names of the downloader flags.
        for name in ["downloader_config", "experimental_downloader_config"] {
            assert_eq!(
                on(&format!("--{name}=dl.cfg"), Flag::DownloaderConfig),
                set("dl.cfg")
            );
        }
        for name in [
            "repository_disable_download",
            "experimental_repository_disable_download",
        ] {
            assert_eq!(
                on(&format!("--{name}"), Flag::RepositoryDisableDownload),
                set("true")
            );
        }
        // With platform configs on, an OS section applies on that OS by
        // itself; it is still reported under its name.
        let platform =
            "build --enable_platform_specific_config\nbuild:linux --lockfile_mode=error\n";
        let flags = flags(platform, &line);
        assert_eq!(
            flags.state(Flag::PlatformSpecificConfig, Chain::Build),
            set("true")
        );
        assert_eq!(
            flags.state(Flag::LockfileMode, Chain::Build),
            possible(&[("linux", "error")])
        );
    }

    #[test]
    fn every_flag_has_one_row_and_no_spelling_twice() {
        for (index, (flag, kind, name)) in FLAGS.iter().enumerate() {
            assert_eq!(
                *flag as usize, index,
                "{flag:?} is out of declaration order"
            );
            assert_eq!(
                FLAGS.iter().filter(|row| row.2 == *name).count(),
                1,
                "{name}"
            );
            // A boolean named `no...` would hide another flag's negation.
            assert!(*kind != Kind::Bool || !name.starts_with("no"), "{name}");
            assert_eq!(lookup(name), Some((*flag, *kind, *name)));
        }
        assert_eq!(FLAGS.len(), Flag::DigestFunction as usize + 1);
        for (old, current) in OLD_NAMES {
            assert!(
                FLAGS.iter().all(|row| row.2 != *old),
                "{old} is also a current name"
            );
            let (flag, kind, written) = lookup(old).expect("an old name resolves");
            assert_eq!(
                (Some((flag, kind)), written),
                (lookup(current).map(|f| (f.0, f.1)), *old)
            );
        }
        assert_eq!(lookup("define"), None);
    }

    /// Only a canonical name takes effect on Bazel 6 to 8, and the gate
    /// owns that match: the reader hands over the raw text.
    #[test]
    fn override_flags_keep_the_raw_name_and_path_of_each_occurrence() {
        let rc = "common --override_repository=rules_foo=%workspace%/third_party/foo\n\
                  common \\\n  --override_repository _main~ext~hub=../hub\n\
                  build:ci --override_repository=+ext+spoke=/abs\n\
                  common --override_repository=broken\n\
                  common --override_module=rules_bar=vendor/bar\n";
        let flags = flags(rc, &exact("7.7.2"));
        let seen = flags.occurrences(Flag::OverrideRepository, Chain::Build);
        let rows: Vec<_> = seen
            .iter()
            .map(|o| {
                (
                    o.name_and_path(),
                    o.config.as_str(),
                    o.certain,
                    o.site.to_string(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                (
                    Some(("rules_foo", "%workspace%/third_party/foo")),
                    "",
                    true,
                    ".bazelrc:1".to_string()
                ),
                (
                    Some(("_main~ext~hub", "../hub")),
                    "",
                    true,
                    ".bazelrc:2".to_string()
                ),
                (None, "", true, ".bazelrc:5".to_string()),
                (
                    Some(("+ext+spoke", "/abs")),
                    "ci",
                    true,
                    ".bazelrc:4".to_string()
                ),
            ]
        );
        assert!(seen.iter().all(|o| o.spelling == "override_repository"));
        // `mod` reads `common` lines and no `build:ci` line.
        assert_eq!(
            flags
                .occurrences(Flag::OverrideRepository, Chain::Mod)
                .len(),
            3
        );
        let module = flags.occurrences(Flag::OverrideModule, Chain::Build);
        assert_eq!(module[0].name_and_path(), Some(("rules_bar", "vendor/bar")));
        assert!(flags
            .occurrences(Flag::InjectRepository, Chain::Build)
            .is_empty());
    }

    #[test]
    fn repo_env_is_read_per_variable() {
        let rc = "common --repo_env=GOPROXY=off\n\
                  common --repo_env=GOPROXY=https://proxy.example,direct\n\
                  common --repo_env=GOFLAGS\n\
                  common --repo_env==GOPRIVATE\n\
                  common:host --repo_env=GO_REPOSITORY_USE_HOST_MODCACHE=1\n\
                  common:host --repo_env GO_REPOSITORY_USE_HOST_CACHE=1\n\
                  common --experimental_strict_repo_env\n";
        let flags = flags(rc, &exact("9.3.2"));
        let value = |text: &str| RepoEnv::Value(text.to_string());
        let env = |name: &str| flags.repo_env(name, Chain::Build);
        assert_eq!(
            env("GOPROXY"),
            FlagState::Set(value("https://proxy.example,direct"))
        );
        assert_eq!(env("GOFLAGS"), FlagState::Set(RepoEnv::Inherit));
        assert_eq!(env("GOPRIVATE"), FlagState::Set(RepoEnv::Unset));
        assert_eq!(env("GONOPROXY"), FlagState::NotSeen);
        for name in [
            "GO_REPOSITORY_USE_HOST_MODCACHE",
            "GO_REPOSITORY_USE_HOST_CACHE",
        ] {
            let host = FlagState::Possible([("host".to_string(), value("1"))].into());
            assert_eq!(env(name), host, "{name}");
        }
        assert_eq!(flags.state(Flag::StrictRepoEnv, Chain::Build), set("true"));
        // Each tracked variable is read by its exact name.
        let seen = GO_REPO_ENV
            .iter()
            .filter(|name| env(name) != FlagState::NotSeen);
        assert_eq!(seen.count(), 5);
        assert_eq!(env("goproxy"), FlagState::NotSeen);
    }

    #[test]
    fn only_an_option_every_build_passes_proves_a_newer_bazel() {
        let shapes = |rc: &str| read(&Files::of(&[(".bazelrc", rc)])).api_shapes();
        assert_eq!(
            shapes("common --enable_workspace\n"),
            [ApiShape::EnableWorkspaceFlag]
        );
        assert_eq!(
            shapes("build --noenable_workspace\n"),
            [ApiShape::EnableWorkspaceFlag]
        );
        // Bazel parses a token even when a later one overrides it.
        assert_eq!(
            shapes("build --lockfile_mode=refresh\nbuild --lockfile_mode=update\n"),
            [ApiShape::LockfileModeRefresh]
        );
        // A config may never be used, `always` is skipped before 6.3.0,
        // and `test` is not every build.
        for rc in [
            "common:new --enable_workspace\n",
            "always --enable_workspace\n",
            "test --enable_workspace\n",
            "try-import new.rc\n",
            "common --lockfile_mode=update\n",
        ] {
            assert_eq!(shapes(rc), [], "{rc}");
        }
    }

    #[test]
    fn imports_are_bounded() {
        // A chain of imports deeper than the reader follows.
        let mut files: Vec<(String, String)> = Vec::new();
        for depth in 0..12 {
            let name = if depth == 0 {
                ".bazelrc".to_string()
            } else {
                format!("{depth}.rc")
            };
            files.push((name, format!("import %workspace%/{}.rc\n", depth + 1)));
        }
        files.push((
            "12.rc".to_string(),
            "common --lockfile_mode=error\n".to_string(),
        ));
        let borrowed: Vec<(&str, &str)> = files.iter().map(|(p, t)| (&p[..], &t[..])).collect();
        let flags = flags_of(&borrowed, &exact("7.7.2"));
        let state = flags.state(Flag::LockfileMode, Chain::Build);
        assert!(matches!(state, FlagState::UnknowableHard(_)), "{state:?}");
        assert!(read(&Files::of(&borrowed)).files.len() <= MAX_DEPTH + 2);

        // Configs that double at every level: Bazel would never finish,
        // and the reader stops instead of following it.
        let mut doubling = String::from("build --config=c0\n");
        for level in 0..40 {
            let next = level + 1;
            doubling += &format!("build:c{level} --config=c{next} --config=c{next}\n");
        }
        for last in ["build:c40 --lockfile_mode=error\n", "build:c40\n", ""] {
            let rc = format!("{doubling}{last}");
            let state = lock_mode(&rc, &exact("7.7.2"), Chain::Build);
            assert!(
                matches!(state, FlagState::UnknowableHard(_)),
                "{last:?}: {state:?}"
            );
        }

        assert_eq!(root_relative("a/./b//c"), Some("a/b/c".to_string()));
        assert_eq!(root_relative("a/../../x/../y"), Some("../y".to_string()));
        assert_eq!(root_relative("../../x"), Some("../../x".to_string()));
        for outside in ["/etc/x", "C:/x", "", ".", "a/.."] {
            assert_eq!(root_relative(outside), None, "{outside:?}");
        }
    }

    #[test]
    fn no_input_makes_the_reader_panic() {
        let seed = "import %workspace%/a.rc\ntry-import-if-bazel-version >=9.0.0 b.rc\n\
                    common:ci --config=x --lockfile_mode=\"error\" \\\n --noenable_bzlmod\n\
                    build --config ci --override_repository a=b --repo_env==X # c\n\
                    startup:linux --output_base='/x y'\nalways --config=ci\n";
        let lines = [
            BazelLine::unknown(),
            exact("6.2.1"),
            exact("9.3.2"),
            majors(6, 8),
        ];
        let mut rng = Rng::new(0x5c);
        for round in 0..300 {
            let mut bytes = seed.as_bytes().to_vec();
            for _ in 0..rng.below(6) {
                let at = rng.below(bytes.len());
                match rng.below(4) {
                    0 => bytes.truncate(at),
                    1 => bytes[at] = (rng.next() & 0xff) as u8,
                    2 => bytes.insert(
                        at,
                        *b"\\\n\"'#:= \r\0-".get(rng.below(11)).expect("in range"),
                    ),
                    _ if bytes.len() < 2 * seed.len() => bytes.extend_from_within(at..),
                    _ => bytes.reverse(),
                }
                if bytes.is_empty() {
                    bytes.push(b'#');
                }
            }
            let files = Files::default()
                .with(".bazelrc", FileText::Bytes(bytes.clone()))
                .with("a.rc", FileText::Bytes(bytes.clone()))
                .with("b.rc", FileText::Bytes(bytes));
            let rc = read(&files);
            let _ = rc.api_shapes();
            let flags = rc.effective(&lines[round % lines.len()]);
            let chains = [Chain::Build, Chain::Fetch, Chain::Mod, Chain::Startup];
            for (flag, ..) in FLAGS {
                let _ = flags.state(*flag, chains[rng.below(chains.len())]);
            }
            let _ = flags.occurrences(Flag::OverrideRepository, Chain::Build);
            let _ = flags.repo_env("X", Chain::Fetch);
            let _ = flags.gaps();
        }
    }
}
