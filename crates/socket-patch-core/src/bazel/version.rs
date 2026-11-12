//! Which Bazel runs a workspace, and what that Bazel does by default
//! (design 2.4, 2.5, 8).
//!
//! - [`read_declared`] and [`line`]: the line ladder. The launcher files
//!   (`.bazeliskrc`, `.bazelversion`) are read the way bazelisk v1.30.0
//!   reads them, then the `lockFileVersion` token, then API shapes. The
//!   result is a range with the evidence for it, never a guess: a floating
//!   or unreadable label is unknown.
//! - [`tier`]: the support tier of a line (owner decision D3).
//! - [`dep_system`]: the one copy of the dependency-system table. Bzlmod,
//!   `WORKSPACE` or both is decided by the line and two rc flags, never by
//!   the files that happen to exist.
//! - [`lock_token_releases`] and [`lockfile_mode_default`]: what a release
//!   writes into `MODULE.bazel.lock` and whether it reads the file at all.
//! - [`module_version_cmp`]: Bazel's ordering of module versions, which
//!   the ruleset version gates compare with.
//!
//! The launcher files are *declared* evidence: bazelisk reads them and the
//! Bazel binary never does, so a line holds only when bazelisk is the
//! launcher. Machine-level settings (`USE_BAZEL_VERSION` in the
//! environment, `~/.bazeliskrc`) are never read: they must not steer what
//! is committed.

use std::cmp::Ordering;
use std::fmt;

use super::model::{BoundaryFiles, DeclSystem, FileText, FileView, RootRef};
use super::rc::{Chain, EffectiveFlags, Flag, FlagState, LockfileMode};

/// Whether something holds on every release a line may run, on none of
/// them, or on some.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    No,
    Maybe,
    Yes,
}

impl Tri {
    pub fn and(self, other: Tri) -> Tri {
        match (self, other) {
            (Tri::No, _) | (_, Tri::No) => Tri::No,
            (Tri::Yes, Tri::Yes) => Tri::Yes,
            _ => Tri::Maybe,
        }
    }
}

impl std::ops::Not for Tri {
    type Output = Tri;

    fn not(self) -> Tri {
        match self {
            Tri::No => Tri::Yes,
            Tri::Maybe => Tri::Maybe,
            Tri::Yes => Tri::No,
        }
    }
}

// ── Releases ─────────────────────────────────────────────────────────

/// One Bazel release: `X.Y.Z`, or the candidate `X.Y.ZrcN`.
///
/// A candidate orders below its release, so a threshold such as "from
/// 7.2.0" is not met by `7.2.0rc1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BazelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// `Some(n)` for the candidate `rcN`.
    pub rc: Option<u32>,
}

impl BazelVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            rc: None,
        }
    }

    /// The top of a floating major (`7.x`): above every release of it,
    /// the ones not yet published included.
    pub const fn ceiling(major: u32) -> Self {
        Self::new(major, u32::MAX, u32::MAX)
    }

    /// `X.Y.Z` or `X.Y.ZrcN`: the two spellings that name one release.
    pub fn parse(label: &str) -> Option<Self> {
        let (release, rc) = match label.split_once("rc") {
            Some((release, n)) => (release, Some(number(n)?)),
            None => (label, None),
        };
        let mut parts = release.split('.');
        let version = Self {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
            rc,
        };
        parts.next().is_none().then_some(version)
    }

    /// The release this is, or is a candidate of.
    pub const fn release(self) -> Self {
        Self::new(self.major, self.minor, self.patch)
    }

    pub const fn is_final(self) -> bool {
        self.rc.is_none()
    }

    fn key(self) -> (u32, u32, u32, u64) {
        let rc = self.rc.map_or(u64::MAX, u64::from);
        (self.major, self.minor, self.patch, rc)
    }
}

impl Ord for BazelVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for BazelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for BazelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minor == u32::MAX {
            return write!(f, "{}.x", self.major);
        }
        write!(f, "{}.{}", self.major, self.minor)?;
        if self.patch != u32::MAX {
            write!(f, ".{}", self.patch)?;
        }
        self.rc.map_or(Ok(()), |rc| write!(f, "rc{rc}"))
    }
}

/// A run of ASCII digits, as bazelisk's `\d+` matches it.
fn number(digits: &str) -> Option<u32> {
    let all_digits = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    all_digits.then(|| digits.parse().ok())?
}

const fn v(major: u32, minor: u32, patch: u32) -> BazelVersion {
    BazelVersion::new(major, minor, patch)
}

/// The newest release of each major the campaign's probes ran. Anything
/// above its major's entry, and every major above the last, is evaluated
/// as the newest audited line with an "untested" advisory (owner decision
/// D10).
pub const NEWEST_AUDITED: [BazelVersion; 6] = [
    v(5, 4, 1),
    v(6, 6, 0),
    v(7, 7, 2),
    v(8, 8, 2),
    v(9, 3, 2),
    BazelVersion {
        major: 10,
        minor: 0,
        patch: 0,
        rc: Some(3),
    },
];

/// The newest audited final release: the line an unknown line is
/// evaluated as.
const NEWEST_RELEASE: BazelVersion = v(9, 3, 2);

// ── Launcher files ───────────────────────────────────────────────────

/// What a launcher label names (bazelisk v1.30.0 `versions.Parse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// `X.Y.Z` or `X.Y.ZrcN`.
    Exact(BazelVersion),
    /// `N.x`, the newest release of N, or `N.*`, which may also be a
    /// candidate. bazelisk floats both, so a gate must hold for all of N.
    Track { major: u32, candidates: bool },
    /// A label bazelisk accepts and that names no release socket-patch
    /// can place: `latest`, `latest-N`, `last_rc`, `last_green`,
    /// `rolling`, a commit, a patch build, a fork. Also the answer when no
    /// file gives a label, where bazelisk falls back to `latest`.
    Floating,
    /// bazelisk cannot parse the label: it stops before any Bazel runs.
    Invalid,
}

/// Classifies a label as bazelisk does: `[<fork>/]<version>`, with the
/// version matched against bazelisk's patterns.
pub fn classify(label: &str) -> Label {
    let (fork, version) = match label.split('/').collect::<Vec<_>>()[..] {
        [version] => ("", version),
        [fork, version] => (fork, version),
        _ => return Label::Invalid,
    };
    // `bazelbuild` is upstream itself; any other fork runs another Bazel.
    let upstream = fork.is_empty() || fork == "bazelbuild";
    match classify_version(version) {
        Label::Invalid => Label::Invalid,
        _ if !upstream => Label::Floating,
        reading => reading,
    }
}

fn classify_version(version: &str) -> Label {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let word = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let release = |s: &str| s.split('.').count() == 3 && s.split('.').all(digits);
    let candidate = |s: &str| {
        s.split_once("rc")
            .is_some_and(|(head, n)| release(head) && digits(n))
    };
    if release(version) || candidate(version) {
        // bazelisk asks for the label as written: `07.7.2` is accepted
        // and is no release, like a number u32 cannot hold.
        let written = BazelVersion::parse(version).filter(|v| v.to_string() == version);
        return written.map_or(Label::Floating, Label::Exact);
    }
    if let Some((major, kind @ ("x" | "*"))) = version.split_once('.') {
        if digits(major) {
            let candidates = kind == "*";
            let track = |major| Label::Track { major, candidates };
            return number(major).map_or(Label::Floating, track);
        }
    }
    // `<release>-<word>` and `<candidate>-<word>` are patch builds;
    // `<N>.0.0-pre.<date>.<n>[.<n>]` is one rolling release.
    let patch = version
        .rsplit_once('-')
        .is_some_and(|(head, tag)| (release(head) || candidate(head)) && word(tag));
    let rolling = version.split_once("-pre.").is_some_and(|(head, pre)| {
        let parts: Vec<&str> = pre.split('.').collect();
        let major = head.strip_suffix(".0.0").is_some_and(digits);
        let date = parts[0].len() == 8 && digits(parts[0]);
        major && date && (2..=3).contains(&parts.len()) && parts.iter().all(|p| digits(p))
    });
    let latest = version == "latest" || version.strip_prefix("latest-").is_some_and(digits);
    let commit = version.len() == 40
        && version
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let named = matches!(version, "last_rc" | "last_green" | "rolling");
    if patch || rolling || latest || commit || named {
        Label::Floating
    } else {
        Label::Invalid
    }
}

/// The label of a `.bazelversion`: the bytes before the first LF, minus
/// exactly one trailing CR. Nothing else is trimmed, so a trailing space,
/// a BOM or a comment stays in the label and bazelisk rejects it; a CRLF
/// checkout reads as its version.
pub fn bazelversion_label(bytes: &[u8]) -> String {
    let line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    String::from_utf8_lossy(line).into_owned()
}

/// The value of `key` in a `.bazeliskrc`: lines split at LF, a line that
/// starts with `#` is a comment, key and value are trimmed and the last
/// assignment wins.
pub fn bazeliskrc_value(bytes: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let assignments = text
        .split('\n')
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='));
    let mut value = None;
    for (name, text) in assignments {
        if name.trim() == key {
            value = Some(text.trim().to_string());
        }
    }
    value
}

/// One launcher file between the project and the read boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredFile {
    /// Its [`FileView`] path: `.bazelversion`, `svc/.bazeliskrc`,
    /// `../.bazelversion`.
    pub file: String,
    /// The label it gives bazelisk. `None`: it has none (no
    /// `USE_BAZEL_VERSION`, an empty first line) or it cannot be read.
    pub label: Option<String>,
    pub readable: bool,
}

/// What bazelisk runs when started in one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    /// The directory, relative to the Bazel root (`""` = the root).
    pub cwd: String,
    /// The file the label comes from; `None` when no file gives one and
    /// bazelisk falls back to `latest`.
    pub file: Option<String>,
    pub label: Option<String>,
    pub reading: Label,
}

/// The launcher files of a root (design 2.4 row 1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declared {
    /// Every `.bazeliskrc` and `.bazelversion` from the project directory
    /// up to the read boundary, nearest the project first.
    pub files: Vec<DeclaredFile>,
    /// What bazelisk picks from each directory between the project and
    /// the Bazel root, without repeats. bazelisk takes the file nearest
    /// its working directory, so one workspace can run two Bazel versions.
    pub picks: Vec<Pick>,
    /// Launcher wrappers under `<root>/tools`. bazelisk runs an executable
    /// one in place of the declared version, even for `--version`. The
    /// executable bit is not visible to this layer, so every file with a
    /// wrapper's name is listed: a blind spot, never a refusal.
    pub wrappers: Vec<String>,
}

const BAZELISKRC: &str = ".bazeliskrc";
const BAZELVERSION: &str = ".bazelversion";

/// Reads the launcher files of `root` as bazelisk v1.30.0 does: from each
/// directory it may be started in, the nearest `.bazeliskrc` with a
/// `USE_BAZEL_VERSION`, else the first line of the nearest `.bazelversion`
/// (a file above the root applies when nothing nearer exists).
pub fn read_declared(root: &RootRef, files: &dyn FileView) -> Declared {
    let dirs = root.dirs_to_boundary();
    let join = |dir: &str, name: &str| match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    };
    // `None` = no such file. bazelisk skips a directory of the name and
    // keeps walking up; a file it cannot read stops it.
    let said = |dir: &str, name: &str, label: &dyn Fn(&[u8]) -> Option<String>| {
        let file = join(dir, name);
        let (label, readable) = match files.read(&file) {
            FileText::Bytes(bytes) => (label(&bytes).filter(|l| !l.is_empty()), true),
            FileText::Absent => return None,
            FileText::Unreadable => {
                let listed = files.list(dir).unwrap_or_default();
                let is_dir = listed.iter().any(|n| n.strip_suffix('/') == Some(name));
                if is_dir {
                    return None;
                }
                (None, false)
            }
        };
        Some(DeclaredFile {
            file,
            label,
            readable,
        })
    };
    let rcs: Vec<Option<DeclaredFile>> = dirs
        .iter()
        .map(|dir| {
            said(dir, BAZELISKRC, &|b| {
                bazeliskrc_value(b, "USE_BAZEL_VERSION")
            })
        })
        .collect();
    let versions: Vec<Option<DeclaredFile>> = dirs
        .iter()
        .map(|dir| said(dir, BAZELVERSION, &|b| Some(bazelversion_label(b))))
        .collect();

    let at_root = dirs.iter().position(|dir| dir.is_empty()).unwrap_or(0);
    let mut picks: Vec<Pick> = Vec::new();
    for cwd in 0..=at_root {
        // Only the nearest `.bazeliskrc` is consulted; one without the key
        // sends bazelisk on to `.bazelversion`.
        let rc = rcs[cwd..].iter().flatten().next();
        let rc = rc.filter(|file| file.label.is_some() || !file.readable);
        let chosen = rc.or_else(|| versions[cwd..].iter().flatten().next());
        let label = chosen.and_then(|file| file.label.clone());
        let pick = Pick {
            cwd: dirs[cwd].clone(),
            file: chosen.map(|file| file.file.clone()),
            reading: label.as_deref().map_or(Label::Floating, classify),
            label,
        };
        let repeat = |p: &Pick| p.file == pick.file && p.label == pick.label;
        if !picks.iter().any(repeat) {
            picks.push(pick);
        }
    }

    let found = rcs.into_iter().zip(versions).flat_map(|(rc, v)| [rc, v]);
    let tools = files.list("tools").unwrap_or_default();
    Declared {
        files: found.flatten().collect(),
        picks,
        wrappers: tools
            .iter()
            .filter(|name| is_wrapper(name))
            .map(|name| format!("tools/{name}"))
            .collect(),
    }
}

/// bazelisk's wrapper candidates: `bazel`, `bazel.<arch>`,
/// `bazel.<os>-<arch>`, each with `.exe` on Windows, `bazel.ps1` and
/// `bazel.bat`. `tools/bazel.rc` is not one.
fn is_wrapper(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("bazel") else {
        return false;
    };
    let rest = rest.strip_suffix(".exe").unwrap_or(rest);
    let arch = |a: &str| matches!(a, "x86_64" | "arm64");
    match rest.strip_prefix('.') {
        None => rest.is_empty(),
        Some("ps1" | "bat") => true,
        Some(platform) => match platform.split_once('-') {
            Some((os, a)) => matches!(os, "linux" | "darwin" | "windows") && arch(a),
            None => arch(platform),
        },
    }
}

// ── The line ─────────────────────────────────────────────────────────

/// An API whose presence proves a lower bound on the line (design 2.4
/// row 3): an older Bazel stops on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiShape {
    /// `use_repo_rule` in `MODULE.bazel`.
    UseRepoRule,
    /// `--enable_workspace` on every build, in either polarity.
    EnableWorkspaceFlag,
    /// `include()` in `MODULE.bazel`.
    Include,
    /// `--lockfile_mode=refresh` on every build.
    LockfileModeRefresh,
    /// `override_repo` in `MODULE.bazel`.
    OverrideRepo,
}

impl ApiShape {
    /// The first release that accepts it.
    pub const fn since(self) -> BazelVersion {
        match self {
            Self::UseRepoRule => v(7, 0, 0),
            Self::EnableWorkspaceFlag => v(7, 1, 0),
            Self::Include | Self::LockfileModeRefresh => v(7, 2, 0),
            Self::OverrideRepo => v(7, 4, 0),
        }
    }

    pub const fn what(self) -> &'static str {
        match self {
            Self::UseRepoRule => "use_repo_rule",
            Self::EnableWorkspaceFlag => "--enable_workspace",
            Self::Include => "include()",
            Self::LockfileModeRefresh => "--lockfile_mode=refresh",
            Self::OverrideRepo => "override_repo",
        }
    }
}

/// One piece of evidence for a line, strongest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineEvidence {
    /// Row 1: what bazelisk runs from one directory. Declared, not
    /// proven: the Bazel binary never reads the launcher files. A
    /// [`Label::Invalid`] reading means bazelisk cannot parse the file.
    Declared(Pick),
    /// Row 2: the `lockFileVersion` of `MODULE.bazel.lock`, as of the
    /// lock. `agrees` is false when no release of the declared line
    /// writes the token.
    LockToken { token: u64, agrees: bool },
    /// Row 3.
    Api(ApiShape),
    /// A `tools/bazel` wrapper that may run in place of the declared
    /// version.
    Wrapper(String),
}

/// The Bazel releases a workspace may run: an inclusive range, either
/// side `None` when nothing bounds it, and what the range rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BazelLine {
    pub lo: Option<BazelVersion>,
    /// For a floating major this is [`BazelVersion::ceiling`].
    pub hi: Option<BazelVersion>,
    pub evidence: Vec<LineEvidence>,
}

impl BazelLine {
    /// No evidence of any line.
    pub const fn unknown() -> Self {
        Self {
            lo: None,
            hi: None,
            evidence: Vec::new(),
        }
    }

    /// A line of one release, with no evidence attached.
    pub const fn of(version: BazelVersion) -> Self {
        Self {
            lo: Some(version),
            hi: Some(version),
            evidence: Vec::new(),
        }
    }

    /// The one release the line names.
    pub fn exact(&self) -> Option<BazelVersion> {
        self.lo.filter(|lo| Some(*lo) == self.hi)
    }

    pub fn is_unknown(&self) -> bool {
        self.lo.is_none() && self.hi.is_none()
    }

    /// Whether the line is at or above `threshold`.
    pub fn at_least(&self, threshold: BazelVersion) -> Tri {
        if self.lo.is_some_and(|lo| lo >= threshold) {
            Tri::Yes
        } else if self.hi.is_some_and(|hi| hi < threshold) {
            Tri::No
        } else {
            Tri::Maybe
        }
    }

    /// Whether the line may run a release no probe ran: its top is open,
    /// or above the newest audited release of its major.
    pub fn untested(&self) -> bool {
        self.hi.is_none_or(|hi| {
            let audited = NEWEST_AUDITED.iter().find(|a| a.major == hi.major);
            audited.is_none_or(|newest| hi > *newest)
        })
    }
}

impl fmt::Display for BazelLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.lo, self.hi) {
            (None, None) => write!(f, "unknown"),
            (Some(lo), None) => write!(f, "{lo} or newer"),
            (None, Some(hi)) => write!(f, "{hi} or older"),
            (Some(lo), Some(hi)) if lo == hi => write!(f, "{lo}"),
            (Some(lo), Some(hi)) if lo == v(hi.major, 0, 0) && hi == ceiling(hi.major) => {
                write!(f, "{hi}")
            }
            (Some(lo), Some(hi)) => write!(f, "{lo} - {hi}"),
        }
    }
}

const fn ceiling(major: u32) -> BazelVersion {
    BazelVersion::ceiling(major)
}

/// The line ladder (design 2.4): the launcher files, then the
/// `lockFileVersion` token, then API shapes.
///
/// When bazelisk would pick different versions from different directories
/// the line is their span, never the nearest alone: a `WORKSPACE`-only hub
/// can be live from one directory and dead from another. One pick that
/// names no release makes the declared line unknown.
pub fn line(declared: &Declared, lock_file_version: Option<u64>, shapes: &[ApiShape]) -> BazelLine {
    let mut evidence: Vec<LineEvidence> = Vec::new();
    let mut span: Option<(BazelVersion, BazelVersion)> = None;
    let mut all_named = !declared.picks.is_empty();
    for pick in &declared.picks {
        evidence.push(LineEvidence::Declared(pick.clone()));
        let range = match pick.reading {
            Label::Exact(version) => Some((version, version)),
            Label::Track { major, .. } => Some((v(major, 0, 0), ceiling(major))),
            Label::Floating | Label::Invalid => None,
        };
        match (range, span) {
            (None, _) => all_named = false,
            (Some(range), None) => span = Some(range),
            (Some((lo, hi)), Some((a, b))) => span = Some((a.min(lo), b.max(hi))),
        }
    }
    let declared_span = span.filter(|_| all_named);
    let (mut lo, mut hi) = (declared_span.map(|s| s.0), declared_span.map(|s| s.1));

    let token_ranges = lock_file_version.map_or(Vec::new(), lock_token_releases);
    if let (Some(token), false) = (lock_file_version, token_ranges.is_empty()) {
        let agrees = match declared_span {
            Some((a, b)) => token_ranges
                .iter()
                .any(|(first, last)| a <= *last && *first <= b),
            None => true,
        };
        match declared_span {
            // No release of the token is the declared one: the lock and
            // the launcher file disagree, so only the major is kept.
            Some((a, b)) if a == b && !agrees => {
                (lo, hi) = (Some(v(a.major, 0, 0)), Some(ceiling(a.major)));
            }
            Some(_) => {}
            None => {
                lo = token_ranges.iter().map(|range| range.0).min();
                hi = token_ranges.iter().map(|range| range.1).max();
            }
        }
        evidence.push(LineEvidence::LockToken { token, agrees });
    }

    evidence.extend(shapes.iter().map(|shape| LineEvidence::Api(*shape)));
    let floor = shapes.iter().map(|shape| shape.since()).max();
    // A declared line is what bazelisk runs, whatever the files use. A
    // line read off the lock can be older than the workspace is now.
    if let (Some(floor), None) = (floor, declared_span) {
        if hi.is_some_and(|hi| hi < floor) {
            (lo, hi) = (Some(floor), None);
        } else if lo.is_none_or(|lo| lo < floor) {
            lo = Some(floor);
        }
    }

    let wrappers = declared.wrappers.iter().cloned();
    evidence.extend(wrappers.map(LineEvidence::Wrapper));
    BazelLine { lo, hi, evidence }
}

// ── Tiers ────────────────────────────────────────────────────────────

/// The support tier of a line for declarations of one system (owner
/// decision D3). Every tier runs the same code; a tier decides the docs
/// row and the CI weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Supported,
    Beta,
    Legacy,
    Refused(TierRefusal),
}

/// Why a line is refused outright. The guards still apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierRefusal {
    /// Bazel 4 or older.
    TooOld,
    /// Bzlmod on Bazel 5, where it is experimental.
    ExperimentalBzlmod,
    /// A `WORKSPACE` declaration on Bazel 9 or newer, which never reads it.
    WorkspaceRemoved,
    /// A `WORKSPACE` declaration with no evidence of the line: with no
    /// pin bazelisk runs `latest`, where `WORKSPACE` is gone.
    LineUnknown,
}

fn tier_at(release: BazelVersion, decl: DeclSystem) -> Tier {
    match (release.major, decl) {
        (0..=4, _) => Tier::Refused(TierRefusal::TooOld),
        (5, DeclSystem::Bzlmod) => Tier::Refused(TierRefusal::ExperimentalBzlmod),
        (5 | 6, _) => Tier::Legacy,
        (7, DeclSystem::Bzlmod) if release.minor < 2 => Tier::Beta,
        // A candidate is no supported release.
        (7..=9, DeclSystem::Bzlmod) if !release.is_final() => Tier::Beta,
        (7..=9, DeclSystem::Bzlmod) => Tier::Supported,
        (7 | 8, DeclSystem::Workspace) => Tier::Beta,
        (_, DeclSystem::Workspace) => Tier::Refused(TierRefusal::WorkspaceRemoved),
        // 10 is at a release candidate; anything newer is unaudited.
        (_, DeclSystem::Bzlmod) => Tier::Beta,
    }
}

/// The tier of `line` for a declaration written in `decl`'s file family:
/// the weakest tier of any release the line may run, because a floating
/// label runs them all over time. A line with no proven top is evaluated
/// as the newest audited release ([`BazelLine::untested`] then holds).
pub fn tier(line: &BazelLine, decl: DeclSystem) -> Tier {
    let Some(hi) = line.hi else {
        return match decl {
            DeclSystem::Workspace => Tier::Refused(TierRefusal::LineUnknown),
            DeclSystem::Bzlmod => tier_at(NEWEST_RELEASE, decl),
        };
    };
    let lo = line.lo.unwrap_or(hi);
    // Where the table changes between `lo` and `hi`.
    let steps = [(5, 0), (6, 0), (7, 0), (7, 2), (8, 0), (9, 0), (10, 0)];
    let steps = steps.iter().map(|(major, minor)| v(*major, *minor, 0));
    let points = [lo, hi]
        .into_iter()
        .chain(steps.filter(|s| lo < *s && *s <= hi));
    let rank = |tier: &Tier| match tier {
        Tier::Refused(_) => 0,
        Tier::Legacy => 1,
        Tier::Beta => 2,
        Tier::Supported => 3,
    };
    let tiers = points.map(|point| tier_at(point, decl));
    tiers.min_by_key(rank).unwrap_or(Tier::Beta)
}

// ── MODULE.bazel.lock ────────────────────────────────────────────────

/// The releases that write each `lockFileVersion`. A range that ends at
/// the newest audited release of its major is left open to that major's
/// ceiling: a later release may write the same token.
const LOCK_TOKENS: &[(u64, BazelVersion, BazelVersion)] = &[
    (1, v(6, 2, 0), v(6, 3, u32::MAX)),
    (3, v(6, 4, 0), ceiling(6)),
    (3, v(7, 0, 0), v(7, 0, u32::MAX)),
    (6, v(7, 1, 0), v(7, 1, u32::MAX)),
    (11, v(7, 2, 0), v(7, 4, u32::MAX)),
    // 12 and 14 are what 7.3.0 and later write under
    // `--incompatible_use_plus_in_repo_names`.
    (12, v(7, 3, 0), ceiling(7)),
    (13, v(7, 5, 0), ceiling(7)),
    (14, v(7, 3, 0), ceiling(7)),
    (16, v(8, 0, 0), v(8, 0, u32::MAX)),
    (18, v(8, 1, 0), v(8, 4, u32::MAX)),
    (24, v(8, 5, 0), v(8, 7, u32::MAX)),
    (26, v(9, 0, 0), v(9, 1, u32::MAX)),
    (28, v(8, 8, 0), ceiling(8)),
    (28, v(9, 2, 0), ceiling(9)),
    (28, NEWEST_AUDITED[5], ceiling(10)),
];

/// The release ranges that write `lockFileVersion` `token`, lowest first;
/// empty for a token no audited release writes. The token is an exact
/// match, never an ordering: 28 is written by 8.8 and 26 by 9.0.
pub fn lock_token_releases(token: u64) -> Vec<(BazelVersion, BazelVersion)> {
    let rows = LOCK_TOKENS.iter().filter(|row| row.0 == token);
    rows.map(|row| (row.1, row.2)).collect()
}

/// The `--lockfile_mode` a line runs with when no flag sets it, or `None`
/// when its releases differ or the line is not bounded on both sides.
///
/// Before 6.2.0 there is no lock file, which reads as `Off`; 6.2.x is
/// `Off`; 6.3.0 alone is `Update`; 6.3.1 to 6.6.x is `Off` again; from
/// 7.0.0 it is `Update`.
pub fn lockfile_mode_default(line: &BazelLine) -> Option<LockfileMode> {
    let (lo, hi) = (line.lo?.release(), line.hi?.release());
    let lone_update = v(6, 3, 0);
    if lo >= v(7, 0, 0) || (lo == lone_update && hi == lone_update) {
        Some(LockfileMode::Update)
    } else if hi < lone_update || (lo > lone_update && hi < v(7, 0, 0)) {
        Some(LockfileMode::Off)
    } else {
        None
    }
}

// ── Dependency system ────────────────────────────────────────────────

/// Which repository system Bazel evaluates in a workspace (design 2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepSystem {
    /// `MODULE.bazel` only; `WORKSPACE` files are dead.
    Bzlmod,
    /// `WORKSPACE.bazel`, else `WORKSPACE`; `WORKSPACE.bzlmod` is ignored.
    Workspace,
    /// Both: `MODULE.bazel`, and `WORKSPACE.bzlmod` if present, else
    /// `WORKSPACE.bazel`, else `WORKSPACE`.
    Hybrid,
    /// Both switched off (7.1 to 7.7): Bazel resolves no external
    /// repository, so every hub is dead.
    Neither,
    /// The line or the flags leave more than one system possible: a flag
    /// set only under a config, command chains that disagree, a line that
    /// spans releases with different defaults.
    DualMode {
        systems: Vec<DepSystem>,
        why: String,
    },
    /// No system can be named: Bazel itself rejects the rc flags on this
    /// line, or an rc file that sets them cannot be read. `why` names the
    /// rc line.
    Unknown { why: String },
}

impl DepSystem {
    /// The `WORKSPACE`-family file Bazel evaluates under this system,
    /// among the ones the root holds.
    pub fn workspace_file(&self, boundary: &BoundaryFiles) -> Option<&'static str> {
        let plain = if boundary.workspace_bazel {
            Some("WORKSPACE.bazel")
        } else {
            boundary.workspace.then_some("WORKSPACE")
        };
        match self {
            Self::Workspace => plain,
            Self::Hybrid if boundary.workspace_bzlmod => Some("WORKSPACE.bzlmod"),
            Self::Hybrid => plain,
            _ => None,
        }
    }
}

/// The stretches of releases that share one row set of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Era {
    /// Bazel 4 and older: no Bzlmod at all.
    Pre5,
    V5,
    V6,
    /// 7.0.x: Bzlmod on, and no flag to switch `WORKSPACE` off.
    V70,
    /// 7.1 to 7.x.
    V7,
    V8,
    /// 9 and newer: both flags are accepted and do nothing.
    V9,
}

const ERAS: [(Era, BazelVersion); 7] = [
    (Era::Pre5, v(0, 0, 0)),
    (Era::V5, v(5, 0, 0)),
    (Era::V6, v(6, 0, 0)),
    (Era::V70, v(7, 0, 0)),
    (Era::V7, v(7, 1, 0)),
    (Era::V8, v(8, 0, 0)),
    (Era::V9, v(9, 0, 0)),
];

/// The eras `line` may run. A candidate belongs to its release's era:
/// `8.0.0rc1` has the defaults of 8.
fn eras(line: &BazelLine) -> Vec<Era> {
    let overlaps = |(i, (_, first)): &(usize, &(Era, BazelVersion))| {
        let next = ERAS.get(i + 1).map(|(_, first)| *first);
        let below_top = line.hi.is_none_or(|hi| hi.release() >= *first);
        let above_bottom = line
            .lo
            .is_none_or(|lo| next.is_none_or(|next| lo.release() < next));
        below_top && above_bottom
    };
    let inside = ERAS.iter().enumerate().filter(overlaps);
    inside.map(|(_, (era, _))| *era).collect()
}

/// What the rc files say about the two flags on one command chain,
/// beyond their values.
struct Spelled {
    /// `--enable_workspace` appears, in either polarity.
    workspace: Option<String>,
    /// `--enable_bzlmod` appears under its non-experimental name.
    plain_bzlmod: Option<String>,
    /// Either flag appears at all.
    any: Option<String>,
}

/// One row of the table: the system an era runs with these two flag
/// values (`None` = not set), or why Bazel stops on them. A flag an era
/// does not know is fatal in either polarity, from a `common` line too
/// (`ERROR: --enable_workspace :: Unrecognized option`, exit 2).
fn row(
    era: Era,
    bzlmod: Option<bool>,
    workspace: Option<bool>,
    spelled: &Spelled,
) -> Result<DepSystem, String> {
    let unknown_flag = |site: &String, flag: &str, since: &str| {
        format!("{site}: Bazel older than {since} stops on `{flag}` (Unrecognized option)")
    };
    match era {
        Era::Pre5 => match &spelled.any {
            Some(site) => Err(unknown_flag(
                site,
                "--experimental_enable_bzlmod` or `--enable_workspace",
                "5.0.0",
            )),
            None => Ok(DepSystem::Workspace),
        },
        Era::V5 | Era::V6 | Era::V70 => {
            if let Some(site) = &spelled.workspace {
                return Err(unknown_flag(site, "--enable_workspace", "7.1.0"));
            }
            if let (Era::V5, Some(site)) = (era, &spelled.plain_bzlmod) {
                return Err(unknown_flag(site, "--enable_bzlmod", "6.0.0"));
            }
            // Bzlmod is off by default through 6.x and on from 7.0.
            let on = bzlmod.unwrap_or(era == Era::V70);
            Ok(if on {
                DepSystem::Hybrid
            } else {
                DepSystem::Workspace
            })
        }
        Era::V7 => Ok(match (bzlmod.unwrap_or(true), workspace.unwrap_or(true)) {
            (true, true) => DepSystem::Hybrid,
            (true, false) => DepSystem::Bzlmod,
            (false, true) => DepSystem::Workspace,
            (false, false) => DepSystem::Neither,
        }),
        Era::V8 => match (bzlmod.unwrap_or(true), workspace.unwrap_or(false)) {
            (true, false) => Ok(DepSystem::Bzlmod),
            (true, true) => Ok(DepSystem::Hybrid),
            (false, true) => Ok(DepSystem::Workspace),
            (false, false) => Err(format!(
                "{}: Bazel 8 stops when `--enable_bzlmod` and `--enable_workspace` are both off",
                spelled.any.clone().unwrap_or_default()
            )),
        },
        Era::V9 => Ok(DepSystem::Bzlmod),
    }
}

/// The values one flag may take on a chain; `None` = not set, so the
/// era's default applies.
fn readings(flag: &str, state: &FlagState<String>) -> Result<Vec<Option<bool>>, String> {
    let parse = |text: &String| match text.as_str() {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        other => Err(format!(
            "`--{flag}={other}` is not a boolean; Bazel stops on it"
        )),
    };
    // The plain command first: its system leads a `DualMode` list.
    let mut out = Vec::new();
    if state.may_be_unset() {
        out.push(None);
    }
    for value in state.values() {
        let value = parse(value)?;
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// The systems one command chain may run on `eras`, or why Bazel stops.
fn chain_systems(
    eras: &[Era],
    flags: &EffectiveFlags,
    chain: Chain,
) -> Result<Vec<DepSystem>, String> {
    if eras.iter().all(|era| *era == Era::V9) {
        return Ok(vec![DepSystem::Bzlmod]);
    }
    let bzlmod = flags.state(Flag::EnableBzlmod, chain);
    let workspace = flags.state(Flag::EnableWorkspace, chain);
    // Unreadable is not unset: the import may flip either flag.
    for state in [&bzlmod, &workspace] {
        if let FlagState::UnknowableHard(why) = state {
            return Err(why.clone());
        }
    }
    let site = |flag: Flag, spelling: Option<&str>| {
        let seen = flags.occurrences(flag, chain);
        let named = seen
            .iter()
            .find(|o| spelling.is_none_or(|s| o.spelling == s));
        named.map(|o| o.site.to_string())
    };
    let workspace_site = site(Flag::EnableWorkspace, None);
    let spelled = Spelled {
        plain_bzlmod: site(Flag::EnableBzlmod, Some("enable_bzlmod")),
        any: workspace_site
            .clone()
            .or_else(|| site(Flag::EnableBzlmod, None)),
        workspace: workspace_site,
    };
    let bzlmod = readings("enable_bzlmod", &bzlmod)?;
    let workspace = readings("enable_workspace", &workspace)?;
    let mut systems: Vec<DepSystem> = Vec::new();
    for era in eras {
        for (b, w) in bzlmod
            .iter()
            .flat_map(|b| workspace.iter().map(move |w| (b, w)))
        {
            let system = row(*era, *b, *w, &spelled)?;
            if !systems.contains(&system) {
                systems.push(system);
            }
        }
    }
    Ok(systems)
}

/// The dependency system of a workspace: the table of design 2.5, keyed
/// on the line and on `--enable_bzlmod` / `--enable_workspace` as the
/// tracked rc files set them.
///
/// The result is one system only when every release of the line, every
/// reading of the flags and every command chain agree. An existing
/// `MODULE.bazel` proves nothing: Bazel 7 and newer create one.
pub fn dep_system(line: &BazelLine, flags: &EffectiveFlags) -> DepSystem {
    let eras = eras(line);
    let mut by_chain: Vec<(Chain, Vec<DepSystem>)> = Vec::new();
    for chain in Chain::COMMANDS {
        match chain_systems(&eras, flags, *chain) {
            Ok(systems) => by_chain.push((*chain, systems)),
            Err(why) => return DepSystem::Unknown { why },
        }
    }
    // `Chain::COMMANDS` starts with the build chain, which governs.
    let build = by_chain[0].1.clone();
    let differs = |systems: &Vec<DepSystem>| {
        systems.len() != build.len() || systems.iter().any(|system| !build.contains(system))
    };
    if let Some((chain, other)) = by_chain.iter().find(|(_, systems)| differs(systems)) {
        let extra = other.iter().filter(|system| !build.contains(system));
        let why = format!(
            "`bazel {}` and `bazel build` read different `--enable_bzlmod` / \
             `--enable_workspace` values from the rc files",
            chain.name()
        );
        return DepSystem::DualMode {
            systems: build.iter().chain(extra).cloned().collect(),
            why,
        };
    }
    match &build[..] {
        [one] => one.clone(),
        _ if eras.len() > 1 && flags_fixed(flags) => DepSystem::DualMode {
            why: format!("Bazel {line} spans releases with different defaults"),
            systems: build,
        },
        _ => DepSystem::DualMode {
            why: "`--enable_bzlmod` or `--enable_workspace` is set only under a config, or only \
                  on some releases of the line"
                .to_string(),
            systems: build,
        },
    }
}

/// Whether neither flag depends on a config or on the release.
fn flags_fixed(flags: &EffectiveFlags) -> bool {
    [Flag::EnableBzlmod, Flag::EnableWorkspace]
        .iter()
        .all(|flag| !matches!(flags.state(*flag, Chain::Build), FlagState::Possible(_)))
}

// ── Module versions ──────────────────────────────────────────────────

/// One dot-separated identifier of a module version. The field order is
/// the comparison: digits-only identifiers sort first and compare as
/// numbers, then as text (`01` is below `1`); the others compare as text.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Identifier<'a> {
    word: bool,
    number: u64,
    text: &'a str,
}

fn identifiers(part: &str, hyphens: bool) -> Option<Vec<Identifier<'_>>> {
    let identifier = |text| {
        let text: &str = text;
        let legal = |b: u8| b.is_ascii_alphanumeric() || (hyphens && b == b'-');
        if text.is_empty() || !text.bytes().all(legal) {
            return None;
        }
        let word = !text.bytes().all(|b| b.is_ascii_digit());
        let number = if word { 0 } else { text.parse().ok()? };
        Some(Identifier { word, number, text })
    };
    part.split('.').map(identifier).collect()
}

/// Compares two module versions as Bazel does (`bzlmod/Version.java`):
/// `RELEASE[-PRERELEASE][+BUILD]`, where a prerelease is below its
/// release, the build part is dropped and the empty version (a
/// non-registry override) is above everything. `None` when either side is
/// not a version Bazel accepts.
///
/// It is looser than SemVer: `1.7.1.bcr.1` is above `1.7.1`, and
/// `1.5.0-rc10` is below `1.5.0-rc9` because `rc10` is not a number.
pub fn module_version_cmp(a: &str, b: &str) -> Option<Ordering> {
    type Key<'a> = (bool, Vec<Identifier<'a>>, bool, Vec<Identifier<'a>>);
    fn key(version: &str) -> Option<Key<'_>> {
        if version.is_empty() {
            return Some((true, Vec::new(), true, Vec::new()));
        }
        let version = match version.split_once('+') {
            Some((head, build)) => {
                let legal = |b: u8| b.is_ascii_alphanumeric() || b == b'.' || b == b'-';
                (!build.is_empty() && build.bytes().all(legal)).then_some(head)?
            }
            None => version,
        };
        let (release, prerelease) = match version.split_once('-') {
            Some((release, prerelease)) => (release, identifiers(prerelease, true)?),
            None => (version, Vec::new()),
        };
        let release = identifiers(release, false)?;
        Some((false, release, prerelease.is_empty(), prerelease))
    }
    Some(key(a)?.cmp(&key(b)?))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;
    use crate::bazel::rc::read;
    use crate::bazel::rc::testing::Files;

    const LAUNCHER: &str = include_str!("../../tests/fixtures/bazel/rc/bazelversion.json");
    const ORDER: &str = include_str!("../../tests/fixtures/bazel/rc/version-order.json");
    const LOCKS: &str =
        include_str!("../../tests/fixtures/bazel/probe_vectors/lockfile/vectors.json");

    fn release(text: &str) -> BazelVersion {
        BazelVersion::parse(text).expect("a release")
    }

    fn exact(text: &str) -> BazelLine {
        BazelLine::of(release(text))
    }

    fn range(lo: BazelVersion, hi: BazelVersion) -> BazelLine {
        BazelLine {
            lo: Some(lo),
            hi: Some(hi),
            evidence: Vec::new(),
        }
    }

    fn major(n: u32) -> BazelLine {
        range(v(n, 0, 0), ceiling(n))
    }

    fn root(project_rel: &str, boundary_levels: usize) -> RootRef {
        RootRef {
            root: std::path::PathBuf::from("/repo/ws"),
            project_rel: project_rel.to_string(),
            boundary_levels,
        }
    }

    fn bytes(text: &str) -> FileText {
        FileText::Bytes(text.as_bytes().to_vec())
    }

    /// The line the launcher files alone give.
    fn declared_line(root: &RootRef, files: &Files) -> BazelLine {
        line(&read_declared(root, files), None, &[])
    }

    fn system(rc: &str, line: &BazelLine) -> DepSystem {
        dep_system(line, &read(&Files::of(&[(".bazelrc", rc)])).effective(line))
    }

    // ── Launcher files (probe C15) ───────────────────────────────────

    #[test]
    fn the_launcher_files_read_as_bazelisk_reads_them() {
        let fixture: Value = serde_json::from_str(LAUNCHER).expect("fixture");
        let vectors = fixture["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 35);
        for vector in vectors {
            let id = vector["id"].as_str().expect("id");
            let text = |key: &str| vector[key].as_str();
            let mut files = Files::default();
            if let Some(hex) = text("bazelversion_hex") {
                files = files.with(
                    ".bazelversion",
                    FileText::Bytes(hex::decode(hex).expect("hex")),
                );
            }
            if let Some(rc) = text("bazeliskrc") {
                files = files.with(".bazeliskrc", bytes(rc));
            }
            let mut project = "";
            match id {
                // The two cells bazelisk ran in `sub/`.
                "subdir-wins" => {
                    files = files.with("sub/.bazelversion", bytes("8.8.2\n"));
                    project = "sub";
                }
                "subdir-inherits" => project = "sub",
                // A directory of that name is skipped, not an error.
                "dir-named-bazelversion" => {
                    files = files
                        .with(".bazelversion", FileText::Unreadable)
                        .with(".bazelversion/keep", bytes(""));
                }
                "tools-bazel-wrapper" => files = files.with("tools/bazel", bytes("#!/bin/sh\n")),
                _ => {}
            }
            let declared = read_declared(&root(project, 0), &files);
            let pick = &declared.picks[0];
            assert_eq!(pick.cwd, project, "{id}");

            let (source, label) = (
                text("expected_source").unwrap(),
                text("expected_label").unwrap(),
            );
            let named = |name: &str| {
                pick.file
                    .as_deref()
                    .is_some_and(|file| file.ends_with(name))
            };
            match source {
                // The environment is machine-level and never read: the
                // files below it are what the reader sees.
                "env" => {
                    assert_eq!(text("env_USE_BAZEL_VERSION"), Some(label), "{id}");
                    assert!(named(BAZELISKRC), "{id}");
                    assert_eq!(pick.label.as_deref(), Some("8.8.2"), "{id}");
                    continue;
                }
                // No label anywhere: bazelisk falls back to `latest`.
                "fallback" => {
                    assert_eq!(
                        (pick.label.as_deref(), pick.reading),
                        (None, Label::Floating),
                        "{id}"
                    );
                    assert!(
                        declared_line(&root(project, 0), &files).is_unknown(),
                        "{id}"
                    );
                    continue;
                }
                file => assert!(named(file), "{id}: {:?}", pick.file),
            }
            assert_eq!(pick.label.as_deref(), Some(label), "{id}");

            let expected = match (text("expected_kind").unwrap(), label) {
                ("release" | "candidate", label) if label.contains('/') => Label::Floating,
                ("release" | "candidate", label) => Label::Exact(release(label)),
                ("track", label) => Label::Track {
                    major: 7,
                    candidates: label.ends_with('*'),
                },
                ("invalid", _) => Label::Invalid,
                ("latest" | "last_rc" | "rolling", _) => Label::Floating,
                (kind, _) => panic!("{id}: unmapped kind {kind}"),
            };
            assert_eq!(pick.reading, expected, "{id}");
            // What bazelisk then did: one release only for a static label.
            let ran = text("bazelisk_online").unwrap();
            let line = declared_line(&root(project, 0), &files);
            match (expected, id) {
                (Label::Exact(version), "subdir-wins") => {
                    // From `sub/` it is 8.8.2 and from the root 7.7.2.
                    assert_eq!(
                        (line.lo, line.hi),
                        (Some(v(7, 7, 2)), Some(version)),
                        "{id}"
                    );
                }
                (Label::Exact(version), "tools-bazel-wrapper") => {
                    assert_eq!(line.exact(), Some(version), "{id}");
                    assert_eq!(ran, "tools/bazel ran instead");
                    assert_eq!(declared.wrappers, ["tools/bazel"]);
                    let wrapper = LineEvidence::Wrapper("tools/bazel".to_string());
                    assert!(line.evidence.contains(&wrapper));
                }
                (Label::Exact(version), _) => {
                    assert_eq!(line.exact(), Some(version), "{id}");
                    assert_eq!(ran, format!("bazel {version}"), "{id}");
                    assert_eq!(vector["expected_static"], true, "{id}");
                }
                (Label::Track { major, .. }, _) => {
                    assert_eq!(
                        (line.lo, line.hi),
                        (Some(v(major, 0, 0)), Some(ceiling(major)))
                    );
                    assert_eq!(text("bazelisk_offline"), Some("error: needs the network"));
                }
                (Label::Invalid, _) => {
                    assert!(line.is_unknown(), "{id}");
                    assert!(ran.starts_with("error:"), "{id}: {ran}");
                }
                (Label::Floating, _) => assert!(line.is_unknown(), "{id}"),
            }
        }
    }

    #[test]
    fn labels_classify_as_bazelisk_classifies_them() {
        let exact = |text: &str| Label::Exact(release(text));
        for (label, expected) in [
            ("7.7.2", exact("7.7.2")),
            ("10.0.0rc3", exact("10.0.0rc3")),
            ("bazelbuild/7.7.2", exact("7.7.2")),
            ("007.07.2", Label::Floating),
            (
                "7.x",
                Label::Track {
                    major: 7,
                    candidates: false,
                },
            ),
            (
                "7.*",
                Label::Track {
                    major: 7,
                    candidates: true,
                },
            ),
            // Accepted by bazelisk; no release socket-patch can place.
            ("latest", Label::Floating),
            ("latest-2", Label::Floating),
            ("last_rc", Label::Floating),
            ("last_green", Label::Floating),
            ("rolling", Label::Floating),
            ("11.0.0-pre.20261028.2", Label::Floating),
            ("11.0.0-pre.20261028.2.1", Label::Floating),
            ("7.7.2-foo", Label::Floating),
            ("7.7.2rc1-foo", Label::Floating),
            ("0123456789abcdef0123456789abcdef01234567", Label::Floating),
            ("myorg/7.7.2", Label::Floating),
            ("myorg/latest", Label::Floating),
            ("99999999999.0.0", Label::Floating),
            // What bazelisk stops on.
            ("", Label::Invalid),
            ("7", Label::Invalid),
            ("7.7", Label::Invalid),
            ("7.X", Label::Invalid),
            ("v7.7.2", Label::Invalid),
            ("7.7.2 ", Label::Invalid),
            ("7.7.2rc", Label::Invalid),
            ("7.7.2-", Label::Invalid),
            ("7.7.2-a.b", Label::Invalid),
            ("latest-", Label::Invalid),
            ("11.1.0-pre.20261028.2", Label::Invalid),
            ("11.0.0-pre.2026102.2", Label::Invalid),
            ("0123456789ABCDEF0123456789abcdef01234567", Label::Invalid),
            ("myorg/v7", Label::Invalid),
            ("a/b/7.7.2", Label::Invalid),
        ] {
            assert_eq!(classify(label), expected, "{label:?}");
        }
        // One trailing CR is dropped and nothing else is trimmed.
        assert_eq!(bazelversion_label(b"7.7.2\r\n8.8.2\n"), "7.7.2");
        assert_eq!(bazelversion_label(b"7.7.2\r\r\n"), "7.7.2\r");
        assert_eq!(bazelversion_label(b"\xef\xbb\xbf7.7.2\n"), "\u{feff}7.7.2");
        assert_eq!(
            classify(&bazelversion_label(b"7.7.2\xff\n")),
            Label::Invalid
        );
        let rc = b"#USE_BAZEL_VERSION=1.0.0\n USE_BAZEL_VERSION = 7.7.2 \r\nOTHER=x\nUSE_BAZEL_VERSION=\t8.8.2\n";
        assert_eq!(
            bazeliskrc_value(rc, "USE_BAZEL_VERSION").as_deref(),
            Some("8.8.2")
        );
        assert_eq!(
            bazeliskrc_value(b"USE_BAZEL_VERSION\n", "USE_BAZEL_VERSION"),
            None
        );
    }

    #[test]
    fn the_declared_line_spans_every_directory_bazelisk_may_start_in() {
        // The nearest file from each directory between project and root.
        let files = Files::of(&[
            (".bazelversion", "7.7.2\n"),
            ("svc/api/.bazelversion", "8.8.2\n"),
        ]);
        let declared = read_declared(&root("svc/api", 1), &files);
        let picks: Vec<_> = declared
            .picks
            .iter()
            .map(|pick| {
                (
                    pick.cwd.as_str(),
                    pick.file.as_deref(),
                    pick.label.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            picks,
            [
                ("svc/api", Some("svc/api/.bazelversion"), Some("8.8.2")),
                ("svc", Some(".bazelversion"), Some("7.7.2")),
            ]
        );
        let spanned = line(&declared, None, &[]);
        assert_eq!(
            (spanned.lo, spanned.hi),
            (Some(v(7, 7, 2)), Some(v(8, 8, 2)))
        );
        assert_eq!(spanned.exact(), None);
        assert_eq!(spanned.evidence.len(), 2);
        assert!(
            matches!(&spanned.evidence[0], LineEvidence::Declared(pick) if pick.cwd == "svc/api")
        );
        assert_eq!(spanned.to_string(), "7.7.2 - 8.8.2");

        // A file above the root applies when nothing nearer exists, and
        // never when the root has its own.
        let above = Files::of(&[("../.bazelversion", "6.6.0\n")]);
        assert_eq!(
            declared_line(&root("", 1), &above).exact(),
            Some(v(6, 6, 0))
        );
        let shadowed = Files::of(&[
            ("../.bazelversion", "6.6.0\n"),
            (".bazelversion", "7.7.2\n"),
        ]);
        let declared = read_declared(&root("", 1), &shadowed);
        assert_eq!(line(&declared, None, &[]).exact(), Some(v(7, 7, 2)));
        let found: Vec<&str> = declared
            .files
            .iter()
            .map(|file| file.file.as_str())
            .collect();
        assert_eq!(found, [".bazelversion", "../.bazelversion"]);
        // Nothing past the read boundary is asked for.
        assert!(declared_line(&root("", 0), &above).is_unknown());

        // `.bazeliskrc` wins over `.bazelversion`; only the nearest one
        // is consulted, and one without the key sends bazelisk on.
        let rc = Files::of(&[
            (".bazeliskrc", "USE_BAZEL_VERSION=8.8.2\n"),
            (".bazelversion", "7.7.2\n"),
            (
                "sub/.bazeliskrc",
                "BAZELISK_BASE_URL=https://mirror.example\n",
            ),
        ]);
        assert_eq!(declared_line(&root("", 0), &rc).exact(), Some(v(8, 8, 2)));
        let from_sub = read_declared(&root("sub", 0), &rc);
        assert_eq!(from_sub.picks[0].file.as_deref(), Some(".bazelversion"));
        let spanned = line(&from_sub, None, &[]);
        assert_eq!(
            (spanned.lo, spanned.hi),
            (Some(v(7, 7, 2)), Some(v(8, 8, 2)))
        );

        // One directory with no usable label makes the whole line unknown.
        let floating = Files::of(&[
            (".bazelversion", "latest\n"),
            ("sub/.bazelversion", "7.7.2\n"),
        ]);
        assert!(declared_line(&root("sub", 0), &floating).is_unknown());
        let unreadable = Files::of(&[("sub/.bazelversion", "7.7.2\n")])
            .with(".bazeliskrc", FileText::Unreadable);
        let declared = read_declared(&root("", 0), &unreadable);
        assert_eq!(
            (
                declared.picks[0].label.as_deref(),
                declared.files[0].readable
            ),
            (None, false)
        );
        assert!(line(&declared, None, &[]).is_unknown());
        // An empty first line is `latest`, even with a version below it.
        let empty = Files::of(&[
            (".bazelversion", "\n7.7.2\n"),
            ("../.bazelversion", "7.7.2\n"),
        ]);
        assert!(declared_line(&root("", 1), &empty).is_unknown());

        assert_eq!(major(7).to_string(), "7.x");
        assert_eq!(BazelLine::unknown().to_string(), "unknown");
    }

    #[test]
    fn launcher_wrappers_are_reported_by_name() {
        let names = [
            "bazel",
            "bazel.exe",
            "bazel.ps1",
            "bazel.bat",
            "bazel.arm64",
            "bazel.x86_64.exe",
            "bazel.linux-x86_64",
            "bazel.darwin-arm64",
            "bazel.windows-arm64.exe",
        ];
        for name in names {
            assert!(is_wrapper(name), "{name}");
        }
        // `tools/bazel.rc` is the rc file no Bazel reads any more.
        for name in [
            "bazel.rc",
            "bazelisk",
            "bazel.sh",
            "bazel.linux",
            "bazel.plan9-arm64",
            "BUILD",
        ] {
            assert!(!is_wrapper(name), "{name}");
        }
        let files = Files::of(&[
            ("tools/bazel.rc", ""),
            ("tools/bazel.linux-x86_64", ""),
            ("tools/bazel/x", ""),
        ]);
        assert_eq!(
            read_declared(&root("", 0), &files).wrappers,
            ["tools/bazel.linux-x86_64"]
        );
    }

    // ── The line ladder ──────────────────────────────────────────────

    #[test]
    fn a_lock_token_narrows_an_undeclared_line_and_checks_a_declared_one() {
        let none = Declared::default();
        let of = |text: &str| read_declared(&root("", 0), &Files::of(&[(".bazelversion", text)]));
        // As of the lock: the releases that write the token.
        let by_token = line(&none, Some(13), &[]);
        assert_eq!(
            (by_token.lo, by_token.hi),
            (Some(v(7, 5, 0)), Some(ceiling(7)))
        );
        assert_eq!(
            by_token.evidence,
            [LineEvidence::LockToken {
                token: 13,
                agrees: true
            }]
        );
        // Token 3 is written by 6.4 - 6.6 and by 7.0.x: the hull.
        let three = line(&none, Some(3), &[]);
        assert_eq!(
            (three.lo, three.hi),
            (Some(v(6, 4, 0)), Some(v(7, 0, u32::MAX)))
        );
        assert_eq!(three.to_string(), "6.4.0 - 7.0");
        // A token no audited release writes is no evidence.
        assert_eq!(line(&none, Some(30), &[]), BazelLine::unknown());
        assert_eq!(line(&none, Some(2), &[]), BazelLine::unknown());

        // A declared release that writes the token stays exact.
        assert_eq!(
            line(&of("7.7.2\n"), Some(13), &[]).exact(),
            Some(v(7, 7, 2))
        );
        // One that does not is kept as its major only: the lock and the
        // launcher file disagree about which 7.x this is.
        let stale = line(&of("7.7.2\n"), Some(18), &[]);
        assert_eq!((stale.lo, stale.hi), (Some(v(7, 0, 0)), Some(ceiling(7))));
        assert!(stale.evidence.contains(&LineEvidence::LockToken {
            token: 18,
            agrees: false
        }));
        // A floating major is not narrowed by what wrote the lock last.
        let floating = line(&of("7.x\n"), Some(11), &[]);
        assert_eq!(
            (floating.lo, floating.hi),
            (Some(v(7, 0, 0)), Some(ceiling(7)))
        );
        // An unusable label leaves the lock as the evidence.
        assert_eq!(
            line(&of("latest\n"), Some(26), &[]).to_string(),
            "9.0.0 - 9.1"
        );
    }

    /// Every release the lockfile probe ran, with the token it wrote.
    #[test]
    fn every_audited_release_writes_the_token_the_table_gives_it() {
        let fixture: Value = serde_json::from_str(LOCKS).expect("fixture");
        let vectors = fixture["recorded_inputs"]["vectors"]
            .as_array()
            .expect("vectors");
        assert_eq!(vectors.len(), 17);
        let mut tokens = Vec::new();
        for vector in vectors {
            let bazel = release(vector["bazel"].as_str().expect("bazel"));
            let token = vector["lockFileVersion"].as_u64().expect("token");
            let ranges = lock_token_releases(token);
            assert!(
                ranges.iter().any(|(lo, hi)| *lo <= bazel && bazel <= *hi),
                "{bazel} wrote token {token}, the table has {ranges:?}"
            );
            // No other token claims the release, bar the two that
            // `--incompatible_use_plus_in_repo_names` selects on 7.3+.
            for (other, lo, hi) in LOCK_TOKENS {
                let variant = matches!(other, 12 | 14);
                assert!(
                    *other == token || variant || bazel < *lo || *hi < bazel,
                    "{bazel}: {other}"
                );
            }
            tokens.push(token);
        }
        tokens.dedup();
        assert_eq!(tokens, [3, 6, 11, 13, 16, 18, 24, 28, 26, 28]);
        assert_eq!(lock_token_releases(28).len(), 3);
        assert_eq!(lock_token_releases(1), [(v(6, 2, 0), v(6, 3, u32::MAX))]);
        assert!(lock_token_releases(0).is_empty());
    }

    #[test]
    fn an_api_shape_is_a_floor_only_where_nothing_is_declared() {
        let none = Declared::default();
        let shapes = [ApiShape::UseRepoRule, ApiShape::Include];
        let floored = line(&none, None, &shapes);
        assert_eq!((floored.lo, floored.hi), (Some(v(7, 2, 0)), None));
        assert_eq!(floored.to_string(), "7.2.0 or newer");
        assert_eq!(floored.evidence.len(), 2);
        // Inside the lock's range the floor raises its bottom; above it
        // the lock is older than the workspace and proves no top.
        let inside = line(&none, Some(3), &[ApiShape::UseRepoRule]);
        assert_eq!(
            (inside.lo, inside.hi),
            (Some(v(7, 0, 0)), Some(v(7, 0, u32::MAX)))
        );
        let above = line(&none, Some(3), &[ApiShape::OverrideRepo]);
        assert_eq!((above.lo, above.hi), (Some(v(7, 4, 0)), None));
        // A declared release is what bazelisk runs, whatever the files use.
        let declared = read_declared(&root("", 0), &Files::of(&[(".bazelversion", "6.6.0\n")]));
        assert_eq!(line(&declared, None, &shapes).exact(), Some(v(6, 6, 0)));
        for (shape, since) in [
            (ApiShape::UseRepoRule, "7.0.0"),
            (ApiShape::EnableWorkspaceFlag, "7.1.0"),
            (ApiShape::Include, "7.2.0"),
            (ApiShape::LockfileModeRefresh, "7.2.0"),
            (ApiShape::OverrideRepo, "7.4.0"),
        ] {
            assert_eq!(shape.since(), release(since), "{}", shape.what());
        }
    }

    #[test]
    fn a_candidate_orders_below_its_release() {
        let ordered = [
            "6.6.0",
            "7.0.0rc1",
            "7.0.0rc2",
            "7.0.0",
            "7.0.1",
            "7.10.0",
            "10.0.0rc3",
            "10.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(release(pair[0]) < release(pair[1]), "{pair:?}");
        }
        assert!(release("7.99.99") < ceiling(7) && ceiling(7) < release("8.0.0rc1"));
        // A threshold is not met by a candidate of it.
        assert_eq!(exact("7.2.0rc1").at_least(v(7, 2, 0)), Tri::No);
        assert_eq!(exact("7.2.0").at_least(v(7, 2, 0)), Tri::Yes);
        assert_eq!(major(7).at_least(v(7, 2, 0)), Tri::Maybe);
        assert_eq!(BazelLine::unknown().at_least(v(7, 2, 0)), Tri::Maybe);
        for text in ["7.7.2", "10.0.0rc3", "0.29.1"] {
            assert_eq!(release(text).to_string(), text);
        }
        for bad in [
            "7.7",
            "7.7.2.1",
            "7.7.x",
            "7.7.2rc",
            "rc1",
            "7.-1.2",
            " 7.7.2",
            "7.7.2-rc1",
        ] {
            assert_eq!(BazelVersion::parse(bad), None, "{bad}");
        }
    }

    // ── Tiers and defaults ───────────────────────────────────────────

    #[test]
    fn every_row_of_the_tier_table() {
        use DeclSystem::{Bzlmod, Workspace};
        let refused = |why| Tier::Refused(why);
        for (line, decl, expected) in [
            (exact("4.2.4"), Workspace, refused(TierRefusal::TooOld)),
            (exact("4.2.4"), Bzlmod, refused(TierRefusal::TooOld)),
            (exact("5.4.1"), Workspace, Tier::Legacy),
            (
                exact("5.4.1"),
                Bzlmod,
                refused(TierRefusal::ExperimentalBzlmod),
            ),
            (exact("6.6.0"), Workspace, Tier::Legacy),
            (exact("6.6.0"), Bzlmod, Tier::Legacy),
            (exact("7.0.2"), Bzlmod, Tier::Beta),
            (exact("7.1.2"), Bzlmod, Tier::Beta),
            (exact("7.7.2"), Workspace, Tier::Beta),
            (exact("8.8.2"), Workspace, Tier::Beta),
            (exact("7.2.0"), Bzlmod, Tier::Supported),
            (exact("7.7.2"), Bzlmod, Tier::Supported),
            (exact("8.8.2"), Bzlmod, Tier::Supported),
            (exact("9.3.2"), Bzlmod, Tier::Supported),
            (exact("10.0.0rc3"), Bzlmod, Tier::Beta),
            (exact("10.0.0"), Bzlmod, Tier::Beta),
            // WORKSPACE is gone from 9.
            (
                exact("9.3.2"),
                Workspace,
                refused(TierRefusal::WorkspaceRemoved),
            ),
            // Newer than audited: as the newest audited line.
            (exact("9.4.0"), Bzlmod, Tier::Supported),
            (exact("12.0.0"), Bzlmod, Tier::Beta),
            // Unknown: MODULE.bazel hubs as the newest audited release;
            // a WORKSPACE hub cannot be placed at all.
            (BazelLine::unknown(), Bzlmod, Tier::Supported),
            (
                BazelLine::unknown(),
                Workspace,
                refused(TierRefusal::LineUnknown),
            ),
            // A range has the weakest tier of what it may run.
            (major(7), Bzlmod, Tier::Beta),
            (major(8), Bzlmod, Tier::Supported),
            (range(v(7, 2, 0), ceiling(9)), Bzlmod, Tier::Supported),
            (range(v(6, 4, 0), v(7, 0, u32::MAX)), Bzlmod, Tier::Legacy),
            (
                range(v(5, 4, 1), v(7, 7, 2)),
                Bzlmod,
                refused(TierRefusal::ExperimentalBzlmod),
            ),
            (range(v(8, 8, 0), ceiling(10)), Bzlmod, Tier::Beta),
            (
                range(v(8, 0, 0), ceiling(9)),
                Workspace,
                refused(TierRefusal::WorkspaceRemoved),
            ),
            // A candidate is never Supported.
            (exact("8.0.0rc1"), Bzlmod, Tier::Beta),
        ] {
            assert_eq!(tier(&line, decl), expected, "Bazel {line}, {decl:?}");
        }

        // The advisory of a line no probe ran.
        for audited in NEWEST_AUDITED {
            assert!(!BazelLine::of(audited).untested(), "{audited}");
        }
        for line in [exact("7.0.2"), range(v(7, 5, 0), v(7, 7, 2))] {
            assert!(!line.untested(), "{line}");
        }
        for line in [
            exact("8.9.0"),
            exact("10.0.0"),
            exact("11.0.0"),
            exact("4.2.4"),
            major(7),
        ] {
            assert!(line.untested(), "{line}");
        }
        assert!(BazelLine::unknown().untested());
        assert!(line(&Declared::default(), None, &[ApiShape::Include]).untested());
    }

    #[test]
    fn the_default_lockfile_mode_per_release() {
        use LockfileMode::{Off, Update};
        for (line, expected) in [
            // No lock file before 6.2.0.
            (exact("5.4.1"), Some(Off)),
            (exact("6.1.2"), Some(Off)),
            (exact("6.2.1"), Some(Off)),
            // 6.3.0 alone shipped `update`.
            (exact("6.3.0"), Some(Update)),
            (exact("6.3.1"), Some(Off)),
            (exact("6.6.0"), Some(Off)),
            (exact("7.0.0"), Some(Update)),
            (exact("9.3.2"), Some(Update)),
            (major(7), Some(Update)),
            (range(v(6, 3, 1), ceiling(6)), Some(Off)),
            (range(v(6, 0, 0), v(6, 2, u32::MAX)), Some(Off)),
            // A 6.x range that contains 6.3.0, or reaches 7.
            (major(6), None),
            (range(v(6, 2, 0), v(6, 3, u32::MAX)), None),
            (range(v(6, 4, 0), v(7, 0, u32::MAX)), None),
            // Not bounded on both sides.
            (BazelLine::unknown(), None),
            (line(&Declared::default(), None, &[ApiShape::Include]), None),
        ] {
            assert_eq!(lockfile_mode_default(&line), expected, "Bazel {line}");
        }
    }

    // ── The dependency-system table ──────────────────────────────────

    /// The table of design 2.5: the 15 rows the hybrid probe (S7 H1)
    /// confirmed on 5.4.1, 6.6.0, 7.0.2, 7.7.2, 8.8.2, 9.3.2 and
    /// 10.0.0rc3, and the rows for flags a line does not know (C16).
    #[test]
    fn every_row_of_the_mode_table() {
        use DepSystem::{Bzlmod, Hybrid, Neither, Workspace};
        let rows: &[(&str, &str, Option<DepSystem>)] = &[
            ("5.4.1", "", Some(Workspace)),
            // Experimental Bzlmod on 5: hybrid, and refused by its tier.
            (
                "5.4.1",
                "common --experimental_enable_bzlmod\n",
                Some(Hybrid),
            ),
            (
                "5.4.1",
                "common --noexperimental_enable_bzlmod\n",
                Some(Workspace),
            ),
            ("6.6.0", "", Some(Workspace)),
            ("6.6.0", "common --enable_bzlmod\n", Some(Hybrid)),
            (
                "6.6.0",
                "common --experimental_enable_bzlmod\n",
                Some(Hybrid),
            ),
            ("7.0.2", "", Some(Hybrid)),
            ("7.0.2", "common --noenable_bzlmod\n", Some(Workspace)),
            ("7.1.0", "", Some(Hybrid)),
            ("7.7.2", "", Some(Hybrid)),
            ("7.7.2", "common --noenable_workspace\n", Some(Bzlmod)),
            ("7.7.2", "common --noenable_bzlmod\n", Some(Workspace)),
            (
                "7.7.2",
                "common --noenable_bzlmod --noenable_workspace\n",
                Some(Neither),
            ),
            ("8.8.2", "", Some(Bzlmod)),
            ("8.8.2", "common --enable_workspace\n", Some(Hybrid)),
            (
                "8.8.2",
                "common --noenable_bzlmod --enable_workspace\n",
                Some(Workspace),
            ),
            // Both flags are accepted no-ops from 9.
            ("9.3.2", "", Some(Bzlmod)),
            ("9.3.2", "common --enable_workspace\n", Some(Bzlmod)),
            ("9.3.2", "common --noenable_bzlmod\n", Some(Bzlmod)),
            (
                "9.3.2",
                "common --noenable_bzlmod --enable_workspace\n",
                Some(Bzlmod),
            ),
            (
                "10.0.0rc3",
                "common --noenable_bzlmod --enable_workspace\n",
                Some(Bzlmod),
            ),
            // Every Bazel command exits 2 on a flag the line lacks...
            ("5.4.1", "common --enable_bzlmod\n", None),
            ("5.4.1", "common --noenable_bzlmod\n", None),
            ("5.4.1", "common --enable_workspace\n", None),
            ("6.6.0", "common --enable_workspace\n", None),
            ("6.6.0", "common --noenable_workspace\n", None),
            ("7.0.2", "common --noenable_workspace\n", None),
            // ...also when only a config passes it,
            ("7.0.2", "common:ws --enable_workspace\n", None),
            ("5.4.1", "common:new --enable_bzlmod\n", None),
            // ...and Bazel 8 stops with both systems off.
            ("8.8.2", "common --noenable_bzlmod\n", None),
            (
                "8.8.2",
                "common --noenable_bzlmod --noenable_workspace\n",
                None,
            ),
        ];
        for (bazel, rc, expected) in rows {
            let found = system(rc, &exact(bazel));
            match expected {
                Some(expected) => assert_eq!(&found, expected, "Bazel {bazel}: {rc:?}"),
                None => {
                    // The reason names the rc line.
                    let named = matches!(&found, DepSystem::Unknown { why } if why.starts_with(".bazelrc:1: "));
                    assert!(named, "Bazel {bazel}: {rc:?} gave {found:?}");
                }
            }
        }
        assert_eq!(
            tier(&exact("5.4.1"), DeclSystem::Bzlmod),
            Tier::Refused(TierRefusal::ExperimentalBzlmod)
        );
        // A candidate has its release's defaults.
        assert_eq!(system("", &exact("8.0.0rc1")), Bzlmod);
        assert_eq!(system("", &exact("4.2.4")), Workspace);
        assert!(matches!(
            system("common --enable_bzlmod=maybe\n", &exact("7.7.2")),
            DepSystem::Unknown { .. }
        ));
    }

    #[test]
    fn an_unknown_line_gives_every_system_its_releases_could_run() {
        use DepSystem::{Bzlmod, Hybrid, Workspace};
        let systems = |rc: &str, line: &BazelLine| match system(rc, line) {
            DepSystem::DualMode { systems, why } => (systems, why),
            other => panic!("{other:?}"),
        };
        let (all, why) = systems("", &BazelLine::unknown());
        assert_eq!(all, [Workspace, Hybrid, Bzlmod]);
        assert!(why.contains("spans releases"), "{why}");
        // Floating majors: 7.x is hybrid throughout, 8.x - 9.x is not one
        // system once `--enable_workspace` is passed.
        assert_eq!(system("", &major(7)), Hybrid);
        assert_eq!(system("", &major(8)), Bzlmod);
        assert_eq!(system("", &range(v(8, 0, 0), ceiling(9))), Bzlmod);
        let (split, _) = systems(
            "common --enable_workspace\n",
            &range(v(8, 0, 0), ceiling(9)),
        );
        assert_eq!(split, [Hybrid, Bzlmod]);
        // The token-3 range covers 6.4 - 6.6 and 7.0.x.
        let (three, _) = systems("", &range(v(6, 4, 0), v(7, 0, u32::MAX)));
        assert_eq!(three, [Workspace, Hybrid]);
        // On a floating 7.x the flag is fatal on 7.0.x.
        assert!(matches!(
            system("common --noenable_workspace\n", &major(7)),
            DepSystem::Unknown { .. }
        ));
    }

    #[test]
    fn a_flag_under_a_config_or_on_one_chain_is_dual_mode() {
        use DepSystem::{Bzlmod, Hybrid, Workspace};
        let seven = exact("7.7.2");
        let dual = |rc: &str, line: &BazelLine| match system(rc, line) {
            DepSystem::DualMode { systems, why } => (systems, why),
            other => panic!("{rc:?}: {other:?}"),
        };
        // The corpus shape: a config that switches Bzlmod off.
        let (systems, why) = dual(
            "common:legacy --noenable_bzlmod --enable_workspace\n",
            &seven,
        );
        assert_eq!(systems, [Hybrid, Workspace]);
        assert!(why.contains("under a config"), "{why}");
        // A config that repeats the default changes nothing.
        assert_eq!(
            system("common:ci --enable_bzlmod --enable_workspace\n", &seven),
            Hybrid
        );
        assert_eq!(
            system("common:ci --noenable_workspace\n", &exact("8.8.2")),
            Bzlmod
        );
        // `build` lines do not reach `query` or `mod`: the repin command
        // `bazel mod deps` would run under another system.
        let (systems, why) = dual("build --noenable_bzlmod\n", &seven);
        assert_eq!(systems, [Workspace, Hybrid]);
        assert!(why.contains("`bazel query`"), "{why}");
        let (systems, _) = dual("test --noenable_workspace\n", &seven);
        assert_eq!(systems, [Hybrid, Bzlmod]);
        // On 9 the flags do nothing, so nothing is dual.
        assert_eq!(
            system(
                "build --noenable_bzlmod\ncommon:x --enable_workspace\n",
                &exact("9.3.2")
            ),
            Bzlmod
        );

        // An import Bazel loads and nobody can read may flip either
        // flag; an optional one is the documented blind spot.
        let hard = system("import %workspace%/missing.rc\n", &seven);
        assert!(
            matches!(&hard, DepSystem::Unknown { why } if why.starts_with("missing.rc ")),
            "{hard:?}"
        );
        assert_eq!(
            system("try-import %workspace%/user.bazelrc\n", &seven),
            Hybrid
        );
        assert_eq!(
            system("import %workspace%/missing.rc\n", &exact("9.3.2")),
            Bzlmod
        );
        // A release-dependent line: `always` is read from 6.3.0.
        let (systems, _) = dual("always --enable_bzlmod\n", &major(6));
        assert_eq!(systems, [Workspace, Hybrid]);
    }

    #[test]
    fn each_system_evaluates_its_own_workspace_file() {
        let all = BoundaryFiles {
            module_bazel: true,
            repo_bazel: false,
            workspace_bazel: true,
            workspace: true,
            workspace_bzlmod: true,
        };
        let plain = BoundaryFiles {
            workspace_bazel: false,
            workspace_bzlmod: false,
            ..all
        };
        let none = BoundaryFiles {
            workspace: false,
            ..plain
        };
        // `WORKSPACE.bzlmod` replaces the others whenever Bzlmod is on,
        // and `WORKSPACE.bazel` outranks `WORKSPACE`.
        assert_eq!(
            DepSystem::Hybrid.workspace_file(&all),
            Some("WORKSPACE.bzlmod")
        );
        assert_eq!(
            DepSystem::Workspace.workspace_file(&all),
            Some("WORKSPACE.bazel")
        );
        assert_eq!(DepSystem::Hybrid.workspace_file(&plain), Some("WORKSPACE"));
        assert_eq!(
            DepSystem::Workspace.workspace_file(&plain),
            Some("WORKSPACE")
        );
        assert_eq!(DepSystem::Workspace.workspace_file(&none), None);
        let dual = DepSystem::DualMode {
            systems: Vec::new(),
            why: String::new(),
        };
        for dead in [DepSystem::Bzlmod, DepSystem::Neither, dual] {
            assert_eq!(dead.workspace_file(&all), None, "{dead:?}");
        }
    }

    #[test]
    fn no_label_makes_the_version_readers_panic() {
        let mut rng = crate::test_rng::Rng::new(0xbe);
        let seeds = [
            "7.7.2",
            "10.0.0rc3",
            "7.x",
            "11.0.0-pre.20261028.2",
            "fork/7.7.2",
            "1.2.3-rc.1+b",
        ];
        for _ in 0..4000 {
            let mut text: Vec<u8> = seeds[rng.below(seeds.len())].as_bytes().to_vec();
            for _ in 0..rng.below(4) {
                let at = rng.below(text.len() + 1);
                match rng.below(3) {
                    0 => text.truncate(at),
                    1 => text.insert(
                        at,
                        *b".-+/rc0x*\r\n \xff".get(rng.below(13)).expect("in range"),
                    ),
                    _ => text.extend_from_within(..at),
                }
            }
            let label = bazelversion_label(&text);
            let _ = (
                classify(&label),
                BazelVersion::parse(&label),
                bazeliskrc_value(&text, "7"),
            );
            let _ = module_version_cmp(&label, "1.0.0");
            let files = Files::default().with(".bazelversion", FileText::Bytes(text));
            let line = declared_line(&root("", 0), &files);
            let _ = (
                line.to_string(),
                tier(&line, DeclSystem::Bzlmod),
                lockfile_mode_default(&line),
            );
            let _ = system("common:x --enable_workspace\n", &line);
        }
    }

    // ── Module versions (probe L7 gv11) ──────────────────────────────

    #[test]
    fn module_versions_order_as_bazel_selects_them() {
        let fixture: Value = serde_json::from_str(ORDER).expect("fixture");
        let pairs = fixture["pairs"].as_array().expect("pairs");
        let mut checked = 0;
        for pair in pairs {
            let (a, b) = (pair["a"].as_str().unwrap(), pair["b"].as_str().unwrap());
            let Some(selected) = pair["selected"].as_str() else {
                // The `+build` pair: Bazel releases disagree about it.
                assert!(pair["skip"].is_string());
                continue;
            };
            let higher = match module_version_cmp(a, b).expect("both parse") {
                Ordering::Less => b,
                Ordering::Greater => a,
                Ordering::Equal => panic!("{a} and {b} compare equal"),
            };
            assert_eq!(higher, selected, "{a} vs {b}");
            assert_eq!(
                module_version_cmp(b, a),
                module_version_cmp(a, b).map(Ordering::reverse)
            );
            checked += 1;
        }
        assert_eq!((checked, pairs.len()), (27, 28));

        use Ordering::{Equal, Greater, Less};
        let rows: BTreeMap<(&str, &str), Option<Ordering>> = [
            // The empty version is a non-registry override: above all.
            (("", "999.0"), Some(Greater)),
            (("", ""), Some(Equal)),
            // The build part is dropped.
            (("1.0.0+build.5", "1.0.0"), Some(Equal)),
            (("1.0.0-rc1+x", "1.0.0-rc1"), Some(Equal)),
            (("01", "1"), Some(Less)),
            (("1.0-a-b", "1.0-a"), Some(Greater)),
            (("18446744073709551615", "1"), Some(Greater)),
            // Not versions.
            (("1..2", "1"), None),
            (("1.0-", "1"), None),
            (("1.0+", "1"), None),
            (("1_0", "1"), None),
            (("1.0-a+b+c", "1"), None),
            (("-rc1", "1"), None),
            (("18446744073709551616", "1"), None),
            (("1.0", "v1,0"), None),
        ]
        .into();
        for ((a, b), expected) in rows {
            assert_eq!(module_version_cmp(a, b), expected, "{a:?} vs {b:?}");
        }
    }
}
