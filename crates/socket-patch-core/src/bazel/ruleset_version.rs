//! The version of a ruleset module that Bazel resolves, as a range (design
//! 2.8).
//!
//! A root `bazel_dep` is a lower bound: Bazel selects the highest version
//! any module of the graph asks for, and the same `MODULE.bazel` resolves
//! differently under another Bazel release. So the answer is `{lo, hi}`
//! with the evidence behind each side, and a gate passes only on proof:
//! [`VersionVerdict::at_least`] for a lower-bound gate,
//! [`VersionVerdict::below`] for an upper-bound one. A missing side is
//! "unknown", never "new enough".
//!
//! The one rule that is not obvious: a family-B lock never raises `lo`. It
//! has no hash of the root file, so after a root `bazel_dep` is deleted it
//! still names the old, higher version and passes every sanity check,
//! while Bazel selects the lower one. An upper bound survives that edit; a
//! lower bound does not.
//!
//! A lock is evidence only while Bazel would use it as it stands. A lock
//! another release wrote, one written under other flags or for another
//! override target, and any lock under `--lockfile_mode=off` is a
//! leftover: Bazel resolves again, with its own builtin modules, and may
//! select less or more than the lock names.
//!
//! This file reads no workspace file. The caller folds `MODULE.bazel`, the
//! rc flags and the Bazel line into [`Evidence`], and for a `WORKSPACE`
//! hub hands [`workspace_hub`] the verdict of the one function that knows
//! which `WORKSPACE` definition Bazel builds.

use std::cmp::Ordering;

use super::module_lock::{FamilyA, FamilyB, ModuleLock};
use super::rc::LockfileMode;
use super::version::{lock_token_releases, lockfile_mode_default, BazelLine, BazelVersion};

/// `{lo, hi}`, each side with its own evidence. `None` is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionVerdict {
    pub lo: Option<Bound>,
    pub hi: Option<Bound>,
    /// Why there is no lower bound, for the refusal that names the remedy.
    pub unproven: Option<Unproven>,
}

/// One side of the range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub version: String,
    pub source: Source,
}

/// The evidence a bound rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `single_version_override(version = ...)`.
    SingleVersionOverride,
    /// A family-A lock whose `moduleFileHash` matches the root file.
    FreshLock,
    /// `--check_direct_dependencies=error`: Bazel fails unless the
    /// declared version is the resolved one.
    DirectDependencyCheck,
    /// A family-B `source.json` key, as of the lock. Upper bound only.
    Lock,
    /// The root `bazel_dep` version.
    Declared,
    /// The version Bazel's builtin `bazel_tools` module requires.
    BazelToolsFloor,
    /// An API the root file uses exists only from this version.
    ApiShape,
    /// The literal `WORKSPACE` definition Bazel builds.
    WorkspaceLiteral,
}

/// Why a verdict has no lower bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unproven {
    /// `archive_override`, `git_override`, `local_path_override` or
    /// `--override_module`: no committed file names the version.
    NonRegistryOverride,
    /// `multiple_version_override`, or an override whose version cannot
    /// be read.
    UnreadableOverride,
    /// No root `bazel_dep` gives a version this reader can fold, or the
    /// one that does is a dev dependency `--ignore_dev_dependency` drops.
    NotDeclared,
    /// The `WORKSPACE` definition is not provably the one Bazel builds,
    /// or its version is not a literal.
    WorkspaceDefinition,
    /// `WORKSPACE` files are not evaluated in this workspace.
    WorkspaceNotEvaluated,
}

impl VersionVerdict {
    pub fn unknown(why: Unproven) -> Self {
        Self {
            lo: None,
            hi: None,
            unproven: Some(why),
        }
    }

    fn exact(version: &str, source: Source) -> Self {
        let bound = Bound {
            version: version.to_string(),
            source,
        };
        Self {
            lo: Some(bound.clone()),
            hi: Some(bound),
            unproven: None,
        }
    }

    /// Whether the version is proven to be `threshold` or later. A
    /// prerelease of the threshold is below it.
    pub fn at_least(&self, threshold: &str) -> bool {
        let lo = self.lo.as_ref();
        lo.and_then(|lo| compare(&lo.version, threshold))
            .is_some_and(Ordering::is_ge)
    }

    /// Whether the version is proven to be earlier than `threshold`.
    pub fn below(&self, threshold: &str) -> bool {
        let hi = self.hi.as_ref();
        hi.and_then(|hi| compare(&hi.version, threshold))
            .is_some_and(Ordering::is_lt)
    }

    /// The range that holds whichever of two verdicts is the true one. A
    /// side either verdict does not know is unknown.
    pub fn union(&self, other: &Self) -> Self {
        // `b` when it lies further out than `a`, in the direction given.
        let outer = |a: &Option<Bound>, b: &Option<Bound>, further: Ordering| {
            let (a, b) = (a.as_ref()?, b.as_ref()?);
            let b_is_further = compare(&b.version, &a.version)? == further;
            Some(if b_is_further { b } else { a }.clone())
        };
        let lo = outer(&self.lo, &other.lo, Ordering::Less);
        let unknown = self.unproven.or(other.unproven);
        Self {
            unproven: match lo {
                Some(_) => None,
                None => unknown.or(Some(Unproven::NotDeclared)),
            },
            lo,
            hi: outer(&self.hi, &other.hi, Ordering::Greater),
        }
    }
}

/// One root `bazel_dep`, from the root file or an `include()`d segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDep {
    pub name: String,
    /// `None` when the version is absent or not a literal.
    pub version: Option<String>,
    pub dev_dependency: bool,
}

/// One override in force on a module: a root declaration, or a tracked
/// `--override_module` flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOverride {
    pub module: String,
    pub kind: OverrideKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideKind {
    /// `archive_override`, `git_override`, `local_path_override`,
    /// `--override_module`.
    NonRegistry,
    /// `single_version_override(version = ...)`.
    Pinned(String),
    /// `single_version_override` with only patches or a registry:
    /// ordinary selection decides the version.
    PatchOnly,
    /// `multiple_version_override`, or a version that is not a literal.
    Unreadable,
}

/// A Bazel release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Release(pub u32, pub u32, pub u32);

/// Every release the workspace's Bazel can be, both ends included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSpan {
    pub lo: Release,
    pub hi: Release,
    /// An end is a release candidate or another prerelease. Their builtin
    /// modules differ from the final release's (8.0.0rc1 required
    /// rules_python 0.36.0, 8.0.0 requires 0.40.0), so no floor applies.
    pub prerelease: bool,
}

impl LineSpan {
    pub fn exact(release: Release) -> Self {
        Self {
            lo: release,
            hi: release,
            prerelease: false,
        }
    }
}

impl Release {
    fn version(self) -> BazelVersion {
        BazelVersion::new(self.0, self.1, self.2)
    }
}

/// `--lockfile_mode` as the tracked rc lines set it, over every command
/// chain and named config. Under `off` Bazel neither reads nor writes
/// `MODULE.bazel.lock`, and a lock in the tree is a leftover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileFlag {
    /// Every reading sets `update`, `refresh` or `error`.
    On,
    /// No reading sets `off` and some reading sets nothing: the default
    /// of the release decides.
    Unset,
    /// `off` is set or possible on some reading, or a reading cannot be
    /// made.
    MaybeOff,
}

/// `--registry` as the tracked rc lines set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registries<'a> {
    /// No line sets the flag: Bazel uses its default list.
    Default,
    /// Every reading gives this list, in this order and as written.
    Set(&'a [String]),
    /// The readings differ, or one cannot be made.
    Unknown,
}

/// From this release `--ignore_dev_dependency` also drops every root
/// override, of every kind and with no message.
const OVERRIDES_DROPPED_FROM: Release = Release(7, 4, 0);
/// The last release that reads and writes a family-A lock.
const LAST_FAMILY_A: Release = Release(7, 1, 2);
/// The one registry of Bazel's default list, as a lock records it.
const DEFAULT_REGISTRY: &str = "https://bcr.bazel.build/";

/// The final releases that read and write a family-A lock.
struct GraphWriter {
    first: Release,
    last: Release,
    /// The `lockFileVersion` these releases write. A release treats a
    /// lock with any other value as empty.
    lock_file_version: u64,
    /// The SHA-256 of `src/MODULE.tools`, which is the `MODULE.bazel` of
    /// the builtin `bazel_tools` module: the one `localOverrideHashes`
    /// member of a root without a `local_path_override`. It changes
    /// whenever the builtin dependencies do, so it tells 6.4 - 6.6 from
    /// 7.0, which write the same `lockFileVersion`.
    module_tools_sha256: &'static str,
}

/// Read at every final tag from 6.2.0 to 7.1.2. The fixture locks of
/// 6.5.0, 6.6.0, 7.0.2 and 7.1.2 hold the last three hashes.
const GRAPH_WRITERS: &[GraphWriter] = &[
    GraphWriter {
        first: Release(6, 2, 0),
        last: Release(6, 3, 2),
        lock_file_version: 1,
        module_tools_sha256: "11c49407fdc54b48d69dcd4478440118124b9cd51b2dca5947a6414a585964a1",
    },
    GraphWriter {
        first: Release(6, 4, 0),
        last: Release(6, 6, 0),
        lock_file_version: 3,
        module_tools_sha256: "0cc38516259ab87144b82461dd874e139f093d8e356667c3a3c5a52441ac448f",
    },
    GraphWriter {
        first: Release(7, 0, 0),
        last: Release(7, 0, 2),
        lock_file_version: 3,
        module_tools_sha256: "922ea6752dc9105de5af957f7a99a6933c0a6a712d23df6aad16a9c399f7e787",
    },
    GraphWriter {
        first: Release(7, 1, 0),
        last: Release(7, 1, 2),
        lock_file_version: 6,
        module_tools_sha256: "1ae69322ac3823527337acf02016e8ee95813d8d356f47060255b8956fa642f0",
    },
];

/// What the committed files say about one module.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// The module that hosts the hub's extension, by its module name
    /// (the caller resolves a `repo_name`).
    pub module: &'a str,
    /// Every root `bazel_dep`, dev dependencies included: the lock's
    /// freshness check needs all of them.
    pub deps: &'a [RootDep],
    /// Every root override, on any module.
    pub overrides: &'a [RootOverride],
    /// `--ignore_dev_dependency` is set, or possible under a named
    /// config, on any command chain.
    pub ignore_dev_dependency: bool,
    /// `--check_direct_dependencies=error` is set unconditionally on the
    /// `build` chain.
    pub check_direct_dependencies_error: bool,
    /// `None` = the Bazel line is unknown.
    pub line: Option<LineSpan>,
    /// Whether Bazel reads the lock at all.
    pub lockfile: LockfileFlag,
    /// The registries Bazel resolves from. A family-A lock records the
    /// list it was written under and is reused only under the same one.
    pub registries: Registries<'a>,
    pub lock: &'a ModuleLock,
    /// The root `MODULE.bazel` as found, before any edit of it.
    pub module_file: Option<&'a [u8]>,
    /// The first version that has an API the root file uses, when the
    /// hub's recognizer proves one.
    pub api_floor: Option<&'a str>,
}

/// The evidence ladder for a module declared under Bzlmod. The first row
/// that applies decides, and the last two each give one side:
///
/// 1. a non-registry override: unknown;
/// 2. `single_version_override(version = v)`: exactly `v`;
/// 3. a family-A lock that Bazel reuses: exactly the version of its
///    graph key;
/// 4. `--check_direct_dependencies=error`: exactly the declared version;
/// 5. a family-B lock that passes its sanity checks: `hi` only;
/// 6. the root `bazel_dep`: `lo` only, raised to the floors.
///
/// Rows 3 and 5 need a lock Bazel reads: neither applies when
/// `--lockfile_mode=off` is set or possible.
///
/// Under `--ignore_dev_dependency`, on a line not proven older than
/// 7.4.0, Bazel resolves with the root overrides on one command chain and
/// without them on another. The verdict is then the union of both
/// ladders.
pub fn resolve(evidence: &Evidence<'_>) -> VersionVerdict {
    let proven_before = |release| evidence.line.is_some_and(|line| line.hi < release);
    let dropped = evidence.ignore_dev_dependency
        && !evidence.overrides.is_empty()
        && !proven_before(OVERRIDES_DROPPED_FROM);
    if !dropped {
        return ladder(evidence, true, true);
    }
    // Bazel may resolve with the root overrides or without them, and the
    // lock was written in one of the two states: it describes neither
    // for certain, so it is no evidence in either.
    ladder(evidence, true, false).union(&ladder(evidence, false, false))
}

fn ladder(evidence: &Evidence<'_>, overrides: bool, lock: bool) -> VersionVerdict {
    // Under `off` Bazel neither reads nor writes the lock: whatever the
    // file says, it was not written for this build.
    let lock = lock && evidence.lockfile != LockfileFlag::MaybeOff;
    if overrides {
        let mut pinned: Option<&str> = None;
        let on_module = |o: &&RootOverride| o.module == evidence.module;
        for over in evidence.overrides.iter().filter(on_module) {
            match &over.kind {
                OverrideKind::NonRegistry => {
                    return VersionVerdict::unknown(Unproven::NonRegistryOverride)
                }
                OverrideKind::Pinned(version)
                    if parse(version).is_some() && pinned.is_none_or(|p| p == version) =>
                {
                    pinned = Some(version.as_str());
                }
                OverrideKind::Pinned(_) | OverrideKind::Unreadable => {
                    return VersionVerdict::unknown(Unproven::UnreadableOverride)
                }
                OverrideKind::PatchOnly => {}
            }
        }
        if let Some(version) = pinned {
            return VersionVerdict::exact(version, Source::SingleVersionOverride);
        }
    }
    if let (true, ModuleLock::FamilyA(graph)) = (lock, evidence.lock) {
        if let Some(verdict) = fresh_graph(evidence, graph) {
            return verdict;
        }
    }
    let declared = declared(evidence);
    if let (true, Some(version)) = (evidence.check_direct_dependencies_error, declared) {
        return VersionVerdict::exact(version, Source::DirectDependencyCheck);
    }
    let lo = declared.map(|version| lower_bound(evidence, version));
    let mut hi = match evidence.lock {
        ModuleLock::FamilyB(hashes) if lock => locked(evidence, hashes),
        _ => None,
    };
    // A lock that selects less than a proven lower bound was written for
    // another root file or by another Bazel: it gives nothing.
    if let (Some(lo), Some(top)) = (&lo, &hi) {
        if compare(&top.version, &lo.version).is_none_or(Ordering::is_lt) {
            hi = None;
        }
    }
    VersionVerdict {
        unproven: lo.is_none().then_some(Unproven::NotDeclared),
        lo,
        hi,
    }
}

/// The exact version from a family-A lock, when Bazel is proven to reuse
/// its graph.
///
/// Bazel 6.2.0 - 7.1.2 reuses the graph only when the lock has the
/// release's own `lockFileVersion`, `--lockfile_mode` is not `off`, and
/// the recorded `moduleFileHash`, `flags` and `localOverrideHashes` all
/// equal the current ones (`BazelDepGraphFunction.java` and
/// `BazelLockFileFunction.java`, the same condition from 6.2.0 to 7.1.2).
/// Otherwise it resolves again, and can select less than the lock names:
/// 7.1.x requires rules_python 0.22.1 where 7.0.x and 6.x require 0.4.0,
/// and a `local_path_override` target can be lowered with no edit of the
/// root file. This row raises `lo`, so each condition must be proven;
/// one that cannot be read off the committed files gives no evidence.
fn fresh_graph(evidence: &Evidence<'_>, graph: &FamilyA) -> Option<VersionVerdict> {
    // One range of releases must hold the whole line: with no pinned line
    // bazelisk runs the newest release, which does not read this lock,
    // and a prerelease has builtin modules of its own.
    let line = evidence.line.filter(|line| !line.prerelease)?;
    let holds = |writer: &&GraphWriter| writer.first <= line.lo && line.hi <= writer.last;
    let writer = GRAPH_WRITERS.iter().find(holds)?;
    if line.lo > line.hi || graph.lock_file_version != Some(writer.lock_file_version) {
        return None;
    }
    let read_by_bazel = match evidence.lockfile {
        LockfileFlag::On => true,
        LockfileFlag::Unset => reads_lock_by_default(line),
        LockfileFlag::MaybeOff => false,
    };
    let fresh = evidence
        .module_file
        .is_some_and(|file| graph.module_file_fresh(file));
    if !read_by_bazel || !fresh {
        return None;
    }

    // `flags`. The lock records the dev-dependency flag, the command-line
    // overrides and the registries it was written under.
    let flags = graph.flags.as_ref()?;
    let same_registries = match evidence.registries {
        Registries::Default => flags.registries == [DEFAULT_REGISTRY],
        Registries::Set(list) => flags.registries == list,
        Registries::Unknown => false,
    };
    let no_flag_drift = !flags.ignore_dev_dependency
        && !evidence.ignore_dev_dependency
        && flags.module_overrides.is_empty()
        && same_registries;
    // `localOverrideHashes`. With no local override in the root, the one
    // member is this release's own `bazel_tools`. The target of a local
    // override is outside what this reader sees, so one in the root, or
    // one the lock was written with, ends the proof.
    let local_overrides = graph.local_override_hashes.as_deref()?;
    let only_bazel_tools = matches!(
        local_overrides,
        [(module, hash)] if module == "bazel_tools" && hash == writer.module_tools_sha256
    );
    let non_registry = |over: &RootOverride| over.kind == OverrideKind::NonRegistry;
    if !no_flag_drift || !only_bazel_tools || evidence.overrides.iter().any(non_registry) {
        return None;
    }

    let modules: Vec<_> = graph.modules_named(evidence.module).collect();
    match modules.as_slice() {
        [] => None,
        [module] => Some(match module.version.as_deref() {
            Some(version) if parse(version).is_some() => {
                VersionVerdict::exact(version, Source::FreshLock)
            }
            Some(_) => VersionVerdict::unknown(Unproven::UnreadableOverride),
            None => VersionVerdict::unknown(Unproven::NonRegistryOverride),
        }),
        _ => Some(VersionVerdict::unknown(Unproven::UnreadableOverride)),
    }
}

/// Whether every release of the line reads the lock when no rc line sets
/// `--lockfile_mode`: the default is `off` on 6.2.x and on 6.3.1 - 6.6.0.
fn reads_lock_by_default(line: LineSpan) -> bool {
    let line = BazelLine {
        lo: Some(line.lo.version()),
        hi: Some(line.hi.version()),
        evidence: Vec::new(),
    };
    lockfile_mode_default(&line).is_some_and(|mode| mode != LockfileMode::Off)
}

/// Whether some release of the line writes `lockFileVersion` `token`.
fn written_on(token: Option<u64>, line: LineSpan) -> bool {
    let (lo, hi) = (line.lo.version(), line.hi.version());
    let ranges = token.map_or(Vec::new(), lock_token_releases);
    ranges
        .iter()
        .any(|(first, last)| *first <= hi && lo <= *last)
}

/// The upper bound from a family-B lock that passes its sanity checks. A
/// lock has no hash of the root file, so none of this is a proof: the
/// checks catch a lock written by another release, a raised or added
/// dependency and a changed override, and a lowered or removed dependency
/// can only move the selection down, which an upper bound survives.
///
/// 1. A release of the line writes the lock's `lockFileVersion`: Bazel
///    treats a lock with another value as empty and resolves with its own
///    builtin modules. 8.8.x and 9.2 - 9.3 write the same value, so the
///    lock must also select at least the rules_python that the line's
///    `bazel_tools` requires, unless the root pins rules_python.
/// 2. Every `single_version_override(version = v)`, on any module, is
///    what the lock selects: a pinned module leaves only its own keys, so
///    a raised pin shows. A non-registry override leaves no key at all
///    and an unreadable one names no version, so the lock cannot show
///    that their target is unchanged, and that target can lift any
///    module of the graph.
/// 3. Every other root `bazel_dep` was discovered at its declared version
///    and none is declared above what the lock selects.
fn locked(evidence: &Evidence<'_>, hashes: &FamilyB) -> Option<Bound> {
    // An unknown line is accepted, and so is a prerelease, whose
    // `lockFileVersion` no table holds: this row can only add an upper
    // bound.
    if let Some(line) = evidence.line {
        // A release up to 7.1.2 does not read this lock.
        if line.hi <= LAST_FAMILY_A {
            return None;
        }
        if !line.prerelease && !written_on(hashes.lock_file_version, line) {
            return None;
        }
    }

    let mut pinned: Vec<&str> = Vec::new();
    for over in evidence.overrides {
        match &over.kind {
            OverrideKind::NonRegistry | OverrideKind::Unreadable => return None,
            OverrideKind::Pinned(version) => {
                if hashes.selected(&over.module) != [version.as_str()] {
                    return None;
                }
                pinned.push(&over.module);
            }
            // Ordinary selection decides the version.
            OverrideKind::PatchOnly => {}
        }
    }
    // A pin can hold rules_python below what `bazel_tools` asks for; a
    // lock that selects less with no pin was written by another release.
    let floor = bazel_tools_floor("rules_python", evidence.line);
    if let (Some(floor), false) = (floor, pinned.contains(&"rules_python")) {
        if let [python] = hashes.selected("rules_python").as_slice() {
            if compare(python, floor).is_none_or(Ordering::is_lt) {
                return None;
            }
        }
    }

    let selected = hashes.selected(evidence.module);
    let [version] = selected.as_slice() else {
        return None;
    };
    parse(version)?;
    for dep in evidence.deps {
        // Bazel ignores the declared version of a pinned module, and the
        // pin was checked above.
        if pinned.contains(&dep.name.as_str()) {
            continue;
        }
        let declared = dep.version.as_deref()?;
        let selected = hashes.selected(&dep.name);
        let [locked] = selected.as_slice() else {
            return None;
        };
        if !hashes.discovered(&dep.name, declared) || compare(declared, locked)?.is_gt() {
            return None;
        }
    }
    Some(Bound {
        version: version.to_string(),
        source: Source::Lock,
    })
}

/// The version the root declares for the module: the lowest when it is
/// declared twice, none when any declaration cannot be read or may be
/// dropped.
fn declared<'a>(evidence: &Evidence<'a>) -> Option<&'a str> {
    let mut lowest: Option<&'a str> = None;
    for dep in evidence
        .deps
        .iter()
        .filter(|dep| dep.name == evidence.module)
    {
        let version = dep.version.as_deref()?;
        if parse(version).is_none() || (dep.dev_dependency && evidence.ignore_dev_dependency) {
            return None;
        }
        let lower = lowest.is_none_or(|low| compare(version, low).is_some_and(Ordering::is_lt));
        if lower {
            lowest = Some(version);
        }
    }
    lowest
}

/// max(declared, `bazel_tools` floor, API-shape floor).
fn lower_bound(evidence: &Evidence<'_>, declared: &str) -> Bound {
    let mut best = (declared, Source::Declared);
    let floors = [
        (
            bazel_tools_floor(evidence.module, evidence.line),
            Source::BazelToolsFloor,
        ),
        (evidence.api_floor, Source::ApiShape),
    ];
    for (floor, source) in floors {
        let higher = |floor: &&str| compare(floor, best.0).is_some_and(Ordering::is_gt);
        if let Some(floor) = floor.filter(higher) {
            best = (floor, source);
        }
    }
    Bound {
        version: best.0.to_string(),
        source: best.1,
    }
}

/// The versions Bazel's builtin `bazel_tools` module requires, per final
/// release range: `bazel_dep` lines of `src/MODULE.tools`, read at every
/// release tag from 7.0.0 to 9.3.2. Every build includes that module, so
/// its requirement is a floor for the whole graph.
const BAZEL_TOOLS_FLOORS: &[(&str, Release, Release, &str)] = &[
    ("rules_python", Release(7, 0, 0), Release(7, 0, 2), "0.4.0"),
    ("rules_python", Release(7, 1, 0), Release(7, 7, 2), "0.22.1"),
    ("rules_python", Release(8, 0, 0), Release(8, 8, 2), "0.40.0"),
    ("rules_python", Release(9, 0, 0), Release(9, 3, 2), "1.7.0"),
];

/// The lowest version of `module` that `bazel_tools` requires on any
/// release the line can be. None when the line is unknown, when an end of
/// it is a prerelease or lies outside the releases read, and for a module
/// `bazel_tools` does not depend on.
pub fn bazel_tools_floor(module: &str, line: Option<LineSpan>) -> Option<&'static str> {
    let line = line.filter(|line| !line.prerelease && line.lo <= line.hi)?;
    let rows = || BAZEL_TOOLS_FLOORS.iter().filter(|row| row.0 == module);
    let holds = |release: Release| rows().any(|row| row.1 <= release && release <= row.2);
    if !holds(line.lo) || !holds(line.hi) {
        return None;
    }
    let spanned = rows().filter(|row| row.1 <= line.hi && line.lo <= row.2);
    spanned
        .map(|row| row.3)
        .min_by(|a, b| compare(a, b).unwrap_or(Ordering::Equal))
}

/// Which dependency system evaluates a `WORKSPACE` hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubSystem {
    /// Bzlmod is off: the `WORKSPACE` definition is the ruleset.
    Workspace,
    /// Both are on: a repository name the root module can see is the
    /// Bzlmod module, also for the `WORKSPACE` file's own `load`.
    Hybrid,
    /// The flags differ between command chains or named configs, or the
    /// system is not known: either may evaluate the hub.
    DualMode,
    /// `WORKSPACE` files are not evaluated.
    Bzlmod,
}

/// The ruleset version of a hub declared in a `WORKSPACE` file.
///
/// `definition` is the version of the ruleset's own `WORKSPACE`
/// definition, and only when `workspace_file::governing` calls that
/// definition exact; Bazel builds the last definition inside the first
/// chunk that defines the name, which no other function here decides.
/// `visible_from_root` says whether the repository name the hub's `load`
/// uses is visible from the root module (a `bazel_dep` name or
/// `repo_name`, a `use_repo` name or alias, a `use_repo_rule` name), and
/// `bzlmod` is [`resolve`] for that module.
pub fn workspace_hub(
    definition: Option<&str>,
    system: HubSystem,
    visible_from_root: bool,
    bzlmod: &VersionVerdict,
) -> VersionVerdict {
    let literal = match definition.filter(|version| parse(version).is_some()) {
        Some(version) => VersionVerdict::exact(version, Source::WorkspaceLiteral),
        None => VersionVerdict::unknown(Unproven::WorkspaceDefinition),
    };
    match system {
        HubSystem::Workspace => literal,
        // The WORKSPACE archive is never fetched: the hub's rule runs
        // from the version Bzlmod selected.
        HubSystem::Hybrid if visible_from_root => bzlmod.clone(),
        HubSystem::Hybrid => literal,
        // Either system may run the hub, whatever the name's visibility.
        HubSystem::DualMode => literal.union(bzlmod),
        HubSystem::Bzlmod => VersionVerdict::unknown(Unproven::WorkspaceNotEvaluated),
    }
}

// ── Version order ────────────────────────────────────────────────────

/// One dot-separated identifier. A digits-only identifier compares as a
/// number and sorts before any other, which compares as text.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Identifier<'a> {
    Number(u64, &'a str),
    Text(&'a str),
}

/// `RELEASE[-PRERELEASE][+BUILD]` as Bazel orders it: the release, then a
/// version with a prerelease before one without, then the prerelease.
/// The build part does not take part.
type Parsed<'a> = (Vec<Identifier<'a>>, bool, Vec<Identifier<'a>>);

/// Parses a module version. None for a string Bazel rejects and for the
/// empty version, which is an override's placeholder and no version.
fn parse(version: &str) -> Option<Parsed<'_>> {
    fn identifiers<'a>(text: &'a str, hyphen: bool) -> Option<Vec<Identifier<'a>>> {
        let identifier = |part: &'a str| {
            let legal = |c: char| c.is_ascii_alphanumeric() || (hyphen && c == '-');
            if part.is_empty() || !part.chars().all(legal) {
                None
            } else if part.bytes().all(|b| b.is_ascii_digit()) {
                Some(Identifier::Number(part.parse().ok()?, part))
            } else {
                Some(Identifier::Text(part))
            }
        };
        text.split('.').map(identifier).collect()
    }
    let (version, build) = match version.split_once('+') {
        Some((version, build)) => (version, Some(build)),
        None => (version, None),
    };
    let legal = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
    if build.is_some_and(|build| build.is_empty() || !build.chars().all(legal)) {
        return None;
    }
    let (release, prerelease) = match version.split_once('-') {
        Some((release, prerelease)) => (release, identifiers(prerelease, true)?),
        None => (version, Vec::new()),
    };
    Some((
        identifiers(release, false)?,
        prerelease.is_empty(),
        prerelease,
    ))
}

/// Bazel's order of two module versions, which is not semver: `6.9` is
/// below `6.10`, `1.0` below `1.0.0`, and `1.5.0-rc10` below `1.5.0-rc9`.
/// None when either is not a version.
///
/// A port of `bzlmod/Version.java`. `bazel/version.rs` holds the same
/// order as `module_version_cmp` (design 2.1), with one difference that
/// keeps this port: there the empty version sorts above every other, and
/// here it is no version at all.
fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(parse(a)?.cmp(&parse(b)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn bytes(rel: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bazel")
            .join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn lock(rel: &str) -> ModuleLock {
        ModuleLock::parse(&bytes(rel))
    }

    fn dep(name: &str, version: &str) -> RootDep {
        RootDep {
            name: name.to_string(),
            version: Some(version.to_string()),
            dev_dependency: false,
        }
    }

    fn over(module: &str, kind: OverrideKind) -> RootOverride {
        RootOverride {
            module: module.to_string(),
            kind,
        }
    }

    fn pinned(version: &str) -> OverrideKind {
        OverrideKind::Pinned(version.to_string())
    }

    /// The `bazel_dep` lines of a fixture root file, which are literal.
    fn deps_of(rel: &str) -> Vec<RootDep> {
        let text = String::from_utf8(bytes(rel)).unwrap();
        let quoted = |line: &str, key: &str| {
            let rest = line.split_once(&format!("{key} = \""))?.1;
            Some(rest.split_once('"')?.0.to_string())
        };
        let lines = text.lines().filter(|line| line.starts_with("bazel_dep("));
        let deps = lines.map(|line| RootDep {
            name: quoted(line, "name").unwrap(),
            version: quoted(line, "version"),
            dev_dependency: false,
        });
        deps.collect()
    }

    /// No flag, no override, no lock, an unknown Bazel line.
    fn evidence<'a>(module: &'a str, deps: &'a [RootDep]) -> Evidence<'a> {
        Evidence {
            module,
            deps,
            overrides: &[],
            ignore_dev_dependency: false,
            check_direct_dependencies_error: false,
            line: None,
            lockfile: LockfileFlag::Unset,
            registries: Registries::Default,
            lock: &ModuleLock::Absent,
            module_file: None,
            api_floor: None,
        }
    }

    fn line(major: u32, minor: u32, patch: u32) -> Option<LineSpan> {
        Some(LineSpan::exact(Release(major, minor, patch)))
    }

    fn span(lo: Release, hi: Release) -> Option<LineSpan> {
        Some(LineSpan {
            lo,
            hi,
            prerelease: false,
        })
    }

    /// A floating major (`9.x`), which is also what a declared release
    /// becomes when no release of the lock's `lockFileVersion` is it.
    fn major(major: u32) -> Option<LineSpan> {
        span(Release(major, 0, 0), Release(major, u32::MAX, u32::MAX))
    }

    /// A byte-real lock of the lockfile probe: the same root file, with
    /// no `bazel_dep`, on every release.
    fn vector(bazel: &str) -> (ModuleLock, Vec<u8>) {
        let dir = format!("probe_vectors/lockfile/recorded-inputs/bazel-{bazel}/fresh");
        let module_file = bytes(&format!("{dir}/root.MODULE.bazel"));
        (lock(&format!("{dir}/root.MODULE.bazel.lock")), module_file)
    }

    type Side<'a> = Option<(&'a str, Source)>;

    fn side(bound: &Option<Bound>) -> Side<'_> {
        let bound = bound.as_ref()?;
        Some((bound.version.as_str(), bound.source))
    }

    fn sides(verdict: &VersionVerdict) -> (Side<'_>, Side<'_>) {
        (side(&verdict.lo), side(&verdict.hi))
    }

    fn exact(version: &str, source: Source) -> (Side<'_>, Side<'_>) {
        (Some((version, source)), Some((version, source)))
    }

    /// Probe L7 gv3 on 7.7.2 and 9.3.2. The lock was written for a root
    /// that also depends on rules_go 0.61.1, which lifts gazelle to
    /// 0.51.3. With that line deleted and the lock untouched Bazel selects
    /// gazelle 0.36.0, and the lock still says 0.51.3 and passes the
    /// freshness check. So the lock gives the upper bound only, and no
    /// `lo >= 0.37.0` gate passes on it.
    #[test]
    fn a_family_b_lock_never_raises_the_lower_bound() {
        for bazel in ["7.7.2", "9.3.2"] {
            let lock = lock(&format!("module_lock/gv3/{bazel}.MODULE.bazel.lock"));
            assert!(matches!(lock, ModuleLock::FamilyB(_)));
            let resolve = |root: &str| {
                let deps = deps_of(&format!("module_lock/gv3/{root}.MODULE.bazel"));
                resolve(&Evidence {
                    lock: &lock,
                    ..evidence("gazelle", &deps)
                })
            };
            let declared_and_locked = (
                Some(("0.36.0", Source::Declared)),
                Some(("0.51.3", Source::Lock)),
            );

            let lowered = resolve("lower");
            assert_eq!(deps_of("module_lock/gv3/lower.MODULE.bazel").len(), 2);
            assert_eq!(sides(&lowered), declared_and_locked, "{bazel}");
            assert!(!lowered.at_least("0.37.0"), "{bazel}");
            assert!(lowered.at_least("0.36.0") && lowered.unproven.is_none());
            // The upper bound holds in the lowered state too.
            assert!(lowered.below("0.52.0") && !lowered.below("0.51.3"));

            // With the root file the lock was written for, the verdict is
            // the same: nothing tells the two states apart.
            assert_eq!(resolve("fresh"), lowered, "{bazel}");

            // A raised dependency is declared above what the lock
            // selects: the lock gives nothing, and the declaration alone
            // carries the gate.
            let raised = resolve("raise");
            assert_eq!(sides(&raised), (Some(("0.54.0", Source::Declared)), None));
            assert!(raised.at_least("0.37.0") && !raised.below("9.0.0"));
        }
    }

    #[test]
    fn a_family_b_lock_that_fails_the_freshness_check_gives_nothing() {
        let lock = lock("module_lock/gv3/9.3.2.MODULE.bazel.lock");
        let fresh = deps_of("module_lock/gv3/fresh.MODULE.bazel");
        let hi = |deps: &[RootDep], overrides: &[RootOverride], line| {
            let evidence = Evidence {
                lock: &lock,
                overrides,
                line,
                ..evidence("gazelle", deps)
            };
            let verdict = resolve(&evidence);
            assert_eq!(sides(&verdict).0, Some(("0.36.0", Source::Declared)));
            verdict.hi.map(|bound| bound.version)
        };
        let with = |extra: RootDep| [&fresh[..], &[extra]].concat();
        let locked = Some("0.51.3".to_string());
        assert_eq!(hi(&fresh, &[], None), locked);
        assert_eq!(hi(&fresh, &[], line(9, 3, 2)), locked);

        // A dependency the lock never discovered at its declared
        // version, one it does not select, and one with no literal
        // version: the root file is not the one the lock was written for.
        assert_eq!(hi(&with(dep("rules_go", "0.60.0")), &[], None), None);
        assert_eq!(hi(&with(dep("rules_dotnet", "0.14.0")), &[], None), None);
        let unreadable = RootDep {
            version: None,
            ..dep("rules_python", "")
        };
        assert_eq!(hi(&with(unreadable.clone()), &[], None), None);
        // An override that only patches leaves the module to ordinary
        // selection: it is checked like any other.
        let patched = [over("rules_python", OverrideKind::PatchOnly)];
        assert_eq!(hi(&with(unreadable), &patched, None), None);
        let patched = [over("rules_go", OverrideKind::PatchOnly)];
        assert_eq!(hi(&fresh, &patched, None), locked);
        // Bazel 7.1.2 and earlier do not read this lock.
        assert_eq!(hi(&fresh, &[], line(7, 1, 2)), None);

        // The lock selects less than an API the root uses needs: it was
        // written for another root file.
        let newer_api = Evidence {
            lock: &lock,
            api_floor: Some("0.52.0"),
            ..evidence("gazelle", &fresh)
        };
        let verdict = resolve(&newer_api);
        assert_eq!(sides(&verdict), (Some(("0.52.0", Source::ApiShape)), None));

        // Two selected versions (`multiple_version_override`) name none.
        let synthetic = |keys: &[&str]| {
            let hash = "ab".repeat(32);
            let member =
                |key: &&str| format!(r#""https://bcr.bazel.build/modules/{key}": "{hash}""#);
            let members: Vec<String> = keys.iter().map(member).collect();
            let json = format!(r#"{{"registryFileHashes": {{{}}}}}"#, members.join(","));
            ModuleLock::parse(json.as_bytes())
        };
        let two = synthetic(&[
            "gazelle/0.36.0/MODULE.bazel",
            "gazelle/0.36.0/source.json",
            "gazelle/0.51.3/source.json",
        ]);
        let deps = [dep("gazelle", "0.36.0")];
        let verdict = resolve(&Evidence {
            lock: &two,
            ..evidence("gazelle", &deps)
        });
        assert_eq!(sides(&verdict), (Some(("0.36.0", Source::Declared)), None));

        // A version Bazel discovered and pruned has a `MODULE.bazel` key
        // above the selected one. A root that now declares it was raised
        // after the lock was written, and that can lift any module.
        let pruned = synthetic(&[
            "rules_go/0.61.1/MODULE.bazel",
            "rules_go/0.61.1/source.json",
            "gazelle/0.51.3/MODULE.bazel",
            "gazelle/0.54.0/MODULE.bazel",
            "gazelle/0.51.3/source.json",
        ]);
        let rules_go_hi = |gazelle: &str| {
            let deps = [dep("rules_go", "0.61.1"), dep("gazelle", gazelle)];
            let evidence = Evidence {
                lock: &pruned,
                ..evidence("rules_go", &deps)
            };
            resolve(&evidence).hi.map(|bound| bound.version)
        };
        assert_eq!(rules_go_hi("0.51.3"), Some("0.61.1".to_string()));
        assert_eq!(rules_go_hi("0.54.0"), None);
    }

    /// Design 2.8 and research 1.4. The lock has no hash of the root
    /// file, so an override is checked against what the lock can show. A
    /// pinned module leaves only its own keys: a raised pin shows. A
    /// non-registry override leaves no key, so its target may have
    /// changed since the lock was written, and that target can lift any
    /// module: dozens of module versions in the registry (emsdk 4.0.13
    /// for one) require rules_python 1.3.x - 1.4.x.
    #[test]
    fn an_override_the_lock_does_not_show_discards_the_lock() {
        let lock = lock("module_lock/gv3/9.3.2.MODULE.bazel.lock");
        let ModuleLock::FamilyB(hashes) = &lock else {
            panic!("not family B");
        };
        // What the lock selects. rules_cc is no root dependency.
        assert_eq!(hashes.selected("rules_go"), ["0.61.1"]);
        assert_eq!(hashes.selected("rules_cc"), ["0.2.17"]);
        assert!(!hashes.discovered("rules_go", "0.99.0"));
        let fresh = deps_of("module_lock/gv3/fresh.MODULE.bazel");
        assert!(!fresh.iter().any(|dep| dep.name == "rules_cc"));
        let verdict = |deps: &[RootDep], overrides: &[RootOverride], line| {
            resolve(&Evidence {
                lock: &lock,
                overrides,
                line,
                ..evidence("gazelle", deps)
            })
        };
        let declared = Some(("0.36.0", Source::Declared));
        let locked = Some(("0.51.3", Source::Lock));
        assert_eq!(sides(&verdict(&fresh, &[], None)), (declared, locked));

        for (module, kind) in [
            ("rules_go", pinned("0.99.0")),
            ("rules_go", OverrideKind::NonRegistry),
            ("rules_go", OverrideKind::Unreadable),
            ("rules_cc", pinned("99.0.0")),
            ("rules_cc", OverrideKind::NonRegistry),
            ("rules_cc", OverrideKind::Unreadable),
            // A pin on a module the lock does not hold at all.
            ("rules_dotnet", pinned("0.14.0")),
            ("rules_cc", pinned("not a version")),
        ] {
            for line in [None, line(9, 3, 2)] {
                let overrides = [over(module, kind.clone())];
                let verdict = verdict(&fresh, &overrides, line);
                assert_eq!(sides(&verdict), (declared, None), "{module} {kind:?}");
                // The gazelle gate of design 4.4 has no upper bound.
                assert!(!verdict.below("1.0.0-beta.1"), "{module} {kind:?}");
            }
        }

        // A pin the lock selects keeps the bound, on a root dependency
        // or not.
        for (module, version) in [("rules_go", "0.61.1"), ("rules_cc", "0.2.17")] {
            let overrides = [over(module, pinned(version))];
            let verdict = verdict(&fresh, &overrides, None);
            assert_eq!(sides(&verdict), (declared, locked), "{module}");
            assert!(verdict.below("1.0.0-beta.1"));
        }
        // Bazel ignores the declared version of a pinned module, and the
        // lock holds no key of it: the pin is what is checked.
        let mut repinned = fresh.clone();
        let rules_go = repinned.iter_mut().find(|dep| dep.name == "rules_go");
        rules_go.unwrap().version = Some("0.50.0".to_string());
        assert!(!hashes.discovered("rules_go", "0.50.0"));
        let pin = [over("rules_go", pinned("0.61.1"))];
        assert_eq!(sides(&verdict(&repinned, &pin, None)), (declared, locked));
        assert_eq!(sides(&verdict(&repinned, &[], None)), (declared, None));
    }

    /// Bazel treats a lock with another release's `lockFileVersion` as
    /// empty (`BazelLockFileFunction.java`) and resolves with its own
    /// builtin modules: the 9.x vectors select rules_jvm_external 6.7
    /// where the 7.7.2 lock says 4.4.2. Under `--lockfile_mode=off` the
    /// lock is not read at all.
    #[test]
    fn a_family_b_lock_of_another_release_gives_nothing() {
        // The root of the vectors has no `bazel_dep`: the lock is the
        // only evidence, and only of an upper bound.
        let hi = |lock: &ModuleLock, line, lockfile| {
            let verdict = resolve(&Evidence {
                lock,
                line,
                lockfile,
                ..evidence("rules_jvm_external", &[])
            });
            assert_eq!(verdict.lo, None);
            verdict.hi.map(|bound| bound.version)
        };
        let unset = LockfileFlag::Unset;
        let some = |version: &str| Some(version.to_string());

        // Lock version 13: 7.5.0 - 7.7.2.
        let (seven, _) = vector("7.7.2");
        assert_eq!(seven.lock_file_version(), Some(13));
        for line in [line(7, 7, 2), line(7, 5, 0), major(7), None] {
            assert_eq!(hi(&seven, line, unset), some("4.4.2"), "{line:?}");
        }
        for line in [
            line(9, 3, 2),
            major(9),
            major(8),
            line(7, 4, 1),
            line(7, 2, 0),
            span(Release(8, 0, 0), Release(9, 3, 2)),
        ] {
            assert_eq!(hi(&seven, line, unset), None, "{line:?}");
        }
        // With the line unknown, or the mode set on every reading, the
        // lock is what was last written; under `off` it is a leftover.
        assert_eq!(hi(&seven, line(7, 7, 2), LockfileFlag::On), some("4.4.2"));
        for line in [line(7, 7, 2), None] {
            assert_eq!(hi(&seven, line, LockfileFlag::MaybeOff), None, "{line:?}");
        }
        // The `lockFileVersion` of a prerelease is in no table.
        let candidate = LineSpan {
            prerelease: true,
            ..LineSpan::exact(Release(10, 0, 0))
        };
        assert_eq!(hi(&seven, Some(candidate), unset), some("4.4.2"));

        // Lock version 28 is written by 8.8.x and by 9.2 - 9.3. The 8.8.2
        // lock selects rules_python 0.40.0, below what `bazel_tools` of
        // 9.3.2 requires: it was not written by that release.
        let (eight, _) = vector("8.8.2");
        assert_eq!(eight.lock_file_version(), Some(28));
        let hi = |lock: &ModuleLock, line| hi(lock, line, unset);
        assert_eq!(hi(&eight, line(8, 8, 2)), some("6.3"));
        assert_eq!(hi(&eight, major(8)), some("6.3"));
        for line in [line(9, 3, 2), line(9, 2, 0), line(9, 1, 1), line(8, 7, 0)] {
            assert_eq!(hi(&eight, line), None, "{line:?}");
        }
        // A pin holds rules_python where it is, on any release: the
        // floor then says nothing about who wrote the lock.
        let pin = [over("rules_python", pinned("0.40.0"))];
        let pinned_python = resolve(&Evidence {
            lock: &eight,
            line: line(9, 3, 2),
            overrides: &pin,
            ..evidence("rules_jvm_external", &[])
        });
        assert_eq!(pinned_python.hi.map(|bound| bound.version), some("6.3"));
        let (nine, _) = vector("9.3.2");
        assert_eq!(nine.lock_file_version(), Some(28));
        assert_eq!(hi(&nine, line(9, 3, 2)), some("6.7"));
        assert_eq!(hi(&nine, major(9)), some("6.7"));
        assert_eq!(hi(&nine, line(9, 1, 1)), None);
        assert_eq!(hi(&nine, major(7)), None);

        // A lock with no `lockFileVersion` is one no release wrote.
        let bare = r#"{"registryFileHashes": {
            "https://bcr.bazel.build/modules/rules_jvm_external/6.3/MODULE.bazel": "HASH",
            "https://bcr.bazel.build/modules/rules_jvm_external/6.3/source.json": "HASH"}}"#;
        let bare = ModuleLock::parse(bare.replace("HASH", &"ab".repeat(32)).as_bytes());
        assert_eq!(hi(&bare, None), some("6.3"));
        assert_eq!(hi(&bare, line(9, 3, 2)), None);
    }

    /// Probe L7 gv1 and gv3, family A: the graph key names the selected
    /// version and `moduleFileHash` proves the lock was written for the
    /// root file as found. Any byte appended to the root file ends that.
    #[test]
    fn a_family_a_lock_is_exact_only_while_the_root_file_is_unchanged() {
        let (lock, module_file) = vector("7.1.2");
        assert!(matches!(lock, ModuleLock::FamilyA(_)));
        let edited = [&module_file[..], b"# a comment\n"].concat();
        let base = Evidence {
            lock: &lock,
            module_file: Some(&module_file),
            line: line(7, 1, 2),
            ..evidence("rules_python", &[])
        };
        // The root has no `bazel_dep` at all: the lock is the evidence.
        let exact_lock = exact("0.22.1", Source::FreshLock);
        assert_eq!(sides(&resolve(&base)), exact_lock);
        let bcr = ["https://bcr.bazel.build/".to_string()];
        for reused in [
            Evidence {
                line: span(Release(7, 1, 0), Release(7, 1, 2)),
                ..base
            },
            Evidence {
                lockfile: LockfileFlag::On,
                ..base
            },
            Evidence {
                registries: Registries::Set(&bcr),
                ..base
            },
        ] {
            assert_eq!(sides(&resolve(&reused)), exact_lock);
        }

        let unproven = VersionVerdict::unknown(Unproven::NotDeclared);
        let mirror = ["https://mirror.example/bcr/".to_string()];
        let both = [bcr[0].clone(), mirror[0].clone()];
        let local = [over("rules_cc", OverrideKind::NonRegistry)];
        for stale in [
            Evidence {
                module_file: Some(&edited),
                ..base
            },
            Evidence {
                module_file: None,
                ..base
            },
            // The lock records the flag it was written under.
            Evidence {
                ignore_dev_dependency: true,
                ..base
            },
            // Bazel 7.7.2 does not read a family-A lock, and with no
            // proof of the line nothing says Bazel reads this one.
            Evidence {
                line: line(7, 7, 2),
                ..base
            },
            Evidence {
                line: span(Release(7, 1, 2), Release(7, 7, 2)),
                ..base
            },
            Evidence { line: None, ..base },
            // 7.1.x alone writes lock version 6. Every older release
            // treats this lock as empty and resolves again: 7.0.2 and
            // 6.6.0 select rules_python 0.4.0.
            Evidence {
                line: line(7, 0, 2),
                ..base
            },
            Evidence {
                line: line(6, 6, 0),
                lockfile: LockfileFlag::On,
                ..base
            },
            Evidence {
                line: major(6),
                lockfile: LockfileFlag::On,
                ..base
            },
            Evidence {
                line: span(Release(6, 2, 0), Release(7, 1, 2)),
                ..base
            },
            Evidence {
                line: span(Release(7, 1, 2), Release(7, 1, 0)),
                ..base
            },
            // A candidate of 7.1.2 has builtin modules of its own.
            Evidence {
                line: Some(LineSpan {
                    prerelease: true,
                    ..LineSpan::exact(Release(7, 1, 2))
                }),
                ..base
            },
            // Under `off` the lock is not read.
            Evidence {
                lockfile: LockfileFlag::MaybeOff,
                ..base
            },
            // The lock was written under the default registry.
            Evidence {
                registries: Registries::Set(&mirror),
                ..base
            },
            Evidence {
                registries: Registries::Set(&both),
                ..base
            },
            Evidence {
                registries: Registries::Set(&[]),
                ..base
            },
            Evidence {
                registries: Registries::Unknown,
                ..base
            },
            // The target of a local override is not in the root file's
            // hash, and Bazel resolves again when it changes.
            Evidence {
                overrides: &local,
                ..base
            },
        ] {
            assert_eq!(resolve(&stale), unproven, "{stale:?}");
        }
        // An override that names its version in the root file is under
        // the root file's hash.
        let pin = [over("rules_cc", pinned("0.0.9"))];
        let pinned_other = Evidence {
            overrides: &pin,
            ..base
        };
        assert_eq!(sides(&resolve(&pinned_other)), exact_lock);

        // Without the lock the declaration and the floor are what is
        // left: a lower bound.
        let deps = [dep("rules_python", "0.20.0")];
        let declared = Evidence {
            module_file: Some(&edited),
            deps: &deps,
            ..base
        };
        assert_eq!(
            sides(&resolve(&declared)),
            (Some(("0.22.1", Source::BazelToolsFloor)), None)
        );

        // `<name>@_`: a module that does not come from a registry.
        let builtin = resolve(&Evidence {
            module: "bazel_tools",
            ..base
        });
        assert_eq!(
            builtin,
            VersionVerdict::unknown(Unproven::NonRegistryOverride)
        );
        // A module the graph does not hold.
        let absent = resolve(&Evidence {
            module: "gazelle",
            ..base
        });
        assert_eq!(absent, unproven);
    }

    /// Bazel 6.2.0 - 7.1.2 reuses the locked graph only for a lock of
    /// its own `lockFileVersion`, written with its own `bazel_tools`,
    /// and never under `--lockfile_mode=off`, which is the default of
    /// 6.2.x and of 6.3.1 - 6.6.0. The four vector locks were written for
    /// one root file, so only these checks tell them apart: 7.1.2
    /// selects rules_python 0.22.1 and rules_java 7.4.0 where 7.0.2
    /// selects 0.4.0 and 7.1.0, and 6.6.0 selects 0.4.0 and 5.5.1.
    #[test]
    fn a_family_a_lock_of_another_release_gives_nothing() {
        let on = LockfileFlag::On;
        let unset = LockfileFlag::Unset;
        let selected = |bazel: &str, module: &'static str, line, lockfile| {
            let (lock, module_file) = vector(bazel);
            let ModuleLock::FamilyA(graph) = &lock else {
                panic!("{bazel}: not family A");
            };
            assert!(graph.module_file_fresh(&module_file), "{bazel}");
            let verdict = resolve(&Evidence {
                lock: &lock,
                module_file: Some(&module_file),
                line,
                lockfile,
                ..evidence(module, &[])
            });
            assert_eq!(verdict.lo, verdict.hi, "{bazel}");
            let source = verdict.lo.as_ref().map(|bound| bound.source);
            assert!(source.is_none_or(|source| source == Source::FreshLock));
            verdict.lo.map(|bound| bound.version)
        };
        let some = |version: &str| Some(version.to_string());

        // Each lock on the release that wrote it.
        let python = "rules_python";
        assert_eq!(
            selected("7.1.2", python, line(7, 1, 2), unset),
            some("0.22.1")
        );
        assert_eq!(
            selected("7.0.2", python, line(7, 0, 2), unset),
            some("0.4.0")
        );
        assert_eq!(
            selected("7.0.2", "rules_java", line(7, 0, 2), unset),
            some("7.1.0")
        );
        assert_eq!(
            selected("6.6.0", "rules_java", line(6, 6, 0), on),
            some("5.5.1")
        );
        let six = span(Release(6, 4, 0), Release(6, 6, 0));
        assert_eq!(selected("6.5.0", python, six, on), some("0.4.0"));
        // 6.4.0 - 6.6.0 read the lock only when a flag says so.
        assert_eq!(selected("6.6.0", "rules_java", line(6, 6, 0), unset), None);
        assert_eq!(selected("6.5.0", python, six, unset), None);

        // Lock version 3 is written by 6.4 - 6.6 and by 7.0: the
        // `bazel_tools` hash tells the two apart.
        assert_eq!(selected("7.0.2", "rules_java", line(6, 6, 0), on), None);
        assert_eq!(selected("6.6.0", "rules_java", line(7, 0, 2), unset), None);
        // A release that writes another lock version.
        assert_eq!(selected("7.0.2", python, line(7, 1, 2), unset), None);
        assert_eq!(selected("7.1.2", python, line(7, 0, 2), unset), None);
        assert_eq!(selected("7.1.2", python, line(6, 6, 0), on), None);
        assert_eq!(selected("6.6.0", python, line(6, 3, 0), unset), None);
        // No one `bazel_tools` is right for every release of the line.
        for line in [major(6), major(7), span(Release(6, 6, 0), Release(7, 0, 2))] {
            for bazel in ["6.6.0", "7.0.2", "7.1.2"] {
                assert_eq!(selected(bazel, python, line, on), None, "{bazel} {line:?}");
            }
        }
    }

    /// The same lock with one recorded value changed: Bazel compares
    /// `flags` and `localOverrideHashes` with the running command, and a
    /// difference means it resolves again. A module that comes from a
    /// local path can be lowered with no edit of the root file.
    #[test]
    fn a_family_a_lock_written_under_other_flags_gives_nothing() {
        let (_, module_file) = vector("7.1.2");
        let dir = "probe_vectors/lockfile/recorded-inputs/bazel-7.1.2/fresh";
        let original: serde_json::Value =
            serde_json::from_slice(&bytes(&format!("{dir}/root.MODULE.bazel.lock"))).unwrap();
        type Json = serde_json::Value;
        let selected = |change: &dyn Fn(&mut Json)| {
            let mut json = original.clone();
            change(&mut json);
            let lock = ModuleLock::parse(&serde_json::to_vec(&json).unwrap());
            assert!(matches!(lock, ModuleLock::FamilyA(_)));
            let verdict = resolve(&Evidence {
                lock: &lock,
                module_file: Some(&module_file),
                line: line(7, 1, 2),
                ..evidence("rules_python", &[])
            });
            verdict.lo.map(|bound| (bound.version, bound.source))
        };
        // Written back unchanged, the lock is the evidence it was.
        let exact = Some(("0.22.1".to_string(), Source::FreshLock));
        assert_eq!(selected(&|_: &mut Json| {}), exact);
        // Members that do not move the selection may differ.
        assert_eq!(
            selected(&|json: &mut Json| json["flags"]["directDependenciesMode"] = "ERROR".into()),
            exact
        );

        let other_tools = "922ea6752dc9105de5af957f7a99a6933c0a6a712d23df6aad16a9c399f7e787";
        let changes: [(&str, &dyn Fn(&mut Json)); 12] = [
            ("the flag", &|json: &mut Json| {
                json["flags"]["ignoreDevDependency"] = true.into();
            }),
            ("--override_module", &|json: &mut Json| {
                json["flags"]["cmdModuleOverrides"]["rules_python"] = "/src/rules_python".into();
            }),
            ("a local override", &|json: &mut Json| {
                json["localOverrideHashes"]["rules_python"] = "ab".repeat(32).into();
            }),
            ("the bazel_tools of 7.0.x", &|json: &mut Json| {
                json["localOverrideHashes"]["bazel_tools"] = other_tools.into();
            }),
            ("no bazel_tools", &|json: &mut Json| {
                json["localOverrideHashes"] = serde_json::json!({});
            }),
            ("another registry", &|json: &mut Json| {
                json["flags"]["cmdRegistries"] = serde_json::json!(["https://mirror.example/"]);
            }),
            ("a second registry", &|json: &mut Json| {
                let both = ["https://bcr.bazel.build/", "https://mirror.example/"];
                json["flags"]["cmdRegistries"] = serde_json::json!(both);
            }),
            ("no flags", &|json: &mut Json| {
                json.as_object_mut().unwrap().remove("flags");
            }),
            ("flags of another shape", &|json: &mut Json| {
                json["flags"]["ignoreDevDependency"] = "false".into();
            }),
            ("no cmdModuleOverrides", &|json: &mut Json| {
                let flags = json["flags"].as_object_mut().unwrap();
                flags.remove("cmdModuleOverrides");
            }),
            ("no localOverrideHashes", &|json: &mut Json| {
                json.as_object_mut().unwrap().remove("localOverrideHashes");
            }),
            ("a hash that is no string", &|json: &mut Json| {
                json["localOverrideHashes"]["bazel_tools"] = 7.into();
            }),
        ];
        for (what, change) in changes {
            assert_eq!(selected(change), None, "{what}");
        }
    }

    /// The table of family-A writers against the byte-real locks and
    /// against the lock versions `bazel/version.rs` knows.
    #[test]
    fn the_family_a_writers_are_what_each_release_wrote() {
        for (bazel, release) in [
            ("6.5.0", Release(6, 5, 0)),
            ("6.6.0", Release(6, 6, 0)),
            ("7.0.2", Release(7, 0, 2)),
            ("7.1.2", Release(7, 1, 2)),
        ] {
            let (lock, _) = vector(bazel);
            let ModuleLock::FamilyA(graph) = lock else {
                panic!("{bazel}: not family A");
            };
            let holds = |writer: &&GraphWriter| writer.first <= release && release <= writer.last;
            let writer = GRAPH_WRITERS.iter().find(holds).unwrap();
            assert_eq!(graph.lock_file_version, Some(writer.lock_file_version));
            let tools = (
                "bazel_tools".to_string(),
                writer.module_tools_sha256.to_string(),
            );
            assert_eq!(graph.local_override_hashes, Some(vec![tools]), "{bazel}");
            let flags = graph.flags.unwrap();
            assert_eq!(flags.registries, [DEFAULT_REGISTRY]);
            assert!(flags.module_overrides.is_empty() && !flags.ignore_dev_dependency);
        }
        for pair in GRAPH_WRITERS.windows(2) {
            assert!(pair[0].last < pair[1].first);
        }
        for writer in GRAPH_WRITERS {
            assert!(writer.first <= writer.last && writer.last <= LAST_FAMILY_A);
            for release in [writer.first, writer.last] {
                let line = LineSpan::exact(release);
                assert!(written_on(Some(writer.lock_file_version), line));
                // No other family-A lock version is written there.
                for other in [1, 3, 6] {
                    let same = other == writer.lock_file_version;
                    assert_eq!(written_on(Some(other), line), same, "{release:?}");
                }
            }
        }
        assert!(!written_on(None, LineSpan::exact(Release(7, 1, 2))));
        // 6.3.0 and every release from 7.0.0 read the lock by default.
        let by_default = |release| reads_lock_by_default(LineSpan::exact(release));
        assert!(by_default(Release(6, 3, 0)) && by_default(Release(7, 0, 0)));
        assert!(!by_default(Release(6, 2, 1)) && !by_default(Release(6, 3, 1)));
        assert!(!by_default(Release(6, 6, 0)));
        let across = LineSpan {
            hi: Release(7, 0, 2),
            ..LineSpan::exact(Release(6, 6, 0))
        };
        assert!(!reads_lock_by_default(across));
    }

    /// The floor table against what Bazel selected: the 17 byte-real
    /// locks of the lockfile probe were written for a root with no
    /// `bazel_dep`, so the rules_python they select is the one
    /// `bazel_tools` requires on that release (probe L7 gv6).
    #[test]
    fn the_bazel_tools_floor_is_what_each_release_selects() {
        let index: serde_json::Value =
            serde_json::from_slice(&bytes("probe_vectors/lockfile/vectors.json")).unwrap();
        let mut floors = Vec::new();
        for vector in index["recorded_inputs"]["vectors"].as_array().unwrap() {
            let bazel = vector["bazel"].as_str().unwrap();
            let dir = vector["dir"].as_str().unwrap();
            let lock = lock(&format!(
                "probe_vectors/lockfile/{dir}/fresh/root.MODULE.bazel.lock"
            ));
            let selected = match &lock {
                ModuleLock::FamilyA(graph) => {
                    let mut modules = graph.modules_named("rules_python");
                    modules.next().unwrap().version.clone().unwrap()
                }
                ModuleLock::FamilyB(hashes) => hashes.selected("rules_python")[0].to_string(),
                other => panic!("{bazel}: {other:?}"),
            };
            let (release, candidate) = match bazel.split_once("rc") {
                Some((release, _)) => (release, true),
                None => (bazel, false),
            };
            let parts: Vec<u32> = release
                .split('.')
                .map(|part| part.parse().unwrap())
                .collect();
            let release = Release(parts[0], parts[1], parts[2]);
            let line = LineSpan {
                prerelease: candidate,
                ..LineSpan::exact(release)
            };
            let floor = bazel_tools_floor("rules_python", Some(line));
            if candidate || release < Release(7, 0, 0) {
                // Outside the releases read: no floor is claimed.
                assert_eq!(floor, None, "{bazel}");
            } else {
                assert_eq!(floor, Some(selected.as_str()), "{bazel}");
            }
            floors.push((bazel.to_string(), selected));
        }
        assert_eq!(floors.len(), 17);
        let selected = |bazel: &str| floors.iter().find(|(b, _)| b == bazel).unwrap().1.as_str();
        assert_eq!(
            ["7.0.2", "7.1.2", "7.7.2", "8.0.0", "8.8.2", "9.0.2", "9.3.2"].map(selected),
            ["0.4.0", "0.22.1", "0.22.1", "0.40.0", "0.40.0", "1.7.0", "1.7.0"]
        );
    }

    #[test]
    fn the_floor_is_the_minimum_over_the_line_and_none_when_unknown() {
        let floor = |line| bazel_tools_floor("rules_python", line);
        assert_eq!(floor(line(7, 0, 0)), Some("0.4.0"));
        assert_eq!(floor(line(7, 1, 0)), Some("0.22.1"));
        assert_eq!(
            floor(span(Release(8, 0, 0), Release(8, 8, 2))),
            Some("0.40.0")
        );
        // A line that can be either of two releases gets the lower floor.
        assert_eq!(
            floor(span(Release(7, 0, 2), Release(7, 7, 2))),
            Some("0.4.0")
        );
        assert_eq!(
            floor(span(Release(7, 7, 2), Release(9, 3, 2))),
            Some("0.22.1")
        );
        assert_eq!(
            floor(span(Release(8, 4, 2), Release(9, 3, 2))),
            Some("0.40.0")
        );
        // Unknown, or an end outside the releases read.
        assert_eq!(floor(None), None);
        assert_eq!(floor(line(6, 6, 0)), None);
        assert_eq!(floor(line(9, 4, 0)), None);
        assert_eq!(floor(line(7, 0, 5)), None);
        assert_eq!(floor(line(7, 8, 0)), None);
        assert_eq!(floor(span(Release(6, 6, 0), Release(7, 7, 2))), None);
        assert_eq!(floor(span(Release(9, 0, 0), Release(9, u32::MAX, 0))), None);
        assert_eq!(floor(span(Release(9, 3, 2), Release(9, 0, 0))), None);
        // 8.0.0rc1 required rules_python 0.36.0, not 0.40.0.
        let candidate = LineSpan {
            prerelease: true,
            ..LineSpan::exact(Release(8, 0, 0))
        };
        assert_eq!(floor(Some(candidate)), None);
        // `bazel_tools` depends on no other ruleset of interest.
        assert_eq!(bazel_tools_floor("gazelle", line(9, 3, 2)), None);
    }

    #[test]
    fn the_lower_bound_is_the_highest_of_declaration_and_floors() {
        let deps = [dep("rules_python", "0.31.0")];
        let lo = |line, api_floor| {
            let evidence = Evidence {
                line,
                api_floor,
                ..evidence("rules_python", &deps)
            };
            let verdict = resolve(&evidence);
            assert_eq!(verdict.hi, None);
            let bound = verdict.lo.unwrap();
            (bound.version, bound.source)
        };
        let of = |version: &str, source| (version.to_string(), source);
        // The same root file on four Bazel lines (probe L7 gv1).
        assert_eq!(lo(None, None), of("0.31.0", Source::Declared));
        assert_eq!(lo(line(7, 7, 2), None), of("0.31.0", Source::Declared));
        assert_eq!(
            lo(line(8, 8, 2), None),
            of("0.40.0", Source::BazelToolsFloor)
        );
        assert_eq!(
            lo(line(9, 3, 2), None),
            of("1.7.0", Source::BazelToolsFloor)
        );
        // `pip.parse(uv_lock = ...)` exists from rules_python 2.2.0.
        assert_eq!(
            lo(line(9, 3, 2), Some("2.2.0")),
            of("2.2.0", Source::ApiShape)
        );
        assert_eq!(
            lo(line(9, 3, 2), Some("0.40.0")),
            of("1.7.0", Source::BazelToolsFloor)
        );
        assert_eq!(
            lo(None, Some("not a version")),
            of("0.31.0", Source::Declared)
        );
        // On Bazel 9 a `lo >= 1.5.0` gate passes with no lock.
        let on_nine = Evidence {
            line: line(9, 3, 2),
            ..evidence("rules_python", &deps)
        };
        assert!(resolve(&on_nine).at_least("1.5.0"));
        assert!(!resolve(&evidence("rules_python", &deps)).at_least("1.5.0"));
    }

    #[test]
    fn a_declaration_that_cannot_be_read_or_may_be_dropped_proves_nothing() {
        let unproven = VersionVerdict::unknown(Unproven::NotDeclared);
        let resolve_with = |deps: &[RootDep], ignore_dev_dependency| {
            resolve(&Evidence {
                ignore_dev_dependency,
                line: line(9, 3, 2),
                ..evidence("rules_python", deps)
            })
        };
        // No declaration: the floor alone is not applied.
        assert_eq!(resolve_with(&[], false), unproven);
        assert_eq!(resolve_with(&[dep("gazelle", "0.36.0")], false), unproven);
        let unfoldable = RootDep {
            version: None,
            ..dep("rules_python", "")
        };
        let alone = std::slice::from_ref(&unfoldable);
        assert_eq!(resolve_with(alone, false), unproven);
        assert_eq!(
            resolve_with(&[dep("rules_python", "1..2")], false),
            unproven
        );
        assert_eq!(resolve_with(&[dep("rules_python", "")], false), unproven);
        // Declared twice: the lower one, and none if either is unread.
        let twice = [dep("rules_python", "2.0.3"), dep("rules_python", "1.8.0")];
        assert_eq!(
            sides(&resolve_with(&twice, false)).0,
            Some(("1.8.0", Source::Declared))
        );
        let half = [dep("rules_python", "2.0.3"), unfoldable];
        assert_eq!(resolve_with(&half, false), unproven);

        // A dev dependency is dropped under `--ignore_dev_dependency`.
        let dev = [RootDep {
            dev_dependency: true,
            ..dep("rules_python", "2.0.3")
        }];
        assert_eq!(
            sides(&resolve_with(&dev, false)).0,
            Some(("2.0.3", Source::Declared))
        );
        assert_eq!(resolve_with(&dev, true), unproven);
    }

    /// Design 2.8 and probes S8 / N1. From Bazel 7.4.0
    /// `--ignore_dev_dependency` drops every root override, so a pin
    /// proves the version only when the flag is off or the line is
    /// proven older. The T0 case: `single_version_override(version =
    /// "1.5.0")` over `bazel_dep` 1.4.0 with `common:ci
    /// --ignore_dev_dependency` never passes a `lo >= 1.5.0` gate.
    #[test]
    fn an_override_under_ignore_dev_dependency_gives_only_the_union() {
        let deps = [dep("rules_python", "1.4.0")];
        let overrides = [over("rules_python", pinned("1.5.0"))];
        let resolve_on = |ignore_dev_dependency, line| {
            resolve(&Evidence {
                overrides: &overrides,
                ignore_dev_dependency,
                line,
                ..evidence("rules_python", &deps)
            })
        };
        let pin = exact("1.5.0", Source::SingleVersionOverride);
        assert_eq!(sides(&resolve_on(false, None)), pin);
        assert_eq!(sides(&resolve_on(false, line(9, 3, 2))), pin);
        // 7.3.2 still honours the override under the flag.
        assert_eq!(sides(&resolve_on(true, line(7, 3, 2))), pin);

        for line in [
            None,
            line(7, 4, 0),
            line(7, 7, 2),
            span(Release(7, 3, 2), Release(7, 4, 1)),
        ] {
            let verdict = resolve_on(true, line);
            assert!(!verdict.at_least("1.5.0"), "{line:?}");
            assert!(verdict.at_least("1.4.0") && !verdict.below("9.0.0"));
            assert_eq!(sides(&verdict), (Some(("1.4.0", Source::Declared)), None));
        }
        // A pin below the declaration: the lower bound is the pin.
        let low = [over("rules_python", pinned("1.2.0"))];
        let verdict = resolve(&Evidence {
            overrides: &low,
            ignore_dev_dependency: true,
            ..evidence("rules_python", &deps)
        });
        assert_eq!(
            sides(&verdict),
            (Some(("1.2.0", Source::SingleVersionOverride)), None)
        );

        // Unknown on either side is unknown.
        let archive = [over("rules_python", OverrideKind::NonRegistry)];
        let verdict = resolve(&Evidence {
            overrides: &archive,
            ignore_dev_dependency: true,
            ..evidence("rules_python", &deps)
        });
        assert_eq!(
            verdict,
            VersionVerdict::unknown(Unproven::NonRegistryOverride)
        );
    }

    /// Under the flag the lock was written with the overrides or
    /// without them, and an override on another module moves this one
    /// too: the lock is evidence in neither state.
    #[test]
    fn a_lock_is_no_evidence_while_overrides_may_be_dropped() {
        let lock = lock("module_lock/gv3/9.3.2.MODULE.bazel.lock");
        let deps = deps_of("module_lock/gv3/fresh.MODULE.bazel");
        let on_rules_go = [over("rules_go", pinned("0.61.1"))];
        let resolve_with = |overrides, ignore_dev_dependency| {
            resolve(&Evidence {
                lock: &lock,
                overrides,
                ignore_dev_dependency,
                ..evidence("gazelle", &deps)
            })
        };
        let declared = Some(("0.36.0", Source::Declared));
        let locked = Some(("0.51.3", Source::Lock));
        assert_eq!(
            sides(&resolve_with(&on_rules_go, false)),
            (declared, locked)
        );
        assert_eq!(sides(&resolve_with(&on_rules_go, true)), (declared, None));
        // With no override in the root there is nothing to drop.
        assert_eq!(sides(&resolve_with(&[], true)), (declared, locked));
    }

    #[test]
    fn an_override_decides_before_any_other_evidence() {
        let deps = [dep("gazelle", "0.36.0")];
        let lock = lock("module_lock/gv3/9.3.2.MODULE.bazel.lock");
        let resolve_with = |overrides: &[RootOverride]| {
            resolve(&Evidence {
                lock: &lock,
                overrides,
                check_direct_dependencies_error: true,
                ..evidence("gazelle", &deps)
            })
        };
        let unknown = VersionVerdict::unknown;
        for kind in [OverrideKind::NonRegistry, OverrideKind::Unreadable] {
            let why = match kind {
                OverrideKind::NonRegistry => Unproven::NonRegistryOverride,
                _ => Unproven::UnreadableOverride,
            };
            assert_eq!(resolve_with(&[over("gazelle", kind)]), unknown(why));
        }
        // `--override_module` beside a pin: the flag wins in Bazel, and
        // either way no file names the version.
        let both = [
            over("gazelle", pinned("0.40.0")),
            over("gazelle", OverrideKind::NonRegistry),
        ];
        assert_eq!(resolve_with(&both), unknown(Unproven::NonRegistryOverride));
        let two = [
            over("gazelle", pinned("0.40.0")),
            over("gazelle", pinned("0.41.0")),
        ];
        assert_eq!(resolve_with(&two), unknown(Unproven::UnreadableOverride));
        let unparsed = [over("gazelle", pinned("latest!"))];
        assert_eq!(
            resolve_with(&unparsed),
            unknown(Unproven::UnreadableOverride)
        );

        let pin = [over("gazelle", pinned("0.40.0"))];
        assert_eq!(
            sides(&resolve_with(&pin)),
            exact("0.40.0", Source::SingleVersionOverride)
        );
        // An override on another module, and one that only patches,
        // leave the ordinary ladder: here the direct-dependency check.
        let other = [
            over("rules_go", OverrideKind::NonRegistry),
            over("gazelle", OverrideKind::PatchOnly),
        ];
        assert_eq!(
            sides(&resolve_with(&other)),
            exact("0.36.0", Source::DirectDependencyCheck)
        );
    }

    /// `--check_direct_dependencies=error` fails resolution unless the
    /// declared version is the selected one (probe L7 gv4).
    #[test]
    fn the_direct_dependency_check_makes_the_declaration_exact() {
        let deps = [dep("gazelle", "0.36.0")];
        let checked = Evidence {
            check_direct_dependencies_error: true,
            ..evidence("gazelle", &deps)
        };
        let verdict = resolve(&checked);
        assert_eq!(
            sides(&verdict),
            exact("0.36.0", Source::DirectDependencyCheck)
        );
        assert!(verdict.below("0.37.0") && !verdict.at_least("0.37.0"));
        // It needs a declaration to make exact.
        let undeclared = Evidence {
            deps: &[],
            ..checked
        };
        assert_eq!(
            resolve(&undeclared),
            VersionVerdict::unknown(Unproven::NotDeclared)
        );
    }

    /// Probe S7 H9, the hybrid-pip shape: `bazel_dep(rules_python,
    /// 1.4.1)` beside a WORKSPACE `http_archive` of rules_python 0.31.0
    /// on Bazel 7.7.2. The WORKSPACE `pip_parse` ran from 1.4.1 and the
    /// archive was never fetched.
    #[test]
    fn a_workspace_hub_takes_the_bzlmod_version_when_its_name_is_visible() {
        let deps = [dep("rules_python", "1.4.1")];
        let bzlmod = resolve(&Evidence {
            line: line(7, 7, 2),
            ..evidence("rules_python", &deps)
        });
        assert_eq!(sides(&bzlmod), (Some(("1.4.1", Source::Declared)), None));
        let archive = exact("0.31.0", Source::WorkspaceLiteral);
        let hub = |definition, system, visible| workspace_hub(definition, system, visible, &bzlmod);

        let hybrid = hub(Some("0.31.0"), HubSystem::Hybrid, true);
        assert_eq!(hybrid, bzlmod);
        assert!(hybrid.at_least("1.4.0") && !hybrid.below("1.0.0"));
        // A name the root module cannot see is the WORKSPACE repository.
        assert_eq!(
            sides(&hub(Some("0.31.0"), HubSystem::Hybrid, false)),
            archive
        );
        assert_eq!(
            sides(&hub(Some("0.31.0"), HubSystem::Workspace, true)),
            archive
        );

        // The flags differ between chains: either may run the hub.
        let dual = hub(Some("0.31.0"), HubSystem::DualMode, true);
        assert_eq!(
            sides(&dual),
            (Some(("0.31.0", Source::WorkspaceLiteral)), None)
        );
        assert!(!dual.at_least("1.4.0") && !dual.below("1.0.0"));

        // A definition `workspace_file::governing` does not call exact.
        let unknown = VersionVerdict::unknown(Unproven::WorkspaceDefinition);
        assert_eq!(hub(None, HubSystem::Workspace, false), unknown);
        assert_eq!(hub(None, HubSystem::Hybrid, false), unknown);
        assert_eq!(hub(None, HubSystem::DualMode, true), unknown);
        // Text that is no version (an empty `strip_prefix` capture).
        assert_eq!(hub(Some(""), HubSystem::Workspace, false), unknown);
        assert_eq!(hub(Some("0.31.0/"), HubSystem::Workspace, false), unknown);
        assert_eq!(hub(None, HubSystem::Hybrid, true), bzlmod);
        assert_eq!(
            hub(Some("0.31.0"), HubSystem::Bzlmod, true),
            VersionVerdict::unknown(Unproven::WorkspaceNotEvaluated)
        );
    }

    #[test]
    fn a_union_keeps_the_outer_bounds_and_forgets_a_side_either_lacks() {
        let range = |lo: Option<&str>, hi: Option<&str>| {
            let bound = |version: &str| Bound {
                version: version.to_string(),
                source: Source::Declared,
            };
            VersionVerdict {
                lo: lo.map(bound),
                hi: hi.map(bound),
                unproven: lo.is_none().then_some(Unproven::NotDeclared),
            }
        };
        let versions = |verdict: &VersionVerdict| {
            let version = |bound: &Option<Bound>| bound.as_ref().map(|b| b.version.clone());
            (version(&verdict.lo), version(&verdict.hi))
        };
        let (a, b) = (
            range(Some("1.4.0"), Some("1.5.0")),
            range(Some("1.2.0"), Some("1.9.0")),
        );
        let outer = (Some("1.2.0".to_string()), Some("1.9.0".to_string()));
        assert_eq!(versions(&a.union(&b)), outer);
        assert_eq!(versions(&b.union(&a)), outer);
        assert_eq!(a.union(&a), a);
        let open = range(Some("1.0.0"), None);
        assert_eq!(versions(&a.union(&open)), (Some("1.0.0".to_string()), None));
        let unknown = VersionVerdict::unknown(Unproven::NonRegistryOverride);
        assert_eq!(a.union(&unknown), unknown);
        assert_eq!(unknown.union(&a), unknown);
        // Nothing is proven about an unknown version.
        assert!(!unknown.at_least("0.0.1") && !unknown.below("999.0.0"));
        assert!(!a.at_least("not a version") && !a.below("not a version"));
    }

    /// Bazel's order, on pairs the version probe settled on eleven
    /// releases (L7 gv11): it is not semver.
    #[test]
    fn versions_compare_as_bazel_compares_them() {
        for (lower, higher) in [
            ("1.5.0-rc0", "1.5.0"),
            ("1.5.0-rc10", "1.5.0-rc9"),
            ("1.5.0-rc.9", "1.5.0-rc.10"),
            ("6.9", "6.10"),
            ("0.54.0", "1.0.0-beta.1"),
            ("1.0.0-beta.2", "1.0.0-beta.10"),
            ("1.0", "1.0.0"),
            ("1.7.1", "1.7.1.bcr.1"),
            ("1.2.3", "1.2.3.socket.ab12cd34"),
            ("1.2.3.socket.ab12cd34", "1.2.4"),
            ("1.2.3-socket.ab12cd34", "1.2.3"),
            ("2025.01.01", "2025.1.2"),
            ("0.36.0", "0.51.3"),
        ] {
            assert_eq!(
                compare(lower, higher),
                Some(Ordering::Less),
                "{lower} {higher}"
            );
            assert_eq!(
                compare(higher, lower),
                Some(Ordering::Greater),
                "{lower} {higher}"
            );
        }
        // The build part does not take part.
        assert_eq!(compare("1.0.0+build.5", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(compare("2.0.3", "2.0.3"), Some(Ordering::Equal));
        for not_a_version in [
            "", "1..2", "1.2.", "v1,2", "1.0-", "1.0+", "1.0 ", "1.0-rc_1", "é",
        ] {
            assert_eq!(compare(not_a_version, "1.0.0"), None, "{not_a_version:?}");
            assert_eq!(compare("1.0.0", not_a_version), None, "{not_a_version:?}");
        }
        // A prerelease of a threshold is below it.
        let rc = VersionVerdict::exact("1.5.0-rc4", Source::Declared);
        assert!(!rc.at_least("1.5.0") && rc.below("1.5.0") && rc.at_least("1.4.9"));
    }
}
