//! Derived state and the lock-refresh policy (design 2.10).
//!
//! Bazel and the rulesets derive state from the bytes of a lock input: a
//! digest in `MODULE.bazel.lock`, a fact, a hash file line, a checksum in a
//! tag. An edit that leaves one of them behind breaks the next build, or
//! worse, builds the unpatched package. So before any file is written
//! [`stale`] lists every such piece of state for the whole write set
//! (paired manifests included), and [`decide`] turns the list into the one
//! rule behind the three outcomes ([`InterimState`]).
//!
//! The answer comes from lock content and the bytes the edit leaves, never
//! from a version table and never from which way the edit goes: `rollback`,
//! `remove`, `repair`, a takeover and the withdrawn-pin sweep ask with the
//! restoring edit and get the same verdict a forward edit would.
//!
//! socket-patch never writes `MODULE.bazel.lock`: a forged digest makes
//! Bazel pass `--lockfile_mode=error` on the unpatched package (probe
//! L1.d). It names the command instead, and [`evidence`] later tells from
//! the committed lock whether the command ran.
//!
//! Two kinds of state are not computed here, because only a recognizer
//! knows them: what a hub derives in its own files (a crate lock digest, a
//! hash-file line, a resolved hash, a checksum value, a lock check target).
//! A recognizer declares those rows in `Hub::derived`, each naming the file
//! whose edit stales it. Of a `maven_install.json` only the resolved hash
//! is such a row: `__INPUT_ARTIFACTS_HASH` covers the hub's attributes,
//! other modules contribute to it, and it is never recomputed, written or
//! compared.

use super::model::{
    DeclSystem, FileText, FileView, Reason, RunRequired, VexWithhold, WithholdKind,
};
use super::module_lock::{
    input_state, ExtensionEntry, ExtensionFacts, Extensions, FactDigest, InputState, ModuleLock,
    GENERAL,
};
use super::rc::{Chain, EffectiveFlags, Flag, FlagState, LockfileMode};
use super::remedy::{self, Remedy};
use super::version::{lockfile_mode_default, BazelLine, Tri};

/// The root module file, whose SHA-256 a family-A lock records.
const ROOT_MODULE: &str = "MODULE.bazel";

/// A module extension by the label of its `.bzl` file without the
/// repository (`//python/extensions:pip.bzl`) and its name, which is how
/// the lock is searched: the repository prefix changes with the Bazel
/// release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtRef<'a> {
    pub label: &'a str,
    pub name: &'a str,
}

/// One piece of state that an edit leaves stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedState {
    /// `MODULE.bazel.lock` records the file for `extension` on `platform`,
    /// and the recorded value is not the SHA-256 of the bytes the edit
    /// leaves (or cannot be compared with them).
    RecordedInput {
        path: String,
        extension: String,
        platform: String,
    },
    /// The lock records a listing or a tree digest of the directory `path`
    /// and the edit changes it. The digest cannot be recomputed here, so
    /// no committed evidence shows a refresh.
    RecordedDir {
        path: String,
        extension: String,
        platform: String,
    },
    /// The lock's facts for the hub's extension may be stale. Only
    /// "may be": facts are shared by every hub of the extension in the
    /// module graph, so the same member can remain after a refresh.
    Facts { extension: String },
    /// The edited `.bzl` file is in the load closure of an extension the
    /// lock has an entry for. The digest differs per Bazel version.
    BzlTransitiveDigest {
        path: String,
        extension: String,
        platform: String,
    },
    /// A family-A lock records the SHA-256 of the root `MODULE.bazel`, and
    /// the edit changes that file: any byte counts.
    ModuleFileHash,
    /// A family-B lock has an entry for the extension, and the edit
    /// changes one of its tags.
    UsagesDigest { extension: String, platform: String },
    /// The lock is unreadable or of a shape this version does not know, or
    /// the facts of the hub's extension are: evidence degrades to no
    /// evidence, so what cannot be read is stale.
    UnknownLockShape { why: String },
    /// Declared by a recognizer: `input` is a manifest or the
    /// `cargo_config` of a crate_universe hub with a `lockfile`. The build
    /// then fails with `Digests do not match` until a repin, under every
    /// lockfile mode.
    CrateLockDigest {
        lockfile: String,
        input: String,
        /// The hub's apparent name and where it is declared: what the
        /// repin command needs.
        hub: String,
        system: DeclSystem,
    },
    /// Declared by a recognizer: a lock check (`compile_pip_requirements`,
    /// a rules_uv `pip_compile`, `lock`, `gazelle_python_manifest`, a
    /// `requirements.bzl` diff test) covers `input`. Its test fails after
    /// the edit and its update command erases the pin.
    LockCheck {
        target: String,
        input: String,
        /// `Some` for a `compile_pip_requirements` target, the one check
        /// with a manual procedure a probe ran: whether rules_python is
        /// proven at or above 1.5.0, which names the test `<name>.test`.
        pip_compile: Option<Tri>,
    },
    /// Declared by a recognizer: the rules_js action-cache file `file`
    /// lists `input` with a hash of its bytes.
    ActionCacheLine { file: String, input: String },
    /// Declared by a recognizer: `file` is a `maven_install.json`, which
    /// signs its own content with `__RESOLVED_ARTIFACTS_HASH`.
    ResolvedHash { file: String },
    /// Declared by a recognizer: the literal `gem_checksums` dict in `file`
    /// has `key` (`<name>-<version>`), and `input` is the lock that pins
    /// that gem.
    ChecksumValue {
        file: String,
        key: String,
        input: String,
    },
}

impl DerivedState {
    /// State inside `MODULE.bazel.lock`, which only Bazel refreshes. Every
    /// other row is declared by a recognizer.
    pub const fn in_lock(&self) -> bool {
        !matches!(
            self,
            Self::CrateLockDigest { .. }
                | Self::LockCheck { .. }
                | Self::ActionCacheLine { .. }
                | Self::ResolvedHash { .. }
                | Self::ChecksumValue { .. }
        )
    }

    /// Whether a lane can recompute the value in the transaction that
    /// stales it.
    pub const fn repairable(&self) -> bool {
        matches!(
            self,
            Self::ActionCacheLine { .. } | Self::ResolvedHash { .. } | Self::ChecksumValue { .. }
        )
    }

    /// Whether `vex` waits for committed evidence that the state was
    /// refreshed. Not for facts and directory records: their refresh
    /// leaves nothing socket-patch can check, the pin's digest is enforced
    /// at fetch, and a stale one fails closed or is refreshed by the next
    /// `update`-mode build.
    pub const fn gates_vex(&self) -> bool {
        !matches!(self, Self::Facts { .. } | Self::RecordedDir { .. })
    }

    /// Why an edit that leaves this state stale is refused.
    pub const fn reason(&self) -> Reason {
        match self {
            Self::LockCheck { .. } => Reason::LockCheckPresent,
            _ if self.in_lock() => Reason::LockfileFrozen,
            _ => Reason::DerivedUnrepairable,
        }
    }

    /// The file whose edit stales a declared row, and for a repairable one
    /// the file that holds the derived value.
    fn declared(&self) -> Option<(&str, &str)> {
        match self {
            Self::CrateLockDigest {
                lockfile, input, ..
            } => Some((input, lockfile)),
            Self::LockCheck { target, input, .. } => Some((input, target)),
            Self::ActionCacheLine { file, input } | Self::ChecksumValue { file, input, .. } => {
                Some((input, file))
            }
            Self::ResolvedHash { file } => Some((file, file)),
            _ => None,
        }
    }

    /// The platform key of the lock entry a row is about.
    fn platform(&self) -> Option<&str> {
        match self {
            Self::RecordedInput { platform, .. }
            | Self::RecordedDir { platform, .. }
            | Self::BzlTransitiveDigest { platform, .. }
            | Self::UsagesDigest { platform, .. } => Some(platform),
            _ => None,
        }
    }
}

/// The one rule behind the three outcomes.
#[derive(Debug, Clone, PartialEq)]
pub enum InterimState {
    /// Nothing stale, or repaired in the same transaction: works.
    Green,
    /// Build and tests keep passing and one command refreshes committed
    /// state: works after.
    SelfHealing { command: Remedy },
    /// The next build would fail: refused.
    Red { what: DerivedState, remedy: Remedy },
}

/// What an edit leaves of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After<'a> {
    /// These bytes. A recorded digest that equals theirs is fresh, which
    /// is how a restoring edit that returns the bytes the lock was written
    /// for stales nothing.
    Bytes(&'a [u8]),
    /// Other bytes than now, not known yet: the gate decides before the
    /// rewriter runs. No recorded digest can be taken to match them.
    Changed,
    /// Nothing: the edit removes the file.
    Removed,
}

/// One file of a write set.
#[derive(Debug, Clone, Copy)]
pub struct Write<'a> {
    /// Relative to the Bazel root, forward slashes.
    pub path: &'a str,
    pub after: After<'a>,
    /// The topmost path the edit creates or removes, when it does: the
    /// file itself, or the first directory that did not exist. A recorded
    /// listing of its parent gains or loses that entry.
    pub entry_change: Option<&'a str>,
    /// For a `.bzl` file: the extensions whose load closure holds it.
    /// Empty means not known, and then every extension of the root module
    /// is taken to load it.
    pub loaded_by: &'a [ExtRef<'a>],
    /// The extensions one of whose tags the edit changes (a value in
    /// `MODULE.bazel` or in an included segment).
    pub tags_of: &'a [ExtRef<'a>],
}

impl<'a> Write<'a> {
    /// An edit of an existing file that leaves these bytes.
    pub const fn bytes(path: &'a str, after: &'a [u8]) -> Self {
        Self {
            after: After::Bytes(after),
            ..Self::changed(path)
        }
    }

    /// A planned edit of an existing file, before its bytes are known.
    pub const fn changed(path: &'a str) -> Self {
        Self {
            path,
            after: After::Changed,
            entry_change: None,
            loaded_by: &[],
            tags_of: &[],
        }
    }
}

/// Which facts an extension stores, and how to look one package up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsOf<'a> {
    /// rules_python `pip`, for a requirements hub that resolves through a
    /// simple index: `dist_hashes[index_url][package]`, the package name
    /// normalized. `removed` and `added` are SHA-256 digests, bare
    /// lowercase hex.
    Pip {
        index_url: &'a str,
        package: &'a str,
    },
    /// Facts keyed per package (rules_rs: `<name>_<version>`). `removed`
    /// and `added` are keys.
    Keyed,
    /// gazelle `go_deps`: one ordered list, which any Go edit can change
    /// (a rewrite adds a member, and Bazel's refresh after a rollback does
    /// not return the first list). `removed` and `added` are not read.
    GoDeps,
}

/// What an edit does to the index pins of one package of a hub whose
/// extension stores facts.
#[derive(Debug, Clone, Copy)]
pub struct FactsEdit<'a> {
    pub extension: ExtRef<'a>,
    pub of: FactsOf<'a>,
    /// The index pins the edit takes away: a forward edit turns them into
    /// direct references, which have no fact.
    pub removed: &'a [&'a str],
    /// The index pins it puts back: a restoring edit.
    pub added: &'a [&'a str],
}

impl FactsEdit<'_> {
    /// Whether `found`, the facts the lock holds for the extension, can
    /// differ from what Bazel computes after the edit. A digest that
    /// cannot be compared counts as "can". `Err` for facts of a shape this
    /// reader does not know: a member it does not model could go stale
    /// unseen.
    fn may_stale(&self, found: &ExtensionFacts) -> Result<bool, String> {
        Ok(match self.of {
            FactsOf::GoDeps => found.go_deps().map(|_| true)?,
            FactsOf::Keyed => {
                let keys = found.keys().ok_or("they are not keyed per package")?;
                let held = |key: &&str| keys.contains(key);
                self.removed.iter().any(held) || !self.added.iter().all(held)
            }
            FactsOf::Pip { index_url, package } => {
                let pip = found.pip()?;
                let held = |digest: &&str| pip.holds_digest(index_url, package, digest);
                let gone = |digest| held(digest) != FactDigest::NotHeld;
                let back = |digest| held(digest) != FactDigest::Held;
                self.removed.iter().any(gone) || self.added.iter().any(back)
            }
        })
    }

    fn state(&self, recorded: &Extensions) -> Option<DerivedState> {
        let ExtRef { label, name } = self.extension;
        let found = recorded.facts_of(label, name);
        let Some(first) = found.first() else {
            // The lock's Bazel stores facts and holds none for this
            // extension: every package of its hubs is a direct reference,
            // and one that returns to the index gains a fact.
            let gains = recorded.stores_facts && !self.added.is_empty();
            let extension = format!("{label}%{name}");
            return gains.then_some(DerivedState::Facts { extension });
        };
        let mut stale = false;
        for facts in &found {
            match self.may_stale(facts) {
                Ok(may) => stale |= may,
                Err(why) => {
                    let why = format!("the facts of {}: {why}", facts.id.raw);
                    return Some(DerivedState::UnknownLockShape { why });
                }
            }
        }
        let extension = first.id.raw.clone();
        stale.then_some(DerivedState::Facts { extension })
    }
}

/// One planned edit: a forward rewrite or the restoring one.
#[derive(Debug, Clone, Copy, Default)]
pub struct Edit<'a> {
    /// Every file the transaction writes: each lock a hub names, the
    /// manifest the native rewriter edits with it, generated files.
    pub writes: &'a [Write<'a>],
    /// `None` for a hub whose extension stores no facts, and always for a
    /// `uv_lock` hub: the pip facts in such a lock belong to rules_python's
    /// own hubs, and the lock is byte-identical after the rewrite.
    pub facts: Option<FactsEdit<'a>>,
    /// The rows of `Hub::derived` that concern the package.
    pub hub: &'a [DerivedState],
    /// The files whose derived values the same transaction recomputes. A
    /// repairable row whose value lives in none of them stays stale.
    pub repairs: &'a [&'a str],
    /// A tracked `startup --digest_function` line
    /// ([`digest_function_tracked`]): Bazel then records digests that are
    /// not SHA-256, so every recorded input of a written file counts as
    /// stale (probe X4).
    pub digest_function: bool,
}

/// Everything the edit leaves stale that its own transaction does not
/// repair: the state inside `MODULE.bazel.lock` first, then the declared
/// rows.
pub fn stale(lock: &ModuleLock, edit: &Edit<'_>) -> Vec<DerivedState> {
    let mut out: Vec<DerivedState> = Vec::new();
    let mut push = |state: DerivedState| {
        if !out.contains(&state) {
            out.push(state);
        }
    };
    match lock.extensions() {
        // Unreadable is not absent: the lock may record any written file.
        None if !edit.writes.is_empty() => push(DerivedState::UnknownLockShape {
            why: match lock {
                ModuleLock::UnknownShape(why) => why.clone(),
                _ => "MODULE.bazel.lock exists and cannot be read".to_string(),
            },
        }),
        None => {}
        Some(recorded) => {
            let row = |entry: &ExtensionEntry| (entry.id.raw.clone(), entry.platform.clone());
            for write in edit.writes {
                let path = write.path.to_string();
                let after = match write.after {
                    After::Bytes(bytes) => Some(FileText::Bytes(bytes.to_vec())),
                    After::Removed => Some(FileText::Absent),
                    After::Changed => None,
                };
                for (entry, input) in recorded.recorded(write.path) {
                    let state = after
                        .as_ref()
                        .map(|file| input_state(&input.recorded, file));
                    if edit.digest_function || state != Some(InputState::Fresh) {
                        let (extension, platform) = row(entry);
                        push(DerivedState::RecordedInput {
                            path: path.clone(),
                            extension,
                            platform,
                        });
                    }
                }
                for (entry, dir) in recorded.recorded_dirs() {
                    let listing = write.entry_change;
                    if listing.is_some_and(|changed| dir.stale_when_created_or_removed(changed))
                        || dir.stale_when_edited(write.path)
                    {
                        let (extension, platform) = row(entry);
                        push(DerivedState::RecordedDir {
                            path: dir.path.clone(),
                            extension,
                            platform,
                        });
                    }
                }
                let loads = |entry: &&ExtensionEntry| match write.loaded_by {
                    [] => entry.id.in_root_module(),
                    known => known
                        .iter()
                        .any(|ext| entry.id.matches(ext.label, ext.name)),
                };
                let is_bzl = write.path.ends_with(".bzl");
                for entry in recorded.entries.iter().filter(|e| is_bzl && loads(e)) {
                    let (extension, platform) = row(entry);
                    push(DerivedState::BzlTransitiveDigest {
                        path: path.clone(),
                        extension,
                        platform,
                    });
                }
                // A family-A lock hashes the whole root file instead.
                let tagged = write
                    .tags_of
                    .iter()
                    .filter(|_| matches!(lock, ModuleLock::FamilyB(_)));
                for entry in tagged.flat_map(|ext| recorded.entries_of(ext.label, ext.name)) {
                    let (extension, platform) = row(entry);
                    push(DerivedState::UsagesDigest {
                        extension,
                        platform,
                    });
                }
            }
            let root = edit.writes.iter().find(|write| write.path == ROOT_MODULE);
            if let (ModuleLock::FamilyA(graph), Some(root)) = (lock, root) {
                if !matches!(root.after, After::Bytes(bytes) if graph.module_file_fresh(bytes)) {
                    push(DerivedState::ModuleFileHash);
                }
            }
            if let Some(state) = edit.facts.and_then(|facts| facts.state(recorded)) {
                push(state);
            }
        }
    }
    for declared in edit.hub {
        let Some((input, holder)) = declared.declared() else {
            continue;
        };
        let repaired = declared.repairable() && edit.repairs.contains(&holder);
        if !repaired && edit.writes.iter().any(|write| write.path == input) {
            push(declared.clone());
        }
    }
    out
}

/// What the plain build does with `MODULE.bazel.lock` (owner decision D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockUse {
    /// `--lockfile_mode=error` on a reading of the build with no
    /// `--config`: a stale lock fails every build.
    Frozen,
    /// `off` on every reading, or unset on a line whose default is proven
    /// to be `off` (6.2.x, and 6.3.1 to 6.6.x): the lock is neither read
    /// nor written.
    Unused,
    /// Anything else: `update`, `refresh`, `error` only under a named
    /// config, or unset where the default is or may be `update` (Bazel 7
    /// and later; 6.3.0, or a range that contains it; no known line).
    Refreshed,
}

/// The lock use that the state of `--lockfile_mode` on the build chain
/// gives on `line`.
///
/// A value that only a release of the line or the working directory
/// decides (a bracketed reading) is a value of the plain build: `error`
/// there is no named config a user opts into, so it freezes the lock.
pub fn lock_use(mode: &FlagState<String>, line: &BazelLine) -> LockUse {
    let is = |value: &String, mode| LockfileMode::parse(value) == Some(mode);
    let default_off = lockfile_mode_default(line) == Some(LockfileMode::Off);
    let unused = |all_off: bool, may_be_unset: bool| {
        if all_off && (default_off || !may_be_unset) {
            LockUse::Unused
        } else {
            LockUse::Refreshed
        }
    };
    match mode {
        FlagState::Set(value) if is(value, LockfileMode::Error) => LockUse::Frozen,
        FlagState::Set(value) => unused(is(value, LockfileMode::Off), false),
        FlagState::Possible(by_reading) => {
            let plain = |key: &String| key.is_empty() || key.starts_with('[');
            let mut readings = by_reading.iter();
            if readings.any(|(key, value)| plain(key) && is(value, LockfileMode::Error)) {
                return LockUse::Frozen;
            }
            let all_off = by_reading.values().all(|v| is(v, LockfileMode::Off));
            unused(all_off, mode.may_be_unset())
        }
        FlagState::NotSeen => unused(true, true),
        // A file that was not read may set the flag.
        FlagState::UnknowableHard(_) | FlagState::UnknowableSoft(_) => LockUse::Refreshed,
    }
}

/// [`lock_use`] of the tracked rc files.
pub fn lock_use_of(flags: &EffectiveFlags, line: &BazelLine) -> LockUse {
    lock_use(&flags.state(Flag::LockfileMode, Chain::Build), line)
}

/// Whether a tracked rc file sets or may set `startup --digest_function`.
pub fn digest_function_tracked(flags: &EffectiveFlags) -> bool {
    let state = flags.state(Flag::DigestFunction, Chain::Startup);
    !state.values().is_empty()
}

/// What the policy decides for one edit.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// [`stale`] for the edit. Under [`LockUse::Unused`] the lock rows are
    /// listed and do not count.
    pub stale: Vec<DerivedState>,
    pub interim: InterimState,
    /// With [`InterimState::Green`]: all that may be stale is state whose
    /// refresh `vex` does not wait for ([`DerivedState::gates_vex`]). The
    /// lane works, and the command is named all the same.
    pub advisory: Option<Remedy>,
}

impl Decision {
    /// The refusal reason of a forward edit; `None` when it may proceed.
    pub fn reason(&self) -> Option<Reason> {
        match &self.interim {
            InterimState::Red { what, .. } => Some(what.reason()),
            _ => None,
        }
    }

    /// Builds fail from the edit until the command has run: the level of
    /// the advisory after an explicit `rollback` or `remove`, which
    /// restore all the same (design 7).
    pub fn builds_fail(&self) -> bool {
        matches!(self.interim, InterimState::Red { .. })
    }

    /// Whether a restoring edit nobody asked for by name may go ahead: the
    /// withdrawn-pin sweep, a takeover and `repair` keep the pin instead
    /// of leaving builds failing (design 7).
    pub fn automatic_restore_allowed(&self) -> bool {
        !self.builds_fail()
    }

    /// The advisory that names the command: after a works-after write,
    /// for facts that may be stale (`gates_vex` false), and after a
    /// restoring edit that leaves state only the command refreshes.
    pub fn run_required(&self) -> Option<RunRequired> {
        match (&self.interim, &self.advisory) {
            (InterimState::SelfHealing { command }, _) => command.run_required(true),
            (InterimState::Red { remedy, .. }, _) => {
                remedy.run_required(self.stale.iter().any(DerivedState::gates_vex))
            }
            (InterimState::Green, Some(advisory)) => advisory.run_required(false),
            (InterimState::Green, None) => None,
        }
    }
}

/// The lock-refresh policy for one edit, forward or restoring.
///
/// - Nothing stale: works.
/// - State that fails the build under every lockfile mode (a crate lock
///   digest, a lock check, a hub value the transaction does not
///   recompute): refused.
/// - Stale lock state under [`LockUse::Frozen`]: refused, facts included.
/// - Under [`LockUse::Refreshed`]: works after, with the command to run on
///   each platform the lock has a stale entry for. Facts or a directory
///   record alone: works, with the same command as an advisory that does
///   not gate `vex`.
/// - Under [`LockUse::Unused`]: works.
///
/// `cx.facts_in_lock` is taken from `lock`.
pub fn decide(
    lock: &ModuleLock,
    edit: &Edit<'_>,
    lock_use: LockUse,
    cx: &remedy::Cx<'_>,
) -> Decision {
    let stale = stale(lock, edit);
    let facts_in_lock = lock.facts().is_some_and(|facts| !facts.is_empty());
    let cx = remedy::Cx {
        facts_in_lock,
        ..*cx
    };
    let done = |interim, advisory| Decision {
        stale: stale.clone(),
        interim,
        advisory,
    };
    if let Some(what) = stale.iter().find(|state| !state.in_lock()) {
        let remedy = match what {
            DerivedState::CrateLockDigest { hub, system, .. } => remedy::repin(&cx, hub, *system),
            DerivedState::LockCheck {
                target,
                pip_compile: Some(dot_test),
                ..
            } => Some(remedy::pip_compile_snippet(target, *dot_test)),
            _ => None,
        };
        let remedy = remedy.unwrap_or_else(|| {
            Remedy::unavailable(match what {
                DerivedState::CrateLockDigest { .. } => {
                    "No repin command exists for a WORKSPACE hub on Bazel 9 or later."
                }
                DerivedState::LockCheck { .. } => {
                    "The update command of the lock check regenerates the file and drops the pin."
                }
                _ => "Regenerate the file with the ruleset's own command, then run again.",
            })
        });
        let what = what.clone();
        return done(InterimState::Red { what, remedy }, None);
    }
    let gating = stale.iter().find(|state| state.gates_vex());
    let Some(first) = gating.or(stale.first()) else {
        return done(InterimState::Green, None);
    };
    let mut platforms: Vec<String> = Vec::new();
    for key in stale.iter().filter_map(DerivedState::platform) {
        if key != GENERAL && !platforms.iter().any(|seen| seen == key) {
            platforms.push(key.to_string());
        }
    }
    let command = remedy::lock_refresh(&cx, &platforms);
    match lock_use {
        LockUse::Unused => done(InterimState::Green, None),
        LockUse::Frozen => {
            let what = first.clone();
            let remedy = command;
            done(InterimState::Red { what, remedy }, None)
        }
        LockUse::Refreshed if gating.is_some() => done(InterimState::SelfHealing { command }, None),
        LockUse::Refreshed => done(InterimState::Green, Some(command)),
    }
}

/// What the lane wrote, for [`evidence`].
#[derive(Debug, Clone, Copy)]
pub struct Proof<'a> {
    /// Every lock input the lane wrote.
    pub inputs: &'a [&'a str],
    /// The extensions that generate the hub's repositories. Each of their
    /// entries must carry the pin, also one that records no file (a
    /// generated paket extension). Empty: every entry that records an
    /// input must.
    pub hub: &'a [ExtRef<'a>],
    /// The pin's digest as the ruleset's repository specs render it.
    /// `None` where the specs do not carry it: digest equality then stands
    /// alone.
    pub pin: Option<&'a str>,
    /// As [`Edit::digest_function`].
    pub digest_function: bool,
}

/// Whether the committed lock shows that the works-after command ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// Every record of every input holds the SHA-256 of the file as found,
    /// under every platform key, and every hub entry carries the pin. Also
    /// when the lock records none of this: nothing is stale then.
    Holds,
    /// The command has not run, or not on `platforms`, or the comparison
    /// cannot be made: `vex` waits. Also for a hub entry that lacks the
    /// pin and records no file, where nothing tells a lock that was not
    /// refreshed from one that was merged by hand.
    Pending { platforms: Vec<String>, why: String },
    /// An entry with a fresh digest and repository specs from before the
    /// pin, which is what a hand-resolved merge of the lock leaves. It
    /// passes `--lockfile_mode=error`, builds the unpatched package in
    /// every mode, and the refresh does not heal it (probe L1.d).
    DerivedStale { extension: String, platform: String },
}

impl Evidence {
    /// The withheld statement, with the remedy in its detail.
    pub fn withhold(&self, cx: &remedy::Cx<'_>) -> Option<VexWithhold> {
        let keys = |platform: &String| Some(platform.clone()).filter(|key| key != GENERAL);
        let (kind, detail) = match self {
            Self::Holds => return None,
            Self::Pending { platforms, why } => {
                let command = remedy::lock_refresh(cx, platforms).text();
                (WithholdKind::RunPending, format!("{why}. {command}"))
            }
            Self::DerivedStale {
                extension,
                platform,
            } => {
                let platforms: Vec<String> = keys(platform).into_iter().collect();
                let remedy = remedy::delete_entry(extension, &platforms);
                (WithholdKind::DerivedStale, remedy.text())
            }
        };
        Some(VexWithhold { kind, detail })
    }
}

/// The evidence that ends works-after, read from the committed lock and
/// the files as found (design 2.10; probes L1.d, L4.a, X4).
pub fn evidence(lock: &ModuleLock, files: &dyn FileView, proof: &Proof<'_>) -> Evidence {
    let pending = |platforms: Vec<String>, why: &str| Evidence::Pending {
        platforms,
        why: why.to_string(),
    };
    let Some(recorded) = lock.extensions() else {
        let why = "MODULE.bazel.lock cannot be read as a lock, so nothing in it is evidence";
        return pending(Vec::new(), why);
    };
    if proof.digest_function {
        let why = "A tracked `startup --digest_function` line makes Bazel record digests that \
                   cannot be compared with the files";
        return pending(Vec::new(), why);
    }
    // The entries that record an input, and the platforms whose record
    // is not the file as found.
    let mut recording: Vec<&ExtensionEntry> = Vec::new();
    let mut behind: Vec<String> = Vec::new();
    for path in proof.inputs {
        let file = files.read(path);
        for (entry, input) in recorded.recorded(path) {
            let fresh = input_state(&input.recorded, &file) == InputState::Fresh;
            if !fresh && !behind.contains(&entry.platform) {
                behind.push(entry.platform.clone());
            }
            if !recording.iter().any(|seen| std::ptr::eq(*seen, entry)) {
                recording.push(entry);
            }
        }
    }
    let root_behind = match lock {
        ModuleLock::FamilyA(graph) if proof.inputs.contains(&ROOT_MODULE) => {
            let root = files.read(ROOT_MODULE);
            !root.as_bytes().is_some_and(|b| graph.module_file_fresh(b))
        }
        _ => false,
    };
    if root_behind || !behind.is_empty() {
        behind.retain(|key| key != GENERAL);
        let why = "MODULE.bazel.lock still records the bytes from before the edit";
        return pending(behind, why);
    }
    let Some(pin) = proof.pin else {
        return Evidence::Holds;
    };
    let hub = proof.hub.iter();
    let named: Vec<&ExtensionEntry> = hub
        .flat_map(|ext| recorded.entries_of(ext.label, ext.name))
        .collect();
    let carriers = if proof.hub.is_empty() {
        &recording
    } else {
        &named
    };
    let mut lacking = carriers.iter().filter(|entry| !entry.specs_mention(pin));
    let records_an_input =
        |entry: &&&ExtensionEntry| recording.iter().any(|r| std::ptr::eq(*r, **entry));
    // A digest that is current beside specs that are not is the forged
    // state. An entry that records no file shows nothing either way: the
    // refresh has not reached it, as far as the lock says.
    if let Some(entry) = lacking.clone().find(records_an_input) {
        return Evidence::DerivedStale {
            extension: entry.id.raw.clone(),
            platform: entry.platform.clone(),
        };
    }
    match lacking.next() {
        Some(entry) => {
            let platforms = Some(entry.platform.clone()).filter(|key| key != GENERAL);
            let why = "The lock entry of the hub's extension does not carry the pin";
            pending(platforms.into_iter().collect(), why)
        }
        None => Evidence::Holds,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::Value;

    use super::super::codes::Code;
    use super::super::rc::read as read_rc;
    use super::super::rc::testing::Files;
    use super::super::version::BazelVersion;
    use super::*;

    const PYPI: &str = "https://pypi.org/simple";
    const PIP: ExtRef<'static> = ExtRef {
        label: "//python/extensions:pip.bzl",
        name: "pip",
    };
    const TOY: ExtRef<'static> = ExtRef {
        label: "//:ext.bzl",
        name: "toy",
    };
    const TOY_ID: &str = "//:ext.bzl%toy";
    /// six 1.17.0, the wheel the pip cells replace.
    const SIX: &str = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
    const LINUX: &str = "os:linux,arch:aarch64";
    const OSX: &str = "os:osx,arch:aarch64";
    const USES: [LockUse; 3] = [LockUse::Frozen, LockUse::Refreshed, LockUse::Unused];

    fn bytes(rel: &str) -> Vec<u8> {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel");
        let path = fixtures.join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The lock `<rel>.MODULE.bazel.lock` of the fixtures.
    fn lock(rel: &str) -> ModuleLock {
        ModuleLock::parse(&bytes(&format!("{rel}.MODULE.bazel.lock")))
    }

    fn json(rel: &str) -> Value {
        serde_json::from_slice(&bytes(rel)).expect("fixture JSON")
    }

    fn view(files: &[(&str, &[u8])]) -> Files {
        let file = |(path, bytes): &(&str, &[u8])| (path.to_string(), bytes.to_vec());
        let files = files.iter().map(file);
        Files::from(files.map(|(path, bytes)| (path, FileText::Bytes(bytes))))
    }

    fn line(version: &str) -> BazelLine {
        BazelLine::of(BazelVersion::parse(version).expect("a release"))
    }

    fn cx(line: &BazelLine) -> remedy::Cx<'_> {
        remedy::Cx {
            line,
            strict_repo_env: false,
            facts_in_lock: false,
            query_hub: None,
        }
    }

    fn writes<'a>(writes: &'a [Write<'a>]) -> Edit<'a> {
        Edit {
            writes,
            ..Edit::default()
        }
    }

    fn with_facts<'a>(writes: &'a [Write<'a>], facts: FactsEdit<'a>) -> Edit<'a> {
        Edit {
            writes,
            facts: Some(facts),
            ..Edit::default()
        }
    }

    fn input(path: &str, extension: &str, platform: &str) -> DerivedState {
        DerivedState::RecordedInput {
            path: path.to_string(),
            extension: extension.to_string(),
            platform: platform.to_string(),
        }
    }

    fn proof<'a>(inputs: &'a [&'a str], hub: &'a [ExtRef<'a>], pin: Option<&'a str>) -> Proof<'a> {
        Proof {
            inputs,
            hub,
            pin,
            digest_function: false,
        }
    }

    /// The outcome of design principle P6 that a decision is.
    fn outcome(decision: &Decision) -> &'static str {
        match (&decision.interim, &decision.advisory) {
            (InterimState::Green, None) => "works",
            (InterimState::Green, Some(_)) => "works, advisory",
            (InterimState::SelfHealing { .. }, None) => "works after",
            (InterimState::Red { .. }, None) => "refused",
            other => panic!("{other:?}"),
        }
    }

    /// Probe L1, 17 releases and nine lock versions, fresh and stale: the
    /// static verdict equals what `bazel build --lockfile_mode=error` did,
    /// row by row, through each of the three input containers.
    #[test]
    fn the_recorded_input_vectors_give_the_verdict_of_bazels_error_mode_build() {
        let index = json("probe_vectors/lockfile/vectors.json");
        let inputs = ["dep.lock", "third_party/py/requirements lock.txt"];
        let mut cases = 0;
        for vector in index["recorded_inputs"]["vectors"].as_array().unwrap() {
            for state in ["fresh", "stale"] {
                let dir = vector["dir"].as_str().unwrap();
                let dir = format!("probe_vectors/lockfile/{dir}/{state}");
                let lock = lock(&format!("{dir}/root"));
                let expected = json(&format!("{dir}/expected.json"));
                let on_disk = inputs.map(|path| bytes(&format!("{dir}/{path}")));
                let written = [0, 1].map(|i| Write::bytes(inputs[i], &on_disk[i]));
                let edit = writes(&written);

                let rows = expected["prototype"]["inputs"].as_array().unwrap();
                let stale_rows = rows.iter().filter(|row| row["state"] == "stale");
                let text = |row: &Value, key: &str| row[key].as_str().unwrap().to_string();
                let predicted: Vec<DerivedState> = stale_rows
                    .map(|row| {
                        let extension = text(row, "extension");
                        input(&text(row, "path"), &extension, &text(row, "factor"))
                    })
                    .collect();
                assert_eq!(stale(&lock, &edit), predicted, "{dir}");
                let failed = expected["bazel_error_mode_build_exit"] != 0;
                assert_eq!(!predicted.is_empty(), failed, "{dir}");

                let line = line(vector["bazel"].as_str().unwrap());
                let [frozen, refreshed, unused] =
                    USES.map(|lock_use| decide(&lock, &edit, lock_use, &cx(&line)));
                assert_eq!(outcome(&frozen) == "refused", failed, "{dir}");
                let reason = failed.then_some(Reason::LockfileFrozen);
                assert_eq!(frozen.reason(), reason, "{dir}");
                let after = if failed { "works after" } else { "works" };
                assert_eq!(outcome(&refreshed), after, "{dir}");
                assert_eq!(outcome(&unused), "works", "{dir}");

                // The same reading is the evidence that the command ran.
                let files = view(&[(inputs[0], &on_disk[0]), (inputs[1], &on_disk[1])]);
                let found = evidence(&lock, &files, &proof(&inputs, &[], None));
                assert_eq!(found == Evidence::Holds, !failed, "{dir}");
                cases += 1;
            }
        }
        assert_eq!(cases, 34);
    }

    /// Probe L3, pip `fact_version` v1 and v2, gazelle `go_deps`, and the
    /// rules_python probe's hubs with an index of their own. On the
    /// baseline lock Bazel's `error`-mode build failed after the rewrite
    /// (`has changed its facts`), on Bazel's own repair it passed.
    #[test]
    fn the_facts_vectors_are_possibly_stale_where_bazel_reported_changed_facts() {
        let facts_row = |extension: &str| {
            let extension = extension.to_string();
            vec![DerivedState::Facts { extension }]
        };
        let lock_input = [Write::changed("requirements_lock.txt")];
        let own_index = "https://127.0.0.1:47292/simple";
        let victim = "cecf23d2e612215c6512613873a29337301ed66f92a1e81810ce20d8f3bab993";
        for (dir, index_url, package, digest) in [
            ("pip-v1", PYPI, "six", SIX),
            ("pip-v2", PYPI, "six", SIX),
            ("pip-index-v1", own_index, "spvictim", victim),
            ("pip-index-v2", own_index, "spvictim", victim),
        ] {
            let state = |name: &str, index_url, removed: &[&str], added: &[&str]| {
                let facts = FactsEdit {
                    extension: PIP,
                    of: FactsOf::Pip { index_url, package },
                    removed,
                    added,
                };
                let lock = lock(&format!("module_lock/facts/{dir}/{name}"));
                stale(&lock, &with_facts(&lock_input, facts))
            };
            let pip = facts_row("@@rules_python+//python/extensions:pip.bzl%pip");
            assert_eq!(state("baseline", index_url, &[digest], &[]), pip, "{dir}");
            assert_eq!(state("bazel-repaired", index_url, &[digest], &[]), []);
            // The restoring edit is the mirror: on the refreshed lock the
            // pin's fact is gone and comes back, on the first lock it
            // never left.
            assert_eq!(state("bazel-repaired", index_url, &[], &[digest]), pip);
            assert_eq!(state("baseline", index_url, &[], &[digest]), [], "{dir}");
            // Under another index nothing is held.
            let other = "https://example.test/simple";
            assert_eq!(state("baseline", other, &[digest], &[]), [], "{dir}");
            // A `uv_lock` hub has no facts of its own: no probe, no row,
            // whatever the lock holds for rules_python's own hubs.
            let baseline = lock(&format!("module_lock/facts/{dir}/baseline"));
            assert_eq!(stale(&baseline, &writes(&lock_input)), [], "{dir}");
        }

        // gazelle: any Go edit can change the one list, and Bazel's
        // refresh does not return it to its first bytes, so the repaired
        // lock stays "possibly stale" where Bazel then passed.
        let go_deps = FactsEdit {
            extension: ExtRef {
                label: "//:extensions.bzl",
                name: "go_deps",
            },
            of: FactsOf::GoDeps,
            removed: &[],
            added: &[],
        };
        let go_mod = [Write::changed("go.mod")];
        for name in ["baseline", "bazel-repaired"] {
            let lock = lock(&format!("module_lock/facts/go-deps/{name}"));
            let found = stale(&lock, &with_facts(&go_mod, go_deps));
            assert_eq!(found, facts_row("@@gazelle+//:extensions.bzl%go_deps"));
        }
    }

    /// Keyed facts (the toy of probe L3, and rules_rs), and the answers
    /// that are neither "held" nor "not held": an extension without facts
    /// in a lock that stores them, a lock that stores none, a digest that
    /// cannot be compared, and facts of a shape this reader does not know.
    #[test]
    fn keyed_facts_follow_the_key_and_facts_of_an_unknown_shape_are_stale() {
        const KEY: &[&str] = &["dep_a@index"];
        let keyed = FactsOf::Keyed;
        let dep_lock = [Write::changed("dep.lock")];
        let rows = |lock: &ModuleLock, extension, of, removed: &[&str], added: &[&str]| {
            let facts = FactsEdit {
                extension,
                of,
                removed,
                added,
            };
            stale(lock, &with_facts(&dep_lock, facts)).len()
        };
        // Bazel failed `error` mode on the baseline (step F2) and passed
        // once the key was gone (F3).
        let (baseline, repaired) = ("module_lock/facts/toy/baseline", "hand-repaired");
        let repaired = lock(&format!("module_lock/facts/toy/{repaired}"));
        let baseline = lock(baseline);
        assert_eq!(rows(&baseline, TOY, keyed, KEY, &[]), 1);
        assert_eq!(rows(&repaired, TOY, keyed, KEY, &[]), 0);
        assert_eq!(rows(&repaired, TOY, keyed, &[], KEY), 1);
        assert_eq!(rows(&baseline, TOY, keyed, &[], KEY), 0);
        let rules_rs = lock("module_lock/facts/rules-rs/baseline");
        let crates = ExtRef {
            label: "//rs:extensions.bzl",
            name: "crate",
        };
        assert_eq!(rows(&rules_rs, crates, keyed, &["cfg-if_1.0.4"], &[]), 1);
        assert_eq!(rows(&rules_rs, crates, keyed, &["cfg-if_1.0.3"], &[]), 0);

        // No facts for the extension. A lock whose Bazel stores facts
        // gains one when a package returns to the index; a Bazel 7 lock
        // never does. Taking a pin away stales neither.
        let parse = |json: &str| ModuleLock::parse(json.as_bytes());
        let stores = parse(r#"{"lockFileVersion": 28, "registryFileHashes": {}, "facts": {}}"#);
        let stores_none = parse(r#"{"lockFileVersion": 13, "registryFileHashes": {}}"#);
        assert_eq!(rows(&stores, TOY, keyed, &[], KEY), 1);
        assert_eq!(rows(&stores, TOY, keyed, KEY, &[]), 0);
        assert_eq!(rows(&stores_none, TOY, keyed, &[], KEY), 0);
        assert_eq!(rows(&ModuleLock::Absent, TOY, keyed, &[], KEY), 0);
        assert_eq!(rows(&stores, TOY, FactsOf::GoDeps, &[], &[]), 0);

        // A digest that is no SHA-256 may be the pin's: possibly stale.
        let holding = |pip: &str| {
            parse(&format!(
                r#"{{"registryFileHashes": {{}}, "facts": {{"//:ext.bzl%toy": [],
                    "@@rules_python+//python/extensions:pip.bzl%pip": {pip}}}}}"#
            ))
        };
        let pip = FactsOf::Pip {
            index_url: PYPI,
            package: "six",
        };
        let md5 = holding(
            r#"{"fact_version": "v2", "dist_hashes": {"https://pypi.org/simple":
                {"six": {"https://f.test/six.whl": "md5:d41d8cd98f00b204e9800998ecf8427e"}}}}"#,
        );
        assert_eq!(rows(&md5, PIP, pip, &[SIX], &[]), 1);
        assert_eq!(rows(&md5, PIP, pip, &["not-a-digest"], &[]), 1);
        // Facts of a shape this reader does not know are an unknown lock
        // shape, which is stale and not only "possibly": a `fact_version`
        // of the future, facts that are no object, a list that is none.
        let v3 = holding(r#"{"fact_version": "v3", "dist_hashes": {}}"#);
        let go_deps = FactsOf::GoDeps;
        for (extension, of) in [(PIP, pip), (TOY, keyed), (TOY, go_deps), (PIP, go_deps)] {
            let facts = FactsEdit {
                extension,
                of,
                removed: &[],
                added: &[],
            };
            let found = stale(&v3, &with_facts(&dep_lock, facts));
            let unknown = matches!(&found[..], [DerivedState::UnknownLockShape { why }]
                if why.starts_with("the facts of ") && found[0].gates_vex());
            assert!(unknown, "{extension:?} {of:?}: {found:?}");
        }
    }

    /// Probe L1.d on each of the eight releases it ran: a lock whose
    /// recorded digest was replaced by hand passes `error` mode and
    /// builds the unpatched package. Digest equality alone would call it
    /// refreshed; the repository specs tell it apart.
    #[test]
    fn a_forged_lock_is_derived_stale_and_names_the_entry_to_delete() {
        const RELEASES: [&str; 8] = [
            "6.6.0",
            "7.0.2",
            "7.1.2",
            "7.7.2",
            "8.4.2",
            "8.8.2",
            "9.3.2",
            "10.0.0rc3",
        ];
        for release in RELEASES {
            let dir = format!("module_lock/stale-repair/bazel-{release}");
            let read = |name: &str| lock(&format!("{dir}/{name}"));
            let before = bytes(&format!("{dir}/dep.lock.before"));
            let after = bytes(&format!("{dir}/dep.lock.after"));
            let pinned = view(&[("dep.lock", &after)]);
            let pin = Some("socket-patched-a-1.0");
            let found = |name: &str, hub: &[ExtRef<'_>], pin| {
                evidence(&read(name), &pinned, &proof(&["dep.lock"], hub, pin))
            };
            assert_eq!(found("updated", &[TOY], pin), Evidence::Holds, "{release}");
            let pending = found("baseline", &[TOY], pin);
            let no_platform =
                matches!(&pending, Evidence::Pending { platforms, .. } if platforms.is_empty());
            assert!(no_platform, "{release}: {pending:?}");
            let forged = found("forged", &[TOY], pin);
            let entry = Evidence::DerivedStale {
                extension: TOY_ID.to_string(),
                platform: GENERAL.to_string(),
            };
            assert_eq!(forged, entry, "{release}");
            // With no hub named, the entry that records the input must
            // carry the pin.
            assert_eq!(found("forged", &[], pin), entry, "{release}");
            assert_eq!(found("updated", &[], pin), Evidence::Holds, "{release}");
            // Where the specs do not carry the digest, equality stands
            // alone; and an empty pin proves nothing.
            assert_eq!(found("forged", &[TOY], None), Evidence::Holds, "{release}");
            assert_eq!(found("updated", &[TOY], Some("")), entry, "{release}");

            let at = line(release);
            let withheld = forged.withhold(&cx(&at)).unwrap();
            let code = |kind| Code::withheld(kind).as_str();
            assert_eq!(code(withheld.kind), "vex_bazel_derived_stale");
            let remedy = "Delete the `//:ext.bzl%toy` entry under `moduleExtensions` in \
                          MODULE.bazel.lock. Run `bazel mod deps --lockfile_mode=update`";
            assert!(withheld.detail.starts_with(remedy), "{}", withheld.detail);
            let waiting = pending.withhold(&cx(&at)).unwrap();
            assert_eq!(code(waiting.kind), "vex_bazel_run_pending");
            let command = "Run `bazel mod deps --lockfile_mode=update`";
            assert!(waiting.detail.contains(command), "{}", waiting.detail);
            assert_eq!(Evidence::Holds.withhold(&cx(&at)), None);

            // What Bazel's `error` mode sees: the forged lock is current
            // for the pinned file, the first lock is not; and the
            // restoring edit is stale on the refreshed lock alone.
            let toy = vec![input("dep.lock", TOY_ID, GENERAL)];
            let rows = |name: &str, after| {
                let write = Write {
                    after,
                    ..Write::changed("dep.lock")
                };
                stale(&read(name), &writes(&[write]))
            };
            let (forward, restore) = (After::Bytes(&after), After::Bytes(&before));
            assert_eq!(rows("forged", forward), [], "{release}");
            assert_eq!(rows("baseline", forward), toy, "{release}");
            assert_eq!(rows("updated", forward), [], "{release}");
            assert_eq!(rows("updated", restore), toy, "{release}");
            assert_eq!(rows("baseline", restore), [], "{release}");
            // A removed file, and an edit whose bytes are not known yet
            // (the gate runs before the rewriter): never fresh.
            for name in ["baseline", "updated", "forged"] {
                assert_eq!(rows(name, After::Removed), toy, "{release} {name}");
                assert_eq!(rows(name, After::Changed), toy, "{release} {name}");
            }
        }
    }

    /// Probes U3 and B2: a generated paket extension that is not
    /// reproducible has an entry, and an edit of the data file it loads
    /// stales `bzlTransitiveDigest` although the entry records no file.
    #[test]
    fn a_paket_data_file_under_a_recorded_extension_is_bzl_transitive_digest() {
        let digest = |path: &str, extension: &str| DerivedState::BzlTransitiveDigest {
            path: path.to_string(),
            extension: extension.to_string(),
            platform: GENERAL.to_string(),
        };
        let pin = "sha512-HriaeJXKHcyWUUFH7BxRZPyHEZusGmYRbiU3G+RoEG5ZzSVl7M7ue+tuBgA6wEKjJQ3hmnp6\
                   Ff5nxjwzuyuWsA==";
        let at = line("9.3.2");
        for (file, label, name, recorded) in [
            (
                "dn-7.7.2-0.14.0.reduced",
                "//deps:paket.main_extension.bzl",
                "main_extension",
                true,
            ),
            (
                "dn-9.3.2-0.22.2",
                "//deps:paket.oldgen_extension.bzl",
                "oldgen_extension",
                true,
            ),
            // The 0.22.2 shape returns `reproducible = True`: no entry.
            (
                "dn-9.3.2-0.22.2",
                "//deps:paket.main_extension.bzl",
                "main_extension",
                false,
            ),
        ] {
            let lock = lock(&format!("module_lock/paket/{file}"));
            let path = label.replace("//deps:", "deps/").replace("_extension", "");
            let loaders = [ExtRef { label, name }];
            let data_file = [Write {
                loaded_by: &loaders,
                ..Write::changed(&path)
            }];
            let edit = writes(&data_file);
            let row = digest(&path, &format!("{label}%{name}"));
            let expected: Vec<DerivedState> = recorded.then_some(row).into_iter().collect();
            assert_eq!(stale(&lock, &edit), expected, "{file} {name}");
            let outcomes = USES.map(|lock_use| outcome(&decide(&lock, &edit, lock_use, &cx(&at))));
            let expected = if recorded {
                ["refused", "works after", "works"]
            } else {
                ["works"; 3]
            };
            assert_eq!(outcomes, expected, "{file} {name}");

            // The entry records no file, so the evidence is the pin in
            // its repository specs.
            let files = view(&[]);
            let found = |pin| evidence(&lock, &files, &proof(&[], &loaders, Some(pin)));
            assert_eq!(found(pin), Evidence::Holds, "{file} {name}");
            // Without a recorded file nothing tells a lock that was not
            // refreshed from a forged one: the command is named again.
            let lacks = matches!(found("sha512-other"), Evidence::Pending { .. });
            assert_eq!(lacks, recorded, "{file} {name}");
        }
        // With no loader named, every recorded extension of the root
        // module is taken to load an edited `.bzl` file (here the probe's
        // own and the old generated one), and no other file is.
        let lock = lock("module_lock/paket/dn-9.3.2-0.22.2");
        let path = "deps/paket.main.bzl";
        let oldgen = "//deps:paket.oldgen_extension.bzl%oldgen_extension";
        assert_eq!(
            stale(&lock, &writes(&[Write::changed(path)])),
            [digest(path, "//:probe_ext.bzl%probe"), digest(path, oldgen)]
        );
        assert_eq!(
            stale(&lock, &writes(&[Write::changed("deps/paket.lock")])),
            []
        );
    }

    /// Design 2.10, the mode column of the lock-refresh table: the D5
    /// split between `error` on the plain build and `error` under a
    /// config, and the defaults of the 6.x releases.
    #[test]
    fn the_lockfile_mode_of_the_plain_build_decides_the_lock_use() {
        let majors = |lo: u32, hi: u32| BazelLine {
            lo: Some(BazelVersion::new(lo, 0, 0)),
            hi: Some(BazelVersion::ceiling(hi)),
            evidence: Vec::new(),
        };
        // `common=error common:ci=off` is an rc file of two lines.
        let on = |spec: &str, line: &BazelLine| {
            let mode =
                |(section, mode): (&str, &str)| format!("{section} --lockfile_mode={mode}\n");
            let lines = spec
                .split(' ')
                .filter_map(|setting| setting.split_once('='));
            let rc: String = lines.map(mode).collect();
            let files = Files::of(&[(".bazelrc", rc.as_str())]);
            lock_use_of(&read_rc(&files).effective(line), line)
        };
        let (frozen, unused, refreshed) = (LockUse::Frozen, LockUse::Unused, LockUse::Refreshed);
        // Nothing set: the default of the line.
        for version in ["5.4.1", "6.2.1", "6.3.1", "6.6.0"] {
            assert_eq!(on("", &line(version)), unused, "{version}");
        }
        for version in ["6.3.0", "7.0.2", "7.7.2", "8.8.2", "9.3.2"] {
            assert_eq!(on("", &line(version)), refreshed, "{version}");
        }
        // A 6.x range contains 6.3.0, and no line is no proof of `off`.
        for range in [majors(6, 6), majors(6, 7), BazelLine::unknown()] {
            assert_eq!(on("", &range), refreshed, "{range}");
        }
        for version in ["6.6.0", "7.7.2", "9.3.2"] {
            let at = line(version);
            let default = on("", &at);
            for (rc, expected) in [
                ("common=error", frozen),
                ("build=error", frozen),
                ("build=ERROR", frozen),
                ("common=update", refreshed),
                ("common=refresh", refreshed),
                ("common=off", unused),
                // `error` only under a named config (D5): the plain build
                // decides, and the command is named.
                ("common:ci=error", refreshed),
                ("common=update common:ci=error", refreshed),
                ("common=off common:ci=error", refreshed),
                ("common=error common:dev=update", frozen),
                ("common=off common:ci=off", unused),
                // A config that turns the lock off leaves the plain build
                // at its default; `mod` and `query` lines never reach it.
                ("common:ci=off", default),
                ("mod=error query=error", default),
            ] {
                assert_eq!(on(rc, &at), expected, "{version}: {rc}");
            }
            // An rc file that was not read may set the flag.
            let files = Files::of(&[(".bazelrc", "try-import %workspace%/user.bazelrc\n")]);
            let unread = lock_use_of(&read_rc(&files).effective(&at), &at);
            assert_eq!(unread, refreshed, "{version}");
        }
        // `always` exists from 6.3.0: on a 6.x range the plain build may
        // run under `error`, which no user opted into by name.
        assert_eq!(on("always=error", &majors(6, 6)), frozen);
        assert_eq!(on("always=off", &majors(6, 6)), refreshed);
        assert_eq!(on("always=off", &line("6.6.0")), unused);

        let digest = |rc: &str| {
            let files = Files::of(&[(".bazelrc", rc)]);
            digest_function_tracked(&read_rc(&files).effective(&line("9.3.2")))
        };
        assert!(!digest("") && !digest("build --lockfile_mode=error\n"));
        assert!(digest("startup --digest_function=blake3\n"));
        assert!(digest("startup --digest_function=sha256\n"));
    }

    /// Design 2.10, the lock-refresh table: each kind of lock state
    /// against each lock use. Stale state is refused when frozen and works
    /// after when refreshed; facts or a listing alone work with the
    /// advisory that does not gate `vex`.
    #[test]
    fn the_lock_refresh_table_gives_one_outcome_per_state_and_lock_use() {
        let at = line("8.8.2");
        let toy_lock = lock("module_lock/stale-repair/bazel-8.8.2/baseline");
        let toy_facts = lock("module_lock/facts/toy/baseline");
        let family_a = lock("probe_vectors/lockfile/recorded-inputs/bazel-6.6.0/fresh/root");
        let listing = lock("module_lock/listing/9.3.2");
        let unreadable = ModuleLock::Unreadable;
        let future = ModuleLock::parse(br#"{"lockFileVersion": 99, "moduleExtensions": {}}"#);

        let dep_lock = [Write::changed("dep.lock")];
        let tags = [TOY];
        let tag_edit = [Write {
            tags_of: &tags,
            ..Write::changed("socket.MODULE.bazel")
        }];
        let root = [Write {
            tags_of: &tags,
            ..Write::changed(ROOT_MODULE)
        }];
        let created = [Write {
            entry_change: Some(".bazelignore"),
            ..Write::bytes(".bazelignore", b".socket/vendor\n")
        }];
        let facts = FactsEdit {
            extension: TOY,
            of: FactsOf::Keyed,
            removed: &["dep_a@index"],
            added: &[],
        };
        let both = with_facts(&dep_lock, facts);
        let row = |what: &str, lock: &ModuleLock, edit: Edit<'_>, outcomes: &str, gates_vex| {
            for (lock_use, expected) in USES.into_iter().zip(outcomes.split(" | ")) {
                let decision = decide(lock, &edit, lock_use, &cx(&at));
                assert_eq!(outcome(&decision), expected, "{what} {lock_use:?}");
                let refused = expected == "refused";
                let reason = refused.then_some(Reason::LockfileFrozen);
                assert_eq!(decision.reason(), reason, "{what}");
                assert_eq!(decision.builds_fail(), refused, "{what}");
                assert_eq!(decision.automatic_restore_allowed(), !refused, "{what}");
                // The command is always the plain refresh, and `vex`
                // waits for it exactly where evidence can show it ran.
                let advisory = decision.run_required();
                assert_eq!(advisory.is_some(), expected != "works", "{what}");
                if let Some(advisory) = advisory {
                    assert_eq!(advisory.kind.as_str(), "lockfile", "{what}");
                    assert_eq!(advisory.command, remedy::LOCK_REFRESH, "{what}");
                    assert_eq!(advisory.gates_vex, gates_vex, "{what} {lock_use:?}");
                    assert_eq!(advisory.platforms, [""; 0], "{what}");
                }
            }
        };
        let (after, advisory) = (
            "refused | works after | works",
            "refused | works, advisory | works",
        );
        let works = "works | works | works";
        row("recorded input", &toy_lock, writes(&dep_lock), after, true);
        row("facts", &toy_facts, both, advisory, false);
        row("usagesDigest", &toy_lock, writes(&tag_edit), after, true);
        row("moduleFileHash", &family_a, writes(&root), after, true);
        row("listing", &listing, writes(&created), advisory, false);
        row("unreadable", &unreadable, writes(&dep_lock), after, true);
        row("unknown shape", &future, writes(&dep_lock), after, true);
        // Facts beside a recorded input do not soften it.
        row("input and facts", &toy_lock, both, after, true);
        row("no lock", &ModuleLock::Absent, both, works, true);
        row("nothing written", &unreadable, Edit::default(), works, true);

        // What each row was.
        let general = || GENERAL.to_string();
        let usages = DerivedState::UsagesDigest {
            extension: TOY_ID.to_string(),
            platform: general(),
        };
        assert_eq!(stale(&toy_lock, &writes(&tag_edit)), [usages]);
        // A family-A lock hashes the root file: the tag is no second row.
        // The bytes the lock was written for are fresh.
        assert_eq!(
            stale(&family_a, &writes(&root)),
            [DerivedState::ModuleFileHash]
        );
        let untouched =
            bytes("probe_vectors/lockfile/recorded-inputs/bazel-6.6.0/fresh/root.MODULE.bazel");
        let same_bytes = [Write::bytes(ROOT_MODULE, &untouched)];
        assert_eq!(stale(&family_a, &writes(&same_bytes)), []);
        // A family-B lock records no root hash, and a tag of an extension
        // without an entry is lock-neutral.
        assert_eq!(stale(&toy_lock, &writes(&root[..1])).len(), 1);
        assert_eq!(stale(&toy_lock, &writes(&same_bytes)), []);
        assert_eq!(stale(&toy_facts, &writes(&tag_edit)), []);
        let listed = DerivedState::RecordedDir {
            path: String::new(),
            extension: TOY_ID.to_string(),
            platform: general(),
        };
        assert_eq!(stale(&listing, &writes(&created)), [listed]);
        let unknown = stale(&future, &writes(&dep_lock));
        let why = matches!(&unknown[..], [DerivedState::UnknownLockShape { why }] if why.contains("neither"));
        assert!(why, "{unknown:?}");

        // The evidence of a family-A root edit is the root hash, and a
        // lock that cannot be read is evidence of nothing.
        let root_proof = proof(&[ROOT_MODULE], &[], None);
        let on_disk =
            |bytes: &[u8]| evidence(&family_a, &view(&[(ROOT_MODULE, bytes)]), &root_proof);
        assert_eq!(on_disk(&untouched), Evidence::Holds);
        assert!(matches!(on_disk(b"edited\n"), Evidence::Pending { .. }));
        let none = view(&[]);
        let pending = matches!(
            evidence(&unreadable, &none, &root_proof),
            Evidence::Pending { .. }
        );
        assert!(pending);
        assert_eq!(
            evidence(&ModuleLock::Absent, &none, &root_proof),
            Evidence::Holds
        );
    }

    /// Probe L4.a: an entry keyed by OS and architecture is refreshed only
    /// on its own platform. Every key is its own row, the command names
    /// each, and after a macOS-only repair the Linux entry is still
    /// pending.
    #[test]
    fn every_platform_key_is_stale_refreshed_and_proven_on_its_own() {
        let after = bytes("module_lock/stale-repair/bazel-9.3.2/dep.lock.after");
        let pin = [Write::bytes("dep.lock", &after)];
        let edit = writes(&pin);
        let at = line("9.3.2");
        let both = lock("module_lock/eval-factors/9.3.2.two-platforms");
        let toy = |platform: &str| input("dep.lock", TOY_ID, platform);
        assert_eq!(stale(&both, &edit), [toy(LINUX), toy(OSX)]);
        let decision = decide(&both, &edit, LockUse::Refreshed, &cx(&at));
        let advisory = decision.run_required().unwrap();
        assert_eq!(advisory.platforms, [LINUX, OSX]);
        assert!(advisory.gates_vex);
        let InterimState::SelfHealing { command } = &decision.interim else {
            panic!("{decision:?}");
        };
        let each = "on each platform the lock records an entry for (os:linux,arch:aarch64; \
                    os:osx,arch:aarch64)";
        assert!(command.text().contains(each), "{}", command.text());

        let repaired = lock("module_lock/eval-factors/9.3.2.after-macos-repair");
        assert_eq!(stale(&repaired, &edit), [toy(LINUX)]);
        let pinned = view(&[("dep.lock", &after)]);
        let proof = proof(&["dep.lock"], &[TOY], Some("socket-patched-a-1.0"));
        let found = evidence(&repaired, &pinned, &proof);
        let Evidence::Pending { platforms, .. } = &found else {
            panic!("{found:?}");
        };
        assert_eq!(platforms, &[LINUX]);
        let detail = found.withhold(&cx(&at)).unwrap().detail;
        assert!(
            detail.contains("entry for (os:linux,arch:aarch64)"),
            "{detail}"
        );
    }

    /// Probe X4: under a non-default `--digest_function` no recorded value
    /// is the file's SHA-256. The entry counts as stale and its evidence
    /// stays pending, with the flag tracked or only its trace in the lock.
    #[test]
    fn a_digest_that_cannot_be_compared_is_stale_and_its_evidence_pending() {
        let file = bytes("probe_vectors/x4/inputs/lf.lock");
        let written = [Write::bytes("lf.lock", &file)];
        let files = view(&[("lf.lock", &file)]);
        let found = |lock: &ModuleLock, digest_function| {
            let proof = Proof {
                digest_function,
                ..proof(&["lf.lock"], &[], None)
            };
            let edit = Edit {
                digest_function,
                ..writes(&written)
            };
            let pending = matches!(evidence(lock, &files, &proof), Evidence::Pending { .. });
            (stale(lock, &edit).len(), pending)
        };
        let sha256 = lock("probe_vectors/x4/locks/9.3.2");
        assert_eq!(found(&sha256, false), (0, false));
        assert_eq!(found(&sha256, true), (1, true));
        for function in ["sha1", "blake3"] {
            let lock = lock(&format!("probe_vectors/x4/locks/9.3.2.digest-{function}"));
            assert_eq!(found(&lock, false), (1, true), "{function}");
        }
    }

    /// The rows a recognizer declares. A crate lock digest and a lock
    /// check are red under every lockfile mode, forward and restoring; a
    /// value the lane recomputes in the same transaction is not stale.
    #[test]
    fn declared_hub_state_is_red_unless_the_transaction_repairs_it() {
        let text = str::to_string;
        let crate_lock = DerivedState::CrateLockDigest {
            lockfile: text("cargo-bazel-lock.json"),
            input: text("Cargo.toml"),
            hub: text("crates"),
            system: DeclSystem::Bzlmod,
        };
        let check = |pip_compile| DerivedState::LockCheck {
            target: text("//third_party/py:requirements"),
            input: text("requirements_lock.txt"),
            pip_compile,
        };
        let cache_file = ".aspect/rules/external_repository_action_cache/npm_translate_lock_x";
        let cache_line = DerivedState::ActionCacheLine {
            file: text(cache_file),
            input: text("pnpm-lock.yaml"),
        };
        let resolved = DerivedState::ResolvedHash {
            file: text("maven_install.json"),
        };
        let checksum = DerivedState::ChecksumValue {
            file: text(ROOT_MODULE),
            key: text("rack-3.1.7"),
            input: text("Gemfile.lock"),
        };
        let at = line("8.8.2");
        let edit = |paths: &[&'static str], hub: &[DerivedState], repairs: &[&'static str]| {
            let written: Vec<Write<'_>> = paths.iter().map(|path| Write::changed(path)).collect();
            let edit = Edit {
                hub,
                repairs,
                ..writes(&written)
            };
            // The lockfile mode changes nothing for a declared row.
            let [frozen, refreshed, unused] =
                USES.map(|lock_use| decide(&ModuleLock::Absent, &edit, lock_use, &cx(&at)));
            assert_eq!((&frozen, &refreshed), (&refreshed, &unused));
            frozen
        };
        let remedy_of = |decision: &Decision| match &decision.interim {
            InterimState::Red { remedy, .. } => remedy.clone(),
            other => panic!("{other:?}"),
        };

        // The crate lock: `Cargo.lock` alone is no input of the digest.
        let rows = [crate_lock.clone()];
        assert_eq!(outcome(&edit(&["Cargo.lock"], &rows, &[])), "works");
        let red = edit(&["Cargo.toml", "Cargo.lock"], &rows, &[]);
        assert_eq!(red.reason(), Some(Reason::DerivedUnrepairable));
        assert!(!red.automatic_restore_allowed() && red.builds_fail());
        let repin = red.run_required().unwrap();
        assert_eq!(repin.kind.as_str(), "repin");
        assert_eq!(repin.command, "CARGO_BAZEL_REPIN=1 bazel mod deps");
        assert!(repin.gates_vex);
        // No repair makes an unrepairable row go away.
        let named = edit(&["Cargo.toml"], &rows, &["cargo-bazel-lock.json"]);
        assert_eq!(outcome(&named), "refused");

        // A lock check: refused, with the probe's procedure where one ran.
        let rows = [check(Some(Tri::No))];
        let red = edit(&["requirements_lock.txt"], &rows, &[]);
        assert_eq!(red.reason(), Some(Reason::LockCheckPresent));
        let remedy = remedy_of(&red);
        assert_eq!(remedy.steps.len(), 3);
        assert!(remedy
            .text()
            .contains("`//third_party/py:requirements_test`"));
        assert_eq!(red.run_required(), None);
        let rows = [check(None)];
        let remedy = remedy_of(&edit(&["requirements_lock.txt"], &rows, &[]));
        assert!(remedy.command.is_empty() && remedy.snippet().is_none());
        assert!(remedy.text().contains("drops the pin"));
        assert_eq!(
            outcome(&edit(&["requirements_other.txt"], &rows, &[])),
            "works"
        );

        // Values a lane recomputes: stale only when it does not.
        for (row, path, holder) in [
            (&cache_line, "pnpm-lock.yaml", cache_file),
            (&resolved, "maven_install.json", "maven_install.json"),
            (&checksum, "Gemfile.lock", ROOT_MODULE),
        ] {
            let rows = [row.clone()];
            assert!(row.repairable() && !row.in_lock(), "{row:?}");
            assert_eq!(
                outcome(&edit(&[path], &rows, &[holder])),
                "works",
                "{row:?}"
            );
            let left = edit(&[path], &rows, &["another.file"]);
            assert_eq!(left.reason(), Some(Reason::DerivedUnrepairable), "{row:?}");
            assert_eq!(left.stale, rows, "{row:?}");
            assert_eq!(
                outcome(&edit(&["unrelated"], &rows, &[])),
                "works",
                "{row:?}"
            );
        }
        assert!(!crate_lock.repairable() && !check(None).repairable());
        assert!(crate_lock.gates_vex() && input("a", "b", "c").in_lock());
    }
}
