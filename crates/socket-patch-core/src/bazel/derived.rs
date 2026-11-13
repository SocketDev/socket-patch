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
use super::rc::{Chain, EffectiveFlags, Flag, FlagState, LockfileMode, OS_CONFIGS};
use super::remedy::{self, Remedy};
use super::version::{lockfile_mode_default, BazelLine, Tri};
use crate::crawlers::python_crawler::canonicalize_pypi_name;

/// The root module file, whose SHA-256 a family-A lock records.
const ROOT_MODULE: &str = "MODULE.bazel";

/// A module extension by the label of its `.bzl` file without the
/// repository (`//python/extensions:pip.bzl`) and its name, which is how
/// the lock is searched: the repository prefix changes with the Bazel
/// release.
///
/// Built only by [`ExtRef::new`], so every value is in the one spelling
/// the lock is matched on. A label in another spelling would match no
/// entry, and "no entry" reads as "nothing stale".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtRef<'a> {
    label: &'a str,
    name: &'a str,
}

impl<'a> ExtRef<'a> {
    /// The extension `name` of the file `bzl_file`, the label as
    /// `use_extension` or the lock spells it: `//pkg:file.bzl`, with or
    /// without a repository in front (`@repo`, `@@repo`, `@`, `@@`), which
    /// is dropped.
    ///
    /// `Err` for every other spelling: a relative label (`:file.bzl`,
    /// `file.bzl`), one that names no target (`//pkg`, `@repo`), and an
    /// empty extension name. Bazel resolves those against the file that
    /// holds them; the caller does that before it asks about the lock.
    pub const fn new(bzl_file: &'a str, name: &'a str) -> Result<Self, &'static str> {
        const RELATIVE: &str = "the label of an extension's `.bzl` file must start with `//`, or \
                                with a repository and `//`: no other spelling matches a lock entry";
        const NO_TARGET: &str = "the label of an extension's `.bzl` file must name the file \
                                 after one `:`";
        let bytes = bzl_file.as_bytes();
        // The repository, if any, ends where the first `//` starts.
        let mut at = 0;
        loop {
            if at + 1 >= bytes.len() {
                return Err(RELATIVE);
            }
            if bytes[at] == b'/' && bytes[at + 1] == b'/' {
                break;
            }
            let in_repository = bytes[0] == b'@' && bytes[at] != b'/' && bytes[at] != b':';
            if !in_repository {
                return Err(RELATIVE);
            }
            at += 1;
        }
        let (mut colons, mut index) = (0usize, at + 2);
        while index < bytes.len() {
            if bytes[index] == b':' {
                colons += 1;
            }
            index += 1;
        }
        if colons != 1 || bytes[bytes.len() - 1] == b':' {
            return Err(NO_TARGET);
        }
        if name.is_empty() {
            return Err("the name of an extension is not empty");
        }
        // `at` is the index of an ASCII `/`, so it is a character boundary.
        let (_, label) = bzl_file.split_at(at);
        Ok(Self { label, name })
    }

    /// The label of the `.bzl` file, without a repository.
    pub const fn label(&self) -> &'a str {
        self.label
    }

    /// The name the extension is bound to in that file.
    pub const fn name(&self) -> &'a str {
        self.name
    }
}

/// Which lock check a [`DerivedState::LockCheck`] is. What its own
/// regeneration does to the pin decides the remedy (remedy matrix 1.2,
/// rows 5 to 8 and 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockCheckKind {
    /// `compile_pip_requirements`: its `.update` keeps only what the `.in`
    /// source names, so it drops a pin written to the lock alone. The one
    /// check with a manual procedure a probe ran (Y6). `dot_test`: whether
    /// rules_python is proven at or above 1.5.0, which names the test
    /// `<name>.test`.
    PipCompile { dot_test: Tri },
    /// `gazelle_python_manifest`: its `.update` rewrites only the
    /// manifest, whose `integrity` covers the bytes of the lock. The lock
    /// and the pin in it stay.
    GazelleManifest,
    /// A diff test over a checked-in `requirements.bzl`: the file is
    /// derived from the lock by a target the project defines, and
    /// regenerating it keeps the pin.
    RequirementsBzl,
    /// A rules_uv `pip_compile` or a rules_python `lock`: the update
    /// resolves the lock again from its source and erases the pin. No
    /// procedure is known that keeps both the pin and a green check.
    Erasing,
}

impl LockCheckKind {
    /// How hard the check's own update is on the pin, hardest first. Of
    /// several checks over one lock the hardest decides the remedy: the
    /// update of a manifest keeps the pin only where no other check then
    /// erases it (design 6: "for a `gazelle_python_manifest` alone").
    const fn rank(self) -> u8 {
        match self {
            Self::Erasing => 0,
            Self::PipCompile { .. } => 1,
            Self::RequirementsBzl => 2,
            Self::GazelleManifest => 3,
        }
    }
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
    /// The lock holds facts for the hub's extension in a shape this
    /// version does not know (a `fact_version` of the future): a member
    /// it does not model could go stale unseen. A facts row like
    /// [`Self::Facts`], so it never gates `vex`: [`evidence`] reads no
    /// fact, and no command changes the shape.
    UnknownFactsShape { extension: String, why: String },
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
    /// The lock is unreadable or of a shape this version does not know:
    /// evidence degrades to no evidence, so what cannot be read is stale.
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
    /// the edit. What its own update command then does to the pin differs
    /// per check ([`LockCheckKind`]): three of them erase it, two do not.
    LockCheck {
        target: String,
        input: String,
        kind: LockCheckKind,
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
    /// refreshed. Not for facts (of a known shape or not) and directory
    /// records: their refresh leaves nothing socket-patch can check, the
    /// pin's digest is enforced at fetch, and a stale one fails closed or
    /// is refreshed by the next `update`-mode build. A row that gates is
    /// one [`evidence`] can see cleared; anything else would withhold the
    /// statement for good.
    pub const fn gates_vex(&self) -> bool {
        !matches!(
            self,
            Self::Facts { .. } | Self::UnknownFactsShape { .. } | Self::RecordedDir { .. }
        )
    }

    /// A row about the facts of an extension.
    const fn is_facts(&self) -> bool {
        matches!(self, Self::Facts { .. } | Self::UnknownFactsShape { .. })
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
    /// file itself, or the first directory that did not exist (or that
    /// the removal leaves empty and takes with it). A recorded listing of
    /// its parent gains or loses that entry. [`Write::created`] and
    /// [`Write::removed`] set it; a removal that leaves it `None` changes
    /// the listing of the file's own directory all the same, and
    /// [`stale`] counts it so.
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

    /// A file the edit creates with these bytes. `topmost` is the first
    /// directory on the way to it that did not exist; `None` when the
    /// file's own directory does, and the file is the new entry.
    pub const fn created(path: &'a str, after: &'a [u8], topmost: Option<&'a str>) -> Self {
        Self {
            entry_change: Some(Self::entry(path, topmost)),
            ..Self::bytes(path, after)
        }
    }

    /// A file the edit removes. `topmost` is the highest directory the
    /// removal takes with it; `None` when the file's own directory stays,
    /// and the file is the entry that goes.
    pub const fn removed(path: &'a str, topmost: Option<&'a str>) -> Self {
        Self {
            after: After::Removed,
            entry_change: Some(Self::entry(path, topmost)),
            ..Self::changed(path)
        }
    }

    const fn entry(path: &'a str, topmost: Option<&'a str>) -> &'a str {
        match topmost {
            Some(topmost) => topmost,
            None => path,
        }
    }

    /// The entry whose creation or removal changes a recorded listing.
    /// A removal always changes one, whatever `entry_change` says.
    fn listing_change(&self) -> Option<&'a str> {
        let removed = matches!(self.after, After::Removed).then_some(self.path);
        self.entry_change.or(removed)
    }
}

/// Which facts an extension stores, and how to look one package up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsOf<'a> {
    /// rules_python `pip`, for a requirements hub that resolves through a
    /// simple index. `removed` and `added` are SHA-256 digests, bare
    /// lowercase hex.
    ///
    /// The package's distributions are looked up under every index of
    /// `dist_hashes`, not only under the hub's: rules_python searches
    /// `extra_index_urls` before the default index, honours
    /// `index_url_overrides` per package, and files the fact under the
    /// root of the index that served the package (`simpleapi_download.bzl`
    /// and `pypi_cache.bzl` at 2.5.0-rc4). A forward edit also stales the
    /// package's member of `index_urls`, which rules_python drops once the
    /// package is no longer looked up in an index.
    ///
    /// `package` is the name in any spelling. Both sides are compared
    /// under PEP 503 normalization (lowercase; a run of `-`, `_` and `.`
    /// is one `-`), so `typing_extensions` and `Typing.Extensions` find
    /// the fact rules_python keys `typing-extensions`.
    ///
    /// `index_url` is the hub's own index, for messages. The verdict
    /// never depends on it.
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
            FactsOf::Pip { package, .. } => {
                let pip = found.pip()?;
                let wanted = canonicalize_pypi_name(package);
                let same = |name: &str| canonicalize_pypi_name(name) == wanted;
                // Under any index: held where one holds the digest, and
                // not comparable where one cannot be compared.
                let held = |digest: &&str| {
                    let mut all = FactDigest::NotHeld;
                    for index in &pip.dist_hashes {
                        for member in index.packages.iter().filter(|p| same(&p.name)) {
                            match pip.holds_digest(&index.url, &member.name, digest) {
                                FactDigest::Held => return FactDigest::Held,
                                FactDigest::CannotTell => all = FactDigest::CannotTell,
                                FactDigest::NotHeld => {}
                            }
                        }
                    }
                    all
                };
                let gone = |digest| held(digest) != FactDigest::NotHeld;
                let back = |digest| held(digest) != FactDigest::Held;
                // Which index serves a package is a fact of its own, and
                // a package that leaves the index loses it.
                let mut listed = pip.index_packages.iter().flat_map(|(_, names)| names);
                let leaves_an_index = !self.removed.is_empty() && listed.any(|name| same(name));
                leaves_an_index || self.removed.iter().any(gone) || self.added.iter().any(back)
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
                    return Some(DerivedState::UnknownFactsShape {
                        extension: facts.id.raw.clone(),
                        why,
                    });
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
                    let listing = write.listing_change();
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

/// A [`FlagState::Possible`] key of the command with no `--config`: the
/// plain reading, or one that only a release of the line or the working
/// directory decides (a bracketed condition).
fn plain_reading(key: &str) -> bool {
    key.is_empty() || key.starts_with('[')
}

/// A [`FlagState::Possible`] key of an OS section (`build:linux`), which
/// `--enable_platform_specific_config` applies by itself on that host
/// OS, with or without a bracketed condition after it.
fn os_reading(key: &str) -> bool {
    OS_CONFIGS.iter().any(|os| {
        let rest = key.strip_prefix(os);
        rest.is_some_and(|rest| rest.is_empty() || rest.starts_with(" ["))
    })
}

/// The lock use that the state of `--lockfile_mode` on one command chain
/// gives on `line`, read without `--enable_platform_specific_config`.
/// [`lock_use_of`] is the answer for a workspace.
///
/// A value that only a release of the line or the working directory
/// decides (a bracketed reading) is a value of the plain command: `error`
/// there is no named config a user opts into, so it freezes the lock.
pub fn lock_use(mode: &FlagState<String>, line: &BazelLine) -> LockUse {
    lock_use_on(mode, line, false)
}

/// [`lock_use`]; with `os_sections`, a value of an OS section counts as
/// one of the plain command.
fn lock_use_on(mode: &FlagState<String>, line: &BazelLine, os_sections: bool) -> LockUse {
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
            let plain = |key: &String| plain_reading(key) || (os_sections && os_reading(key));
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

/// What the plain `bazel build` and `bazel test` of the tracked rc files
/// do with the lock (D5): frozen when either is, unused only when both
/// are. `test` inherits `build`, so its own lines can only add to it, and
/// a `test --lockfile_mode=error` line fails the plain `bazel test` on a
/// stale lock although the build passes.
///
/// Two things a single [`FlagState`] does not say are read here:
///
/// - `--enable_platform_specific_config`. Where the plain command sets or
///   may set it, Bazel applies the section of the host OS (`build:linux`)
///   with no `--config`, so `error` there freezes the lock on that OS,
///   and the lock is committed for every OS. Set only under a config, the
///   flag leaves the OS sections the named configs they are. Bazel expands
///   the OS section where the flag stands, so a later plain line can
///   override it; that order is not modelled, which only over-refuses.
/// - The files that were not read ([`EffectiveFlags::gaps`]). A state is
///   the value in what was read, and an unread file may set `update` or
///   `error` after an `off` that was: the lock is then not proven unused,
///   and the command is named.
pub fn lock_use_of(flags: &EffectiveFlags, line: &BazelLine) -> LockUse {
    let on = |chain| {
        let os_sections = match flags.state(Flag::PlatformSpecificConfig, chain) {
            FlagState::Set(value) => value == "true",
            FlagState::Possible(by_reading) => {
                let mut readings = by_reading.iter();
                readings.any(|(key, value)| plain_reading(key) && value == "true")
            }
            _ => false,
        };
        lock_use_on(&flags.state(Flag::LockfileMode, chain), line, os_sections)
    };
    match [on(Chain::Build), on(Chain::Test)] {
        [LockUse::Frozen, _] | [_, LockUse::Frozen] => LockUse::Frozen,
        [LockUse::Unused, LockUse::Unused] if flags.gaps().is_empty() => LockUse::Unused,
        _ => LockUse::Refreshed,
    }
}

/// Whether a tracked rc file sets or may set `startup --digest_function`
/// to a function other than SHA-256. Bazel's default is SHA-256 and its
/// converter takes `SHA-256` and `SHA256` in any case
/// (`DigestHashFunction.java`), so a line that spells out the default
/// leaves every recorded digest comparable.
pub fn digest_function_tracked(flags: &EffectiveFlags) -> bool {
    let state = flags.state(Flag::DigestFunction, Chain::Startup);
    let default = |value: &&String| {
        let name = value.to_ascii_lowercase();
        name == "sha256" || name == "sha-256"
    };
    !state.values().iter().all(default)
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

/// Whether `MODULE.bazel.lock` holds facts or can come to hold them, which
/// is when the refresh advisory carries the conditional sentence about
/// `bazel clean --expunge` (design 7): the lock cannot be read, the Bazel
/// that wrote it stores facts (a `facts` member, empty or not), or `stale`
/// has a facts row. "Holds a fact now" is too narrow: the state those
/// releases hide needs only an `update`-mode evaluation and an older lock
/// put back (probe L3.c), and an edit that returns a package to the index
/// gives a lock with `"facts": {}` its first fact.
///
/// The one rule for `remedy::Cx::facts_in_lock`: [`decide`] and
/// [`Evidence::withhold`] apply it, and a caller that builds a refresh
/// remedy itself does the same.
pub fn facts_in_lock(lock: &ModuleLock, stale: &[DerivedState]) -> bool {
    let stores_facts = lock
        .extensions()
        .is_none_or(|recorded| recorded.stores_facts);
    stores_facts || stale.iter().any(DerivedState::is_facts)
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
/// `cx.facts_in_lock` is not read: it is [`facts_in_lock`] of `lock` and
/// the stale rows.
pub fn decide(
    lock: &ModuleLock,
    edit: &Edit<'_>,
    lock_use: LockUse,
    cx: &remedy::Cx<'_>,
) -> Decision {
    let stale = stale(lock, edit);
    let cx = remedy::Cx {
        facts_in_lock: facts_in_lock(lock, &stale),
        ..*cx
    };
    let done = |interim, advisory| Decision {
        stale: stale.clone(),
        interim,
        advisory,
    };
    // The first declared row, and of several lock checks the hardest.
    let declared = stale.iter().filter(|state| !state.in_lock());
    let hardest = declared.min_by_key(|state| match state {
        DerivedState::LockCheck { kind, .. } => kind.rank(),
        _ => 0,
    });
    if let Some(what) = hardest {
        let remedy = match what {
            DerivedState::CrateLockDigest { hub, system, .. } => remedy::repin(&cx, hub, *system),
            DerivedState::LockCheck { target, kind, .. } => match kind {
                LockCheckKind::PipCompile { dot_test } => {
                    Some(remedy::pip_compile_snippet(target, *dot_test))
                }
                LockCheckKind::GazelleManifest => Some(remedy::gazelle_manifest(target)),
                LockCheckKind::RequirementsBzl => Some(remedy::requirements_bzl()),
                LockCheckKind::Erasing => None,
            },
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
    /// The lock records an input of the lane (or, in family A, the root
    /// module file it wrote) and a tracked `startup --digest_function`
    /// line makes Bazel record digests that are not SHA-256. No record can
    /// be compared with its file and no command changes that (probe X4),
    /// so `vex` waits for as long as the line is tracked. `why` is the
    /// whole detail: it names no command.
    Incomparable { why: String },
    /// Entries with a fresh digest and repository specs from before the
    /// pin, which is what a hand-resolved merge of the lock leaves. They
    /// pass `--lockfile_mode=error`, build the unpatched package in every
    /// mode, and the refresh does not heal them (probe L1.d). `platforms`
    /// are the keys of every such entry of `extension`; empty for the one
    /// entry of an extension that is not keyed by platform.
    DerivedStale {
        extension: String,
        platforms: Vec<String>,
    },
}

impl Evidence {
    /// The withheld statement, with the remedy in its detail. `lock` is
    /// the lock the evidence was read from: `cx.facts_in_lock` is not
    /// read, it is [`facts_in_lock`] of that lock.
    pub fn withhold(&self, lock: &ModuleLock, cx: &remedy::Cx<'_>) -> Option<VexWithhold> {
        let cx = remedy::Cx {
            facts_in_lock: facts_in_lock(lock, &[]),
            ..*cx
        };
        let (kind, detail) = match self {
            Self::Holds => return None,
            Self::Pending { platforms, why } => {
                let command = remedy::lock_refresh(&cx, platforms).text();
                (WithholdKind::RunPending, format!("{why}. {command}"))
            }
            Self::Incomparable { why } => (WithholdKind::RunPending, why.clone()),
            Self::DerivedStale {
                extension,
                platforms,
            } => {
                let remedy = remedy::delete_entry(extension, platforms);
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
    let root_hash = match lock {
        ModuleLock::FamilyA(graph) if proof.inputs.contains(&ROOT_MODULE) => Some(graph),
        _ => None,
    };
    // Only what the lock records can be out of reach: a lock that records
    // none of the inputs holds, whatever the digest function.
    if proof.digest_function && (root_hash.is_some() || !recording.is_empty()) {
        let why = "A tracked `startup --digest_function` line makes Bazel record digests in \
                   MODULE.bazel.lock that are not SHA-256, so its records cannot be compared \
                   with the files. No command changes that: the statement is withheld while \
                   the line is tracked.";
        return Evidence::Incomparable {
            why: why.to_string(),
        };
    }
    let root_behind = root_hash.is_some_and(|graph| {
        let root = files.read(ROOT_MODULE);
        !root.as_bytes().is_some_and(|b| graph.module_file_fresh(b))
    });
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
    let mut forged = lacking.clone().filter(records_an_input);
    if let Some(first) = forged.next() {
        // Every forged entry of that extension: the remedy deletes each,
        // and each is written again only on its own platform (probe L4).
        let same_extension = forged.filter(|entry| entry.id.raw == first.id.raw);
        let mut platforms: Vec<String> = Vec::new();
        for entry in std::iter::once(first).chain(same_extension) {
            if entry.platform != GENERAL && !platforms.contains(&entry.platform) {
                platforms.push(entry.platform.clone());
            }
        }
        return Evidence::DerivedStale {
            extension: first.id.raw.clone(),
            platforms,
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
    const PIP: ExtRef<'static> = ext("//python/extensions:pip.bzl", "pip");
    const TOY: ExtRef<'static> = ext("//:ext.bzl", "toy");
    const TOY_ID: &str = "//:ext.bzl%toy";
    /// six 1.17.0, the wheel the pip cells replace.
    const SIX: &str = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
    const LINUX: &str = "os:linux,arch:aarch64";
    const OSX: &str = "os:osx,arch:aarch64";
    const USES: [LockUse; 3] = [LockUse::Frozen, LockUse::Refreshed, LockUse::Unused];

    /// An extension by a label [`ExtRef::new`] takes.
    const fn ext(label: &'static str, name: &'static str) -> ExtRef<'static> {
        match ExtRef::new(label, name) {
            Ok(ext) => ext,
            Err(_) => panic!("not the label of an extension's `.bzl` file"),
        }
    }

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
            // The hub's own index does not narrow the lookup: the fact is
            // filed under the index that served the package, which an
            // extra index or a per-package override makes another one.
            let other = "https://example.test/simple";
            assert_eq!(state("baseline", other, &[digest], &[]), pip, "{dir}");
            assert_eq!(state("bazel-repaired", other, &[digest], &[]), []);
            assert_eq!(state("bazel-repaired", other, &[], &[digest]), pip);
            // A `uv_lock` hub has no facts of its own: no probe, no row,
            // whatever the lock holds for rules_python's own hubs.
            let baseline = lock(&format!("module_lock/facts/{dir}/baseline"));
            assert_eq!(stale(&baseline, &writes(&lock_input)), [], "{dir}");
        }

        // gazelle: any Go edit can change the one list, and Bazel's
        // refresh does not return it to its first bytes, so the repaired
        // lock stays "possibly stale" where Bazel then passed.
        let go_deps = FactsEdit {
            extension: ext("//:extensions.bzl", "go_deps"),
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
        let crates = ext("//rs:extensions.bzl", "crate");
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
        // Facts of a shape this reader does not know are a facts row of
        // their own, stale and not only "possibly": a `fact_version` of
        // the future, facts that are no object, a list that is none. Like
        // every facts row it never gates `vex`: no fact is part of the
        // evidence, and no command changes the shape.
        let v3 = holding(r#"{"fact_version": "v3", "dist_hashes": {}}"#);
        let go_deps = FactsOf::GoDeps;
        let at = line("8.8.2");
        for (extension, of) in [(PIP, pip), (TOY, keyed), (TOY, go_deps), (PIP, go_deps)] {
            let facts = FactsEdit {
                extension,
                of,
                removed: &[],
                added: &[],
            };
            let edit = with_facts(&dep_lock, facts);
            let found = stale(&v3, &edit);
            let [DerivedState::UnknownFactsShape { extension: id, why }] = &found[..] else {
                panic!("{extension:?} {of:?}: {found:?}");
            };
            assert!(id.ends_with(&format!("{}%{}", extension.label(), extension.name())));
            assert!(!why.is_empty() && !found[0].gates_vex() && found[0].in_lock());

            // Refused when frozen; otherwise works with the advisory, and
            // the advisory says what the evidence says: `vex` does not
            // wait, because nothing the command writes would end the wait.
            let [frozen, refreshed, unused] =
                USES.map(|lock_use| decide(&v3, &edit, lock_use, &cx(&at)));
            assert_eq!(outcome(&frozen), "refused", "{extension:?} {of:?}");
            assert_eq!(frozen.reason(), Some(Reason::LockfileFrozen));
            assert_eq!(
                outcome(&refreshed),
                "works, advisory",
                "{extension:?} {of:?}"
            );
            assert_eq!(outcome(&unused), "works", "{extension:?} {of:?}");
            let gates_vex = refreshed.run_required().unwrap().gates_vex;
            let hub = [extension];
            let found = evidence(&v3, &view(&[]), &proof(&["dep.lock"], &hub, Some("pin")));
            assert_eq!(gates_vex, found != Evidence::Holds, "{extension:?} {of:?}");
            assert!(!gates_vex);
        }
    }

    /// Source-verified on rules_python 2.5.0-rc4: a fact is filed under
    /// the root of the index that served the package, with the name
    /// hyphenated, and the index that serves a package is a fact of its
    /// own (`index_urls`) that goes when the package leaves the index.
    #[test]
    fn pip_facts_are_found_under_any_index_and_any_spelling_of_the_name() {
        const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let extra = "https://extra.example/simple";
        let lock = |index_urls: &str| {
            ModuleLock::parse(
                format!(
                    r#"{{"lockFileVersion": 28, "registryFileHashes": {{}}, "facts": {{
                    "@@rules_python+//python/extensions:pip.bzl%pip": {{
                        "fact_version": "v2",
                        "dist_hashes": {{
                            "https://pypi.org/simple": {{"six": {{
                                "https://f.test/six.whl": "sha256:{OTHER}"}}}},
                            "{extra}": {{"typing-extensions": {{
                                "https://f.test/te.whl": "sha256:{DIGEST}"}}}}
                        }}{index_urls}
                    }}}}}}"#
                )
                .as_bytes(),
            )
        };
        let written = [Write::changed("requirements_lock.txt")];
        let rows = |lock: &ModuleLock, index_url, package, removed: &[&str], added: &[&str]| {
            let facts = FactsEdit {
                extension: PIP,
                of: FactsOf::Pip { index_url, package },
                removed,
                added,
            };
            stale(lock, &with_facts(&written, facts))
        };
        let held = lock("");
        let at = line("8.8.2");
        for index_url in [PYPI, extra, "https://unrelated.test/simple"] {
            for package in [
                "typing-extensions",
                "typing_extensions",
                "Typing.Extensions",
                "TYPING__EXTENSIONS",
            ] {
                let what = format!("{index_url} {package}");
                let forward = rows(&held, index_url, package, &[DIGEST], &[]);
                assert!(
                    matches!(&forward[..], [DerivedState::Facts { .. }]),
                    "{what}: {forward:?}"
                );
                // The restoring edit finds the digest it puts back, and a
                // digest the lock does not hold is a fact to come.
                assert_eq!(
                    rows(&held, index_url, package, &[], &[DIGEST]),
                    [],
                    "{what}"
                );
                assert_eq!(rows(&held, index_url, package, &[], &[OTHER]).len(), 1);
                assert_eq!(rows(&held, index_url, package, &[OTHER], &[]), [], "{what}");

                // Under an unconditional `error` the forward edit is
                // refused, which is what Bazel's `has changed its facts`
                // would otherwise say after the write.
                let facts = FactsEdit {
                    extension: PIP,
                    of: FactsOf::Pip { index_url, package },
                    removed: &[DIGEST],
                    added: &[],
                };
                let edit = with_facts(&written, facts);
                let frozen = decide(&held, &edit, LockUse::Frozen, &cx(&at));
                assert_eq!(frozen.reason(), Some(Reason::LockfileFrozen), "{what}");
            }
            // Another package's fact is not this one's.
            assert_eq!(rows(&held, index_url, "typing", &[DIGEST], &[]), []);
            assert_eq!(rows(&held, index_url, "six", &[DIGEST], &[]), []);
        }

        // `index_urls`: the package leaves the index on a forward edit and
        // its member goes, whatever digests the lock holds for it.
        let listed = lock(
            r#", "index_urls": {"https://extra.example/simple/":
                {"typing-extensions": "https://extra.example/simple/typing-extensions/"}}"#,
        );
        for package in ["typing_extensions", "Typing-Extensions"] {
            assert_eq!(rows(&listed, PYPI, package, &[OTHER], &[]).len(), 1);
            assert_eq!(rows(&held, PYPI, package, &[OTHER], &[]), [], "{package}");
            // Nothing leaves the index on a restoring edit.
            assert_eq!(
                rows(&listed, PYPI, package, &[], &[DIGEST]),
                [],
                "{package}"
            );
        }
        assert_eq!(rows(&listed, PYPI, "six", &[DIGEST], &[]), []);
    }

    /// Design 7: the conditional `bazel clean --expunge` sentence rides on
    /// the advisory wherever the lock holds facts or can come to hold
    /// them, on a line that includes 8.5 to 9.2. A lock with `"facts": {}`
    /// gains its first fact when a package returns to the index, and a
    /// lock that cannot be read may hold any.
    #[test]
    fn the_expunge_sentence_follows_the_lock_and_not_the_callers_flag() {
        const EXPUNGE: &str = "clean --expunge";
        let parse = |json: &str| ModuleLock::parse(json.as_bytes());
        let empty_facts =
            parse(r#"{"lockFileVersion": 28, "registryFileHashes": {}, "facts": {}}"#);
        let no_facts = parse(r#"{"lockFileVersion": 13, "registryFileHashes": {}}"#);
        let dep_lock = [Write::changed("dep.lock")];
        let gains = FactsEdit {
            extension: TOY,
            of: FactsOf::Keyed,
            removed: &[],
            added: &["dep_a@index"],
        };
        let texts = |lock: &ModuleLock, edit: &Edit<'_>, version: &str, caller_says: bool| {
            let at = line(version);
            let cx = remedy::Cx {
                facts_in_lock: caller_says,
                ..cx(&at)
            };
            let refreshed = decide(lock, edit, LockUse::Refreshed, &cx);
            let advisory = match (&refreshed.interim, &refreshed.advisory) {
                (InterimState::SelfHealing { command }, None) => command.text(),
                (InterimState::Green, Some(advisory)) => advisory.text(),
                other => panic!("{other:?}"),
            };
            let frozen = decide(lock, edit, LockUse::Frozen, &cx);
            let InterimState::Red { remedy, .. } = &frozen.interim else {
                panic!("{frozen:?}");
            };
            [advisory, remedy.text()].map(|text| text.contains(EXPUNGE))
        };
        for caller_says in [false, true] {
            // The lock that gains a fact, and the one that cannot be read.
            let edit = with_facts(&dep_lock, gains);
            assert_eq!(stale(&empty_facts, &edit).len(), 1);
            assert_eq!(texts(&empty_facts, &edit, "8.8.2", caller_says), [true; 2]);
            let unreadable = ModuleLock::Unreadable;
            let edit = writes(&dep_lock);
            assert_eq!(texts(&unreadable, &edit, "8.8.2", caller_says), [true; 2]);
            // Outside 8.5 to 9.2 nothing is hidden, and a Bazel 7 lock
            // stores no fact on any line.
            assert_eq!(texts(&unreadable, &edit, "7.7.2", caller_says), [false; 2]);
            assert_eq!(texts(&unreadable, &edit, "9.3.2", caller_says), [false; 2]);
            let toy_lock = lock("module_lock/stale-repair/bazel-7.7.2/baseline");
            assert_eq!(texts(&toy_lock, &edit, "8.8.2", caller_says), [false; 2]);
        }
        assert!(facts_in_lock(&empty_facts, &[]));
        assert!(facts_in_lock(&ModuleLock::Unreadable, &[]));
        assert!(facts_in_lock(&ModuleLock::UnknownShape(String::new()), &[]));
        assert!(!facts_in_lock(&no_facts, &[]) && !facts_in_lock(&ModuleLock::Absent, &[]));
        let row = DerivedState::Facts {
            extension: TOY_ID.to_string(),
        };
        assert!(facts_in_lock(&no_facts, &[row]));

        // The withheld detail follows the same rule, from the lock the
        // evidence was read from.
        let at = line("8.8.2");
        let pending = Evidence::Pending {
            platforms: Vec::new(),
            why: "why".to_string(),
        };
        for caller_says in [false, true] {
            let cx = remedy::Cx {
                facts_in_lock: caller_says,
                ..cx(&at)
            };
            let detail = |lock: &ModuleLock| pending.withhold(lock, &cx).unwrap().detail;
            assert!(detail(&empty_facts).contains(EXPUNGE));
            assert!(detail(&ModuleLock::Unreadable).contains(EXPUNGE));
            assert!(!detail(&no_facts).contains(EXPUNGE));
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
                platforms: Vec::new(),
            };
            assert_eq!(forged, entry, "{release}");
            // However `use_extension` spells the file, the ref is the one
            // the lock is searched by; and a ref of another file names no
            // entry, which holds (a reproducible extension has none).
            for spelling in ["@@//:ext.bzl", "@//:ext.bzl", "@toy_repo//:ext.bzl"] {
                let hub = [ExtRef::new(spelling, "toy").unwrap()];
                assert_eq!(found("forged", &hub, pin), entry, "{release} {spelling}");
            }
            let other = [ext("//:other.bzl", "toy")];
            assert_eq!(found("forged", &other, pin), Evidence::Holds, "{release}");
            // With no hub named, the entry that records the input must
            // carry the pin.
            assert_eq!(found("forged", &[], pin), entry, "{release}");
            assert_eq!(found("updated", &[], pin), Evidence::Holds, "{release}");
            // Where the specs do not carry the digest, equality stands
            // alone; and an empty pin proves nothing.
            assert_eq!(found("forged", &[TOY], None), Evidence::Holds, "{release}");
            assert_eq!(found("updated", &[TOY], Some("")), entry, "{release}");

            let at = line(release);
            let withheld = forged.withhold(&read("forged"), &cx(&at)).unwrap();
            let code = |kind| Code::withheld(kind).as_str();
            assert_eq!(code(withheld.kind), "vex_bazel_derived_stale");
            let remedy = "Delete the `//:ext.bzl%toy` entry under `moduleExtensions` in \
                          MODULE.bazel.lock. Run `bazel mod deps --lockfile_mode=update`";
            assert!(withheld.detail.starts_with(remedy), "{}", withheld.detail);
            let baseline = read("baseline");
            let waiting = pending.withhold(&baseline, &cx(&at)).unwrap();
            assert_eq!(code(waiting.kind), "vex_bazel_run_pending");
            let command = "Run `bazel mod deps --lockfile_mode=update`";
            assert!(waiting.detail.contains(command), "{}", waiting.detail);
            assert_eq!(Evidence::Holds.withhold(&baseline, &cx(&at)), None);

            // What Bazel's `error` mode sees: the forged lock is current
            // for the pinned file, the first lock is not; and the
            // restoring edit is stale on the refreshed lock alone.
            let toy = vec![input("dep.lock", TOY_ID, GENERAL)];
            let rows = |name: &str, write: Write<'_>| stale(&read(name), &writes(&[write]));
            let forward = Write::bytes("dep.lock", &after);
            let restore = Write::bytes("dep.lock", &before);
            assert_eq!(rows("forged", forward), [], "{release}");
            assert_eq!(rows("baseline", forward), toy, "{release}");
            assert_eq!(rows("updated", forward), [], "{release}");
            assert_eq!(rows("updated", restore), toy, "{release}");
            assert_eq!(rows("baseline", restore), [], "{release}");
            // A removed file, and an edit whose bytes are not known yet
            // (the gate runs before the rewriter): never fresh.
            for name in ["baseline", "updated", "forged"] {
                let removed = Write::removed("dep.lock", None);
                assert_eq!(rows(name, removed), toy, "{release} {name}");
                let planned = Write::changed("dep.lock");
                assert_eq!(rows(name, planned), toy, "{release} {name}");
            }

            // The rows that are found by the extension: a tag edit and an
            // edit of a `.bzl` file it loads, by any spelling of the ref.
            let usages = DerivedState::UsagesDigest {
                extension: TOY_ID.to_string(),
                platform: GENERAL.to_string(),
            };
            let loaded = DerivedState::BzlTransitiveDigest {
                path: "defs.bzl".to_string(),
                extension: TOY_ID.to_string(),
                platform: GENERAL.to_string(),
            };
            let baseline = read("baseline");
            for spelling in ["//:ext.bzl", "@@//:ext.bzl", "@toy_repo//:ext.bzl"] {
                let refs = [ExtRef::new(spelling, "toy").unwrap()];
                let tag_edit = Write {
                    tags_of: &refs,
                    ..Write::changed("socket.MODULE.bazel")
                };
                let bzl_edit = Write {
                    loaded_by: &refs,
                    ..Write::changed("defs.bzl")
                };
                let found = stale(&baseline, &writes(&[tag_edit, bzl_edit]));
                let family_b = matches!(baseline, ModuleLock::FamilyB(_));
                let expected: Vec<DerivedState> = family_b
                    .then(|| usages.clone())
                    .into_iter()
                    .chain([loaded.clone()])
                    .collect();
                assert_eq!(found, expected, "{release} {spelling}");
            }
        }
    }

    /// A ref is built in one spelling or not at all: a label that Bazel
    /// would resolve against the file that holds it matches no lock
    /// entry, and "no entry" reads as "nothing stale".
    #[test]
    fn an_extension_ref_takes_an_absolute_label_and_drops_its_repository() {
        let same = ext("//python/extensions:pip.bzl", "pip");
        for spelling in [
            "//python/extensions:pip.bzl",
            "@rules_python//python/extensions:pip.bzl",
            "@@rules_python+//python/extensions:pip.bzl",
            "@@rules_python~0.31.0//python/extensions:pip.bzl",
            "@//python/extensions:pip.bzl",
            "@@//python/extensions:pip.bzl",
        ] {
            let built = ExtRef::new(spelling, "pip").expect(spelling);
            assert_eq!(built, same, "{spelling}");
            assert_eq!(built.label(), "//python/extensions:pip.bzl");
            assert_eq!(built.name(), "pip");
        }
        assert_eq!(ext("@@//:ext.bzl", "toy"), TOY);
        assert_eq!(TOY.label(), "//:ext.bzl");
        for refused in [
            "",
            ":ext.bzl",
            "ext.bzl",
            "pkg:ext.bzl",
            "pkg/ext.bzl",
            "//pkg",
            "//pkg/ext.bzl",
            "//pkg:",
            "//",
            "@repo",
            "@repo//pkg",
            "@repo:ext.bzl",
            "@re/po//pkg:ext.bzl",
            "//pkg:a:b",
            "/pkg:ext.bzl",
        ] {
            assert!(ExtRef::new(refused, "toy").is_err(), "{refused:?}");
        }
        assert!(ExtRef::new("//:ext.bzl", "").is_err());
        // A facts row is found by the ref too.
        let facts = lock("module_lock/facts/toy/baseline");
        for spelling in ["@@//:ext.bzl", "@toy_repo//:ext.bzl"] {
            let edit = FactsEdit {
                extension: ExtRef::new(spelling, "toy").unwrap(),
                of: FactsOf::Keyed,
                removed: &["dep_a@index"],
                added: &[],
            };
            let found = stale(&facts, &with_facts(&[Write::changed("dep.lock")], edit));
            let row = DerivedState::Facts {
                extension: TOY_ID.to_string(),
            };
            assert!(found.contains(&row), "{spelling}: {found:?}");
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
            let loaders = [ExtRef::new(label, name).unwrap()];
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
        let rc_of = |spec: &str| -> String {
            let mode =
                |(section, mode): (&str, &str)| format!("{section} --lockfile_mode={mode}\n");
            let lines = spec
                .split(' ')
                .filter_map(|setting| setting.split_once('='));
            lines.map(mode).collect()
        };
        let of_files =
            |files: &Files, line: &BazelLine| lock_use_of(&read_rc(files).effective(line), line);
        let on = |spec: &str, line: &BazelLine| {
            of_files(&Files::of(&[(".bazelrc", rc_of(spec).as_str())]), line)
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
                // The plain `bazel test` counts as the plain build does
                // (D5): `test` inherits `build`, and its own line fails
                // the tests on a stale lock although the build passes.
                ("test=error", frozen),
                ("build=update test=error", frozen),
                ("build=off test=update", refreshed),
                ("build=off test=off", unused),
                ("test=off", default),
                ("test:ci=error", refreshed),
                ("run=error coverage=error", default),
                // An OS section is a named config while nothing turns
                // `--enable_platform_specific_config` on.
                ("build:linux=error", refreshed),
                ("common:macos=error common:windows=error", refreshed),
            ] {
                assert_eq!(on(rc, &at), expected, "{version}: {rc}");
            }
            // With the flag on the plain build, Bazel applies the section
            // of the host OS by itself: `error` there freezes the lock on
            // that OS, and the lock is committed for every OS.
            let platform = "--enable_platform_specific_config";
            for (flag_line, rc, expected) in [
                ("build", "build:linux=error", frozen),
                ("common", "build:linux=error", frozen),
                ("common", "common:macos=error", frozen),
                ("build", "common:windows=error", frozen),
                ("build", "build:freebsd=error", frozen),
                ("build", "build:openbsd=error", frozen),
                ("build", "common=update build:linux=error", frozen),
                (
                    "build",
                    "common:linux=error common:macos=error common:windows=error",
                    frozen,
                ),
                ("build", "test:linux=error", frozen),
                ("test", "test:linux=error", frozen),
                // Another config stays one, and so does an OS section when
                // the flag is itself set only under a config or for a
                // command the build does not inherit from.
                ("build", "build:ci=error", refreshed),
                ("build", "build:linux=update", refreshed),
                ("common:ci", "build:linux=error", refreshed),
                ("build:linux", "build:linux=error", refreshed),
                ("query", "build:linux=error", refreshed),
            ] {
                let rc = format!("{flag_line} {platform}\n{}", rc_of(rc));
                let found = of_files(&Files::of(&[(".bazelrc", rc.as_str())]), &at);
                assert_eq!(found, expected, "{version}:\n{rc}");
            }
            let off = format!("build --no{}\n", &platform[2..]);
            let rc = format!("{off}{}", rc_of("build:linux=error"));
            let found = of_files(&Files::of(&[(".bazelrc", rc.as_str())]), &at);
            assert_eq!(found, refreshed, "{version}:\n{rc}");

            // An rc file that was not read may set the flag: after an
            // `off` that was read too, wherever the import stands. The
            // lock is then not proven unused, for an optional file and
            // for one Bazel is sure to load alike.
            let absent = "try-import %workspace%/user.bazelrc\n";
            let unreadable = "import %workspace%/ci.bazelrc\n";
            let off = rc_of("common=off");
            for rc in [
                absent.to_string(),
                unreadable.to_string(),
                format!("{off}{absent}"),
                format!("{absent}{off}"),
                format!("{off}{unreadable}"),
                format!("{unreadable}{off}"),
            ] {
                let files = Files::of(&[(".bazelrc", rc.as_str())])
                    .with("ci.bazelrc", FileText::Unreadable);
                assert_eq!(of_files(&files, &at), refreshed, "{version}:\n{rc}");
            }
            // Read, the same files prove it, and `error` in what was read
            // stays frozen whatever was not.
            let read = Files::of(&[
                (
                    ".bazelrc",
                    "common --lockfile_mode=off\nimport %workspace%/ci.bazelrc\n",
                ),
                ("ci.bazelrc", "common:ci --lockfile_mode=off\n"),
            ]);
            assert_eq!(of_files(&read, &at), unused, "{version}");
            let rc = format!("{}{absent}", rc_of("common=error"));
            let found = of_files(&Files::of(&[(".bazelrc", rc.as_str())]), &at);
            assert_eq!(found, frozen, "{version}");
        }
        // The gap rows on the three lines the default differs on.
        for version in ["6.6.0", "7.7.2", "8.8.2"] {
            let at = line(version);
            for import in [
                "try-import %workspace%/user.bazelrc",
                "import %workspace%/ci.bazelrc",
            ] {
                let rc = format!("common --lockfile_mode=off\n{import}\n");
                let files = Files::of(&[(".bazelrc", rc.as_str())])
                    .with("ci.bazelrc", FileText::Unreadable);
                let flags = read_rc(&files).effective(&at);
                assert_eq!(flags.gaps().len(), 1, "{version}: {import}");
                let mode = flags.state(Flag::LockfileMode, Chain::Build);
                assert_eq!(mode, FlagState::Set("off".to_string()), "{version}");
                assert_eq!(lock_use(&mode, &at), unused, "{version}: {import}");
                assert_eq!(lock_use_of(&flags, &at), refreshed, "{version}: {import}");
            }
        }
        // One state alone does not see the test chain or the OS sections.
        let flags = |rc: &str| {
            let at = line("8.8.2");
            read_rc(&Files::of(&[(".bazelrc", rc)])).effective(&at)
        };
        let test_only = flags("test --lockfile_mode=error\n");
        let at = line("8.8.2");
        let build = test_only.state(Flag::LockfileMode, Chain::Build);
        assert_eq!(lock_use(&build, &at), refreshed);
        let test = test_only.state(Flag::LockfileMode, Chain::Test);
        assert_eq!(lock_use(&test, &at), frozen);
        assert_eq!(lock_use_of(&test_only, &at), frozen);
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
        assert!(digest("startup --digest_function=SHA-1\n"));
        // SHA-256 is Bazel's default, under either of its names and in any
        // case: a line that spells it out changes no recorded digest.
        for default in ["sha256", "SHA256", "sha-256", "SHA-256"] {
            assert!(!digest(&format!("startup --digest_function={default}\n")));
        }
        let mixed = "startup --digest_function=sha256\nstartup:linux --digest_function=blake3\n";
        assert!(digest(mixed));
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
        let created = [Write::created(".bazelignore", b".socket/vendor\n", None)];
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
        let detail = found.withhold(&repaired, &cx(&at)).unwrap().detail;
        assert!(
            detail.contains("entry for (os:linux,arch:aarch64)"),
            "{detail}"
        );
    }

    /// Probes L1.d and L4: a hand-merged lock can hold the forged state
    /// under one platform key or under each. Every forged key is named,
    /// only those members are deleted, and the command is named for the
    /// same keys: a member deleted on another platform would stay missing
    /// there, and its `error`-mode build would fail.
    #[test]
    fn every_forged_platform_member_is_named_and_no_other() {
        let before = bytes("module_lock/stale-repair/bazel-9.3.2/dep.lock.before");
        let after = bytes("module_lock/stale-repair/bazel-9.3.2/dep.lock.after");
        let (stale_digest, pinned_digest) = (
            crate::bazel::module_lock::sha256_hex(&before),
            crate::bazel::module_lock::sha256_hex(&after),
        );
        let text = |rel: &str| {
            let lock = bytes(&format!("module_lock/eval-factors/{rel}.MODULE.bazel.lock"));
            String::from_utf8(lock).expect("the lock is UTF-8")
        };
        let pinned = view(&[("dep.lock", &after)]);
        let proof = proof(&["dep.lock"], &[TOY], Some("socket-patched-a-1.0"));
        let found = |lock: &str| {
            let lock = ModuleLock::parse(lock.as_bytes());
            let found = evidence(&lock, &pinned, &proof);
            let at = line("9.3.2");
            let detail = found
                .withhold(&lock, &cx(&at))
                .map(|withheld| withheld.detail);
            (found, detail.unwrap_or_default())
        };
        let forged = |platforms: &[&str]| Evidence::DerivedStale {
            extension: TOY_ID.to_string(),
            platforms: platforms.iter().map(|key| key.to_string()).collect(),
        };

        // Both keys record the bytes from before the pin: forge both.
        let two = text("9.3.2.two-platforms");
        assert_eq!(two.matches(&stale_digest).count(), 2);
        let (evidence_of_both, detail) = found(&two.replace(&stale_digest, &pinned_digest));
        assert_eq!(evidence_of_both, forged(&[LINUX, OSX]));
        assert!(
            detail.starts_with(
                "Delete the `os:linux,arch:aarch64`, `os:osx,arch:aarch64` members of the \
                 `//:ext.bzl%toy` entry under `moduleExtensions` in MODULE.bazel.lock, and leave \
                 its other members. Run `bazel mod deps --lockfile_mode=update` on each of those \
                 platforms and commit the result"
            ),
            "{detail}"
        );

        // macOS was refreshed for real and Linux was merged by hand: only
        // the Linux member is forged, and only it is deleted.
        let repaired = text("9.3.2.after-macos-repair");
        assert_eq!(repaired.matches(&stale_digest).count(), 1);
        let (evidence_of_one, detail) = found(&repaired.replace(&stale_digest, &pinned_digest));
        assert_eq!(evidence_of_one, forged(&[LINUX]));
        assert!(
            detail.starts_with(
                "Delete the `os:linux,arch:aarch64` member of the `//:ext.bzl%toy` entry under \
                 `moduleExtensions` in MODULE.bazel.lock, and leave its other members. Run \
                 `bazel mod deps --lockfile_mode=update` on that platform and commit the result"
            ),
            "{detail}"
        );
        assert!(!detail.contains(OSX), "{detail}");

        // One key forged while the other is still behind: the refresh
        // comes first, and it is named for the platform that lacks it.
        let (behind, detail) = found(&two.replacen(&stale_digest, &pinned_digest, 1));
        let Evidence::Pending { platforms, .. } = &behind else {
            panic!("{behind:?}");
        };
        assert_eq!(platforms, &[OSX]);
        assert!(
            detail.contains("entry for (os:osx,arch:aarch64)"),
            "{detail}"
        );
    }

    /// Probe X4: under a non-default `--digest_function` no recorded value
    /// is the file's SHA-256. The entry counts as stale and its evidence
    /// stays pending, with the flag tracked or only its trace in the lock.
    /// With the flag tracked no command ends the wait, and none is named.
    #[test]
    fn a_digest_that_cannot_be_compared_is_stale_and_its_evidence_pending() {
        let file = bytes("probe_vectors/x4/inputs/lf.lock");
        let written = [Write::bytes("lf.lock", &file)];
        let files = view(&[("lf.lock", &file)]);
        let at = line("9.3.2");
        // The stale rows, the evidence, and whether the withheld detail
        // names the refresh.
        let found = |lock: &ModuleLock, inputs: &[&str], digest_function| {
            let proof = Proof {
                digest_function,
                ..proof(inputs, &[], None)
            };
            let edit = Edit {
                digest_function,
                ..writes(&written)
            };
            let found = evidence(lock, &files, &proof);
            let detail = found
                .withhold(lock, &cx(&at))
                .map(|withheld| withheld.detail);
            let names_refresh = detail.is_some_and(|detail| detail.contains(remedy::LOCK_REFRESH));
            let kind = match found {
                Evidence::Holds => "holds",
                Evidence::Pending { .. } => "pending",
                Evidence::Incomparable { .. } => "incomparable",
                Evidence::DerivedStale { .. } => "derived stale",
            };
            (stale(lock, &edit).len(), kind, names_refresh)
        };
        let input = &["lf.lock"][..];
        let sha256 = lock("probe_vectors/x4/locks/9.3.2");
        assert_eq!(found(&sha256, input, false), (0, "holds", false));
        // Tracked: stale, withheld, and no command that could never clear
        // it. The statement is withheld under the same code.
        assert_eq!(found(&sha256, input, true), (1, "incomparable", false));
        let tracked = Proof {
            digest_function: true,
            ..proof(input, &[], None)
        };
        let withheld = evidence(&sha256, &files, &tracked).withhold(&sha256, &cx(&at));
        let withheld = withheld.expect("withheld");
        assert_eq!(
            Code::withheld(withheld.kind).as_str(),
            "vex_bazel_run_pending"
        );
        assert!(
            withheld.detail.contains("cannot be compared"),
            "{}",
            withheld.detail
        );
        assert!(!withheld.detail.contains("bazel "), "{}", withheld.detail);
        // Only its trace in the lock: nothing says the function is not
        // SHA-256, and the record reads as the bytes from before the edit.
        for function in ["sha1", "blake3"] {
            let lock = lock(&format!("probe_vectors/x4/locks/9.3.2.digest-{function}"));
            assert_eq!(
                found(&lock, input, false),
                (1, "pending", true),
                "{function}"
            );
            assert_eq!(
                found(&lock, input, true),
                (1, "incomparable", false),
                "{function}"
            );
        }

        // What the lock does not record cannot be out of reach: no lock,
        // and a lock that records none of the lane's inputs, hold under a
        // tracked digest function too. Withholding there would be for
        // good, because no refresh adds a record.
        assert_eq!(found(&ModuleLock::Absent, input, true), (0, "holds", false));
        let unrecorded = &["other.lock"][..];
        for digest_function in [false, true] {
            let found = found(&sha256, unrecorded, digest_function);
            assert_eq!((found.1, found.2), ("holds", false), "{digest_function}");
        }
        let updated = lock("module_lock/stale-repair/bazel-8.8.2/updated");
        assert_eq!(found(&updated, unrecorded, true).1, "holds");
        // A family-A lock hashes the root module file, which is a record
        // of its own.
        let family_a = lock("probe_vectors/lockfile/recorded-inputs/bazel-6.6.0/fresh/root");
        let root =
            bytes("probe_vectors/lockfile/recorded-inputs/bazel-6.6.0/fresh/root.MODULE.bazel");
        let files = view(&[(ROOT_MODULE, &root)]);
        let root_proof = |digest_function| Proof {
            digest_function,
            ..proof(&[ROOT_MODULE], &[], None)
        };
        assert_eq!(
            evidence(&family_a, &files, &root_proof(false)),
            Evidence::Holds
        );
        let tracked = evidence(&family_a, &files, &root_proof(true));
        assert!(
            matches!(tracked, Evidence::Incomparable { .. }),
            "{tracked:?}"
        );
        // And an unreadable lock is evidence of nothing either way.
        let unreadable = evidence(&ModuleLock::Unreadable, &files, &root_proof(true));
        assert!(
            matches!(unreadable, Evidence::Pending { .. }),
            "{unreadable:?}"
        );
    }

    /// A removal always changes the listing of the file's directory, and
    /// a creation does when the lane says so. On a lock that records the
    /// listing of the root (`path.readdir()`), both stale the entry
    /// although no recorded file changes.
    #[test]
    fn a_created_or_removed_file_stales_a_recorded_listing() {
        let listing = lock("module_lock/listing/9.3.2");
        let listed = |path: &str| DerivedState::RecordedDir {
            path: path.to_string(),
            extension: TOY_ID.to_string(),
            platform: GENERAL.to_string(),
        };
        let rows = |write: Write<'_>| stale(&listing, &writes(&[write]));
        let at = line("9.3.2");
        let refused = |write: Write<'_>| {
            let edit = [write];
            decide(&listing, &writes(&edit), LockUse::Frozen, &cx(&at)).builds_fail()
        };
        let root = [listed("")];

        // Removed: the file is the entry that goes, with or without the
        // lane saying so; or the directory it was the last file of.
        let removed = Write::removed("requirements.txt", None);
        assert_eq!(rows(removed), root);
        assert!(refused(removed));
        let forgotten = Write {
            after: After::Removed,
            ..Write::changed("requirements.txt")
        };
        assert_eq!(forgotten.entry_change, None);
        assert_eq!(rows(forgotten), root);
        assert!(refused(forgotten));
        let with_its_directory = Write::removed(".socket/bazel/index.json", Some(".socket"));
        assert_eq!(rows(with_its_directory), root);
        // The file's own directory stays, and it is one no listing covers.
        let below = Write::removed(".socket/bazel/index.json", None);
        assert_eq!(rows(below), []);
        assert!(!refused(below));
        // `third_party` is listed too.
        let listed_below = Write::removed("third_party/new.lock", None);
        assert_eq!(rows(listed_below), [listed("third_party")]);

        // Created: the new entry is the file, or the first directory that
        // did not exist.
        let created = Write::created("pnpm-workspace.yaml", b"packages: []\n", None);
        assert_eq!(rows(created), root);
        assert!(refused(created));
        let in_a_new_directory = Write::created(".socket/bazel/index.json", b"{}", Some(".socket"));
        assert_eq!(rows(in_a_new_directory), root);
        let in_an_old_one = Write::created(".socket/bazel/index.json", b"{}", None);
        assert_eq!(rows(in_an_old_one), []);
        // An edit of an existing file changes no listing.
        assert_eq!(rows(Write::bytes("requirements.txt", b"six==1.17.0\n")), []);
        assert_eq!(rows(Write::changed("requirements.txt")), []);
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
        let check = |kind| DerivedState::LockCheck {
            target: text("//third_party/py:requirements"),
            input: text("requirements_lock.txt"),
            kind,
        };
        let pip_compile = LockCheckKind::PipCompile { dot_test: Tri::No };
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
        let rows = [check(pip_compile)];
        let red = edit(&["requirements_lock.txt"], &rows, &[]);
        assert_eq!(red.reason(), Some(Reason::LockCheckPresent));
        let remedy = remedy_of(&red);
        assert_eq!(remedy.steps.len(), 3);
        assert!(remedy
            .text()
            .contains("`//third_party/py:requirements_test`"));
        assert_eq!(red.run_required(), None);
        // Every lock check is refused, and only the checks whose update
        // resolves the lock again are said to drop the pin: a rules_uv
        // `pip_compile` and `lock`.
        let rows = [check(LockCheckKind::Erasing)];
        let red = edit(&["requirements_lock.txt"], &rows, &[]);
        assert_eq!(red.reason(), Some(Reason::LockCheckPresent));
        let remedy = remedy_of(&red);
        assert!(remedy.command.is_empty() && remedy.snippet().is_none());
        assert!(remedy.text().contains("drops the pin"));
        assert_eq!(
            outcome(&edit(&["requirements_other.txt"], &rows, &[])),
            "works"
        );
        // A gazelle manifest: the pin by hand, then the manifest's own
        // update, which rewrites the manifest alone (design 6).
        let rows = [check(LockCheckKind::GazelleManifest)];
        let red = edit(&["requirements_lock.txt"], &rows, &[]);
        assert_eq!(red.reason(), Some(Reason::LockCheckPresent));
        let remedy = remedy_of(&red);
        assert_eq!(
            remedy,
            remedy::gazelle_manifest("//third_party/py:requirements")
        );
        assert_eq!(
            remedy.command,
            "bazel run //third_party/py:requirements.update"
        );
        assert_eq!(remedy.steps.len(), 2);
        assert!(remedy.steps[1].contains("`bazel run //third_party/py:requirements.update`"));
        assert!(
            !remedy.text().contains("drops the pin"),
            "{}",
            remedy.text()
        );
        assert_eq!(red.run_required(), None);
        // A manifest beside another check is not "a manifest alone": the
        // check whose update is hardest on the pin decides, in whatever
        // order the recognizer declares them.
        let manifest = check(LockCheckKind::GazelleManifest);
        let generated = check(LockCheckKind::RequirementsBzl);
        let erasing = check(LockCheckKind::Erasing);
        for (rows, hardest) in [
            ([manifest.clone(), check(pip_compile)], check(pip_compile)),
            ([check(pip_compile), manifest.clone()], check(pip_compile)),
            ([manifest.clone(), erasing.clone()], erasing.clone()),
            ([check(pip_compile), erasing.clone()], erasing.clone()),
            ([manifest.clone(), generated.clone()], generated.clone()),
            ([generated.clone(), check(pip_compile)], check(pip_compile)),
        ] {
            let red = edit(&["requirements_lock.txt"], &rows, &[]);
            let InterimState::Red { what, .. } = &red.interim else {
                panic!("{red:?}");
            };
            assert_eq!(what, &hardest, "{rows:?}");
            assert_eq!(red.stale, rows);
            let alone = edit(&["requirements_lock.txt"], &[hardest], &[]);
            assert_eq!(remedy_of(&red), remedy_of(&alone), "{rows:?}");
        }
        // A checked-in `requirements.bzl`: the project's own target, which
        // keeps the pin.
        let rows = [check(LockCheckKind::RequirementsBzl)];
        let red = edit(&["requirements_lock.txt"], &rows, &[]);
        assert_eq!(red.reason(), Some(Reason::LockCheckPresent));
        let remedy = remedy_of(&red);
        assert_eq!(remedy, remedy::requirements_bzl());
        assert!(remedy.command.is_empty() && remedy.snippet().is_none());
        assert!(remedy.text().contains("does not drop the pin"));
        assert!(
            !remedy.text().contains("drops the pin"),
            "{}",
            remedy.text()
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
        assert!(!crate_lock.repairable() && !check(pip_compile).repairable());
        assert!(crate_lock.gates_vex() && input("a", "b", "c").in_lock());
    }
}
