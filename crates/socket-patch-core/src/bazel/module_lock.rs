//! `MODULE.bazel.lock`, read-only (design 2.8 and 2.10).
//!
//! socket-patch never writes this file. It reads it for two answers: which
//! version of a ruleset Bazel selected, and which of the lock's records go
//! stale when a file changes. A record this reader misses reads as
//! "nothing stale", and the next `--lockfile_mode=error` build then fails.
//! So every reader here fails closed: a lock it does not fully understand
//! is [`ModuleLock::UnknownShape`], which is never an error and never
//! evidence, and callers treat it as stale.
//!
//! The shape is decided by which keys are present, never by
//! `lockFileVersion`: release candidates write numbers of their own, and a
//! committed lock can come from one.
//!
//! - Family A (Bazel 6.2 - 7.1) writes the resolved module graph and the
//!   SHA-256 of the root `MODULE.bazel`, so its freshness can be checked.
//! - Family B (Bazel 7.2 and later) writes registry file hashes and no
//!   root-file hash. It cannot be proven fresh: after a root `bazel_dep`
//!   is removed it still names the old, higher version.
//!
//! Recorded inputs are read from three containers and from nowhere else.
//! The file is never searched for a path: a family-A lock also names an
//! input inside the tags of `moduleDepGraph`, where Bazel does not check
//! it.
//!
//! An extension that lists a directory records the listing, not the
//! files: [`RecordedDir`]. Creating `.bazelignore` or `.socket/` in a
//! listed root stales such a record although no recorded file changed.
//!
//! "Nothing recorded" and "not known" are different answers, and the
//! accessors keep them apart in the type: for a lock that is unreadable
//! or of an unknown shape every query returns `None`, and only an absent
//! lock answers `Some` of nothing.
//!
//! Non-ASCII paths. Bazel up to 8.7 writes its internal strings into the
//! lock, where each byte of a UTF-8 file name is one character
//! (`cafÃ©` for `café`); Bazel 8.8 and 9 write Unicode. The two older
//! containers are decoded when read, so a path here is always the name
//! on disk. Probed on macOS arm64 with Bazel 7.7.2, 8.7.0 and 9.3.2;
//! Linux and Windows are unprobed.

use serde_json::{Map, Value};

use super::model::{FileText, FileView};
use crate::formats::text::strip_bom_bytes;
use crate::utils::digest::sha256_hex_of;

/// The lock's path under a Bazel root.
pub const MODULE_LOCK: &str = "MODULE.bazel.lock";

/// The platform key of an entry that depends on neither OS nor
/// architecture. Any other key (`os:linux,arch:amd64`) is an entry Bazel
/// refreshes only on that platform.
pub const GENERAL: &str = "general";

/// `Err` carries why the lock is an unknown shape.
type Shape<T> = Result<T, String>;

/// The lock as found.
#[derive(Debug, Clone, PartialEq)]
pub enum ModuleLock {
    /// No lock file: Bazel resolves afresh and nothing can be stale.
    Absent,
    FamilyA(FamilyA),
    FamilyB(FamilyB),
    /// The file exists and its bytes could not be read. Not absent: it
    /// may record the file an edit changes.
    Unreadable,
    /// Bytes that are not a lock this reader knows, with the reason.
    UnknownShape(String),
}

/// A lock that holds the resolved module graph (`moduleDepGraph`).
#[derive(Debug, Clone, PartialEq)]
pub struct FamilyA {
    pub lock_file_version: Option<u64>,
    /// The SHA-256 Bazel recorded for the root `MODULE.bazel`.
    pub module_file_hash: String,
    /// The flags the graph was resolved under. `None` when the member is
    /// absent or not the shape Bazel 6.2 - 7.1 writes: nothing then says
    /// that Bazel reuses the graph.
    pub flags: Option<GraphFlags>,
    /// `localOverrideHashes`: the SHA-256 of the `MODULE.bazel` of every
    /// module that comes from a local path. Bazel's builtin `bazel_tools`
    /// is one, so a lock Bazel wrote always has that member. `None` as
    /// for [`Self::flags`].
    pub local_override_hashes: Option<Vec<(String, String)>>,
    /// Every module of the graph but the root.
    pub modules: Vec<GraphModule>,
    pub extensions: Extensions,
}

/// The members of a family-A lock's `flags` that decide which versions
/// Bazel selects. Bazel reuses the locked graph only while every recorded
/// flag, these included, equals its value on the running command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFlags {
    /// `cmdRegistries`: the `--registry` list in order, or Bazel's
    /// default list when the flag was not given.
    pub registries: Vec<String>,
    /// `cmdModuleOverrides`: module name and path of every
    /// `--override_module`.
    pub module_overrides: Vec<(String, String)>,
    /// `ignoreDevDependency`.
    pub ignore_dev_dependency: bool,
}

/// One `moduleDepGraph` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphModule {
    pub name: String,
    /// `None` for a `<name>@_` key: a non-registry override, whose
    /// version field is whatever the override target says about itself.
    pub version: Option<String>,
}

/// A lock that holds registry file hashes (`registryFileHashes`).
#[derive(Debug, Clone, PartialEq)]
pub struct FamilyB {
    pub lock_file_version: Option<u64>,
    /// The `.../modules/<name>/<version>/{MODULE.bazel,source.json}` keys.
    pub registry_files: Vec<RegistryFile>,
    pub extensions: Extensions,
}

/// One registry file of a module version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryFile {
    pub module: String,
    pub version: String,
    pub kind: RegistryFileKind,
    /// The key holds a SHA-256. `false` is Bazel's `not found` marker, or
    /// any other value: the registry did not serve the file.
    pub found: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryFileKind {
    /// `MODULE.bazel`: a version Bazel met during discovery.
    ModuleFile,
    /// `source.json`: a version Bazel selected.
    Source,
}

/// What both families record about module extensions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extensions {
    /// One entry per extension and platform key, in file order.
    pub entries: Vec<ExtensionEntry>,
    /// The top-level `facts` (Bazel 8.5 and later), one per extension.
    pub facts: Vec<ExtensionFacts>,
}

/// An extension id as the lock spells it: `<label>%<name>`, with a third
/// `%` part for an isolated usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionId {
    pub raw: String,
    /// The canonical repository of the `.bzl` file, `""` for the root
    /// module. Its spelling changes with the Bazel release
    /// (`rules_python~0.31.0`, `rules_python~`, `rules_python+`), so
    /// nothing is matched on it.
    pub repo: String,
    /// The label without its repository: `//python/extensions:pip.bzl`.
    pub label: String,
    pub name: String,
    pub isolated: bool,
}

impl ExtensionId {
    fn parse(raw: &str) -> Shape<Self> {
        let mut parts = raw.splitn(3, '%');
        let (label, name) = (parts.next().unwrap_or_default(), parts.next());
        let at = label.find("//");
        let (Some(name), Some(at)) = (name.filter(|n| !n.is_empty()), at) else {
            return Err(format!("extension id {raw:?} is not `<label>%<name>`"));
        };
        Ok(Self {
            raw: raw.to_string(),
            repo: label[..at].trim_start_matches('@').to_string(),
            label: label[at..].to_string(),
            name: name.to_string(),
            isolated: parts.next().is_some(),
        })
    }

    /// Whether this is the extension `name` of the file `label`
    /// (`//deps:paket.main_extension.bzl`), in any repository. Bazel
    /// writes a root-module id without `@@` and prints it with, and the
    /// repository of a ruleset changes spelling with the Bazel release.
    pub fn matches(&self, label: &str, name: &str) -> bool {
        self.label == label && self.name == name
    }

    /// The extension is defined in the root module.
    pub fn in_root_module(&self) -> bool {
        self.repo.is_empty()
    }
}

/// What the lock records about one extension on one platform. An
/// extension that returns `reproducible = True` has no entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensionEntry {
    pub id: ExtensionId,
    /// [`GENERAL`], or the OS and architecture the entry is valid for.
    pub platform: String,
    /// Stale when a `.bzl` file in the extension's load closure changes.
    /// The value differs per Bazel version and cannot be recomputed here.
    pub bzl_transitive_digest: Option<String>,
    /// Stale when a tag of the extension changes (family B).
    pub usages_digest: Option<String>,
    /// The main-repository files the extension read.
    pub inputs: Vec<RecordedInput>,
    /// The main-repository directories the extension depends on beyond
    /// the bytes of single files: a file created or removed in one of
    /// them stales the entry although no recorded file changed.
    pub dirs: Vec<RecordedDir>,
    /// The repositories the extension generated from those inputs.
    pub repo_specs: Vec<RepoSpec>,
}

impl ExtensionEntry {
    /// Whether any generated repository carries `needle` (a pin's digest
    /// in the ruleset's rendering). A recorded digest that matches the
    /// file proves only that the digest line is current: a hand-merged
    /// lock can hold a fresh digest beside old repository specs, which
    /// passes `--lockfile_mode=error` and builds the unpatched package.
    pub fn specs_mention(&self, needle: &str) -> bool {
        self.repo_specs.iter().any(|spec| spec.mentions(needle))
    }
}

/// One main-repository file an extension read, with the value Bazel
/// recorded for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedInput {
    /// Relative to the Bazel root, forward slashes.
    pub path: String,
    /// The key as the lock spells it, without the escapes of the
    /// `recordedInputs` form.
    pub key: String,
    /// The recorded value: the SHA-256 of the file's bytes under Bazel's
    /// default digest function.
    pub recorded: String,
}

/// One main-repository directory an extension depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedDir {
    /// Relative to the Bazel root, forward slashes; `""` is the root.
    pub path: String,
    /// The key as the lock spells it, without the escapes of the
    /// `recordedInputs` form.
    pub key: String,
    pub watch: DirWatch,
    /// Bazel's digest of the listing or the tree, or `DIR`. It is never
    /// recomputed here: [`Self::stale_when_created_or_removed`] and
    /// [`Self::stale_when_edited`] say which changes move it.
    pub recorded: String,
}

/// What an extension depends on in a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirWatch {
    /// That the path is a directory (a `FILE` record with the value
    /// `DIR`): stale when the directory is removed or becomes a file.
    Exists,
    /// The names directly inside it (`path.readdir()`; a `DIRENTS` item
    /// or a `recordedDirentsInputs` key): stale when an entry is created
    /// or removed there. The bytes of the entries do not count.
    Entries,
    /// Everything below it (a `DIRTREE` item): stale on any change under
    /// the directory. Bazel 10 can leave names out of the watch; they are
    /// not read here, so every path below counts.
    Tree,
}

impl RecordedDir {
    /// Whether creating or removing `path` (root-relative, a file or a
    /// directory) stales this record. A caller that creates
    /// `.socket/bazel/index.json` in a root without `.socket` asks about
    /// `.socket`: that is the entry the root's listing gains.
    pub fn stale_when_created_or_removed(&self, path: &str) -> bool {
        // The directory itself, or one above it, appears or disappears.
        let own = is_under(&self.path, path);
        match self.watch {
            DirWatch::Exists => own,
            DirWatch::Entries => own || parent_of(path) == Some(self.path.as_str()),
            DirWatch::Tree => own || is_under(path, &self.path),
        }
    }

    /// Whether changing the bytes of the existing file `path` stales
    /// this record. Only a watched tree digests file contents; such a
    /// record is never fresh after an edit below it.
    pub fn stale_when_edited(&self, path: &str) -> bool {
        self.watch == DirWatch::Tree && is_under(path, &self.path)
    }
}

/// Whether `path` is `dir` or lies below it; `""` is the root.
fn is_under(path: &str, dir: &str) -> bool {
    let rest = path.strip_prefix(dir);
    dir.is_empty() || rest.is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The directory that holds `path`; `None` for the root itself.
fn parent_of(path: &str) -> Option<&str> {
    match path.rsplit_once('/') {
        Some((parent, _)) => Some(parent),
        None => (!path.is_empty()).then_some(""),
    }
}

/// One `generatedRepoSpecs` member.
#[derive(Debug, Clone, PartialEq)]
pub struct RepoSpec {
    pub name: String,
    /// `<bzl file>%<rule>`, when the lock names one.
    pub rule: Option<String>,
    pub attributes: Value,
}

impl RepoSpec {
    /// Whether `needle` occurs in any string of the attributes, keys
    /// included. An empty needle is in nothing: it would prove everything.
    pub fn mentions(&self, needle: &str) -> bool {
        fn walk(value: &Value, needle: &str) -> bool {
            match value {
                Value::String(text) => text.contains(needle),
                Value::Array(items) => items.iter().any(|item| walk(item, needle)),
                Value::Object(members) => members
                    .iter()
                    .any(|(key, member)| key.contains(needle) || walk(member, needle)),
                _ => false,
            }
        }
        !needle.is_empty() && walk(&self.attributes, needle)
    }
}

/// How a recorded input compares with the file as found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputState {
    /// The recorded value is the SHA-256 of the file's bytes.
    Fresh,
    /// It is not, or the file is gone: an `error`-mode build that
    /// evaluates the extension fails.
    Stale,
    /// The comparison cannot be made: the recorded value is not a
    /// SHA-256 (a non-default `--digest_function`, or one of Bazel's
    /// markers for a directory or a missing file), or the file could not
    /// be read. Never taken for fresh.
    CannotCompare,
}

/// One recorded input with its state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InputVerdict<'a> {
    pub entry: &'a ExtensionEntry,
    pub input: &'a RecordedInput,
    pub state: InputState,
}

/// Compares a recorded value with the file as found. The digest is over
/// the raw bytes, so a line-ending flip of an untouched file is stale.
pub fn input_state(recorded: &str, file: &FileText) -> InputState {
    if !is_sha256(recorded) {
        return InputState::CannotCompare;
    }
    match file {
        FileText::Bytes(bytes) if sha256_hex(bytes) == recorded => InputState::Fresh,
        FileText::Bytes(_) | FileText::Absent => InputState::Stale,
        FileText::Unreadable => InputState::CannotCompare,
    }
}

/// Lowercase hex SHA-256, the form Bazel records.
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256_hex_of(bytes)
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

impl ModuleLock {
    /// Reads the lock of the Bazel root `files` views.
    pub fn read(files: &dyn FileView) -> Self {
        Self::from_file(&files.read(MODULE_LOCK))
    }

    pub fn from_file(file: &FileText) -> Self {
        match file {
            FileText::Bytes(bytes) => Self::parse(bytes),
            FileText::Absent => Self::Absent,
            FileText::Unreadable => Self::Unreadable,
        }
    }

    /// Parses the bytes of a lock. Bazel reads the file with a BOM, with
    /// CRLF line ends and with or without a final newline, so all of them
    /// are accepted here.
    pub fn parse(bytes: &[u8]) -> Self {
        let bytes = strip_bom_bytes(bytes);
        let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
            return Self::UnknownShape("the file is not JSON".to_string());
        };
        shape(&root).unwrap_or_else(Self::UnknownShape)
    }

    pub fn lock_file_version(&self) -> Option<u64> {
        match self {
            Self::FamilyA(lock) => lock.lock_file_version,
            Self::FamilyB(lock) => lock.lock_file_version,
            Self::Absent | Self::Unreadable | Self::UnknownShape(_) => None,
        }
    }

    /// What the lock records about extensions. `None` when that is not
    /// known (the lock is unreadable or of an unknown shape): the caller
    /// then treats every record as stale. An absent lock records
    /// nothing, which is `Some` of nothing.
    ///
    /// Every query below goes through here, so none of them can answer
    /// "not recorded" or "nothing stale" for a lock that was not read.
    pub fn extensions(&self) -> Option<&Extensions> {
        static NOTHING: Extensions = Extensions {
            entries: Vec::new(),
            facts: Vec::new(),
        };
        match self {
            Self::Absent => Some(&NOTHING),
            Self::FamilyA(lock) => Some(&lock.extensions),
            Self::FamilyB(lock) => Some(&lock.extensions),
            Self::Unreadable | Self::UnknownShape(_) => None,
        }
    }

    /// Every extension entry; `None` as for [`Self::extensions`].
    pub fn entries(&self) -> Option<&[ExtensionEntry]> {
        Some(&self.extensions()?.entries)
    }

    /// The facts of every extension; `None` as for [`Self::extensions`].
    pub fn facts(&self) -> Option<&[ExtensionFacts]> {
        Some(&self.extensions()?.facts)
    }

    /// The entries of one extension, one per platform key; `None` as for
    /// [`Self::extensions`].
    pub fn entries_of(&self, label: &str, name: &str) -> Option<Vec<&ExtensionEntry>> {
        Some(self.extensions()?.entries_of(label, name))
    }

    /// The facts of one extension; `None` as for [`Self::extensions`].
    pub fn facts_of(&self, label: &str, name: &str) -> Option<Vec<&ExtensionFacts>> {
        Some(self.extensions()?.facts_of(label, name))
    }

    /// Every record of the root-relative file `path`, under every
    /// extension and platform key; `None` as for [`Self::extensions`].
    pub fn recorded(&self, path: &str) -> Option<Vec<(&ExtensionEntry, &RecordedInput)>> {
        Some(self.extensions()?.recorded(path))
    }

    /// Every directory record, under every extension and platform key;
    /// `None` as for [`Self::extensions`].
    pub fn recorded_dirs(&self) -> Option<Vec<(&ExtensionEntry, &RecordedDir)>> {
        Some(self.extensions()?.recorded_dirs())
    }

    /// Every recorded input compared with the file `files` holds; `None`
    /// as for [`Self::extensions`]. A `Stale` row predicts that an
    /// `error`-mode build which evaluates that extension fails.
    pub fn input_verdicts(&self, files: &dyn FileView) -> Option<Vec<InputVerdict<'_>>> {
        Some(self.extensions()?.input_verdicts(files))
    }
}

impl Extensions {
    /// The entries of one extension, one per platform key.
    pub fn entries_of(&self, label: &str, name: &str) -> Vec<&ExtensionEntry> {
        let entries = self.entries.iter();
        entries
            .filter(|entry| entry.id.matches(label, name))
            .collect()
    }

    /// The facts of one extension.
    pub fn facts_of(&self, label: &str, name: &str) -> Vec<&ExtensionFacts> {
        let facts = self.facts.iter();
        facts
            .filter(|facts| facts.id.matches(label, name))
            .collect()
    }

    /// Every record of the root-relative file `path`.
    ///
    /// A path of an older container that could not be decoded is kept as
    /// the lock spells it, so a non-ASCII `path` is also looked up in
    /// that spelling: it never reads as not recorded for its spelling
    /// alone.
    pub fn recorded(&self, path: &str) -> Vec<(&ExtensionEntry, &RecordedInput)> {
        let internal = (!path.is_ascii()).then(|| to_internal(path));
        let same = |found: &str| found == path || internal.as_deref() == Some(found);
        let mut records = Vec::new();
        for entry in &self.entries {
            let inputs = entry.inputs.iter().filter(|input| same(&input.path));
            records.extend(inputs.map(|input| (entry, input)));
        }
        records
    }

    /// Every directory record.
    pub fn recorded_dirs(&self) -> Vec<(&ExtensionEntry, &RecordedDir)> {
        let entries = self.entries.iter();
        let dirs = entries.flat_map(|entry| entry.dirs.iter().map(move |dir| (entry, dir)));
        dirs.collect()
    }

    /// Every recorded input compared with the file `files` holds.
    pub fn input_verdicts(&self, files: &dyn FileView) -> Vec<InputVerdict<'_>> {
        let mut verdicts = Vec::new();
        for entry in &self.entries {
            for input in &entry.inputs {
                let state = input_state(&input.recorded, &files.read(&input.path));
                verdicts.push(InputVerdict {
                    entry,
                    input,
                    state,
                });
            }
        }
        verdicts
    }
}

impl FamilyA {
    /// Whether the lock was written for these root `MODULE.bazel` bytes.
    /// Any byte counts, a comment or a CRLF checkout included, so a
    /// mismatch means only that Bazel will resolve again.
    pub fn module_file_fresh(&self, module_file: &[u8]) -> bool {
        self.module_file_hash == sha256_hex(module_file)
    }

    /// The graph's entries for the module `name`.
    pub fn modules_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a GraphModule> {
        self.modules
            .iter()
            .filter(move |module| module.name == name)
    }
}

impl FamilyB {
    /// The versions of `module` Bazel selected: those with a
    /// `source.json` hash, from any registry.
    pub fn selected(&self, module: &str) -> Vec<&str> {
        let mut versions: Vec<&str> = Vec::new();
        for file in &self.registry_files {
            let selected = file.kind == RegistryFileKind::Source && file.found;
            if selected && file.module == module && !versions.contains(&file.version.as_str()) {
                versions.push(&file.version);
            }
        }
        versions
    }

    /// Whether Bazel met `module` at `version` during discovery: its
    /// `MODULE.bazel` has a hash. A superset of the selected versions.
    pub fn discovered(&self, module: &str, version: &str) -> bool {
        self.registry_files.iter().any(|file| {
            let module_file = file.kind == RegistryFileKind::ModuleFile && file.found;
            module_file && file.module == module && file.version == version
        })
    }
}

fn shape(root: &Value) -> Shape<ModuleLock> {
    let top = root.as_object().ok_or("the top level is not an object")?;
    let lock_file_version = top.get("lockFileVersion").and_then(Value::as_u64);
    let extensions = extensions(top)?;
    match (top.get("moduleDepGraph"), top.get("registryFileHashes")) {
        (Some(graph), None) => {
            let hash = top.get("moduleFileHash").and_then(Value::as_str);
            Ok(ModuleLock::FamilyA(FamilyA {
                lock_file_version,
                module_file_hash: hash.ok_or("moduleFileHash is not a string")?.to_string(),
                flags: graph_flags(top),
                local_override_hashes: top.get("localOverrideHashes").and_then(string_pairs),
                modules: graph_modules(object(graph, "moduleDepGraph")?)?,
                extensions,
            }))
        }
        (None, Some(hashes)) => Ok(ModuleLock::FamilyB(FamilyB {
            lock_file_version,
            registry_files: registry_files(object(hashes, "registryFileHashes")?),
            extensions,
        })),
        (Some(_), Some(_)) => Err("both moduleDepGraph and registryFileHashes".to_string()),
        (None, None) => Err("neither moduleDepGraph nor registryFileHashes".to_string()),
    }
}

fn object<'a>(value: &'a Value, what: &str) -> Shape<&'a Map<String, Value>> {
    let object = value.as_object();
    object.ok_or_else(|| format!("{what} is not an object"))
}

fn string<'a>(value: &'a Value, what: &str) -> Shape<&'a str> {
    let string = value.as_str();
    string.ok_or_else(|| format!("{what} is not a string"))
}

/// The members of an object whose values are all strings.
fn string_pairs(value: &Value) -> Option<Vec<(String, String)>> {
    let pair = |(key, value): (&String, &Value)| Some((key.clone(), value.as_str()?.to_string()));
    value.as_object()?.iter().map(pair).collect()
}

/// The three `flags` members that decide the selection. The other four
/// (yanked versions, and the modes of two checks) only add errors.
fn graph_flags(top: &Map<String, Value>) -> Option<GraphFlags> {
    let flags = top.get("flags")?.as_object()?;
    let registries = flags.get("cmdRegistries")?.as_array()?.iter();
    let registries = registries.map(|url| url.as_str().map(str::to_string));
    Some(GraphFlags {
        registries: registries.collect::<Option<_>>()?,
        module_overrides: string_pairs(flags.get("cmdModuleOverrides")?)?,
        ignore_dev_dependency: flags.get("ignoreDevDependency")?.as_bool()?,
    })
}

/// `<root>`, `<name>@<version>` or `<name>@_` keys.
fn graph_modules(graph: &Map<String, Value>) -> Shape<Vec<GraphModule>> {
    let mut modules = Vec::new();
    for (key, module) in graph {
        object(module, "a moduleDepGraph member")?;
        if key == "<root>" {
            continue;
        }
        let split = key.split_once('@');
        let Some((name, version)) = split.filter(|(n, v)| !n.is_empty() && !v.is_empty()) else {
            return Err(format!(
                "moduleDepGraph key {key:?} is not `<name>@<version>`"
            ));
        };
        modules.push(GraphModule {
            name: name.to_string(),
            version: (version != "_").then(|| version.to_string()),
        });
    }
    Ok(modules)
}

/// Keys are matched by their end, so the registry prefix and mirrors do
/// not matter. Other keys (`bazel_registry.json`) are not module files.
fn registry_files(hashes: &Map<String, Value>) -> Vec<RegistryFile> {
    let mut files = Vec::new();
    for (key, value) in hashes {
        let (rest, kind) = if let Some(rest) = key.strip_suffix("/source.json") {
            (rest, RegistryFileKind::Source)
        } else if let Some(rest) = key.strip_suffix("/MODULE.bazel") {
            (rest, RegistryFileKind::ModuleFile)
        } else {
            continue;
        };
        let mut segments = rest.rsplitn(4, '/');
        let (version, module, dir) = (segments.next(), segments.next(), segments.next());
        if let (Some(version), Some(module), Some("modules")) = (version, module, dir) {
            if !version.is_empty() && !module.is_empty() {
                files.push(RegistryFile {
                    module: module.to_string(),
                    version: version.to_string(),
                    kind,
                    found: value.as_str().is_some_and(is_sha256),
                });
            }
        }
    }
    files
}

fn extensions(top: &Map<String, Value>) -> Shape<Extensions> {
    let mut out = Extensions::default();
    // Absent only in the first lock version (Bazel 6.2), which recorded
    // no extension.
    if let Some(value) = top.get("moduleExtensions") {
        for (raw, platforms) in object(value, "moduleExtensions")? {
            let id = ExtensionId::parse(raw)?;
            for (platform, entry) in object(platforms, raw)? {
                let entry = entry_of(&id, platform, object(entry, raw)?)?;
                out.entries.push(entry);
            }
        }
    }
    if let Some(value) = top.get("facts") {
        for (raw, facts) in object(value, "facts")? {
            out.facts.push(ExtensionFacts {
                id: ExtensionId::parse(raw)?,
                value: facts.clone(),
            });
        }
    }
    Ok(out)
}

fn entry_of(id: &ExtensionId, platform: &str, entry: &Map<String, Value>) -> Shape<ExtensionEntry> {
    let mut records = Records::default();
    let mut containers = 0;
    // Lock version 3: label keys, `@@//<pkg>:<name>`.
    if let Some(value) = entry.get("accumulatedFileDigests") {
        containers += 1;
        for (key, recorded) in object(value, "accumulatedFileDigests")? {
            let recorded = string(recorded, "a recorded digest")?;
            if let Some(label) = main_repo(key) {
                let (package, name) = label
                    .split_once(':')
                    .ok_or_else(|| format!("recorded label {key:?} has no target"))?;
                let path = if package.is_empty() {
                    name.to_string()
                } else {
                    format!("{package}/{name}")
                };
                records.file(from_internal(&path), key, recorded)?;
            }
        }
    }
    // Lock versions 6 - 24: path keys, `@@//<path>`.
    if let Some(value) = entry.get("recordedFileInputs") {
        containers += 1;
        for (key, recorded) in object(value, "recordedFileInputs")? {
            let recorded = string(recorded, "a recorded digest")?;
            if let Some(path) = main_repo(key) {
                records.file(from_internal(path), key, recorded)?;
            }
        }
    }
    // The same lock versions keep directory listings beside the files.
    if let Some(value) = entry.get("recordedDirentsInputs") {
        for (key, recorded) in object(value, "recordedDirentsInputs")? {
            let recorded = string(recorded, "a recorded listing")?;
            if let Some(path) = main_repo(key) {
                records.dir(from_internal(path), key, recorded, DirWatch::Entries)?;
            }
        }
    }
    // Lock versions 26 and 28: `<KIND>:<escaped key> <escaped value>`.
    if let Some(value) = entry.get("recordedInputs") {
        containers += 1;
        let items = value.as_array().ok_or("recordedInputs is not an array")?;
        for item in items {
            let item = string(item, "a recordedInputs item")?;
            // Bazel splits at the first space, unescapes both parts and
            // takes the kind up to the first colon. A space inside either
            // part is written `\s`, so the first space is the only one.
            let parsed = item.split_once(' ').and_then(|(key, recorded)| {
                let key = unescape(key);
                let (kind, key) = key.split_once(':')?;
                Some((kind.to_string(), key.to_string(), unescape(recorded)))
            });
            let Some((kind, key, recorded)) = parsed else {
                return Err(format!(
                    "recorded input {item:?} is not `<KIND>:<key> <value>`"
                ));
            };
            // Environment variables, repository mappings, kinds this
            // reader does not know and keys of other repositories are
            // not records of a workspace path: skipped, not unknown.
            match (kind.as_str(), main_repo(&key)) {
                ("FILE", Some(path)) => records.file(path.to_string(), &key, &recorded)?,
                ("DIRENTS", Some(path)) => {
                    records.dir(path.to_string(), &key, &recorded, DirWatch::Entries)?;
                }
                ("DIRTREE", Some(path)) => {
                    // Bazel 10 appends the names it leaves out of the
                    // watch. A normalised path cannot hold `/../`.
                    let path = path
                        .split_once(TREE_EXCLUDES)
                        .map_or(path, |(path, _)| path);
                    records.dir(path.to_string(), &key, &recorded, DirWatch::Tree)?;
                }
                _ => {}
            }
        }
    }
    // An entry that names none of the three records its inputs somewhere
    // this reader does not look: reading it as "no inputs" would miss
    // every one of them.
    if containers == 0 {
        return Err(format!(
            "extension {:?} has no known input container",
            id.raw
        ));
    }
    let digest = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_string);
    Ok(ExtensionEntry {
        id: id.clone(),
        platform: platform.to_string(),
        bzl_transitive_digest: digest("bzlTransitiveDigest"),
        usages_digest: digest("usagesDigest"),
        inputs: records.inputs,
        dirs: records.dirs,
        repo_specs: repo_specs(entry)?,
    })
}

/// The path part of a main-repository key (`@@//x`, and the `@//x` and
/// `//x` spellings Bazel also parses as the main repository); empty for
/// the root, `@@//`. `None` for a path of another repository or an
/// absolute path: no edit of the workspace changes those.
fn main_repo(key: &str) -> Option<&str> {
    let label = key.strip_prefix("@@").or_else(|| key.strip_prefix('@'));
    label.unwrap_or(key).strip_prefix("//")
}

/// The value Bazel records for a path that is a directory.
const IS_DIRECTORY: &str = "DIR";

/// What follows the path of a `DIRTREE` key that leaves names out.
const TREE_EXCLUDES: &str = "?/../excludes=";

/// The main-repository records of one entry.
#[derive(Default)]
struct Records {
    inputs: Vec<RecordedInput>,
    dirs: Vec<RecordedDir>,
}

impl Records {
    /// A file record: the digest of a file, or `DIR` for a path that is
    /// a directory, which is no file an edit could stale.
    fn file(&mut self, path: String, key: &str, recorded: &str) -> Shape<()> {
        if recorded == IS_DIRECTORY {
            // The root is a directory in every workspace: Bazel records
            // it before it lists the root, and it cannot go stale.
            if path.is_empty() {
                return Ok(());
            }
            return self.dir(path, key, recorded, DirWatch::Exists);
        }
        normalised(&path, key, false)?;
        self.inputs.push(RecordedInput {
            path,
            key: key.to_string(),
            recorded: recorded.to_string(),
        });
        Ok(())
    }

    fn dir(&mut self, path: String, key: &str, recorded: &str, watch: DirWatch) -> Shape<()> {
        normalised(&path, key, true)?;
        self.dirs.push(RecordedDir {
            path,
            key: key.to_string(),
            watch,
            recorded: recorded.to_string(),
        });
        Ok(())
    }
}

/// Bazel writes normalised paths. Anything else cannot be matched with a
/// workspace path, and matching it loosely could miss the file. The empty
/// path is the root, which only a directory record can name.
fn normalised(path: &str, key: &str, root: bool) -> Shape<()> {
    let segments = || path.split('/');
    if (root && path.is_empty()) || segments().all(|s| !matches!(s, "" | "." | "..")) {
        return Ok(());
    }
    Err(format!("recorded input {key:?} is not a normalised path"))
}

/// The path a key of the two older containers names. Bazel 6.2 - 8.7
/// writes its internal strings into the lock: each byte of a UTF-8 file
/// name as one character, so `café` is spelled `cafÃ©`. A path that is
/// not such a string (a character above U+00FF, or bytes that are not
/// UTF-8) is kept as found.
fn from_internal(path: &str) -> String {
    if path.is_ascii() {
        return path.to_string();
    }
    let bytes: Option<Vec<u8>> = path.chars().map(|c| u8::try_from(c).ok()).collect();
    let decoded = bytes.and_then(|bytes| String::from_utf8(bytes).ok());
    decoded.unwrap_or_else(|| path.to_string())
}

/// `path` as Bazel 6.2 - 8.7 spells it: the inverse of [`from_internal`].
fn to_internal(path: &str) -> String {
    path.bytes().map(char::from).collect()
}

/// Undoes Bazel's escape of one part of a `recordedInputs` item: `\s` is
/// a space, `\n` a newline, any other escaped character is itself, and a
/// backslash that ends the text is dropped, as Bazel drops it.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
        } else if let Some(escaped) = chars.next() {
            out.push(match escaped {
                's' => ' ',
                'n' => '\n',
                other => other,
            });
        }
    }
    out
}

fn repo_specs(entry: &Map<String, Value>) -> Shape<Vec<RepoSpec>> {
    let mut specs = Vec::new();
    let Some(value) = entry.get("generatedRepoSpecs") else {
        return Ok(specs);
    };
    for (name, spec) in object(value, "generatedRepoSpecs")? {
        let spec = object(spec, "a generated repository spec")?;
        let text = |key: &str| spec.get(key).and_then(Value::as_str);
        // Lock versions up to 24 split the rule id in two members.
        let split = text("bzlFile").zip(text("ruleClassName"));
        let rule = text("repoRuleId").map(str::to_string);
        specs.push(RepoSpec {
            name: name.clone(),
            rule: rule.or_else(|| split.map(|(file, class)| format!("{file}%{class}"))),
            attributes: spec.get("attributes").cloned().unwrap_or(Value::Null),
        });
    }
    Ok(specs)
}

// ── Facts ────────────────────────────────────────────────────────────

/// The facts one extension stored in the lock, as found. Facts are shared
/// by every hub of the extension in the module graph, the hubs of other
/// modules included, so a member can legitimately remain after a refresh:
/// what they give is "possibly stale", never "stale".
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensionFacts {
    pub id: ExtensionId,
    pub value: Value,
}

/// rules_python `pip` facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipFacts {
    pub fact_version: PipFactVersion,
    /// `dist_hashes`: index URL, then normalized package, then
    /// distribution URL to digest.
    pub dist_hashes: Vec<PipIndex>,
    /// The packages of `index_urls`, per index URL.
    pub index_packages: Vec<(String, Vec<String>)>,
}

/// How `dist_hashes` renders a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipFactVersion {
    /// Bare SHA-256 hex (rules_python 2.0.3).
    V1,
    /// `<algo>:<hex>`, empty when the index gave none (2.5.0-rc4).
    V2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipIndex {
    pub url: String,
    pub packages: Vec<PipPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipPackage {
    pub name: String,
    /// Distribution URL and digest, the digest as found.
    pub dists: Vec<(String, String)>,
}

impl PipFacts {
    /// The distributions recorded for `package` (normalized) under the
    /// index `index_url`, compared without a trailing slash.
    pub fn dists(&self, index_url: &str, package: &str) -> &[(String, String)] {
        fn trim(url: &str) -> &str {
            url.trim_end_matches('/')
        }
        let mut indexes = self.dist_hashes.iter();
        let index = indexes.find(|index| trim(&index.url) == trim(index_url));
        let package = index.and_then(|index| index.packages.iter().find(|p| p.name == package));
        package.map_or(&[], |package| &package.dists)
    }

    /// Whether a distribution of `package` under `index_url` has the
    /// SHA-256 `sha256` (bare lowercase hex).
    ///
    /// rules_python stores whatever the index advertises: an empty
    /// digest when the link has no `#sha256=` fragment (2.0.3) or no
    /// fragment at all (2.5.0-rc4), and `md5:<hex>` for an index that
    /// publishes MD5, which is pypiserver's default. Such a distribution
    /// may be the pinned file, so the answer is then
    /// [`FactDigest::CannotTell`], and callers treat that as possibly
    /// stale, like [`FactDigest::Held`].
    pub fn holds_digest(&self, index_url: &str, package: &str, sha256: &str) -> FactDigest {
        let dists = self.dists(index_url, package);
        if dists.is_empty() {
            return FactDigest::NotHeld;
        }
        if !is_lower_sha256(sha256) {
            return FactDigest::CannotTell;
        }
        let mut cannot_tell = false;
        for (_, digest) in dists {
            // The SHA-256 of a distribution, in this fact version's
            // rendering; none for an empty digest or another algorithm.
            let hex = match self.fact_version {
                PipFactVersion::V1 => Some(digest.as_str()),
                PipFactVersion::V2 => digest.strip_prefix("sha256:"),
            };
            match hex.filter(|hex| is_lower_sha256(hex)) {
                Some(hex) if hex == sha256 => return FactDigest::Held,
                Some(_) => {}
                None => cannot_tell = true,
            }
        }
        if cannot_tell {
            FactDigest::CannotTell
        } else {
            FactDigest::NotHeld
        }
    }
}

/// Whether pip facts hold a pin's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactDigest {
    /// A distribution of the package has the digest.
    Held,
    /// The package has no distribution under that index, or each one has
    /// a SHA-256 and none is the digest.
    NotHeld,
    /// A distribution's digest is empty or not a SHA-256, or the digest
    /// asked for is not one: the two cannot be compared. Never taken for
    /// [`Self::NotHeld`].
    CannotTell,
}

/// A SHA-256 as an index publishes it and socket-patch renders it.
fn is_lower_sha256(text: &str) -> bool {
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    text.len() == 64 && text.bytes().all(lower_hex)
}

/// One member of gazelle's `required_mod_files_v1` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoModFact {
    pub importpath: String,
    pub sha256: String,
    pub version: String,
}

impl ExtensionFacts {
    /// The facts as rules_python's `pip` extension writes them. `Err` is
    /// an unknown shape: a member this reader does not model could go
    /// stale unseen, so the caller treats the facts as possibly stale.
    pub fn pip(&self) -> Result<PipFacts, String> {
        let facts = object(&self.value, "pip facts")?;
        let known = [
            "fact_version",
            "dist_hashes",
            "dist_filenames",
            "dist_yanked",
            "index_urls",
        ];
        if let Some(key) = facts.keys().find(|key| !known.contains(&key.as_str())) {
            return Err(format!("unknown pip facts member {key:?}"));
        }
        let fact_version = match facts.get("fact_version").and_then(Value::as_str) {
            Some("v1") => PipFactVersion::V1,
            Some("v2") => PipFactVersion::V2,
            other => return Err(format!("unknown pip fact_version {other:?}")),
        };
        let mut dist_hashes = Vec::new();
        for (url, packages) in members(facts, "dist_hashes")? {
            let mut index = PipIndex {
                url: url.clone(),
                packages: Vec::new(),
            };
            for (name, dists) in object(packages, "a dist_hashes index")? {
                let mut package = PipPackage {
                    name: name.clone(),
                    dists: Vec::new(),
                };
                for (dist, digest) in object(dists, "a dist_hashes package")? {
                    let digest = string(digest, "a dist_hashes digest")?;
                    package.dists.push((dist.clone(), digest.to_string()));
                }
                index.packages.push(package);
            }
            dist_hashes.push(index);
        }
        let mut index_packages = Vec::new();
        for (url, packages) in members(facts, "index_urls")? {
            let packages = object(packages, "an index_urls index")?;
            index_packages.push((url.clone(), packages.keys().cloned().collect()));
        }
        Ok(PipFacts {
            fact_version,
            dist_hashes,
            index_packages,
        })
    }

    /// The facts as gazelle's `go_deps` extension writes them: one
    /// ordered list, which can be empty. A rewrite adds a member; it does
    /// not replace one.
    pub fn go_deps(&self) -> Result<Vec<GoModFact>, String> {
        let facts = object(&self.value, "go_deps facts")?;
        let list = facts.get("required_mod_files_v1").and_then(Value::as_array);
        let (Some(list), 1) = (list, facts.len()) else {
            return Err("go_deps facts are not one required_mod_files_v1 list".to_string());
        };
        let mut out = Vec::new();
        for item in list {
            let item = object(item, "a required_mod_files_v1 member")?;
            let text = |key: &str| item.get(key).and_then(Value::as_str).map(str::to_string);
            let fields = (text("importpath"), text("sha256"), text("version"));
            let ((Some(importpath), Some(sha256), Some(version)), 3) = (fields, item.len()) else {
                return Err("a required_mod_files_v1 member has an unknown shape".to_string());
            };
            out.push(GoModFact {
                importpath,
                sha256,
                version,
            });
        }
        Ok(out)
    }

    /// The top-level keys, for facts keyed per package (rules_rs:
    /// `<name>_<version>`). `None` when the facts are not an object.
    pub fn keys(&self) -> Option<Vec<&str>> {
        let facts = self.value.as_object()?;
        Some(facts.keys().map(String::as_str).collect())
    }
}

/// The members of the object `facts[key]`; none when the key is absent.
fn members<'a>(facts: &'a Map<String, Value>, key: &str) -> Shape<Vec<(&'a String, &'a Value)>> {
    match facts.get(key) {
        Some(value) => Ok(object(value, key)?.iter().collect()),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PYPI: &str = "https://pypi.org/simple";
    const PIP: (&str, &str) = ("//python/extensions:pip.bzl", "pip");
    /// six 1.17.0, the wheel a hosted rewrite replaces in the pip cells.
    const SIX_1_17: &str = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel")
    }

    fn bytes(rel: &str) -> Vec<u8> {
        let path = fixtures().join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn lock(rel: &str) -> ModuleLock {
        ModuleLock::parse(&bytes(rel))
    }

    fn json(rel: &str) -> Value {
        serde_json::from_slice(&bytes(rel)).expect("fixture JSON")
    }

    fn text(value: &Value) -> &str {
        value.as_str().expect("a string in the vectors")
    }

    /// A workspace made of fixture files: `dir` is its root, and `renamed`
    /// maps a workspace path to the fixture that holds its bytes. No
    /// fixture has the name of a Bazel boundary file.
    struct Workspace {
        dir: PathBuf,
        renamed: Vec<(&'static str, String)>,
    }

    impl Workspace {
        fn new(dir: &str, renamed: &[(&'static str, &str)]) -> Self {
            let renamed = renamed.iter().map(|(at, file)| (*at, file.to_string()));
            Self {
                dir: fixtures().join(dir),
                renamed: renamed.collect(),
            }
        }
    }

    impl FileView for Workspace {
        fn read(&self, rel: &str) -> FileText {
            let renamed = self.renamed.iter().find(|(at, _)| *at == rel);
            let path = self.dir.join(renamed.map_or(rel, |(_, file)| file));
            match std::fs::read(path) {
                Ok(bytes) => FileText::Bytes(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileText::Absent,
                Err(_) => FileText::Unreadable,
            }
        }
        fn list(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }

    /// What a lock of a known family records. The queries on
    /// `ModuleLock` itself return `None` for any other lock.
    fn ext(lock: &ModuleLock) -> &Extensions {
        let known = matches!(lock, ModuleLock::FamilyA(_) | ModuleLock::FamilyB(_));
        assert!(known, "{lock:?}");
        lock.extensions().unwrap()
    }

    fn unknown(json: &str) -> bool {
        matches!(
            ModuleLock::parse(json.as_bytes()),
            ModuleLock::UnknownShape(_)
        )
    }

    /// A family-B lock with one extension entry.
    fn with_entry(entry: &str) -> String {
        format!(
            r#"{{"lockFileVersion": 28, "registryFileHashes": {{}},
                "moduleExtensions": {{"//:ext.bzl%toy": {{"general": {entry}}}}}}}"#
        )
    }

    fn states(lock: &ModuleLock, files: &dyn FileView) -> Vec<(String, String, InputState)> {
        let verdicts = ext(lock).input_verdicts(files);
        let row = |v: &InputVerdict<'_>| (v.entry.platform.clone(), v.input.path.clone(), v.state);
        verdicts.iter().map(row).collect()
    }

    /// The fixtures are byte-real: a recorded digest is over a file's
    /// bytes, so a checkout that converted line endings, or an edit of a
    /// fixture, would change what every test below proves.
    #[test]
    fn the_fixture_checksums_hold() {
        fn files(dir: &Path, out: &mut BTreeSet<PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("fixture directory") {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    files(&path, out);
                } else {
                    out.insert(path);
                }
            }
        }
        let dir = fixtures().join("module_lock");
        let mut on_disk = BTreeSet::new();
        files(&dir, &mut on_disk);
        assert!(on_disk.remove(&dir.join("SHA256SUMS")));

        let sums = String::from_utf8(bytes("module_lock/SHA256SUMS")).unwrap();
        let mut listed = BTreeSet::new();
        for line in sums.lines() {
            let (digest, file) = line.split_once("  ").expect("`<sha256>  <path>`");
            assert_eq!(
                sha256_hex(&bytes(&format!("module_lock/{file}"))),
                digest,
                "{file}"
            );
            listed.insert(dir.join(file));
        }
        assert_eq!(listed, on_disk);
        assert!(listed.len() >= 100);
        // No fixture is a file Bazel would take for a workspace boundary.
        let boundary = [
            "MODULE.bazel",
            "MODULE.bazel.lock",
            "BUILD.bazel",
            "WORKSPACE",
        ];
        let name = |path: &PathBuf| path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!listed
            .iter()
            .any(|path| boundary.contains(&name(path).as_str())));
    }

    /// Design 2.10 and probe L1: on 17 releases, fresh and stale, the
    /// static reading of every recorded input equals what Bazel did in
    /// `--lockfile_mode=error`. The vectors hold one byte-real lock for
    /// each lock version a pinned Bazel writes, and a sub-package input
    /// with a space in its name, which each of the three parsers spells
    /// differently.
    #[test]
    fn the_recorded_input_vectors_agree_with_bazel() {
        let index = json("probe_vectors/lockfile/vectors.json");
        let vectors = index["recorded_inputs"]["vectors"].as_array().unwrap();
        let (mut cases, mut versions) = (0, BTreeSet::new());
        for vector in vectors {
            for state in ["fresh", "stale"] {
                let dir = format!("probe_vectors/lockfile/{}/{state}", text(&vector["dir"]));
                let renamed = [
                    (MODULE_LOCK, "root.MODULE.bazel.lock"),
                    ("MODULE.bazel", "root.MODULE.bazel"),
                ];
                let files = Workspace::new(&dir, &renamed);
                let lock = ModuleLock::read(&files);
                let expected = json(&format!("{dir}/expected.json"));
                let version = expected["lockFileVersion"].as_u64();
                assert_eq!(lock.lock_file_version(), version, "{dir}");
                versions.insert(version.unwrap());

                let rows = expected["prototype"]["inputs"].as_array().unwrap();
                let verdicts = ext(&lock).input_verdicts(&files);
                assert_eq!(verdicts.len(), rows.len(), "{dir}");
                for (verdict, row) in verdicts.iter().zip(rows) {
                    assert_eq!(verdict.entry.id.raw, text(&row["extension"]), "{dir}");
                    assert_eq!(verdict.entry.platform, text(&row["factor"]), "{dir}");
                    assert_eq!(verdict.input.key, text(&row["key"]), "{dir}");
                    assert_eq!(verdict.input.path, text(&row["path"]), "{dir}");
                    assert_eq!(verdict.input.recorded, text(&row["recorded"]), "{dir}");
                    let fresh = verdict.state == InputState::Fresh;
                    assert_eq!(fresh, text(&row["state"]) == "fresh", "{dir}");
                    assert_ne!(verdict.state, InputState::CannotCompare, "{dir}");
                }
                let stale = verdicts.iter().any(|v| v.state == InputState::Stale);
                let bazel_failed = expected["bazel_error_mode_build_exit"] != 0;
                assert_eq!(stale, bazel_failed, "{dir}");

                // Family A exactly where the vectors say the lock records
                // the root file's hash; the root file is untouched in
                // both states.
                let module_file = files.read("MODULE.bazel");
                match &lock {
                    ModuleLock::FamilyA(graph) => {
                        assert_eq!(vector["family"], "A", "{dir}");
                        assert!(graph.module_file_fresh(module_file.as_bytes().unwrap()));
                    }
                    ModuleLock::FamilyB(_) => assert_eq!(vector["family"], "B", "{dir}"),
                    other => panic!("{dir}: {other:?}"),
                }
                cases += 1;
            }
        }
        assert_eq!(cases, 34);
        assert_eq!(
            versions.into_iter().collect::<Vec<_>>(),
            [3, 6, 11, 13, 16, 18, 24, 26, 28]
        );
    }

    /// Probe X4: nine inputs (LF, CRLF, BOM, no final newline, empty, not
    /// UTF-8, nested, a space in the name) on six byte-real locks. The
    /// recorded value is the SHA-256 of the bytes on disk, nothing
    /// normalised.
    #[test]
    fn the_x4_vectors_agree() {
        let index = json("probe_vectors/x4/vectors.json");
        let mut locks = 0;
        for cell in index["cells"].as_array().unwrap() {
            let Some(lock_file) = cell["lock_file"].as_str() else {
                continue;
            };
            let renamed = [(MODULE_LOCK, format!("../{lock_file}"))];
            let renamed: Vec<_> = renamed.iter().map(|(at, f)| (*at, f.as_str())).collect();
            let files = Workspace::new("probe_vectors/x4/inputs", &renamed);
            let lock = ModuleLock::read(&files);
            let verdicts = ext(&lock).input_verdicts(&files);
            let recorded = cell["recorded"].as_array().unwrap();
            assert_eq!(verdicts.len(), 9, "{lock_file}");
            for row in recorded {
                let path = text(&row["path"]);
                let verdict = verdicts.iter().find(|v| v.input.path == path);
                let verdict = verdict.unwrap_or_else(|| panic!("{lock_file}: {path} not read"));
                assert_eq!(verdict.input.recorded, text(&row["value"]), "{lock_file}");
                assert_eq!(verdict.state, InputState::Fresh, "{lock_file}: {path}");
                assert_eq!(verdict.entry.platform, GENERAL);
            }
            // The key spells the same file three ways.
            let key = |path: &str| ext(&lock).recorded(path)[0].1.key.clone();
            let nested = key("sub/pkg/deep/dir/file.lock");
            match text(&cell["container"]) {
                "accumulatedFileDigests" => assert_eq!(nested, "@@//sub/pkg:deep/dir/file.lock"),
                _ => assert_eq!(nested, "@@//sub/pkg/deep/dir/file.lock"),
            }
            locks += 1;
        }
        assert_eq!(locks, 6);
    }

    /// Probe X4: a flip of line endings alone stales the entry, and under
    /// a non-default `--digest_function` no recorded value is a SHA-256.
    /// A SHA-1 value cannot be compared. A BLAKE3 value has the length of
    /// a SHA-256 and reads as stale. Neither is ever fresh.
    #[test]
    fn a_digest_that_is_not_the_files_sha256_is_never_fresh() {
        let lf = FileText::Bytes(bytes("probe_vectors/x4/inputs/lf.lock"));
        let crlf = FileText::Bytes(bytes("probe_vectors/x4/inputs/crlf.lock"));
        let recorded = sha256_hex(lf.as_bytes().unwrap());
        assert_eq!(input_state(&recorded, &lf), InputState::Fresh);
        assert_eq!(input_state(&recorded, &crlf), InputState::Stale);
        assert_eq!(input_state(&recorded, &FileText::Absent), InputState::Stale);
        assert_eq!(
            input_state(&recorded, &FileText::Unreadable),
            InputState::CannotCompare
        );
        // Bazel compares the strings, and it writes lowercase.
        assert_eq!(
            input_state(&recorded.to_uppercase(), &lf),
            InputState::Stale
        );
        // Bazel's markers for a missing path and a directory.
        for marker in ["ENOENT", "DIR", ""] {
            assert_eq!(
                input_state(marker, &FileText::Absent),
                InputState::CannotCompare
            );
        }

        for (function, state) in [
            ("sha1", InputState::CannotCompare),
            ("blake3", InputState::Stale),
        ] {
            let lock_file = format!("../locks/9.3.2.digest-{function}.MODULE.bazel.lock");
            let files = Workspace::new("probe_vectors/x4/inputs", &[(MODULE_LOCK, &lock_file)]);
            let lock = ModuleLock::read(&files);
            let verdicts = ext(&lock).input_verdicts(&files);
            assert_eq!(verdicts.len(), 9);
            assert!(verdicts.iter().all(|v| v.state == state), "{function}");
        }
    }

    /// Probe L6: Bazel 7.0.2 accepted the CRLF-encoded lock in `error`
    /// mode. The lock is also read with a BOM and without its final
    /// newline; the recorded digest still decides, over raw bytes.
    #[test]
    fn a_lock_is_read_with_crlf_a_bom_and_no_final_newline() {
        let pair = "probe_vectors/lockfile/l6-crlf-pair/bazel-7.0.2";
        let crlf = bytes(&format!("{pair}/crlf/root.MODULE.bazel.lock"));
        assert!(crlf.windows(2).any(|w| w == b"\r\n"));
        let parsed = ModuleLock::parse(&crlf);
        assert!(matches!(parsed, ModuleLock::FamilyA(_)));

        let with_bom = [&b"\xEF\xBB\xBF"[..], &crlf].concat();
        assert_eq!(ModuleLock::parse(&with_bom), parsed);
        let lf: Vec<u8> = crlf.iter().copied().filter(|b| *b != b'\r').collect();
        assert_eq!(ModuleLock::parse(&lf), parsed);
        assert_eq!(ModuleLock::parse(lf.trim_ascii_end()), parsed);

        let states = |input: &str| {
            let files = Workspace::new(pair, &[("dep.lock", input)]);
            states(&parsed, &files)
        };
        let row = |state| vec![(GENERAL.to_string(), "dep.lock".to_string(), state)];
        assert_eq!(states("crlf/dep.lock"), row(InputState::Fresh));
        assert_eq!(states("lf/dep.lock"), row(InputState::Stale));
        // The LF lock records the LF input.
        let lf_lock = lock(&format!("{pair}/lf/root.MODULE.bazel.lock"));
        let files = Workspace::new(pair, &[("dep.lock", "lf/dep.lock")]);
        assert_eq!(
            super::tests::states(&lf_lock, &files),
            row(InputState::Fresh)
        );
    }

    /// A lock that was not read never answers "not recorded" or "nothing
    /// stale": every query is `None`, which a caller cannot take for an
    /// empty answer. Only an absent lock records nothing.
    #[test]
    fn a_lock_that_was_not_read_answers_no_query() {
        let files = Workspace::new("module_lock/stale-repair/bazel-9.3.2", &[]);
        let unreadable = ModuleLock::from_file(&FileText::Unreadable);
        assert_eq!(unreadable, ModuleLock::Unreadable);
        // A lock of a family this reader does not know, which records
        // the file an edit changes.
        let future = format!(
            r#"{{"lockFileVersion": 99, "moduleExtensions": {{"//:ext.bzl%toy": {{"general":
                {{"recordedInputs": ["FILE:@@//dep.lock {SHA_A}"]}}}}}}}}"#
        );
        let future = ModuleLock::parse(future.as_bytes());
        assert!(matches!(future, ModuleLock::UnknownShape(_)));
        for lock in [&unreadable, &future] {
            assert!(lock.extensions().is_none(), "{lock:?}");
            assert_eq!(lock.recorded("dep.lock"), None);
            assert_eq!(lock.input_verdicts(&files), None);
            assert_eq!(lock.recorded_dirs(), None);
            assert_eq!(lock.entries(), None);
            assert_eq!(lock.facts(), None);
            assert_eq!(lock.entries_of("//:ext.bzl", "toy"), None);
            assert_eq!(lock.facts_of("//:ext.bzl", "toy"), None);
            assert_eq!(lock.lock_file_version(), None);
        }

        // No lock file: Bazel resolves afresh, and nothing can be stale.
        let absent = ModuleLock::from_file(&FileText::Absent);
        assert_eq!(absent, ModuleLock::Absent);
        assert_eq!(absent.recorded("dep.lock"), Some(Vec::new()));
        assert_eq!(absent.input_verdicts(&files), Some(Vec::new()));
        assert_eq!(absent.recorded_dirs(), Some(Vec::new()));
        assert_eq!(absent.entries(), Some(&[][..]));
        assert_eq!(absent.facts(), Some(&[][..]));
        assert_eq!(absent.entries_of("//:ext.bzl", "toy"), Some(Vec::new()));
        assert_eq!(absent.facts_of("//:ext.bzl", "toy"), Some(Vec::new()));

        // The same queries on a lock that was read.
        let read = lock("module_lock/stale-repair/bazel-9.3.2/baseline.MODULE.bazel.lock");
        assert_eq!(
            read.recorded("dep.lock").map(|records| records.len()),
            Some(1)
        );
        assert_eq!(read.recorded("other.lock"), Some(Vec::new()));
        assert_eq!(read.input_verdicts(&files).map(|rows| rows.len()), Some(1));
        assert_eq!(read.recorded_dirs(), Some(Vec::new()));
    }

    /// Unknown shape is `UnknownShape`, never an error and never a
    /// partial reading: a lock understood halfway reads as "nothing
    /// stale" for the half that was not.
    #[test]
    fn a_lock_this_reader_does_not_know_is_an_unknown_shape() {
        for json in [
            "",
            "not json",
            "[]",
            // A future family: neither key.
            r#"{"lockFileVersion": 99, "moduleExtensions": {}}"#,
            r#"{"moduleDepGraph": {}, "moduleFileHash": "x", "registryFileHashes": {}}"#,
            // Family A without the hash that proves it fresh.
            r#"{"moduleDepGraph": {}}"#,
            r#"{"moduleDepGraph": {"gazelle": {}}, "moduleFileHash": "x"}"#,
            r#"{"moduleDepGraph": {"gazelle@0.36.0": 1}, "moduleFileHash": "x"}"#,
            r#"{"registryFileHashes": []}"#,
            r#"{"registryFileHashes": {}, "moduleExtensions": []}"#,
            r#"{"registryFileHashes": {}, "moduleExtensions": {"no-percent": {}}}"#,
            r#"{"registryFileHashes": {}, "moduleExtensions": {"%toy": {}}}"#,
            r#"{"registryFileHashes": {}, "facts": {"//:ext.bzl": {}}}"#,
            // Lock version 1 (Bazel 6.3) files an entry without a
            // platform key; no probe ran it.
            r#"{"moduleDepGraph": {}, "moduleFileHash": "x",
                "moduleExtensions": {"//:ext.bzl%toy": {"bzlTransitiveDigest": "d"}}}"#,
        ] {
            assert!(unknown(json), "{json}");
        }
        for entry in [
            // No container this reader knows: the inputs are recorded
            // somewhere it does not look.
            r#"{"bzlTransitiveDigest": "d", "generatedRepoSpecs": {}}"#.to_string(),
            r#"{"watchedFiles": {"@@//dep.lock": "x"}}"#.to_string(),
            r#"{"recordedInputs": {}}"#.to_string(),
            r#"{"recordedInputs": [1]}"#.to_string(),
            r#"{"recordedInputs": ["FILE:@@//dep.lock"]}"#.to_string(),
            r#"{"recordedInputs": ["nokind value"]}"#.to_string(),
            r#"{"recordedFileInputs": []}"#.to_string(),
            r#"{"recordedFileInputs": {"@@//dep.lock": 7}}"#.to_string(),
            // A label with no target, and paths Bazel never writes.
            format!(r#"{{"accumulatedFileDigests": {{"@@//pkg": "{SHA_A}"}}}}"#),
            format!(r#"{{"recordedFileInputs": {{"@@//../dep.lock": "{SHA_A}"}}}}"#),
            format!(r#"{{"recordedFileInputs": {{"@@//a//dep.lock": "{SHA_A}"}}}}"#),
            format!(r#"{{"recordedInputs": ["FILE:@@//a/./dep.lock {SHA_A}"]}}"#),
            // The root is no file, and a directory path is normalised too.
            format!(r#"{{"recordedInputs": ["FILE:@@// {SHA_A}"]}}"#),
            format!(r#"{{"recordedFileInputs": {{"@@//": "{SHA_A}"}}}}"#),
            r#"{"recordedInputs": ["FILE:@@//. DIR"]}"#.to_string(),
            r#"{"recordedInputs": ["DIRENTS:@@//a/../b 7f"]}"#.to_string(),
            r#"{"recordedInputs": ["DIRTREE:@@//a//b 7f"]}"#.to_string(),
            r#"{"recordedInputs": ["DIRTREE:@@//a/..?/../excludes=x 7f"]}"#.to_string(),
            r#"{"recordedFileInputs": {}, "recordedDirentsInputs": []}"#.to_string(),
            r#"{"recordedFileInputs": {}, "recordedDirentsInputs": {"@@//x": 7}}"#.to_string(),
            r#"{"recordedFileInputs": {}, "recordedDirentsInputs": {"@@//x/": "7f"}}"#.to_string(),
            // A listing is no file container: the files are elsewhere.
            r#"{"recordedDirentsInputs": {"@@//x": "7f"}}"#.to_string(),
            r#"{"recordedInputs": [], "generatedRepoSpecs": []}"#.to_string(),
            r#"{"recordedInputs": [], "generatedRepoSpecs": {"dep_a": "spec"}}"#.to_string(),
        ] {
            assert!(unknown(&with_entry(&entry)), "{entry}");
        }
    }

    /// What is not a main-repository path is not an unknown shape: it is
    /// skipped, because no edit of the workspace changes it. A record of
    /// a main-repository directory is kept, apart from the files.
    #[test]
    fn inputs_of_other_kinds_and_other_repositories_are_skipped() {
        // The first four items are what Bazel 9.3.2 wrote for an
        // extension that lists the root and `third_party`.
        let entry = format!(
            r#"{{"recordedInputs": [
                "FILE:@@// DIR",
                "DIRENTS:@@// 8a2b",
                "FILE:@@//third_party DIR",
                "DIRENTS:@@//third_party 7869",
                "DIRTREE:@@//vendor 5d41",
                "DIRTREE:@@//gen?/../excludes=abc%2F**,file%2Cwith%2Ccommas 77aa",
                "DIRTREE:@@//?/../excludes=bazel-* 0b0b",
                "REPO_MAPPING:rules_dotnet+,platforms platforms",
                "ENV:GOPROXY \\0",
                "FUTURE:@@//x.lock {SHA_A}",
                "FILE:@@rules_go+//go.mod {SHA_A}",
                "DIRENTS:@@rules_go+//go 7f",
                "DIRTREE:/usr/share/zoneinfo 7f",
                "FILE:/etc/hosts {SHA_A}",
                "FILE:@@//a\\sb\\\\c.lock {SHA_A}",
                "FILE:@//single.lock {SHA_A}",
                "FILE://bare.lock ENOENT"
            ]}}"#
        );
        let lock = ModuleLock::parse(with_entry(&entry).as_bytes());
        let [entry] = ext(&lock).entries.as_slice() else {
            panic!("{lock:?}");
        };
        let paths: Vec<&str> = entry.inputs.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(paths, ["a b\\c.lock", "single.lock", "bare.lock"]);
        assert_eq!(entry.inputs[0].key, "@@//a b\\c.lock");
        assert_eq!(entry.inputs[2].recorded, "ENOENT");
        // The root's own `DIR` record cannot go stale and is dropped; its
        // listing is kept, with the empty path.
        let dirs = |entry: &ExtensionEntry| -> Vec<(String, DirWatch, String)> {
            let row = |d: &RecordedDir| (d.path.clone(), d.watch, d.recorded.clone());
            entry.dirs.iter().map(row).collect()
        };
        let row =
            |path: &str, watch, recorded: &str| (path.to_string(), watch, recorded.to_string());
        assert_eq!(
            dirs(entry),
            [
                row("", DirWatch::Entries, "8a2b"),
                row("third_party", DirWatch::Exists, "DIR"),
                row("third_party", DirWatch::Entries, "7869"),
                row("vendor", DirWatch::Tree, "5d41"),
                row("gen", DirWatch::Tree, "77aa"),
                row("", DirWatch::Tree, "0b0b"),
            ]
        );
        assert_eq!(entry.dirs[0].key, "@@//");
        assert_eq!(
            entry.dirs[4].key,
            "@@//gen?/../excludes=abc%2F**,file%2Cwith%2Ccommas"
        );
        assert_eq!(lock.recorded_dirs().map(|dirs| dirs.len()), Some(6));

        // The older containers skip the same keys, and keep their
        // listings in a container of their own: Bazel 7.7.2 wrote the
        // `third_party` key and 8.7.0 the root key as well.
        for container in ["accumulatedFileDigests", "recordedFileInputs"] {
            let entry = format!(
                r#"{{"{container}": {{"@@gazelle~//:go.mod": "{SHA_A}", "/abs/x": "{SHA_A}"}},
                    "recordedDirentsInputs": {{"@@//": "6187", "@@//third_party": "7869",
                        "@@gazelle~//internal": "7f", "/abs": "7f"}},
                    "envVariables": {{"GOPROXY": null}}}}"#
            );
            let lock = ModuleLock::parse(with_entry(&entry).as_bytes());
            let [entry] = ext(&lock).entries.as_slice() else {
                panic!("{lock:?}");
            };
            assert!(entry.inputs.is_empty());
            assert_eq!(
                dirs(entry),
                [
                    row("", DirWatch::Entries, "6187"),
                    row("third_party", DirWatch::Entries, "7869"),
                ]
            );
        }
        // A directory an extension watched by hand.
        let entry = r#"{"recordedFileInputs": {"@@//": "DIR", "@@//third_party": "DIR"}}"#;
        let lock = ModuleLock::parse(with_entry(entry).as_bytes());
        let [entry] = ext(&lock).entries.as_slice() else {
            panic!("{lock:?}");
        };
        assert!(entry.inputs.is_empty());
        assert_eq!(dirs(entry), [row("third_party", DirWatch::Exists, "DIR")]);

        // Unknown top-level members are another reader's business, and
        // the first lock version had no `moduleExtensions`.
        let bare = r#"{"moduleDepGraph": {"<root>": {}}, "moduleFileHash": "x", "flags": {}}"#;
        let ModuleLock::FamilyA(graph) = ModuleLock::parse(bare.as_bytes()) else {
            panic!("not family A");
        };
        assert_eq!(graph.lock_file_version, None);
        assert!(graph.modules.is_empty() && graph.extensions.entries.is_empty());
    }

    /// Bazel 8.8.2 - 10.0.0rc3 split an item at its first space
    /// (`RepoRecordedInput.java`, `WithValue.parse`). Bazel writes no raw
    /// space in a key, so an item with two is not one it wrote: read
    /// Bazel's way the value is no digest, and the row is never fresh.
    #[test]
    fn a_recorded_item_is_split_at_its_first_space() {
        let entry = format!(r#"{{"recordedInputs": ["FILE:@@//a b.lock {SHA_A}"]}}"#);
        let lock = ModuleLock::parse(with_entry(&entry).as_bytes());
        let [entry] = ext(&lock).entries.as_slice() else {
            panic!("{lock:?}");
        };
        let [input] = entry.inputs.as_slice() else {
            panic!("{entry:?}");
        };
        assert_eq!(input.path, "a");
        assert_eq!(input.recorded, format!("b.lock {SHA_A}"));
        let file = FileText::Bytes(Vec::new());
        assert_eq!(
            input_state(&input.recorded, &file),
            InputState::CannotCompare
        );
    }

    #[test]
    fn unescape_follows_bazel() {
        assert_eq!(unescape(r"a\sb"), "a b");
        assert_eq!(unescape(r"a\\sb"), r"a\sb");
        assert_eq!(unescape(r"a\nb"), "a\nb");
        assert_eq!(unescape(r"a\xb"), "axb");
        assert_eq!(unescape("trailing\\"), "trailing");
        assert_eq!(unescape("café"), "café");
    }

    /// A review probe on macOS arm64 (`module_lock/listing/`). A toy
    /// extension lists `third_party`, finds the directory `café` there
    /// and reads its `dep.lock`; on 8.7.0 and 9.3.2 it lists the root
    /// too. Bazel 7.7.2 and 8.7.0 spell the path with one character per
    /// UTF-8 byte, 9.3.2 in Unicode. Read either way it is the file on
    /// disk: recorded, and fresh while untouched.
    #[test]
    fn a_non_ascii_path_and_a_listed_directory_are_read_from_real_locks() {
        const INPUT: &str = "third_party/café/dep.lock";
        const INTERNAL: &str = "third_party/caf\u{c3}\u{a9}/dep.lock";
        let third_party = "786967d62642dc046d15e40945c82b0bc96178c2a6b5e0a7e9d575c32814bd86";
        let no_lock_yet = "6187a32bf44b88701ca15f7b79c457d395c2b9cb3d021e255e779f681e8d9472";
        let with_lock = "8a2b5501a1e470e81ec62ec0fde3d55c0f8b4e79684dc5ed0a58e7449060eafe";
        let (exists, entries) = (DirWatch::Exists, DirWatch::Entries);
        type Dirs<'a> = Vec<(&'a str, DirWatch, &'a str)>;
        let cases: [(&str, u64, &str, Dirs<'_>); 3] = [
            (
                "7.7.2",
                13,
                INTERNAL,
                vec![("third_party", entries, third_party)],
            ),
            (
                "8.7.0",
                24,
                INTERNAL,
                vec![
                    ("", entries, no_lock_yet),
                    ("third_party", entries, third_party),
                ],
            ),
            (
                "9.3.2",
                28,
                INPUT,
                vec![
                    ("", entries, with_lock),
                    ("third_party", exists, "DIR"),
                    ("third_party", entries, third_party),
                ],
            ),
        ];
        for (bazel, version, spelled, dirs) in cases {
            let lock_file = format!("listing/{bazel}.MODULE.bazel.lock");
            let workspace = |input: &str| {
                let renamed = [
                    (MODULE_LOCK, lock_file.as_str()),
                    ("MODULE.bazel", "listing/root.MODULE.bazel"),
                    (INPUT, input),
                ];
                Workspace::new("module_lock", &renamed)
            };
            let untouched = workspace("stale-repair/bazel-9.3.2/dep.lock.before");
            let lock = ModuleLock::read(&untouched);
            assert_eq!(lock.lock_file_version(), Some(version), "{bazel}");

            // One record of the file, under the name it has on disk, with
            // the key as the lock spells it.
            let records = lock.recorded(INPUT).unwrap();
            let [(entry, input)] = records.as_slice() else {
                panic!("{bazel}: {} records", records.len());
            };
            assert!(entry.id.matches("//:ext.bzl", "toy"), "{bazel}");
            assert_eq!(input.path, INPUT, "{bazel}");
            assert_eq!(input.key, format!("@@//{spelled}"), "{bazel}");
            // A directory really named `cafÃ©` would be another file.
            assert_eq!(lock.recorded(INTERNAL), Some(Vec::new()), "{bazel}");

            // The untouched file is fresh, and an edit of it is stale.
            let state_of = |files: &Workspace| {
                let verdicts = lock.input_verdicts(files).unwrap();
                let of_input = |v: &&InputVerdict<'_>| v.input.path == INPUT;
                let state = verdicts.iter().find(of_input).unwrap().state;
                let others = verdicts.iter().filter(|v| v.input.path != INPUT);
                (state, others.map(|v| v.state).collect::<Vec<_>>())
            };
            // 7.7.2 also records the root `MODULE.bazel`, which the
            // extension names to find the root.
            let others = vec![InputState::Fresh; usize::from(bazel == "7.7.2")];
            assert_eq!(state_of(&untouched), (InputState::Fresh, others.clone()));
            let edited = workspace("stale-repair/bazel-9.3.2/dep.lock.after");
            assert_eq!(state_of(&edited), (InputState::Stale, others), "{bazel}");

            // The listings are kept apart from the files. A `DIR` record
            // is no file: it is never a row of `input_verdicts`.
            let found = lock.recorded_dirs().unwrap();
            let found: Dirs<'_> = found
                .iter()
                .map(|(_, dir)| (dir.path.as_str(), dir.watch, dir.recorded.as_str()))
                .collect();
            assert_eq!(found, dirs, "{bazel}");

            // What socket-patch creates in a root (design 5.1) stales a
            // listing of that root and nothing else; an edit of a file's
            // bytes stales no listing.
            let stale_dirs = |path: &str| -> Vec<(String, DirWatch)> {
                let dirs = lock.recorded_dirs().unwrap();
                let hit = dirs
                    .iter()
                    .filter(|(_, dir)| dir.stale_when_created_or_removed(path));
                hit.map(|(_, dir)| (dir.path.clone(), dir.watch)).collect()
            };
            let root_listing: Vec<_> = dirs.iter().filter(|dir| dir.0.is_empty()).collect();
            let root_listing = vec![(String::new(), entries); root_listing.len()];
            assert_eq!(stale_dirs(".bazelignore"), root_listing, "{bazel}");
            assert_eq!(stale_dirs(".socket"), root_listing, "{bazel}");
            assert!(stale_dirs(".socket/bazel/index.json").is_empty(), "{bazel}");
            assert!(stale_dirs(INPUT).is_empty(), "{bazel}");
            assert_eq!(
                stale_dirs("third_party/new"),
                [("third_party".to_string(), entries)],
                "{bazel}"
            );
            let all = lock.recorded_dirs().unwrap();
            assert!(!all.iter().any(|(_, dir)| dir.stale_when_edited(INPUT)));
        }
    }

    /// The same probe on 9.3.2. With the lock above `--lockfile_mode=error`
    /// builds; after `.bazelignore` and `.socket/bazel/index.json` are
    /// created it fails with `directory entries of @@// changed`, and
    /// `update` then rewrites one record: the root's listing.
    #[test]
    fn creating_a_root_entry_changes_only_the_roots_listing_record() {
        let read = |name: &str| lock(&format!("module_lock/listing/{name}.MODULE.bazel.lock"));
        let (before, after) = (read("9.3.2"), read("9.3.2.after-root-files"));
        let (before, after) = (ext(&before), ext(&after));
        let [before] = before.entries.as_slice() else {
            panic!("{before:?}");
        };
        let [after] = after.entries.as_slice() else {
            panic!("{after:?}");
        };
        assert_eq!(before.inputs, after.inputs);
        assert_eq!(before.repo_specs, after.repo_specs);
        assert_eq!(before.dirs.len(), 3);
        for (was, is) in before.dirs.iter().zip(&after.dirs) {
            assert_eq!((&was.path, was.watch), (&is.path, is.watch));
            let root_listing = was.path.is_empty() && was.watch == DirWatch::Entries;
            assert_eq!(was.recorded != is.recorded, root_listing, "{was:?}");
            assert_eq!(
                was.stale_when_created_or_removed(".bazelignore"),
                root_listing
            );
        }
    }

    #[test]
    fn a_directory_record_says_which_changes_stale_it() {
        let dir = |path: &str, watch| RecordedDir {
            path: path.to_string(),
            key: format!("@@//{path}"),
            watch,
            recorded: String::new(),
        };
        let created = |dir: &RecordedDir, path: &str| dir.stale_when_created_or_removed(path);

        let listing = dir("third_party", DirWatch::Entries);
        assert!(created(&listing, "third_party/new") && created(&listing, "third_party/py"));
        // The directory itself, or one above it, appears or disappears.
        assert!(created(&listing, "third_party"));
        assert!(!created(&listing, "third_party/py/requirements.txt"));
        assert!(!created(&listing, "third_party_2") && !created(&listing, "third"));
        assert!(!created(&listing, "other/third_party/new"));
        assert!(!listing.stale_when_edited("third_party/dep.lock"));

        let root = dir("", DirWatch::Entries);
        assert!(created(&root, ".bazelignore") && created(&root, ".socket"));
        assert!(!created(&root, ".socket/bazel") && !root.stale_when_edited("dep.lock"));

        let exists = dir("a/b", DirWatch::Exists);
        assert!(created(&exists, "a/b") && created(&exists, "a"));
        assert!(!created(&exists, "a/b/c") && !created(&exists, "a/bc"));
        assert!(!exists.stale_when_edited("a/b/c"));

        // A watched tree digests every name and every file below it.
        let tree = dir("vendor", DirWatch::Tree);
        assert!(created(&tree, "vendor/a/b.txt") && created(&tree, "vendor"));
        assert!(tree.stale_when_edited("vendor/a/b.txt"));
        assert!(!tree.stale_when_edited("vendored/a.txt") && !created(&tree, "vendored"));
        let whole = dir("", DirWatch::Tree);
        assert!(whole.stale_when_edited("any/file") && created(&whole, "any"));
    }

    /// A path of the two older containers is decoded only when it is
    /// what Bazel's internal spelling of a UTF-8 name looks like.
    /// Anything else is kept as found, and still found by a query in
    /// either spelling.
    #[test]
    fn a_path_is_decoded_from_bazels_internal_spelling() {
        assert_eq!(
            from_internal("third_party/dep.lock"),
            "third_party/dep.lock"
        );
        assert_eq!(from_internal("caf\u{c3}\u{a9}/dep.lock"), "café/dep.lock");
        assert_eq!(to_internal("café/dep.lock"), "caf\u{c3}\u{a9}/dep.lock");
        assert_eq!(
            from_internal(&to_internal("日本/依存.lock")),
            "日本/依存.lock"
        );
        // A directory really named `cafÃ©` is spelled with four characters.
        let double = to_internal("caf\u{c3}\u{a9}");
        assert_eq!(double.chars().count(), 7);
        assert_eq!(from_internal(&double), "caf\u{c3}\u{a9}");
        // A Latin-1 byte that is no UTF-8 (a name in another encoding),
        // and a character no byte can be: kept as found.
        for kept in [
            "caf\u{e9}/dep.lock",
            "日本/dep.lock",
            "caf\u{c3}\u{a9}/日本",
        ] {
            assert_eq!(from_internal(kept), kept);
        }

        let inputs = |container: &str, key: &str| {
            let entry = match container {
                "recordedInputs" => format!(r#"{{"recordedInputs": ["FILE:{key} {SHA_A}"]}}"#),
                _ => format!(r#"{{"{container}": {{"{key}": "{SHA_A}"}}}}"#),
            };
            ModuleLock::parse(with_entry(&entry).as_bytes())
        };
        let count = |lock: &ModuleLock, path: &str| lock.recorded(path).unwrap().len();
        // Label keys of lock version 3 are decoded like path keys.
        let v3 = inputs("accumulatedFileDigests", "@@//caf\u{c3}\u{a9}:dep.lock");
        let [(_, input)] = v3.recorded("café/dep.lock").unwrap()[..] else {
            panic!("{v3:?}");
        };
        assert_eq!(input.key, "@@//caf\u{c3}\u{a9}:dep.lock");
        // A listing key of the same lock versions too.
        let entry = r#"{"recordedFileInputs": {}, "recordedDirentsInputs": {"@@//cafÃ©": "7f"}}"#;
        let listed = ModuleLock::parse(with_entry(entry).as_bytes());
        assert_eq!(listed.recorded_dirs().unwrap()[0].1.path, "café");

        // Kept as found: found by the same spelling.
        let latin1 = inputs("recordedFileInputs", "@@//caf\u{e9}/dep.lock");
        assert_eq!(count(&latin1, "caf\u{e9}/dep.lock"), 1);
        let wide = inputs("recordedFileInputs", "@@//日本/dep.lock");
        assert_eq!(count(&wide, "日本/dep.lock"), 1);
        // `recordedInputs` is written in Unicode and is not decoded. If
        // a release this reader has not probed wrote the internal
        // spelling there, a query for the name on disk still finds it.
        let undecoded = inputs("recordedInputs", "@@//caf\u{c3}\u{a9}/dep.lock");
        assert_eq!(count(&undecoded, "café/dep.lock"), 1);
        assert_eq!(count(&undecoded, "caf\u{c3}\u{a9}/dep.lock"), 1);
        assert_eq!(count(&undecoded, "cafe/dep.lock"), 0);
        let unicode = inputs("recordedInputs", "@@//café/dep.lock");
        assert_eq!(count(&unicode, "café/dep.lock"), 1);
        assert_eq!(count(&unicode, "caf\u{c3}\u{a9}/dep.lock"), 0);
    }

    /// Probe L7: family A names the selected version in a graph key, and
    /// its root-file hash stales on any byte. Family B names it in a
    /// `source.json` key; `MODULE.bazel` keys are the discovered superset.
    #[test]
    fn selected_module_versions_are_read_from_both_families() {
        let dir = "probe_vectors/lockfile/recorded-inputs/bazel-6.6.0/fresh";
        let ModuleLock::FamilyA(graph) = lock(&format!("{dir}/root.MODULE.bazel.lock")) else {
            panic!("not family A");
        };
        let versions = |name| -> Vec<_> { graph.modules_named(name).map(|m| &m.version).collect() };
        assert_eq!(versions("rules_python"), [&Some("0.4.0".to_string())]);
        // A builtin module has no registry version.
        assert_eq!(versions("bazel_tools"), [&None]);
        assert!(versions("gazelle").is_empty() && versions("<root>").is_empty());
        let module_file = bytes(&format!("{dir}/root.MODULE.bazel"));
        assert!(graph.module_file_fresh(&module_file));
        assert!(!graph.module_file_fresh(&[&module_file[..], b"# comment\n"].concat()));
        let crlf = String::from_utf8(module_file)
            .unwrap()
            .replace('\n', "\r\n");
        assert!(!graph.module_file_fresh(crlf.as_bytes()));

        for line in ["7.7.2", "9.3.2"] {
            let ModuleLock::FamilyB(hashes) =
                lock(&format!("module_lock/gv3/{line}.MODULE.bazel.lock"))
            else {
                panic!("not family B");
            };
            assert_eq!(hashes.selected("gazelle"), ["0.51.3"], "{line}");
            assert_eq!(hashes.selected("rules_go"), ["0.61.1"], "{line}");
            assert!(
                hashes.discovered("gazelle", "0.36.0") && hashes.discovered("gazelle", "0.51.3")
            );
            assert!(!hashes.discovered("gazelle", "0.54.0"));
            assert!(hashes.selected("no_such_module").is_empty());
        }
    }

    #[test]
    fn registry_keys_are_matched_by_their_end() {
        let json = format!(
            r#"{{"registryFileHashes": {{
                "https://bcr.bazel.build/bazel_registry.json": "{SHA_A}",
                "https://bcr.bazel.build/modules/gazelle/0.36.0/MODULE.bazel": "{SHA_A}",
                "https://bcr.bazel.build/modules/gazelle/0.51.3/MODULE.bazel": "{SHA_A}",
                "https://bcr.bazel.build/modules/gazelle/0.51.3/source.json": "{SHA_A}",
                "https://mirror.example/bcr/modules/gazelle/0.51.3/source.json": "{SHA_A}",
                "file:///registry/modules/gazelle/0.54.0/source.json": "not found",
                "https://bcr.bazel.build/modules/rules_go/0.61.1/source.json": 7,
                "https://bcr.bazel.build/gazelle/0.99.0/source.json": "{SHA_A}",
                "https://bcr.bazel.build/modules//0.99.0/source.json": "{SHA_A}"
            }}}}"#
        );
        let ModuleLock::FamilyB(hashes) = ModuleLock::parse(json.as_bytes()) else {
            panic!("not family B");
        };
        // One version, though two registries serve it; `not found` and a
        // value that is no hash select nothing.
        assert_eq!(hashes.selected("gazelle"), ["0.51.3"]);
        assert!(hashes.selected("rules_go").is_empty());
        assert!(hashes.discovered("gazelle", "0.36.0"));
        assert!(!hashes.discovered("gazelle", "0.54.0"));
        assert_eq!(hashes.registry_files.len(), 6);
    }

    /// Probes U3 / B2: a generated paket extension that is not
    /// reproducible has an entry keyed without `@@`, and an edit of its
    /// `paket.<group>.bzl` stales `bzlTransitiveDigest`. The entry
    /// records no file.
    #[test]
    fn extension_entries_expose_their_bzl_transitive_digest() {
        for (file, extension, digest) in [
            (
                "dn-7.7.2-0.14.0.reduced",
                "main_extension",
                "qIZbWuaP4GG970R9G/tPdkHnAu78VjQY4VVMT2iU+L4=",
            ),
            (
                "dn-9.3.2-0.22.2",
                "oldgen_extension",
                "e436ghFYKuHU/BRgIn6WAJqU5XgjJE9or5BRt/55+hM=",
            ),
        ] {
            let lock = lock(&format!("module_lock/paket/{file}.MODULE.bazel.lock"));
            let label = format!("//deps:paket.{extension}.bzl");
            let entries = lock.entries_of(&label, extension).unwrap();
            let [entry] = entries.as_slice() else {
                panic!("{file}: {} entries", entries.len());
            };
            assert_eq!(entry.id.raw, format!("{label}%{extension}"));
            assert!(entry.id.in_root_module() && !entry.id.isolated);
            assert_eq!(entry.platform, GENERAL);
            assert_eq!(entry.bzl_transitive_digest.as_deref(), Some(digest));
            assert!(entry.usages_digest.is_some());
            assert!(entry.inputs.is_empty(), "{file}");
            // The generated repositories carry the package digest.
            assert!(entry.specs_mention("sha512-HriaeJXKHcyWUUFH7BxRZPyHEZusGmYRbiU3G+RoEG5ZzSVl7M7ue+tuBgA6wEKjJQ3hmnp6Ff5nxjwzuyuWsA=="));
            // Another extension of the same file, or the name alone, is
            // not this entry.
            assert_eq!(lock.entries_of(&label, "other"), Some(Vec::new()));
            assert_eq!(lock.entries_of("//:paket.bzl", extension), Some(Vec::new()));
        }
    }

    #[test]
    fn an_extension_id_is_matched_without_its_repository() {
        let id = |raw| ExtensionId::parse(raw).unwrap();
        // Bazel prints a root-module id with `@@` and writes it without.
        let printed = id("@@//deps:paket.main_extension.bzl%main_extension");
        assert!(printed.in_root_module());
        assert!(printed.matches("//deps:paket.main_extension.bzl", "main_extension"));
        // One ruleset, four spellings of its repository.
        for raw in [
            "@rules_python~0.24.0//python/extensions:pip.bzl%pip",
            "@@rules_python~0.31.0//python/extensions:pip.bzl%pip",
            "@@rules_python~//python/extensions:pip.bzl%pip",
            "@@rules_python+//python/extensions:pip.bzl%pip",
        ] {
            let id = id(raw);
            assert!(id.matches(PIP.0, PIP.1) && !id.in_root_module(), "{raw}");
            assert_eq!(id.raw, raw);
        }
        assert_eq!(
            id("@@rules_python+//python/extensions:pip.bzl%pip").repo,
            "rules_python+"
        );
        assert!(
            !id("@@rules_python+//python/private/pypi:pip.bzl%pip_internal").matches(PIP.0, PIP.1)
        );
        let isolated = id("//:ext.bzl%toy%<root>~my_usage");
        assert!(isolated.isolated && isolated.matches("//:ext.bzl", "toy"));
    }

    /// Probe L1.d: a lock whose recorded digest was replaced by hand
    /// passes `error` mode and builds the unpatched package, on each of
    /// the eight releases the probe ran. Digest equality alone is
    /// therefore no evidence: the entry's repository specs must carry
    /// the new pin too. The eight locks cover both families, the three
    /// input containers and both spellings of a spec's rule.
    #[test]
    fn a_forged_digest_is_told_from_a_refresh_by_the_repository_specs() {
        let mut shapes = BTreeSet::new();
        for (line, version, family_a) in [
            ("6.6.0", 3, true),
            ("7.0.2", 3, true),
            ("7.1.2", 6, true),
            ("7.7.2", 13, false),
            ("8.4.2", 18, false),
            ("8.8.2", 28, false),
            ("9.3.2", 28, false),
            ("10.0.0rc3", 28, false),
        ] {
            let dir = format!("module_lock/stale-repair/bazel-{line}");
            let after = Workspace::new(&dir, &[("dep.lock", "dep.lock.after")]);
            let before = Workspace::new(&dir, &[("dep.lock", "dep.lock.before")]);
            let read = |name: &str| {
                let lock = lock(&format!("{dir}/{name}.MODULE.bazel.lock"));
                assert_eq!(lock.lock_file_version(), Some(version), "{line} {name}");
                assert_eq!(matches!(lock, ModuleLock::FamilyA(_)), family_a, "{line}");
                lock
            };
            let state = |lock: &ModuleLock, files: &Workspace| {
                let verdicts = ext(lock).input_verdicts(files);
                let [verdict] = verdicts.as_slice() else {
                    panic!("{line}: {} inputs", verdicts.len());
                };
                assert_eq!(verdict.input.path, "dep.lock");
                (
                    verdict.state,
                    verdict.entry.specs_mention("socket-patched-a-1.0"),
                )
            };
            let (baseline, forged, updated) = (read("baseline"), read("forged"), read("updated"));
            assert_eq!(
                state(&baseline, &before),
                (InputState::Fresh, false),
                "{line}"
            );
            assert_eq!(
                state(&baseline, &after),
                (InputState::Stale, false),
                "{line}"
            );
            assert_eq!(state(&forged, &after), (InputState::Fresh, false), "{line}");
            assert_eq!(state(&updated, &after), (InputState::Fresh, true), "{line}");
            assert_eq!(
                state(&updated, &before),
                (InputState::Stale, true),
                "{line}"
            );

            // The forged lock is the baseline with one digest replaced:
            // the entry differs in its recorded input and in nothing
            // else, the repository specs included.
            let entry = |lock: &ModuleLock| ext(lock).entries_of("//:ext.bzl", "toy")[0].clone();
            let (was, forged, updated) = (entry(&baseline), entry(&forged), entry(&updated));
            assert_eq!(forged.platform, GENERAL, "{line}");
            assert_eq!(forged.repo_specs, was.repo_specs, "{line}");
            assert_ne!(updated.repo_specs, was.repo_specs, "{line}");
            assert_ne!(forged.inputs, was.inputs, "{line}");
            assert_eq!(forged.inputs, updated.inputs, "{line}");
            let spec = &forged.repo_specs[0];
            assert_eq!(spec.name, "dep_a", "{line}");
            assert_eq!(
                spec.rule.as_deref(),
                Some("@@//:ext.bzl%toy_repo"),
                "{line}"
            );
            assert_eq!(spec.attributes["content"], "upstream-a-1.0", "{line}");
            shapes.insert((version, forged.inputs[0].key.clone()));
        }
        let shapes: Vec<_> = shapes.iter().map(|(v, key)| (*v, key.as_str())).collect();
        assert_eq!(
            shapes,
            [
                (3, "@@//:dep.lock"),
                (6, "@@//dep.lock"),
                (13, "@@//dep.lock"),
                (18, "@@//dep.lock"),
                (28, "@@//dep.lock"),
            ]
        );
    }

    #[test]
    fn a_repository_spec_is_searched_in_keys_values_and_nested_values() {
        let spec = RepoSpec {
            name: "pypi_six".to_string(),
            rule: None,
            attributes: serde_json::json!({
                "requirement": "six==1.17.0 --hash=sha256:4721f3",
                "urls": ["https://example.test/six.whl"],
                "integrity": {"sha256-abc": {"file": "six.whl"}},
                "count": 4721,
            }),
        };
        for needle in ["sha256:4721f3", "example.test/six", "sha256-abc", "six.whl"] {
            assert!(spec.mentions(needle), "{needle}");
        }
        // Neither a number, nor the repository's name, nor nothing.
        for needle in ["4721,", "pypi_six", "", "sha256:ffff"] {
            assert!(!spec.mentions(needle), "{needle:?}");
        }
        let lock = lock("module_lock/stale-repair/bazel-7.7.2/baseline.MODULE.bazel.lock");
        let spec = &lock.entries_of("//:ext.bzl", "toy").unwrap()[0].repo_specs[0];
        assert_eq!(spec.name, "dep_a");
        assert_eq!(spec.rule.as_deref(), Some("@@//:ext.bzl%toy_repo"));
        let lock = lock_9_3_2_spec_rule();
        assert_eq!(lock.as_deref(), Some("@@//:ext.bzl%toy_repo"));
    }

    /// The rule id of lock version 28, which writes it as one member.
    fn lock_9_3_2_spec_rule() -> Option<String> {
        let lock = lock("module_lock/stale-repair/bazel-9.3.2/baseline.MODULE.bazel.lock");
        let entries = lock.entries_of("//:ext.bzl", "toy").unwrap();
        entries[0].repo_specs[0].rule.clone()
    }

    /// Probe L4.a: an entry keyed by OS and architecture is refreshed
    /// only on its own platform. After a macOS-only repair the Linux
    /// entry keeps the old digest and the old repository specs.
    #[test]
    fn every_platform_key_is_its_own_entry() {
        let dir = "module_lock";
        let after = Workspace::new(
            dir,
            &[("dep.lock", "stale-repair/bazel-9.3.2/dep.lock.after")],
        );
        let before = Workspace::new(
            dir,
            &[("dep.lock", "stale-repair/bazel-9.3.2/dep.lock.before")],
        );
        let read = |name: &str| {
            lock(&format!(
                "{dir}/eval-factors/9.3.2.{name}.MODULE.bazel.lock"
            ))
        };
        let row = |platform: &str, state| (platform.to_string(), "dep.lock".to_string(), state);
        let (linux, osx) = ("os:linux,arch:aarch64", "os:osx,arch:aarch64");
        let (fresh, stale) = (InputState::Fresh, InputState::Stale);

        let both = read("two-platforms");
        assert_eq!(states(&both, &before), [row(linux, fresh), row(osx, fresh)]);
        assert_eq!(states(&both, &after), [row(linux, stale), row(osx, stale)]);

        let repaired = read("after-macos-repair");
        assert_eq!(
            states(&repaired, &after),
            [row(linux, stale), row(osx, fresh)]
        );
        let records = repaired.recorded("dep.lock").unwrap();
        let patched = |index: usize| records[index].0.specs_mention("socket-patched-a-1.0");
        assert_eq!(records.len(), 2);
        assert!(!patched(0) && patched(1));
        assert_eq!(repaired.recorded("other.lock"), Some(Vec::new()));
        // Four more extensions have a general entry and no file input.
        assert!(repaired.entries().unwrap().len() > 2);
    }

    /// Probe L3: pip facts are `dist_hashes[index][package][dist URL]`
    /// with a `fact_version`, and no extension entry exists beside them.
    /// They are shared by every pip hub of the module graph: Bazel's own
    /// repair on 8.8.2 removes two of the four `six` members and keeps
    /// the package, so a member that remains proves nothing.
    #[test]
    fn pip_facts_are_read_in_both_fact_versions() {
        let read = |dir: &str, name: &str| {
            let lock = lock(&format!("module_lock/facts/{dir}/{name}.MODULE.bazel.lock"));
            assert_eq!(lock.entries_of(PIP.0, PIP.1), Some(Vec::new()));
            let facts = lock.facts_of(PIP.0, PIP.1).unwrap();
            let [facts] = facts.as_slice() else {
                panic!("{dir}/{name}: {} pip facts", facts.len());
            };
            assert_eq!(facts.id.repo, "rules_python+");
            facts.pip().unwrap()
        };

        // rules_python 2.0.3 on Bazel 8.8.2: bare hex.
        let baseline = read("pip-v1", "baseline");
        assert_eq!(baseline.fact_version, PipFactVersion::V1);
        assert_eq!(baseline.dist_hashes.len(), 1);
        // Two packages are pinned; other modules' hubs add thirty.
        assert_eq!(baseline.dist_hashes[0].packages.len(), 32);
        assert_eq!(baseline.dists(PYPI, "six").len(), 4);
        let (held, not_held) = (FactDigest::Held, FactDigest::NotHeld);
        assert_eq!(baseline.holds_digest(PYPI, "six", SIX_1_17), held);
        let slash = "https://pypi.org/simple/";
        assert_eq!(baseline.holds_digest(slash, "six", SIX_1_17), held);
        let other = "https://example.test/simple";
        assert_eq!(baseline.holds_digest(other, "six", SIX_1_17), not_held);
        assert_eq!(baseline.holds_digest(PYPI, "idna", SIX_1_17), not_held);
        // A digest that is not bare lowercase hex cannot be compared
        // with a package that has distributions, and with none it is
        // not held.
        for asked in [format!("sha256:{SIX_1_17}"), SIX_1_17.to_uppercase()] {
            let cannot_tell = FactDigest::CannotTell;
            assert_eq!(baseline.holds_digest(PYPI, "six", &asked), cannot_tell);
            assert_eq!(
                baseline.holds_digest(PYPI, "no-such-package", &asked),
                not_held
            );
        }
        let repaired = read("pip-v1", "bazel-repaired");
        assert_eq!(repaired.holds_digest(PYPI, "six", SIX_1_17), not_held);
        assert_eq!(repaired.dists(PYPI, "six").len(), 2);

        // rules_python 2.5.0-rc4 on Bazel 9.3.2: `sha256:<hex>`.
        let baseline = read("pip-v2", "baseline");
        assert_eq!(baseline.fact_version, PipFactVersion::V2);
        assert_eq!(baseline.dists(PYPI, "six").len(), 2);
        assert_eq!(baseline.holds_digest(PYPI, "six", SIX_1_17), held);
        let digest = &baseline.dists(PYPI, "six")[1].1;
        assert_eq!(*digest, format!("sha256:{SIX_1_17}"));
        assert_eq!(baseline.holds_digest(PYPI, "six", SHA_A), not_held);
        let repaired = read("pip-v2", "bazel-repaired");
        assert!(repaired.dists(PYPI, "six").is_empty());
        assert_eq!(repaired.holds_digest(PYPI, "six", SIX_1_17), not_held);
        assert_eq!(repaired.dist_hashes[0].packages.len(), 31);
    }

    /// Probe Y1 (`rules-python/RESULTS.md` 2.2): a hub that resolves
    /// through its own index (`experimental_index_url`) has its packages
    /// under that index's URL, beside the pypi.org packages of
    /// rules_python's own hubs. The pin is looked up under the hub's
    /// index and nowhere else. After the hosted rewrite of `spvictim`,
    /// Bazel's `update` removes that one member, in both fact versions.
    #[test]
    fn pip_facts_are_keyed_by_the_index_the_hub_resolves_through() {
        const INDEX: &str = "https://127.0.0.1:47292/simple";
        // The wheels the requirements file pinned before the rewrite.
        const VICTIM: &str = "cecf23d2e612215c6512613873a29337301ed66f92a1e81810ce20d8f3bab993";
        const DEP: &str = "ba58fd28227ddfb1aa681e7dd02f1e9eeafff1690bc965f515579f844f6099a1";
        let (held, not_held) = (FactDigest::Held, FactDigest::NotHeld);
        for (dir, fact_version, of_other_hubs) in [
            ("pip-index-v1", PipFactVersion::V1, 32),
            ("pip-index-v2", PipFactVersion::V2, 31),
        ] {
            let dir = format!("module_lock/facts/{dir}");
            // The root file names the index.
            let root = String::from_utf8(bytes(&format!("{dir}/root.MODULE.bazel"))).unwrap();
            assert!(root.contains(&format!("experimental_index_url = \"{INDEX}\"")));
            let read = |name: &str| {
                let lock = lock(&format!("{dir}/{name}.MODULE.bazel.lock"));
                assert_eq!(lock.lock_file_version(), Some(28), "{dir}");
                assert_eq!(lock.entries_of(PIP.0, PIP.1), Some(Vec::new()), "{dir}");
                let facts = lock.facts_of(PIP.0, PIP.1).unwrap();
                let [facts] = facts.as_slice() else {
                    panic!("{dir}/{name}: {} pip facts", facts.len());
                };
                facts.pip().unwrap()
            };
            let indexes = |facts: &PipFacts| -> Vec<(String, usize)> {
                let row = |index: &PipIndex| (index.url.clone(), index.packages.len());
                facts.dist_hashes.iter().map(row).collect()
            };
            let rows =
                |hub: usize| vec![(INDEX.to_string(), hub), (PYPI.to_string(), of_other_hubs)];

            let baseline = read("baseline");
            assert_eq!(baseline.fact_version, fact_version, "{dir}");
            assert_eq!(indexes(&baseline), rows(2), "{dir}");
            assert_eq!(baseline.holds_digest(INDEX, "spvictim", VICTIM), held);
            assert_eq!(baseline.holds_digest(INDEX, "spdep", DEP), held);
            // Another package of the index, and the package under an
            // index the hub does not resolve through.
            assert_eq!(baseline.holds_digest(INDEX, "spdep", VICTIM), not_held);
            assert_eq!(baseline.holds_digest(PYPI, "spvictim", VICTIM), not_held);

            let repaired = read("bazel-repaired");
            assert_eq!(indexes(&repaired), rows(1), "{dir}");
            assert!(repaired.dists(INDEX, "spvictim").is_empty(), "{dir}");
            assert_eq!(repaired.holds_digest(INDEX, "spvictim", VICTIM), not_held);
            assert_eq!(repaired.holds_digest(INDEX, "spdep", DEP), held);
            // Nothing else moved: the other hubs' packages are as they were.
            assert_eq!(repaired.dist_hashes[1], baseline.dist_hashes[1], "{dir}");
            assert_eq!(
                repaired.dists(INDEX, "spdep"),
                baseline.dists(INDEX, "spdep")
            );
        }
    }

    #[test]
    fn pip_facts_of_an_unknown_shape_are_refused() {
        let pip = |value: Value| {
            let id = ExtensionId::parse("@@rules_python+//python/extensions:pip.bzl%pip").unwrap();
            ExtensionFacts { id, value }.pip()
        };
        let hashes = serde_json::json!({PYPI: {"six": {"https://f.test/six.whl": ""}}});
        // Every member rules_python writes, with an empty digest (the
        // index advertised none) and a second index.
        let known = pip(serde_json::json!({
            "fact_version": "v2",
            "dist_hashes": hashes,
            "dist_filenames": {PYPI: {"six": {"https://f.test/six.whl": "six.whl"}}},
            "dist_yanked": {PYPI: {"six": {"sha256:ab": "broken"}}},
            "index_urls": {"https://extra.test/simple": {"six": "https://extra.test/simple/six/"}},
        }))
        .unwrap();
        assert_eq!(
            known.dists(PYPI, "six"),
            [("https://f.test/six.whl".to_string(), String::new())]
        );
        assert_eq!(known.holds_digest(PYPI, "six", ""), FactDigest::CannotTell);
        assert_eq!(
            known.index_packages,
            [(
                "https://extra.test/simple".to_string(),
                vec!["six".to_string()]
            )]
        );
        // `dist_hashes` can be absent when only index URLs are stored.
        let bare = pip(serde_json::json!({"fact_version": "v1"})).unwrap();
        assert!(bare.dist_hashes.is_empty() && bare.dists(PYPI, "six").is_empty());

        for facts in [
            serde_json::json!([]),
            serde_json::json!({"dist_hashes": hashes}),
            serde_json::json!({"fact_version": "v3", "dist_hashes": hashes}),
            serde_json::json!({"fact_version": 2, "dist_hashes": hashes}),
            serde_json::json!({"fact_version": "v2", "dist_hashes": hashes, "dist_sizes": {}}),
            serde_json::json!({"fact_version": "v2", "dist_hashes": []}),
            serde_json::json!({"fact_version": "v2", "dist_hashes": {PYPI: []}}),
            serde_json::json!({"fact_version": "v2", "dist_hashes": {PYPI: {"six": []}}}),
            serde_json::json!({"fact_version": "v2", "dist_hashes": {PYPI: {"six": {"u": 1}}}}),
            serde_json::json!({"fact_version": "v2", "index_urls": {"https://extra.test": 1}}),
        ] {
            assert!(pip(facts.clone()).is_err(), "{facts}");
        }
    }

    /// rules_python stores the digest the index advertises. 2.0.3 keeps
    /// what follows `#sha256=`, so a link without it leaves an empty
    /// value; 2.5.0-rc4 keeps `<algo>:<hex>` for any algorithm and an
    /// empty value for none. pypi.org always publishes SHA-256;
    /// pypiserver publishes MD5 by default. Such a distribution may be
    /// the pinned file, so the lookup never answers "not held" for it.
    #[test]
    fn a_pip_digest_that_is_no_sha256_cannot_be_told_from_the_pin() {
        let pip = |fact_version: &str, dists: Value| {
            let id = ExtensionId::parse("@@rules_python+//python/extensions:pip.bzl%pip").unwrap();
            let value = serde_json::json!({
                "fact_version": fact_version,
                "dist_hashes": {PYPI: {"six": dists}},
            });
            ExtensionFacts { id, value }.pip().unwrap()
        };
        let holds = |fact_version: &str, dists: Value| {
            pip(fact_version, dists).holds_digest(PYPI, "six", SIX_1_17)
        };
        let (whl, sdist) = ("https://f.test/six.whl", "https://f.test/six.tar.gz");
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let v2_pin = format!("sha256:{SIX_1_17}");
        let v2_other = format!("sha256:{SHA_A}");
        let (held, not_held, cannot_tell) = (
            FactDigest::Held,
            FactDigest::NotHeld,
            FactDigest::CannotTell,
        );

        // An index that advertises no digest.
        assert_eq!(holds("v1", serde_json::json!({whl: ""})), cannot_tell);
        assert_eq!(holds("v2", serde_json::json!({whl: ""})), cannot_tell);
        // An index that advertises MD5.
        let v2_md5 = format!("md5:{md5}");
        assert_eq!(holds("v2", serde_json::json!({whl: v2_md5})), cannot_tell);
        assert_eq!(holds("v1", serde_json::json!({whl: md5})), cannot_tell);
        // A digest in the other fact version's rendering, or uppercase.
        assert_eq!(holds("v1", serde_json::json!({whl: v2_pin})), cannot_tell);
        assert_eq!(holds("v2", serde_json::json!({whl: SIX_1_17})), cannot_tell);
        let upper = SIX_1_17.to_uppercase();
        assert_eq!(holds("v1", serde_json::json!({whl: upper})), cannot_tell);
        // One distribution that cannot be compared is enough, and a
        // match beside it still holds.
        let mixed = serde_json::json!({whl: v2_other, sdist: ""});
        assert_eq!(holds("v2", mixed), cannot_tell);
        let matched = serde_json::json!({whl: v2_pin, sdist: ""});
        assert_eq!(holds("v2", matched), held);
        // Every digest is a SHA-256 and none is the pin: not held.
        assert_eq!(holds("v2", serde_json::json!({whl: v2_other})), not_held);
        assert_eq!(holds("v1", serde_json::json!({whl: SHA_A})), not_held);
        assert_eq!(holds("v1", serde_json::json!({})), not_held);
        // Another package, or another index, has no distribution here.
        let empty = pip("v2", serde_json::json!({whl: ""}));
        assert_eq!(empty.holds_digest(PYPI, "idna", SIX_1_17), not_held);
        let other = "https://example.test/simple";
        assert_eq!(empty.holds_digest(other, "six", SIX_1_17), not_held);
    }

    /// Probe L3: gazelle's facts are one ordered list, and a rewrite adds
    /// a member (the replacement's `.mod` file) instead of replacing one.
    #[test]
    fn go_deps_facts_are_one_ordered_list() {
        let facts = |name: &str| {
            let lock = lock(&format!(
                "module_lock/facts/go-deps/{name}.MODULE.bazel.lock"
            ));
            assert!(ext(&lock)
                .entries_of("//:extensions.bzl", "go_deps")
                .is_empty());
            let go_deps = ext(&lock).facts_of("//:extensions.bzl", "go_deps")[0];
            // The Go SDK's facts are another extension's and another shape.
            let sdk = ext(&lock).facts_of("//go:extensions.bzl", "go_sdk")[0];
            assert!(sdk.go_deps().is_err() && sdk.pip().is_err());
            assert!(go_deps.pip().is_err());
            go_deps.go_deps().unwrap()
        };
        let errors = |list: &[GoModFact]| -> Vec<String> {
            let rows = list
                .iter()
                .filter(|m| m.importpath == "github.com/pkg/errors");
            rows.map(|m| m.version.clone()).collect()
        };
        let (baseline, repaired) = (facts("baseline"), facts("bazel-repaired"));
        assert_eq!((baseline.len(), repaired.len()), (172, 173));
        assert_eq!(baseline[0].importpath, "github.com/pkg/errors");
        assert_eq!(baseline[0].sha256.len(), 64);
        assert_eq!(errors(&baseline), ["v0.9.1"]);
        assert_eq!(errors(&repaired), ["v0.8.1", "v0.9.1"]);

        let go_deps = |value: Value| {
            let id = ExtensionId::parse("@@gazelle+//:extensions.bzl%go_deps").unwrap();
            ExtensionFacts { id, value }.go_deps()
        };
        assert_eq!(
            go_deps(serde_json::json!({"required_mod_files_v1": []})),
            Ok(Vec::new())
        );
        let member = serde_json::json!({"importpath": "a", "sha256": "b", "version": "v1"});
        for facts in [
            serde_json::json!({}),
            serde_json::json!({"required_mod_files_v2": []}),
            serde_json::json!({"required_mod_files_v1": [], "other": 1}),
            serde_json::json!({"required_mod_files_v1": {}}),
            serde_json::json!({"required_mod_files_v1": ["a"]}),
            serde_json::json!({"required_mod_files_v1": [{"importpath": "a", "sha256": "b"}]}),
            serde_json::json!({"required_mod_files_v1": [
                {"importpath": "a", "sha256": "b", "version": "v1", "replace": "c"}
            ]}),
        ] {
            assert!(go_deps(facts.clone()).is_err(), "{facts}");
        }
        assert_eq!(
            go_deps(serde_json::json!({"required_mod_files_v1": [member]}))
                .unwrap()
                .len(),
            1
        );
    }

    /// Probe L3 (toy): facts of a reproducible extension are keyed as
    /// the extension chooses, and it has no entry. `factsVersions` is
    /// tolerated beside them.
    #[test]
    fn facts_are_kept_per_extension_as_found() {
        let keys = |name: &str| -> Vec<String> {
            let raw = bytes(&format!("module_lock/facts/toy/{name}.MODULE.bazel.lock"));
            assert!(raw.windows(14).any(|w| w == b"\"factsVersions"));
            let lock = ModuleLock::parse(&raw);
            assert_eq!(lock.entries(), Some(&[][..]));
            let Some([facts]) = lock.facts() else {
                panic!("{name}: {:?}", lock.facts());
            };
            assert!(facts.id.in_root_module() && facts.id.matches("//:ext.bzl", "toy"));
            facts
                .keys()
                .unwrap()
                .into_iter()
                .map(str::to_string)
                .collect()
        };
        assert_eq!(keys("baseline"), ["dep_a@index", "dep_b@index"]);
        assert_eq!(keys("hand-repaired"), ["dep_b@index"]);
        let id = ExtensionId::parse("//:ext.bzl%toy").unwrap();
        let list = ExtensionFacts {
            id,
            value: serde_json::json!([]),
        };
        assert_eq!(list.keys(), None);
    }

    /// The rules_rs probe (`rust-vendor-rules-rs/RESULTS.md`, cell
    /// `rs0026-b88-single`): rules_rs keys its facts `<name>_<version>`,
    /// one per crate of every hub in the module graph, and its `crate`
    /// extension is reproducible, so no entry stands beside them. This
    /// lock is rules_rs 0.0.26 on Bazel 8.8.2, whose one fact is the one
    /// crate the project locks; by 0.0.61 rules_rs has hubs of its own,
    /// and a one-crate project's lock then holds 303 keys.
    #[test]
    fn rules_rs_facts_are_keyed_by_crate_name_and_version() {
        const CRATE: (&str, &str) = ("//rs:extensions.bzl", "crate");
        let lock = lock("module_lock/facts/rules-rs/baseline.MODULE.bazel.lock");
        assert_eq!(lock.lock_file_version(), Some(28));
        assert_eq!(lock.entries_of(CRATE.0, CRATE.1), Some(Vec::new()));
        let facts = lock.facts_of(CRATE.0, CRATE.1).unwrap();
        let [facts] = facts.as_slice() else {
            panic!("{} crate facts", facts.len());
        };
        assert_eq!(facts.id.raw, "@@rules_rs+//rs:extensions.bzl%crate");
        assert_eq!(facts.keys(), Some(vec!["cfg-if_1.0.4"]));
        // The value is the crate's index metadata as one JSON string.
        let metadata = facts.value["cfg-if_1.0.4"].as_str().unwrap();
        assert!(serde_json::from_str::<Value>(metadata).unwrap().is_object());
        // They are no other ruleset's facts.
        assert!(facts.pip().is_err() && facts.go_deps().is_err());
        assert_eq!(lock.facts().map(<[ExtensionFacts]>::len), Some(1));
    }
}
