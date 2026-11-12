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

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::model::{FileText, FileView};

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
    /// Every module of the graph but the root.
    pub modules: Vec<GraphModule>,
    pub extensions: Extensions,
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
    hex::encode(Sha256::digest(bytes))
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
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
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

    /// What the lock records about extensions; `None` when the lock is
    /// not a known family, which is not "nothing recorded".
    pub fn extensions(&self) -> Option<&Extensions> {
        match self {
            Self::FamilyA(lock) => Some(&lock.extensions),
            Self::FamilyB(lock) => Some(&lock.extensions),
            Self::Absent | Self::Unreadable | Self::UnknownShape(_) => None,
        }
    }

    /// Every extension entry. Empty for a lock that is not a known
    /// family, which says nothing about what that lock records: match on
    /// the variant before reading "no entry" as "nothing stale".
    pub fn entries(&self) -> &[ExtensionEntry] {
        self.extensions().map_or(&[], |ext| &ext.entries)
    }

    /// The facts of every extension, under the caveat of [`Self::entries`].
    pub fn facts(&self) -> &[ExtensionFacts] {
        self.extensions().map_or(&[], |ext| &ext.facts)
    }

    /// The entries of one extension, one per platform key.
    pub fn entries_of<'a>(
        &'a self,
        label: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a ExtensionEntry> {
        let entries = self.entries().iter();
        entries.filter(move |entry| entry.id.matches(label, name))
    }

    /// The facts of one extension.
    pub fn facts_of<'a>(
        &'a self,
        label: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a ExtensionFacts> {
        let facts = self.facts().iter();
        facts.filter(move |facts| facts.id.matches(label, name))
    }

    /// Every record of the root-relative file `path`, under every
    /// extension and platform key.
    pub fn recorded<'a>(
        &'a self,
        path: &'a str,
    ) -> impl Iterator<Item = (&'a ExtensionEntry, &'a RecordedInput)> {
        self.entries().iter().flat_map(move |entry| {
            let inputs = entry.inputs.iter().filter(move |input| input.path == path);
            inputs.map(move |input| (entry, input))
        })
    }

    /// Every recorded input compared with the file `files` holds. A
    /// `Stale` row predicts that an `error`-mode build which evaluates
    /// that extension fails.
    pub fn input_verdicts(&self, files: &dyn FileView) -> Vec<InputVerdict<'_>> {
        let mut verdicts = Vec::new();
        for entry in self.entries() {
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
    let mut inputs = Vec::new();
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
                inputs.push(recorded_input(path, key, recorded)?);
            }
        }
    }
    // Lock versions 6 - 24: path keys, `@@//<path>`.
    if let Some(value) = entry.get("recordedFileInputs") {
        containers += 1;
        for (key, recorded) in object(value, "recordedFileInputs")? {
            let recorded = string(recorded, "a recorded digest")?;
            if let Some(path) = main_repo(key) {
                inputs.push(recorded_input(path.to_string(), key, recorded)?);
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
                Some((kind == "FILE", key.to_string(), unescape(recorded)))
            });
            let Some((is_file, key, recorded)) = parsed else {
                return Err(format!(
                    "recorded input {item:?} is not `<KIND>:<key> <value>`"
                ));
            };
            // Directory listings, environment variables and repository
            // mappings are other kinds: not files, and not read here.
            if let Some(path) = main_repo(&key).filter(|_| is_file) {
                inputs.push(recorded_input(path.to_string(), &key, &recorded)?);
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
        inputs,
        repo_specs: repo_specs(entry)?,
    })
}

/// The path part of a main-repository key (`@@//x`, and the `@//x` and
/// `//x` spellings Bazel also parses as the main repository). `None` for
/// a file of another repository or an absolute path: no edit of the
/// workspace changes those.
fn main_repo(key: &str) -> Option<&str> {
    let label = key.strip_prefix("@@").or_else(|| key.strip_prefix('@'));
    label.unwrap_or(key).strip_prefix("//")
}

fn recorded_input(path: String, key: &str, recorded: &str) -> Shape<RecordedInput> {
    // Bazel writes normalised paths. Anything else cannot be matched with
    // a workspace file, and matching it loosely could miss the file.
    let normal = path
        .split('/')
        .all(|segment| !matches!(segment, "" | "." | ".."));
    if !normal {
        return Err(format!("recorded input {key:?} is not a normalised path"));
    }
    Ok(RecordedInput {
        path,
        key: key.to_string(),
        recorded: recorded.to_string(),
    })
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
    /// SHA-256 `sha256` (bare hex), in this fact version's rendering.
    pub fn holds_digest(&self, index_url: &str, package: &str, sha256: &str) -> bool {
        let rendered = match self.fact_version {
            PipFactVersion::V1 => sha256.to_string(),
            PipFactVersion::V2 => format!("sha256:{sha256}"),
        };
        let mut dists = self.dists(index_url, package).iter();
        is_sha256(sha256) && dists.any(|(_, digest)| *digest == rendered)
    }
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
        let verdicts = lock.input_verdicts(files);
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
        assert!(listed.len() >= 49);
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
                let verdicts = lock.input_verdicts(&files);
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
            let verdicts = lock.input_verdicts(&files);
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
            let key = |path: &str| lock.recorded(path).next().unwrap().1.key.clone();
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
            let verdicts = lock.input_verdicts(&files);
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

    #[test]
    fn a_lock_file_that_is_absent_or_unreadable_is_not_a_shape() {
        assert_eq!(ModuleLock::from_file(&FileText::Absent), ModuleLock::Absent);
        let unreadable = ModuleLock::from_file(&FileText::Unreadable);
        assert_eq!(unreadable, ModuleLock::Unreadable);
        // Neither has entries, and neither says that nothing is recorded.
        assert!(unreadable.entries().is_empty() && unreadable.facts().is_empty());
        assert_eq!(unreadable.lock_file_version(), None);
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
            r#"{"recordedInputs": [], "generatedRepoSpecs": []}"#.to_string(),
            r#"{"recordedInputs": [], "generatedRepoSpecs": {"dep_a": "spec"}}"#.to_string(),
        ] {
            assert!(unknown(&with_entry(&entry)), "{entry}");
        }
    }

    /// What is not a main-repository file is not an unknown shape: it is
    /// skipped, because no edit of the workspace changes it.
    #[test]
    fn inputs_of_other_kinds_and_other_repositories_are_skipped() {
        let entry = format!(
            r#"{{"recordedInputs": [
                "REPO_MAPPING:rules_dotnet+,platforms platforms",
                "ENV:GOPROXY \\0",
                "DIRENTS:@@//third_party 7f",
                "FILE:@@rules_go+//go.mod {SHA_A}",
                "FILE:/etc/hosts {SHA_A}",
                "FILE:@@//a\\sb\\\\c.lock {SHA_A}",
                "FILE:@//single.lock {SHA_A}",
                "FILE://bare.lock ENOENT"
            ]}}"#
        );
        let lock = ModuleLock::parse(with_entry(&entry).as_bytes());
        let [entry] = lock.entries() else {
            panic!("{lock:?}");
        };
        let paths: Vec<&str> = entry.inputs.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(paths, ["a b\\c.lock", "single.lock", "bare.lock"]);
        assert_eq!(entry.inputs[0].key, "@@//a b\\c.lock");
        assert_eq!(entry.inputs[2].recorded, "ENOENT");

        // The older containers skip the same keys.
        for container in ["accumulatedFileDigests", "recordedFileInputs"] {
            let entry = format!(
                r#"{{"{container}": {{"@@gazelle~//:go.mod": "{SHA_A}", "/abs/x": "{SHA_A}"}},
                    "recordedDirentsInputs": {{"@@//third_party": "7f"}},
                    "envVariables": {{"GOPROXY": null}}}}"#
            );
            let lock = ModuleLock::parse(with_entry(&entry).as_bytes());
            assert!(matches!(lock.entries(), [entry] if entry.inputs.is_empty()));
        }

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
        let [entry] = lock.entries() else {
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
            let entries: Vec<_> = lock.entries_of(&label, extension).collect();
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
            assert_eq!(lock.entries_of(&label, "other").count(), 0);
            assert_eq!(lock.entries_of("//:paket.bzl", extension).count(), 0);
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
    /// passes `error` mode and builds the unpatched package, on every
    /// line. Digest equality alone is therefore no evidence: the entry's
    /// repository specs must carry the new pin too.
    #[test]
    fn a_forged_digest_is_told_from_a_refresh_by_the_repository_specs() {
        for line in ["7.0.2", "7.7.2", "9.3.2"] {
            let dir = format!("module_lock/stale-repair/bazel-{line}");
            let after = Workspace::new(&dir, &[("dep.lock", "dep.lock.after")]);
            let before = Workspace::new(&dir, &[("dep.lock", "dep.lock.before")]);
            let read = |name: &str| lock(&format!("{dir}/{name}.MODULE.bazel.lock"));
            let state = |lock: &ModuleLock, files: &Workspace| {
                let verdicts = lock.input_verdicts(files);
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
        }
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
        let spec = &lock
            .entries_of("//:ext.bzl", "toy")
            .next()
            .unwrap()
            .repo_specs[0];
        assert_eq!(spec.name, "dep_a");
        assert_eq!(spec.rule.as_deref(), Some("@@//:ext.bzl%toy_repo"));
        let lock = lock_9_3_2_spec_rule();
        assert_eq!(lock.as_deref(), Some("@@//:ext.bzl%toy_repo"));
    }

    /// The rule id of lock version 28, which writes it as one member.
    fn lock_9_3_2_spec_rule() -> Option<String> {
        let lock = lock("module_lock/stale-repair/bazel-9.3.2/baseline.MODULE.bazel.lock");
        let entry = lock.entries_of("//:ext.bzl", "toy").next().unwrap();
        entry.repo_specs[0].rule.clone()
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
        let records: Vec<_> = repaired.recorded("dep.lock").collect();
        let patched = |index: usize| records[index].0.specs_mention("socket-patched-a-1.0");
        assert_eq!(records.len(), 2);
        assert!(!patched(0) && patched(1));
        assert_eq!(repaired.recorded("other.lock").count(), 0);
        // Four more extensions have a general entry and no file input.
        assert!(repaired.entries().len() > 2);
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
            assert_eq!(lock.entries_of(PIP.0, PIP.1).count(), 0);
            let facts: Vec<_> = lock.facts_of(PIP.0, PIP.1).collect();
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
        assert!(baseline.holds_digest(PYPI, "six", SIX_1_17));
        assert!(baseline.holds_digest("https://pypi.org/simple/", "six", SIX_1_17));
        assert!(!baseline.holds_digest("https://example.test/simple", "six", SIX_1_17));
        assert!(!baseline.holds_digest(PYPI, "idna", SIX_1_17));
        assert!(!baseline.holds_digest(PYPI, "six", &format!("sha256:{SIX_1_17}")));
        let repaired = read("pip-v1", "bazel-repaired");
        assert!(!repaired.holds_digest(PYPI, "six", SIX_1_17));
        assert_eq!(repaired.dists(PYPI, "six").len(), 2);

        // rules_python 2.5.0-rc4 on Bazel 9.3.2: `sha256:<hex>`.
        let baseline = read("pip-v2", "baseline");
        assert_eq!(baseline.fact_version, PipFactVersion::V2);
        assert_eq!(baseline.dists(PYPI, "six").len(), 2);
        assert!(baseline.holds_digest(PYPI, "six", SIX_1_17));
        let digest = &baseline.dists(PYPI, "six")[1].1;
        assert_eq!(*digest, format!("sha256:{SIX_1_17}"));
        let repaired = read("pip-v2", "bazel-repaired");
        assert!(repaired.dists(PYPI, "six").is_empty());
        assert_eq!(repaired.dist_hashes[0].packages.len(), 31);
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
        assert!(!known.holds_digest(PYPI, "six", ""));
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

    /// Probe L3: gazelle's facts are one ordered list, and a rewrite adds
    /// a member (the replacement's `.mod` file) instead of replacing one.
    #[test]
    fn go_deps_facts_are_one_ordered_list() {
        let facts = |name: &str| {
            let lock = lock(&format!(
                "module_lock/facts/go-deps/{name}.MODULE.bazel.lock"
            ));
            assert_eq!(lock.entries_of("//:extensions.bzl", "go_deps").count(), 0);
            let go_deps = lock
                .facts_of("//:extensions.bzl", "go_deps")
                .next()
                .unwrap();
            // The Go SDK's facts are another extension's and another shape.
            let sdk = lock
                .facts_of("//go:extensions.bzl", "go_sdk")
                .next()
                .unwrap();
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
            assert!(lock.entries().is_empty());
            let [facts] = lock.facts() else {
                panic!("{name}: {} facts", lock.facts().len());
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
}
