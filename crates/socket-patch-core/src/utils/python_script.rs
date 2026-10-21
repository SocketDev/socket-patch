use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::ArtifactSource;
use crate::vendor::common::{is_pep508_direct_reference, pep508_name, pyproject_dependency_specs};

pub(crate) fn script_metadata(text: &str) -> Result<(Range<usize>, String), String> {
    let mut offset = 0;
    let mut start = None;
    let mut metadata = String::new();
    let mut block = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "# /// script" {
            if start.is_some() || block.is_some() {
                return Err("multiple PEP 723 script metadata blocks".to_string());
            }
            start = Some(offset + line.len());
        } else if let Some(begin) = start {
            if trimmed == "# ///" {
                block = Some((begin..offset, metadata.clone()));
                start = None;
            } else {
                let content = trimmed
                    .strip_prefix("# ")
                    .or_else(|| trimmed.strip_prefix('#'))
                    .ok_or_else(|| "invalid PEP 723 metadata comment".to_string())?;
                metadata.push_str(content);
                metadata.push('\n');
            }
        }
        offset += line.len();
    }
    if start.is_some() {
        return Err("unclosed PEP 723 script metadata block".to_string());
    }
    block.ok_or_else(|| "script has no PEP 723 metadata block".to_string())
}

pub(crate) fn replace_script_metadata(text: &str, metadata: &str) -> Result<String, String> {
    let (span, _) = script_metadata(text)?;
    let newline = crate::utils::line_endings::terminator(text);
    let mut replacement = String::new();
    for line in metadata.lines() {
        replacement.push('#');
        if !line.is_empty() {
            replacement.push(' ');
            replacement.push_str(line);
        }
        replacement.push_str(newline);
    }
    let mut output = text.to_string();
    output.replace_range(span, &replacement);
    Ok(output)
}

/// The PEP 503 name a dependency specifier declares.
fn dependency_name(specifier: &str) -> String {
    canonicalize_pypi_name(pep508_name(specifier))
}

/// Whether `previous` is socket-patch's own earlier hosted source for this
/// package that `current` may replace: a rotated grant token on the same
/// artifact path, or (the shared PyPI recognizer) a superseding patch uuid
/// for the same name and version on Socket's patch server.
pub(crate) fn same_hosted_artifact(
    previous: &str,
    current: &str,
    name: &str,
    version: &str,
) -> bool {
    if crate::vendor::lock_inventory::pypi::replaceable_hosted_pin(previous, current, name, version)
    {
        return true;
    }
    let (Ok(previous), Ok(current)) = (reqwest::Url::parse(previous), reqwest::Url::parse(current))
    else {
        return false;
    };
    if previous.origin() != current.origin()
        || previous.username() != current.username()
        || previous.password() != current.password()
        || previous.query() != current.query()
        || previous.fragment() != current.fragment()
    {
        return false;
    }
    let previous_path: Vec<_> = previous.path_segments().into_iter().flatten().collect();
    let current_path: Vec<_> = current.path_segments().into_iter().flatten().collect();
    if previous_path.len() != current_path.len() || current_path.len() < 3 {
        return false;
    }
    let grant_index = current_path.len() - 3;
    previous_path[..grant_index] == current_path[..grant_index]
        && previous_path[grant_index + 1..] == current_path[grant_index + 1..]
        && uuid::Uuid::parse_str(previous_path[grant_index]).is_ok()
        && uuid::Uuid::parse_str(current_path[grant_index]).is_ok()
        && uuid::Uuid::parse_str(current_path[grant_index + 1]).is_ok()
}

/// How a freshly created `[tool.uv.sources]` is laid out.
///
/// A PEP 723 script block is reverted by DOCUMENT restore
/// (`vendor::pypi_lock::restore_document`), which can only converge on the
/// exact pre-vendor bytes after an out-of-order multi-package revert of
/// DIRECT dependencies (one `sources.<name>` key each) when the tables we
/// created vanish once empty. Only DOTTED keys do that after a parse round
/// trip (dotted-ness is syntax; `implicit` is not), so the script block
/// keeps `tool.uv.sources.x = { … }` right after `dependencies`, where
/// placement was never a problem. TRANSITIVE pairs are different: they share
/// one `override-dependencies` array, and `restore_value`'s array branch
/// flags drift as soon as the entries stop lining up, so their revert stays
/// order-dependent whatever the layout.
///
/// A `pyproject.toml` is reverted by exact text replay of the recorded
/// original, so it can use uv's own layout: header-less `[tool]` / `[tool.uv]`
/// parents and a real `[tool.uv.sources]` table. Where that header lands is
/// toml_edit's choice, not ours: a new table is rendered right after the
/// last PRE-EXISTING table visited before it in depth-first key order —
/// directly after an existing `[tool.uv]`, after `[tool.ruff]` when that is
/// the only `[tool.*]` table (even when that puts it BEFORE `[project]`),
/// and at the very end of the document — after a trailing `[build-system]` —
/// when there is no `[tool]` block yet. (Dotted keys would instead render as
/// `tool.uv.sources.x = …` in the ROOT body — i.e. ABOVE `[project]` —
/// whenever the pyproject had no `[tool]` header yet; an older CLI wrote
/// exactly that, and `rewrite_sources` keeps extending such a dotted table
/// rather than adding a second, conflicting header.)
#[derive(Clone, Copy)]
enum SourcesLayout {
    Dotted,
    Tables,
}

impl SourcesLayout {
    fn parent(self) -> Item {
        let mut table = Table::new();
        match self {
            Self::Dotted => table.set_dotted(true),
            Self::Tables => table.set_implicit(true),
        }
        Item::Table(table)
    }

    fn leaf(self) -> Item {
        let mut table = Table::new();
        if matches!(self, Self::Dotted) {
            table.set_dotted(true);
        }
        Item::Table(table)
    }
}

fn rewrite_sources(
    document: &mut DocumentMut,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    direct: bool,
    layout: SourcesLayout,
) -> Result<(), String> {
    let hosted = matches!(artifact, ArtifactSource::Url(_));
    let (key, location) = match artifact {
        ArtifactSource::Url(location) => ("url", location),
        ArtifactSource::Path(location) => ("path", location),
    };
    let tool = document.entry("tool").or_insert(layout.parent());
    let uv = tool
        .as_table_like_mut()
        .ok_or("Python tool metadata must be a table")?
        .entry("uv")
        .or_insert(layout.parent());
    let uv = uv
        .as_table_like_mut()
        .ok_or("Python tool.uv metadata must be a table")?;
    let sources = uv.entry("sources").or_insert(layout.leaf());
    let sources = sources
        .as_table_like_mut()
        .ok_or("Python tool.uv.sources must be a table")?;
    let existing = sources
        .iter()
        .find(|(candidate, _)| canonicalize_pypi_name(candidate) == name)
        .map(|(key, value)| (key.to_string(), value.clone()));
    if let Some((existing_name, existing)) = existing {
        let previous = existing
            .as_table_like()
            .filter(|table| table.len() == 1)
            .and_then(|table| table.get(key))
            .and_then(Item::as_str);
        let same = previous.is_some_and(|previous| {
            previous == location
                || (key == "url" && same_hosted_artifact(previous, location, name, version))
        });
        if !same {
            return Err(format!("Python project already declares a source for {existing_name}; revert it before applying a different patch"));
        }
        if previous != Some(location) {
            let mut source = InlineTable::new();
            source.insert(key, Value::from(location));
            source.fmt();
            sources.insert(&existing_name, Item::Value(Value::InlineTable(source)));
        }
    } else {
        let mut source = InlineTable::new();
        source.insert(key, Value::from(location));
        source.fmt();
        sources.insert(name, Item::Value(Value::InlineTable(source)));
    }
    if !direct {
        let specifier = format!("{name}=={version}");
        let overrides = uv
            .entry("override-dependencies")
            .or_insert(Item::Value(Value::Array(Array::new())));
        let overrides = overrides
            .as_array_mut()
            .ok_or("Python override-dependencies must be an array")?;
        let existing = overrides
            .iter()
            .filter_map(Value::as_str)
            .find(|spec| dependency_name(spec) == name)
            .map(str::to_string);
        if let Some(existing) = existing {
            if existing != specifier {
                return Err(format!(
                    "Python project already overrides {name}; revert it before applying a patch"
                ));
            }
        } else if hosted {
            push_hosted_override(overrides, specifier);
        } else {
            overrides.push(specifier);
        }
    }
    Ok(())
}

/// Refuse when one of `specs` declares `name` (canonical) as a PEP 508
/// direct reference (`six @ https://…`, `six @ git+…`): that is the user's
/// own source, the `[project]` spelling of a `[tool.uv.sources]` entry, and
/// a source added beside it would silently replace it (hosted) or leave a
/// lock uv rejects (vendored) (#767).
fn refuse_direct_reference<'a>(
    file: &str,
    name: &str,
    specs: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    match specs
        .into_iter()
        .find(|spec| dependency_name(spec) == name && is_pep508_direct_reference(spec))
    {
        Some(spec) => Err(format!(
            "{file} declares {name} as the PEP 508 direct reference {spec:?}; refusing to \
             overwrite a user-authored source"
        )),
        None => Ok(()),
    }
}

/// The comment the hosted rewrite puts on the line above each
/// `override-dependencies` entry it adds. v5 hosted mode keeps no ledger,
/// so this comment is the only evidence the upstream restore has that the
/// entry is socket-patch's to remove: an entry without it, even one spelled
/// exactly `<name>==<version>`, is the user's own pin and is kept (#411).
pub(crate) const HOSTED_OVERRIDE_MARK: &str =
    "# socket-patch hosted: pins a patched transitive dependency; rollback removes it";

/// Whether an `override-dependencies` element carries
/// [`HOSTED_OVERRIDE_MARK`] (the hosted rewrite added it).
pub(crate) fn is_hosted_override(value: &Value) -> bool {
    value
        .decor()
        .prefix()
        .and_then(|prefix| prefix.as_str())
        .is_some_and(|prefix| prefix.contains(HOSTED_OVERRIDE_MARK))
}

/// One `override-dependencies` entry the hosted rewrite added for a
/// transitive dependency ([`hosted_override_pins`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedOverridePin {
    /// Its index in the `override-dependencies` array.
    pub index: usize,
    /// PEP 503 canonical name.
    pub name: String,
    pub version: String,
}

/// The `<name>==<version>` entries of the metadata's `[tool.uv]
/// override-dependencies` that the hosted rewrite added
/// ([`HOSTED_OVERRIDE_MARK`]) for a package the metadata does not declare
/// directly (`script`: `doc` is a PEP 723 block, whose own requirements are
/// its `dependencies`). The rewrite adds an override only for a transitive
/// dependency, so a marked entry for a direct one is not its own. Hosted
/// mode keeps no ledger: these are the only overrides socket-patch may
/// remove (#411), and the only ones a relock can leave behind as Socket's
/// own wiring (#1445).
pub(crate) fn hosted_override_pins(doc: &DocumentMut, script: bool) -> Vec<HostedOverridePin> {
    let uv = doc
        .get("tool")
        .and_then(Item::as_table_like)
        .and_then(|t| t.get("uv"))
        .and_then(Item::as_table_like);
    let Some(overrides) = uv
        .and_then(|u| u.get("override-dependencies"))
        .and_then(Item::as_array)
    else {
        return Vec::new();
    };
    let strings = |item: Option<&Item>| -> Vec<String> {
        item.and_then(Item::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|spec| canonicalize_pypi_name(pep508_name(spec)))
            .collect()
    };
    let direct: Vec<String> = if script {
        strings(doc.get("dependencies"))
    } else {
        pyproject_dependency_specs(doc)
            .iter()
            .map(|(_, spec)| canonicalize_pypi_name(pep508_name(spec)))
            .chain(strings(uv.and_then(|u| u.get("dev-dependencies"))))
            .collect()
    };
    overrides
        .iter()
        .enumerate()
        .filter(|(_, value)| is_hosted_override(value))
        .filter_map(|(index, value)| {
            let compact: String = value
                .as_str()?
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let raw = pep508_name(&compact);
            let version = compact[raw.len()..].strip_prefix("==")?;
            let exact = !version.is_empty()
                && version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '!' | '-' | '_'));
            let name = canonicalize_pypi_name(raw);
            (exact && !raw.is_empty() && !direct.contains(&name)).then(|| HostedOverridePin {
                index,
                name,
                version: version.to_string(),
            })
        })
        .collect()
}

/// Whether `metadata` (a pyproject.toml, or a PEP 723 script when
/// `script`) wires `name` as a transitive package: an `[tool.uv]
/// override-dependencies` entry names it (the hosted rewrite's marked one or
/// the user's own, which the rewrite reuses) and no dependency array
/// declares it, so `[tool.uv.sources]` reaches it only through the
/// override. uv before 0.5.5 ignores sources there (#1569). Unparseable
/// metadata wires nothing.
pub(crate) fn wires_through_override(metadata: &str, script: bool, name: &str) -> bool {
    let toml = if script {
        match script_metadata(metadata) {
            Ok((_, toml)) => toml,
            Err(_) => return false,
        }
    } else {
        metadata.to_string()
    };
    let Ok(doc) = toml.parse::<DocumentMut>() else {
        return false;
    };
    let name = canonicalize_pypi_name(name);
    let uv = doc
        .get("tool")
        .and_then(Item::as_table_like)
        .and_then(|tool| tool.get("uv"))
        .and_then(Item::as_table_like);
    if !contains_dependency(uv.and_then(|uv| uv.get("override-dependencies")), &name) {
        return false;
    }
    // The same "direct" reading the rewrites use to decide on an override.
    let direct = if script {
        contains_dependency(doc.get("dependencies"), &name)
    } else {
        pyproject_dependency_specs(&doc)
            .into_iter()
            .any(|(_, spec)| dependency_name(spec) == name)
            || uv.is_some_and(|uv| contains_dependency(uv.get("dev-dependencies"), &name))
    };
    !direct
}

/// The advisory for [`wires_through_override`] wiring, shared by hosted
/// (`redirect_uv_override_requires_uv_0_5_6`) and vendored
/// (`pypi_uv_override_requires_uv_0_5_6`). Measured with the real binaries,
/// 0.5.5 is the first uv that keeps the override's source; the advice and
/// the codes keep the documented 0.5.6.
pub(crate) fn uv_override_advisory(name: &str, version: &str) -> String {
    format!(
        "transitive wiring of {name}=={version} via [tool.uv] override-dependencies is \
         not honored by uv before 0.5.5, which reinstalls the registry wheel on a plain \
         `uv sync` — pin uv >= 0.5.6 or make the package a direct dependency"
    )
}

/// The advisory for a repointed `[manifest]` `constraints` /
/// `build-constraints` entry, shared by hosted
/// (`redirect_uv_constraints_require_uv_0_5_6`) and vendored
/// (`pypi_uv_constraints_require_uv_0_5_6`); `wheel` says whose wheel
/// (`hosted` / `vendored`). uv 0.5.4 still rejects the entry, 0.5.5 accepts
/// it.
pub(crate) fn uv_constraints_advisory(name: &str, wheel: &str) -> String {
    format!(
        "[manifest] constraints for {name} were repointed at the {wheel} wheel, the shape \
         uv 0.5.5+ writes; uv 0.2.37–0.5.4 reject it under `uv sync --locked` (`--frozen` \
         and a plain `uv sync` still install the patch) — pin uv >= 0.5.6 or drop the \
         constraint on the patched package"
    )
}

/// Append `specifier` to `overrides` on its own line, under
/// [`HOSTED_OVERRIDE_MARK`]. An array the rewrite just created (empty) is
/// laid out multi-line with a trailing comma; an existing array keeps its
/// other elements as they were. Removing the element again (its decor goes
/// with it) restores the array's original bytes.
fn push_hosted_override(overrides: &mut Array, specifier: String) {
    const INDENT: &str = "    ";
    let created = overrides.is_empty();
    let mut value = Value::from(specifier);
    value
        .decor_mut()
        .set_prefix(format!("\n{INDENT}{HOSTED_OVERRIDE_MARK}\n{INDENT}"));
    value.decor_mut().set_suffix("");
    overrides.push_formatted(value);
    if created {
        overrides.set_trailing_comma(true);
        overrides.set_trailing("\n");
    }
}

fn contains_dependency(item: Option<&Item>, name: &str) -> bool {
    item.and_then(Item::as_array).is_some_and(|dependencies| {
        dependencies
            .iter()
            .filter_map(Value::as_str)
            .any(|specifier| dependency_name(specifier) == name)
    })
}

/// The project-level uv settings file, read beside `pyproject.toml` (and
/// beside a PEP 723 script, from uv's working directory).
pub const UV_TOML: &str = "uv.toml";

/// A uv settings file above the scanned root that uv applies to a PEP 723
/// script (#1501) or a project (#1545) there, found by
/// [`find_ancestor_uv_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvConfig {
    /// The file relative to the scanned root, e.g. `../uv.toml`.
    pub rel: String,
    pub text: String,
}

impl UvConfig {
    /// Whether the file is a `uv.toml` (settings at its top level) rather
    /// than a `pyproject.toml` (settings under `[tool.uv]`).
    pub fn is_uv_toml(&self) -> bool {
        Path::new(&self.rel).file_name() == Some(UV_TOML.as_ref())
    }

    /// The file as refusals name it, with the settings table it holds:
    /// (label, path of the table within the file).
    fn settings_location(&self) -> (String, &'static [&'static str]) {
        if self.is_uv_toml() {
            (self.rel.clone(), &[])
        } else {
            (format!("{} [tool.uv]", self.rel), &["tool", "uv"])
        }
    }
}

/// Whether a PEP 723 script or a project in a root holding `pyproject` and
/// `uv_toml` takes uv's settings from the root itself, so uv looks no
/// further up.
pub fn root_governs_script(pyproject: Option<&str>, uv_toml: Option<&str>) -> bool {
    uv_toml.is_some() || pyproject.is_some_and(pyproject_has_uv_settings)
}

/// Whether uv takes a script's settings from `pyproject`: it has a
/// `[tool.uv]` table. One that does not parse does not: uv warns and goes
/// on to the parent directory.
fn pyproject_has_uv_settings(pyproject: &str) -> bool {
    pyproject.parse::<DocumentMut>().is_ok_and(|document| {
        document
            .get("tool")
            .and_then(Item::as_table_like)
            .and_then(|tool| tool.get("uv"))
            .is_some()
    })
}

/// The uv settings file above `root` that uv applies to a PEP 723 script
/// or a project in `root`, when `root` itself holds none.
///
/// uv reads a script's or a project's settings from the nearest directory
/// at or above its own that holds a `uv.toml`, or a `pyproject.toml` with
/// a `[tool.uv]` table, with `uv.toml` first in each directory. A
/// user-level `uv.toml`
/// (`~/.config/uv`) is the installing machine's and is not looked up.
pub fn find_ancestor_uv_config(root: &Path) -> Option<UvConfig> {
    for (rel, path) in ancestor_uv_config_files(root) {
        let text = match crate::utils::fs::read_regular_to_string_sync(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            // uv stops at a settings file it cannot read and reports it.
            Err(_) => return None,
        };
        let config = UvConfig { rel, text };
        if config.is_uv_toml() || pyproject_has_uv_settings(&config.text) {
            return Some(config);
        }
    }
    None
}

/// `[tool.uv]` keys that describe the project declaring them rather than
/// settings another project inherits: uv documents them as project
/// metadata, read from the project's (or its workspace root's) own
/// pyproject. Checked against uv 0.11: a parent's `override-dependencies`
/// or `constraint-dependencies` never reaches a child project's lock.
const UV_PROJECT_ONLY_KEYS: &[&str] = &[
    "build-backend",
    "build-constraint-dependencies",
    "conflicts",
    "constraint-dependencies",
    "default-groups",
    "dependency-groups",
    "dev-dependencies",
    "environments",
    "exclude-dependencies",
    "managed",
    "override-dependencies",
    "package",
    "required-environments",
    "sources",
    "workspace",
];

/// Refuse to wire a project whose `pyproject` would shadow the uv settings
/// it inherits from `ancestor` (#1545).
///
/// uv reads a project's settings from the nearest directory at or above it
/// that holds a `uv.toml` or a `pyproject.toml` with `[tool.uv]`, the same
/// lookup as a script's ([`find_ancestor_uv_config`]). When the project's
/// own `pyproject` and `uv_toml` set none, the `[tool.uv]` table a wired
/// source adds makes the project's pyproject the settings file, so every
/// setting of the parent (`exclude-newer`, `resolution`, indexes) is
/// dropped: `uv sync --locked` fails on those the lock records, and a
/// plain `uv lock` re-resolves without them. Every inherited setting is
/// refused, not only the recorded ones, since socket-patch must not
/// silently change how uv installs the project. A parent that sets only project metadata
/// ([`UV_PROJECT_ONLY_KEYS`], e.g. a workspace root's `workspace`), or
/// does not parse (uv reports it itself), loses nothing.
pub fn refuse_uv_project_shadowing(
    pyproject: &str,
    uv_toml: Option<&str>,
    ancestor: Option<&UvConfig>,
) -> Result<(), String> {
    let Some(config) = ancestor else {
        return Ok(());
    };
    if root_governs_script(Some(pyproject), uv_toml) {
        return Ok(());
    }
    let Ok(document) = config.text.parse::<DocumentMut>() else {
        return Ok(());
    };
    let (label, path) = config.settings_location();
    let mut settings = Some(document.as_table() as &dyn TableLike);
    for key in path {
        settings = settings
            .and_then(|table| table.get(key))
            .and_then(Item::as_table_like);
    }
    let keys: Vec<&str> = settings
        .into_iter()
        .flat_map(|table| table.iter().map(|(key, _)| key))
        .filter(|key| !UV_PROJECT_ONLY_KEYS.contains(key))
        .collect();
    if keys.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{label} sets {} for this project, and the [tool.uv] table a wired source adds to \
         pyproject.toml would make uv read its settings from pyproject.toml instead and drop \
         them (a lock written with them then fails `uv sync --locked`); add a [tool.uv] table \
         to pyproject.toml carrying the settings the project needs to wire a patch",
        keys.join(", ")
    ))
}

/// The files [`find_ancestor_uv_config`] may read, in lookup order, as
/// (path relative to `root`, absolute path).
pub fn ancestor_uv_config_files(root: &Path) -> Vec<(String, PathBuf)> {
    let Ok(root) = std::path::absolute(root) else {
        return Vec::new();
    };
    let mut normalized = PathBuf::new();
    for component in root.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    let mut up = String::new();
    let mut files = Vec::new();
    for dir in normalized.ancestors().skip(1) {
        up.push_str("../");
        for name in [UV_TOML, "pyproject.toml"] {
            files.push((format!("{up}{name}"), dir.join(name)));
        }
    }
    files
}

/// A uv setting pair that applies to some packages: a bool that sets it
/// for every package and a list naming packages (uv's `Combine` keeps the
/// nearer bool and adds the lists up).
struct PackageSetting {
    all: &'static str,
    packages: &'static str,
    /// Why the setting makes a wired patch fail, after "{file} sets {key}, ".
    consequence: &'static str,
    remedy: &'static str,
}

const NO_SOURCES: PackageSetting = PackageSetting {
    all: "no-sources",
    packages: "no-sources-package",
    consequence: "so uv ignores the [tool.uv.sources] entry and a plain `uv sync` would \
                  install the unpatched registry wheel",
    remedy: "remove the setting to wire a patch",
};

const NO_BINARY: PackageSetting = PackageSetting {
    all: "no-binary",
    packages: "no-binary-package",
    consequence: "so uv refuses to install it from a wheel and every `uv sync` would fail on \
                  the patched wheel (\"marked as `--no-binary` but is itself a binary \
                  distribution\")",
    remedy: "patches are shipped as wheels; remove the package from the setting to wire a \
             patch",
};

/// The governing project settings file, as (label, text, path of its
/// settings table): a `uv.toml` replaces pyproject's `[tool.uv]` outright.
fn project_settings<'a>(
    pyproject: Option<&'a str>,
    uv_toml: Option<&'a str>,
) -> Option<(String, &'a str, &'static [&'static str])> {
    match uv_toml {
        Some(text) => Some((UV_TOML.to_string(), text, &[][..])),
        None => pyproject.map(|text| {
            (
                "pyproject.toml [tool.uv]".to_string(),
                text,
                &["tool", "uv"][..],
            )
        }),
    }
}

/// The governing project settings for a PEP 723 script in a root whose own
/// `pyproject` and `uv_toml` may not govern it: when neither sets uv's
/// settings, `ancestor` (the [`find_ancestor_uv_config`] above the root)
/// does (#1501).
fn script_project_settings<'a>(
    pyproject: Option<&'a str>,
    uv_toml: Option<&'a str>,
    ancestor: Option<&'a UvConfig>,
) -> Option<(String, &'a str, &'static [&'static str])> {
    match ancestor {
        Some(config) if !root_governs_script(pyproject, uv_toml) => {
            let (label, path) = config.settings_location();
            Some((label, config.text.as_str(), path))
        }
        _ => project_settings(pyproject, uv_toml),
    }
}

/// Refuse to wire a `[tool.uv.sources]` entry for `name` that uv would
/// ignore (#564).
///
/// Under `no-sources = true`, or a `no-sources-package` list naming the
/// package, uv drops the source, so a wired entry fails `uv sync --locked`,
/// and a plain `uv sync` relocks the package to the registry and installs
/// the unpatched wheel. `script` is the PEP 723 script being wired (`None`
/// for a project), and `pyproject` and `uv_toml` are the project's files,
/// when present. Each file's settings are uv's (checked against uv 0.11): a
/// `uv.toml` replaces pyproject's `[tool.uv]` outright; a script's own
/// `no-sources` wins over the project's, while the two `no-sources-package`
/// lists combine; and an explicit `no-sources = false` disables the list.
/// A file that does not parse sets nothing here: uv reports it itself, and
/// the rewriters report a metadata file they cannot edit.
pub fn refuse_uv_no_sources(
    name: &str,
    script: Option<&str>,
    pyproject: Option<&str>,
    uv_toml: Option<&str>,
) -> Result<(), String> {
    refuse_package_setting(
        &NO_SOURCES,
        name,
        script,
        project_settings(pyproject, uv_toml),
    )
}

/// [`refuse_uv_no_sources`] for a PEP 723 script in a root whose own
/// `pyproject` and `uv_toml` may not govern it: when neither sets uv's
/// settings, `ancestor` (the [`find_ancestor_uv_config`] above the root)
/// does (#1501).
pub fn refuse_uv_script_no_sources(
    name: &str,
    script: &str,
    pyproject: Option<&str>,
    uv_toml: Option<&str>,
    ancestor: Option<&UvConfig>,
) -> Result<(), String> {
    refuse_package_setting(
        &NO_SOURCES,
        name,
        Some(script),
        script_project_settings(pyproject, uv_toml, ancestor),
    )
}

/// Refuse to wire a patched wheel for `name` that uv may not install
/// (#1603).
///
/// Under `no-binary = true`, or a `no-binary-package` list naming the
/// package, uv installs the package only from an sdist, and every Socket
/// artifact is a wheel: once wired, `uv sync` (locked, frozen or plain)
/// and `uv run --locked` fail. The settings combine as uv's
/// ([`refuse_uv_no_sources`]): a `uv.toml` replaces pyproject's
/// `[tool.uv]`, a script's own `no-binary` wins over the project's, the
/// two lists add up, and `no-binary = false` disables the list.
pub fn refuse_uv_no_binary(
    name: &str,
    script: Option<&str>,
    pyproject: Option<&str>,
    uv_toml: Option<&str>,
) -> Result<(), String> {
    refuse_package_setting(
        &NO_BINARY,
        name,
        script,
        project_settings(pyproject, uv_toml),
    )
}

/// [`refuse_uv_no_binary`] for a PEP 723 script, with the project settings
/// chosen as in [`refuse_uv_script_no_sources`].
pub fn refuse_uv_script_no_binary(
    name: &str,
    script: &str,
    pyproject: Option<&str>,
    uv_toml: Option<&str>,
    ancestor: Option<&UvConfig>,
) -> Result<(), String> {
    refuse_package_setting(
        &NO_BINARY,
        name,
        Some(script),
        script_project_settings(pyproject, uv_toml, ancestor),
    )
}

/// The check behind [`refuse_uv_no_sources`] and [`refuse_uv_no_binary`]:
/// `project` is the governing settings file as (label, text, path of its
/// settings table).
fn refuse_package_setting(
    setting: &PackageSetting,
    name: &str,
    script: Option<&str>,
    project: Option<(String, &str, &[&str])>,
) -> Result<(), String> {
    struct Settings {
        file: String,
        all: Option<bool>,
        packages: Vec<String>,
    }
    let settings = |file: String, toml: &str, path: &[&str]| -> Option<Settings> {
        let document: DocumentMut = toml.parse().ok()?;
        let mut table = document.as_table() as &dyn TableLike;
        for key in path {
            table = table.get(key)?.as_table_like()?;
        }
        Some(Settings {
            file,
            all: table.get(setting.all).and_then(Item::as_bool),
            packages: table
                .get(setting.packages)
                .and_then(Item::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(canonicalize_pypi_name)
                .collect(),
        })
    };
    let script = script.and_then(|text| {
        let (_, metadata) = script_metadata(text).ok()?;
        settings(
            "the script's [tool.uv]".to_string(),
            &metadata,
            &["tool", "uv"],
        )
    });
    let project = project.and_then(|(file, text, path)| settings(file, text, path));
    let levels = [script, project];
    let levels = levels.iter().flatten();
    let refusal = |file: &str, key: &str| {
        Err(format!(
            "{file} sets {key}, {}; {}",
            setting.consequence, setting.remedy
        ))
    };
    match levels
        .clone()
        .find_map(|level| Some((level.file.as_str(), level.all?)))
    {
        Some((file, true)) => return refusal(file, &format!("{} = true", setting.all)),
        Some((_, false)) => return Ok(()),
        None => {}
    }
    let name = canonicalize_pypi_name(name);
    match levels
        .into_iter()
        .find(|level| level.packages.contains(&name))
    {
        Some(level) => refusal(&level.file, &format!("{} naming {name}", setting.packages)),
        None => Ok(()),
    }
}

pub fn rewrite_project_metadata(
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
) -> Result<Option<String>, String> {
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid pyproject.toml: {error}"))?;
    let name = canonicalize_pypi_name(name);
    if document
        .get("project")
        .and_then(Item::as_table_like)
        .is_none()
    {
        return Err("pyproject.toml has no project table".to_string());
    }
    let tool_uv = document
        .get("tool")
        .and_then(Item::as_table_like)
        .and_then(|tool| tool.get("uv"))
        .and_then(Item::as_table_like);
    let legacy_dev = tool_uv
        .and_then(|uv| uv.get("dev-dependencies"))
        .and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    refuse_direct_reference(
        "pyproject.toml",
        &name,
        pyproject_dependency_specs(&document)
            .into_iter()
            .map(|(_, spec)| spec)
            .chain(legacy_dev),
    )?;
    let direct = pyproject_dependency_specs(&document)
        .into_iter()
        .any(|(_, spec)| dependency_name(spec) == name)
        // The legacy `[tool.uv] dev-dependencies` array (still honoured by uv
        // with a deprecation warning) is a direct declaration too: uv records
        // it under `[package.metadata.requires-dev]`, so an override here
        // would be redundant — and ignored by uv < 0.5.6, which does not
        // apply `[tool.uv.sources]` to `override-dependencies`.
        || tool_uv
            .is_some_and(|uv| contains_dependency(uv.get("dev-dependencies"), &name));
    if tool_uv.is_some_and(|uv| uv.contains_key("workspace")) {
        return Err(
            "hosted sources for uv workspaces require a package-scoped source mapping".to_string(),
        );
    }
    rewrite_sources(
        &mut document,
        &name,
        version,
        artifact,
        direct,
        SourcesLayout::Tables,
    )?;
    let output = crate::utils::python_lock::preserve_line_endings(text, document.to_string());
    Ok((output != text).then_some(output))
}

pub fn rewrite_script_metadata(
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
) -> Result<Option<String>, String> {
    let (_, metadata) = script_metadata(text)?;
    let mut document: DocumentMut = metadata
        .parse()
        .map_err(|error| format!("invalid script metadata: {error}"))?;
    let name = canonicalize_pypi_name(name);
    refuse_direct_reference(
        "the script metadata",
        &name,
        document
            .get("dependencies")
            .and_then(Item::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    )?;
    let direct = contains_dependency(document.get("dependencies"), &name);
    rewrite_sources(
        &mut document,
        &name,
        version,
        artifact,
        direct,
        SourcesLayout::Dotted,
    )?;
    let output = replace_script_metadata(text, &document.to_string())?;
    Ok((output != text).then_some(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #815: the re-commented block takes the script's majority line
    /// ending; one stray CRLF line no longer turns it CRLF.
    #[test]
    fn replaced_metadata_takes_the_majority_line_ending() {
        let lf_majority =
            "#!/usr/bin/env python\r\n# /// script\n# dependencies = []\n# ///\nprint('x')\n";
        let out = replace_script_metadata(lf_majority, "dependencies = [\"a\"]\n").unwrap();
        assert!(out.contains("# dependencies = [\"a\"]\n# ///"), "{out:?}");
        let crlf_majority = "# /// script\r\n# dependencies = []\r\n# ///\r\nprint('x')\n";
        let out = replace_script_metadata(crlf_majority, "dependencies = [\"a\"]\n").unwrap();
        assert!(out.contains("# dependencies = [\"a\"]\r\n# ///"), "{out:?}");
    }

    /// #767: a PEP 508 direct reference to the patched package, wherever
    /// the project or script declares it, is the user's own source: the
    /// rewrite refuses instead of adding a `[tool.uv.sources]` entry beside it.
    #[test]
    fn direct_references_to_the_package_are_refused() {
        const URL: &str = "https://patch.socket.dev/six-1.16.0-py2.py3-none-any.whl";
        const WHEEL: &str =
            "https://files.pythonhosted.org/packages/d9/six-1.16.0-py2.py3-none-any.whl";
        let head = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n";
        for (deps, tail) in [
            (format!("[\"six @ {WHEEL}\", \"idna==3.7\"]"), String::new()),
            (
                "[\"Six[x]@git+https://github.com/benjaminp/six@1.16.0\"]".to_string(),
                String::new(),
            ),
            (
                "[\"idna==3.7\"]".to_string(),
                format!("\n[project.optional-dependencies]\nx = [\"six @ {WHEEL}\"]\n"),
            ),
            (
                "[\"idna==3.7\"]".to_string(),
                format!("\n[dependency-groups]\ndev = [\"six @ {WHEEL}\"]\n"),
            ),
            (
                "[\"idna==3.7\"]".to_string(),
                format!("\n[tool.uv]\ndev-dependencies = [\"six @ {WHEEL}\"]\n"),
            ),
        ] {
            let text = format!("{head}dependencies = {deps}\n{tail}");
            let err = rewrite_project_metadata(&text, "six", "1.16.0", ArtifactSource::Url(URL))
                .unwrap_err();
            assert!(err.contains("PEP 508 direct reference"), "{err}\n{text}");
        }
        let script =
            format!("# /// script\n# dependencies = [\"six @ {WHEEL}\"]\n# ///\nimport six\n");
        for artifact in [
            ArtifactSource::Url(URL),
            ArtifactSource::Path("w/six-1.16.0-py2.py3-none-any.whl"),
        ] {
            let err = rewrite_script_metadata(&script, "six", "1.16.0", artifact).unwrap_err();
            assert!(err.contains("PEP 508 direct reference"), "{err}");
        }
        // Another package's direct reference is not this one's source.
        let other = format!("{head}dependencies = [\"six==1.16.0\", \"idna @ {WHEEL}\"]\n");
        assert!(
            rewrite_project_metadata(&other, "six", "1.16.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn sources_are_paired_without_changing_the_script() {
        let script = "#!/usr/bin/env python3\n# /// script\n# dependencies = [\"urllib3==1.26.18\"]\n# ///\nprint('preserved')\n";
        let output = rewrite_script_metadata(
            script,
            "urllib3",
            "1.26.18",
            ArtifactSource::Path(".socket/vendor/pypi/patched.whl"),
        )
        .unwrap()
        .unwrap();
        assert!(output.starts_with("#!/usr/bin/env python3\n# /// script\n"));
        assert!(output.ends_with("# ///\nprint('preserved')\n"));
        let (_, metadata) = script_metadata(&output).unwrap();
        let document: DocumentMut = metadata.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["urllib3"]["path"].as_str(),
            Some(".socket/vendor/pypi/patched.whl")
        );
        assert!(rewrite_script_metadata(
            &output,
            "urllib3",
            "1.26.18",
            ArtifactSource::Path(".socket/vendor/pypi/patched.whl")
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn hosted_grant_refresh_preserves_patch_identity() {
        let previous = "https://patch.socket.dev/pkg/pypi/11111111-1111-4111-8111-111111111111/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
        let current = previous.replace(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        let script = "# /// script\n# dependencies = [\"urllib3==1.26.18\"]\n# ///\n";
        let old =
            rewrite_script_metadata(script, "urllib3", "1.26.18", ArtifactSource::Url(previous))
                .unwrap()
                .unwrap();
        let new =
            rewrite_script_metadata(&old, "urllib3", "1.26.18", ArtifactSource::Url(&current))
                .unwrap()
                .unwrap();
        assert!(new.contains(&current));
        assert!(!new.contains(previous));
        let different_host = current.replace("patch.socket.dev", "example.test");
        assert!(rewrite_script_metadata(
            &old,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(&different_host)
        )
        .is_err());
    }

    const OWN_A: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/11111111-1111-4111-8111-111111111111/aaaaaaaa-0000-4000-8000-000000000001/six-1.16.0-py2.py3-none-any.whl";
    const OWN_B: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/22222222-2222-4222-8222-222222222222/aaaaaaaa-0000-4000-8000-000000000004/six-1.16.0-py2.py3-none-any.whl";

    /// #742: a superseding patch (a new patch uuid for the same package and
    /// version) re-pins socket-patch's OWN earlier hosted source in both a
    /// uv project and a PEP 723 script, instead of refusing it as a
    /// user-authored source.
    #[test]
    fn superseding_patch_repins_own_hosted_source() {
        let project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"idna==3.7\"]\n";
        let script = "# /// script\n# dependencies = [\"six==1.16.0\"]\n# ///\n";
        type Rewrite = fn(&str, &str, &str, ArtifactSource<'_>) -> Result<Option<String>, String>;
        let writers: [(&str, Rewrite); 2] = [
            (project, rewrite_project_metadata),
            (script, rewrite_script_metadata),
        ];
        for (original, rewrite) in writers {
            let wired = rewrite(original, "six", "1.16.0", ArtifactSource::Url(OWN_A))
                .unwrap()
                .unwrap();
            let repinned = rewrite(&wired, "six", "1.16.0", ArtifactSource::Url(OWN_B))
                .unwrap_or_else(|e| panic!("superseding patch refused: {e}"))
                .expect("re-pinned");
            assert!(repinned.contains(OWN_B), "{repinned}");
            assert!(!repinned.contains(OWN_A), "{repinned}");
            assert_eq!(repinned.matches("six-1.16.0").count(), 1, "{repinned}");
            // The re-pin is settled: running the same patch again is a no-op.
            assert_eq!(
                rewrite(&repinned, "six", "1.16.0", ArtifactSource::Url(OWN_B)).unwrap(),
                None
            );
            // A path-prefixed --patch-server-url deployment re-pins its own
            // earlier source too.
            let custom_a = OWN_A.replace("patch.socket.dev/", "patches.internal.example/socket/");
            let custom_b = OWN_B.replace("patch.socket.dev/", "patches.internal.example/socket/");
            let wired = rewrite(original, "six", "1.16.0", ArtifactSource::Url(&custom_a))
                .unwrap()
                .unwrap();
            let repinned = rewrite(&wired, "six", "1.16.0", ArtifactSource::Url(&custom_b))
                .unwrap()
                .expect("re-pinned on a custom origin");
            assert!(repinned.contains(&custom_b) && !repinned.contains(&custom_a));
            // Not ours: another host, another version, credentials, or a
            // user path source still refuse.
            let wired = rewrite(original, "six", "1.16.0", ArtifactSource::Url(OWN_A))
                .unwrap()
                .unwrap();
            for foreign in [
                OWN_A.replace("patch.socket.dev", "example.test"),
                OWN_A.replace("1.16.0", "1.15.0"),
                OWN_A.replace("https://", "https://user@"),
            ] {
                let user = wired.replace(OWN_A, &foreign);
                assert!(
                    rewrite(&user, "six", "1.16.0", ArtifactSource::Url(OWN_B)).is_err(),
                    "{foreign} must stay a user source"
                );
            }
        }
    }

    /// A package declared in ANY project table (dependencies, an extra, a
    /// PEP 735 group, the legacy `[tool.uv] dev-dependencies`) is direct: its
    /// source needs no override. Anything else gets one.
    #[test]
    fn project_metadata_classifies_every_declaration_table() {
        let url = ArtifactSource::Url("https://example.test/patch.whl");
        let overrides = |text: &str| {
            let output = rewrite_project_metadata(text, "Urllib3", "1.26.18", url)
                .unwrap()
                .unwrap();
            let document: DocumentMut = output.parse().unwrap();
            assert_eq!(
                document["tool"]["uv"]["sources"]["urllib3"]["url"].as_str(),
                Some("https://example.test/patch.whl"),
                "{text}"
            );
            document["tool"]["uv"]
                .get("override-dependencies")
                .is_some()
        };
        for direct in [
            "[project]\nname='a'\ndependencies=[\" urllib3 >=1\"]\n",
            "[project]\nname='a'\n[project.optional-dependencies]\nx=[\"idna\", \"URLLIB3[socks]\"]\n",
            "[project]\nname='a'\n[dependency-groups]\nqa=[{include-group='x'}, \"urllib3\"]\n",
            "[project]\nname='a'\n[tool.uv]\ndev-dependencies=[\"urllib3\"]\n",
        ] {
            assert!(!overrides(direct), "{direct}");
        }
        for transitive in [
            "[project]\nname='a'\ndependencies=[\"requests\", 7]\n",
            "[project]\nname='a'\n[project.optional-dependencies]\nx=\"urllib3\"\n",
            "[project]\nname='a'\n[dependency-groups]\nqa=\"urllib3\"\n[tool.hatch.envs.x]\ndependencies=[\"urllib3\"]\n",
        ] {
            assert!(overrides(transitive), "{transitive}");
        }
    }

    #[test]
    fn transitive_sources_are_bound_to_an_override() {
        let output = rewrite_script_metadata(
            "# /// script\n# dependencies = [\"requests\"]\n# ///\n",
            "urllib3",
            "1.26.18",
            ArtifactSource::Url("https://example.test/patch.whl"),
        )
        .unwrap()
        .unwrap();
        let (_, metadata) = script_metadata(&output).unwrap();
        let document: DocumentMut = metadata.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["override-dependencies"][0].as_str(),
            Some("urllib3==1.26.18")
        );
    }
}

#[cfg(test)]
mod rendering_tests {
    use super::*;

    const URL: &str = "https://patch.socket.dev/alpha-1.0.0-py3-none-any.whl";

    /// A package declared only in the legacy `[tool.uv] dev-dependencies`
    /// array is a DIRECT dependency for hosted wiring: uv tracks it under
    /// `[package.metadata.requires-dev]`, so the source alone redirects it and
    /// no `override-dependencies` entry may be added (uv < 0.5.6 ignores
    /// sources on overrides and would reinstall the registry wheel).
    #[test]
    fn tool_uv_dev_dependencies_count_as_direct_for_hosted_sources() {
        let out = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = []\n\n[tool.uv]\ndev-dependencies = [\"alpha==1.0.0\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert!(!out.contains("override-dependencies"), "{out}");
        assert!(
            out.contains(&format!("[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}")),
            "{out}"
        );
        assert!(
            rewrite_project_metadata(&out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_none()
        );
    }

    /// A second pass over a rendering must be a no-op: the source is
    /// recognised as already present and nothing is re-emitted.
    fn assert_settled(out: &str) {
        assert!(
            rewrite_project_metadata(out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_none(),
            "second rewrite must be a no-op over:\n{out}"
        );
    }

    /// Byte-level shape of a pyproject edit: uv's own layout — a
    /// `[tool.uv.sources]` header AFTER `[project]` when `[project]` is the
    /// last table, never dotted keys at the top of the file; a transitive
    /// dep adds `[tool.uv]` with its override. (The sibling tests below pin
    /// where the header lands when other tables follow or precede.)
    #[test]
    fn project_sources_render_as_uv_style_headers_after_project() {
        let direct = rewrite_project_metadata(
            "[project]\nname = \"p\"\nversion = \"0.1.0\"\ndependencies = [\"alpha==1.0.0\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            direct,
            format!("[project]\nname = \"p\"\nversion = \"0.1.0\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n")
        );
        assert_settled(&direct);
        let transitive = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"requests\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            transitive,
            format!("[project]\nname = \"p\"\ndependencies = [\"requests\"]\n\n[tool.uv]\noverride-dependencies = [\n    {HOSTED_OVERRIDE_MARK}\n    \"alpha==1.0.0\",\n]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n")
        );
        assert_settled(&transitive);
        // An existing `[tool.uv]` header gains the sources as its own
        // sub-table; a CRLF pyproject stays CRLF.
        let existing = rewrite_project_metadata(
            "[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[tool.uv]\r\ndev-dependencies = [\"pytest\"]\r\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            existing,
            format!("[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[tool.uv]\r\ndev-dependencies = [\"pytest\"]\r\n\r\n[tool.uv.sources]\r\nalpha = {{ url = \"{URL}\" }}\r\n")
        );
        assert_settled(&existing);
        // An existing `[tool.uv.sources]` header is reused as-is.
        let header = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"beta\"]\n\n[tool.uv.sources]\nbeta = { git = \"https://example.test/beta\" }\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            header,
            format!("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"beta\"]\n\n[tool.uv.sources]\nbeta = {{ git = \"https://example.test/beta\" }}\nalpha = {{ url = \"{URL}\" }}\n")
        );
        assert_settled(&header);
    }

    /// The PEP 723 block keeps the fully dotted shape so that document
    /// restore can drop it without a trace once every source is reverted.
    #[test]
    fn script_sources_stay_dotted_inside_the_metadata_block() {
        let script = "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n# ///\nprint('x')\n";
        let out = rewrite_script_metadata(script, "alpha", "1.0.0", ArtifactSource::Url(URL))
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            format!("# /// script\n# dependencies = [\"alpha==1.0.0\"]\n# tool.uv.sources.alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n")
        );
        assert!(
            rewrite_script_metadata(&out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_none()
        );
    }

    /// No `[tool]` block yet and a `[build-system]` after `[project]`:
    /// toml_edit appends the new header after the LAST existing table, so
    /// `[tool.uv.sources]` follows `[build-system]`, not `[project]`. CRLF
    /// input stays CRLF.
    #[test]
    fn project_sources_follow_a_trailing_build_system_table() {
        let lf = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            lf,
            format!("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n")
        );
        assert_settled(&lf);
        let crlf = rewrite_project_metadata(
            "[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[build-system]\r\nrequires = [\"hatchling\"]\r\nbuild-backend = \"hatchling.build\"\r\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            crlf,
            format!("[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[build-system]\r\nrequires = [\"hatchling\"]\r\nbuild-backend = \"hatchling.build\"\r\n\r\n[tool.uv.sources]\r\nalpha = {{ url = \"{URL}\" }}\r\n")
        );
        assert_eq!(crlf.matches("\r\n").count(), crlf.matches('\n').count());
        assert_settled(&crlf);
    }

    /// `[tool]` with `uv = { … }` as an INLINE table: there is no `[tool.uv]`
    /// header to hang a `[tool.uv.sources]` table off, so the source has to
    /// live inside the inline table. toml_edit renders it as a dotted
    /// `sources.alpha = { … }` key on the `uv = { … }` line; whatever the
    /// exact spelling, it must parse back to the source and settle on the
    /// second pass. A transitive dep adds its override to the same table.
    #[test]
    fn project_sources_join_an_inline_tool_uv_table() {
        let direct = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool]\nuv = { dev-dependencies = [\"pytest\"] }\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        let document: DocumentMut = direct.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(URL)
        );
        assert_eq!(
            document["tool"]["uv"]["dev-dependencies"][0].as_str(),
            Some("pytest")
        );
        assert!(document["tool"]["uv"].is_inline_table(), "{direct}");
        assert_eq!(direct.matches("[tool]").count(), 1, "{direct}");
        assert!(!direct.contains("[tool.uv"), "{direct}");
        let uv_line = direct
            .lines()
            .find(|line| line.starts_with("uv = {"))
            .unwrap_or_else(|| panic!("uv stays an inline table:\n{direct}"));
        assert!(
            uv_line.contains(&format!("sources.alpha = {{ url = \"{URL}\" }}")),
            "{direct}"
        );
        assert!(uv_line.ends_with('}'), "{direct}");
        assert!(
            direct.starts_with(
                "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool]\n"
            ),
            "{direct}"
        );
        assert_settled(&direct);

        let transitive = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"requests\"]\n\n[tool]\nuv = { dev-dependencies = [\"pytest\"] }\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        let document: DocumentMut = transitive.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(URL)
        );
        assert_eq!(
            document["tool"]["uv"]["override-dependencies"][0].as_str(),
            Some("alpha==1.0.0")
        );
        assert!(document["tool"]["uv"].is_inline_table(), "{transitive}");
        assert!(!transitive.contains("[tool.uv"), "{transitive}");
        assert_settled(&transitive);
    }

    /// The header follows the tool block, not `[project]`: with `[tool.ruff]`
    /// as the only `[tool.*]` table and `[project]` after it, the new
    /// `[tool.uv.sources]` (and a transitive dep's `[tool.uv]`) land inside
    /// the tool block BEFORE `[project]`. With `[tool.uv]` followed by
    /// `[tool.ruff]`, the sources header goes right after `[tool.uv]`.
    #[test]
    fn project_sources_land_in_a_tool_block_that_precedes_project() {
        let direct = rewrite_project_metadata(
            "[tool.ruff]\nline-length = 100\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            direct,
            format!("[tool.ruff]\nline-length = 100\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n")
        );
        assert_settled(&direct);

        let transitive = rewrite_project_metadata(
            "[tool.ruff]\nline-length = 100\n\n[project]\nname = \"p\"\ndependencies = [\"requests\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            transitive,
            format!("[tool.ruff]\nline-length = 100\n\n[tool.uv]\noverride-dependencies = [\n    {HOSTED_OVERRIDE_MARK}\n    \"alpha==1.0.0\",\n]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n\n[project]\nname = \"p\"\ndependencies = [\"requests\"]\n")
        );
        assert_settled(&transitive);

        let after_uv = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool.uv]\ndev-dependencies = [\"pytest\"]\n\n[tool.ruff]\nline-length = 100\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            after_uv,
            format!("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool.uv]\ndev-dependencies = [\"pytest\"]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n\n[tool.ruff]\nline-length = 100\n")
        );
        assert_settled(&after_uv);
    }

    /// Upgrade path: an older CLI wrote the source as a dotted
    /// `tool.uv.sources.other = { … }` key in the ROOT body (above
    /// `[project]`). The new source must extend that dotted table — one more
    /// dotted line, no second `[tool.uv.sources]` header that would make the
    /// document invalid — and a transitive dep's override joins it the same
    /// way.
    #[test]
    fn project_sources_extend_a_dotted_root_body_table_from_an_older_cli() {
        let direct = rewrite_project_metadata(
            "tool.uv.sources.other = { git = \"https://example.test/other\" }\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"other\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            direct,
            format!("tool.uv.sources.other = {{ git = \"https://example.test/other\" }}\ntool.uv.sources.alpha = {{ url = \"{URL}\" }}\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"other\"]\n")
        );
        let document: DocumentMut = direct.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["other"]["git"].as_str(),
            Some("https://example.test/other")
        );
        assert_eq!(
            document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(URL)
        );
        assert_settled(&direct);

        let transitive = rewrite_project_metadata(
            "tool.uv.sources.other = { git = \"https://example.test/other\" }\n\n[project]\nname = \"p\"\ndependencies = [\"other\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            transitive,
            format!("tool.uv.sources.other = {{ git = \"https://example.test/other\" }}\ntool.uv.sources.alpha = {{ url = \"{URL}\" }}\ntool.uv.override-dependencies = [\n    {HOSTED_OVERRIDE_MARK}\n    \"alpha==1.0.0\",\n]\n\n[project]\nname = \"p\"\ndependencies = [\"other\"]\n")
        );
        assert_settled(&transitive);
    }

    /// A user-authored `# [tool.uv.sources]` (or `# [tool.uv]`) header inside
    /// the PEP 723 block coexists with our insertion: the source joins the
    /// existing table, the extracted block still parses, and
    /// `replace_script_metadata` re-comments every line so the block stays a
    /// valid PEP 723 comment block.
    #[test]
    fn script_block_with_user_sources_header_stays_parseable_and_commented() {
        fn block_lines(script: &str) -> Vec<&str> {
            let start = script.find("# /// script\n").unwrap() + "# /// script\n".len();
            let end = script.find("\n# ///\n").unwrap();
            script[start..end].lines().collect()
        }
        let cases = [
            (
                "# /// script\n# dependencies = [\"alpha==1.0.0\", \"beta\"]\n#\n# [tool.uv.sources]\n# beta = { git = \"https://example.test/beta\" }\n# ///\nprint('x')\n",
                format!("# /// script\n# dependencies = [\"alpha==1.0.0\", \"beta\"]\n#\n# [tool.uv.sources]\n# beta = {{ git = \"https://example.test/beta\" }}\n# alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n"),
            ),
            (
                "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n#\n# [tool.uv]\n# exclude-newer = \"2024-01-01T00:00:00Z\"\n# ///\nprint('x')\n",
                format!("# /// script\n# dependencies = [\"alpha==1.0.0\"]\n#\n# [tool.uv]\n# exclude-newer = \"2024-01-01T00:00:00Z\"\n# sources.alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n"),
            ),
            (
                "# /// script\n# dependencies = [\"requests\", \"beta\"]\n#\n# [tool.uv.sources]\n# beta = { git = \"https://example.test/beta\" }\n# ///\nprint('x')\n",
                format!("# /// script\n# dependencies = [\"requests\", \"beta\"]\n#\n# [tool.uv]\n# override-dependencies = [\n#     {HOSTED_OVERRIDE_MARK}\n#     \"alpha==1.0.0\",\n# ]\n#\n# [tool.uv.sources]\n# beta = {{ git = \"https://example.test/beta\" }}\n# alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n"),
            ),
        ];
        for (script, expected) in cases {
            let out = rewrite_script_metadata(script, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .unwrap();
            assert_eq!(out, expected);
            for line in block_lines(&out) {
                assert!(
                    line == "#" || line.starts_with("# "),
                    "every block line must stay a comment: {line:?} in\n{out}"
                );
            }
            let (_, metadata) = script_metadata(&out).unwrap();
            let document: DocumentMut = metadata.parse().unwrap();
            assert_eq!(
                document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
                Some(URL)
            );
            if script.contains("beta") {
                assert_eq!(
                    document["tool"]["uv"]["sources"]["beta"]["git"].as_str(),
                    Some("https://example.test/beta")
                );
            }
            if !script.contains("alpha==") {
                assert_eq!(
                    document["tool"]["uv"]["override-dependencies"][0].as_str(),
                    Some("alpha==1.0.0")
                );
            }
            assert!(
                rewrite_script_metadata(&out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                    .unwrap()
                    .is_none(),
                "{out}"
            );
        }
    }
}

#[cfg(test)]
mod ancestor_config_tests {
    use super::*;

    const SCRIPT: &str = "# /// script\n# dependencies = [\"six==1.16.0\"]\n# ///\n";
    const PYPROJECT: &str = "[project]\nname = \"root\"\nversion = \"0\"\n";

    /// #1501: uv takes a script's settings from the nearest directory above
    /// it that holds a uv.toml, or a pyproject.toml with `[tool.uv]`; uv.toml
    /// first in each directory, and a pyproject without `[tool.uv]` skipped.
    #[test]
    fn find_ancestor_uv_config_follows_uvs_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("a/b/scripts");
        std::fs::create_dir_all(&root).unwrap();
        // Beside the root: never an ancestor.
        std::fs::write(root.join(UV_TOML), "no-sources = true\n").unwrap();
        assert_eq!(find_ancestor_uv_config(&root), None);

        // A pyproject without [tool.uv] does not stop the walk.
        std::fs::write(temp.path().join("a/b/pyproject.toml"), PYPROJECT).unwrap();
        let with_uv = format!("{PYPROJECT}[tool.uv]\nno-sources = true\n");
        std::fs::write(temp.path().join("a/pyproject.toml"), &with_uv).unwrap();
        assert_eq!(
            find_ancestor_uv_config(&root),
            Some(UvConfig {
                rel: "../../pyproject.toml".into(),
                text: with_uv.clone(),
            })
        );
        // uv.toml wins over pyproject.toml in the same directory, and a
        // `..` in the root is resolved before walking.
        std::fs::write(temp.path().join("a/uv.toml"), "offline = true\n").unwrap();
        assert_eq!(
            find_ancestor_uv_config(&root.join("../scripts")),
            Some(UvConfig {
                rel: "../../uv.toml".into(),
                text: "offline = true\n".into(),
            })
        );
        // A pyproject that does not parse is skipped, as uv warns and walks
        // on to the parent.
        std::fs::write(temp.path().join("a/b/pyproject.toml"), "[project\n").unwrap();
        assert_eq!(
            find_ancestor_uv_config(&root.join("../scripts")).map(|config| config.rel),
            Some("../../uv.toml".into())
        );
        // uv stops at a settings file it cannot read (here a directory),
        // so the farther one is never reached.
        std::fs::create_dir(temp.path().join("a/b/uv.toml")).unwrap();
        assert_eq!(find_ancestor_uv_config(&root), None);
    }

    #[test]
    fn script_takes_an_ancestor_only_when_the_root_sets_nothing() {
        let ancestor = |rel: &str, text: &str| UvConfig {
            rel: rel.into(),
            text: text.into(),
        };
        let parent_uv = ancestor("../uv.toml", "no-sources = true\n");
        let error =
            refuse_uv_script_no_sources("six", SCRIPT, None, None, Some(&parent_uv)).unwrap_err();
        assert!(
            error.starts_with("../uv.toml sets no-sources = true"),
            "{error}"
        );
        let parent_pyproject = ancestor(
            "../pyproject.toml",
            "[tool.uv]\nno-sources-package = [\"Six\"]\n",
        );
        let error = refuse_uv_script_no_sources(
            "six",
            SCRIPT,
            Some(PYPROJECT),
            None,
            Some(&parent_pyproject),
        )
        .unwrap_err();
        assert!(
            error.starts_with("../pyproject.toml [tool.uv] sets no-sources-package naming six"),
            "{error}"
        );

        // A root pyproject that does not parse does not govern either.
        assert!(refuse_uv_script_no_sources(
            "six",
            SCRIPT,
            Some("[project\n"),
            None,
            Some(&parent_uv)
        )
        .is_err());

        // The root's own settings stop uv's lookup at the root.
        let root_uv = format!("{PYPROJECT}[tool.uv]\noffline = true\n");
        assert_eq!(
            refuse_uv_script_no_sources("six", SCRIPT, Some(&root_uv), None, Some(&parent_uv)),
            Ok(())
        );
        assert_eq!(
            refuse_uv_script_no_sources("six", SCRIPT, None, Some(""), Some(&parent_uv)),
            Ok(())
        );
        // The script's own setting still wins.
        let script_false =
            SCRIPT.replace("# ///\n", "#\n# [tool.uv]\n# no-sources = false\n# ///\n");
        assert_eq!(
            refuse_uv_script_no_sources("six", &script_false, None, None, Some(&parent_uv)),
            Ok(())
        );
    }

    /// #1545: a project whose root sets no uv settings takes a parent's
    /// `uv.toml` / `[tool.uv]`, and the `[tool.uv]` table a patch adds
    /// would make uv read the project's pyproject instead and drop them.
    #[test]
    fn project_refuses_to_shadow_an_ancestors_settings() {
        let ancestor = |rel: &str, text: &str| UvConfig {
            rel: rel.into(),
            text: text.into(),
        };
        let parent_uv = ancestor("../uv.toml", "resolution = \"lowest-direct\"\n");
        let error = refuse_uv_project_shadowing(PYPROJECT, None, Some(&parent_uv)).unwrap_err();
        assert!(error.starts_with("../uv.toml sets resolution"), "{error}");
        let parent_pyproject = ancestor(
            "../pyproject.toml",
            "[project]\nname = \"mono\"\n[tool.uv]\nexclude-newer = \"2024-01-01T00:00:00Z\"\n",
        );
        let error =
            refuse_uv_project_shadowing(PYPROJECT, None, Some(&parent_pyproject)).unwrap_err();
        assert!(
            error.starts_with("../pyproject.toml [tool.uv] sets exclude-newer"),
            "{error}"
        );

        // The root's own settings already stop uv's lookup at the root.
        let root_uv = format!("{PYPROJECT}[tool.uv]\nmanaged = true\n");
        assert_eq!(
            refuse_uv_project_shadowing(&root_uv, None, Some(&parent_uv)),
            Ok(())
        );
        assert_eq!(
            refuse_uv_project_shadowing(PYPROJECT, Some(""), Some(&parent_uv)),
            Ok(())
        );
        assert_eq!(refuse_uv_project_shadowing(PYPROJECT, None, None), Ok(()));
        // A parent that holds only another project's metadata (a workspace
        // root, its sources) sets nothing this project inherits.
        for text in [
            "[tool.uv]\n",
            "[tool.uv.workspace]\nmembers = [\"libs/*\"]\n[tool.uv.sources]\nlib = { workspace = true }\n",
            "[tool.uv]\nmanaged = true\npackage = false\ndev-dependencies = []\n",
            "[tool.uv]\noverride-dependencies = [\"six<2\"]\nconstraint-dependencies = []\n",
        ] {
            assert_eq!(
                refuse_uv_project_shadowing(
                    PYPROJECT,
                    None,
                    Some(&ancestor("../pyproject.toml", text))
                ),
                Ok(()),
                "{text}"
            );
        }
        // An index is a setting as well as project metadata.
        assert!(refuse_uv_project_shadowing(
            PYPROJECT,
            None,
            Some(&ancestor(
                "../../uv.toml",
                "[[index]]\nurl = \"https://mirror.test/simple\"\n"
            ))
        )
        .is_err());
        // A parent that does not parse sets nothing: uv reports it itself.
        assert_eq!(
            refuse_uv_project_shadowing(
                PYPROJECT,
                None,
                Some(&ancestor("../uv.toml", "resolution =\n"))
            ),
            Ok(())
        );
    }
}
