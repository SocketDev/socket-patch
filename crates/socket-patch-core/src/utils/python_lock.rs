use std::path::Path;

use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::digest::{sha256_hex, sha256_prefixed};

#[cfg(test)]
#[path = "python_lock_oracle.rs"]
pub(crate) mod oracle;

#[derive(Clone, Copy, Debug)]
pub enum ArtifactSource<'a> {
    Url(&'a str),
    Path(&'a str),
}

impl ArtifactSource<'_> {
    fn key(self) -> &'static str {
        match self {
            Self::Url(_) => "url",
            Self::Path(_) => "path",
        }
    }

    fn location(self) -> String {
        match self {
            Self::Url(url) => url.to_string(),
            Self::Path(path) => path.to_string(),
        }
    }
}

// ── read model shared by the lock inventory and lockfile discovery ────

/// The `[[…]]` array holding a native Python lock's packages, and whether
/// the lock is PEP 751: `packages` (a `lock-version` pylock), `distribution`
/// (uv 0.2.x) or `package` (uv ≥ 0.2.35 and PEP 723 script locks). The
/// lock inventory, lockfile discovery and `lock_inventory::
/// wired_vendor_integrity` all pick the array with this one rule.
pub(crate) fn lock_package_collection(doc: &DocumentMut) -> (&'static str, bool) {
    if doc.contains_key("lock-version") {
        ("packages", true)
    } else if doc.contains_key("distribution") {
        ("distribution", false)
    } else {
        ("package", false)
    }
}

/// The tables of an array-of-tables, an array of inline tables, or a single
/// (inline) table item — every shape a lock writes an artifact list in.
pub(crate) fn table_likes(item: Option<&Item>) -> Vec<&dyn TableLike> {
    match item {
        Some(Item::ArrayOfTables(tables)) => tables.iter().map(|t| t as &dyn TableLike).collect(),
        Some(Item::Value(Value::Array(values))) => values
            .iter()
            .filter_map(Value::as_inline_table)
            .map(|t| t as &dyn TableLike)
            .collect(),
        Some(item) => item.as_table_like().into_iter().collect(),
        None => Vec::new(),
    }
}

/// One artifact entry (`wheels[]`, `wheel`, `sdist`, `archive`) of a lock
/// package.
pub(crate) struct LockArtifact<'t> {
    pub(crate) url: Option<&'t str>,
    pub(crate) path: Option<&'t str>,
    /// uv's local-wheel `filename`.
    pub(crate) filename: Option<&'t str>,
    /// The lowercase sha256: `hash = "sha256:<hex>"` (uv), else
    /// `hashes = { sha256 = "<hex>" }` (PEP 751); only a 64-hex digest.
    pub(crate) sha256: Option<String>,
}

impl<'t> LockArtifact<'t> {
    /// Where the artifact is fetched from: its `url`, else its `path`.
    pub(crate) fn location(&self) -> Option<&'t str> {
        self.url.or(self.path)
    }
}

/// Read one artifact table (see [`LockArtifact`]).
pub(crate) fn lock_artifact(table: &dyn TableLike) -> LockArtifact<'_> {
    let str_of = |key: &str| table.get(key).and_then(Item::as_str);
    let sha256 = str_of("hash").and_then(sha256_prefixed).or_else(|| {
        table
            .get("hashes")
            .and_then(Item::as_table_like)
            .and_then(|hashes| hashes.get("sha256"))
            .and_then(Item::as_str)
            .and_then(sha256_hex)
    });
    LockArtifact {
        url: str_of("url"),
        path: str_of("path"),
        filename: str_of("filename"),
        sha256,
    }
}

/// Every artifact of `package` under `keys`, in key order (singular tables
/// and arrays alike).
pub(crate) fn package_artifacts<'t>(
    package: &'t dyn TableLike,
    keys: &[&str],
) -> Vec<LockArtifact<'t>> {
    keys.iter()
        .flat_map(|key| table_likes(package.get(key)))
        .map(lock_artifact)
        .collect()
}

/// A uv package's `source`, in either spelling: the uv ≤ 0.2.17 string
/// grammar `"<kind>+<value>"` or the `{ registry | url | path | … }` table.
/// The one reader of both; each caller keeps its own precedence between the
/// kinds — the inventory's [`Self::is_remote`], [`uv_source_location`]
/// (url before path, registry ignored) and lockfile discovery's
/// resolved-elsewhere evidence (registry first).
#[derive(Clone, Copy)]
pub(crate) enum UvSource<'t> {
    Str(&'t str),
    Table(&'t dyn TableLike),
}

impl<'t> UvSource<'t> {
    /// `package`'s `source`; `None` when absent or neither a string nor a
    /// table.
    pub(crate) fn of(package: &'t dyn TableLike) -> Option<Self> {
        let source = package.get("source")?;
        match source.as_str() {
            Some(s) => Some(Self::Str(s)),
            None => source.as_table_like().map(Self::Table),
        }
    }

    /// The `<prefix>+` value of the string form, or the table's string `key`.
    fn field(self, prefix: &str, key: &str) -> Option<&'t str> {
        match self {
            Self::Str(s) => s.strip_prefix(prefix),
            Self::Table(table) => table.get(key).and_then(Item::as_str),
        }
    }

    /// `registry+<index>` / `registry = "<index>"`.
    pub(crate) fn registry(self) -> Option<&'t str> {
        self.field("registry+", "registry")
    }

    /// `direct+<url>` / `url = "<url>"`.
    pub(crate) fn url(self) -> Option<&'t str> {
        self.field("direct+", "url")
    }

    /// `path+<path>` / `path = "<path>"`.
    pub(crate) fn path(self) -> Option<&'t str> {
        self.field("path+", "path")
    }

    /// Whether the source is a registry or a direct url — a remote the fetch
    /// layer can resolve. The table form tests key PRESENCE (a non-string
    /// value still counts).
    pub(crate) fn is_remote(self) -> bool {
        match self {
            Self::Str(s) => s.starts_with("registry+") || s.starts_with("direct+"),
            Self::Table(table) => table.contains_key("registry") || table.contains_key("url"),
        }
    }
}

/// A uv package's install location: `source = { url | path }`, or the uv
/// 0.2.x string grammar `direct+<url>` / `path+<path>`. Registry, git,
/// editable, virtual and directory sources yield `None`.
pub(crate) fn uv_source_location(package: &dyn TableLike) -> Option<&str> {
    let source = UvSource::of(package)?;
    source.url().or_else(|| source.path())
}

pub fn is_python_lock_name(name: &str) -> bool {
    name == "uv.lock"
        || name.ends_with(".py.lock")
        || name == "pylock.toml"
        || (name.starts_with("pylock.") && name.ends_with(".toml"))
}

pub fn python_lock_paths(root: &Path) -> std::io::Result<Vec<String>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root)? {
        // One unreadable directory entry must not hide every other lock:
        // the callers treat an `Err` as "no Python locks here", which would
        // silently drop the whole project from inventory, repair, and the
        // hosted candidate list.
        let Ok(entry) = entry else {
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_python_lock_name(&name) {
            continue;
        }
        // `DirEntry::file_type` does NOT follow symlinks, so a lock that is a
        // symlink (a shared pylock, a checked-in link) was never discovered
        // even though every reader opens it fine. `fs::metadata` follows the
        // link; a link to a directory or FIFO is still excluded by `is_file`.
        if !std::fs::metadata(entry.path())
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        paths.push(name);
    }
    paths.sort();
    Ok(paths)
}

/// Re-apply the input's CRLF convention to a toml_edit rendering.
///
/// toml_edit (0.25.x) re-emits every newline as `\n`: a CRLF document comes
/// back entirely LF even when nothing was edited, so a rewritten lock or
/// pyproject would churn on every line under git and a byte-exact revert
/// could never converge. When the input used CRLF exclusively, convert the
/// rendering back; mixed-ending files are left as rendered rather than
/// half-converted.
pub fn preserve_line_endings(original: &str, rendered: String) -> String {
    let uses_crlf = original.contains("\r\n");
    let has_bare_lf = original.replace("\r\n", "").contains('\n');
    if !uses_crlf || has_bare_lf {
        return rendered;
    }
    let mut output = String::with_capacity(rendered.len() + rendered.matches('\n').count());
    let mut previous = '\0';
    for character in rendered.chars() {
        if character == '\n' && previous != '\r' {
            output.push('\r');
        }
        output.push(character);
        previous = character;
    }
    output
}

fn inline(entries: &[(&str, Value)]) -> Value {
    let mut table = InlineTable::new();
    for (key, value) in entries {
        table.insert(*key, value.clone());
    }
    table.fmt();
    Value::InlineTable(table)
}

fn matching_package(table: &Table, name: &str, version: &str) -> bool {
    table
        .get("name")
        .and_then(Item::as_str)
        .is_some_and(|value| canonicalize_pypi_name(value) == name)
        && table.get("version").and_then(Item::as_str) == Some(version)
}

fn source_identity(source: &Item) -> Option<(&str, &str)> {
    if let Some(value) = source.as_value() {
        return source_value_identity(value);
    }
    let table = source.as_table()?;
    ["registry", "url", "path"].into_iter().find_map(|key| {
        table
            .get(key)
            .and_then(Item::as_str)
            .map(|value| (key, value))
    })
}

fn source_value_identity(source: &Value) -> Option<(&str, &str)> {
    if let Some(value) = source.as_str() {
        return Some(("legacy", value));
    }
    let table = source.as_inline_table()?;
    ["registry", "url", "path"].into_iter().find_map(|key| {
        table
            .get(key)
            .and_then(Value::as_str)
            .map(|value| (key, value))
    })
}

fn rewrite_reference_value(
    value: &mut Value,
    name: &str,
    version: &str,
    original_source: &Item,
    source: &Item,
) {
    match value {
        Value::Array(array) => {
            for value in array.iter_mut() {
                rewrite_reference_value(value, name, version, original_source, source);
            }
        }
        Value::InlineTable(table) => {
            if table
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|value| canonicalize_pypi_name(value) == name)
                && table
                    .get("version")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value == version)
                && table.get("source").is_some_and(|value| {
                    source_value_identity(value) == source_identity(original_source)
                })
            {
                if let Some(value) = source.as_value() {
                    table.insert("source", value.clone());
                }
            }
            for (_, value) in table.iter_mut() {
                rewrite_reference_value(value, name, version, original_source, source);
            }
        }
        _ => {}
    }
}

fn rewrite_references(
    item: &mut Item,
    name: &str,
    version: &str,
    original_source: &Item,
    source: &Item,
) {
    match item {
        Item::Value(value) => {
            rewrite_reference_value(value, name, version, original_source, source);
        }
        Item::Table(table) => {
            if matching_package(table, name, version)
                && table
                    .get("source")
                    .is_some_and(|value| source_identity(value) == source_identity(original_source))
            {
                table.insert("source", source.clone());
            }
            for (_, item) in table.iter_mut() {
                rewrite_references(item, name, version, original_source, source);
            }
        }
        Item::ArrayOfTables(tables) => {
            for table in tables.iter_mut() {
                for (_, item) in table.iter_mut() {
                    rewrite_references(item, name, version, original_source, source);
                }
                if matching_package(table, name, version)
                    && table.get("source").is_some_and(|value| {
                        source_identity(value) == source_identity(original_source)
                    })
                {
                    table.insert("source", source.clone());
                }
            }
        }
        Item::None => {}
    }
}

fn rewrite_manifest(document: &mut DocumentMut, name: &str, artifact: ArtifactSource<'_>) {
    let Some(manifest) = document
        .get_mut("manifest")
        .and_then(Item::as_table_like_mut)
    else {
        return;
    };
    // `[tool.uv] constraint-dependencies` / `build-constraint-dependencies`
    // land here as `{ name, specifier }`; uv >= 0.5.6 re-serializes a sourced
    // package's element as `{ name, url|path }` (specifier dropped), so a
    // stale specifier keeps `uv lock --check` / `uv sync --locked` at exit 2
    // and a plain sync churns the lock. Repoint every matching element in
    // both arrays, independent of the `requirements` key below (a project
    // lock has none — only script locks do).
    for key in ["constraints", "build-constraints"] {
        if let Some(constraints) = manifest.get_mut(key).and_then(Item::as_array_mut) {
            for constraint in constraints
                .iter_mut()
                .filter_map(Value::as_inline_table_mut)
            {
                if constraint
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|value| canonicalize_pypi_name(value) == name)
                {
                    constraint.remove("specifier");
                    constraint.remove("url");
                    constraint.remove("path");
                    constraint.insert(artifact.key(), Value::from(artifact.location()));
                }
            }
        }
    }
    if !manifest.contains_key("requirements") {
        return;
    }
    let mut direct = false;
    if let Some(requirements) = manifest
        .get_mut("requirements")
        .and_then(Item::as_array_mut)
    {
        for requirement in requirements
            .iter_mut()
            .filter_map(Value::as_inline_table_mut)
        {
            if requirement
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|value| canonicalize_pypi_name(value) == name)
            {
                requirement.remove("specifier");
                requirement.remove("url");
                requirement.remove("path");
                requirement.insert(artifact.key(), Value::from(artifact.location()));
                direct = true;
            }
        }
    }
    if direct {
        return;
    }
    let overrides = manifest
        .entry("overrides")
        .or_insert(Item::Value(Value::Array(Array::new())));
    let Some(overrides) = overrides.as_array_mut() else {
        return;
    };
    for requirement in overrides.iter_mut().filter_map(Value::as_inline_table_mut) {
        if requirement
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|value| canonicalize_pypi_name(value) == name)
        {
            requirement.remove("specifier");
            requirement.remove("url");
            requirement.remove("path");
            requirement.insert(artifact.key(), Value::from(artifact.location()));
            return;
        }
    }
    overrides.push_formatted(inline(&[
        ("name", Value::from(name)),
        (artifact.key(), Value::from(artifact.location())),
    ]));
}

pub fn check_python_lock_source_scope(text: &str, name: &str, version: &str) -> Result<(), String> {
    let document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid Python lock: {error}"))?;
    source_scope(&document, name, version)
}

fn source_scope(document: &DocumentMut, name: &str, version: &str) -> Result<(), String> {
    let name = canonicalize_pypi_name(name);
    for collection in ["package", "distribution"] {
        if let Some(packages) = document.get(collection).and_then(Item::as_array_of_tables) {
            if packages.iter().any(|package| {
                package
                    .get("name")
                    .and_then(Item::as_str)
                    .is_some_and(|value| canonicalize_pypi_name(value) == name)
                    && package
                        .get("version")
                        .and_then(Item::as_str)
                        .is_some_and(|value| value != version)
            }) {
                return Err(format!("{name} resolves to multiple versions; a global uv source would replace other versions, so marker-specific source mappings are required"));
            }
        }
    }
    Ok(())
}

fn rewrite_requirement_sources(item: &mut Item, name: &str, artifact: ArtifactSource<'_>) {
    if let Some(requirements) = item.as_array_mut() {
        for requirement in requirements
            .iter_mut()
            .filter_map(Value::as_inline_table_mut)
        {
            if requirement
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|value| canonicalize_pypi_name(value) == name)
            {
                requirement.remove("specifier");
                requirement.remove("url");
                requirement.remove("path");
                requirement.insert(artifact.key(), Value::from(artifact.location()));
            }
        }
    } else if let Some(table) = item.as_table_like_mut() {
        for (_, item) in table.iter_mut() {
            rewrite_requirement_sources(item, name, artifact);
        }
    }
}

pub fn complete_python_lock_metadata(
    text: &str,
    project: Option<&str>,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    wheel_metadata: Option<&str>,
) -> Result<String, String> {
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid Python lock: {error}"))?;
    if document
        .get("package")
        .and_then(Item::as_array_of_tables)
        .is_none()
    {
        return Ok(text.to_string());
    }
    complete_python_lock_metadata_in(
        &mut document,
        project,
        name,
        version,
        artifact,
        wheel_metadata,
    )?;
    Ok(preserve_line_endings(text, document.to_string()))
}

/// [`complete_python_lock_metadata`] on an already-parsed lock, in place.
/// A lock with no `[[package]]` collection is left untouched. Every `Err` is
/// raised before the document is touched.
fn complete_python_lock_metadata_in(
    document: &mut DocumentMut,
    project: Option<&str>,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    wheel_metadata: Option<&str>,
) -> Result<(), String> {
    let Some(completion) = prepare_metadata_completion(document, project, name, wheel_metadata)?
    else {
        return Ok(());
    };
    finish_metadata_completion(document, completion, version, artifact);
    Ok(())
}

/// Everything [`complete_python_lock_metadata`] can refuse over, decided
/// before it mutates the lock. The refusals read only the metadata inputs,
/// the lock's `[[package]]` collection and its `manifest` / `overrides`
/// shapes — none of which [`apply_python_lock_plan`] changes (it replaces
/// entry sources and artifacts, and only ever inserts an ARRAY `overrides`
/// where none existed) — so preparing against the pre-rewrite lock gives the
/// verdict the post-rewrite lock would.
struct MetadataCompletion {
    name: String,
    /// The pyproject's `[tool.uv] override-dependencies` names the dep.
    project: Option<bool>,
    wheel: Option<Table>,
}

fn prepare_metadata_completion(
    document: &DocumentMut,
    project: Option<&str>,
    name: &str,
    wheel_metadata: Option<&str>,
) -> Result<Option<MetadataCompletion>, String> {
    if document
        .get("package")
        .and_then(Item::as_array_of_tables)
        .is_none()
    {
        return Ok(None);
    }
    let name = canonicalize_pypi_name(name);
    let project = match project {
        Some(project) => {
            let project: DocumentMut = project
                .parse()
                .map_err(|error| format!("invalid pyproject.toml: {error}"))?;
            let overridden = project
                .get("tool")
                .and_then(Item::as_table_like)
                .and_then(|tool| tool.get("uv"))
                .and_then(Item::as_table_like)
                .and_then(|uv| uv.get("override-dependencies"))
                .and_then(Item::as_array)
                .is_some_and(|overrides| {
                    overrides.iter().filter_map(Value::as_str).any(|specifier| {
                        canonicalize_pypi_name(
                            specifier
                                .split(|ch: char| {
                                    !ch.is_ascii_alphanumeric()
                                        && ch != '-'
                                        && ch != '_'
                                        && ch != '.'
                                })
                                .next()
                                .unwrap_or_default(),
                        ) == name
                    })
                });
            if overridden {
                // A missing manifest / overrides is created as a table / an
                // array, so only an existing one of the wrong shape refuses.
                if let Some(manifest) = document.get("manifest") {
                    let manifest = manifest
                        .as_table_like()
                        .ok_or("uv manifest must be a table")?;
                    if manifest
                        .get("overrides")
                        .is_some_and(|overrides| overrides.as_array().is_none())
                    {
                        return Err("uv manifest overrides must be an array".to_string());
                    }
                }
            }
            Some(overridden)
        }
        None => None,
    };
    let wheel = match wheel_metadata {
        Some(metadata) => {
            let metadata: DocumentMut = metadata
                .parse()
                .map_err(|error| format!("invalid wheel metadata: {error}"))?;
            let mut metadata = metadata
                .get("package")
                .and_then(Item::as_table_like)
                .and_then(|package| package.get("metadata"))
                .and_then(Item::as_table)
                .ok_or("wheel metadata has no package metadata table")?
                .clone();
            metadata.set_position(None);
            Some(metadata)
        }
        None => None,
    };
    Ok(Some(MetadataCompletion {
        name,
        project,
        wheel,
    }))
}

fn finish_metadata_completion(
    document: &mut DocumentMut,
    completion: MetadataCompletion,
    version: &str,
    artifact: ArtifactSource<'_>,
) {
    let MetadataCompletion {
        name,
        project,
        wheel,
    } = completion;
    if let Some(overridden) = project {
        let packages = document
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
            .expect("package collection checked");
        for package in packages.iter_mut() {
            let root = package
                .get("source")
                .and_then(Item::as_table_like)
                .is_some_and(|source| {
                    ["virtual", "editable"]
                        .into_iter()
                        .any(|key| source.get(key).and_then(Item::as_str) == Some("."))
                });
            if root {
                if let Some(metadata) = package
                    .get_mut("metadata")
                    .and_then(Item::as_table_like_mut)
                {
                    for key in ["requires-dist", "requires-dev"] {
                        if let Some(requirements) = metadata.get_mut(key) {
                            rewrite_requirement_sources(requirements, &name, artifact);
                        }
                    }
                }
            }
        }
        if overridden {
            let manifest = document
                .entry("manifest")
                .or_insert(Item::Table(Table::new()))
                .as_table_like_mut()
                .expect("manifest shape prepared");
            let overrides = manifest
                .entry("overrides")
                .or_insert(Item::Value(Value::Array(Array::new())));
            let exists = overrides.as_array().is_some_and(|overrides| {
                overrides
                    .iter()
                    .filter_map(Value::as_inline_table)
                    .any(|requirement| {
                        requirement
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|value| canonicalize_pypi_name(value) == name)
                    })
            });
            if exists {
                rewrite_requirement_sources(overrides, &name, artifact);
            } else {
                overrides
                    .as_array_mut()
                    .expect("overrides shape prepared")
                    .push_formatted(inline(&[
                        ("name", Value::from(name.as_str())),
                        (artifact.key(), Value::from(artifact.location())),
                    ]));
            }
        }
    }
    if let Some(metadata) = wheel {
        for package in document
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
            .expect("package collection checked")
            .iter_mut()
        {
            if matching_package(package, &name, version) {
                package.insert("metadata", Item::Table(metadata.clone()));
            }
        }
    }
}

/// Everything [`rewrite_python_lock`] decides before it mutates the
/// document: every refusal (`Err`) and every not-applicable (`None`) is
/// settled here, so a plan that exists always rewrites.
struct PythonLockPlan {
    pep751: bool,
    legacy: bool,
    collection: &'static str,
    index: usize,
    name: String,
    original_source: Option<Item>,
    legacy_strings: bool,
    legacy_artifact_tables: bool,
}

fn plan_python_lock_rewrite(
    document: &DocumentMut,
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
) -> Result<Option<PythonLockPlan>, String> {
    if document
        .get("manifest")
        .and_then(Item::as_table_like)
        .is_some_and(|manifest| manifest.contains_key("requirements"))
    {
        source_scope(document, name, version)?;
    }
    let pep751 = document.get("lock-version").is_some();
    let legacy = document.get("distribution").is_some();
    if pep751 {
        if document.get("lock-version").and_then(Item::as_str) != Some("1.0") {
            return Err("unsupported PEP 751 lock version".to_string());
        }
    } else if document.get("version").and_then(Item::as_integer) != Some(1) {
        return Err("unsupported uv lock version".to_string());
    }
    let collection = if pep751 {
        "packages"
    } else if legacy {
        "distribution"
    } else {
        "package"
    };
    let name = canonicalize_pypi_name(name);
    let Some(packages) = document.get(collection).and_then(Item::as_array_of_tables) else {
        return Ok(None);
    };
    let matches: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter_map(|(index, table)| matching_package(table, &name, version).then_some(index))
        .collect();
    if matches.len() > 1 {
        return Err(format!(
            "multiple lock entries for {name}@{version}; source selection is ambiguous"
        ));
    }
    let Some(&index) = matches.first() else {
        return Ok(None);
    };
    let package = packages.get(index).expect("matching package index exists");
    let original_source = package.get("source").cloned();
    // uv 0.2.18 through 0.2.34 kept the `[[distribution]]` table name but had
    // already moved to inline-table sources (`source = { registry = … }`,
    // `wheels = [{ … }]`, `dependencies = [{ name = … }]`). Those binaries
    // reject the string grammar (`source = "direct+…"`, `[[distribution.wheel]]`)
    // with "data did not match any variant of untagged enum SourceWire" and
    // then IGNORE the lock: an ordinary `uv sync` re-resolves from the
    // pyproject source (still the patch), but `--frozen` / `--locked` fail.
    // Follow the entry's OWN source shape, not the table name.
    let legacy_strings = legacy
        && original_source
            .as_ref()
            .and_then(source_identity)
            .is_some_and(|(kind, _)| kind == "legacy");
    // The artifact shape flipped separately (at 0.2.5→0.2.6): uv 0.2.6–0.2.17
    // still write string sources but already use inline `sdist = { … }` /
    // `wheels = [ … ]` instead of the `[distribution.sdist]` /
    // `[[distribution.wheel]]` tables of uv ≤0.2.5.
    // uv 0.2.17 parses an unexpected `[[distribution.wheel]]` but ignores it,
    // then treats the direct wheel URL as a source archive ("Unsupported
    // archive type: …whl"). Decide from the entry's own artifact keys, then
    // from any sibling entry in the document.
    let legacy_artifact_tables = legacy
        && (package.get("wheel").is_some_and(Item::is_array_of_tables)
            || package.get("sdist").is_some_and(Item::is_table)
            || (package.get("wheel").is_none()
                && package.get("wheels").is_none()
                && package.get("sdist").is_none()
                && (text.contains("[[distribution.wheel]]")
                    || text.contains("[distribution.sdist]"))));
    if !pep751
        && !original_source.as_ref().is_some_and(|source| {
            source_identity(source).is_some_and(|(kind, value)| {
                kind != "legacy"
                    || value.starts_with("registry+")
                    || value.starts_with("direct+")
                    || value.starts_with("path+")
            })
        })
    {
        return Ok(None);
    }
    if pep751 && (package.contains_key("vcs") || package.contains_key("directory")) {
        return Ok(None);
    }
    let location = artifact.location();
    let filename = location
        .split(['?', '#'])
        .next()
        .unwrap_or(&location)
        .rsplit('/')
        .next()
        .unwrap_or(&location);
    if !filename.ends_with(".whl")
        && !filename.ends_with(".tar.gz")
        && !filename.ends_with(".zip")
        && !filename.ends_with(".tar.bz2")
        && !filename.ends_with(".tar.xz")
    {
        return Err("patch artifact is not a Python distribution archive".to_string());
    }
    if !pep751 && legacy && matches!(artifact, ArtifactSource::Path(_)) {
        // Both `[[distribution]]` shapes record ABSOLUTE paths/file URLs
        // for local artifacts (uv 0.2.34 writes `source = { path = "/abs/…" }`
        // and `wheels = [{ url = "file:///abs/…" }]`), so a committed
        // relative wheel cannot be expressed portably before 0.2.35.
        return Err("uv `[[distribution]]` lockfiles (uv < 0.2.35, experimental `uv lock`) cannot carry a portable local wheel: `--locked` rejects relative paths and `uv lock`/`uv sync` rewrite them to absolute ones; upgrade to uv >=0.2.35 for native vendoring, or use a requirements.txt installation".to_string());
    }
    Ok(Some(PythonLockPlan {
        pep751,
        legacy,
        collection,
        index,
        name,
        original_source,
        legacy_strings,
        legacy_artifact_tables,
    }))
}

/// A Python lock parsed ONCE for repeated "would [`rewrite_python_lock`]
/// rewrite this dep?" checks — the hosted wheel-metadata gate asks it for
/// every pypi dep without re-parsing and re-serializing the lock each time.
pub struct PythonLockProbe<'t> {
    text: &'t str,
    /// `None` when the lock does not parse (every dep then probes false,
    /// as `rewrite_python_lock`'s `Err` would).
    document: Option<DocumentMut>,
}

impl<'t> PythonLockProbe<'t> {
    pub fn new(text: &'t str) -> Self {
        Self {
            text,
            document: text.parse().ok(),
        }
    }

    /// Exactly `matches!(rewrite_python_lock(text, …), Ok(Some(_)))`.
    pub fn rewrites(&self, name: &str, version: &str, artifact: ArtifactSource<'_>) -> bool {
        self.document.as_ref().is_some_and(|document| {
            matches!(
                plan_python_lock_rewrite(document, self.text, name, version, artifact),
                Ok(Some(_))
            )
        })
    }
}

/// A native Python lock parsed ONCE for a whole hosted rewrite: the hosted
/// rewriter plans, applies and completes every dep against this one
/// in-memory document instead of re-parsing the lock three times per dep
/// (rewrite, source scope, metadata completion).
///
/// Each step answers exactly what its text twin answers on the lock's
/// current rendering: [`Self::plan`] is [`rewrite_python_lock`]'s verdict,
/// [`Self::source_scope`] is [`check_python_lock_source_scope`], and
/// [`Self::rewrite`] renders what `complete_python_lock_metadata(
/// rewrite_python_lock(…))` would. A refused dep leaves the document as it
/// was, since every refusal is decided before the first mutation.
pub(crate) struct PythonLockSession {
    document: Result<DocumentMut, String>,
}

/// A dep [`PythonLockSession::plan`] settled as rewritable.
pub(crate) struct PlannedPythonLockRewrite(PythonLockPlan);

impl PythonLockSession {
    pub(crate) fn new(text: &str) -> Self {
        Self {
            document: text
                .parse()
                .map_err(|error| format!("invalid Python lock: {error}")),
        }
    }

    /// [`rewrite_python_lock`]'s refusal / not-applicable verdict, where
    /// `text` is the session's current rendering.
    pub(crate) fn plan(
        &self,
        text: &str,
        name: &str,
        version: &str,
        artifact: ArtifactSource<'_>,
    ) -> Result<Option<PlannedPythonLockRewrite>, String> {
        let document = self.document.as_ref().map_err(String::clone)?;
        Ok(
            plan_python_lock_rewrite(document, text, name, version, artifact)?
                .map(PlannedPythonLockRewrite),
        )
    }

    /// [`check_python_lock_source_scope`] on the current rendering.
    pub(crate) fn source_scope(&self, name: &str, version: &str) -> Result<(), String> {
        source_scope(
            self.document.as_ref().map_err(String::clone)?,
            name,
            version,
        )
    }

    /// Apply `plan` and complete the entry's metadata, returning the new
    /// rendering (with `text`'s line endings). On `Err` — a metadata
    /// completion refusal — the document is untouched.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rewrite(
        &mut self,
        text: &str,
        plan: PlannedPythonLockRewrite,
        name: &str,
        version: &str,
        artifact: ArtifactSource<'_>,
        sha256: &str,
        project: Option<&str>,
        wheel_metadata: Option<&str>,
    ) -> Result<String, String> {
        let document = self
            .document
            .as_mut()
            .expect("a planned rewrite has a parsed document");
        let completion = prepare_metadata_completion(document, project, name, wheel_metadata)?;
        apply_python_lock_plan(document, plan.0, version, artifact, sha256);
        if let Some(completion) = completion {
            finish_metadata_completion(document, completion, version, artifact);
        }
        Ok(preserve_line_endings(text, document.to_string()))
    }
}

pub fn rewrite_python_lock(
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    sha256: &str,
) -> Result<Option<String>, String> {
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid Python lock: {error}"))?;
    let Some(plan) = plan_python_lock_rewrite(&document, text, name, version, artifact)? else {
        return Ok(None);
    };
    apply_python_lock_plan(&mut document, plan, version, artifact, sha256);
    Ok(Some(preserve_line_endings(text, document.to_string())))
}

/// The mutation half of [`rewrite_python_lock`]: repoint the planned entry
/// (and every reference to it) at `artifact`. Infallible — every refusal was
/// settled by the plan.
fn apply_python_lock_plan(
    document: &mut DocumentMut,
    plan: PythonLockPlan,
    version: &str,
    artifact: ArtifactSource<'_>,
    sha256: &str,
) {
    let PythonLockPlan {
        pep751,
        legacy,
        collection,
        index,
        name,
        original_source,
        legacy_strings,
        legacy_artifact_tables,
    } = plan;
    let package = document
        .get_mut(collection)
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|packages| packages.get_mut(index))
        .expect("planned package index exists");
    let location = artifact.location();
    let filename = location
        .split(['?', '#'])
        .next()
        .unwrap_or(&location)
        .rsplit('/')
        .next()
        .unwrap_or(&location);
    let wheel = filename.ends_with(".whl");
    for key in ["sdist", "wheel", "wheels", "archive"] {
        package.remove(key);
    }
    if pep751 {
        package.remove("index");
        let hashes = inline(&[("sha256", Value::from(sha256))]);
        package.insert(
            "archive",
            Item::Value(inline(&[
                (artifact.key(), Value::from(location)),
                ("hashes", hashes),
            ])),
        );
    } else {
        let source = if legacy_strings {
            Item::Value(Value::from(format!("direct+{location}")))
        } else {
            Item::Value(inline(&[(artifact.key(), Value::from(location.clone()))]))
        };
        package.insert("source", source.clone());
        let artifact_key = if matches!(artifact, ArtifactSource::Path(_)) && wheel {
            "filename"
        } else {
            "url"
        };
        let artifact_location = if artifact_key == "filename" {
            filename
        } else {
            &location
        };
        let entry = inline(&[
            (artifact_key, Value::from(artifact_location)),
            ("hash", Value::from(format!("sha256:{sha256}"))),
        ]);
        if legacy_artifact_tables && wheel {
            let mut table = Table::new();
            table["url"] = toml_edit::value(artifact_location);
            table["hash"] = toml_edit::value(format!("sha256:{sha256}"));
            let mut array = ArrayOfTables::new();
            array.push(table);
            package.insert("wheel", Item::ArrayOfTables(array));
        } else if wheel {
            let mut array = Array::new();
            array.push_formatted(entry);
            package.insert("wheels", Item::Value(Value::Array(array)));
        } else if legacy_artifact_tables {
            let mut table = Table::new();
            table["url"] = toml_edit::value(artifact_location);
            table["hash"] = toml_edit::value(format!("sha256:{sha256}"));
            package.insert("sdist", Item::Table(table));
        } else {
            package.insert("sdist", Item::Value(entry));
        }
        if let Some(original_source) = original_source {
            rewrite_references(
                document.as_item_mut(),
                &name,
                version,
                &original_source,
                &source,
            );
        }
    }
    if !pep751 && !legacy {
        rewrite_manifest(document, &name, artifact);
    }
}

/// Whether `name` is a PEP 723 script lock (`<script>.py.lock`).
pub fn is_script_lock_name(name: &str) -> bool {
    name.ends_with(".py.lock")
}

/// The `<script>.py` a PEP 723 script lock `<script>.py.lock` belongs to;
/// `None` for any other name (`Some` exactly when [`is_script_lock_name`]).
pub fn script_of_lock(lock: &str) -> Option<&str> {
    lock.strip_suffix(".lock").filter(|s| s.ends_with(".py"))
}

/// The metadata file uv pairs a native lock with: `pyproject.toml` for
/// `uv.lock`, the `<script>.py` for a `<script>.py.lock`; `None` for any
/// other lock. Presence is the caller's to check.
pub fn paired_metadata_rel(lock: &str) -> Option<&str> {
    if lock == "uv.lock" {
        return Some("pyproject.toml");
    }
    script_of_lock(lock)
}

#[cfg(test)]
mod script_lock_name_tests {
    use super::*;

    #[test]
    fn script_locks_pair_with_their_script_and_uv_lock_with_pyproject() {
        assert!(is_script_lock_name("tool.py.lock"));
        assert!(!is_script_lock_name("uv.lock"));
        assert!(!is_script_lock_name("tool.lock"));
        assert_eq!(script_of_lock("tool.py.lock"), Some("tool.py"));
        assert_eq!(script_of_lock("uv.lock"), None);
        assert_eq!(script_of_lock("tool.lock"), None);
        assert_eq!(paired_metadata_rel("uv.lock"), Some("pyproject.toml"));
        assert_eq!(paired_metadata_rel("tool.py.lock"), Some("tool.py"));
        assert_eq!(paired_metadata_rel("pylock.toml"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::{is_python_lock_name, rewrite_python_lock, ArtifactSource};

    const URL: &str = "https://patch.socket.dev/pkg/urllib3-1.26.18-py2.py3-none-any.whl";
    const SHA256: &str = "ccc9a9e0b18a5efc7038c504cfc580e47d2e02e5390f2e29cad833cbccb956b6";
    const NATIVE: &str = r#"version = 1
revision = 3

[[package]]
name = "project"
version = "1"
source = { virtual = "." }
dependencies = [
    { name = "urllib3", version = "1.26.18", source = {registry='https://pypi.org/simple'} },
    { name = "urllib3", version = "2.0.0", source = { registry = "https://pypi.org/simple" } },
]

[[package]]
name = "urllib3"
version = "1.26.18"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://pypi.org/urllib3-1.26.18.tar.gz", hash = "sha256:old", size = 123 }
wheels = [{ url = "https://pypi.org/urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:old", size = 123, upload-time = "2023-10-17T17:47:01.725Z" }]

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://pypi.org/urllib3-2.0.0-py3-none-any.whl", hash = "sha256:other" }]
"#;

    #[test]
    fn hosted_native_uses_direct_source_and_keeps_other_versions() {
        let rewritten = rewrite_python_lock(
            NATIVE,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(URL),
            SHA256,
        )
        .unwrap()
        .unwrap();
        let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let packages = document["package"].as_array_of_tables().unwrap();
        assert_eq!(
            packages.get(1).unwrap()["source"]["url"].as_str(),
            Some(URL)
        );
        assert!(packages.get(1).unwrap().get("sdist").is_none());
        assert_eq!(
            packages.get(1).unwrap()["wheels"].as_array().unwrap().len(),
            1
        );
        assert!(!rewritten.contains("upload-time"));
        assert!(!rewritten.contains("size = 123"));
        assert_eq!(
            packages.get(0).unwrap()["dependencies"][0]["source"]["url"].as_str(),
            Some(URL)
        );
        assert_eq!(
            packages.get(0).unwrap()["dependencies"][1]["source"]["registry"].as_str(),
            Some("https://pypi.org/simple")
        );
        assert!(rewritten.contains("urllib3-2.0.0-py3-none-any.whl"));
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
    }

    #[test]
    fn hosted_source_archive_never_occupies_a_wheel_slot() {
        let url = "https://patch.socket.dev/pkg/urllib3-1.26.18.tar.gz";
        let rewritten = rewrite_python_lock(
            NATIVE,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(url),
            SHA256,
        )
        .unwrap()
        .unwrap();
        let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let package = document["package"]
            .as_array_of_tables()
            .unwrap()
            .get(1)
            .unwrap();
        assert!(package.get("wheels").is_none());
        assert_eq!(package["sdist"]["url"].as_str(), Some(url));
    }

    #[test]
    fn legacy_distribution_updates_source_qualified_edges() {
        let text = r#"version = 1
[[distribution]]
name = "project"
version = "1"
source = "directory+file:///project"
[[distribution.dependencies]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"
[[distribution]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"
[distribution.sdist]
url = "https://pypi.org/urllib3-1.26.18.tar.gz"
hash = "sha256:old"
[[distribution.wheel]]
url = "https://pypi.org/urllib3-1.26.18-py2.py3-none-any.whl"
hash = "sha256:old"
"#;
        let rewritten =
            rewrite_python_lock(text, "urllib3", "1.26.18", ArtifactSource::Url(URL), SHA256)
                .unwrap()
                .unwrap();
        assert_eq!(rewritten.matches(&format!("direct+{URL}")).count(), 2);
        assert!(!rewritten.contains("registry+"));
        assert!(!rewritten.contains("distribution.sdist"));
        assert!(rewritten.contains("[[distribution.wheel]]"));
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
    }

    /// uv 0.2.18–0.2.34 (`uv lock` as shipped): `[[distribution]]` tables
    /// with INLINE-TABLE sources. Emitting the string grammar here made those
    /// binaries reject the lock ("data did not match any variant of untagged
    /// enum SourceWire") and re-resolve, so `--frozen` / `--locked` failed.
    #[test]
    fn hybrid_distribution_lock_keeps_inline_table_sources() {
        let text = r#"version = 1
requires-python = ">=3.9"

[[distribution]]
name = "socket-uv-patch-fixture"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "urllib3" },
]

[[distribution]]
name = "urllib3"
version = "1.26.18"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/urllib3-1.26.18.tar.gz", hash = "sha256:old", size = 305687 }
wheels = [
    { url = "https://files.pythonhosted.org/urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:old", size = 143835 },
]
"#;
        let rewritten =
            rewrite_python_lock(text, "urllib3", "1.26.18", ArtifactSource::Url(URL), SHA256)
                .unwrap()
                .unwrap();
        assert!(rewritten.contains("[[distribution]]"), "{rewritten}");
        assert!(
            rewritten.contains(&format!("source = {{ url = \"{URL}\" }}")),
            "{rewritten}"
        );
        assert!(
            rewritten.contains(&format!(
                "{{ url = \"{URL}\", hash = \"sha256:{SHA256}\" }}"
            )),
            "{rewritten}"
        );
        assert!(!rewritten.contains("direct+"), "{rewritten}");
        assert!(!rewritten.contains("[[distribution.wheel]]"), "{rewritten}");
        assert!(!rewritten.contains("sdist"), "{rewritten}");
        assert!(!rewritten.contains("pythonhosted"), "{rewritten}");
        // The root entry's edge and source are untouched; re-run is a no-op.
        assert!(rewritten.contains("source = { editable = \".\" }"));
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
        // Vendoring stays refused for every `[[distribution]]` shape.
        let refused = rewrite_python_lock(
            text,
            "urllib3",
            "1.26.18",
            ArtifactSource::Path(".socket/vendor/pypi/x/urllib3-1.26.18-py2.py3-none-any.whl"),
            SHA256,
        )
        .unwrap_err();
        assert!(refused.contains("0.2.35"), "{refused}");
    }

    /// uv 0.2.6–0.2.17: string sources, but INLINE `sdist = {…}` /
    /// `wheels = [{…}]` artifacts. The bare `[[distribution.dependencies]]`
    /// edge here is the 0.2.16–0.2.17 shape (0.2.6–0.2.15 still write
    /// source-qualified edges, covered above). Emitting `[[distribution.wheel]]` here left the binary with a
    /// direct URL and no wheel, which it tried to build as an sdist
    /// ("Unsupported archive type: urllib3-….whl").
    #[test]
    fn string_source_inline_artifact_lock_keeps_inline_wheels() {
        let text = r#"version = 1
requires-python = ">=3.9"

[[distribution]]
name = "socket-uv-patch-fixture"
version = "0.1.0"
source = "editable+."

[[distribution.dependencies]]
name = "urllib3"

[[distribution]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"
sdist = { url = "https://files.pythonhosted.org/urllib3-1.26.18.tar.gz", hash = "sha256:old", size = 305687 }
wheels = [{ url = "https://files.pythonhosted.org/urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:old", size = 143835 }]
"#;
        let rewritten =
            rewrite_python_lock(text, "urllib3", "1.26.18", ArtifactSource::Url(URL), SHA256)
                .unwrap()
                .unwrap();
        assert!(
            rewritten.contains(&format!("source = \"direct+{URL}\"")),
            "{rewritten}"
        );
        assert!(
            rewritten.contains(&format!(
                "wheels = [{{ url = \"{URL}\", hash = \"sha256:{SHA256}\" }}]"
            )),
            "{rewritten}"
        );
        assert!(!rewritten.contains("[[distribution.wheel]]"), "{rewritten}");
        assert!(!rewritten.contains("sdist"), "{rewritten}");
        assert!(
            rewritten.contains("[[distribution.dependencies]]\nname = \"urllib3\""),
            "{rewritten}"
        );
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
    }

    /// uv ≤0.2.5 (string sources + `[distribution.sdist]` /
    /// `[[distribution.wheel]]` SUB-TABLES): a patch shipped as a source
    /// archive must land in a `[distribution.sdist]` sub-table — not an
    /// inline `sdist = { … }` those binaries never wrote — and the stale
    /// `[[distribution.wheel]]` must go so the URL is not fetched twice.
    #[test]
    fn legacy_sdist_redirect_emits_sub_table() {
        let text = r#"version = 1

[[distribution]]
name = "project"
version = "1"
source = "editable+."

[[distribution.dependencies]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"

[[distribution]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"

[distribution.sdist]
url = "https://files.pythonhosted.org/urllib3-1.26.18.tar.gz"
hash = "sha256:old"
size = 305687

[[distribution.wheel]]
url = "https://files.pythonhosted.org/urllib3-1.26.18-py2.py3-none-any.whl"
hash = "sha256:old"
size = 143835
"#;
        let url = "https://patch.socket.dev/pkg/urllib3-1.26.18.tar.gz";
        let rewritten =
            rewrite_python_lock(text, "urllib3", "1.26.18", ArtifactSource::Url(url), SHA256)
                .unwrap()
                .unwrap();
        let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let target = document["distribution"]
            .as_array_of_tables()
            .unwrap()
            .get(1)
            .unwrap();
        assert_eq!(target["source"].as_str(), Some(&*format!("direct+{url}")));
        assert!(target["sdist"].is_table(), "{rewritten}");
        assert_eq!(target["sdist"]["url"].as_str(), Some(url));
        assert_eq!(
            target["sdist"]["hash"].as_str(),
            Some(&*format!("sha256:{SHA256}"))
        );
        assert!(target.get("wheel").is_none(), "{rewritten}");
        assert!(target.get("wheels").is_none(), "{rewritten}");
        assert!(rewritten.contains("[distribution.sdist]"), "{rewritten}");
        assert!(!rewritten.contains("[[distribution.wheel]]"), "{rewritten}");
        assert!(!rewritten.contains("sdist = {"), "{rewritten}");
        assert!(!rewritten.contains("pythonhosted"), "{rewritten}");
        assert!(!rewritten.contains("size = "), "{rewritten}");
        // The source-qualified edge follows the new source.
        assert_eq!(rewritten.matches(&format!("direct+{url}")).count(), 2);
        assert!(!rewritten.contains("registry+"), "{rewritten}");
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(url),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
    }

    /// A `[[distribution]]` entry with no artifact keys of its own (uv wrote
    /// none for an editable/directory-less registry entry it never fetched)
    /// carries no evidence of the document's artifact grammar. The shape is
    /// then taken from any SIBLING entry: `[[distribution.wheel]]` siblings
    /// (≤0.2.5) → a `[[distribution.wheel]]` sub-table; inline `wheels = […]`
    /// siblings (0.2.6–0.2.17) → an inline `wheels` array.
    #[test]
    fn artifactless_target_follows_sibling_shape() {
        let target = r#"
[[distribution]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"
"#;
        let sub_table_sibling = format!(
            r#"version = 1

[[distribution]]
name = "certifi"
version = "2024.2.2"
source = "registry+https://pypi.org/simple"

[[distribution.wheel]]
url = "https://files.pythonhosted.org/certifi-2024.2.2-py3-none-any.whl"
hash = "sha256:certifi"
{target}"#
        );
        let rewritten = rewrite_python_lock(
            &sub_table_sibling,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(URL),
            SHA256,
        )
        .unwrap()
        .unwrap();
        let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let entry = document["distribution"]
            .as_array_of_tables()
            .unwrap()
            .get(1)
            .unwrap();
        assert_eq!(entry["source"].as_str(), Some(&*format!("direct+{URL}")));
        assert!(entry["wheel"].is_array_of_tables(), "{rewritten}");
        assert_eq!(entry["wheel"][0]["url"].as_str(), Some(URL));
        assert_eq!(
            entry["wheel"][0]["hash"].as_str(),
            Some(&*format!("sha256:{SHA256}"))
        );
        assert!(entry.get("wheels").is_none(), "{rewritten}");
        assert_eq!(
            rewritten.matches("[[distribution.wheel]]").count(),
            2,
            "{rewritten}"
        );
        assert!(!rewritten.contains("wheels = ["), "{rewritten}");
        // The sibling's own artifact is untouched.
        assert!(rewritten.contains("certifi-2024.2.2-py3-none-any.whl"));
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );

        let inline_sibling = format!(
            r#"version = 1

[[distribution]]
name = "certifi"
version = "2024.2.2"
source = "registry+https://pypi.org/simple"
wheels = [{{ url = "https://files.pythonhosted.org/certifi-2024.2.2-py3-none-any.whl", hash = "sha256:certifi" }}]
{target}"#
        );
        let rewritten = rewrite_python_lock(
            &inline_sibling,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(URL),
            SHA256,
        )
        .unwrap()
        .unwrap();
        let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let entry = document["distribution"]
            .as_array_of_tables()
            .unwrap()
            .get(1)
            .unwrap();
        assert_eq!(entry["source"].as_str(), Some(&*format!("direct+{URL}")));
        assert!(entry["wheels"].is_array(), "{rewritten}");
        assert_eq!(entry["wheels"][0]["url"].as_str(), Some(URL));
        assert!(entry.get("wheel").is_none(), "{rewritten}");
        assert!(
            rewritten.contains(&format!(
                "wheels = [{{ url = \"{URL}\", hash = \"sha256:{SHA256}\" }}]"
            )),
            "{rewritten}"
        );
        assert!(!rewritten.contains("[[distribution.wheel]]"), "{rewritten}");
        assert_eq!(
            rewrite_python_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
    }

    #[test]
    fn pep751_replaces_registry_artifacts_with_one_archive() {
        let text = r#"lock-version = "1.0"
created-by = "uv"
[[packages]]
name = "urllib3"
version = "1.26.18"
marker = "python_version >= '3.9'"
sdist = { url = "https://pypi.org/urllib3.tar.gz", hashes = {sha256 = "old"} }
wheels = [{url = "https://pypi.org/urllib3.whl", hashes = {sha256 = "old"}}]
"#;
        for source in [
            ArtifactSource::Url(URL),
            ArtifactSource::Path(".socket/vendor/pypi/id/urllib3-1.26.18-py2.py3-none-any.whl"),
        ] {
            let rewritten = rewrite_python_lock(text, "urllib3", "1.26.18", source, SHA256)
                .unwrap()
                .unwrap();
            let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
            let package = document["packages"]
                .as_array_of_tables()
                .unwrap()
                .get(0)
                .unwrap();
            assert!(package.get("sdist").is_none());
            assert!(package.get("wheels").is_none());
            assert_eq!(
                package["archive"][source.key()].as_str(),
                Some(source.location().as_str())
            );
            assert_eq!(
                package["archive"]["hashes"]["sha256"].as_str(),
                Some(SHA256)
            );
            assert_eq!(package["marker"].as_str(), Some("python_version >= '3.9'"));
        }
    }

    #[test]
    fn rejects_unknown_versions_and_ambiguous_sources() {
        assert!(rewrite_python_lock(
            "version = 2",
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(URL),
            SHA256
        )
        .is_err());
        assert!(rewrite_python_lock(
            "lock-version = '2.0'",
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(URL),
            SHA256
        )
        .is_err());
        assert!(rewrite_python_lock(
            &NATIVE.replace("2.0.0", "1.26.18"),
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(URL),
            SHA256
        )
        .is_err());
        assert!(rewrite_python_lock(
            NATIVE,
            "urllib3",
            "1.26.19",
            ArtifactSource::Url(URL),
            SHA256
        )
        .unwrap()
        .is_none());
        assert!(rewrite_python_lock("version = 1\n[[package]]\nname='urllib3'\nversion='1.26.18'\nsource={git='https://example.test/repo'}", "urllib3", "1.26.18", ArtifactSource::Url(URL), SHA256).unwrap().is_none());
    }

    #[test]
    fn script_manifest_tracks_direct_and_transitive_sources() {
        for (dependency, expected_key) in [("urllib3", "requirements"), ("requests", "overrides")] {
            let native = NATIVE.replace(
                "name = \"urllib3\"\nversion = \"2.0.0\"",
                "name = \"unrelated\"\nversion = \"2.0.0\"",
            );
            let text = native.replacen("[[package]]", &format!("[manifest]\nrequirements = [{{name=\"{dependency}\", specifier=\"==1.26.18\", extras=[\"socks\"], marker=\"python_version >= '3.9'\"}}]\n\n[[package]]"), 1);
            let rewritten = rewrite_python_lock(
                &text,
                "urllib3",
                "1.26.18",
                ArtifactSource::Url(URL),
                SHA256,
            )
            .unwrap()
            .unwrap();
            let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
            let requirement = document["manifest"][expected_key][0]
                .as_inline_table()
                .unwrap();
            assert_eq!(requirement["url"].as_str(), Some(URL));
            assert!(requirement.get("specifier").is_none());
            if dependency == "urllib3" {
                assert_eq!(
                    requirement["extras"]
                        .as_array()
                        .unwrap()
                        .get(0)
                        .unwrap()
                        .as_str(),
                    Some("socks")
                );
                assert_eq!(
                    requirement["marker"].as_str(),
                    Some("python_version >= '3.9'")
                );
            }
        }
    }

    #[test]
    fn refuses_global_sources_for_marker_separated_versions() {
        let text = NATIVE.replacen("[[package]]", "[manifest]\nrequirements=[{name='urllib3',specifier='==1.26.18',marker=\"python_version < '3.10'\"},{name='urllib3',specifier='==2.0.0',marker=\"python_version >= '3.10'\"}]\n[[package]]", 1);
        for artifact in [
            ArtifactSource::Url(URL),
            ArtifactSource::Path(".socket/vendor/pypi/id/urllib3-1.26.18-py2.py3-none-any.whl"),
        ] {
            assert!(
                rewrite_python_lock(&text, "urllib3", "1.26.18", artifact, SHA256)
                    .unwrap_err()
                    .contains("multiple versions")
            );
        }
    }

    #[test]
    fn discovers_supported_lock_filenames_only() {
        for name in [
            "uv.lock",
            "example.py.lock",
            "pylock.toml",
            "pylock.dev.toml",
        ] {
            assert!(is_python_lock_name(name));
        }
        for name in ["poetry.lock", "script.py", "uv.lock.bak", "pylock.toml.bak"] {
            assert!(!is_python_lock_name(name));
        }
    }
}

#[cfg(test)]
mod discovery_and_line_ending_tests {
    use super::*;

    #[test]
    fn crlf_locks_keep_their_line_endings_through_a_rewrite() {
        let lock = "lock-version = \"1.0\"\r\ncreated-by = \"uv\"\r\n\r\n[[packages]]\r\nname = \"requests\"\r\nversion = \"2.28.1\"\r\nwheels = [{ name = \"requests-2.28.1-py3-none-any.whl\", url = \"https://pypi.org/requests-2.28.1-py3-none-any.whl\", hashes = { sha256 = \"old\" } }]\r\n";
        let url = "https://patch.socket.dev/requests-2.28.1-py3-none-any.whl";
        let out = rewrite_python_lock(
            lock,
            "requests",
            "2.28.1",
            ArtifactSource::Url(url),
            &"a".repeat(64),
        )
        .unwrap()
        .expect("rewritten");
        assert!(out.contains(url) && !out.contains("pypi.org"), "{out}");
        assert!(!out.contains("\r\r"), "{out:?}");
        assert_eq!(
            out.matches("\r\n").count(),
            out.matches('\n').count(),
            "every newline must stay CRLF: {out:?}"
        );
        // Re-running over the CRLF output is byte-stable.
        assert_eq!(
            rewrite_python_lock(
                &out,
                "requests",
                "2.28.1",
                ArtifactSource::Url(url),
                &"a".repeat(64)
            )
            .unwrap()
            .as_deref(),
            Some(out.as_str())
        );
    }

    #[test]
    fn line_endings_are_restored_only_for_pure_crlf_inputs() {
        assert_eq!(
            preserve_line_endings("a\r\nb\r\n", "a\nb\n".into()),
            "a\r\nb\r\n"
        );
        assert_eq!(
            preserve_line_endings("a\r\nb\nc", "a\nb\nc".into()),
            "a\nb\nc"
        );
        assert_eq!(preserve_line_endings("a\nb\n", "a\nb\n".into()), "a\nb\n");
        assert_eq!(
            preserve_line_endings("a\r\n", "a\r\nb\n".into()),
            "a\r\nb\r\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn python_lock_paths_follow_symlinks_and_skip_non_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("shared.toml"), "lock-version = \"1.0\"\n").unwrap();
        std::os::unix::fs::symlink(root.join("shared.toml"), root.join("pylock.toml")).unwrap();
        std::fs::write(root.join("tool.py.lock"), "version = 1\n").unwrap();
        // A directory that merely carries a lock name, and a dangling link.
        std::fs::create_dir(root.join("uv.lock")).unwrap();
        std::os::unix::fs::symlink(root.join("missing"), root.join("pylock.dev.toml")).unwrap();
        assert_eq!(
            python_lock_paths(root).unwrap(),
            vec!["pylock.toml".to_string(), "tool.py.lock".to_string()]
        );
    }
}

#[cfg(test)]
mod manifest_constraints_tests {
    use super::{rewrite_python_lock, ArtifactSource};

    const URL: &str = "https://patch.socket.dev/pkg/urllib3-1.26.18-py2.py3-none-any.whl";
    const SHA256: &str = "ccc9a9e0b18a5efc7038c504cfc580e47d2e02e5390f2e29cad833cbccb956b6";

    /// `[tool.uv] constraint-dependencies` / `build-constraint-dependencies`
    /// land in `[manifest] constraints` / `build-constraints` as
    /// `{ name, specifier }`; uv >= 0.5.6 re-serializes a sourced package's
    /// element as `{ name, url|path }`, so a stale specifier keeps
    /// `uv lock --check` / `uv sync --locked` at exit 2 after a hosted scan.
    /// Both arrays are repointed even when the project lock has no
    /// `requirements` key (only script locks carry one), and no `overrides`
    /// array is invented for a direct dependency.
    #[test]
    fn hosted_rewrite_repoints_manifest_constraints_and_build_constraints() {
        let text = r#"version = 1
revision = 3
requires-python = ">=3.9"

[manifest]
constraints = [{ name = "urllib3", specifier = "==1.26.18" }]
build-constraints = [
    { name = "other", specifier = "==1.0" },
    { name = "urllib3", specifier = ">=1.26" },
]

[[package]]
name = "fixture"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "urllib3" },
]

[package.metadata]
requires-dist = [{ name = "urllib3", specifier = "==1.26.18" }]

[[package]]
name = "urllib3"
version = "1.26.18"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://pypi.org/urllib3-1.26.18.tar.gz", hash = "sha256:old", size = 123 }
wheels = [
    { url = "https://pypi.org/urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:old", size = 123 },
]
"#;
        let rewritten =
            rewrite_python_lock(text, "urllib3", "1.26.18", ArtifactSource::Url(URL), SHA256)
                .unwrap()
                .unwrap();
        let document: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let manifest = &document["manifest"];
        let constraint = manifest["constraints"][0].as_inline_table().unwrap();
        assert_eq!(constraint["url"].as_str(), Some(URL));
        assert!(constraint.get("specifier").is_none(), "{rewritten}");
        let build = manifest["build-constraints"].as_array().unwrap();
        let foreign = build.get(0).unwrap().as_inline_table().unwrap();
        assert_eq!(foreign["specifier"].as_str(), Some("==1.0"));
        assert!(
            foreign.get("url").is_none(),
            "a foreign constraint is untouched"
        );
        let ours = build.get(1).unwrap().as_inline_table().unwrap();
        assert_eq!(ours["url"].as_str(), Some(URL));
        assert!(ours.get("specifier").is_none(), "{rewritten}");
        assert!(
            manifest.as_table_like().unwrap().get("overrides").is_none(),
            "a direct dependency must not gain an overrides array: {rewritten}"
        );
    }
}

/// `PythonLockProbe::rewrites` must agree with `rewrite_python_lock`
/// returning `Ok(Some(_))` for every lock shape and every refusal /
/// not-applicable path — the hosted wheel-metadata gate relies on it.
#[cfg(test)]
mod probe_equivalence_tests {
    use super::{rewrite_python_lock, ArtifactSource, PythonLockProbe};

    const SHA256: &str = "ccc9a9e0b18a5efc7038c504cfc580e47d2e02e5390f2e29cad833cbccb956b6";
    const NATIVE: &str = r#"version = 1
revision = 3

[[package]]
name = "project"
version = "1"
source = { virtual = "." }
dependencies = [
    { name = "urllib3", version = "1.26.18", source = { registry = "https://pypi.org/simple" } },
]

[[package]]
name = "urllib3"
version = "1.26.18"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://pypi.org/urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:old" }]

[[package]]
name = "Zope.Interface"
version = "6.0"
source = { git = "https://example.test/zope" }

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://pypi.org/six-1.16.0.tar.gz", hash = "sha256:old" }
"#;
    const LEGACY_STRINGS: &str = r#"version = 1

[[distribution]]
name = "urllib3"
version = "1.26.18"
source = "registry+https://pypi.org/simple"

[[distribution.wheel]]
url = "https://pypi.org/urllib3-1.26.18-py2.py3-none-any.whl"
hash = "sha256:old"

[[distribution]]
name = "six"
version = "1.16.0"
source = "git+https://example.test/six"
"#;
    const PEP751: &str = r#"lock-version = "1.0"

[[packages]]
name = "urllib3"
version = "1.26.18"
index = "https://pypi.org/simple"
wheels = [{ url = "https://pypi.org/urllib3-1.26.18-py2.py3-none-any.whl", hashes = { sha256 = "old" } }]

[[packages]]
name = "six"
version = "1.16.0"
vcs = { type = "git", url = "https://example.test/six", commit-id = "abc" }
"#;

    #[test]
    fn probe_matches_rewrite_outcome_for_every_shape() {
        let script = NATIVE.replacen(
            "[[package]]",
            "[manifest]\nrequirements = [{ name = \"urllib3\", specifier = \"==1.26.18\" }]\n\n[[package]]",
            1,
        );
        let multi_version = format!(
            "{script}\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n"
        );
        let duplicate = NATIVE.replace(
            "name = \"six\"\nversion = \"1.16.0\"",
            "name = \"urllib3\"\nversion = \"1.26.18\"",
        );
        let locks = [
            NATIVE.to_string(),
            NATIVE.replace("\n", "\r\n"),
            script,
            multi_version,
            duplicate,
            LEGACY_STRINGS.to_string(),
            PEP751.to_string(),
            "version = 2\n".to_string(),
            "lock-version = '2.0'\n".to_string(),
            "version = 1\n".to_string(),
            "this is [not toml".to_string(),
        ];
        let wheel = "https://patch.socket.dev/pkg/urllib3-1.26.18-py2.py3-none-any.whl";
        let sdist = "https://patch.socket.dev/pkg/six-1.16.0.tar.gz?token=x#frag";
        let artifacts = [
            ArtifactSource::Url(wheel),
            ArtifactSource::Url(sdist),
            ArtifactSource::Url("https://patch.socket.dev/pkg/urllib3.exe"),
            ArtifactSource::Path(".socket/vendor/pypi/id/urllib3-1.26.18-py2.py3-none-any.whl"),
        ];
        let targets = [
            ("urllib3", "1.26.18"),
            ("URLLIB3", "1.26.18"),
            ("urllib3", "2.0.0"),
            ("urllib3", "9.9.9"),
            ("six", "1.16.0"),
            ("zope-interface", "6.0"),
            ("absent", "1.0"),
        ];
        let mut outcomes = std::collections::BTreeSet::new();
        for lock in &locks {
            let probe = PythonLockProbe::new(lock);
            for (name, version) in targets {
                for artifact in artifacts {
                    let rewrite = rewrite_python_lock(lock, name, version, artifact, SHA256);
                    outcomes.insert(match &rewrite {
                        Ok(Some(_)) => "some",
                        Ok(None) => "none",
                        Err(_) => "err",
                    });
                    assert_eq!(
                        probe.rewrites(name, version, artifact),
                        matches!(rewrite, Ok(Some(_))),
                        "{name}@{version} via {artifact:?} over:\n{lock}\nrewrite: {rewrite:?}"
                    );
                }
            }
        }
        assert_eq!(
            outcomes.len(),
            3,
            "every outcome is exercised: {outcomes:?}"
        );
    }
}
