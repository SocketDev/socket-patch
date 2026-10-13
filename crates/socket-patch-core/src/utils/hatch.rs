use std::collections::{BTreeMap, HashMap};

use toml_edit::{DocumentMut, Item, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::preserve_line_endings;
use crate::vendor::common::{pep508_name, pyproject_dependency_specs, DeclTable};

/// The two documents the hatch planner reads and rewrites, in the order
/// [`plan`] and [`rewrite_all`] parse them.
pub const HATCH_FILES: [&str; 2] = ["pyproject.toml", "hatch.toml"];

/// The first character of `root`'s path that Hatch's `{root:uri}` expands
/// into a broken file URL (#547). Hatchling's `path_to_uri` escapes only
/// the space, so pip percent-decodes a `%XX` escape, cuts the path at a
/// `#` fragment or `?` query, and the PEP 508 parser stops at a `;`, a tab
/// or any other whitespace or control character. Hatch builds the URL from
/// the real path (symlinks resolved), so that is the path checked; only its
/// named components are, so a Windows `\\?\` prefix never counts. `None`
/// when the expansion is a usable URL.
pub fn root_uri_unsafe_char(root: &std::path::Path) -> Option<char> {
    let real = std::fs::canonicalize(root)
        .or_else(|_| std::path::absolute(root))
        .unwrap_or_else(|_| root.to_path_buf());
    real.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_string_lossy()),
            _ => None,
        })
        .find_map(|name| {
            let chars: Vec<char> = name.chars().collect();
            chars.iter().enumerate().find_map(|(i, &c)| {
                let escape = c == '%'
                    && chars
                        .get(i + 1..i + 3)
                        .is_some_and(|hex| hex.iter().all(char::is_ascii_hexdigit));
                (escape
                    || matches!(c, '#' | '?' | ';')
                    || c.is_control()
                    || (c.is_whitespace() && c != ' '))
                    .then_some(c)
            })
        })
}

pub fn is_hatch(files: &BTreeMap<String, String>) -> bool {
    files.contains_key("hatch.toml")
        || files.get("pyproject.toml").is_some_and(|text| {
            text.parse::<DocumentMut>().is_ok_and(|document| {
                document
                    .get("tool")
                    .and_then(|tool| tool.get("hatch"))
                    .is_some()
                    || document
                        .get("build-system")
                        .and_then(|build| build.get("build-backend"))
                        .and_then(Item::as_str)
                        == Some("hatchling.build")
            })
        })
}

/// Whether the project's Hatch configuration locks environments (Hatch
/// 1.17+: `lock-envs = true`, or an environment with `locked = true` or a
/// `lock-filename`). Read the way Hatch merges its configuration: a
/// hatch.toml TOP-LEVEL key replaces pyproject's `[tool.hatch]` key of the
/// same name, so a hatch.toml `envs` table hides every pyproject
/// environment and a hatch.toml `lock-envs` overrides pyproject's (the rule
/// [`environment_specs`] applies to dependencies).
fn locks_environments(files: &BTreeMap<String, String>) -> bool {
    let external = parsed(files, HATCH_FILES[1]);
    let project = parsed(files, HATCH_FILES[0]);
    let key = |name: &str| -> Option<Item> {
        if let Some(item) = external.as_ref().and_then(|doc| doc.get(name)) {
            return Some(item.clone());
        }
        project
            .as_ref()
            .and_then(|doc| doc.get("tool"))
            .and_then(|tool| tool.get("hatch"))
            .and_then(|hatch| hatch.get(name))
            .cloned()
    };
    key("lock-envs").and_then(|item| item.as_bool()) == Some(true)
        || key("envs")
            .as_ref()
            .and_then(Item::as_table_like)
            .is_some_and(|envs| {
                envs.iter().any(|(_, env)| {
                    env.get("locked").and_then(Item::as_bool) == Some(true)
                        || env.get("lock-filename").is_some()
                })
            })
}

/// Whether `path` is a PEP 751 lock Hatch derives from pyproject (#479):
/// a `pylock.toml` / `pylock.<name>.toml` in a Hatch project whose
/// environments are locked. Hatch regenerates it from pyproject whenever
/// the dependency hash changes, so it is not an independent install
/// source: the Hatch wiring (pyproject) is what must be rewritten, and a
/// rewrite of only the lock is thrown away by the next environment sync.
pub fn is_hatch_lock(files: &BTreeMap<String, String>, path: &str) -> bool {
    crate::utils::python_lock::is_pep751_lock_name(path)
        && is_hatch(files)
        && locks_environments(files)
}

/// One PEP 508 dependency string Hatch installs.
pub(crate) struct HatchSpec<'d> {
    /// `pyproject.toml` or `hatch.toml` (a [`HATCH_FILES`] entry).
    pub(crate) file: &'static str,
    pub(crate) table: DeclTable,
    pub(crate) spec: &'d str,
}

/// Every dependency string Hatch reads, in this order: pyproject's
/// [`pyproject_dependency_specs`] (`[project]` dependencies, extras, PEP 735
/// groups), then the environments' `dependencies` / `extra-dependencies` —
/// pyproject's `[tool.hatch.envs.*]` unless hatch.toml carries an `envs` key,
/// in which case hatch.toml's `[envs.*]`. Each caller parses the documents
/// its own way and passes `None` for one that is absent or not TOML. Shared
/// by the planner's predicates below and lockfile discovery
/// (`vex::discover::pypi_other`), which walk the same tables.
pub(crate) fn dependency_specs<'d>(
    pyproject: Option<&'d DocumentMut>,
    hatch_toml: Option<&'d DocumentMut>,
) -> Vec<HatchSpec<'d>> {
    let mut specs: Vec<HatchSpec<'d>> = pyproject
        .into_iter()
        .flat_map(pyproject_dependency_specs)
        .map(|(table, spec)| HatchSpec {
            file: HATCH_FILES[0],
            table,
            spec,
        })
        .collect();
    specs.extend(environment_specs(pyproject, hatch_toml));
    specs
}

/// The Hatch environment tables: `envs` of the hatch.toml document, else of
/// pyproject's `[tool.hatch]` (Hatch merges an external config by TOP-LEVEL
/// key, so a hatch.toml `envs` key — whatever its value — replaces
/// pyproject's whole table).
fn environment_specs<'d>(
    pyproject: Option<&'d DocumentMut>,
    hatch_toml: Option<&'d DocumentMut>,
) -> Vec<HatchSpec<'d>> {
    let (file, hatch) = match hatch_toml.filter(|d| d.contains_key("envs")) {
        Some(doc) => (HATCH_FILES[1], Some(doc.as_item())),
        None => (
            HATCH_FILES[0],
            pyproject
                .and_then(|d| d.get("tool"))
                .and_then(|t| t.get("hatch")),
        ),
    };
    hatch
        .and_then(|h| h.get("envs"))
        .and_then(Item::as_table_like)
        .into_iter()
        .flat_map(|envs| envs.iter())
        .flat_map(|(_, env)| {
            ["dependencies", "extra-dependencies"]
                .into_iter()
                .filter_map(move |key| env.get(key))
        })
        .filter_map(Item::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(|spec| HatchSpec {
            file,
            table: DeclTable::Env,
            spec,
        })
        .collect()
}

fn parsed(files: &BTreeMap<String, String>, file: &str) -> Option<DocumentMut> {
    files.get(file).and_then(|text| text.parse().ok())
}

pub fn has_environment_dependency(files: &BTreeMap<String, String>, name: &str) -> bool {
    let external = parsed(files, HATCH_FILES[1]);
    let project = parsed(files, HATCH_FILES[0]);
    environment_specs(project.as_ref(), external.as_ref())
        .iter()
        .any(|s| canonicalize_pypi_name(pep508_name(s.spec)) == canonicalize_pypi_name(name))
}

fn replacement(spec: &str, name: &str, version: &str, url: &str) -> Result<Option<String>, String> {
    let declared = pep508_name(spec);
    if canonicalize_pypi_name(declared) != name {
        return Ok(None);
    }
    if spec.contains(['\r', '\n']) {
        return Err(format!("{name}: multiline requirements are unsupported"));
    }
    let mut rest = spec.trim_start()[declared.len()..].trim_start();
    let extras = if rest.starts_with('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("{name}: invalid extras"))?;
        let extras = &rest[..=end];
        rest = rest[end + 1..].trim_start();
        extras
    } else {
        ""
    };
    let (constraint, marker) = rest
        .split_once(';')
        .map_or((rest, ""), |(left, right)| (left, right));
    let constraint: String = constraint
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if constraint.starts_with('@') {
        let existing = constraint.trim_start_matches('@');
        if existing == url {
            return Ok(Some(spec.to_owned()));
        }
        // socket-patch's own earlier hosted reference (a rotated grant or a
        // superseding patch uuid for this release) is re-pinned in place.
        if !crate::vendor::lock_inventory::pypi::replaceable_hosted_pin(
            existing, url, name, version,
        ) {
            return Err(format!(
                "{name}: an existing direct source must be reverted before patching"
            ));
        }
    } else if !crate::utils::pep440::is_exact_pin_of(&constraint, version) {
        return Err(format!(
            "{name}: Hatch patching requires an exact =={version} declaration"
        ));
    }
    let suffix = if marker.trim().is_empty() {
        String::new()
    } else {
        format!(" ; {}", marker.trim())
    };
    Ok(Some(format!("{declared}{extras} @ {url}{suffix}")))
}

/// One dependency of a [`rewrite_all`] batch: the arguments [`rewrite`]
/// takes for a single one.
pub struct HatchDep<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub url: &'a str,
}

/// One requirement string a batch rewrote, in `file` (a [`HATCH_FILES`]
/// entry): the declaration before and after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HatchEdit {
    pub file: String,
    pub original: String,
    pub new: String,
}

/// What [`rewrite_all`] made of a batch: the Hatch files it changed (path →
/// new text) and, per dependency in input order, the requirement strings it
/// rewrote or why it refused that dependency.
pub struct HatchBatch {
    pub files: BTreeMap<String, String>,
    pub steps: Vec<Result<Vec<HatchEdit>, String>>,
}

/// One dependency of a [`Round`] and what the walk found for it.
struct Target<'a> {
    /// Canonical PyPI name.
    name: String,
    version: &'a str,
    url: &'a str,
    error: Option<String>,
    matched: usize,
    project_matched: usize,
    edits: Vec<HatchEdit>,
}

/// The dependencies one walk of the Hatch documents rewrites, at most one
/// per canonical name. Requirements of different names never touch each
/// other's strings, so each target's outcome is the one a [`plan`] of it
/// alone would give. The walk runs twice: a check pass (`apply == false`)
/// that counts matches and records errors without changing anything, then
/// an apply pass that rewrites only the targets the check left error-free,
/// so a target refused midway leaves none of its declarations rewritten.
struct Round<'a> {
    targets: Vec<Target<'a>>,
    index: HashMap<String, usize>,
    apply: bool,
}

impl Round<'_> {
    /// A structural error stops the walk, as it stops a single [`plan`]:
    /// every target that has not already failed fails with it.
    fn fail_rest(&mut self, error: &str) {
        for target in &mut self.targets {
            target.error.get_or_insert_with(|| error.to_owned());
        }
    }
}

/// Rewrite `item`'s declarations of every live target. `Err` is a
/// structural error (it applies to every target); a requirement a target
/// cannot take is recorded on that target and the walk goes on.
fn rewrite_array(
    item: &mut Item,
    round: &mut Round,
    file: &str,
    project: bool,
) -> Result<Vec<usize>, String> {
    let array = item
        .as_array_mut()
        .ok_or("dependency declarations must be arrays")?;
    let mut matched = Vec::new();
    for entry in array.iter_mut() {
        if entry.is_inline_table() {
            continue;
        }
        let text = entry
            .as_str()
            .ok_or("dependency declarations must contain strings")?;
        let Some(&index) = round
            .index
            .get(canonicalize_pypi_name(pep508_name(text)).as_str())
        else {
            continue;
        };
        let target = &mut round.targets[index];
        if target.error.is_some() {
            continue;
        }
        match replacement(text, &target.name, target.version, target.url) {
            Err(error) => target.error = Some(error),
            Ok(None) => {}
            Ok(Some(rewritten)) => {
                matched.push(index);
                if !round.apply {
                    target.matched += 1;
                    target.project_matched += usize::from(project);
                } else if rewritten != text {
                    target.edits.push(HatchEdit {
                        file: file.to_owned(),
                        original: text.to_owned(),
                        new: rewritten.clone(),
                    });
                    let decoration = entry.decor().clone();
                    *entry = Value::from(rewritten);
                    *entry.decor_mut() = decoration;
                }
            }
        }
    }
    Ok(matched)
}

fn rewrite_project(document: &mut DocumentMut, round: &mut Round) -> Result<(), String> {
    let file = HATCH_FILES[0];
    if let Some(project) = document.get_mut("project") {
        if project
            .get("dynamic")
            .and_then(Item::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|v| matches!(v.as_str(), Some("dependencies" | "optional-dependencies")))
            })
        {
            return Err("dynamic project dependencies require agent mode".into());
        }
        if let Some(dependencies) = project
            .as_table_like_mut()
            .and_then(|table| table.get_mut("dependencies"))
        {
            rewrite_array(dependencies, round, file, true)?;
        }
        if let Some(groups) = project
            .as_table_like_mut()
            .and_then(|table| table.get_mut("optional-dependencies"))
        {
            for (_, dependencies) in groups
                .as_table_like_mut()
                .ok_or("optional dependencies must be a table")?
                .iter_mut()
            {
                rewrite_array(dependencies, round, file, true)?;
            }
        }
    }
    if let Some(groups) = document.get_mut("dependency-groups") {
        for (_, dependencies) in groups
            .as_table_like_mut()
            .ok_or("dependency groups must be a table")?
            .iter_mut()
        {
            for index in rewrite_array(dependencies, round, file, true)? {
                let target = &mut round.targets[index];
                if target.url.starts_with("{root:uri}") {
                    target.error.get_or_insert_with(|| "Hatch does not expand root placeholders in dependency groups; use environment dependencies or agent mode".into());
                }
            }
        }
    }
    Ok(())
}

fn rewrite_environments(hatch: &mut Item, round: &mut Round, file: &str) -> Result<(), String> {
    if hatch.get("sources").is_some() || hatch.get("env").is_some() {
        return Err("Hatch sources and environment plugins require agent mode".into());
    }
    if let Some(environments) = hatch
        .as_table_like_mut()
        .and_then(|table| table.get_mut("envs"))
    {
        for (_, environment) in environments
            .as_table_like_mut()
            .ok_or("Hatch environments must be a table")?
            .iter_mut()
        {
            if environment.get("sources").is_some()
                || environment.get("overrides").is_some()
                || environment
                    .get("type")
                    .and_then(Item::as_str)
                    .is_some_and(|kind| kind != "virtual")
            {
                return Err(
                    "Hatch sources, overrides and custom environments require agent mode".into(),
                );
            }
            for key in ["dependencies", "extra-dependencies"] {
                if let Some(dependencies) = environment
                    .as_table_like_mut()
                    .and_then(|table| table.get_mut(key))
                {
                    rewrite_array(dependencies, round, file, false)?;
                }
            }
        }
    }
    Ok(())
}

/// One pass over every declaration Hatch installs, in the order a single
/// [`plan`] walks them: pyproject's project tables, then the environments
/// of the merged configuration.
fn walk(
    documents: &mut BTreeMap<&'static str, DocumentMut>,
    round: &mut Round,
) -> Result<(), String> {
    if let Some(project) = documents.get_mut(HATCH_FILES[0]) {
        rewrite_project(project, round)?;
    }
    // Hatch merges external configuration by top-level key, not recursively.
    let external_keys = external_keys(documents);
    if let Some(document) = documents.get_mut(HATCH_FILES[0]) {
        if let Some(hatch) = document.get_mut("tool").and_then(|tool| {
            tool.as_table_like_mut()
                .and_then(|table| table.get_mut("hatch"))
        }) {
            let mut effective = hatch.clone();
            if let Some(table) = effective.as_table_like_mut() {
                for key in &external_keys {
                    table.remove(key);
                }
            }
            rewrite_environments(&mut effective, round, HATCH_FILES[0])?;
            if round.apply {
                if let Some(table) = effective.as_table_like() {
                    for (key, item) in table.iter() {
                        hatch[key] = item.clone();
                    }
                }
            }
        }
    }
    if let Some(document) = documents.get_mut(HATCH_FILES[1]) {
        let mut hatch = Item::Table(document.as_table().clone());
        rewrite_environments(&mut hatch, round, HATCH_FILES[1])?;
        if round.apply {
            *document.as_table_mut() = hatch
                .as_table()
                .ok_or("invalid Hatch configuration")?
                .clone();
        }
    }
    Ok(())
}

fn external_keys(documents: &BTreeMap<&'static str, DocumentMut>) -> Vec<String> {
    documents
        .get(HATCH_FILES[1])
        .map(|d| d.iter().map(|(k, _)| k.to_owned()).collect())
        .unwrap_or_default()
}

/// Run one [`Round`] over `documents`: check, then apply what passed.
fn run_round(documents: &mut BTreeMap<&'static str, DocumentMut>, round: &mut Round) {
    if round
        .targets
        .iter()
        .any(|t| t.url.starts_with("{root:uri}"))
    {
        if let Err(error) = require_pip_installer_documents(documents.values()) {
            for target in &mut round.targets {
                if target.url.starts_with("{root:uri}") {
                    target.error = Some(error.clone());
                }
            }
        }
    }
    round.apply = false;
    if let Err(error) = walk(documents, round) {
        round.fail_rest(&error);
        return;
    }
    for target in &mut round.targets {
        if target.error.is_none() && target.matched == 0 {
            target.error = Some(format!("{}=={} has no explicit Hatch declaration; transitive-only dependencies require agent mode", target.name, target.version));
        }
    }
    // A project-table match needs Hatch's direct-reference permission, which
    // no requirement rewrite touches: whether it can be granted is judged
    // once, on a copy.
    let external = external_keys(documents).iter().any(|key| key == "metadata");
    let permission_file = permission_file(external);
    let needs_permission = |target: &Target| target.error.is_none() && target.project_matched > 0;
    if round.targets.iter().any(needs_permission) {
        let granted = documents
            .get(permission_file)
            .ok_or_else(|| "missing Hatch configuration".to_owned())
            .and_then(|document| enable_permission(&mut document.clone(), external));
        if let Err(error) = granted {
            for target in &mut round.targets {
                if needs_permission(target) {
                    target.error = Some(error.clone());
                }
            }
        }
    }
    if round.targets.iter().all(|target| target.error.is_some()) {
        return;
    }
    round.apply = true;
    // The check pass found every structural error, and the apply pass walks
    // the same tables.
    if let Err(error) = walk(documents, round) {
        round.fail_rest(&error);
        return;
    }
    if round.targets.iter().any(needs_permission) {
        if let Some(document) = documents.get_mut(permission_file) {
            // Judged grantable above.
            let _ = enable_permission(document, external);
        }
    }
}

fn permission_file(external: bool) -> &'static str {
    if external {
        HATCH_FILES[1]
    } else {
        HATCH_FILES[0]
    }
}

fn parse_documents(
    files: &BTreeMap<String, String>,
) -> Result<BTreeMap<&'static str, DocumentMut>, String> {
    let mut documents = BTreeMap::new();
    for file in HATCH_FILES {
        if let Some(text) = files.get(file) {
            documents.insert(
                file,
                text.parse::<DocumentMut>()
                    .map_err(|error| format!("{file}: {error}"))?,
            );
        }
    }
    Ok(documents)
}

fn render(
    files: &BTreeMap<String, String>,
    documents: BTreeMap<&'static str, DocumentMut>,
) -> BTreeMap<String, String> {
    documents
        .into_iter()
        .filter_map(|(name, document)| {
            let original = &files[name];
            let new = preserve_line_endings(original, document.to_string());
            (new != *original).then_some((name.to_owned(), new))
        })
        .collect()
}

/// [`rewrite`] every dependency of `deps` over one parse and one render of
/// the Hatch documents. Each step is what [`rewrite`] would give for that
/// dependency applied after the ones before it: dependencies of one name
/// run in input order, one per round, and distinct names never interact.
pub fn rewrite_all(files: &BTreeMap<String, String>, deps: &[HatchDep]) -> HatchBatch {
    let mut documents = match parse_documents(files) {
        Ok(documents) => documents,
        Err(error) => {
            return HatchBatch {
                files: BTreeMap::new(),
                steps: deps.iter().map(|_| Err(error.clone())).collect(),
            }
        }
    };
    let names: Vec<String> = deps
        .iter()
        .map(|dep| canonicalize_pypi_name(dep.name))
        .collect();
    let mut rounds: Vec<Vec<usize>> = Vec::new();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for (position, name) in names.iter().enumerate() {
        let occurrence = seen.entry(name.as_str()).or_default();
        if rounds.len() <= *occurrence {
            rounds.push(Vec::new());
        }
        rounds[*occurrence].push(position);
        *occurrence += 1;
    }
    let mut steps: Vec<Result<Vec<HatchEdit>, String>> =
        deps.iter().map(|_| Ok(Vec::new())).collect();
    for positions in rounds {
        let mut round = Round {
            targets: positions
                .iter()
                .map(|&position| Target {
                    name: names[position].clone(),
                    version: deps[position].version,
                    url: deps[position].url,
                    error: None,
                    matched: 0,
                    project_matched: 0,
                    edits: Vec::new(),
                })
                .collect(),
            index: positions
                .iter()
                .enumerate()
                .map(|(index, &position)| (names[position].clone(), index))
                .collect(),
            apply: false,
        };
        run_round(&mut documents, &mut round);
        for (position, target) in positions.into_iter().zip(round.targets) {
            steps[position] = match target.error {
                Some(error) => Err(error),
                None => Ok(target.edits),
            };
        }
    }
    HatchBatch {
        files: render(files, documents),
        steps,
    }
}

pub struct HatchPermission {
    pub file: String,
    pub original: String,
    pub new: String,
}

pub struct HatchPlan {
    pub files: BTreeMap<String, String>,
    pub permission: Option<HatchPermission>,
}

pub fn rewrite(
    files: &BTreeMap<String, String>,
    name: &str,
    version: &str,
    url: &str,
) -> Result<BTreeMap<String, String>, String> {
    plan(files, name, version, url).map(|plan| plan.files)
}

fn enable_permission(document: &mut DocumentMut, external: bool) -> Result<(), String> {
    let keys = permission_keys(external);
    let mut table: &mut dyn toml_edit::TableLike = document.as_table_mut();
    for key in keys {
        if !table.contains_key(key) {
            table.insert(key, Item::Table(toml_edit::Table::new()));
        }
        table = table
            .get_mut(key)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| format!("{key} must be a TOML table"))?;
    }
    if table
        .get("allow-direct-references")
        .is_some_and(|item| !item.is_bool())
    {
        return Err("allow-direct-references must be a boolean".into());
    }
    table.insert("allow-direct-references", toml_edit::value(true));
    Ok(())
}

/// The table path holding Hatch's direct-reference permission: hatch.toml's
/// `[metadata]` when that file carries the key, else pyproject's
/// `[tool.hatch.metadata]`.
pub(crate) fn permission_keys(external: bool) -> &'static [&'static str] {
    if external {
        &["metadata"]
    } else {
        &["tool", "hatch", "metadata"]
    }
}

/// Remove `keys`' last table's `allow-direct-references = true` (the
/// permission a project direct reference needs), then every table on the
/// path that is left empty. Shared by the hosted unwind and the vendored
/// permission ledger, so both lanes agree on what the file looks like once
/// no project direct reference is left.
pub(crate) fn drop_direct_reference_permission(doc: &mut DocumentMut, keys: &[&str]) -> bool {
    fn walk(table: &mut dyn toml_edit::TableLike, keys: &[&str]) -> bool {
        let Some((first, rest)) = keys.split_first() else {
            return table.get("allow-direct-references").and_then(Item::as_bool) == Some(true)
                && table.remove("allow-direct-references").is_some();
        };
        let Some(child) = table.get_mut(first).and_then(Item::as_table_like_mut) else {
            return false;
        };
        let removed = walk(child, rest);
        if removed && child.is_empty() {
            table.remove(first);
        }
        removed
    }
    walk(doc.as_table_mut(), keys)
}

pub fn has_project_direct_references(files: &BTreeMap<String, String>) -> bool {
    let Some(document) = parsed(files, HATCH_FILES[0]) else {
        return false;
    };
    pyproject_dependency_specs(&document)
        .into_iter()
        .any(|(_, spec)| {
            spec.split(';')
                .next()
                .is_some_and(|requirement| requirement.contains('@'))
        })
}

/// Refuse a project whose Hatch environments use the uv installer
/// (`installer = "uv"` or a non-empty `uv-path`): uv does not enforce local
/// wheel fragment hashes, so a vendored wheel needs pip.
pub fn require_pip_installer(files: &BTreeMap<String, String>) -> Result<(), String> {
    let mut documents = Vec::new();
    for file in HATCH_FILES {
        if let Some(text) = files.get(file) {
            documents.push(
                text.parse::<DocumentMut>()
                    .map_err(|error| format!("{file}: {error}"))?,
            );
        }
    }
    require_pip_installer_documents(documents.iter())
}

fn require_pip_installer_documents<'a>(
    documents: impl Iterator<Item = &'a DocumentMut>,
) -> Result<(), String> {
    for document in documents {
        let hatch = document
            .get("tool")
            .and_then(|tool| tool.get("hatch"))
            .unwrap_or(document.as_item());
        if hatch
            .get("envs")
            .and_then(Item::as_table_like)
            .is_some_and(|envs| {
                envs.iter().any(|(_, env)| {
                    env.get("installer").and_then(Item::as_str) == Some("uv")
                        || env
                            .get("uv-path")
                            .and_then(Item::as_str)
                            .is_some_and(|path| !path.is_empty())
                })
            })
        {
            return Err("vendored Hatch wheels require the pip installer: uv does not enforce local wheel fragment hashes".into());
        }
    }
    Ok(())
}

pub fn plan(
    files: &BTreeMap<String, String>,
    name: &str,
    version: &str,
    url: &str,
) -> Result<HatchPlan, String> {
    let name = canonicalize_pypi_name(name);
    let mut documents = parse_documents(files)?;
    let mut round = Round {
        targets: vec![Target {
            name: name.clone(),
            version,
            url,
            error: None,
            matched: 0,
            project_matched: 0,
            edits: Vec::new(),
        }],
        index: HashMap::from([(name, 0)]),
        apply: false,
    };
    run_round(&mut documents, &mut round);
    let target = round.targets.pop().ok_or("missing Hatch target")?;
    if let Some(error) = target.error {
        return Err(error);
    }
    // `run_round` granted the permission in the rewritten documents; the
    // vendored ledger also records it alone over the original text.
    let permission = if target.project_matched > 0 {
        let external = external_keys(&documents)
            .iter()
            .any(|key| key == "metadata");
        let file = permission_file(external);
        let original = files[file].clone();
        let mut permission_only = original
            .parse::<DocumentMut>()
            .map_err(|error| error.to_string())?;
        enable_permission(&mut permission_only, external)?;
        Some(HatchPermission {
            file: file.into(),
            new: preserve_line_endings(&original, permission_only.to_string()),
            original,
        })
    } else {
        None
    };
    Ok(HatchPlan {
        files: render(files, documents),
        permission,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #479 (Bugbot): Hatch merges hatch.toml over `[tool.hatch]` by
    /// top-level key, so a shadowed `locked` / `lock-envs` does not make a
    /// pylock Hatch-derived, and one set in hatch.toml does.
    #[test]
    fn hatch_lock_detection_follows_the_config_merge() {
        let head = "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"app\"\n";
        let files = |pyproject: &str, hatch: Option<&str>| -> BTreeMap<String, String> {
            let mut files =
                BTreeMap::from([("pyproject.toml".to_string(), format!("{head}{pyproject}"))]);
            if let Some(hatch) = hatch {
                files.insert("hatch.toml".to_string(), hatch.to_string());
            }
            files
        };
        let locked = "\n[tool.hatch.envs.default]\nlocked = true\n";
        assert!(is_hatch_lock(&files(locked, None), "pylock.toml"));
        assert!(!is_hatch_lock(&files(locked, None), "uv.lock"));
        // A hatch.toml `envs` table replaces pyproject's environments.
        assert!(!is_hatch_lock(
            &files(locked, Some("[envs.default]\ninstaller = \"uv\"\n")),
            "pylock.toml"
        ));
        assert!(is_hatch_lock(
            &files("", Some("[envs.test]\nlocked = true\n")),
            "pylock.test.toml"
        ));
        // A hatch.toml `lock-envs` overrides pyproject's.
        let lock_envs = "\n[tool.hatch]\nlock-envs = true\n";
        assert!(is_hatch_lock(&files(lock_envs, None), "pylock.toml"));
        assert!(!is_hatch_lock(
            &files(lock_envs, Some("lock-envs = false\n")),
            "pylock.toml"
        ));
        assert!(!is_hatch_lock(&files("", None), "pylock.toml"));
    }

    fn files(text: &str) -> BTreeMap<String, String> {
        [("pyproject.toml".into(), text.into())]
            .into_iter()
            .collect()
    }

    #[test]
    fn exact_sources_extras_markers_and_newlines() {
        for newline in ["\n", "\r\n"] {
            let original = "[project]\ndependencies = [\"Urllib3[socks]==1.26.18 ; sys_platform == 'win32'\"] # keep\n[tool.hatch.envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n".replace('\n', newline);
            let inputs = files(&original);
            let result = rewrite(
                &inputs,
                "urllib3",
                "1.26.18",
                "https://patch.test/one.whl#sha256=abc",
            )
            .unwrap();
            let patched = &result["pyproject.toml"];
            assert!(patched.contains(
                "Urllib3[socks] @ https://patch.test/one.whl#sha256=abc ; sys_platform == 'win32'"
            ));
            assert!(patched.contains("# keep"));
            assert!(patched.contains("allow-direct-references = true"));
            assert!(rewrite(
                &result,
                "urllib3",
                "1.26.18",
                "https://patch.test/one.whl#sha256=abc"
            )
            .unwrap()
            .is_empty());
            if newline == "\r\n" {
                assert!(!patched.replace("\r\n", "").contains('\n'));
            }
            let (restored, drifted) = crate::vendor::restore_python_document(
                &patched.replace("\r\n", "\n").replace('\n', "\r\n"),
                &original,
                patched,
            )
            .unwrap();
            assert!(!drifted);
            assert_eq!(
                restored.replace("\r\n", "\n"),
                original.replace("\r\n", "\n")
            );
        }
    }

    /// #650: a superseding patch (a new patch uuid for the same package and
    /// version) re-pins socket-patch's OWN earlier hosted direct reference —
    /// in `pyproject.toml` (project and env tables) and in `hatch.toml` —
    /// instead of refusing it as an unknown user source.
    #[test]
    fn superseding_patch_repins_own_hosted_reference() {
        const A: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/11111111-1111-4111-8111-111111111111/aaaaaaaa-0000-4000-8000-000000000001/six-1.16.0-py2.py3-none-any.whl#sha256=aaaa";
        const B: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/22222222-2222-4222-8222-222222222222/aaaaaaaa-0000-4000-8000-000000000004/six-1.16.0-py2.py3-none-any.whl#sha256=bbbb";
        let inputs: BTreeMap<String, String> = [
            ("pyproject.toml".to_string(), "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0 ; python_version >= '3'\"]\n[tool.hatch.envs.default]\ndependencies = [\"six==1.16.0\"]\n".to_string()),
            ("hatch.toml".to_string(), "[envs.lint]\ndependencies = [\"Six[x]==1.16.0\"]\n".to_string()),
        ]
        .into_iter()
        .collect();
        // hatch.toml's `envs` replaces pyproject's whole env table, so the
        // project dependency and the hatch.toml env are the two declarations.
        let mut wired = inputs.clone();
        wired.extend(rewrite(&inputs, "six", "1.16.0", A).unwrap());
        let count = |files: &BTreeMap<String, String>, url: &str| -> usize {
            files.values().map(|t| t.matches(url).count()).sum()
        };
        assert_eq!(count(&wired, A), 2);
        let edits = rewrite(&wired, "six", "1.16.0", B)
            .unwrap_or_else(|e| panic!("superseding patch refused: {e}"));
        let mut repinned = wired.clone();
        repinned.extend(edits);
        for text in repinned.values() {
            assert!(!text.contains(A), "{text}");
        }
        assert_eq!(count(&repinned, B), 2);
        assert!(repinned["pyproject.toml"].contains(&format!("six @ {B} ; python_version >= '3'")));
        assert!(repinned["hatch.toml"].contains(&format!("Six[x] @ {B}")));
        assert!(rewrite(&repinned, "six", "1.16.0", B).unwrap().is_empty());
        // Not ours: another host, another version, or credentials stay a
        // user source that must be reverted first.
        for foreign in [
            A.replace("patch.socket.dev", "example.test"),
            A.replace("1.16.0", "1.15.0"),
            A.replace("https://", "https://user@"),
        ] {
            let user: BTreeMap<String, String> = wired
                .iter()
                .map(|(k, v)| (k.clone(), v.replace(A, &foreign)))
                .collect();
            assert!(
                rewrite(&user, "six", "1.16.0", B).is_err(),
                "{foreign} must stay a user source"
            );
        }
    }

    /// #475: Hatch (via pip/uv) selects a release under PEP 440, so
    /// `==1.26.18.0` and `==01.26.18` are exact pins of 1.26.18.
    #[test]
    fn pep440_equivalent_pins_are_exact_declarations() {
        for pin in [
            "urllib3==1.26.18.0",
            "urllib3 == 01.26.18",
            "Urllib3==v1.26.18",
        ] {
            let text = format!("[project]\ndependencies=[\"{pin}\"]\n");
            let result = rewrite(
                &files(&text),
                "urllib3",
                "1.26.18",
                "https://patch.test/a.whl",
            )
            .unwrap_or_else(|error| panic!("{pin}: {error}"));
            assert!(
                result["pyproject.toml"].contains("@ https://patch.test/a.whl"),
                "{pin}"
            );
        }
        for pin in [
            "urllib3==1.26.18.1",
            "urllib3===1.26.18.0",
            "urllib3==1.26.*",
        ] {
            let text = format!("[project]\ndependencies=[\"{pin}\"]\n");
            assert!(
                rewrite(
                    &files(&text),
                    "urllib3",
                    "1.26.18",
                    "https://patch.test/a.whl"
                )
                .is_err(),
                "{pin}"
            );
        }
    }

    #[test]
    fn external_tables_override_inline_and_metadata_permissions() {
        let mut inputs = files("[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\ndependencies=[\"urllib3>=0\"]\n");
        inputs.insert("hatch.toml".into(), "[metadata]\nallow-direct-references=false\n[envs.default]\ndependencies=[\"urllib3==1.26.18\"]\n".into());
        let result = rewrite(&inputs, "urllib3", "1.26.18", "https://patch.test/a.whl").unwrap();
        assert!(result["pyproject.toml"].contains("urllib3>=0"));
        assert!(!result["pyproject.toml"].contains("allow-direct-references"));
        let document = result["hatch.toml"].parse::<DocumentMut>().unwrap();
        assert_eq!(
            document["metadata"]["allow-direct-references"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn unsupported_shapes_never_return_partial_edits() {
        for text in [
            "[project]\ndependencies=[\"urllib3>=1\"]",
            "[project]\ndependencies=[\"urllib3==1.26.18\", \"urllib3==2.0.0\"]",
            "[project]\ndynamic=[\"dependencies\"]",
            "[project]\ndependencies=[\"urllib3 @ https://foreign.test/x.whl\"]",
            "[tool.hatch.envs.default]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default.overrides]\nplatform.windows.dependencies=[\"urllib3==1.26.18\"]",
            "[tool.hatch.envs.default]\ndependencies=[\"requests==2.31.0\"]",
            "[project]\ndependencies=[false]",
            "[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch]\nmetadata=false",
            "[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool]\nhatch=false",
            "[project]\ndependencies=[\"urllib3==1.26.18\\nidna==3.6\"]",
        ] {
            assert!(rewrite(&files(text), "urllib3", "1.26.18", "https://patch.test/a.whl").is_err(), "{text}");
        }
    }

    #[test]
    fn uv_installer_and_explicit_path_refuse_local_wheels() {
        for setting in ["installer='uv'", "uv-path='uv'"] {
            let inputs = files(&format!("[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\n{setting}\n"));
            assert!(rewrite(&inputs, "urllib3", "1.26.18", "https://patch.test/a.whl").is_ok());
            assert!(rewrite(
                &inputs,
                "urllib3",
                "1.26.18",
                "{root:uri}/.socket/vendor/a.whl"
            )
            .unwrap_err()
            .contains("pip installer"));
        }
    }

    #[test]
    fn require_pip_installer_refuses_uv_settings_in_either_file() {
        for setting in ["installer='uv'", "uv-path='uv'"] {
            let project = files(&format!("[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\n{setting}\n"));
            assert!(require_pip_installer(&project)
                .unwrap_err()
                .contains("pip installer"));
            let external = both(
                "[project]\ndependencies=[\"urllib3==1.26.18\"]",
                Some(&format!("[envs.default]\n{setting}\n")),
            );
            assert!(require_pip_installer(&external)
                .unwrap_err()
                .contains("pip installer"));
        }
        for allowed in ["installer='pip'", "uv-path=''"] {
            let project = files(&format!("[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\n{allowed}\n"));
            assert!(require_pip_installer(&project).is_ok(), "{allowed}");
        }
    }

    fn both(pyproject: &str, hatch: Option<&str>) -> BTreeMap<String, String> {
        let mut inputs = files(pyproject);
        if let Some(hatch) = hatch {
            inputs.insert("hatch.toml".into(), hatch.into());
        }
        inputs
    }

    #[test]
    fn environment_dependency_follows_the_effective_envs_table() {
        let inline = "[tool.hatch.envs.default]\ndependencies=[\"Urllib3 >=1\"]\n\
                      [tool.hatch.envs.test]\nextra-dependencies=[\"idna==3.6\"]\n";
        assert!(has_environment_dependency(&both(inline, None), "urllib3"));
        assert!(has_environment_dependency(&both(inline, None), "IDNA"));
        assert!(!has_environment_dependency(&both(inline, None), "six"));
        // A hatch.toml `envs` table replaces pyproject's (top-level merge).
        let external = "[envs.default]\ndependencies=[\"six==1.16.0\"]\n";
        assert!(!has_environment_dependency(
            &both(inline, Some(external)),
            "urllib3"
        ));
        assert!(has_environment_dependency(
            &both(inline, Some(external)),
            "six"
        ));
        // …even a non-table one; a hatch.toml without `envs`, or one that is
        // not TOML, leaves pyproject's in force.
        assert!(!has_environment_dependency(
            &both(inline, Some("envs = 1\n")),
            "urllib3"
        ));
        for hatch in ["[metadata]\nx = 1\n", "not = [toml"] {
            assert!(
                has_environment_dependency(&both(inline, Some(hatch)), "urllib3"),
                "{hatch}"
            );
        }
        // Project tables are not environments; non-string members are skipped.
        let project = "[project]\ndependencies=[\"urllib3==1\"]\n\
                       [tool.hatch.envs.default]\ndependencies=[1, {x=1}]\n";
        assert!(!has_environment_dependency(&both(project, None), "urllib3"));
        assert!(!has_environment_dependency(
            &both("not = [toml", None),
            "urllib3"
        ));
    }

    #[test]
    fn project_direct_references_cover_every_project_table() {
        for text in [
            "[project]\ndependencies=[\"a @ https://x.test/a.whl\"]",
            "[project.optional-dependencies]\nx=[\"b\", \"a @ file:///a.whl\"]",
            "[dependency-groups]\nqa=[{include-group=\"x\"}, \"a@https://x.test/a.whl\"]",
        ] {
            assert!(has_project_direct_references(&files(text)), "{text}");
        }
        for text in [
            "not = [toml",
            "[project]\ndependencies=[\"a ; python_version >= '3' and extra == 'x@y'\"]",
            "[project.optional-dependencies]\nx=\"a @ https://x.test/a.whl\"",
            "[dependency-groups]\nqa=\"a @ https://x.test/a.whl\"",
            "[tool.hatch.envs.default]\ndependencies=[\"a @ https://x.test/a.whl\"]",
        ] {
            assert!(!has_project_direct_references(&files(text)), "{text}");
        }
        assert!(!has_project_direct_references(&BTreeMap::new()));
    }

    #[test]
    fn groups_accept_hosted_and_refuse_unexpanded_vendor_context() {
        let inputs = files("[dependency-groups]\nqa=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\ndependency-groups=[\"qa\"]");
        assert!(rewrite(&inputs, "urllib3", "1.26.18", "https://patch.test/a.whl").is_ok());
        assert!(rewrite(
            &inputs,
            "urllib3",
            "1.26.18",
            "{root:uri}/.socket/vendor/a.whl"
        )
        .unwrap_err()
        .contains("does not expand"));
    }

    /// Rewrite `deps` one at a time, each over the previous one's output:
    /// the per-dependency contract [`rewrite_all`] must keep.
    fn sequential(
        files: &BTreeMap<String, String>,
        deps: &[HatchDep],
    ) -> (BTreeMap<String, String>, Vec<Result<(), String>>) {
        let mut current = files.clone();
        let steps = deps
            .iter()
            .map(|dep| {
                rewrite(&current, dep.name, dep.version, dep.url).map(|changes| {
                    current.extend(changes);
                })
            })
            .collect();
        (current, steps)
    }

    fn assert_batch_matches_sequential(files: &BTreeMap<String, String>, deps: &[HatchDep]) {
        let (expected, expected_steps) = sequential(files, deps);
        let batch = rewrite_all(files, deps);
        let mut actual = files.clone();
        actual.extend(batch.files.clone());
        assert_eq!(actual, expected);
        let steps: Vec<Result<(), String>> = batch
            .steps
            .iter()
            .map(|step| step.as_ref().map(|_| ()).map_err(Clone::clone))
            .collect();
        assert_eq!(steps, expected_steps);
        // Only the changed documents come back, as with `rewrite`.
        for (path, text) in &batch.files {
            assert_ne!(files.get(path), Some(text), "{path} is unchanged");
        }
        // Every recorded edit changes a requirement string of its file.
        for edit in batch.steps.iter().flatten().flatten() {
            assert_ne!(edit.original, edit.new);
            assert!(files.contains_key(&edit.file), "{edit:?}");
        }
    }

    const HOSTED_A: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/11111111-1111-4111-8111-111111111111/aaaaaaaa-0000-4000-8000-000000000001/six-1.16.0-py2.py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HOSTED_B: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/22222222-2222-4222-8222-222222222222/aaaaaaaa-0000-4000-8000-000000000004/six-1.16.0-py2.py3-none-any.whl#sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// #1471: one batch over many deps gives exactly what rewriting them
    /// one at a time gives — successes, per-dependency refusals (inexact
    /// pin, no declaration), extras and markers, a name repeated with a
    /// superseding url (runs after the first, in input order), and a name
    /// spelled differently in the declaration.
    #[test]
    fn batch_rewrite_matches_sequential_rewrites() {
        let pyproject = files(concat!(
            "[project]\nname = \"app\"\n",
            "dependencies = [\n  \"six==1.16.0\",\n  \"Requests[socks]==2.31.0 ; python_version >= '3.8'\",\n  \"idna>=3\",\n]\n",
            "[project.optional-dependencies]\nextra = [\"six==1.16.0\", \"Zope.Interface==6.0\"]\n",
            "[dependency-groups]\nqa = [\"pytest==8.0.0\"]\n",
            "[tool.hatch.envs.default]\ndependencies = [\"urllib3==1.26.18\", \"zope-interface==6.0\"]\n",
            "[tool.hatch.envs.lint]\nextra-dependencies = [\"idna==3.4\", \"six==1.16.0\"]\n",
        ));
        let deps = [
            HatchDep {
                name: "six",
                version: "1.16.0",
                url: HOSTED_A,
            },
            HatchDep {
                name: "requests",
                version: "2.31.0",
                url: "https://patch.test/requests.whl#sha256=00",
            },
            HatchDep {
                name: "idna",
                version: "3.4",
                url: "https://patch.test/idna.whl",
            },
            HatchDep {
                name: "urllib3",
                version: "1.26.18",
                url: "https://patch.test/urllib3.whl",
            },
            HatchDep {
                name: "absent",
                version: "1.0",
                url: "https://patch.test/absent.whl",
            },
            HatchDep {
                name: "zope.interface",
                version: "6.0",
                url: "https://patch.test/zope.whl",
            },
            HatchDep {
                name: "pytest",
                version: "8.0.0",
                url: "https://patch.test/pytest.whl",
            },
            HatchDep {
                name: "SIX",
                version: "1.16.0",
                url: HOSTED_B,
            },
        ];
        assert_batch_matches_sequential(&pyproject, &deps);
        let batch = rewrite_all(&pyproject, &deps);
        assert!(batch.steps[2].as_ref().unwrap_err().contains("exact"));
        assert!(batch.steps[4].as_ref().unwrap_err().contains("no explicit"));
        let wired = &batch.files["pyproject.toml"];
        // The repeated name re-pinned all three six declarations to the
        // superseding url; the refused idna kept every declaration.
        assert_eq!(wired.matches(HOSTED_B).count(), 3, "{wired}");
        assert!(!wired.contains(HOSTED_A), "{wired}");
        assert!(
            wired.contains("\"idna>=3\"") && wired.contains("\"idna==3.4\""),
            "{wired}"
        );
        assert_eq!(batch.steps[7].as_ref().unwrap().len(), 3);
        assert!(batch.steps.iter().filter(|s| s.is_ok()).count() == 6);
        // An empty batch changes nothing.
        let empty = rewrite_all(&pyproject, &[]);
        assert!(empty.files.is_empty() && empty.steps.is_empty());
    }

    /// #1471: hatch.toml's `envs` replaces pyproject's, a refusal found in
    /// a later table leaves that dep's earlier declarations untouched, and
    /// a structural refusal fails every dep not already refused (each with
    /// the message a lone `rewrite` gives it).
    #[test]
    fn batch_rewrite_follows_merges_and_refusal_order() {
        let mut merged = files(concat!(
            "[project]\nname = \"app\"\n",
            "dependencies = [\"six==1.16.0\", \"attrs==23.1.0\"]\n",
            "[tool.hatch.envs.default]\ndependencies = [\"click==8.1.7\"]\n",
        ));
        merged.insert(
            "hatch.toml".into(),
            "[envs.default]\ndependencies = [\"click==8.1.7\", \"attrs>=23\"]\n\r\n[envs.docs]\nextra-dependencies = [\"six==1.16.0\"]\r\n".into(),
        );
        let deps = [
            HatchDep {
                name: "six",
                version: "1.16.0",
                url: "https://patch.test/six.whl",
            },
            HatchDep {
                name: "attrs",
                version: "23.1.0",
                url: "https://patch.test/attrs.whl",
            },
            HatchDep {
                name: "click",
                version: "8.1.7",
                url: "https://patch.test/click.whl",
            },
        ];
        assert_batch_matches_sequential(&merged, &deps);
        let batch = rewrite_all(&merged, &deps);
        // attrs is refused by its hatch.toml range, so its exact project pin
        // stays as written.
        assert!(batch.steps[1].is_err());
        assert!(batch.files["pyproject.toml"].contains("\"attrs==23.1.0\""));
        // pyproject's shadowed environment is not rewritten.
        assert!(batch.files["pyproject.toml"].contains("dependencies = [\"click==8.1.7\"]"));

        let structural = files(concat!(
            "[project]\nname = \"app\"\n",
            "dependencies = [\"six==1.16.0\", \"idna>=3\"]\n",
            "[tool.hatch.envs.default]\ndependencies = [\"click==8.1.7\"]\n",
            "[tool.hatch.envs.custom]\ntype = \"container\"\n",
        ));
        let deps = [
            HatchDep {
                name: "six",
                version: "1.16.0",
                url: "https://patch.test/six.whl",
            },
            HatchDep {
                name: "idna",
                version: "3.4",
                url: "https://patch.test/idna.whl",
            },
            HatchDep {
                name: "click",
                version: "8.1.7",
                url: "https://patch.test/click.whl",
            },
        ];
        assert_batch_matches_sequential(&structural, &deps);
        let batch = rewrite_all(&structural, &deps);
        assert!(batch.files.is_empty());
        assert!(batch.steps[0]
            .as_ref()
            .unwrap_err()
            .contains("custom environments"));
        assert!(batch.steps[1].as_ref().unwrap_err().contains("exact"));

        let mut broken = structural.clone();
        broken.insert("hatch.toml".into(), "[envs\n".into());
        assert_batch_matches_sequential(&broken, &deps);
        assert!(rewrite_all(&broken, &deps)
            .steps
            .iter()
            .all(|step| step.as_ref().unwrap_err().starts_with("hatch.toml:")));
    }

    /// #1471: vendored `{root:uri}` deps keep their pip-installer and
    /// dependency-group refusals inside a batch, beside hosted deps that
    /// still wire.
    #[test]
    fn batch_rewrite_keeps_root_placeholder_refusals() {
        let inputs = files(concat!(
            "[dependency-groups]\nqa = [\"urllib3==1.26.18\"]\n",
            "[tool.hatch.envs.default]\ndependencies = [\"six==1.16.0\"]\n",
        ));
        let deps = [
            HatchDep {
                name: "urllib3",
                version: "1.26.18",
                url: "{root:uri}/.socket/vendor/u.whl",
            },
            HatchDep {
                name: "six",
                version: "1.16.0",
                url: "https://patch.test/six.whl",
            },
        ];
        assert_batch_matches_sequential(&inputs, &deps);
        assert!(rewrite_all(&inputs, &deps).steps[0]
            .as_ref()
            .unwrap_err()
            .contains("does not expand"));
        let mut uv = inputs.clone();
        uv.insert(
            "hatch.toml".into(),
            "[envs.default]\ninstaller = \"uv\"\ndependencies = [\"six==1.16.0\"]\n".into(),
        );
        let deps = [
            HatchDep {
                name: "six",
                version: "1.16.0",
                url: "{root:uri}/.socket/vendor/six.whl",
            },
            HatchDep {
                name: "urllib3",
                version: "1.26.18",
                url: "https://patch.test/u.whl",
            },
        ];
        assert_batch_matches_sequential(&uv, &deps);
        assert!(rewrite_all(&uv, &deps).steps[0]
            .as_ref()
            .unwrap_err()
            .contains("pip installer"));
    }
}
