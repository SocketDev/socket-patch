//! PyPI upstream restores for the formats whose hosted rewrite is a single
//! reference swap: `Pipfile.lock` entries, `requirements.txt` lines and
//! Hatch's PEP 508 direct references (`pyproject.toml` / `hatch.toml`).
//! The TOML locks live in [`super::pypi_locks`] (Poetry, PDM) and
//! [`super::uv`] (uv, PEP 723 script locks, PEP 751 pylock).
//!
//! Every restorer rewrites ONLY the entries whose reference is a hosted URL
//! naming an in-scope patch uuid; the version is the pin's (the hosted
//! rewriters drop every `==` pin, and discovery reads it back from the
//! url). Hashes are re-resolved from PyPI's JSON API
//! ([`super::client::UpstreamClient::pypi_files`]): every release file,
//! sorted by filename — what Pipenv and pip-compile record.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::{json, Value};
use toml_edit::{DocumentMut, Item};

use super::client::PypiFile;
use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::preserve_line_endings;
use crate::vendor::common::pep508_name;

/// The in-scope pin a hosted `location` names.
pub(super) fn pin_of<'p>(
    location: &str,
    pins: &BTreeMap<&str, &'p HostedPin>,
    ctx: &Ctx<'_>,
) -> Option<&'p HostedPin> {
    let uuid = ctx.hosted_uuid(location)?;
    pins.get(uuid.as_str()).copied()
}

/// `(canonical name, version)` of a pin, or its refusal.
pub(super) fn pin_coords(pin: &HostedPin, result: &mut FormatResult) -> Option<(String, String)> {
    match pin.name_version() {
        Some((name, version)) => Some((canonicalize_pypi_name(&name), version)),
        None => {
            result.refuse(&pin.uuid, format!("{} is not a pypi purl", pin.purl));
            None
        }
    }
}

/// The release files of every `(uuid, name, version)` wanted, fetched
/// concurrently and keyed by `(name, version)`. A failed lookup refuses its
/// pin.
pub(super) async fn fetch_release_files(
    wanted: &BTreeSet<(String, String, String)>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> BTreeMap<(String, String), Vec<PypiFile>> {
    let lookups = wanted.iter().map(|(uuid, name, version)| async move {
        (
            uuid.clone(),
            name.clone(),
            version.clone(),
            ctx.client.pypi_files(name, version).await,
        )
    });
    let mut out = BTreeMap::new();
    for (uuid, name, version, files) in futures_util::future::join_all(lookups).await {
        match files {
            Ok(files) => {
                out.insert((name, version), files);
            }
            Err(why) => result.refuse(&uuid, format!("{name}=={version}: {why}")),
        }
    }
    out
}

/// Whether every wheel of a release installs on every platform and every
/// Python 3 (`py3` in its python tag, `none` ABI, `any` platform), so a
/// lock that keeps only the files its targets can install — PDM without
/// `cross_platform`, uv's `requires-python` / environment filtering — still
/// records all of them. Sdists always qualify.
pub(super) fn universal_release(files: &[PypiFile]) -> bool {
    files.iter().all(|f| {
        let Some(stem) = f.filename.strip_suffix(".whl") else {
            return true;
        };
        let tags: Vec<&str> = stem.rsplitn(4, '-').collect();
        matches!(tags.as_slice(), [platform, abi, python, _]
            if *platform == "any" && *abi == "none" && python.split('.').any(|t| t == "py3"))
    })
}

/// A TOML basic string.
pub(super) fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML value parsed from `text`, keeping its own layout; its outer
/// decor is cleared so it renders after `key = ` like any other value.
pub(super) fn toml_value(text: &str) -> Option<toml_edit::Value> {
    let doc: DocumentMut = format!("v = {text}\n").parse().ok()?;
    let mut value = doc.get("v")?.as_value()?.clone();
    value.decor_mut().clear();
    Some(value)
}

/// `entries` as the multi-line array Poetry and PDM write (4-space indent,
/// trailing comma; `[]` when empty).
pub(super) fn multiline_toml_array(entries: &[String]) -> String {
    if entries.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[\n");
    for entry in entries {
        out.push_str("    ");
        out.push_str(entry);
        out.push_str(",\n");
    }
    out.push(']');
    out
}

// ── Pipfile.lock ─────────────────────────────────────────────────────────────

/// Whether `url` is PyPI's simple index (the only upstream the restore can
/// re-derive hashes for).
pub(super) fn is_pypi_simple(url: &str) -> bool {
    matches!(
        url.trim()
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .as_str(),
        "https://pypi.org/simple" | "https://pypi.python.org/simple"
    )
}

/// Whether the registry entry restored for `name` resolves from PyPI (the
/// only upstream whose hashes the restore can re-derive). The hosted
/// rewrite keeps the entry's `index` exactly as Pipenv wrote it, so the
/// restore never picks one: `entry_index` is carried back verbatim and only
/// checked here. Pipenv records `index` by release, Pipfile spelling and
/// locking environment (2022.12.19 writes it for an `extras` table and
/// 2026.8.0 does not; neither for a marker-excluded or a transitive
/// package) — nothing the lock's other entries could reveal.
fn pipenv_index_is_pypi(
    doc: &Value,
    entry_index: Option<&str>,
    pipfile: Option<&str>,
    name: &str,
) -> Result<(), String> {
    let sources: Vec<(&str, &str)> = doc
        .pointer("/_meta/sources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| {
            Some((
                s.get("name").and_then(Value::as_str)?,
                s.get("url").and_then(Value::as_str)?,
            ))
        })
        .collect();
    if !sources.iter().any(|(_, url)| is_pypi_simple(url)) {
        return Err(format!(
            "no package index in Pipfile.lock `_meta.sources` is PyPI ({}), so the \
             upstream hashes cannot be re-derived",
            sources
                .iter()
                .map(|(_, u)| *u)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let is_pypi = |index: &str| {
        sources
            .iter()
            .any(|(n, url)| *n == index && is_pypi_simple(url))
    };
    if let Some(index) = entry_index {
        if !is_pypi(index) {
            return Err(format!(
                "Pipfile.lock installs {name} from index {index:?}, not PyPI"
            ));
        }
    }
    if let Some(explicit) = pipfile.and_then(|p| pipfile_explicit_index(p, name)) {
        if !is_pypi(&explicit) {
            return Err(format!(
                "the Pipfile installs {name} from index {explicit:?}, not PyPI"
            ));
        }
    }
    Ok(())
}

/// The `index = "…"` a Pipfile declares for `name` in any package category.
fn pipfile_explicit_index(pipfile: &str, name: &str) -> Option<String> {
    let doc: DocumentMut = pipfile.trim_start_matches('\u{feff}').parse().ok()?;
    let canon = canonicalize_pypi_name(name);
    for (category, table) in doc.iter() {
        if matches!(category, "source" | "requires" | "pipenv" | "scripts") {
            continue;
        }
        let Some(table) = table.as_table_like() else {
            continue;
        };
        for (key, item) in table.iter() {
            if canonicalize_pypi_name(key) != canon {
                continue;
            }
            if let Some(index) = item
                .as_table_like()
                .and_then(|t| t.get("index"))
                .and_then(Item::as_str)
            {
                return Some(index.to_string());
            }
        }
    }
    None
}

/// One hosted `Pipfile.lock` entry.
struct PipenvHit {
    /// Index into the lock's `formats::pipenv::entries`.
    entry: usize,
    uuid: String,
    name: String,
    version: String,
}

pub(crate) async fn restore_pipfile_lock(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let (entries, doc) = match (
            crate::formats::pipenv::entries(&text),
            crate::vendor::lock_inventory::pypi::parse_pipfile_lock(&text),
        ) {
            (Ok(entries), Ok(doc)) => (entries, doc),
            (Err(e), _) => {
                refuse_all_in(&pins, rel, &mut result, format!("{rel}: {e}"));
                continue;
            }
            (_, Err(e)) => {
                refuse_all_in(
                    &pins,
                    rel,
                    &mut result,
                    format!("{rel} is not valid JSON: {e}"),
                );
                continue;
            }
        };
        let mut hits: Vec<PipenvHit> = Vec::new();
        for (i, (_, entry)) in entries.iter().enumerate() {
            let Some(object) = entry.value.as_object() else {
                continue;
            };
            let reference = object
                .get("file")
                .or_else(|| object.get("path"))
                .and_then(Value::as_str);
            let Some(pin) = reference.and_then(|r| pin_of(r, &pins, ctx)) else {
                continue;
            };
            let Some((_, version)) = pin_coords(pin, &mut result) else {
                continue;
            };
            if object.contains_key("file") && object.contains_key("path") {
                result.refuse(
                    &pin.uuid,
                    format!("{rel}: {} carries both `file` and `path`", entry.name),
                );
                continue;
            }
            if let Some(pinned) = object.get("version").and_then(Value::as_str) {
                if pinned != format!("=={version}") {
                    result.refuse(
                        &pin.uuid,
                        format!(
                            "{rel}: {} pins {pinned} beside the hosted {version} reference",
                            entry.name
                        ),
                    );
                    continue;
                }
            }
            hits.push(PipenvHit {
                entry: i,
                uuid: pin.uuid.clone(),
                name: entry.name.clone(),
                version,
            });
        }
        if hits.is_empty() {
            continue;
        }
        let pipfile_rel = match rel.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/Pipfile"),
            None => "Pipfile".to_string(),
        };
        let pipfile = view.read(&pipfile_rel).await.ok().flatten();
        let wanted = hits
            .iter()
            .filter(|h| !result.refused.contains_key(&h.uuid))
            .map(|h| {
                (
                    h.uuid.clone(),
                    canonicalize_pypi_name(&h.name),
                    h.version.clone(),
                )
            })
            .collect();
        let released = fetch_release_files(&wanted, ctx, &mut result).await;
        let mut splices: Vec<(std::ops::Range<usize>, String, String)> = Vec::new();
        for hit in &hits {
            if result.refused.contains_key(&hit.uuid) {
                continue;
            }
            let (_, entry) = &entries[hit.entry];
            let mut object = entry.value.as_object().cloned().unwrap_or_default();
            // `index` (and every other key but the reference, `version` and
            // `hashes`) is carried back as the entry holds it: the hosted
            // rewrite left Pipenv's own value, and a relock hybrid (Pipenv
            // 2023+ keeps our reference on a marker-excluded entry and
            // restores `version`/`hashes` around it) holds what Pipenv
            // just wrote.
            let entry_index = object.get("index").and_then(Value::as_str);
            if let Err(why) = pipenv_index_is_pypi(&doc, entry_index, pipfile.as_deref(), &hit.name)
            {
                result.refuse(&hit.uuid, format!("{rel}: {why}"));
                continue;
            }
            let Some(release) =
                released.get(&(canonicalize_pypi_name(&hit.name), hit.version.clone()))
            else {
                continue;
            };
            object.remove("file");
            object.remove("path");
            object.insert("version".into(), json!(format!("=={}", hit.version)));
            let mut hashes: Vec<String> = release
                .iter()
                .map(|f| format!("sha256:{}", f.sha256))
                .collect();
            hashes.sort();
            hashes.dedup();
            object.insert("hashes".into(), json!(hashes));
            let mut value = Value::Object(object);
            value.sort_all_objects();
            match crate::formats::pipenv::format_entry(&value, &text, entry.range.start) {
                Ok(rendered) => splices.push((entry.range.clone(), rendered, hit.uuid.clone())),
                Err(e) => result.refuse(&hit.uuid, format!("{rel}: {e}")),
            }
        }
        let mut next = text.clone();
        splices.sort_by_key(|(range, _, _)| std::cmp::Reverse(range.start));
        let mut changed = false;
        for (range, rendered, uuid) in splices {
            // A pin refused in another entry of this lock stays hosted in all.
            if result.refused.contains_key(&uuid) {
                continue;
            }
            next.replace_range(range, &rendered);
            result.handled.insert(uuid);
            changed = true;
        }
        if changed {
            view.write(rel, next);
        }
    }
    result
}

// ── requirements.txt ─────────────────────────────────────────────────────────

static HOSTED_LINE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\s*\[[^\]\r\n]*\])?\s*@\s*(\S+)(.*)$")
        .expect("static hosted requirement regex is valid")
});

/// Whether a requirements line carries a `--hash` option.
fn has_hash_option(tokens: &[&str]) -> bool {
    tokens
        .iter()
        .any(|t| *t == "--hash" || t.starts_with("--hash="))
}

/// Whether a requirements line is an editable (`-e <path>`, `-e<path>`,
/// `--editable <path>`, `--editable=<path>`), which pip refuses in
/// hash-checking mode.
fn is_editable(tokens: &[&str]) -> bool {
    tokens.first().is_some_and(|t| {
        (t.starts_with("-e") && !t.starts_with("--"))
            || *t == "--editable"
            || t.starts_with("--editable=")
    })
}

/// A hosted requirement line, cut into what its registry spelling keeps.
struct HostedLine {
    uuid: String,
    version: String,
    /// BOM + indentation before the name.
    prefix: String,
    name: String,
    extras: String,
    marker: String,
    options: String,
    comment: String,
    /// The hosted line carries `--hash`: the requirements rewriter writes
    /// it only into a file already in pip's hash-checking mode (#376),
    /// else it pins by the url's `#sha256=` fragment.
    hashed: bool,
}

/// The in-scope hosted line `requirement` is, if any: `Err((uuid, why))`
/// when it is one that cannot be restored.
fn hosted_line(
    requirement: &super::super::requirements::LogicalRequirement,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
) -> Option<Result<HostedLine, (String, String)>> {
    use super::super::requirements::{requirement_tokens, unquoted_index};
    let text = requirement.text.trim();
    let caps = HOSTED_LINE_RE.captures(text)?;
    let pin = pin_of(&caps[3], pins, ctx)?;
    let version = match pin.name_version() {
        Some((name, version))
            if canonicalize_pypi_name(&caps[1]) == canonicalize_pypi_name(&name) =>
        {
            version
        }
        _ => {
            return Some(Err((
                pin.uuid.clone(),
                format!(
                    "{:?} is wired to the hosted artifact of another package",
                    &caps[1]
                ),
            )))
        }
    };
    let rest = caps.get(4).map_or("", |m| m.as_str());
    let (body, comment) =
        unquoted_index(rest, '#', true).map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
    let tokens = requirement_tokens(body);
    let marker_len = tokens.iter().take_while(|t| !t.starts_with("--")).count();
    let marker = tokens[..marker_len].join(" ");
    let hashed = has_hash_option(&tokens[marker_len..]);
    let mut options = Vec::new();
    let mut rest_tokens = tokens[marker_len..].iter();
    while let Some(token) = rest_tokens.next() {
        if *token == "--hash" {
            rest_tokens.next();
        } else if !token.starts_with("--hash=") {
            options.push(*token);
        }
    }
    let unprefixed = requirement
        .original
        .strip_prefix('\u{feff}')
        .unwrap_or(&requirement.original);
    let indent = &unprefixed[..unprefixed.len() - unprefixed.trim_start_matches([' ', '\t']).len()];
    let bom = if requirement.original.starts_with('\u{feff}') {
        "\u{feff}"
    } else {
        ""
    };
    Some(Ok(HostedLine {
        uuid: pin.uuid.clone(),
        version,
        prefix: format!("{bom}{indent}"),
        name: caps[1].to_string(),
        extras: caps.get(2).map_or("", |m| m.as_str().trim()).to_string(),
        marker,
        options: options.join(" "),
        comment: comment.trim().to_string(),
        hashed,
    }))
}

pub(crate) async fn restore_requirements(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use super::super::requirements::{logical_requirements, requirement_tokens};
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let mut requirements = logical_requirements(&text);
        let mut hits: Vec<(usize, HostedLine)> = Vec::new();
        // The file's hash-checking mode, read off every line the hosted
        // rewrite did not write.
        let (mut require_hashes, mut hashed, mut unhashed) = (false, 0usize, 0usize);
        // The continuation indent of a hashed line pip-compile style
        // (`name==v \` then one indented `--hash=…` per line).
        let mut continuation: Option<String> = None;
        for (i, requirement) in requirements.iter().enumerate() {
            match hosted_line(requirement, &pins, ctx) {
                Some(Ok(line)) => {
                    hits.push((i, line));
                    continue;
                }
                Some(Err((uuid, why))) => {
                    result.refuse(&uuid, format!("{rel}: {why}"));
                    continue;
                }
                None => {}
            }
            let (code, _) = crate::utils::requirements::split_comment(&requirement.text);
            let code = code.trim();
            if code.is_empty() {
                continue;
            }
            let tokens = requirement_tokens(code);
            if tokens.contains(&"--require-hashes") {
                require_hashes = true;
            }
            // pip refuses an editable in hash-checking mode, so one settles
            // the file as unhashed (#410).
            if is_editable(&tokens) {
                unhashed += 1;
                continue;
            }
            if code.starts_with('-') {
                continue;
            }
            // Another pin's hosted line (always hashed) says nothing about
            // the original mode.
            if tokens
                .iter()
                .any(|t| ctx.hosted_uuid(t.trim_end_matches(';')).is_some())
            {
                continue;
            }
            if has_hash_option(&tokens) {
                hashed += 1;
                if continuation.is_none() {
                    continuation = requirement
                        .original
                        .split('\n')
                        .nth(1)
                        .filter(|l| l.trim_start().starts_with("--hash"))
                        .map(|l| l[..l.len() - l.trim_start().len()].to_string());
                }
            } else {
                unhashed += 1;
            }
        }
        if hits.is_empty() {
            continue;
        }
        let hash_mode = match (require_hashes || hashed > 0, unhashed > 0) {
            (true, false) => Ok(true),
            (false, true) => Ok(false),
            (true, true) => Err(format!(
                "{rel} mixes hashed and unhashed requirements, so whether the original line \
                 carried `--hash` options is not derivable"
            )),
            // Every requirement is a hosted pin (#410): nothing else in the
            // file can conflict with either form, so follow the hosted lines'
            // own shape, which records the mode the rewrite found.
            (false, false) => Ok(hits.iter().any(|(_, line)| line.hashed)),
        };
        let hash_mode = match hash_mode {
            Ok(mode) => mode,
            Err(why) => {
                for (_, line) in &hits {
                    result.refuse(&line.uuid, why.clone());
                }
                continue;
            }
        };
        let released = if hash_mode {
            let wanted = hits
                .iter()
                .map(|(_, l)| {
                    (
                        l.uuid.clone(),
                        canonicalize_pypi_name(&l.name),
                        l.version.clone(),
                    )
                })
                .collect();
            fetch_release_files(&wanted, ctx, &mut result).await
        } else {
            BTreeMap::new()
        };
        let eol = crate::utils::line_endings::terminator(&text);
        let mut rewritten: Vec<(usize, String, String)> = Vec::new();
        for (i, line) in &hits {
            if result.refused.contains_key(&line.uuid) {
                continue;
            }
            let mut out = format!(
                "{}{}{}=={}",
                line.prefix, line.name, line.extras, line.version
            );
            for suffix in [&line.marker, &line.options] {
                if !suffix.is_empty() {
                    out.push(' ');
                    out.push_str(suffix);
                }
            }
            if hash_mode {
                let Some(release) =
                    released.get(&(canonicalize_pypi_name(&line.name), line.version.clone()))
                else {
                    continue;
                };
                let mut hashes: Vec<&str> = release.iter().map(|f| f.sha256.as_str()).collect();
                hashes.sort();
                hashes.dedup();
                for hash in hashes {
                    match &continuation {
                        Some(indent) => {
                            out.push_str(&format!(" \\{eol}{indent}--hash=sha256:{hash}"))
                        }
                        None => out.push_str(&format!(" --hash=sha256:{hash}")),
                    }
                }
            }
            if !line.comment.is_empty() {
                out.push(' ');
                out.push_str(&line.comment);
            }
            rewritten.push((*i, out, line.uuid.clone()));
        }
        let mut changed = false;
        for (i, out, uuid) in rewritten {
            if result.refused.contains_key(&uuid) {
                continue;
            }
            requirements[i].original = out;
            result.handled.insert(uuid);
            changed = true;
        }
        if changed {
            let next: String = requirements
                .into_iter()
                .map(|r| r.original + &r.ending)
                .collect();
            view.write(rel, next);
        }
    }
    result
}

// ── Hatch: pyproject.toml / hatch.toml ───────────────────────────────────────

/// `declared[extras] @ <location>[ ; marker]` → `(declared, extras,
/// location, marker)`.
fn direct_reference(spec: &str) -> Option<(&str, &str, &str, &str)> {
    let spec = spec.trim();
    let declared = pep508_name(spec);
    if declared.is_empty() {
        return None;
    }
    let mut rest = spec[declared.len()..].trim_start();
    let mut extras = "";
    if rest.starts_with('[') {
        let end = rest.find(']')?;
        extras = &rest[..=end];
        rest = rest[end + 1..].trim_start();
    }
    let rest = rest.strip_prefix('@')?.trim_start();
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let location = rest[..end].trim_end_matches(';');
    let after = &rest[location.len()..];
    let marker = after.trim().strip_prefix(';').map_or("", str::trim);
    Some((declared, extras, location, marker))
}

/// Restore every hosted direct reference in one dependency array; the uuids
/// restored are added to `restored`, a mismatched one refuses.
fn restore_hatch_array(
    item: &mut Item,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
    restored: &mut BTreeSet<String>,
) -> usize {
    let Some(array) = item.as_array_mut() else {
        return 0;
    };
    let mut count = 0;
    for entry in array.iter_mut() {
        let Some(spec) = entry.as_str() else {
            continue;
        };
        let Some((declared, extras, location, marker)) = direct_reference(spec) else {
            continue;
        };
        let Some(pin) = pin_of(location, pins, ctx) else {
            continue;
        };
        let Some((name, version)) = pin_coords(pin, result) else {
            continue;
        };
        if canonicalize_pypi_name(declared) != name {
            result.refuse(
                &pin.uuid,
                format!("{declared:?} is wired to the hosted artifact of another package"),
            );
            continue;
        }
        let mut next = format!("{declared}{extras}=={version}");
        if !marker.is_empty() {
            next.push_str(" ; ");
            next.push_str(marker);
        }
        let decor = entry.decor().clone();
        *entry = toml_edit::Value::from(next);
        *entry.decor_mut() = decor;
        restored.insert(pin.uuid.clone());
        count += 1;
    }
    count
}

/// Every `dependencies` / `extra-dependencies` array of an `envs` table.
fn restore_hatch_envs(
    envs: Option<&mut Item>,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
    restored: &mut BTreeSet<String>,
) {
    let Some(envs) = envs.and_then(Item::as_table_like_mut) else {
        return;
    };
    for (_, env) in envs.iter_mut() {
        let Some(env) = env.as_table_like_mut() else {
            continue;
        };
        for key in ["dependencies", "extra-dependencies"] {
            if let Some(item) = env.get_mut(key) {
                restore_hatch_array(item, pins, ctx, result, restored);
            }
        }
    }
}

pub(crate) async fn restore_hatch(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use crate::utils::hatch::HATCH_FILES;
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    let mut docs: BTreeMap<&str, (String, DocumentMut)> = BTreeMap::new();
    for rel in HATCH_FILES {
        let text = if files.iter().any(|f| f == rel) {
            match read_or_refuse(view, rel, &pins, &mut result).await {
                Some(text) => text,
                None => continue,
            }
        } else {
            match view.read(rel).await {
                Ok(Some(text)) => text,
                _ => continue,
            }
        };
        match text.trim_start_matches('\u{feff}').parse::<DocumentMut>() {
            Ok(doc) => {
                docs.insert(rel, (text, doc));
            }
            Err(e) => refuse_all_in(&pins, rel, &mut result, format!("{rel}: {e}")),
        }
    }
    let mut restored: BTreeSet<String> = BTreeSet::new();
    let mut project_restored = 0;
    if let Some((_, doc)) = docs.get_mut("pyproject.toml") {
        if let Some(project) = doc.get_mut("project").and_then(Item::as_table_like_mut) {
            if let Some(item) = project.get_mut("dependencies") {
                project_restored +=
                    restore_hatch_array(item, &pins, ctx, &mut result, &mut restored);
            }
            if let Some(groups) = project
                .get_mut("optional-dependencies")
                .and_then(Item::as_table_like_mut)
            {
                for (_, item) in groups.iter_mut() {
                    project_restored +=
                        restore_hatch_array(item, &pins, ctx, &mut result, &mut restored);
                }
            }
        }
        if let Some(groups) = doc
            .get_mut("dependency-groups")
            .and_then(Item::as_table_like_mut)
        {
            for (_, item) in groups.iter_mut() {
                project_restored +=
                    restore_hatch_array(item, &pins, ctx, &mut result, &mut restored);
            }
        }
        let hatch = doc
            .get_mut("tool")
            .and_then(Item::as_table_like_mut)
            .and_then(|t| t.get_mut("hatch"));
        restore_hatch_envs(
            hatch.and_then(|h| h.get_mut("envs")),
            &pins,
            ctx,
            &mut result,
            &mut restored,
        );
    }
    if let Some((_, doc)) = docs.get_mut("hatch.toml") {
        restore_hatch_envs(doc.get_mut("envs"), &pins, ctx, &mut result, &mut restored);
    }
    // The permission the rewrite set once a PROJECT table got a direct
    // reference: dropped when none is left there (whatever its prior value,
    // it then governs nothing).
    let project_direct = docs.get("pyproject.toml").is_some_and(|(_, doc)| {
        crate::vendor::common::pyproject_dependency_specs(doc)
            .into_iter()
            .any(|(_, spec)| spec.split(';').next().is_some_and(|r| r.contains('@')))
    });
    if project_restored > 0 && !project_direct {
        let external = docs
            .get("hatch.toml")
            .is_some_and(|(_, doc)| doc.contains_key("metadata"));
        let file = if external {
            "hatch.toml"
        } else {
            "pyproject.toml"
        };
        if let Some((_, doc)) = docs.get_mut(file) {
            crate::utils::hatch::drop_direct_reference_permission(
                doc,
                crate::utils::hatch::permission_keys(external),
            );
        }
    }
    let restored: BTreeSet<String> = restored
        .into_iter()
        .filter(|u| !result.refused.contains_key(u))
        .collect();
    if !restored.is_empty() {
        for (rel, (text, doc)) in docs {
            let bom = if text.starts_with('\u{feff}') {
                "\u{feff}"
            } else {
                ""
            };
            let next = preserve_line_endings(&text, format!("{bom}{doc}"));
            if next != text {
                view.write(rel, next);
            }
        }
    }
    result.handled.extend(restored);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> PypiFile {
        PypiFile {
            filename: name.into(),
            url: format!("https://files.example/{name}"),
            sha256: "a".repeat(64),
            size: None,
            upload_time: None,
        }
    }

    #[test]
    fn universal_release_accepts_only_pure_python3_wheels() {
        assert!(universal_release(&[
            file("x-1.tar.gz"),
            file("x-1-py3-none-any.whl")
        ]));
        assert!(universal_release(&[file("x-1-py2.py3-none-any.whl")]));
        assert!(universal_release(&[file("x-1-2-py3-none-any.whl")]));
        assert!(!universal_release(&[file("x-1-py27-none-any.whl")]));
        assert!(!universal_release(&[file(
            "x-1-cp311-cp311-manylinux_2_17_x86_64.whl"
        )]));
        assert!(!universal_release(&[file("x-1-py3-abi3-any.whl")]));
    }

    #[test]
    fn direct_references_split_like_the_hatch_rewriter_writes_them() {
        assert_eq!(
            direct_reference("Urllib3[socks] @ https://h/u.whl#sha256=ab ; python_version >= '3'"),
            Some((
                "Urllib3",
                "[socks]",
                "https://h/u.whl#sha256=ab",
                "python_version >= '3'"
            ))
        );
        assert_eq!(
            direct_reference("urllib3 @ https://h/u.whl"),
            Some(("urllib3", "", "https://h/u.whl", ""))
        );
        assert_eq!(direct_reference("urllib3==1.0"), None);
    }

    #[test]
    fn pipenv_index_must_name_pypi_and_is_never_chosen() {
        let doc = json!({"_meta": {"sources": [
            {"name": "private", "url": "https://mirror.example/simple"},
            {"name": "pypi", "url": "https://pypi.org/simple/"},
        ]}});
        // The entry's own index (or none at all) is checked, never picked.
        assert!(pipenv_index_is_pypi(&doc, Some("pypi"), None, "x").is_ok());
        assert!(pipenv_index_is_pypi(&doc, None, None, "x").is_ok());
        assert!(pipenv_index_is_pypi(&doc, Some("private"), None, "x")
            .unwrap_err()
            .contains("not PyPI"));
        assert!(pipenv_index_is_pypi(&doc, Some("gone"), None, "x")
            .unwrap_err()
            .contains("not PyPI"));
        let pipfile = "[packages]\nX = { version = \"==1\", index = \"private\" }\n";
        assert!(pipenv_index_is_pypi(&doc, None, Some(pipfile), "x")
            .unwrap_err()
            .contains("the Pipfile installs"));
        let pipfile = "[packages]\nX = { version = \"==1\", index = \"pypi\" }\n";
        assert!(pipenv_index_is_pypi(&doc, Some("pypi"), Some(pipfile), "x").is_ok());
        let mirror = json!({"_meta": {"sources": [{"name": "m", "url": "https://m/simple"}]}});
        assert!(pipenv_index_is_pypi(&mirror, None, None, "x")
            .unwrap_err()
            .contains("is PyPI"));
        // Two spellings of PyPI: whichever the entry names is PyPI.
        let twice = json!({"_meta": {"sources": [
            {"name": "a", "url": "https://pypi.org/simple"},
            {"name": "b", "url": "https://pypi.python.org/simple"},
        ]}});
        assert!(pipenv_index_is_pypi(&twice, Some("b"), None, "x").is_ok());
    }

    #[test]
    fn toml_values_keep_their_layout() {
        let rendered = multiline_toml_array(&[format!(
            "{{file = {}, hash = \"sha256:ab\"}}",
            toml_quote("a.whl")
        )]);
        let value = toml_value(&rendered).unwrap();
        let mut doc: DocumentMut = "files = []\n".parse().unwrap();
        doc["files"] = Item::Value(value);
        assert_eq!(
            doc.to_string(),
            "files = [\n    {file = \"a.whl\", hash = \"sha256:ab\"},\n]\n"
        );
        assert_eq!(multiline_toml_array(&[]), "[]");
        assert_eq!(toml_quote("a\"b\\"), "\"a\\\"b\\\\\"");
    }

    // ── requirements.txt: pip's hash-checking mode (#410) ──────────────────

    use super::super::{restore_upstream, HostedPin, PinStatus, RestoreOptions, RestoreOutcome};

    /// #815: a restored hashed line's continuation takes the file's majority
    /// line ending; one stray CRLF comment no longer turns it CRLF.
    #[tokio::test]
    #[serial_test::serial]
    async fn restored_hash_continuation_takes_the_majority_line_ending() {
        let other = format!("idna==3.4 \\\n    --hash=sha256:{}\n", "c".repeat(64));
        for (head, eol) in [
            ("# pinned\r\n", "\n"),
            ("# pinned\r\n# by pip-compile\r\n# x\r\n# y\r\n", "\r\n"),
        ] {
            let (outcome, after) = restore_six(&format!("{head}{other}{}\n", hashed_line())).await;
            assert_restored(&outcome);
            assert!(
                after.contains(&format!("six==1.16.0 \\{eol}    --hash=sha256:")),
                "{after:?}"
            );
            assert_eq!(
                after.matches("\\\r\n").count(),
                if eol == "\r\n" { 2 } else { 0 }
            );
        }
    }
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SIX_UUID: &str = "41041041-0410-4410-8410-410410410410";
    const SIX_PATCHED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SIX_WHEEL: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const SIX_SDIST: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn six_url() -> String {
        format!(
            "https://patch.socket.dev/patch-registry/pypi/11111111-1111-1111-1111-111111111111/{SIX_UUID}/six-1.16.0-py2.py3-none-any.whl"
        )
    }

    /// The hosted line the requirements rewriter writes for six into an
    /// unhashed file (url `#sha256=` fragment, no `--hash` option).
    fn fragment_line() -> String {
        format!("six @ {}#sha256={SIX_PATCHED}", six_url())
    }

    /// The hosted line it writes into a hashed file (and that every pre-#383
    /// v5 rewrite wrote, whatever the file's mode).
    fn hashed_line() -> String {
        format!("six @ {} --hash=sha256:{SIX_PATCHED}", six_url())
    }

    async fn pypi_json() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/six/1.16.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "urls": [
                    { "filename": "six-1.16.0-py2.py3-none-any.whl",
                      "url": "https://files.example/six-1.16.0-py2.py3-none-any.whl",
                      "digests": { "sha256": SIX_WHEEL } },
                    { "filename": "six-1.16.0.tar.gz",
                      "url": "https://files.example/six-1.16.0.tar.gz",
                      "digests": { "sha256": SIX_SDIST } },
                ]
            })))
            .mount(&server)
            .await;
        server
    }

    /// Restore six's hosted pin in `requirements` (online against a mocked
    /// PyPI JSON API); the outcome and the file afterwards.
    async fn restore_six(requirements: &str) -> (RestoreOutcome, String) {
        let server = pypi_json().await;
        std::env::set_var("SOCKET_PYPI_JSON_API", format!("{}/pypi", server.uri()));
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("requirements.txt"), requirements).unwrap();
        let pins = [HostedPin {
            purl: "pkg:pypi/six@1.16.0".into(),
            uuid: SIX_UUID.into(),
            files: vec!["requirements.txt".into()],
        }];
        let outcome = restore_upstream(tmp.path(), &pins, &RestoreOptions::default()).await;
        std::env::remove_var("SOCKET_PYPI_JSON_API");
        let after = std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap();
        (outcome, after)
    }

    fn assert_restored(outcome: &RestoreOutcome) {
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
    }

    /// #410: a file whose only requirement is the hosted pin restores. The
    /// hosted line's own shape records the original mode: a `#sha256=`
    /// fragment means the file was unhashed.
    #[tokio::test]
    #[serial_test::serial]
    async fn requirements_with_only_a_hosted_pin_restores_unhashed() {
        for eol in ["\n", "\r\n"] {
            let (outcome, after) = restore_six(&format!("{}{eol}", fragment_line())).await;
            assert_restored(&outcome);
            assert_eq!(after, format!("six==1.16.0{eol}"));
        }
        // Comments, options and blank lines don't settle the mode either.
        let (outcome, after) = restore_six(&format!(
            "# pinned\n--index-url https://pypi.org/simple\n\n{} # via app\n",
            fragment_line()
        ))
        .await;
        assert_restored(&outcome);
        assert_eq!(
            after,
            "# pinned\n--index-url https://pypi.org/simple\n\nsix==1.16.0 # via app\n"
        );
    }

    /// #410: an all-hosted file whose hosted line carries `--hash` restores
    /// in hash-checking mode, with every upstream release file's hash. With
    /// no other requirement in the file there is nothing for it to conflict
    /// with.
    #[tokio::test]
    #[serial_test::serial]
    async fn requirements_with_only_a_hashed_hosted_pin_restores_hashed() {
        let (outcome, after) = restore_six(&format!("{}\n", hashed_line())).await;
        assert_restored(&outcome);
        assert_eq!(
            after,
            format!("six==1.16.0 --hash=sha256:{SIX_WHEEL} --hash=sha256:{SIX_SDIST}\n")
        );
    }

    /// #410: pip refuses an editable requirement in hash-checking mode, so an
    /// `-e` line settles the file as unhashed, even beside a hosted line
    /// that carries `--hash` (the pre-#383 shape).
    #[tokio::test]
    #[serial_test::serial]
    async fn an_editable_line_settles_requirements_as_unhashed() {
        for editable in ["-e .", "-e ./lib", "--editable .", "--editable=.", "-e."] {
            for hosted in [fragment_line(), hashed_line()] {
                let (outcome, after) = restore_six(&format!("{editable}\n{hosted}\n")).await;
                assert_restored(&outcome);
                assert_eq!(after, format!("{editable}\nsix==1.16.0\n"), "{hosted}");
            }
        }
    }

    /// Other requirement lines still decide, and genuinely mixed files are
    /// still refused rather than guessed.
    #[tokio::test]
    #[serial_test::serial]
    async fn other_requirement_lines_still_settle_the_mode() {
        let (outcome, after) = restore_six(&format!("idna==3.7\n{}\n", hashed_line())).await;
        assert_restored(&outcome);
        assert_eq!(after, "idna==3.7\nsix==1.16.0\n");

        let hashed_idna = "idna==3.7 --hash=sha256:aaaa\n";
        let (outcome, after) = restore_six(&format!("{hashed_idna}{}\n", fragment_line())).await;
        assert_restored(&outcome);
        assert_eq!(
            after,
            format!(
                "{hashed_idna}six==1.16.0 --hash=sha256:{SIX_WHEEL} --hash=sha256:{SIX_SDIST}\n"
            )
        );

        let mixed = format!(
            "idna==3.7 --hash=sha256:aaaa\ncertifi==2024.2.2\n{}\n",
            fragment_line()
        );
        let (outcome, after) = restore_six(&mixed).await;
        assert!(
            matches!(&outcome.pins[0].status, PinStatus::Refused(why) if why.contains("mixes hashed and unhashed")),
            "{:?}",
            outcome.pins
        );
        assert_eq!(after, mixed);

        // `-e` beside `--require-hashes` is a file pip can't install at all.
        let broken = format!("--require-hashes\n-e .\n{}\n", hashed_line());
        let (outcome, after) = restore_six(&broken).await;
        assert!(
            matches!(&outcome.pins[0].status, PinStatus::Refused(_)),
            "{:?}",
            outcome.pins
        );
        assert_eq!(after, broken);
    }
}
