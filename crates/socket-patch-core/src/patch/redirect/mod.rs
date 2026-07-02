//! Registry-redirect rewriters (the `scan --redirect` engine).
//!
//! Rewrites lockfiles / registry configs so ONLY the patched dependency points
//! at Socket's HOSTED vendored patches — the Rust counterpart of the depscan
//! backend's `@socketsecurity/app/patches/registry-rewrite` TS rewriters. Both
//! sides are held byte-consistent by the SHARED golden fixtures under
//! `tests/fixtures/redirect/` (see `tests/redirect_golden.rs`): a fixture's
//! `expected/` bytes are produced identically by the TS backend (the GitHub-app
//! PR flow) and by this CLI, so a customer gets the same result whether Socket
//! opens the PR or they run `socket-patch scan --redirect` locally.
//!
//! Non-JSON formats are edited SURGICALLY (regex/string) to stay byte-stable
//! and reproducible across languages; JSON uses `serde_json` with
//! `preserve_order` (2-space pretty + trailing newline) to match the TS
//! `JSON.stringify(v, null, 2) + '\n'`.

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod state;
pub use state::{load_redirect_state, RedirectState, REDIRECT_STATE_REL};

/// One ecosystem's integrity hashes (mirrors the TS `PatchArtifactIntegrity`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Integrity {
    pub sha512: Option<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub dirhash_h1: Option<String>,
    pub yarn_berry10c0: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryOverrideIdentifiers {
    pub name: String,
    pub version: String,
    pub cargo_cksum_sha256: Option<String>,
    pub go_module_path: Option<String>,
    pub nuget_id_lower: Option<String>,
    pub nuget_version_norm: Option<String>,
    pub maven_group_id: Option<String>,
    pub maven_artifact_id: Option<String>,
    pub gem_checksum_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryOverride {
    pub kind: String,
    pub index_url: String,
    pub identifiers: RegistryOverrideIdentifiers,
}

/// One patched dependency to redirect (mirrors the TS `DepOverride`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepOverride {
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub version: String,
    pub token: String,
    pub patch_uuid: String,
    pub artifact_url: String,
    #[serde(default)]
    pub berry_zip_url: Option<String>,
    #[serde(default)]
    pub registry_override: Option<RegistryOverride>,
    pub integrity: Integrity,
}

/// One recorded file edit (mirrors the TS `FileEdit`). `Deserialize` so the
/// persisted `redirect-state.json` ledger round-trips (see `redirect::state`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEdit {
    pub path: String,
    pub kind: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWarning {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct RewriteResult {
    /// Rewritten file contents keyed by repo-relative path — only CHANGED files.
    pub files: BTreeMap<String, String>,
    pub edits: Vec<FileEdit>,
    pub warnings: Vec<RewriteWarning>,
}

/// Combined name as it appears in registry coordinates / lock keys.
fn full_name(dep: &DepOverride) -> String {
    match &dep.namespace {
        Some(ns) if !ns.is_empty() => format!("{ns}/{}", dep.name),
        _ => dep.name.clone(),
    }
}

/// Canonical JSON serialization matching TS `JSON.stringify(v, null, 2) + '\n'`
/// (2-space pretty via serde_json, key order preserved by `preserve_order`,
/// `/` unescaped).
fn serialize_json(value: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).unwrap_or_default()
    )
}

/// Run every rewriter and merge the results (each owns distinct files).
pub fn rewrite_registry_redirect(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
) -> RewriteResult {
    let mut result = RewriteResult::default();
    rewrite_npm_lock(files, overrides, &mut result);
    rewrite_pnpm_lock(files, overrides, &mut result);
    rewrite_yarn_classic(files, overrides, &mut result);
    rewrite_pypi_requirements(files, overrides, &mut result);
    rewrite_uv_lock(files, overrides, &mut result);
    rewrite_cargo(files, overrides, &mut result);
    rewrite_composer_lock(files, overrides, &mut result);
    rewrite_nuget(files, overrides, &mut result);
    rewrite_gem(files, overrides, &mut result);
    rewrite_maven_pom(files, overrides, &mut result);
    rewrite_golang(overrides, &mut result);
    result
}

// ── npm package-lock.json / npm-shrinkwrap.json ─────────────────────────────
fn rewrite_npm_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() {
        return;
    }
    let lockfile = ["npm-shrinkwrap.json", "package-lock.json"]
        .into_iter()
        .find(|f| files.contains_key(*f));
    let Some(lockfile) = lockfile else {
        result.warnings.push(RewriteWarning {
            code: "redirect_npm_no_lockfile".into(),
            detail: "no package-lock.json / npm-shrinkwrap.json present".into(),
        });
        return;
    };
    let Ok(mut lock) = serde_json::from_str::<Value>(&files[lockfile]) else {
        return;
    };
    let mut changed = false;
    for dep in &npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        let suffix = format!("node_modules/{fname}");
        if let Some(packages) = lock.get_mut("packages").and_then(Value::as_object_mut) {
            for (key, entry) in packages.iter_mut() {
                let matches_key = key == &suffix || key.ends_with(&format!("/{suffix}"));
                let matches_ver =
                    entry.get("version").and_then(Value::as_str) == Some(dep.version.as_str());
                if matches_key && matches_ver {
                    if let Some(edit) = rewrite_npm_entry(
                        entry,
                        dep,
                        &sha512,
                        lockfile,
                        "redirect_npm_lock_entry",
                        key,
                    ) {
                        result.edits.push(edit);
                        changed = true;
                    }
                }
            }
        }
        // v2 legacy `dependencies` tree (keyed by name), recursive.
        if let Some(deps) = lock.get_mut("dependencies").and_then(Value::as_object_mut) {
            changed = rewrite_npm_v2_deps(deps, &fname, dep, &sha512, lockfile, result) || changed;
        }
    }
    if changed {
        result.files.insert(lockfile.into(), serialize_json(&lock));
    }
}

fn rewrite_npm_entry(
    entry: &mut Value,
    dep: &DepOverride,
    sha512: &str,
    lockfile: &str,
    kind: &str,
    key: &str,
) -> Option<FileEdit> {
    let obj = entry.as_object_mut()?;
    // Already redirected: recording an edit whose `original` IS the hosted
    // URL would grow the ledger on every re-run and poison a future revert.
    if obj.get("resolved").and_then(Value::as_str) == Some(dep.artifact_url.as_str())
        && obj.get("integrity").and_then(Value::as_str) == Some(sha512)
    {
        return None;
    }
    let original = json!({
        "resolved": obj.get("resolved").cloned().unwrap_or(Value::Null),
        "integrity": obj.get("integrity").cloned().unwrap_or(Value::Null),
    });
    obj.insert("resolved".into(), Value::String(dep.artifact_url.clone()));
    obj.insert("integrity".into(), Value::String(sha512.to_string()));
    Some(FileEdit {
        path: lockfile.into(),
        kind: kind.into(),
        action: "rewritten".into(),
        key: Some(key.into()),
        original: Some(original),
        new: Some(json!({ "resolved": dep.artifact_url, "integrity": sha512 })),
    })
}

fn rewrite_npm_v2_deps(
    deps: &mut serde_json::Map<String, Value>,
    fname: &str,
    dep: &DepOverride,
    sha512: &str,
    lockfile: &str,
    result: &mut RewriteResult,
) -> bool {
    let mut changed = false;
    for (name, entry) in deps.iter_mut() {
        if name == fname
            && entry.get("version").and_then(Value::as_str) == Some(dep.version.as_str())
        {
            if let Some(edit) =
                rewrite_npm_entry(entry, dep, sha512, lockfile, "redirect_npm_lock_dep", name)
            {
                result.edits.push(edit);
                changed = true;
            }
        }
        if let Some(nested) = entry.get_mut("dependencies").and_then(Value::as_object_mut) {
            changed = rewrite_npm_v2_deps(nested, fname, dep, sha512, lockfile, result) || changed;
        }
    }
    changed
}

// ── pip requirements.txt ────────────────────────────────────────────────────
fn normalize_py_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(ch);
            prev_dash = false;
        }
    }
    out
}

fn rewrite_pypi_requirements(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let pypi: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "pypi").collect();
    if pypi.is_empty() || !files.contains_key("requirements.txt") {
        return;
    }
    let name_re = Regex::new(r"^([A-Za-z0-9._-]+)\s*(?:[=<>~!]=?|@|;|\s|$)").unwrap();
    let mut lines: Vec<String> = files["requirements.txt"]
        .split('\n')
        .map(|s| s.to_string())
        .collect();
    let mut changed = false;
    for dep in &pypi {
        let Some(sha256) = dep.integrity.sha256.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_requirements_missing_sha256".into(),
                detail: format!("{} has no sha256 integrity", dep.name),
            });
            continue;
        };
        let target = normalize_py_name(&dep.name);
        for raw in lines.iter_mut() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            let Some(caps) = name_re.captures(line) else {
                continue;
            };
            if normalize_py_name(&caps[1]) != target {
                continue;
            }
            // pip-compile --generate-hashes emits backslash continuations
            // (`foo==1.2 \` + indented `--hash=…` lines). Rewriting only the
            // first physical line would orphan the old hash lines and — with
            // an environment marker — leave a mid-line `\` that makes pip
            // fail with InvalidMarker. Refuse rather than corrupt.
            if line.ends_with('\\') {
                result.warnings.push(RewriteWarning {
                    code: "redirect_requirements_continuation".into(),
                    detail: format!(
                        "{}@{} uses backslash continuations; not rewritten",
                        dep.name, dep.version
                    ),
                });
                continue;
            }
            // Take the marker from the requirement portion only — everything
            // BEFORE any per-requirement ` --` option. Grabbing to end-of-line
            // would swallow a previously appended `--hash=…` and duplicate it
            // on every re-run.
            let req_part = line.split(" --").next().unwrap_or(line).trim_end();
            let marker = match req_part.find(';') {
                Some(idx) => req_part[idx..].trim_end(),
                None => "",
            };
            let rewritten = if marker.is_empty() {
                format!("{} @ {} --hash=sha256:{sha256}", dep.name, dep.artifact_url)
            } else {
                format!(
                    "{} @ {} {marker} --hash=sha256:{sha256}",
                    dep.name, dep.artifact_url
                )
            };
            if rewritten != *raw {
                result.edits.push(FileEdit {
                    path: "requirements.txt".into(),
                    kind: "redirect_requirements_line".into(),
                    action: "rewritten".into(),
                    key: Some(dep.name.clone()),
                    original: Some(Value::String(raw.clone())),
                    new: Some(Value::String(rewritten.clone())),
                });
                *raw = rewritten;
                changed = true;
            }
        }
    }
    if changed {
        result
            .files
            .insert("requirements.txt".into(), lines.join("\n"));
    }
}

// ── cargo (Cargo.toml + .cargo/config.toml + Cargo.lock) ─────────────────────
fn cargo_registry_name(patch_uuid: &str) -> String {
    format!("socket-patch-{patch_uuid}")
}

fn rewrite_cargo(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let cargo: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "cargo")
        .collect();
    if cargo.is_empty() {
        return;
    }
    let mut cargo_toml = files.get("Cargo.toml").cloned();
    let mut cargo_lock = files.get("Cargo.lock").cloned();
    let mut cargo_config = files.get(".cargo/config.toml").cloned().unwrap_or_default();
    let (mut toml_changed, mut lock_changed, mut config_changed) = (false, false, false);

    for dep in &cargo {
        let Some(ov) = &dep.registry_override else {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_missing_override".into(),
                detail: format!("{} has no cargo-sparse registry override", dep.name),
            });
            continue;
        };
        if ov.kind != "cargo-sparse" {
            continue;
        }
        let Some(cksum) = ov
            .identifiers
            .cargo_cksum_sha256
            .clone()
            .or_else(|| dep.integrity.sha256.clone())
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_missing_cksum".into(),
                detail: format!("{} has no sha256 cksum", dep.name),
            });
            continue;
        };
        let reg = cargo_registry_name(&dep.patch_uuid);
        let index_url = &ov.index_url;

        // 1. .cargo/config.toml registry definition (idempotent).
        if !cargo_config.contains(&format!("[registries.{reg}]")) {
            let block = format!("[registries.{reg}]\nindex = \"{index_url}\"\n");
            let sep = if !cargo_config.is_empty() && !cargo_config.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let prefix = if cargo_config.is_empty() { "" } else { "\n" };
            cargo_config = format!("{cargo_config}{sep}{prefix}{block}");
            config_changed = true;
            result.edits.push(FileEdit {
                path: ".cargo/config.toml".into(),
                kind: "redirect_cargo_registry".into(),
                action: "added".into(),
                key: Some(reg.clone()),
                original: None,
                new: Some(Value::String(block)),
            });
        }

        // 2. Cargo.toml dep → add `registry = "<reg>"`.
        if let Some(toml) = cargo_toml.as_mut() {
            if let Some(edit) = add_cargo_toml_registry(toml, &dep.name, &reg) {
                result.edits.push(edit);
                toml_changed = true;
            } else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_cargo_toml_dep_not_found".into(),
                    detail: format!("no [dependencies] entry for {} in Cargo.toml", dep.name),
                });
            }
        }

        // 3. Cargo.lock [[package]] → set source + checksum.
        if let Some(lock) = cargo_lock.as_mut() {
            match set_cargo_lock_source(lock, &dep.name, &dep.version, index_url, &cksum) {
                CargoLockRewrite::Rewritten(edit) => {
                    result.edits.push(*edit);
                    lock_changed = true;
                }
                // Re-run over an already-redirected lock: nothing to record.
                CargoLockRewrite::AlreadyRedirected => {}
                CargoLockRewrite::NotFound => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_cargo_lock_pkg_not_found".into(),
                        detail: format!(
                            "no [[package]] for {}@{} in Cargo.lock",
                            dep.name, dep.version
                        ),
                    });
                }
            }
        }
    }

    if toml_changed {
        if let Some(t) = cargo_toml {
            result.files.insert("Cargo.toml".into(), t);
        }
    }
    if lock_changed {
        if let Some(l) = cargo_lock {
            result.files.insert("Cargo.lock".into(), l);
        }
    }
    if config_changed {
        result
            .files
            .insert(".cargo/config.toml".into(), cargo_config);
    }
}

fn add_cargo_toml_registry(content: &mut String, crate_name: &str, reg: &str) -> Option<FileEdit> {
    let c = regex::escape(crate_name);
    // Inline table: `crate = { version = "…", … }`.
    let table_re = Regex::new(&format!(r"(?m)^({c}\s*=\s*\{{)([^}}\n]*)(\}})")).unwrap();
    if let Some(m) = table_re.captures(content) {
        let inner = m.get(2).unwrap().as_str();
        if Regex::new(r"\bregistry\s*=").unwrap().is_match(inner) {
            return None;
        }
        let whole = m.get(0).unwrap().as_str().to_string();
        let inner_trim = inner.trim_end();
        let sep = if inner_trim.trim().ends_with(',') || inner_trim.trim().is_empty() {
            ""
        } else {
            ","
        };
        let rebuilt = format!(
            "{}{inner_trim}{sep} registry = \"{reg}\" {}",
            m.get(1).unwrap().as_str(),
            m.get(3).unwrap().as_str()
        );
        *content = content.replacen(&whole, &rebuilt, 1);
        return Some(FileEdit {
            path: "Cargo.toml".into(),
            kind: "redirect_cargo_toml_dep".into(),
            action: "rewritten".into(),
            key: Some(crate_name.into()),
            original: Some(Value::String(whole)),
            new: Some(Value::String(rebuilt)),
        });
    }
    // Plain version: `crate = "1.0"`.
    let ver_re = Regex::new(&format!(r#"(?m)^({c}\s*=\s*)"([^"]+)"\s*$"#)).unwrap();
    if let Some(m) = ver_re.captures(content) {
        let whole = m.get(0).unwrap().as_str().to_string();
        let rebuilt = format!(
            "{}{{ version = \"{}\", registry = \"{reg}\" }}",
            m.get(1).unwrap().as_str(),
            m.get(2).unwrap().as_str()
        );
        *content = content.replacen(&whole, &rebuilt, 1);
        return Some(FileEdit {
            path: "Cargo.toml".into(),
            kind: "redirect_cargo_toml_dep".into(),
            action: "rewritten".into(),
            key: Some(crate_name.into()),
            original: Some(Value::String(whole)),
            new: Some(Value::String(rebuilt)),
        });
    }
    None
}

fn set_cargo_lock_source(
    content: &mut String,
    crate_name: &str,
    version: &str,
    index_url: &str,
    cksum: &str,
) -> CargoLockRewrite {
    // Rust's regex has NO lookahead, so bound the [[package]] block by string
    // search: from its header to the next `\n[[package]]` (or EOF), so the
    // trailing bytes after the block (incl. the final newline) are preserved.
    let head = format!("[[package]]\nname = \"{crate_name}\"\nversion = \"{version}\"\n");
    let Some(block_start) = content.find(&head) else {
        return CargoLockRewrite::NotFound;
    };
    let body_start = block_start + head.len();
    let mut block_end = match content[body_start..].find("\n[[package]]") {
        Some(rel) => body_start + rel,
        None => content.len(),
    };
    // Exclude trailing newline(s) from the block region so the recorded
    // original/new strings stop after the last content byte (mirrors the TS
    // rewriter's `(?=\n*$)` lookahead), while the file keeps its trailing
    // newline (it stays outside the replaced region).
    while block_end > body_start && content.as_bytes()[block_end - 1] == b'\n' {
        block_end -= 1;
    }
    let original = content[block_start..block_end].to_string();
    let mut body = content[body_start..block_end].to_string();
    let source_re = Regex::new(r#"(?m)^source = "[^"]*"$"#).unwrap();
    if source_re.is_match(&body) {
        body = source_re
            .replace(&body, format!("source = \"{index_url}\"").as_str())
            .to_string();
    } else {
        body = format!("source = \"{index_url}\"\n{body}");
    }
    let checksum_re = Regex::new(r#"(?m)^checksum = "[^"]*"$"#).unwrap();
    if checksum_re.is_match(&body) {
        body = checksum_re
            .replace(&body, format!("checksum = \"{cksum}\"").as_str())
            .to_string();
    } else {
        let after_source = Regex::new(r#"(?m)^(source = "[^"]*"\n)"#).unwrap();
        body = after_source
            .replace(&body, format!("${{1}}checksum = \"{cksum}\"\n").as_str())
            .to_string();
    }
    let rebuilt = format!("{head}{body}");
    // Already redirected (re-run): the block is at the target values; a
    // recorded edit would have original == new and grow the ledger forever.
    if rebuilt == original {
        return CargoLockRewrite::AlreadyRedirected;
    }
    *content = content.replacen(&original, &rebuilt, 1);
    CargoLockRewrite::Rewritten(Box::new(FileEdit {
        path: "Cargo.lock".into(),
        kind: "redirect_cargo_lock_entry".into(),
        action: "rewritten".into(),
        key: Some(format!("{crate_name}@{version}")),
        original: Some(Value::String(original)),
        new: Some(Value::String(rebuilt)),
    }))
}

/// Outcome of the Cargo.lock `[[package]]` rewrite — distinguishes a re-run
/// over an already-redirected block (no edit, no warning) from a genuinely
/// missing package (caller warns).
enum CargoLockRewrite {
    Rewritten(Box<FileEdit>),
    AlreadyRedirected,
    NotFound,
}

// ── pnpm-lock.yaml ───────────────────────────────────────────────────────────
/// A `pnpm-lock.yaml` is `pnpm-lock.yaml` at the project root or at any nested
/// path (e.g. Rush repos keep them under `common/config/rush/`). Every such
/// files-map key is rewritten under the same grammar.
fn is_pnpm_lock_key(key: &str) -> bool {
    key == "pnpm-lock.yaml" || key.ends_with("/pnpm-lock.yaml")
}

fn rewrite_pnpm_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    // Deterministic order: BTreeMap iterates keys sorted, so goldens are
    // stable across every pnpm lock in the set.
    let lock_keys: Vec<&String> = files.keys().filter(|k| is_pnpm_lock_key(k)).collect();
    if npm.is_empty() || lock_keys.is_empty() {
        return;
    }
    // Work on an editable copy of each lock so a single dep can be rewritten
    // in whichever locks contain it.
    let mut contents: Vec<(&String, String, bool)> = lock_keys
        .iter()
        .map(|k| (*k, files[*k].clone(), false))
        .collect();
    for dep in &npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        // `(^ {2}/?<fn>@<ver>:\n(?: {4,}.*\n)*? {4,}resolution: )\{([^}\n]*)\}`
        let pat = String::from(r"(?m)(^ {2}/?")
            + &regex::escape(&fname)
            + "@"
            + &regex::escape(&dep.version)
            + r":\n(?: {4,}.*\n)*? {4,}resolution: )\{([^}\n]*)\}";
        let re = Regex::new(&pat).unwrap();
        let mut matched_any = false;
        for (key, content, changed) in &mut contents {
            let Some(caps) = re.captures(content) else {
                continue;
            };
            matched_any = true;
            let whole = caps.get(0).unwrap().as_str().to_string();
            let prefix = caps.get(1).unwrap().as_str().to_string();
            let inner = caps.get(2).unwrap().as_str().to_string();
            let original = format!("{{{inner}}}");
            let mut fields: Vec<String> = vec![
                format!("integrity: {sha512}"),
                format!("tarball: {}", dep.artifact_url),
            ];
            for f in inner.split(',') {
                let t = f.trim();
                if !t.is_empty() && !t.starts_with("integrity:") && !t.starts_with("tarball:") {
                    fields.push(t.to_string());
                }
            }
            let rebuilt = format!("{{{}}}", fields.join(", "));
            // Already redirected (re-run): no edit, no ledger growth.
            if rebuilt == original {
                continue;
            }
            *content = content.replacen(&whole, &format!("{prefix}{rebuilt}"), 1);
            *changed = true;
            result.edits.push(FileEdit {
                path: (*key).clone(),
                kind: "redirect_pnpm_resolution".into(),
                action: "rewritten".into(),
                key: Some(format!("{fname}@{}", dep.version)),
                original: Some(Value::String(original)),
                new: Some(Value::String(rebuilt)),
            });
        }
        // The entry-not-found warning fires only when the dep matched in NO
        // pnpm lock across the whole set, not once per lock.
        if !matched_any {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_entry_not_found".into(),
                detail: format!("no inline resolution for {fname}@{}", dep.version),
            });
        }
    }
    for (key, content, changed) in contents {
        if changed {
            result.files.insert(key.clone(), content);
        }
    }
}

// ── yarn.lock (classic) ──────────────────────────────────────────────────────
fn rewrite_yarn_classic(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("yarn.lock") {
        return;
    }
    let content = &files["yarn.lock"];
    if Regex::new(r"(?m)^__metadata:").unwrap().is_match(content) {
        return; // yarn-berry — not classic
    }
    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolved_re = Regex::new(r#"\n {2}resolved "[^"]*""#).unwrap();
    let integrity_re = Regex::new(r"\n {2}integrity [^\n]*").unwrap();
    let mut changed = false;
    for dep in &npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_classic_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        let header_re =
            Regex::new(&(String::from(r#"(?m)^ *"?"#) + &regex::escape(&fname) + "@")).unwrap();
        let version_re =
            Regex::new(&(String::from(r#"\n {2}version ""#) + &regex::escape(&dep.version) + "\""))
                .unwrap();
        for block in blocks.iter_mut() {
            if !header_re.is_match(block) || !version_re.is_match(block) {
                continue;
            }
            let frag = dep
                .integrity
                .sha1
                .as_ref()
                .map(|s| format!("#{s}"))
                .unwrap_or_default();
            let mut rewritten = resolved_re
                .replace(
                    block,
                    format!("\n  resolved \"{}{frag}\"", dep.artifact_url).as_str(),
                )
                .to_string();
            if integrity_re.is_match(&rewritten) {
                rewritten = integrity_re
                    .replace(&rewritten, format!("\n  integrity {sha512}").as_str())
                    .to_string();
            } else {
                rewritten = resolved_re
                    .replace(
                        &rewritten,
                        // $0 re-inserts the matched resolved line, then add integrity.
                        format!(
                            "\n  resolved \"{}{frag}\"\n  integrity {sha512}",
                            dep.artifact_url
                        )
                        .as_str(),
                    )
                    .to_string();
            }
            if rewritten != *block {
                result.edits.push(FileEdit {
                    path: "yarn.lock".into(),
                    kind: "redirect_yarn_classic_entry".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}", dep.version)),
                    original: Some(Value::String(block.clone())),
                    new: Some(Value::String(rewritten.clone())),
                });
                *block = rewritten;
                changed = true;
            }
        }
    }
    if changed {
        result.files.insert("yarn.lock".into(), blocks.join("\n\n"));
    }
}

// ── uv.lock ──────────────────────────────────────────────────────────────────
fn rewrite_uv_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let pypi: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "pypi").collect();
    if pypi.is_empty() || !files.contains_key("uv.lock") {
        return;
    }
    let mut content = files["uv.lock"].clone();
    let wheel_re = Regex::new(r#"\{ url = "[^"]*", hash = "sha256:[^"]*"([^}]*) \}"#).unwrap();
    let name_re = Regex::new(r#"name = "([^"]+)""#).unwrap();
    let mut changed = false;
    for dep in &pypi {
        let Some(sha256) = dep.integrity.sha256.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_uv_missing_sha256".into(),
                detail: format!("{} has no sha256 integrity", dep.name),
            });
            continue;
        };
        // Find the [[package]] block for this name+version by string bounds
        // (no lookahead in Rust regex). Iterate over [[package]] starts.
        let target = normalize_py_name(&dep.name);
        let mut matched = false;
        let marker = "[[package]]\n";
        let mut search = 0usize;
        while let Some(rel) = content[search..].find(marker) {
            let block_start = search + rel;
            let body_start = block_start + marker.len();
            let block_end = match content[body_start..].find("\n[[package]]") {
                Some(r) => body_start + r + 1,
                None => content.len(),
            };
            let block = content[block_start..block_end].to_string();
            search = block_end;
            let name_ok = name_re
                .captures(&block)
                .map(|c| normalize_py_name(&c[1]) == target)
                .unwrap_or(false);
            let version_ok = block.contains(&format!("version = \"{}\"\n", dep.version))
                || block.contains(&format!("version = \"{}\"", dep.version));
            if !name_ok || !version_ok {
                continue;
            }
            // Split the head (`[[package]]\nname\nversion\n` — 3 lines) from the
            // body, so the recorded edit is the BODY (matches the TS rewriter,
            // whose regex captured head + body separately).
            let head_end = {
                let mut nl = 0;
                let mut idx = block.len();
                for (i, ch) in block.char_indices() {
                    if ch == '\n' {
                        nl += 1;
                        if nl == 3 {
                            idx = i + 1;
                            break;
                        }
                    }
                }
                idx
            };
            let head = block[..head_end].to_string();
            let body = block[head_end..].to_string();
            if !wheel_re.is_match(&body) {
                continue;
            }
            let new_body = wheel_re
                .replace(
                    &body,
                    format!(
                        "{{ url = \"{}\", hash = \"sha256:{sha256}\"${{1}} }}",
                        dep.artifact_url
                    )
                    .as_str(),
                )
                .to_string();
            if new_body == body {
                continue;
            }
            content = format!(
                "{}{}{}{}",
                &content[..block_start],
                head,
                new_body,
                &content[block_end..]
            );
            matched = true;
            changed = true;
            result.edits.push(FileEdit {
                path: "uv.lock".into(),
                kind: "redirect_uv_lock_wheel".into(),
                action: "rewritten".into(),
                key: Some(format!("{}@{}", dep.name, dep.version)),
                original: Some(Value::String(body)),
                new: Some(Value::String(new_body)),
            });
            break;
        }
        if !matched {
            result.warnings.push(RewriteWarning {
                code: "redirect_uv_entry_not_found".into(),
                detail: format!("no uv.lock wheel entry for {}@{}", dep.name, dep.version),
            });
        }
    }
    if changed {
        result.files.insert("uv.lock".into(), content);
    }
}

// ── composer.lock ────────────────────────────────────────────────────────────
fn rewrite_composer_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let composer: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "composer")
        .collect();
    if composer.is_empty() || !files.contains_key("composer.lock") {
        return;
    }
    let mut content = files["composer.lock"].clone();
    let type_re = Regex::new(r#"("type": ")[^"]*(")"#).unwrap();
    let url_re = Regex::new(r#"("url": ")[^"]*(")"#).unwrap();
    let shasum_re = Regex::new(r#"("shasum": ")[^"]*(")"#).unwrap();
    let mut changed = false;
    for dep in &composer {
        let composer_name = full_name(dep);
        let Some(sha1) = dep.integrity.sha1.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_missing_sha1".into(),
                detail: format!("{composer_name} has no sha1 (dist.shasum) integrity"),
            });
            continue;
        };
        let Some(name_idx) = content.find(&format!("\"name\": \"{composer_name}\"")) else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_pkg_not_found".into(),
                detail: format!("no composer.lock package named {composer_name}"),
            });
            continue;
        };
        let Some(dist_start) = content[name_idx..]
            .find("\"dist\": {")
            .map(|r| name_idx + r)
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist".into(),
                detail: format!("{composer_name} has no dist block"),
            });
            continue;
        };
        let Some(dist_end) = content[dist_start..].find('}').map(|r| dist_start + r) else {
            continue;
        };
        let block = content[dist_start..=dist_end].to_string();
        let escaped_url = dep.artifact_url.replace('/', "\\/");
        let mut rewritten = type_re.replace(&block, "${1}zip${2}").to_string();
        rewritten = url_re
            .replace(&rewritten, format!("${{1}}{escaped_url}${{2}}").as_str())
            .to_string();
        if rewritten.contains("\"shasum\": \"") {
            rewritten = shasum_re
                .replace(&rewritten, format!("${{1}}{sha1}${{2}}").as_str())
                .to_string();
        }
        if rewritten != block {
            content = format!(
                "{}{}{}",
                &content[..dist_start],
                rewritten,
                &content[dist_end + 1..]
            );
            changed = true;
            result.edits.push(FileEdit {
                path: "composer.lock".into(),
                kind: "redirect_composer_dist".into(),
                action: "rewritten".into(),
                key: Some(composer_name),
                original: Some(Value::String(block)),
                new: Some(Value::String(rewritten)),
            });
        }
    }
    if changed {
        result.files.insert("composer.lock".into(), content);
    }
}

// ── nuget (nuget.config + packages.lock.json) ────────────────────────────────
fn default_nuget_config() -> String {
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>\n</configuration>\n".to_string()
}

/// The default public NuGet source key/URL, seeded as the catch-all target when
/// a from-scratch `<packageSourceMapping>` would otherwise have NO pre-existing
/// source to fan `*` out to (a socket-only mapping NU1100s every other package).
const NUGET_ORG_KEY: &str = "nuget.org";
const NUGET_ORG_URL: &str = "https://api.nuget.org/v3/index.json";

fn add_nuget_source(config: &str, reg: &str, index_url: &str, pkg_id: &str) -> String {
    // Capture the pre-existing packageSource keys BEFORE the Socket source is
    // added — the fallback below fans a `*` mapping out to them.
    let mut pre_existing_keys = nuget_package_source_keys(config);
    let mut out = config.to_string();

    // A from-scratch <packageSourceMapping> is EXCLUSIVE: once it exists, every
    // package must match some source's `*`/pattern or restore fails NU1100. If
    // there are NO pre-existing sources to fan `*` out to, the mapping would be
    // socket-only and every other package would fail. Seed the implicit default
    // nuget.org source so the catch-all has a real target (unless the config
    // already has one). Only relevant when we are about to CREATE the mapping.
    let creating_mapping = !out.contains("<packageSourceMapping>");
    let seed_nuget_org =
        creating_mapping && pre_existing_keys.is_empty() && !config.contains(NUGET_ORG_KEY);
    if seed_nuget_org {
        out = insert_nuget_source(&out, NUGET_ORG_KEY, NUGET_ORG_URL);
        pre_existing_keys.push(NUGET_ORG_KEY.to_string());
    }

    out = insert_nuget_source(&out, reg, index_url);

    let socket_mapping = format!(
        "    <packageSource key=\"{reg}\">\n      <package pattern=\"{pkg_id}\" />\n    </packageSource>"
    );
    if !creating_mapping {
        // A mapping already exists (e.g. a prior patched dep, or the project's
        // own): append ONLY this source's mapping — every other source is
        // already covered.
        out = out.replacen(
            "<packageSourceMapping>",
            &format!("<packageSourceMapping>\n{socket_mapping}"),
            1,
        );
    } else {
        // Creating the mapping from scratch. Once ANY <packageSourceMapping>
        // exists, NuGet requires EVERY package to match some source's pattern,
        // so a mapping that routed only the patched id to the Socket source
        // would make every OTHER package fail restore with NU1100. Fan a
        // `<package pattern="*" />` out to each pre-existing source (which now
        // includes the seeded nuget.org when the config had none) so the rest
        // of the restore keeps resolving exactly where it did before.
        let fallback_mappings = pre_existing_keys
            .iter()
            .map(|key| {
                format!(
                    "    <packageSource key=\"{key}\">\n      <package pattern=\"*\" />\n    </packageSource>"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let inner = if fallback_mappings.is_empty() {
            socket_mapping
        } else {
            format!("{socket_mapping}\n{fallback_mappings}")
        };
        let map_block = format!("  <packageSourceMapping>\n{inner}\n  </packageSourceMapping>");
        out = out.replacen(
            "</configuration>",
            &format!("{map_block}\n</configuration>"),
            1,
        );
    }
    out
}

/// Insert an `<add key="…" value="…" />` source under `<packageSources>`,
/// creating the element (right after `<configuration>`) when absent. A
/// self-closing `<packageSources />` (any whitespace before `/>`) is expanded
/// in place into an open/close pair rather than left dangling beside a
/// duplicate element.
fn insert_nuget_source(config: &str, key: &str, url: &str) -> String {
    let source_line = format!("    <add key=\"{key}\" value=\"{url}\" />");
    // A self-closing element carries no children, so expand it to an open/close
    // pair holding the new source. Matched before the open-tag check because a
    // `<packageSources/>` literal does not contain the `<packageSources>` open
    // tag.
    let self_closing = Regex::new(r"<packageSources\s*/>").unwrap();
    if let Some(m) = self_closing.find(config) {
        let mut out = String::with_capacity(config.len() + source_line.len() + 40);
        out.push_str(&config[..m.start()]);
        out.push_str(&format!(
            "<packageSources>\n{source_line}\n  </packageSources>"
        ));
        out.push_str(&config[m.end()..]);
        out
    } else if config.contains("<packageSources>") {
        config.replacen(
            "<packageSources>",
            &format!("<packageSources>\n{source_line}"),
            1,
        )
    } else {
        config.replacen(
            "<configuration>",
            &format!("<configuration>\n  <packageSources>\n{source_line}\n  </packageSources>"),
            1,
        )
    }
}

/// The `key` of every `<add … />` under `<packageSources>` (empty when there
/// is no such element). Used to preserve resolution for non-patched packages
/// when a `<packageSourceMapping>` is introduced.
fn nuget_package_source_keys(config: &str) -> Vec<String> {
    let region_re = Regex::new(r"(?s)<packageSources>(.*?)</packageSources>").unwrap();
    let scope = region_re
        .captures(config)
        .map(|c| c.get(1).unwrap().as_str())
        .unwrap_or("");
    Regex::new(r#"<add\s+key="([^"]+)""#)
        .unwrap()
        .captures_iter(scope)
        .map(|c| c[1].to_string())
        .collect()
}

fn rewrite_nuget(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let nuget: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "nuget")
        .collect();
    if nuget.is_empty() {
        return;
    }
    let mut config = files
        .get("nuget.config")
        .cloned()
        .unwrap_or_else(default_nuget_config);
    let mut config_changed = false;
    let mut lock: Option<Value> = files
        .get("packages.lock.json")
        .and_then(|s| serde_json::from_str(s).ok());
    let mut lock_changed = false;

    for dep in &nuget {
        let Some(ov) = &dep.registry_override else {
            result.warnings.push(RewriteWarning {
                code: "redirect_nuget_missing_override".into(),
                detail: format!("{} has no nuget-v3 registry override", dep.name),
            });
            continue;
        };
        if ov.kind != "nuget-v3" {
            continue;
        }
        let Some(sha512_sri) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_nuget_missing_sha512".into(),
                detail: format!("{} has no sha512 integrity", dep.name),
            });
            continue;
        };
        let content_hash = sha512_sri
            .strip_prefix("sha512-")
            .unwrap_or(&sha512_sri)
            .to_string();
        let reg = format!("socket-patch-{}", dep.patch_uuid);
        let id_lower = ov
            .identifiers
            .nuget_id_lower
            .clone()
            .unwrap_or_else(|| dep.name.to_lowercase());

        if !config.contains(&format!("key=\"{reg}\"")) {
            config = add_nuget_source(&config, &reg, &ov.index_url, &dep.name);
            config_changed = true;
            result.edits.push(FileEdit {
                path: "nuget.config".into(),
                kind: "redirect_nuget_source".into(),
                action: "rewritten".into(),
                key: Some(reg.clone()),
                original: None,
                new: Some(json!({ "source": ov.index_url, "pattern": dep.name })),
            });
        }

        if let Some(lock_val) = lock.as_mut() {
            if let Some(deps) = lock_val
                .get_mut("dependencies")
                .and_then(Value::as_object_mut)
            {
                for framework in deps.values_mut() {
                    if let Some(fw) = framework.as_object_mut() {
                        for (id, entry) in fw.iter_mut() {
                            if id.to_lowercase() == id_lower {
                                if let Some(obj) = entry.as_object_mut() {
                                    let resolved = ov
                                        .identifiers
                                        .nuget_version_norm
                                        .clone()
                                        .unwrap_or_else(|| dep.version.clone());
                                    // Already redirected (re-run): no edit.
                                    if obj.get("resolved").and_then(Value::as_str)
                                        == Some(resolved.as_str())
                                        && obj.get("contentHash").and_then(Value::as_str)
                                            == Some(content_hash.as_str())
                                    {
                                        continue;
                                    }
                                    let original = json!({
                                        "resolved": obj.get("resolved").cloned().unwrap_or(Value::Null),
                                        "contentHash": obj.get("contentHash").cloned().unwrap_or(Value::Null),
                                    });
                                    obj.insert("resolved".into(), Value::String(resolved.clone()));
                                    obj.insert(
                                        "contentHash".into(),
                                        Value::String(content_hash.clone()),
                                    );
                                    lock_changed = true;
                                    result.edits.push(FileEdit {
                                        path: "packages.lock.json".into(),
                                        kind: "redirect_nuget_lock".into(),
                                        action: "rewritten".into(),
                                        key: Some(id.clone()),
                                        original: Some(original),
                                        new: Some(json!({
                                            "resolved": resolved,
                                            "contentHash": content_hash,
                                        })),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if config_changed {
        result.files.insert("nuget.config".into(), config);
    }
    if lock_changed {
        if let Some(lock_val) = lock {
            result
                .files
                .insert("packages.lock.json".into(), serialize_json(&lock_val));
        }
    }
}

// ── rubygems (Gemfile + Gemfile.lock) ────────────────────────────────────────
fn rewrite_gem(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let gem: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "gem").collect();
    if gem.is_empty() {
        return;
    }
    let mut gemfile = files.get("Gemfile").cloned();
    let mut gemfile_changed = false;
    let mut lock = files.get("Gemfile.lock").cloned();
    let mut lock_changed = false;
    // Static regex — compile once, not per-dependency (clippy: regex-in-loop).
    let checksums_re = Regex::new(r"(?m)^CHECKSUMS$").unwrap();

    for dep in &gem {
        let Some(ov) = &dep.registry_override else {
            result.warnings.push(RewriteWarning {
                code: "redirect_gem_missing_override".into(),
                detail: format!("{} has no rubygems-compact-index override", dep.name),
            });
            continue;
        };
        if ov.kind != "rubygems-compact-index" {
            continue;
        }
        let Some(sha256) = ov
            .identifiers
            .gem_checksum_sha256
            .clone()
            .or_else(|| dep.integrity.sha256.clone())
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_gem_missing_sha256".into(),
                detail: format!("{} has no sha256 checksum", dep.name),
            });
            continue;
        };

        if let Some(gf) = gemfile.as_mut() {
            if !gf.contains(&format!("source \"{}\"", ov.index_url)) {
                let gem_line_re = Regex::new(
                    &(String::from(r#"(?m)^\s*gem ["']"#)
                        + &regex::escape(&dep.name)
                        + r#"["'][^\n]*$"#),
                )
                .unwrap();
                let block = format!(
                    "source \"{}\" do\n  gem \"{}\", \"{}\"\nend",
                    ov.index_url, dep.name, dep.version
                );
                if let Some(m) = gem_line_re.find(gf) {
                    let original = m.as_str().to_string();
                    let new_gf = gem_line_re.replace(gf, block.as_str()).to_string();
                    *gf = new_gf;
                    gemfile_changed = true;
                    result.edits.push(FileEdit {
                        path: "Gemfile".into(),
                        kind: "redirect_gemfile_source_block".into(),
                        action: "rewritten".into(),
                        key: Some(dep.name.clone()),
                        original: Some(Value::String(original)),
                        new: Some(Value::String(block)),
                    });
                } else {
                    let sep = if gf.ends_with('\n') { "" } else { "\n" };
                    *gf = format!("{gf}{sep}{block}\n");
                    gemfile_changed = true;
                    result.edits.push(FileEdit {
                        path: "Gemfile".into(),
                        kind: "redirect_gemfile_source_block".into(),
                        action: "added".into(),
                        key: Some(dep.name.clone()),
                        original: None,
                        new: Some(Value::String(block)),
                    });
                }
            }
        }

        if let Some(lk) = lock.as_mut() {
            let sum_line_re = Regex::new(
                &(String::from(r"(?m)^(  ")
                    + &regex::escape(&dep.name)
                    + r" \("
                    + &regex::escape(&dep.version)
                    + r"\)) sha256=[0-9a-f]+$"),
            )
            .unwrap();
            let new_val = format!("{} ({}) sha256={sha256}", dep.name, dep.version);
            // Already redirected (re-run): the CHECKSUMS line is at the
            // target value; recording an edit would grow the ledger forever.
            if lk.contains(&format!("\n  {new_val}\n")) || lk.ends_with(&format!("\n  {new_val}")) {
                // no-op
            } else if sum_line_re.is_match(lk) {
                *lk = sum_line_re
                    .replace(lk, format!("${{1}} sha256={sha256}").as_str())
                    .to_string();
                lock_changed = true;
                result.edits.push(FileEdit {
                    path: "Gemfile.lock".into(),
                    kind: "redirect_gemfile_lock_checksum".into(),
                    action: "rewritten".into(),
                    key: Some(dep.name.clone()),
                    original: None,
                    new: Some(Value::String(new_val)),
                });
            } else if checksums_re.is_match(lk) {
                *lk = checksums_re
                    .replace(
                        lk,
                        format!(
                            "CHECKSUMS\n  {} ({}) sha256={sha256}",
                            dep.name, dep.version
                        )
                        .as_str(),
                    )
                    .to_string();
                lock_changed = true;
                result.edits.push(FileEdit {
                    path: "Gemfile.lock".into(),
                    kind: "redirect_gemfile_lock_checksum".into(),
                    action: "added".into(),
                    key: Some(dep.name.clone()),
                    original: None,
                    new: Some(Value::String(new_val)),
                });
            } else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_gem_no_checksums_section".into(),
                    detail: format!(
                        "Gemfile.lock has no CHECKSUMS section (bundler <2.6) — cannot pin {}",
                        dep.name
                    ),
                });
            }
        }
    }

    if gemfile_changed {
        if let Some(gf) = gemfile {
            result.files.insert("Gemfile".into(), gf);
        }
    }
    if lock_changed {
        if let Some(lk) = lock {
            result.files.insert("Gemfile.lock".into(), lk);
        }
    }
}

// ── maven (pom.xml repository + gradle manual snippet) ──────────────────────
//
// Minimal per-dependency override: ONLY the patched artifact is pointed at a
// single-artifact Socket maven2 repository. Maven has no lockfile, so the
// strongest client-side verification a stock `mvn` offers is
// `<checksumPolicy>fail</checksumPolicy>` against the `.jar.sha1` sidecar the
// SAME repository serves — the injected `<repository>` turns that on.
// Same-GAV handling is VERIFY-ONLY: the rewriter never edits a dependency's
// `<version>` (maven resolves the pinned version straight from the socket
// repo, checked first; everything else falls through to the project's other
// repositories) — it only warns when the redirect can't take effect. Gradle
// has no equivalent surgical single-line edit, so a present build script gets
// a paste-able `exclusiveContent { … }` snippet warning instead of any edit.

/// Gradle build scripts (Groovy + Kotlin DSL) that trigger the manual snippet.
const GRADLE_FILES: &[&str] = &[
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
];

/// Unique-per-patch maven repository id (valid chars: alnum, `-`, `_`, `.`).
fn maven_repository_id(patch_uuid: &str) -> String {
    format!("socket-patch-{patch_uuid}")
}

fn rewrite_maven_pom(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let maven: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "maven")
        .collect();
    if maven.is_empty() {
        return;
    }
    let mut pom = files.get("pom.xml").cloned();
    let mut pom_changed = false;
    let gradle_build_present = GRADLE_FILES.iter().any(|f| files.contains_key(*f));

    for dep in &maven {
        let ov = dep
            .registry_override
            .as_ref()
            .filter(|ov| ov.kind == "maven2");
        let Some(ov) = ov else {
            result.warnings.push(RewriteWarning {
                code: "redirect_maven_missing_override".into(),
                detail: format!("{} has no maven2 registry override", full_name(dep)),
            });
            continue;
        };
        let group_id = ov
            .identifiers
            .maven_group_id
            .clone()
            .or_else(|| dep.namespace.clone())
            .unwrap_or_default();
        let artifact_id = ov
            .identifiers
            .maven_artifact_id
            .clone()
            .unwrap_or_else(|| dep.name.clone());

        // Gradle: emit a paste-able exclusiveContent snippet (never edit a
        // build script). Independent of the pom edit — a project may ship both.
        if gradle_build_present {
            result.warnings.push(RewriteWarning {
                code: "redirect_gradle_manual_snippet".into(),
                detail: gradle_snippet(&ov.index_url, &group_id, &artifact_id, &dep.version),
            });
        }

        let Some(pom_text) = pom.as_ref() else {
            continue;
        };

        // VERIFY-ONLY same-GAV inspection: never edit the version; only warn
        // when the redirect can't take effect for this dependency.
        match find_maven_dependency_inner(pom_text, &group_id, &artifact_id) {
            None => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_maven_dep_not_found".into(),
                    detail: format!(
                        "no <dependency> for {group_id}:{artifact_id} in pom.xml (adding repository anyway)"
                    ),
                });
            }
            Some(dep_inner) => {
                if let Some(typ) = extract_maven_tag_text(&dep_inner, "type") {
                    if typ.trim() != "jar" {
                        // The single-jar socket repository can only serve a
                        // `.jar`; a war/pom/aar/etc. dependency can't be
                        // redirected — skip without adding a repo.
                        result.warnings.push(RewriteWarning {
                            code: "redirect_maven_unsupported_packaging".into(),
                            detail: format!(
                                "{group_id}:{artifact_id} has <type>{}</type> (only jar can be redirected); skipping",
                                typ.trim()
                            ),
                        });
                        continue;
                    }
                }
                match extract_maven_tag_text(&dep_inner, "version") {
                    None => {
                        result.warnings.push(RewriteWarning {
                            code: "redirect_maven_dep_unpinned".into(),
                            detail: format!(
                                "{group_id}:{artifact_id} has no literal <version> (inherited/managed); the socket repository only serves {}",
                                dep.version
                            ),
                        });
                    }
                    Some(version) if version.contains("${") => {
                        result.warnings.push(RewriteWarning {
                            code: "redirect_maven_dep_unpinned".into(),
                            detail: format!(
                                "{group_id}:{artifact_id} <version> is a property placeholder ({}); the socket repository only serves {}",
                                version.trim(),
                                dep.version
                            ),
                        });
                    }
                    Some(_) => {}
                }
            }
        }

        // Idempotency: the repository id already present ⇒ no-op (no edit). A
        // re-run over already-rewritten output records zero edits.
        let repo_id = maven_repository_id(&dep.patch_uuid);
        if pom_text.contains(&format!("<id>{repo_id}</id>")) {
            continue;
        }
        let rebuilt = insert_maven_repository(pom_text, &repo_id, &ov.index_url);
        pom = Some(rebuilt);
        pom_changed = true;
        result.edits.push(FileEdit {
            path: "pom.xml".into(),
            kind: "redirect_maven_repository".into(),
            action: "added".into(),
            key: Some(repo_id.clone()),
            original: None,
            new: Some(json!({ "id": repo_id, "url": ov.index_url })),
        });
    }

    if pom_changed {
        if let Some(p) = pom {
            result.files.insert("pom.xml".into(), p);
        }
    }
}

/// The `<repository>` block for the socket-patch source: releases enabled with
/// `<checksumPolicy>fail</checksumPolicy>` (the only client-side verification
/// a stock mvn offers against the served `.jar.sha1`); snapshots disabled
/// (patched artifacts are always released versions). Indented for insertion
/// under a `<repositories>` element (2-space step).
fn maven_repository_block(id: &str, url: &str) -> String {
    format!(
        "    <repository>\n      <id>{id}</id>\n      <url>{url}</url>\n      <releases>\n        <enabled>true</enabled>\n        <checksumPolicy>fail</checksumPolicy>\n      </releases>\n      <snapshots>\n        <enabled>false</enabled>\n      </snapshots>\n    </repository>"
    )
}

/// Insert the socket-patch repository block. Prefer an existing
/// `<repositories>` element (single replace, inserted first so it's consulted
/// before the project's other repositories); otherwise author a full
/// `<repositories>` section immediately before the closing `</project>`.
/// `<repositories>` is matched exactly so it never collides with
/// `<pluginRepositories>`.
fn insert_maven_repository(pom: &str, id: &str, url: &str) -> String {
    let block = maven_repository_block(id, url);
    if pom.contains("<repositories>") {
        return pom.replacen("<repositories>", &format!("<repositories>\n{block}"), 1);
    }
    let section = format!("  <repositories>\n{block}\n  </repositories>");
    pom.replacen("</project>", &format!("{section}\n</project>"), 1)
}

/// Return the inner XML of the first `<dependency>` whose `<groupId>` +
/// `<artifactId>` match, or None when none matches. Scans every `<dependency>`
/// block (including any under `<dependencyManagement>`), which is enough for
/// the verify-only version/type inspection.
fn find_maven_dependency_inner(pom: &str, group_id: &str, artifact_id: &str) -> Option<String> {
    let dep_re = Regex::new(r"(?s)<dependency\b[^>]*>(.*?)</dependency>").unwrap();
    for caps in dep_re.captures_iter(pom) {
        let inner = caps.get(1).unwrap().as_str();
        let g = extract_maven_tag_text(inner, "groupId");
        let a = extract_maven_tag_text(inner, "artifactId");
        if let (Some(g), Some(a)) = (g, a) {
            if g.trim() == group_id && a.trim() == artifact_id {
                return Some(inner.to_string());
            }
        }
    }
    None
}

/// Text content of the first `<tag>…</tag>` in `xml` (untrimmed — callers
/// trim), or None.
fn extract_maven_tag_text(xml: &str, tag: &str) -> Option<String> {
    Regex::new(&format!("(?s)<{tag}>(.*?)</{tag}>"))
        .unwrap()
        .captures(xml)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

/// A paste-able Gradle `exclusiveContent` block that pins ONLY the patched
/// artifact to the socket maven2 repository (Groovy DSL — the common case; the
/// Kotlin DSL differs only in quoting). Emitted as a warning detail; the
/// rewriter never edits a build script.
fn gradle_snippet(index_url: &str, group_id: &str, artifact_id: &str, version: &str) -> String {
    format!(
        "Gradle build detected — add this per-dependency repository manually (no automatic edit):\nrepositories {{\n    exclusiveContent {{\n        forRepository {{\n            maven {{ url \"{index_url}\" }}\n        }}\n        filter {{\n            includeVersion(\"{group_id}\", \"{artifact_id}\", \"{version}\")\n        }}\n    }}\n}}"
    )
}

// ── golang (documented limitation) ──────────────────────────────────────────
// Hosted redirect for Go is a deliberate no-go: every workable shape needs
// machine-local GOPROXY/GOPRIVATE configuration that can't be committed to the
// repo as a per-dependency edit. The full analysis (sumdb hard-fail, module-
// path identity vs the build-once converter, GOPROXY leaking licensed bytes to
// the public mirror) lives in `docs/design/golang-hosted-no-go.md`.
fn rewrite_golang(overrides: &[DepOverride], result: &mut RewriteResult) {
    for dep in overrides.iter().filter(|o| o.ecosystem == "golang") {
        result.warnings.push(RewriteWarning {
            code: "redirect_golang_unsupported".into(),
            detail: format!(
                "{}@{}: hosted redirect for Go is not possible without machine-local GOPROXY/GOPRIVATE configuration; run `socket-patch vendor` (committable, offline-verified) instead",
                full_name(dep),
                dep.version
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm_override(name: &str, version: &str, url: &str, sha512: &str) -> DepOverride {
        DepOverride {
            ecosystem: "npm".into(),
            name: name.into(),
            namespace: None,
            version: version.into(),
            token: String::new(),
            patch_uuid: "11111111-1111-4111-8111-111111111111".into(),
            artifact_url: url.into(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha512: Some(sha512.into()),
                ..Default::default()
            },
        }
    }

    fn pypi_override(name: &str, version: &str, url: &str, sha256: &str) -> DepOverride {
        DepOverride {
            ecosystem: "pypi".into(),
            name: name.into(),
            namespace: None,
            version: version.into(),
            token: String::new(),
            patch_uuid: "11111111-1111-4111-8111-111111111111".into(),
            artifact_url: url.into(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha256: Some(sha256.into()),
                ..Default::default()
            },
        }
    }

    /// Re-running a rewriter over its own output must be a no-op: zero new
    /// edits, byte-identical files. Recorded edits whose `original` is the
    /// already-redirected value would grow the committed ledger on every
    /// `scan --redirect` run and poison a future revert.
    #[test]
    fn second_pass_over_rewritten_output_is_a_noop() {
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "0.0.0" },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#
            .to_string(),
        );
        files.insert(
            "requirements.txt".to_string(),
            "requests==2.28.1 ; python_version >= \"3.7\"\n".to_string(),
        );
        let overrides = vec![
            npm_override(
                "left-pad",
                "1.3.0",
                "http://patch.test/left-pad-1.3.0.tgz",
                "sha512-PATCHED==",
            ),
            pypi_override(
                "requests",
                "2.28.1",
                "http://patch.test/requests-2.28.1-py3-none-any.whl",
                &"c".repeat(64),
            ),
        ];

        let first = rewrite_registry_redirect(&files, &overrides);
        assert!(!first.edits.is_empty(), "first pass must record edits");

        // Overlay the rewritten outputs and run again.
        let mut second_input = files.clone();
        for (name, content) in &first.files {
            second_input.insert(name.clone(), content.clone());
        }
        let second = rewrite_registry_redirect(&second_input, &overrides);
        assert!(
            second.edits.is_empty(),
            "second pass must record NO edits (ledger growth): {:?}",
            second.edits
        );
        assert!(
            second.files.is_empty(),
            "second pass must change no files: {:?}",
            second.files.keys()
        );
    }

    /// The requirements marker is taken from the requirement portion only —
    /// a previously appended `--hash=…` must never be swallowed into the
    /// marker (that duplicated the hash on every re-run).
    #[test]
    fn requirements_marker_line_is_rerun_stable() {
        let mut files = BTreeMap::new();
        files.insert(
            "requirements.txt".to_string(),
            "requests==2.28.1 ; python_version >= \"3.7\"\n".to_string(),
        );
        let overrides = vec![pypi_override(
            "requests",
            "2.28.1",
            "http://patch.test/requests-2.28.1-py3-none-any.whl",
            &"c".repeat(64),
        )];
        let first = rewrite_registry_redirect(&files, &overrides);
        let out = first.files.get("requirements.txt").expect("rewritten");
        assert_eq!(
            out.matches("--hash=sha256:").count(),
            1,
            "exactly one hash after the first pass: {out}"
        );
        assert!(
            out.contains("; python_version >= \"3.7\" --hash="),
            "marker preserved ahead of the hash: {out}"
        );

        let mut again = files.clone();
        again.insert("requirements.txt".to_string(), out.clone());
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "re-run over the marker line must be a no-op; got files={:?} edits={:?}",
            second.files,
            second.edits
        );
    }

    fn maven_override() -> DepOverride {
        DepOverride {
            ecosystem: "maven".into(),
            name: "slf4j-api".into(),
            namespace: Some("org.slf4j".into()),
            version: "1.7.36".into(),
            token: "tok".into(),
            patch_uuid: "uuid".into(),
            artifact_url:
                "https://patch.socket.dev/patch/maven/org.slf4j/slf4j-api/1.7.36/tok/uuid/slf4j-api-1.7.36.jar"
                    .into(),
            berry_zip_url: None,
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: "https://patch.socket.dev/patch-registry/maven/tok/uuid/maven2".into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: "org.slf4j/slf4j-api".into(),
                    version: "1.7.36".into(),
                    maven_group_id: Some("org.slf4j".into()),
                    maven_artifact_id: Some("slf4j-api".into()),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha1: Some("a".repeat(40)),
                md5: Some("b".repeat(32)),
                ..Default::default()
            },
        }
    }

    fn pom_with_dep(version_xml: &str, type_xml: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>dev.socket.test</groupId>\n  <artifactId>consumer</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n      <groupId>org.slf4j</groupId>\n      <artifactId>slf4j-api</artifactId>{version_xml}{type_xml}\n    </dependency>\n  </dependencies>\n</project>\n"
        )
    }

    /// A literal-pinned dep gets one `added` edit, and re-running over the
    /// rewritten pom is a no-op (the `<id>` idempotency guard) — an edit whose
    /// `original` is the already-redirected value would grow the committed
    /// ledger on every `scan --redirect` run.
    #[test]
    fn maven_pom_rewrite_and_rerun_noop() {
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        let overrides = vec![maven_override()];
        let first = rewrite_registry_redirect(&files, &overrides);
        let out = first.files.get("pom.xml").expect("pom rewritten");
        assert!(out.contains("<id>socket-patch-uuid</id>"), "{out}");
        assert!(
            out.contains("<checksumPolicy>fail</checksumPolicy>"),
            "{out}"
        );
        assert!(first.warnings.is_empty(), "{:?}", first.warnings);
        assert_eq!(first.edits.len(), 1);
        assert_eq!(first.edits[0].kind, "redirect_maven_repository");
        assert_eq!(first.edits[0].action, "added");

        let mut again = files.clone();
        again.insert("pom.xml".to_string(), out.clone());
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "second pass must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    /// Verify-only warnings: a `${property}` version still adds the repo but
    /// warns unpinned; a missing dependency warns not-found; a non-jar
    /// `<type>` skips the repo entirely (the single-jar repo can't serve it);
    /// a present Gradle build script yields the manual snippet, no edits.
    #[test]
    fn maven_pom_warning_branches() {
        let overrides = vec![maven_override()];

        // Property placeholder → repo added + unpinned warning.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>${slf4j.version}</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.contains_key("pom.xml"), "repo still added");
        assert_eq!(r.warnings.len(), 1);
        assert_eq!(r.warnings[0].code, "redirect_maven_dep_unpinned");

        // No matching dependency → repo added anyway + not-found warning.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>other</artifactId>\n      <version>1.0.0</version>\n    </dependency>\n  </dependencies>\n</project>\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.contains_key("pom.xml"));
        assert_eq!(r.warnings[0].code, "redirect_maven_dep_not_found");

        // Non-jar <type> → NO repo, unsupported-packaging warning.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep(
                "\n      <version>1.7.36</version>",
                "\n      <type>pom</type>",
            ),
        );
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(r.warnings.len(), 1);
        assert_eq!(r.warnings[0].code, "redirect_maven_unsupported_packaging");

        // Gradle build script present → paste-able snippet, no file edits.
        let mut files = BTreeMap::new();
        files.insert(
            "build.gradle".to_string(),
            "plugins { id 'java' }\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(r.warnings.len(), 1);
        assert_eq!(r.warnings[0].code, "redirect_gradle_manual_snippet");
        assert!(
            r.warnings[0]
                .detail
                .contains("includeVersion(\"org.slf4j\", \"slf4j-api\", \"1.7.36\")"),
            "snippet pins the exact GAV: {}",
            r.warnings[0].detail
        );
    }

    fn nuget_override() -> DepOverride {
        DepOverride {
            ecosystem: "nuget".into(),
            name: "Newtonsoft.Json".into(),
            namespace: None,
            version: "13.0.3".into(),
            token: "tok".into(),
            patch_uuid: "uuid".into(),
            artifact_url: "https://patch.test/newtonsoft.json.13.0.3.nupkg".into(),
            berry_zip_url: None,
            registry_override: Some(RegistryOverride {
                kind: "nuget-v3".into(),
                index_url: "https://patch.test/nuget/index.json".into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: "Newtonsoft.Json".into(),
                    version: "13.0.3".into(),
                    nuget_id_lower: Some("newtonsoft.json".into()),
                    nuget_version_norm: Some("13.0.3".into()),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha512: Some("sha512-PATCHED==".into()),
                ..Default::default()
            },
        }
    }

    /// Creating a `<packageSourceMapping>` from scratch: once ANY mapping
    /// exists NuGet requires EVERY package to match some source's pattern, so
    /// the rewriter must fan a `pattern="*"` mapping out to every pre-existing
    /// source or all other packages fail restore with NU1100.
    #[test]
    fn nuget_no_preexisting_mapping_gets_catch_all() {
        let mut files = BTreeMap::new();
        files.insert(
            "nuget.config".to_string(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n    <add key=\"corp-feed\" value=\"https://nuget.corp.example/v3/index.json\" />\n  </packageSources>\n</configuration>\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        let out = r.files.get("nuget.config").expect("config rewritten");
        assert!(
            out.contains(
                "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
            ),
            "nuget.org catch-all present: {out}"
        );
        assert!(
            out.contains(
                "    <packageSource key=\"corp-feed\">\n      <package pattern=\"*\" />\n    </packageSource>"
            ),
            "corp-feed catch-all present: {out}"
        );
        // The Socket mapping stays first (most specific pattern wins in NuGet,
        // but ordering mirrors the TS rewriter for byte-consistency).
        let socket_idx = out.find("key=\"socket-patch-uuid\">").unwrap();
        let star_idx = out.find("pattern=\"*\"").unwrap();
        assert!(socket_idx < star_idx, "socket mapping precedes catch-alls");
    }

    /// A config with NO pre-existing `<packageSources>` entries: a from-scratch
    /// mapping would be socket-only, so every non-patched package would fail
    /// restore with NU1100. The rewriter must seed the implicit default
    /// nuget.org source and fan `*` out to it alongside the socket mapping.
    #[test]
    fn nuget_empty_sources_seeds_org_catch_all() {
        let mut files = BTreeMap::new();
        // An empty <packageSources> and no mapping (a realistic minimal config).
        files.insert(
            "nuget.config".to_string(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n  </packageSources>\n</configuration>\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        let out = r.files.get("nuget.config").expect("config rewritten");
        // nuget.org seeded as a source...
        assert!(
            out.contains("<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />"),
            "nuget.org source seeded: {out}"
        );
        // ...and mapped `*` so non-patched packages keep resolving.
        assert!(
            out.contains(
                "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
            ),
            "nuget.org catch-all present: {out}"
        );
        // The socket mapping still routes the patched id.
        assert!(
            out.contains(
                "key=\"socket-patch-uuid\">\n      <package pattern=\"Newtonsoft.Json\" />"
            ),
            "socket mapping present: {out}"
        );
        // Exactly one catch-all (we didn't fan out to a phantom source).
        assert_eq!(
            out.matches("<package pattern=\"*\" />").count(),
            1,
            "single seeded catch-all: {out}"
        );
    }

    /// A SELF-CLOSING `<packageSources />` must be expanded in place (not left
    /// dangling beside a freshly-created duplicate element). The output is
    /// byte-identical to the open-but-empty `<packageSources></packageSources>`
    /// case — the tag form is cosmetic once expanded.
    #[test]
    fn nuget_self_closing_sources_expanded_in_place() {
        let mk = |sources_xml: &str| {
            let mut files = BTreeMap::new();
            files.insert(
                "nuget.config".to_string(),
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  {sources_xml}\n</configuration>\n"
                ),
            );
            let r = rewrite_registry_redirect(&files, &[nuget_override()]);
            r.files
                .get("nuget.config")
                .expect("config rewritten")
                .clone()
        };
        // Whitespace variants of the self-closing tag both expand.
        let out_sc = mk("<packageSources />");
        let out_sc_tight = mk("<packageSources/>");
        let out_open = mk("<packageSources>\n  </packageSources>");

        assert_eq!(
            out_sc, out_open,
            "self-closing (with space) expands to the same bytes as the open-empty form"
        );
        assert_eq!(
            out_sc_tight, out_open,
            "self-closing (no space) expands to the same bytes as the open-empty form"
        );
        // Exactly ONE opening <packageSources> element — no dangling duplicate.
        assert_eq!(
            out_sc.matches("<packageSources>").count(),
            1,
            "single packageSources element (no duplicate): {out_sc}"
        );
        // The self-closing tag is gone.
        assert!(!out_sc.contains("<packageSources />"));
        assert!(!out_sc.contains("<packageSources/>"));
        // nuget.org still seeded + mapped.
        assert!(out_sc.contains("<add key=\"nuget.org\""));
        assert!(out_sc.contains(
            "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
        ));
    }

    /// A pre-existing `<packageSourceMapping>` already covers the other
    /// sources — the rewriter must append ONLY the Socket mapping and add NO
    /// catch-all (injecting `*` entries would loosen the project's own
    /// deliberate routing).
    #[test]
    fn nuget_preexisting_mapping_gets_no_catch_all() {
        let mut files = BTreeMap::new();
        files.insert(
            "nuget.config".to_string(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"nuget.org\">\n      <package pattern=\"Contoso.*\" />\n    </packageSource>\n  </packageSourceMapping>\n</configuration>\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        let out = r.files.get("nuget.config").expect("config rewritten");
        assert!(
            out.contains(
                "key=\"socket-patch-uuid\">\n      <package pattern=\"Newtonsoft.Json\" />"
            ),
            "socket mapping appended: {out}"
        );
        assert!(
            !out.contains("pattern=\"*\""),
            "no catch-all injected when a mapping pre-exists: {out}"
        );
        assert_eq!(
            out.matches("<packageSourceMapping>").count(),
            1,
            "existing mapping element reused: {out}"
        );
    }

    /// pip-compile --generate-hashes continuation lines are refused (warning)
    /// rather than corrupted: rewriting only the first physical line would
    /// orphan the old `--hash` lines, and with a marker pip hard-fails on the
    /// mid-line backslash (InvalidMarker).
    #[test]
    fn requirements_continuation_lines_are_refused() {
        let mut files = BTreeMap::new();
        files.insert(
            "requirements.txt".to_string(),
            "requests==2.28.1 ; python_version >= \"3.7\" \\\n    --hash=sha256:OLDOLDOLD\n"
                .to_string(),
        );
        let overrides = vec![pypi_override(
            "requests",
            "2.28.1",
            "http://patch.test/requests-2.28.1-py3-none-any.whl",
            &"c".repeat(64),
        )];
        let result = rewrite_registry_redirect(&files, &overrides);
        assert!(
            result.files.is_empty() && result.edits.is_empty(),
            "continuation input must not be rewritten: {:?}",
            result.files
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.code == "redirect_requirements_continuation"),
            "must surface the continuation refusal: {:?}",
            result.warnings
        );
    }
}
