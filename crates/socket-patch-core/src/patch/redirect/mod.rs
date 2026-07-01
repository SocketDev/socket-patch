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
fn rewrite_pnpm_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("pnpm-lock.yaml") {
        return;
    }
    let mut content = files["pnpm-lock.yaml"].clone();
    let mut changed = false;
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
        let Some(caps) = re.captures(&content) else {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_entry_not_found".into(),
                detail: format!("no inline resolution for {fname}@{}", dep.version),
            });
            continue;
        };
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
        content = content.replacen(&whole, &format!("{prefix}{rebuilt}"), 1);
        changed = true;
        result.edits.push(FileEdit {
            path: "pnpm-lock.yaml".into(),
            kind: "redirect_pnpm_resolution".into(),
            action: "rewritten".into(),
            key: Some(format!("{fname}@{}", dep.version)),
            original: Some(Value::String(original)),
            new: Some(Value::String(rebuilt)),
        });
    }
    if changed {
        result.files.insert("pnpm-lock.yaml".into(), content);
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

fn add_nuget_source(config: &str, reg: &str, index_url: &str, pkg_id: &str) -> String {
    let mut out = config.to_string();
    let source_line = format!("    <add key=\"{reg}\" value=\"{index_url}\" />");
    if out.contains("<packageSources>") {
        out = out.replacen(
            "<packageSources>",
            &format!("<packageSources>\n{source_line}"),
            1,
        );
    } else {
        out = out.replacen(
            "<configuration>",
            &format!("<configuration>\n  <packageSources>\n{source_line}\n  </packageSources>"),
            1,
        );
    }
    let map_block = format!(
        "  <packageSourceMapping>\n    <packageSource key=\"{reg}\">\n      <package pattern=\"{pkg_id}\" />\n    </packageSource>\n  </packageSourceMapping>"
    );
    if out.contains("<packageSourceMapping>") {
        out = out.replacen(
            "<packageSourceMapping>",
            &format!(
                "<packageSourceMapping>\n    <packageSource key=\"{reg}\">\n      <package pattern=\"{pkg_id}\" />\n    </packageSource>"
            ),
            1,
        );
    } else {
        out = out.replacen(
            "</configuration>",
            &format!("{map_block}\n</configuration>"),
            1,
        );
    }
    out
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

// ── golang (documented limitation) ──────────────────────────────────────────
fn rewrite_golang(overrides: &[DepOverride], result: &mut RewriteResult) {
    for dep in overrides.iter().filter(|o| o.ecosystem == "golang") {
        result.warnings.push(RewriteWarning {
            code: "redirect_golang_unsupported".into(),
            detail: format!(
                "{}@{}: remote per-dependency redirect is not expressible in go.mod without a fall-through GOPROXY; use local vendor mode for golang",
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
