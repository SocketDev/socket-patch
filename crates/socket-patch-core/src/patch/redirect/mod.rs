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

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::vendor::yarn_berry_lock::yarnrc_compression_level;

pub mod golang_local;
mod state;
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
    /// Maven hosted-mode Socket-suffixed version
    /// (`<base>-socket.<first-8-hex-of-patch-uuid>`). Present ONLY when the
    /// upstream pom was captured AND could be safely rewritten to advertise it;
    /// when present the rewriter pins THIS version (never the bare upstream
    /// `version`) so the patched jar resolves solely off the Socket repo —
    /// fail-closed. Omitted ⇒ legacy same-GAV serving. Set together with
    /// `maven_pom_sha256`.
    pub maven_suffixed_version: Option<String>,
    /// sha256 hex of the exact `.pom` bytes the serve route returns under
    /// `maven_suffixed_version`, pinned as a Maven trusted checksum. Only
    /// meaningful alongside `maven_suffixed_version`.
    pub maven_pom_sha256: Option<String>,
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
    rewrite_yarn_berry(files, overrides, &mut result);
    rewrite_bun_lock(files, overrides, &mut result);
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
        // Another npm-family lock (pnpm — root or nested Rush —, yarn, bun)
        // owns the redirect for these deps and its rewriter emits its own
        // per-dep diagnostics; warning "no package-lock.json" on every
        // successful pnpm/yarn/bun/Rush run is pure noise that trains users
        // to ignore the warnings channel. Only warn when NO npm-family
        // lockfile exists at all.
        let sibling_lock_present = files.keys().any(|k| {
            k == "yarn.lock"
                || k == "bun.lock"
                || k == "bun.lockb"
                || k == "pnpm-lock.yaml"
                || k.ends_with("/pnpm-lock.yaml")
        });
        if !sibling_lock_present {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_no_lockfile".into(),
                detail: "no package-lock.json / npm-shrinkwrap.json present".into(),
            });
        }
        return;
    };
    let Ok(mut lock) = serde_json::from_str::<Value>(&files[lockfile]) else {
        // A corrupt lockfile is strictly worse than a missing one (which
        // warns above) — never skip the whole npm redirect silently.
        result.warnings.push(RewriteWarning {
            code: "redirect_npm_lock_unparseable".into(),
            detail: format!("{lockfile} is not valid JSON; npm redirect skipped"),
        });
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
        let target = canonicalize_pypi_name(&dep.name);
        for raw in lines.iter_mut() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            let Some(caps) = name_re.captures(line) else {
                continue;
            };
            if canonicalize_pypi_name(&caps[1]) != target {
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
    // Cargo reads the LEGACY extensionless `.cargo/config` in preference to
    // `config.toml` when both exist (it warns about the duplicate), so a
    // managed `[registries.…]` block written to `config.toml` there is
    // silently inert and the `registry = "socket-patch-…"` this rewriter puts
    // in Cargo.toml then names an undefined registry. Same preference
    // `vendor::cargo_config::config_path` applies on the vendor path.
    let cargo_config_key = if files.contains_key(".cargo/config") {
        ".cargo/config"
    } else {
        ".cargo/config.toml"
    };
    let mut cargo_config = files.get(cargo_config_key).cloned().unwrap_or_default();
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
        let reg = format!("socket-patch-{}", dep.patch_uuid);
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
                path: cargo_config_key.into(),
                kind: "redirect_cargo_registry".into(),
                action: "added".into(),
                key: Some(reg.clone()),
                original: None,
                new: Some(Value::String(block)),
            });
        }

        // 2. Cargo.toml dep → add `registry = "<reg>"`.
        if let Some(toml) = cargo_toml.as_mut() {
            match add_cargo_toml_registry(toml, &dep.name, &reg) {
                CargoTomlRewrite::Rewritten(edit) => {
                    result.edits.push(*edit);
                    toml_changed = true;
                }
                // Re-run over an already-redirected Cargo.toml: not missing.
                CargoTomlRewrite::AlreadyRedirected => {}
                CargoTomlRewrite::NotFound => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_cargo_toml_dep_not_found".into(),
                        detail: format!("no [dependencies] entry for {} in Cargo.toml", dep.name),
                    });
                }
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
        result.files.insert(cargo_config_key.into(), cargo_config);
    }
}

/// Outcome of the Cargo.toml dependency rewrite — a re-run over an entry that
/// already carries OUR `registry = "socket-patch-…"` is "already redirected"
/// (silent), not "dependency not found" (caller warns).
enum CargoTomlRewrite {
    Rewritten(Box<FileEdit>),
    AlreadyRedirected,
    NotFound,
}

fn add_cargo_toml_registry(content: &mut String, crate_name: &str, reg: &str) -> CargoTomlRewrite {
    let c = regex::escape(crate_name);
    // Inline table: `crate = { version = "…", … }`.
    let table_re = Regex::new(&format!(r"(?m)^({c}\s*=\s*\{{)([^}}\n]*)(\}})")).unwrap();
    if let Some(m) = table_re.captures(content) {
        let inner = m.get(2).unwrap().as_str();
        if Regex::new(&format!(r#"\bregistry\s*=\s*"{}""#, regex::escape(reg)))
            .unwrap()
            .is_match(inner)
        {
            return CargoTomlRewrite::AlreadyRedirected;
        }
        if Regex::new(r"\bregistry\s*=").unwrap().is_match(inner) {
            // Pinned to some OTHER registry — leave it alone; the caller's
            // warning surfaces that the redirect did not land.
            return CargoTomlRewrite::NotFound;
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
        return CargoTomlRewrite::Rewritten(Box::new(FileEdit {
            path: "Cargo.toml".into(),
            kind: "redirect_cargo_toml_dep".into(),
            action: "rewritten".into(),
            key: Some(crate_name.into()),
            original: Some(Value::String(whole)),
            new: Some(Value::String(rebuilt)),
        }));
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
        return CargoTomlRewrite::Rewritten(Box::new(FileEdit {
            path: "Cargo.toml".into(),
            kind: "redirect_cargo_toml_dep".into(),
            action: "rewritten".into(),
            key: Some(crate_name.into()),
            original: Some(Value::String(whole)),
            new: Some(Value::String(rebuilt)),
        }));
    }
    CargoTomlRewrite::NotFound
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
    // A pnpm lock lives at the project root or at any nested path (e.g. Rush
    // repos keep them under `common/config/rush/`); every such files-map key
    // is rewritten under the same grammar. Deterministic order: BTreeMap
    // iterates keys sorted, so goldens are stable across every lock in the set.
    let lock_keys: Vec<&String> = files
        .keys()
        .filter(|k| k.as_str() == "pnpm-lock.yaml" || k.ends_with("/pnpm-lock.yaml"))
        .collect();
    if npm.is_empty() || lock_keys.is_empty() {
        return;
    }
    // Work on an editable copy of each lock so a single dep can be rewritten
    // in whichever locks contain it. A CRLF lock can never match the rewrite
    // grammar (its pattern anchors on `):\n`, but every CRLF line puts a `\r`
    // byte before the `\n`), so the miss used to surface per-dep as a
    // misleading `redirect_pnpm_entry_not_found`. Name the real cause instead
    // and skip the lock (fail-closed, as before).
    let mut contents: Vec<(&String, String, bool)> = Vec::new();
    for k in &lock_keys {
        let content = files[*k].clone();
        if content.contains("\r\n") {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_crlf_unsupported".into(),
                detail: format!(
                    "{k} has CRLF (Windows) line endings; the redirect's \
                     byte-surgical rewrite only supports LF — normalize the \
                     file to LF line endings and re-run"
                ),
            });
            continue;
        }
        contents.push((*k, content, false));
    }
    if contents.is_empty() {
        return;
    }
    for dep in &npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        // `(^ {2}(?:'<key>'|/?<key>):\n(?: {4,}.*\n)*? {4,}resolution: )\{([^}\n]*)\}`
        // where `<key>` is `<fn>@<ver>`. lockfileVersion 9 single-quotes keys
        // that begin with `@` (`'@scope/name@1.0.0':` — YAML forbids a plain
        // scalar starting with `@`); v6 keys start with `/` and are unquoted.
        let key = regex::escape(&fname) + "@" + &regex::escape(&dep.version);
        let pat = String::from(r"(?m)(^ {2}(?:'")
            + &key
            + r"'|/?"
            + &key
            + r"):\n(?: {4,}.*\n)*? {4,}resolution: )\{([^}\n]*)\}";
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

// ── yarn.lock (berry / v2+) ──────────────────────────────────────────────────
// Berry derives its fetch URL from the descriptor's `npm:` resolution and
// verifies the CONVERTED CACHE ZIP against the lock's `checksum:` (a
// `10c0/<sha512-hex>` over the zip, not the tarball). To redirect ONE dep we
// rewrite only the lock entry: `resolution:` gains yarn's own
// `::__archiveUrl=<encodeURIComponent(url)>` binding, and `checksum:` becomes
// our precomputed `integrity.yarnBerry10c0`. The descriptor KEY + package.json
// are untouched (the `name@npm:^range` descriptor still satisfies, so
// `--immutable` passes). Byte-for-byte twin of the TS `rewriteYarnBerry`.

/// Only cacheKey `10c0` (yarn 4, compressionLevel 0 default) has a checksum we
/// can reproduce offline; matches the vendored backend's `SUPPORTED_CACHE_KEY`.
const YARN_BERRY_SUPPORTED_CACHE_KEY: &str = "10c0";

/// The `cacheKey:` value from the `__metadata` block (berry writes it unquoted:
/// `  cacheKey: 10c0`), mirroring the vendored backend's `berry_field`.
fn berry_cache_key(content: &str) -> Option<String> {
    let meta = content.split("\n\n").find(|b| {
        b.lines()
            .next()
            .is_some_and(|l| l.trim_end() == "__metadata:")
    })?;
    for line in meta.lines().skip(1) {
        if let Some(rest) = line.strip_prefix("  cacheKey:") {
            return Some(rest.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Split `name@npm:...` at the `@` past a leading `@scope/` marker.
fn split_berry_descriptor(pattern: &str) -> Option<(&str, &str)> {
    let from = usize::from(pattern.starts_with('@'));
    let at = pattern[from..].find('@')? + from;
    let (name, range) = (&pattern[..at], &pattern[at + 1..]);
    if name.is_empty() || range.is_empty() {
        return None;
    }
    Some((name, range))
}

/// Split a berry lock key into its comma-joined descriptor patterns. yarn
/// wraps a multi-descriptor key in ONE outer quote pair (`"a@npm:^1,
/// a@npm:^2"`), so strip a single wrapping pair first, THEN split on `, ` —
/// that surfaces every descriptor (letting a genuinely mixed-name key be
/// detected as ambiguous) while a single quoted descriptor stays intact.
/// Twin of the TS `splitKeyPatterns`.
fn split_berry_key_patterns(key: &str) -> Vec<String> {
    let trimmed = key.trim();
    let inner = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    inner
        .split(", ")
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

fn rewrite_yarn_berry(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("yarn.lock") {
        return;
    }
    let content = &files["yarn.lock"];
    // The classic rewriter handles a v1 lock; berry stays out of its way.
    if !Regex::new(r"(?m)^__metadata:").unwrap().is_match(content) {
        return;
    }

    // Whole-file gates. A CRLF lock collapses the `\n\n` block grammar (a
    // `\r\n\r\n` file contains no `\n\n`), so `berry_cache_key` used to come
    // back None and the refusal below misdiagnosed a perfectly good
    // `cacheKey: 10c0` lock as "cacheKey is `(missing)`" — sending Windows
    // users chasing yarn cache config instead of line endings. Same
    // fail-closed outcome, honest diagnosis.
    if content.contains("\r\n") {
        result.warnings.push(RewriteWarning {
            code: "redirect_yarn_berry_crlf_unsupported".into(),
            detail: "yarn.lock has CRLF (Windows) line endings; the redirect's \
                     byte-surgical rewrite only supports LF — normalize the \
                     file to LF line endings and re-run"
                .into(),
        });
        return;
    }
    // Refuse any lock whose cache checksum we can't reproduce
    // offline. A guessed `checksum:` bricks installs (YN0018).
    let key = berry_cache_key(content);
    if key.as_deref() != Some(YARN_BERRY_SUPPORTED_CACHE_KEY) {
        result.warnings.push(RewriteWarning {
            code: "redirect_yarn_berry_cache_unsupported".into(),
            detail: format!(
                "yarn.lock cacheKey is `{}`; only `{YARN_BERRY_SUPPORTED_CACHE_KEY}` \
                 (yarn 4, compressionLevel 0 default) has an offline-reproducible cache checksum",
                key.as_deref().unwrap_or("(missing)")
            ),
        });
        return;
    }
    if let Some(rc) = files.get(".yarnrc.yml") {
        if let Some(level) = yarnrc_compression_level(rc) {
            if level != "0" {
                result.warnings.push(RewriteWarning {
                    code: "redirect_yarn_berry_cache_unsupported".into(),
                    detail: format!(
                        ".yarnrc.yml sets `compressionLevel: {level}`, which changes berry's \
                         cache checksums; only compressionLevel 0 (the yarn 4 default) is supported"
                    ),
                });
                return;
            }
        }
    }

    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolution_re = Regex::new(r#"\n {2}resolution: "[^"]*""#).unwrap();
    let checksum_re = Regex::new(r"\n {2}checksum: [^\n]*").unwrap();
    let mut changed = false;
    for dep in &npm {
        let fname = full_name(dep);
        let Some(checksum) = dep.integrity.yarn_berry10c0.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_berry_missing_checksum".into(),
                detail: format!(
                    "{fname}@{} has no yarnBerry10c0 cache checksum",
                    dep.version
                ),
            });
            continue;
        };
        // Berry versions are UNQUOTED (`  version: 1.3.0`, spike B3 ground truth).
        let version_re =
            Regex::new(&(String::from(r"\n {2}version: ") + &regex::escape(&dep.version) + "\n"))
                .unwrap();
        let mut matched_any = false;
        for block in blocks.iter_mut() {
            // A block's key is its first line up to a trailing colon; skip
            // header comment blocks and the leading `__metadata` block.
            let Some(first_line) = block.lines().next() else {
                continue;
            };
            if first_line.starts_with([' ', '\t', '#']) || !first_line.ends_with(':') {
                continue;
            }
            let raw_key = &first_line[..first_line.len() - 1];
            if raw_key == "__metadata" {
                continue;
            }
            let patterns = split_berry_key_patterns(raw_key);
            let parsed: Vec<Option<(&str, &str)>> =
                patterns.iter().map(|p| split_berry_descriptor(p)).collect();
            // Every comma-joined pattern must parse as a descriptor.
            if parsed.iter().any(Option::is_none) {
                continue;
            }
            let names: std::collections::BTreeSet<&str> =
                parsed.iter().map(|p| p.unwrap().0).collect();
            if !names.contains(fname.as_str()) {
                continue;
            }
            if names.len() > 1 {
                result.warnings.push(RewriteWarning {
                    code: "redirect_yarn_berry_ambiguous_entry".into(),
                    detail: format!(
                        "lock entry `{raw_key}` mixes {fname} with other descriptors; skipping"
                    ),
                });
                continue;
            }
            if !version_re.is_match(block) {
                continue;
            }
            // Descriptor ranges carry a protocol; only an `npm:` range names
            // a registry tarball this rewriter can own. A `patch:` range
            // (yarn's OWN builtin compat patches — the 2026-07 strapi
            // incident family), `workspace:`, `portal:`, or `link:` block
            // must survive byte-identically: splicing an npm resolution
            // under such a key corrupts the key/resolution protocol pairing.
            // Mirrors the vendor backend's fail-closed gate
            // (vendor/yarn_berry_lock.rs).
            if !parsed.iter().all(|p| p.unwrap().1.starts_with("npm:")) {
                result.warnings.push(RewriteWarning {
                    code: "redirect_yarn_berry_unsupported_protocol".into(),
                    detail: format!(
                        "lock entry `{raw_key}` resolves {fname}@{} through a protocol \
                         the hosted redirect cannot own (workspace:/patch:/portal:/link:); \
                         leaving it byte-identical",
                        dep.version
                    ),
                });
                continue;
            }
            // Rewrite the resolution wholesale from name+version — handles a
            // pre-existing `::__archiveUrl=` (custom-registry lock) for free.
            let resolution = format!(
                "{fname}@npm:{}::__archiveUrl={}",
                dep.version,
                crate::utils::uri::encode_uri_component(&dep.artifact_url)
            );
            let mut rewritten = resolution_re
                .replace(block, format!("\n  resolution: \"{resolution}\"").as_str())
                .to_string();
            if checksum_re.is_match(&rewritten) {
                rewritten = checksum_re
                    .replace(&rewritten, format!("\n  checksum: {checksum}").as_str())
                    .to_string();
            } else {
                rewritten = resolution_re
                    .replace(
                        &rewritten,
                        format!("\n  resolution: \"{resolution}\"\n  checksum: {checksum}")
                            .as_str(),
                    )
                    .to_string();
            }
            matched_any = true;
            if rewritten != *block {
                result.edits.push(FileEdit {
                    path: "yarn.lock".into(),
                    kind: "redirect_yarn_berry_entry".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}", dep.version)),
                    original: Some(Value::String(block.clone())),
                    new: Some(Value::String(rewritten.clone())),
                });
                *block = rewritten;
                changed = true;
            }
        }
        if !matched_any {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_berry_entry_not_found".into(),
                detail: format!("no npm: lock entry resolving {fname}@{}", dep.version),
            });
        }
    }
    if changed {
        result.files.insert("yarn.lock".into(), blocks.join("\n\n"));
    }
}

// ── bun.lock (text lockfile) ─────────────────────────────────────────────────
// A registry 4-tuple `["name@version", "<registry>", {deps}, "sha512-…"]` is
// rewritten to a URL 3-tuple `["name@<artifactUrl>", {deps verbatim},
// "<sha512>"]`: bun then fetches `<artifactUrl>` directly and verifies the SRI.
// Binary `bun.lockb` is NEVER parsed — its presence (without a text `bun.lock`)
// is a documented refusal. Uses the shared `bun_lock_text` grammar (fail-CLOSED
// on any deviation). Byte-for-byte twin of the TS `rewriteBun`.
fn rewrite_bun_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    use crate::vendor::bun_lock_text::{
        check_lock_version, decode_json_string, parse_packages_section,
    };

    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() {
        return;
    }
    // Binary lockfile without a text one: presence-only refusal. NEVER parse
    // `.lockb` content. The CLI auto-migrates it to text before rewriting.
    if files.contains_key("bun.lockb") && !files.contains_key("bun.lock") {
        result.warnings.push(RewriteWarning {
            code: "redirect_bun_lockb_unsupported".into(),
            detail: "bun.lockb is a binary lockfile; re-lock with a text lockfile \
                     (`bun install --save-text-lockfile`) so the redirect can pin the hosted patch"
                .into(),
        });
        return;
    }
    let Some(content) = files.get("bun.lock") else {
        return;
    };
    if check_lock_version(content).is_err() {
        result.warnings.push(RewriteWarning {
            code: "redirect_bun_lock_unsupported".into(),
            detail: "bun.lock lockfileVersion is not 1; re-lock with bun >= 1.3".into(),
        });
        return;
    }
    let mut lines: Vec<String> = content.split('\n').map(str::to_string).collect();
    let entries = match parse_packages_section(&lines) {
        Ok(entries) => entries,
        Err(_) => {
            // Fail-closed: never line-splice a lock whose packages section
            // deviates from bun's emitted single-line grammar.
            result.warnings.push(RewriteWarning {
                code: "redirect_bun_lock_unsupported".into(),
                detail: "bun.lock packages section is not in bun's emitted single-line shape"
                    .into(),
            });
            return;
        }
    };

    let mut changed = false;
    for dep in &npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_bun_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        let target_spec = format!("{fname}@{}", dep.version);
        let url_spec = format!("{fname}@{}", dep.artifact_url);
        let mut matched_any = false;
        for entry in &entries {
            let Some(spec) = entry.elems.first().and_then(|e| decode_json_string(e)) else {
                continue;
            };
            let deps_verbatim: String;
            if entry.elems.len() == 4
                && spec == target_spec
                && decode_json_string(&entry.elems[1]).is_some()
                && entry.elems[2].starts_with('{')
                && decode_json_string(&entry.elems[3]).is_some()
            {
                // Registry 4-tuple → URL 3-tuple. Deps object preserved verbatim.
                deps_verbatim = entry.elems[2].clone();
            } else if entry.elems.len() == 3 && spec == url_spec {
                // Already one of our URL 3-tuples for this exact URL. Idempotent
                // if the integrity already matches; otherwise refresh it.
                matched_any = true;
                if entry.elems[2] == format!("\"{sha512}\"") {
                    continue;
                }
                deps_verbatim = entry.elems[1].clone();
            } else if entry.elems.len() == 3
                && entry.elems[1].starts_with('{')
                && is_prior_hosted_bun_spec(&spec, &fname, &dep.artifact_url)
            {
                // A URL 3-tuple written by an EARLIER redirect whose artifact
                // URL has since changed (a patch republish rotates the uuid
                // path segment; grant-token rotation changes the token — the
                // registry `name@version` spec was destroyed by that first
                // rewrite, so exact-URL matching alone would strand the stale
                // pin forever). Re-pin to the current URL. Ownership is
                // claimed narrowly — same origin and same `<name>-<version>
                // .tgz` leaf as the CURRENT artifact URL — so user URL deps
                // and other-version entries never match (fail-closed).
                deps_verbatim = entry.elems[1].clone();
            } else {
                // Same-name-but-unowned entry (user file:/URL dep, other
                // version) — never touched.
                continue;
            }
            matched_any = true;
            let original = lines[entry.line_idx].clone();
            let rebuilt = format!(
                "{indent}{key}: [{url}, {deps}, {integrity}]{comma}",
                indent = entry.indent,
                key = entry.key_raw,
                url = serde_json::to_string(&url_spec).unwrap(),
                deps = deps_verbatim,
                integrity = serde_json::to_string(&sha512).unwrap(),
                comma = if entry.trailing_comma { "," } else { "" },
            );
            if rebuilt == original {
                continue;
            }
            lines[entry.line_idx] = rebuilt.clone();
            result.edits.push(FileEdit {
                path: "bun.lock".into(),
                kind: "redirect_bun_lock_package".into(),
                action: "rewritten".into(),
                key: Some(entry.key.clone()),
                original: Some(Value::String(original)),
                new: Some(Value::String(rebuilt)),
            });
            changed = true;
        }
        if !matched_any {
            // Mirrors the pnpm/berry/uv rewriters: a granted dep that matched
            // no rewritable tuple (lock re-resolved to another version, entry
            // occupied by an unowned URL/file: spec) must be diagnosable, not
            // a silent drop from the `redirected` count.
            result.warnings.push(RewriteWarning {
                code: "redirect_bun_entry_not_found".into(),
                detail: format!("no rewritable bun.lock entry for {fname}@{}", dep.version),
            });
        }
    }
    if changed {
        result.files.insert("bun.lock".into(), lines.join("\n"));
    }
}

/// True when a bun.lock 3-tuple spec (`name@<url>`) was written by an earlier
/// hosted redirect of this same dependency: the spec's URL shares both the
/// origin (`scheme://host[:port]`) and the trailing `<name>-<version>.tgz`
/// path leaf with the CURRENT artifact URL. Both halves come from the live
/// override — nothing about the patch server's URL layout is assumed — and
/// anything that fails to parse fails the match (closed): user URL deps live
/// on other origins, and another version's artifact has a different leaf.
fn is_prior_hosted_bun_spec(spec: &str, fname: &str, current_url: &str) -> bool {
    let Some(old_url) = spec
        .strip_prefix(fname)
        .and_then(|rest| rest.strip_prefix('@'))
    else {
        return false;
    };
    fn origin_and_leaf(url: &str) -> Option<(&str, &str)> {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return None;
        }
        let scheme_end = url.find("://").unwrap() + 3;
        let path_start = url[scheme_end..].find('/')? + scheme_end;
        let leaf = url[path_start..]
            .rsplit('/')
            .next()
            .filter(|l| !l.is_empty())?;
        Some((&url[..path_start], leaf))
    }
    match (origin_and_leaf(old_url), origin_and_leaf(current_url)) {
        (Some(old), Some(new)) => old == new,
        _ => false,
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
        let target = canonicalize_pypi_name(&dep.name);
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
                .map(|c| canonicalize_pypi_name(&c[1]) == target)
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
            // Repoint EVERY url/hash entry in the block — sdist AND all
            // wheels. uv prefers a wheel, so an upstream `wheels` entry left
            // behind installs the unpatched artifact while the redirect is
            // reported (and attested) as landed.
            let new_body = wheel_re
                .replace_all(
                    &body,
                    format!(
                        "{{ url = \"{}\", hash = \"sha256:{sha256}\"${{1}} }}",
                        dep.artifact_url
                    )
                    .as_str(),
                )
                .to_string();
            if new_body == body {
                // Already redirected (re-run): the entry exists at the target
                // values — not "entry not found".
                matched = true;
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

/// The argument tail of a `gem "name", …` line minus any leading quoted
/// version-constraint args (`"7.0.0"`, `'~> 7.0'`, `">= 1", "< 2"`) — i.e. the
/// options (`require: false`, `group: :test`, …) that must survive the move
/// into the source block. Empty when the line carries none; bails to empty on
/// an unparseable tail (unbalanced quote), matching the previous behavior.
/// Shared with the vendor backend's Gemfile rewrite (`vendor::gem`),
/// which has the same drop-the-options failure mode.
pub(crate) fn gem_line_trailing_options(tail: &str) -> String {
    let mut rest = tail.trim_start();
    loop {
        let Some(after_comma) = rest.strip_prefix(',') else {
            return String::new();
        };
        let arg = after_comma.trim_start();
        match arg.chars().next() {
            Some(q @ ('"' | '\'')) => match arg[1..].find(q) {
                Some(end) => rest = arg[1 + end + 1..].trim_start(),
                None => return String::new(),
            },
            Some(_) => return arg.trim_end().to_string(),
            None => return String::new(),
        }
    }
}

/// The source-selecting option a `gem` line's argument tail carries, if any
/// (only the code before any `#` comment counts). Bundler allows ONE source
/// per gem, so an option like `git:` preserved into the Socket source block
/// OVERRIDES the block and the redirect becomes a silent no-op. Mirrors the
/// token list `vendor::gem::rest_blocks_edit` refuses for the same reason.
fn gem_tail_source_option(tail: &str) -> Option<&'static str> {
    let code = tail.split('#').next().unwrap_or("");
    [
        "path:",
        ":path",
        "git:",
        ":git",
        "github:",
        ":github",
        "source:",
        ":source",
        "gist:",
        ":gist",
        "bitbucket:",
        ":bitbucket",
    ]
    .into_iter()
    .find(|tok| code.contains(tok))
}

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

        // Platform-suffixed CHECKSUMS siblings (`name (version-arm64-darwin)
        // sha256=`) mean bundler resolves platform-specific gems the patch
        // registry does not serve — redirecting would pin the bare-platform
        // sha while installs keep fetching the upstream platform gem
        // (guaranteed mismatch or a silently unpatched install). Fail closed:
        // skip the dep entirely.
        if let Some(lk) = lock.as_deref() {
            let platform_re = Regex::new(
                &(String::from(r"(?m)^  ")
                    + &regex::escape(&dep.name)
                    + r" \("
                    + &regex::escape(&dep.version)
                    + r"-[^)]+\) sha256="),
            )
            .unwrap();
            if platform_re.is_match(lk) {
                result.warnings.push(RewriteWarning {
                    code: "redirect_gem_platform_unsupported".into(),
                    detail: format!(
                        "Gemfile.lock CHECKSUMS carries platform-specific entries for {} {} — \
                         the patch registry serves only the ruby platform gem; redirect skipped",
                        dep.name, dep.version
                    ),
                });
                continue;
            }
        }

        // Whether THIS dep's Gemfile source redirect is in place (just
        // written or already present) — the lock pin below is gated on it.
        let mut source_placed = false;
        if let Some(gf) = gemfile.as_mut() {
            // Grant-agnostic idempotency guard: the grant-token (and patch
            // uuid) segments of the index URL rotate per request, so an
            // exact-URL check misses the block a previous run wrote and this
            // run would wrap the gem line inside it — nesting source blocks.
            // Wildcard the rotating segments instead (mirrors the CHECKSUMS
            // at-target guard below).
            let mut url_pat = regex::escape(&ov.index_url);
            for rotating in [&dep.token, &dep.patch_uuid] {
                if !rotating.is_empty() {
                    url_pat =
                        url_pat.replace(&regex::escape(&format!("/{rotating}/")), "/[^/\"]+/");
                }
            }
            // `\r?\n`: the rewriter emits LF, but a `core.autocrlf` checkout
            // rewrites the working tree to CRLF — the guard must still
            // recognize the block there, or the indented `gem` line inside
            // it falls through to `gem_line_re` and gets wrapped again.
            let block_re = Regex::new(
                &(String::from(r#"(?m)^source "("#)
                    + &url_pat
                    + r#")" do\r?\n  gem ["']"#
                    + &regex::escape(&dep.name)
                    + r#"["']"#),
            )
            .unwrap();
            if let Some(m) = block_re.captures(gf) {
                let url = m.get(1).unwrap();
                if url.as_str() == ov.index_url {
                    source_placed = true;
                } else {
                    // Rotated grant: refresh the URL in place — never nest.
                    let (range, old_url) = (url.range(), url.as_str().to_string());
                    gf.replace_range(range, &ov.index_url);
                    gemfile_changed = true;
                    result.edits.push(FileEdit {
                        path: "Gemfile".into(),
                        kind: "redirect_gemfile_source_url".into(),
                        action: "rewritten".into(),
                        key: Some(dep.name.clone()),
                        original: Some(Value::String(old_url)),
                        new: Some(Value::String(ov.index_url.clone())),
                    });
                    source_placed = true;
                }
            } else {
                // Tolerate the legal spellings of a declaration: tab / extra
                // spaces after `gem`, and the parenthesized call form.
                let gem_line_re = Regex::new(
                    &(String::from(r#"(?m)^\s*gem(?:[ \t]*(\()[ \t]*|[ \t]+)["']"#)
                        + &regex::escape(&dep.name)
                        + r#"["']([^\n]*)$"#),
                )
                .unwrap();
                // Looser "declared at all?" probe: gates the append branch —
                // appending next to a declaration the recognizer above cannot
                // parse would leave the gem declared twice (bundler
                // hard-fails on the duplicate).
                let declared_re = Regex::new(
                    &(String::from(r#"(?m)^[ \t]*gem\b[^\n]*["']"#)
                        + &regex::escape(&dep.name)
                        + r#"["']"#),
                )
                .unwrap();
                if let Some(m) = gem_line_re.captures(gf) {
                    let range = m.get(0).unwrap().range();
                    let original = m.get(0).unwrap().as_str().to_string();
                    let paren = m.get(1).is_some();
                    let raw_tail = m.get(2).unwrap().as_str().to_string();
                    // A parenthesized call keeps its closing `)` in the tail:
                    // strip it (dropping any comment with it), or fail closed
                    // when it is absent (the call continues past this line).
                    let tail = if paren {
                        let code = raw_tail.split('#').next().unwrap_or("").trim_end();
                        match code.strip_suffix(')') {
                            Some(t) => t.to_string(),
                            None => {
                                result.warnings.push(RewriteWarning {
                                    code: "redirect_gem_unrecognized_declaration".into(),
                                    detail: format!(
                                        "the `gem \"{}\"` declaration is in a form the \
                                         rewriter cannot safely edit; redirect skipped",
                                        dep.name
                                    ),
                                });
                                continue;
                            }
                        }
                    } else {
                        raw_tail
                    };
                    // A source-selecting option would move into the block and
                    // OVERRIDE it in bundler's DSL, leaving the redirect a
                    // silent no-op that still gets attested. Fail closed.
                    if let Some(tok) = gem_tail_source_option(&tail) {
                        result.warnings.push(RewriteWarning {
                            code: "redirect_gem_source_option".into(),
                            detail: format!(
                                "the `gem \"{}\"` declaration carries `{tok}`, which would \
                                 override the Socket source block; redirect skipped",
                                dep.name
                            ),
                        });
                        continue;
                    }
                    // Trailing options (`require: false`, `group: …`) must
                    // survive the move into the source block — dropping
                    // `require: false` auto-requires the gem at boot.
                    let opts = gem_line_trailing_options(&tail);
                    let block = if opts.is_empty() {
                        format!(
                            "source \"{}\" do\n  gem \"{}\", \"{}\"\nend",
                            ov.index_url, dep.name, dep.version
                        )
                    } else {
                        format!(
                            "source \"{}\" do\n  gem \"{}\", \"{}\", {opts}\nend",
                            ov.index_url, dep.name, dep.version
                        )
                    };
                    // Splice by the match's byte range: a substring replace of
                    // the line's TEXT would hit an identical commented-out
                    // duplicate earlier in the file and corrupt it (and the
                    // block may carry user text a regex replacement would
                    // `$`-expand).
                    gf.replace_range(range, &block);
                    gemfile_changed = true;
                    result.edits.push(FileEdit {
                        path: "Gemfile".into(),
                        kind: "redirect_gemfile_source_block".into(),
                        action: "rewritten".into(),
                        key: Some(dep.name.clone()),
                        original: Some(Value::String(original)),
                        new: Some(Value::String(block)),
                    });
                    source_placed = true;
                } else if declared_re.is_match(gf) {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_gem_unrecognized_declaration".into(),
                        detail: format!(
                            "the `gem \"{}\"` declaration is in a form the rewriter \
                             cannot safely edit; redirect skipped",
                            dep.name
                        ),
                    });
                    continue;
                } else {
                    // Genuinely undeclared (a transitive dep): append a block.
                    let block = format!(
                        "source \"{}\" do\n  gem \"{}\", \"{}\"\nend",
                        ov.index_url, dep.name, dep.version
                    );
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
                    source_placed = true;
                }
            }
        }

        if let Some(lk) = lock.as_mut() {
            // The pin only makes sense once the source redirect is in place
            // (just written or already present): pinning the patched sha
            // while the gem still resolves upstream guarantees a checksum
            // failure on the next install.
            if !source_placed {
                result.warnings.push(RewriteWarning {
                    code: "redirect_gem_lock_without_source".into(),
                    detail: format!(
                        "no Gemfile source redirect is in place for {} — CHECKSUMS pin skipped",
                        dep.name
                    ),
                });
                continue;
            }
            let sum_line_re = Regex::new(
                &(String::from(r"(?m)^(  ")
                    + &regex::escape(&dep.name)
                    + r" \("
                    + &regex::escape(&dep.version)
                    + r"\)) sha256=([0-9a-f]+)$"),
            )
            .unwrap();
            let new_val = format!("{} ({}) sha256={sha256}", dep.name, dep.version);
            // Already redirected (re-run): the CHECKSUMS line is at the
            // target value; recording an edit would grow the ledger forever.
            if lk.contains(&format!("\n  {new_val}\n")) || lk.ends_with(&format!("\n  {new_val}")) {
                // no-op
            } else if let Some(m) = sum_line_re.captures(lk) {
                // The pre-edit line goes into the ledger as `original` so a
                // future `--revert` can restore the upstream sha.
                let old_val = format!(
                    "{} ({}) sha256={}",
                    dep.name,
                    dep.version,
                    m.get(2).unwrap().as_str()
                );
                *lk = sum_line_re
                    .replace(lk, format!("${{1}} sha256={sha256}").as_str())
                    .to_string();
                lock_changed = true;
                result.edits.push(FileEdit {
                    path: "Gemfile.lock".into(),
                    kind: "redirect_gemfile_lock_checksum".into(),
                    action: "rewritten".into(),
                    key: Some(dep.name.clone()),
                    original: Some(Value::String(old_val)),
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

    // The rewritten pair breaks bundler's frozen/deployment mode: the lock's
    // GEM section still records the upstream source, so `bundle install` with
    // `frozen`/`--deployment` set rejects the Gemfile's new source block.
    // Mirror of the CLI's pnpm trust-lockfile warning.
    if gemfile_changed || lock_changed {
        result.warnings.push(RewriteWarning {
            code: "redirect_gem_frozen_install".into(),
            detail: "Gemfile was repointed at the Socket patch registry but Gemfile.lock's \
                     GEM section still records the upstream source; bundler rejects the pair \
                     under frozen/deployment mode — run `bundle install` (unfrozen) once to \
                     record the new source in Gemfile.lock"
                .into(),
        });
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

// ── maven (pom.xml version pin + repository + trusted checksums) ────────────
//
// Maven has no lockfile, so the patched jar is pinned two ways depending on
// whether the reference API captured a rewritable upstream pom (see the TS twin
// `registry-rewrite/maven-pom.ts` for the full rationale):
//
//   FAIL-CLOSED — the override carries `identifiers.mavenSuffixedVersion`
//   (`<base>-socket.<hex8>`) + the `mavenPomSha256` of the served pom. That
//   version exists ONLY on the Socket repo, so the rewriter pins it EXPLICITLY
//   (rewrite the literal `<version>`, or add a `<dependencyManagement>` entry
//   for a transitive) — a resolver that can't reach the Socket repo or is
//   handed different bytes can't fall through to Central, so the build
//   hard-fails instead of silently going unpatched. When a pin lands we also
//   inject the single-artifact `<repository>` (releases + `checksumPolicy=fail`)
//   and, when the jar + pom sha256 are both known, Maven Trusted Checksums
//   files (`.mvn/maven.config` + `.mvn/checksums/checksums.sha256`).
//
//   LEGACY same-GAV — no `mavenSuffixedVersion`. The patched jar is served
//   under its original GAV, so the rewriter only injects the `<repository>` and
//   warns `redirect_maven_same_gav_fallback` (a Socket-repo outage/tamper falls
//   back to the UNPATCHED artifact — NOT fail-closed).
//
// Gradle has no equivalent surgical single-line edit, so a present build script
// gets a paste-able `exclusiveContent { … }` snippet warning instead of an
// edit. pom.xml + `.mvn/*` are authored surgically (mirrors the cargo/nuget
// rewriters): every byte not touched by an edit is preserved.

/// Gradle build scripts (Groovy + Kotlin DSL) that trigger the manual snippet.
const GRADLE_FILES: &[&str] = &[
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
];

/// The six `-Daether.*` args that enable Maven's Trusted Checksums resolver
/// post-processor (twin of the TS `MVN_CONFIG_ARGS`), one per `.mvn/maven.config`
/// line. `failIfMissing=false` so a dependency without a committed checksum
/// still resolves (only a MISMATCH fails); origin-unaware so one checksum
/// matches the artifact from any repository.
const MVN_CONFIG_ARGS: &[&str] = &[
    "-Daether.artifactResolver.postProcessor.trustedChecksums=true",
    "-Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256",
    "-Daether.artifactResolver.postProcessor.trustedChecksums.failIfMissing=false",
    "-Daether.trustedChecksumsSource.summaryFile=true",
    "-Daether.trustedChecksumsSource.summaryFile.basedir=${session.rootDirectory}/.mvn/checksums",
    "-Daether.trustedChecksumsSource.summaryFile.originAware=false",
];

const MVN_CONFIG: &str = ".mvn/maven.config";
const MVN_CHECKSUMS: &str = ".mvn/checksums/checksums.sha256";

/// Strip any `sha256-`/`sha256:` SRI-style prefix off a stored hash, leaving the
/// bare lowercase hex Maven's trusted-checksums summary file expects (twin of
/// the TS `bareSha256Hex`).
fn bare_sha256_hex(hash: &str) -> String {
    let lower = hash.trim().to_lowercase();
    if let Some(rest) = lower.strip_prefix("sha256-") {
        return rest.to_string();
    }
    if let Some(rest) = lower.strip_prefix("sha256:") {
        return rest.to_string();
    }
    lower
}

/// A `<dependency>` block matched by groupId:artifactId, with the byte offsets
/// of its literal `<version>` inner text (None when the dep carries no literal
/// version — inherited/managed) and its trimmed version/type text. Mirrors the
/// TS `MavenDependencyMatch`.
struct MavenDependencyMatch {
    version_inner: Option<(usize, usize)>,
    version_text: Option<String>,
    type_text: Option<String>,
}

/// Inner-text byte range of the first `<tag>…</tag>` inside `pom[from, to)`, or
/// None. Offsets are into the FULL `pom`.
fn maven_tag_inner_range(pom: &str, tag: &str, from: usize, to: usize) -> Option<(usize, usize)> {
    let re = Regex::new(&format!("(?s)<{tag}>(.*?)</{tag}>")).unwrap();
    let caps = re.captures(&pom[from..to])?;
    let inner = caps.get(1).unwrap();
    Some((from + inner.start(), from + inner.end()))
}

/// Trimmed text of the first `<tag>…</tag>` inside `pom[from, to)`, or None.
fn maven_tag_text_in(pom: &str, tag: &str, from: usize, to: usize) -> Option<String> {
    maven_tag_inner_range(pom, tag, from, to).map(|(s, e)| pom[s..e].trim().to_string())
}

/// Every `<dependency>` block whose `<groupId>` + `<artifactId>` match, with
/// its literal `<version>` range/text and `<type>` text (twin of the TS
/// `findDependencyMatches`). A `<dependency>` inside `<dependencyManagement>`
/// is matched the same way as a direct one — the suffixing path tells "managed
/// in an unseen parent" (no literal version → depMgmt pin) from "pinned here"
/// (rewrite the literal) purely by whether ANY match carries a literal
/// `<version>`. Returns ALL matches so a managed base-version entry gets
/// rewritten even when a direct dependency declares no version.
fn find_maven_dependency_matches(
    pom: &str,
    group_id: &str,
    artifact_id: &str,
) -> Vec<MavenDependencyMatch> {
    let dep_re = Regex::new(r"(?s)<dependency\b[^>]*>.*?</dependency>").unwrap();
    let mut matches = vec![];
    for m in dep_re.find_iter(pom) {
        let (dep_open, dep_close) = (m.start(), m.end());
        let g = maven_tag_text_in(pom, "groupId", dep_open, dep_close);
        let a = maven_tag_text_in(pom, "artifactId", dep_open, dep_close);
        if g.as_deref() != Some(group_id) || a.as_deref() != Some(artifact_id) {
            continue;
        }
        let version_inner = maven_tag_inner_range(pom, "version", dep_open, dep_close);
        matches.push(MavenDependencyMatch {
            version_text: version_inner.map(|(s, e)| pom[s..e].trim().to_string()),
            version_inner,
            type_text: maven_tag_text_in(pom, "type", dep_open, dep_close),
        });
    }
    matches
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
    let mut mvn_config = files.get(MVN_CONFIG).cloned().unwrap_or_default();
    let mut mvn_config_changed = false;
    // (local-repo-relative path, bare sha256 hex) entries to merge in.
    let mut checksum_entries: Vec<(String, String)> = vec![];
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
        let suffixed_version = ov.identifiers.maven_suffixed_version.clone();
        let pom_sha256 = ov.identifiers.maven_pom_sha256.clone();
        let jar_sha256 = dep.integrity.sha256.clone();

        // Gradle: emit a paste-able exclusiveContent snippet (never edit a
        // build script). Independent of the pom edit — a project may ship both.
        // Pin the suffixed version when fail-closed; the legacy base otherwise.
        if gradle_build_present {
            let gradle_version = suffixed_version.as_deref().unwrap_or(&dep.version);
            result.warnings.push(RewriteWarning {
                code: "redirect_gradle_manual_snippet".into(),
                detail: gradle_snippet(
                    &ov.index_url,
                    &group_id,
                    &artifact_id,
                    gradle_version,
                    suffixed_version.is_some(),
                ),
            });
        }

        if pom.is_none() {
            continue;
        }
        // Unique-per-patch repository id (valid chars: alnum, `-`, `_`, `.`).
        let repo_id = format!("socket-patch-{}", dep.patch_uuid);

        // LEGACY same-GAV fallback: no suffixed version means the patched jar is
        // served under its original GAV. Add the repository (transport checksum
        // policy `fail`) exactly as before and warn that this is NOT
        // fail-closed.
        let Some(suffixed_version) = suffixed_version else {
            let pom_text = pom.as_ref().unwrap();
            // Verify-only inspection: warn when the redirect can't take effect.
            // Only the FIRST match matters here (legacy behavior).
            let matches = find_maven_dependency_matches(pom_text, &group_id, &artifact_id);
            match matches.first() {
                None => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_maven_dep_not_found".into(),
                        detail: format!(
                            "no <dependency> for {group_id}:{artifact_id} in pom.xml (adding repository anyway)"
                        ),
                    });
                }
                Some(first) => {
                    if let Some(typ) = &first.type_text {
                        if typ != "jar" {
                            result.warnings.push(RewriteWarning {
                                code: "redirect_maven_unsupported_packaging".into(),
                                detail: format!(
                                    "{group_id}:{artifact_id} has <type>{typ}</type> (only jar can be redirected); skipping"
                                ),
                            });
                            continue;
                        }
                    }
                    match &first.version_text {
                        None => {
                            result.warnings.push(RewriteWarning {
                                code: "redirect_maven_dep_unpinned".into(),
                                detail: format!(
                                    "{group_id}:{artifact_id} has no literal <version> (inherited/managed); the socket repository only serves {}",
                                    dep.version
                                ),
                            });
                        }
                        Some(v) if v.contains("${") => {
                            result.warnings.push(RewriteWarning {
                                code: "redirect_maven_dep_unpinned".into(),
                                detail: format!(
                                    "{group_id}:{artifact_id} <version> is a property placeholder ({v}); the socket repository only serves {}",
                                    dep.version
                                ),
                            });
                        }
                        Some(_) => {}
                    }
                }
            }
            result.warnings.push(RewriteWarning {
                code: "redirect_maven_same_gav_fallback".into(),
                detail: format!(
                    "{group_id}:{artifact_id} is patched at its original GAV; a Socket-repo failure falls back to the unpatched artifact — not fail-closed. The backend will serve suffixed versions once the upstream pom is available."
                ),
            });
            if pom_text.contains(&format!("<id>{repo_id}</id>")) {
                continue;
            }
            pom = Some(insert_maven_repository(pom_text, &repo_id, &ov.index_url));
            pom_changed = true;
            result.edits.push(FileEdit {
                path: "pom.xml".into(),
                kind: "redirect_maven_repository".into(),
                action: "added".into(),
                key: Some(repo_id.clone()),
                original: None,
                new: Some(json!({ "id": repo_id, "url": ov.index_url })),
            });
            continue;
        };

        // FAIL-CLOSED: pin the suffixed version explicitly. Scan every matching
        // <dependency>, tracking depMgmt containment via the version presence
        // so we can tell a literal pin here from a version managed elsewhere.
        let matches = find_maven_dependency_matches(pom.as_ref().unwrap(), &group_id, &artifact_id);

        // An unsupported <type> on any match: the single-jar repo can't serve
        // it — skip the whole dep (no version edit, no repo, no checksum).
        if let Some(non_jar) = matches
            .iter()
            .find(|m| m.type_text.as_deref().is_some_and(|t| t != "jar"))
        {
            result.warnings.push(RewriteWarning {
                code: "redirect_maven_unsupported_packaging".into(),
                detail: format!(
                    "{group_id}:{artifact_id} has <type>{}</type> (only jar can be redirected); skipping",
                    non_jar.type_text.as_deref().unwrap_or_default()
                ),
            });
            continue;
        }

        // A `${property}` version on any match: refuse this dep entirely.
        // Editing the literal would break the property reference, and a depMgmt
        // pin could strand sibling artifacts sharing the property.
        if let Some(prop) = matches
            .iter()
            .find(|m| m.version_text.as_deref().is_some_and(|v| v.contains("${")))
        {
            result.warnings.push(RewriteWarning {
                code: "redirect_maven_dep_unpinned".into(),
                detail: format!(
                    "{group_id}:{artifact_id} <version> is a property placeholder ({}); refusing to pin the suffixed version (a property edit could strand sibling artifacts)",
                    prop.version_text.as_deref().unwrap_or_default()
                ),
            });
            continue;
        }

        let mut pin_landed = false;
        // Literal versions among the matches, with their inner ranges.
        let versioned: Vec<(usize, usize, String)> = matches
            .iter()
            .filter_map(|m| {
                m.version_inner
                    .zip(m.version_text.clone())
                    .map(|((s, e), v)| (s, e, v))
            })
            .collect();
        // Rewrite base → suffixed. Descending offset order so earlier edits
        // don't shift later matches' offsets.
        let mut to_rewrite: Vec<(usize, usize)> = versioned
            .iter()
            .filter(|(_, _, v)| *v == dep.version)
            .map(|(s, e, _)| (*s, *e))
            .collect();
        to_rewrite.sort_by(|a, b| b.0.cmp(&a.0));
        for (start, end) in &to_rewrite {
            let mut rebuilt = pom.as_ref().unwrap().clone();
            rebuilt.replace_range(*start..*end, &suffixed_version);
            pom = Some(rebuilt);
            pom_changed = true;
            pin_landed = true;
            result.edits.push(FileEdit {
                path: "pom.xml".into(),
                kind: "redirect_maven_dep_version".into(),
                action: "rewritten".into(),
                key: Some(format!("{group_id}:{artifact_id}")),
                original: Some(Value::String(dep.version.clone())),
                new: Some(Value::String(suffixed_version.clone())),
            });
        }
        // A literal version that is neither base nor the applied suffixed
        // version disagrees with the row — skip it (don't guess). A dep whose
        // only match is a mismatch adds no pin (versioned is non-empty, so the
        // depMgmt branch below is skipped).
        for (_, _, v) in &versioned {
            if *v != dep.version && *v != suffixed_version {
                result.warnings.push(RewriteWarning {
                    code: "redirect_maven_dep_version_mismatch".into(),
                    detail: format!(
                        "{group_id}:{artifact_id} <version>{v}</version> matches neither the base ({}) nor the suffixed ({suffixed_version}) version; skipping",
                        dep.version
                    ),
                });
            }
        }

        // No literal <version> among the matches (transitive-only, or the
        // version is managed in an unseen parent): pin via
        // <dependencyManagement>. A re-run finds the suffixed entry we authored
        // as a versioned match, so `versioned` is non-empty and this branch is
        // skipped (idempotent).
        if versioned.is_empty() {
            pom = Some(insert_maven_dependency_management(
                pom.as_ref().unwrap(),
                &group_id,
                &artifact_id,
                &suffixed_version,
            ));
            pom_changed = true;
            pin_landed = true;
            result.edits.push(FileEdit {
                path: "pom.xml".into(),
                kind: "redirect_maven_dep_management".into(),
                action: "added".into(),
                key: Some(format!("{group_id}:{artifact_id}")),
                original: None,
                new: Some(
                    json!({ "groupId": group_id, "artifactId": artifact_id, "version": suffixed_version }),
                ),
            });
            result.warnings.push(RewriteWarning {
                code: "redirect_maven_dep_management_added".into(),
                detail: format!(
                    "{group_id}:{artifact_id} has no literal <version> in pom.xml; added a <dependencyManagement> pin for the suffixed version {suffixed_version}"
                ),
            });
        }

        // A pin landed this run: inject the repository (idempotent via the <id>
        // guard) and emit trusted checksums. When the pin was already present
        // from a prior run, `pin_landed` stays false and both are skipped,
        // keeping a re-run edit-free.
        if !pin_landed {
            continue;
        }
        if !pom
            .as_ref()
            .unwrap()
            .contains(&format!("<id>{repo_id}</id>"))
        {
            pom = Some(insert_maven_repository(
                pom.as_ref().unwrap(),
                &repo_id,
                &ov.index_url,
            ));
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

        // Trusted Checksums: only when BOTH the jar sha256 and the served pom
        // sha256 are known. Two entries per dep — the jar and the pom — under
        // the SUFFIXED version's local-repo path.
        if let (Some(jar), Some(pom_hash)) = (&jar_sha256, &pom_sha256) {
            let (merged, conflicts) =
                merge_mvn_config(&mvn_config, &format!("{group_id}:{artifact_id}"));
            for conflict in conflicts {
                result.warnings.push(RewriteWarning {
                    code: "redirect_maven_trusted_checksums_conflict".into(),
                    detail: conflict,
                });
            }
            if merged != mvn_config {
                let action = if files.contains_key(MVN_CONFIG) {
                    "rewritten"
                } else {
                    "added"
                };
                mvn_config = merged;
                mvn_config_changed = true;
                result.edits.push(FileEdit {
                    path: MVN_CONFIG.into(),
                    kind: "redirect_maven_config".into(),
                    action: action.into(),
                    key: Some("trustedChecksums".into()),
                    original: None,
                    new: None,
                });
            }
            checksum_entries.push((
                local_repo_artifact_path(&group_id, &artifact_id, &suffixed_version, "jar"),
                bare_sha256_hex(jar),
            ));
            checksum_entries.push((
                local_repo_artifact_path(&group_id, &artifact_id, &suffixed_version, "pom"),
                bare_sha256_hex(pom_hash),
            ));
        }
    }

    if pom_changed {
        if let Some(p) = pom {
            result.files.insert("pom.xml".into(), p);
        }
    }
    if mvn_config_changed {
        result.files.insert(MVN_CONFIG.into(), mvn_config);
    }
    if !checksum_entries.is_empty() {
        let existing = files.get(MVN_CHECKSUMS).cloned().unwrap_or_default();
        let action = if files.contains_key(MVN_CHECKSUMS) {
            "rewritten"
        } else {
            "added"
        };
        result.files.insert(
            MVN_CHECKSUMS.into(),
            merge_checksums(&existing, &checksum_entries),
        );
        result.edits.push(FileEdit {
            path: MVN_CHECKSUMS.into(),
            kind: "redirect_maven_trusted_checksums".into(),
            action: action.into(),
            key: None,
            original: None,
            new: None,
        });
    }
}

/// Insert the socket-patch `<repository>` block: releases enabled with
/// `<checksumPolicy>fail</checksumPolicy>` (the transport-level check against
/// the served `.jar.sha1`); snapshots disabled (patched artifacts are always
/// released versions). Prefer an existing `<repositories>` element (single
/// replace, inserted first so it's consulted before the project's other
/// repositories); otherwise author a full `<repositories>` section immediately
/// before the closing `</project>`. `<repositories>` is matched exactly so it
/// never collides with `<pluginRepositories>`.
fn insert_maven_repository(pom: &str, id: &str, url: &str) -> String {
    let block = format!(
        "    <repository>\n      <id>{id}</id>\n      <url>{url}</url>\n      <releases>\n        <enabled>true</enabled>\n        <checksumPolicy>fail</checksumPolicy>\n      </releases>\n      <snapshots>\n        <enabled>false</enabled>\n      </snapshots>\n    </repository>"
    );
    if pom.contains("<repositories>") {
        return pom.replacen("<repositories>", &format!("<repositories>\n{block}"), 1);
    }
    let section = format!("  <repositories>\n{block}\n  </repositories>");
    pom.replacen("</project>", &format!("{section}\n</project>"), 1)
}

/// Add a `<dependencyManagement>` version pin. Prefer extending an existing
/// `<dependencyManagement><dependencies>` element (insert right after the
/// opening `<dependencies>` tag); otherwise author a full
/// `<dependencyManagement>` section before `</project>`. Mirrors the TS
/// `insertDependencyManagement`.
fn insert_maven_dependency_management(
    pom: &str,
    group_id: &str,
    artifact_id: &str,
    version: &str,
) -> String {
    let block = format!(
        "      <dependency>\n        <groupId>{group_id}</groupId>\n        <artifactId>{artifact_id}</artifactId>\n        <version>{version}</version>\n      </dependency>"
    );
    let dm_re = Regex::new(r"(?s)<dependencyManagement>\s*<dependencies>").unwrap();
    if let Some(m) = dm_re.find(pom) {
        let matched = m.as_str();
        return pom.replacen(matched, &format!("{matched}\n{block}"), 1);
    }
    let section = format!(
        "  <dependencyManagement>\n    <dependencies>\n{block}\n    </dependencies>\n  </dependencyManagement>"
    );
    pom.replacen("</project>", &format!("{section}\n</project>"), 1)
}

/// Merge trusted-checksums resolver args into `.mvn/maven.config` (one arg per
/// line). Dedupe by the `-Dkey=` prefix: an arg whose key is already present is
/// left untouched (existing value wins). Returns the merged text + any conflict
/// messages (a pre-existing SAME key with a DIFFERENT value). Twin of the TS
/// `mergeMvnConfig`.
fn merge_mvn_config(existing: &str, coordinate: &str) -> (String, Vec<String>) {
    let lines: Vec<&str> = if existing.is_empty() {
        vec![]
    } else {
        existing.split('\n').collect()
    };
    let mut conflicts = vec![];
    let key_of =
        |line: &str| -> Option<String> { line.find('=').map(|eq| line[..=eq].to_string()) };
    let mut present: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in &lines {
        if let Some(key) = key_of(line) {
            present.insert(key, (*line).to_string());
        }
    }
    let mut appended: Vec<&str> = vec![];
    for arg in MVN_CONFIG_ARGS {
        let key = key_of(arg).unwrap();
        match present.get(&key) {
            None => {
                appended.push(arg);
                present.insert(key, (*arg).to_string());
            }
            Some(existing_line) if existing_line.trim() != *arg => {
                conflicts.push(format!(
                    "{coordinate}: {MVN_CONFIG} already sets {key} to a different value ({}); leaving it as-is",
                    existing_line.trim()
                ));
            }
            Some(_) => {}
        }
    }
    if appended.is_empty() {
        return (existing.to_string(), conflicts);
    }
    let base = if existing.is_empty() {
        String::new()
    } else if existing.ends_with('\n') {
        existing.to_string()
    } else {
        format!("{existing}\n")
    };
    (format!("{base}{}\n", appended.join("\n")), conflicts)
}

/// Merge trusted-checksum entries into `.mvn/checksums/checksums.sha256` (GNU
/// coreutils format: `<sha256-hex><TWO spaces><local-repo-relative path>`).
/// Parse existing entries, replace/add by path, re-sort by path, trailing
/// newline. A malformed line (no double-space separator) is dropped. Twin of
/// the TS `mergeChecksums`.
fn merge_checksums(existing: &str, entries: &[(String, String)]) -> String {
    let mut by_path: BTreeMap<String, String> = BTreeMap::new();
    if !existing.is_empty() {
        for line in existing.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(sep) = line.find("  ") {
                by_path.insert(line[sep + 2..].to_string(), line[..sep].to_string());
            }
        }
    }
    for (path, sha256) in entries {
        by_path.insert(path.clone(), sha256.clone());
    }
    // BTreeMap iterates keys in sorted (byte) order — matching JS's default
    // sort on the ASCII paths.
    let body: Vec<String> = by_path
        .iter()
        .map(|(path, sha)| format!("{sha}  {path}"))
        .collect();
    format!("{}\n", body.join("\n"))
}

/// The local-repository-relative artifact path Maven derives for a coordinate:
/// `<groupId-with-slashes>/<artifactId>/<version>/<artifactId>-<version>.<ext>`.
fn local_repo_artifact_path(group_id: &str, artifact_id: &str, version: &str, ext: &str) -> String {
    format!(
        "{}/{artifact_id}/{version}/{artifact_id}-{version}.{ext}",
        group_id.replace('.', "/")
    )
}

/// A paste-able Gradle `exclusiveContent` block that pins ONLY the patched
/// artifact to the socket maven2 repository (Groovy DSL — the common case; the
/// Kotlin DSL differs only in quoting). Uses the SUFFIXED version when
/// fail-closed; the message reminds the user to also bump the dependency
/// declaration. Emitted as a warning detail; the rewriter never edits a build
/// script.
fn gradle_snippet(
    index_url: &str,
    group_id: &str,
    artifact_id: &str,
    version: &str,
    suffixed: bool,
) -> String {
    let bump = if suffixed {
        format!(
            " Also bump the {group_id}:{artifact_id} dependency declaration to version {version} — exclusiveContent is fail-closed by repo exclusivity."
        )
    } else {
        String::new()
    };
    format!(
        "Gradle build detected — add this per-dependency repository manually (no automatic edit):\nrepositories {{\n    exclusiveContent {{\n        forRepository {{\n            maven {{ url \"{index_url}\" }}\n        }}\n        filter {{\n            includeVersion(\"{group_id}\", \"{artifact_id}\", \"{version}\")\n        }}\n    }}\n}}{bump}"
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

    const MAVEN_SUFFIXED: &str = "1.7.36-socket.aaaaaaaa";

    /// A fail-closed override (suffixed version + jar/pom sha256 present).
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
                    maven_suffixed_version: Some(MAVEN_SUFFIXED.into()),
                    maven_pom_sha256: Some("d".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha1: Some("a".repeat(40)),
                md5: Some("b".repeat(32)),
                sha256: Some("c".repeat(64)),
                ..Default::default()
            },
        }
    }

    /// A legacy override — no suffixed version, no sha256 (same-GAV serving).
    fn legacy_maven_override() -> DepOverride {
        let mut dep = maven_override();
        let ids = &mut dep.registry_override.as_mut().unwrap().identifiers;
        ids.maven_suffixed_version = None;
        ids.maven_pom_sha256 = None;
        dep.integrity.sha256 = None;
        dep
    }

    fn pom_with_dep(version_xml: &str, type_xml: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>dev.socket.test</groupId>\n  <artifactId>consumer</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n      <groupId>org.slf4j</groupId>\n      <artifactId>slf4j-api</artifactId>{version_xml}{type_xml}\n    </dependency>\n  </dependencies>\n</project>\n"
        )
    }

    fn warning_codes(r: &RewriteResult) -> Vec<&str> {
        r.warnings.iter().map(|w| w.code.as_str()).collect()
    }

    /// Fail-closed literal pin: the `<version>` is rewritten to the suffixed
    /// value, the repository + trusted-checksum files are emitted, and a re-run
    /// over the fully-pinned output records nothing (idempotent).
    #[test]
    fn maven_pom_fail_closed_literal_pin_and_rerun_noop() {
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        let overrides = vec![maven_override()];
        let first = rewrite_registry_redirect(&files, &overrides);
        let out = first.files.get("pom.xml").expect("pom rewritten");
        assert!(
            out.contains(&format!("<version>{MAVEN_SUFFIXED}</version>")),
            "version suffixed: {out}"
        );
        assert!(!out.contains("<version>1.7.36</version>"), "base replaced");
        assert!(out.contains("<id>socket-patch-uuid</id>"), "{out}");
        assert!(out.contains("<checksumPolicy>fail</checksumPolicy>"));
        let config = first.files.get(".mvn/maven.config").expect("config");
        assert!(config.contains("trustedChecksums=true"), "{config}");
        let checksums = first
            .files
            .get(".mvn/checksums/checksums.sha256")
            .expect("checksums");
        assert!(
            checksums.contains(&format!(
                "{}  org/slf4j/slf4j-api/{MAVEN_SUFFIXED}/slf4j-api-{MAVEN_SUFFIXED}.jar",
                "c".repeat(64)
            )),
            "jar entry: {checksums}"
        );
        assert!(
            checksums.contains(&format!(
                "{}  org/slf4j/slf4j-api/{MAVEN_SUFFIXED}/slf4j-api-{MAVEN_SUFFIXED}.pom",
                "d".repeat(64)
            )),
            "pom entry: {checksums}"
        );
        assert!(first.warnings.is_empty(), "{:?}", first.warnings);
        let kinds: Vec<&str> = first.edits.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "redirect_maven_dep_version",
                "redirect_maven_repository",
                "redirect_maven_config",
                "redirect_maven_trusted_checksums",
            ]
        );

        let mut again = files.clone();
        again.insert("pom.xml".to_string(), out.clone());
        again.insert(".mvn/maven.config".to_string(), config.clone());
        again.insert(
            ".mvn/checksums/checksums.sha256".to_string(),
            checksums.clone(),
        );
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "second pass must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    /// Fail-closed transitive-only (no matching dependency): a
    /// `<dependencyManagement>` pin for the suffixed version is authored (with
    /// the informational note, NOT the legacy dep_not_found warning).
    #[test]
    fn maven_pom_fail_closed_transitive_dep_management() {
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>ch.qos.logback</groupId>\n      <artifactId>logback-classic</artifactId>\n      <version>1.4.14</version>\n    </dependency>\n  </dependencies>\n</project>\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        let out = r.files.get("pom.xml").expect("pom rewritten");
        assert!(
            out.contains("<dependencyManagement>")
                && out.contains(&format!("<version>{MAVEN_SUFFIXED}</version>")),
            "depMgmt pin authored: {out}"
        );
        assert!(warning_codes(&r).contains(&"redirect_maven_dep_management_added"));
        assert!(!warning_codes(&r).contains(&"redirect_maven_dep_not_found"));
        let kinds: Vec<&str> = r.edits.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "redirect_maven_dep_management",
                "redirect_maven_repository",
                "redirect_maven_config",
                "redirect_maven_trusted_checksums",
            ]
        );
    }

    /// Fail-closed refusals: a `${property}` version refuses the whole dep (no
    /// repo/checksums); a mismatched literal version skips it; a non-jar
    /// `<type>` skips it.
    #[test]
    fn maven_pom_fail_closed_refusals() {
        // Property placeholder → full refusal.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>${slf4j.version}</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert!(warning_codes(&r).contains(&"redirect_maven_dep_unpinned"));
        assert!(!warning_codes(&r).contains(&"redirect_maven_repository"));

        // Mismatched literal version → skip.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.30</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_maven_dep_version_mismatch"]
        );

        // Non-jar <type> → skip.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep(
                "\n      <version>1.7.36</version>",
                "\n      <type>pom</type>",
            ),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_maven_unsupported_packaging"]
        );
    }

    /// Fail-closed without a jar/pom sha256: the version + repo are pinned but
    /// NO checksum files are emitted (nothing to verify against). And a
    /// `sha256-`-prefixed hash is stripped to bare hex before it lands.
    #[test]
    fn maven_pom_fail_closed_checksum_conditions() {
        // No jar sha256 → no .mvn files.
        let mut dep = maven_override();
        dep.integrity.sha256 = None;
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(r.files.contains_key("pom.xml"), "version still pinned");
        assert!(!r.files.contains_key(".mvn/maven.config"));
        assert!(!r.files.contains_key(".mvn/checksums/checksums.sha256"));

        // A `sha256-` SRI prefix is stripped to bare hex.
        let mut dep = maven_override();
        dep.integrity.sha256 = Some(format!("sha256-{}", "c".repeat(64)));
        dep.registry_override
            .as_mut()
            .unwrap()
            .identifiers
            .maven_pom_sha256 = Some(format!("sha256-{}", "d".repeat(64)));
        let r = rewrite_registry_redirect(&files, &[dep]);
        let checksums = r
            .files
            .get(".mvn/checksums/checksums.sha256")
            .expect("checksums");
        assert!(
            !checksums.contains("sha256-"),
            "prefix stripped: {checksums}"
        );
        assert!(checksums.contains(&format!("{}  ", "c".repeat(64))));
        assert!(checksums.contains(&format!("{}  ", "d".repeat(64))));
    }

    /// A user `.mvn/maven.config` key set to a different value is preserved
    /// (never overridden) and a conflict warning is emitted.
    #[test]
    fn maven_pom_trusted_checksums_conflict() {
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        files.insert(
            ".mvn/maven.config".to_string(),
            "-Daether.trustedChecksumsSource.summaryFile.originAware=true\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        let config = r.files.get(".mvn/maven.config").expect("config");
        assert!(
            config.contains("originAware=true"),
            "user value kept: {config}"
        );
        assert!(!config.contains("originAware=false"), "ours NOT written");
        assert!(warning_codes(&r).contains(&"redirect_maven_trusted_checksums_conflict"));
    }

    /// Legacy same-GAV fallback (no suffixed version): only the repository is
    /// added, no `.mvn` files, and the same_gav_fallback warning is emitted.
    #[test]
    fn maven_pom_legacy_same_gav_fallback() {
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        let out = r.files.get("pom.xml").expect("repo added");
        assert!(out.contains("<id>socket-patch-uuid</id>"));
        assert!(out.contains("<version>1.7.36</version>"), "base GAV kept");
        assert!(!r.files.contains_key(".mvn/maven.config"));
        assert!(!r.files.contains_key(".mvn/checksums/checksums.sha256"));
        assert!(warning_codes(&r).contains(&"redirect_maven_same_gav_fallback"));
        let kinds: Vec<&str> = r.edits.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["redirect_maven_repository"]);
    }

    /// A present Gradle build script yields a paste-able snippet pinning the
    /// SUFFIXED version, with no file edits.
    #[test]
    fn maven_pom_gradle_manual_snippet() {
        let mut files = BTreeMap::new();
        files.insert(
            "build.gradle".to_string(),
            "plugins { id 'java' }\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(warning_codes(&r), vec!["redirect_gradle_manual_snippet"]);
        let detail = &r.warnings[0].detail;
        assert!(
            detail.contains(&format!(
                "includeVersion(\"org.slf4j\", \"slf4j-api\", \"{MAVEN_SUFFIXED}\")"
            )),
            "snippet pins the suffixed version: {detail}"
        );
        assert!(
            detail.contains("bump the org.slf4j:slf4j-api dependency declaration"),
            "snippet reminds to bump the declaration: {detail}"
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

    fn berry_override(name: &str, version: &str, url: &str, checksum: &str) -> DepOverride {
        DepOverride {
            integrity: Integrity {
                yarn_berry10c0: Some(checksum.into()),
                ..Default::default()
            },
            ..npm_override(name, version, url, "sha512-x==")
        }
    }

    fn berry_lock(cache_key: &str) -> String {
        format!(
            "# header\n\n__metadata:\n  version: 8\n  cacheKey: {cache_key}\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
             checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
            "3".repeat(128)
        )
    }

    #[test]
    fn yarn_berry_warning_branches() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);

        // A classic (v1) lock is declined silently — the classic rewriter owns it.
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://x/lp.tgz\"\n  \
             integrity sha512-y==\n"
                .to_string(),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(
            r.files.is_empty() && r.warnings.is_empty(),
            "classic declined"
        );

        // Unsupported cacheKey → refusal.
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), berry_lock("8c0"));
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_yarn_berry_cache_unsupported");

        // .yarnrc.yml compressionLevel != 0 → refusal.
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), berry_lock("10c0"));
        files.insert(
            ".yarnrc.yml".to_string(),
            "compressionLevel: 9\n".to_string(),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_yarn_berry_cache_unsupported");

        // Missing yarnBerry10c0 checksum → per-dep warning.
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), berry_lock("10c0"));
        let no_checksum = DepOverride {
            integrity: Integrity::default(),
            ..ovr.clone()
        };
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, &[no_checksum], &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_yarn_berry_missing_checksum");

        // No npm: entry for the dep → not-found warning.
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(
            &files,
            &[berry_override(
                "right-pad",
                "9.9.9",
                "http://p.test/rp.tgz",
                &checksum,
            )],
            &mut r,
        );
        assert_eq!(r.warnings[0].code, "redirect_yarn_berry_entry_not_found");

        // A genuinely mixed-name multi-descriptor key → ambiguous, skip block.
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"left-pad@npm:^1.3.0, right-pad@npm:^1.0.0\":\n  version: 1.3.0\n  \
                 resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  languageName: node\n  \
                 linkType: hard\n",
                "3".repeat(128)
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, &[ovr], &mut r);
        assert!(r.files.is_empty());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_yarn_berry_ambiguous_entry"));
    }

    fn bun_lock_file(entry: &str, version: u64) -> String {
        format!(
            "{{\n  \"lockfileVersion\": {version},\n  \"packages\": {{\n    {entry}\n  }}\n}}\n"
        )
    }

    #[test]
    fn bun_lock_warning_branches() {
        let sha512 = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &sha512);

        // bun.lockb without a bun.lock → presence-only refusal (never parsed).
        let mut files = BTreeMap::new();
        files.insert("bun.lockb".to_string(), "BINARY-NEVER-PARSED".to_string());
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_lockb_unsupported");

        // Both present → text lock wins, no lockb warning.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"]",
                1,
            ),
        );
        files.insert("bun.lockb".to_string(), "BINARY".to_string());
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.contains_key("bun.lock"));
        assert!(!r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_bun_lockb_unsupported"));

        // Unsupported lockfileVersion → refusal.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"]",
                2,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_lock_unsupported");

        // Non-single-line packages section → fail-closed refusal.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"left-pad\": [\n      \
             \"left-pad@1.3.0\"\n    ],\n  }\n}\n"
                .to_string(),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_lock_unsupported");

        // Missing sha512 → per-dep warning.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"]",
                1,
            ),
        );
        let no_sha = DepOverride {
            integrity: Integrity::default(),
            ..ovr
        };
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, &[no_sha], &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_missing_sha512");
        assert_eq!(
            r.warnings.len(),
            1,
            "the sha512 refusal must not double-warn entry-not-found"
        );
    }

    /// A bun.lock already redirected by an earlier run holds a URL 3-tuple —
    /// the registry `name@version` spec is gone — so when the artifact URL
    /// changes (patch republish rotates the uuid segment, token rotation
    /// changes the token) the entry MUST still be re-pinned to the new URL;
    /// exact-URL matching alone stranded the stale pin forever. Ownership is
    /// origin + `<name>-<version>.tgz` leaf, so user URL deps and
    /// other-version artifacts stay untouched.
    #[test]
    fn bun_lock_re_redirects_stale_hosted_url() {
        let old_sha = format!("sha512-{}==", "O".repeat(86));
        let new_sha = format!("sha512-{}==", "N".repeat(86));
        let old_url = "https://patch.socket.dev/patch/npm/oldtoken-1111/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz";
        let new_url = "https://patch.socket.dev/patch/npm/newtoken-2222/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/left-pad-1.3.0.tgz";
        let ovr = npm_override("left-pad", "1.3.0", new_url, &new_sha);

        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                &format!("\"left-pad\": [\"left-pad@{old_url}\", {{}}, \"{old_sha}\"],"),
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r
            .files
            .get("bun.lock")
            .expect("stale URL must be re-pinned");
        assert!(
            out.contains(&format!("\"left-pad@{new_url}\"")) && !out.contains(old_url),
            "entry must carry the NEW artifact URL: {out}"
        );
        assert!(out.contains(&new_sha) && !out.contains(&old_sha));
        assert!(
            r.warnings.is_empty(),
            "re-pin is not a warning case: {:?}",
            r.warnings
        );
        assert_eq!(r.edits.len(), 1);

        // Idempotent: a second run over the re-pinned lock is a no-op.
        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), out.clone());
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty(), "same-URL rerun must stay a no-op");
        assert!(r.warnings.is_empty());

        // A user's own URL dep (different origin, same leaf) is never claimed.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                &format!(
                    "\"left-pad\": [\"left-pad@https://example.com/mirror/left-pad-1.3.0.tgz\", {{}}, \"{old_sha}\"],"
                ),
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(
            r.files.is_empty(),
            "foreign-origin URL dep must not be touched"
        );
        assert_eq!(r.warnings[0].code, "redirect_bun_entry_not_found");

        // Our origin but ANOTHER version's leaf is never claimed either.
        let other_version_url = "https://patch.socket.dev/patch/npm/oldtoken-1111/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.2.0.tgz";
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                &format!("\"left-pad\": [\"left-pad@{other_version_url}\", {{}}, \"{old_sha}\"],"),
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(
            r.files.is_empty(),
            "other-version tuple must not be touched"
        );
        assert_eq!(r.warnings[0].code, "redirect_bun_entry_not_found");
    }

    /// A granted dep that matches no rewritable tuple (lock re-resolved to a
    /// different version) must warn — mirroring pnpm/berry/uv — instead of
    /// silently dropping out of the `redirected` count.
    #[test]
    fn bun_lock_entry_not_found_warns() {
        let sha512 = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &sha512);

        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@1.2.0\", \"\", {}, \"sha512-OLD==\"],",
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_entry_not_found");
        assert!(
            r.warnings[0].detail.contains("left-pad@1.3.0"),
            "the warning must name the missing dep: {}",
            r.warnings[0].detail
        );

        // A successful rewrite emits NO warning.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],",
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.contains_key("bun.lock"));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// A packages header spelled any way other than bun's byte-exact emitted
    /// shape must fail CLOSED with the unsupported warning — not parse as an
    /// empty lock and silently skip the dep.
    #[test]
    fn bun_lock_noncanonical_packages_header_fails_closed() {
        let sha512 = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &sha512);

        for lock in [
            // Tab-indented header.
            "{\n  \"lockfileVersion\": 1,\n\t\"packages\": {\n    \
             \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],\n\t}\n}\n",
            // 4-space re-indent.
            "{\n  \"lockfileVersion\": 1,\n    \"packages\": {\n    \
             \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],\n    }\n}\n",
            // Space before the colon.
            "{\n  \"lockfileVersion\": 1,\n  \"packages\" : {\n    \
             \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],\n  }\n}\n",
        ] {
            let mut files = BTreeMap::new();
            files.insert("bun.lock".to_string(), lock.to_string());
            let mut r = RewriteResult::default();
            rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
            assert!(r.files.is_empty(), "must not rewrite: {lock}");
            assert_eq!(
                r.warnings[0].code, "redirect_bun_lock_unsupported",
                "non-canonical header must refuse, not read as empty: {lock}"
            );
        }
    }

    /// A realistic uv.lock block carries BOTH an `sdist` entry and a `wheels`
    /// entry. Every `{ url, hash }` in the block must be repointed at the
    /// hosted patch: uv PREFERS a wheel, so leaving `wheels` at the upstream
    /// URL/hash makes the install silently use the UNPATCHED artifact while
    /// the scan confirms the dep as redirected (the artifact URL landed in
    /// the sdist slot).
    #[test]
    fn uv_lock_sdist_and_wheels_all_repointed() {
        let lock = "version = 1\nrequires-python = \">=3.8\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.28.1\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/aa/requests-2.28.1.tar.gz\", hash = \"sha256:aaaa\" }\nwheels = [\n    { url = \"https://files.pythonhosted.org/packages/bb/requests-2.28.1-py3-none-any.whl\", hash = \"sha256:bbbb\" },\n]\n";
        let mut files = BTreeMap::new();
        files.insert("uv.lock".to_string(), lock.to_string());
        let url = "http://patch.test/requests-2.28.1-py3-none-any.whl";
        let overrides = vec![pypi_override("requests", "2.28.1", url, &"c".repeat(64))];
        let first = rewrite_registry_redirect(&files, &overrides);
        let out = first.files.get("uv.lock").expect("uv.lock rewritten");
        assert!(
            !out.contains("files.pythonhosted.org"),
            "no upstream URL may survive for the redirected dep: {out}"
        );
        assert_eq!(
            out.matches(url).count(),
            2,
            "sdist AND wheel repointed: {out}"
        );
        assert_eq!(
            out.matches(&format!("hash = \"sha256:{}\"", "c".repeat(64)))
                .count(),
            2,
            "both hashes pinned: {out}"
        );

        // Re-run over the rewritten output: a no-op, and NOT reported as
        // entry-not-found (the entry exists — it is already redirected).
        let mut again = files.clone();
        again.insert("uv.lock".to_string(), out.clone());
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "re-run must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
        assert!(
            !second
                .warnings
                .iter()
                .any(|w| w.code == "redirect_uv_entry_not_found"),
            "already-redirected must not warn entry-not-found: {:?}",
            second.warnings
        );
    }

    fn cargo_sparse_override() -> DepOverride {
        DepOverride {
            ecosystem: "cargo".into(),
            name: "serde".into(),
            namespace: None,
            version: "1.0.190".into(),
            token: "tok".into(),
            patch_uuid: "uuid".into(),
            artifact_url: "https://patch.test/serde-1.0.190.crate".into(),
            berry_zip_url: None,
            registry_override: Some(RegistryOverride {
                kind: "cargo-sparse".into(),
                index_url: "sparse+https://patch.test/cargo/uuid/".into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: "serde".into(),
                    version: "1.0.190".into(),
                    cargo_cksum_sha256: Some("e".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity::default(),
        }
    }

    /// A re-run over already-redirected cargo output must be SILENT: the
    /// Cargo.toml dep already carries `registry = "socket-patch-…"`, which is
    /// "already redirected", not "dependency missing" — warning
    /// `redirect_cargo_toml_dep_not_found` on every re-run is false and sends
    /// the operator hunting for a [dependencies] entry that exists.
    #[test]
    fn cargo_rerun_over_redirected_output_is_silent() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
                .to_string(),
        );
        files.insert(
            "Cargo.lock".to_string(),
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"91f70896d6720bc714a4a57d22fc91f1db634680e65c8efe13323f1fa38d53f5\"\n"
                .to_string(),
        );
        let overrides = vec![cargo_sparse_override()];
        let first = rewrite_registry_redirect(&files, &overrides);
        assert!(!first.edits.is_empty(), "first pass records edits");
        assert!(first.warnings.is_empty(), "{:?}", first.warnings);

        let mut again = files.clone();
        for (name, content) in &first.files {
            again.insert(name.clone(), content.clone());
        }
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "re-run must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
        assert!(
            second.warnings.is_empty(),
            "re-run over redirected output must not warn: {:?}",
            second.warnings
        );
    }

    /// A project carrying the LEGACY extensionless `.cargo/config` must have
    /// the managed `[registries.socket-patch-…]` block written into THAT file.
    /// When both spellings exist cargo reads `config` (and warns), so a block
    /// parked in `config.toml` is silently inert: the `registry =
    /// "socket-patch-…"` the rewriter puts in Cargo.toml then names an
    /// undefined registry and the build breaks — while the run still reports
    /// the dep redirected (the index URL "landed in a file") and attests it.
    /// Same invariant the vendor path enforces in `vendor::cargo_config`.
    #[test]
    fn cargo_legacy_config_is_the_file_edited() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
                .to_string(),
        );
        files.insert(
            "Cargo.lock".to_string(),
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"91f70896d6720bc714a4a57d22fc91f1db634680e65c8efe13323f1fa38d53f5\"\n"
                .to_string(),
        );
        files.insert(
            ".cargo/config".to_string(),
            "[net]\nretry = 3\n".to_string(),
        );

        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let written = r.files.get(".cargo/config").unwrap_or_else(|| {
            panic!(
                "the legacy `.cargo/config` is the file cargo reads; got {:?}",
                r.files.keys().collect::<Vec<_>>()
            )
        });
        assert!(
            written.contains("[registries.socket-patch-uuid]"),
            "registry definition must land in the legacy config: {written}"
        );
        assert!(
            written.contains("retry = 3"),
            "the user's existing config must be preserved, not clobbered: {written}"
        );
        assert!(
            !r.files.contains_key(".cargo/config.toml"),
            "no shadowed config.toml may be created alongside the legacy config: {:?}",
            r.files.keys().collect::<Vec<_>>()
        );
        assert!(
            r.edits
                .iter()
                .any(|e| e.path == ".cargo/config" && e.kind == "redirect_cargo_registry"),
            "the recorded edit must name the file actually written (revert target): {:?}",
            r.edits.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
    }

    /// The default (no legacy file) shape is unchanged: `.cargo/config.toml`.
    #[test]
    fn cargo_config_toml_is_the_default_target() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.contains_key(".cargo/config.toml"));
        assert!(!r.files.contains_key(".cargo/config"));
    }

    fn gem_override(name: &str, version: &str) -> DepOverride {
        DepOverride {
            ecosystem: "gem".into(),
            name: name.into(),
            namespace: None,
            version: version.into(),
            token: "tok".into(),
            patch_uuid: "uuid".into(),
            artifact_url: format!("https://patch.test/{name}-{version}.gem"),
            berry_zip_url: None,
            registry_override: Some(RegistryOverride {
                kind: "rubygems-compact-index".into(),
                index_url: "https://patch.test/gem/tok/uuid/".into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: name.into(),
                    version: version.into(),
                    gem_checksum_sha256: Some("f".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity::default(),
        }
    }

    /// Trailing options on the original `gem` line (`require: false`,
    /// `group: …`) must survive the move into the source block — dropping
    /// `require: false` auto-requires the gem at boot, changing app behavior
    /// (e.g. rack-mini-profiler enables itself globally when required).
    #[test]
    fn gemfile_rewrite_preserves_trailing_options() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rack-mini-profiler\", \"3.1.0\", require: false\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rack-mini-profiler", "3.1.0")]);
        let out = r.files.get("Gemfile").expect("Gemfile rewritten");
        assert!(
            out.contains("  gem \"rack-mini-profiler\", \"3.1.0\", require: false\n"),
            "options preserved inside the source block: {out}"
        );
    }

    /// A minimal Gemfile.lock with the given CHECKSUMS lines (rails 7.0.0).
    fn gem_lock(checksums: &str) -> String {
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\n\
             CHECKSUMS\n{checksums}\n\nBUNDLED WITH\n   2.6.2\n"
        )
    }

    /// The edit must splice by the regex match's byte range: a substring
    /// replace of the matched line's TEXT finds an identical commented-out
    /// duplicate earlier in the file first and corrupts the comment while the
    /// live line keeps resolving upstream.
    #[test]
    fn gemfile_rewrite_ignores_commented_duplicate() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\
             # gem \"rails\", \"7.0.0\" pinned during the 6.x upgrade\n\
             gem \"rails\", \"7.0.0\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let out = r.files.get("Gemfile").expect("Gemfile rewritten");
        assert!(
            out.contains("\n# gem \"rails\", \"7.0.0\" pinned during the 6.x upgrade\n"),
            "commented-out duplicate left untouched: {out}"
        );
        assert!(
            out.contains(
                "\nsource \"https://patch.test/gem/tok/uuid/\" do\n  gem \"rails\", \"7.0.0\"\nend\n"
            ),
            "live line replaced by the source block: {out}"
        );
    }

    /// The grant token in the index URL rotates per request, so a re-run must
    /// recognize the source block a previous run wrote (token-wildcard match,
    /// not exact URL) and refresh its URL in place — never wrap the block's
    /// gem line inside a new nested block.
    #[test]
    fn gemfile_rerun_with_rotated_grant_updates_url_never_nests() {
        fn ov(token: &str) -> DepOverride {
            let mut o = gem_override("rails", "7.0.0");
            o.token = token.into();
            if let Some(r) = o.registry_override.as_mut() {
                r.index_url = format!("https://patch.test/gem/{token}/uuid/");
            }
            o
        }
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        let first = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        let redirected = first.files.get("Gemfile").expect("first run rewrites");
        files.insert("Gemfile".to_string(), redirected.clone());

        let second = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        let out = second
            .files
            .get("Gemfile")
            .expect("rotated grant refreshes the URL");
        assert_eq!(
            out.matches("source \"https://patch.test/gem/").count(),
            1,
            "exactly one Socket source block, never nested: {out}"
        );
        assert!(
            out.contains(
                "source \"https://patch.test/gem/tok-two/uuid/\" do\n  gem \"rails\", \"7.0.0\"\nend"
            ),
            "URL refreshed in place: {out}"
        );
        assert!(!out.contains("tok-one"), "old grant token gone: {out}");
        assert!(
            second
                .edits
                .iter()
                .any(|e| e.kind == "redirect_gemfile_source_url"
                    && e.original
                        == Some(Value::String("https://patch.test/gem/tok-one/uuid/".into()))),
            "URL refresh recorded with the old URL as original: {:?}",
            second.edits
        );

        // Same grant again: a true no-op.
        files.insert("Gemfile".to_string(), out.clone());
        let third = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        assert!(
            third.files.is_empty() && third.edits.is_empty(),
            "same-grant re-run must be a no-op: files={:?} edits={:?}",
            third.files.keys(),
            third.edits
        );
    }

    /// A `core.autocrlf` checkout rewrites a previously-redirected Gemfile to
    /// CRLF. The block recognizer must still see the Socket source block
    /// there: if it misses, the indented `gem` line inside the block matches
    /// `gem_line_re` and gets wrapped in a second, nested source block.
    #[test]
    fn gemfile_rerun_on_crlf_checkout_never_nests() {
        fn ov(token: &str) -> DepOverride {
            let mut o = gem_override("rails", "7.0.0");
            o.token = token.into();
            if let Some(r) = o.registry_override.as_mut() {
                r.index_url = format!("https://patch.test/gem/{token}/uuid/");
            }
            o
        }
        // The block exactly as run 1 writes it, after a CRLF checkout.
        let crlf_gemfile = "source \"https://rubygems.org\"\r\n\r\n\
             source \"https://patch.test/gem/tok-one/uuid/\" do\r\n  \
             gem \"rails\", \"7.0.0\"\r\nend\r\n";
        let mut files = BTreeMap::new();
        files.insert("Gemfile".to_string(), crlf_gemfile.to_string());

        // Same grant: recognized in place, a true no-op.
        let same = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        assert!(
            !same.files.contains_key("Gemfile"),
            "same-grant re-run on a CRLF checkout must not rewrite the Gemfile: {:?}",
            same.files.get("Gemfile")
        );

        // Rotated grant: URL refreshed inside the existing block, never nested.
        let rotated = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        let out = rotated
            .files
            .get("Gemfile")
            .expect("rotated grant refreshes the URL on a CRLF checkout");
        assert_eq!(
            out.matches("source \"https://patch.test/gem/").count(),
            1,
            "exactly one Socket source block, never nested: {out}"
        );
        assert!(!out.contains("tok-one"), "old grant token gone: {out}");
        assert!(
            out.contains("source \"https://patch.test/gem/tok-two/uuid/\" do\r\n"),
            "existing CRLF block body left intact: {out}"
        );
    }

    /// A gem-level source option (`git:` / `path:` / `github:` / `source:`)
    /// preserved into the Socket source block OVERRIDES it in bundler's DSL,
    /// leaving the redirect a silent no-op that still gets attested. Fail
    /// closed: warn and leave both files untouched.
    #[test]
    fn gemfile_gem_with_source_option_fails_closed() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\n\
             gem \"rails\", \"7.0.0\", git: \"https://github.com/rails/rails\"\n"
                .to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "source-selecting option must skip the redirect: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_source_option"),
            "skip must warn: {:?}",
            r.warnings
        );
    }

    /// Platform-specific CHECKSUMS siblings (`rails (7.0.0-arm64-darwin)`)
    /// mean bundler resolves a platform gem the patch registry does not
    /// serve — the bare-platform pin would leave the platform line at the
    /// upstream sha (or duplicate the bare line). Fail closed: skip the dep.
    #[test]
    fn gem_platform_checksums_fail_closed() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!(
                "  rails (7.0.0) sha256={}\n  rails (7.0.0-arm64-darwin) sha256={}",
                "2".repeat(64),
                "3".repeat(64)
            )),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "platform gems must skip the whole dep: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_platform_unsupported"),
            "skip must warn: {:?}",
            r.warnings
        );
    }

    /// Legal-but-non-canonical declarations (parenthesized call, tab / double
    /// space after `gem`) must be recognized and rewritten in place — falling
    /// through to the append branch declares the gem twice, which bundler
    /// rejects.
    #[test]
    fn gemfile_paren_and_whitespace_declarations_are_rewritten_not_duplicated() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\n\
             gem(\"rails\", \"7.0.0\", require: false)\n\
             gem\t\"puma\", \"6.0.0\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(
            &files,
            &[
                gem_override("rails", "7.0.0"),
                gem_override("puma", "6.0.0"),
            ],
        );
        let out = r.files.get("Gemfile").expect("Gemfile rewritten");
        assert!(
            out.contains(
                "source \"https://patch.test/gem/tok/uuid/\" do\n  \
                 gem \"rails\", \"7.0.0\", require: false\nend"
            ),
            "paren declaration rewritten with options kept, `)` stripped: {out}"
        );
        assert!(
            !out.contains("gem(\"rails\"") && !out.contains("gem\t\"puma\""),
            "original declarations replaced, not duplicated: {out}"
        );
        assert!(
            out.contains(
                "source \"https://patch.test/gem/tok/uuid/\" do\n  gem \"puma\", \"6.0.0\"\nend"
            ),
            "tab-separated declaration rewritten: {out}"
        );
    }

    /// A declaration the recognizer cannot parse (`gem\"rails\"` — legal ruby,
    /// no separator) must NOT fall through to the append branch: warn and skip
    /// instead of declaring the gem twice.
    #[test]
    fn gemfile_unrecognizable_declaration_fails_closed_no_append() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem\"rails\", \"7.0.0\"\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "unrecognizable declaration must not append a duplicate: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_unrecognized_declaration"),
            "skip must warn: {:?}",
            r.warnings
        );
    }

    /// The CHECKSUMS pin is gated on the Gemfile source redirect being in
    /// place: with no Gemfile in the candidate map, pinning the patched sha
    /// while the gem still resolves upstream guarantees a checksum failure.
    #[test]
    fn gem_lock_pin_gated_on_source_redirect() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "lock pin without a source redirect must be skipped: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_lock_without_source"),
            "skip must warn: {:?}",
            r.warnings
        );
    }

    /// A landed gem redirect breaks bundler frozen/deployment installs (the
    /// lock's GEM section still records the upstream source), so the rewrite
    /// must say so — and only when it actually changed something.
    #[test]
    fn gem_redirect_warns_about_frozen_installs() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let ovr = gem_override("rails", "7.0.0");
        let first = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            first
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_frozen_install"),
            "landed redirect must warn about frozen installs: {:?}",
            first.warnings
        );

        // No-op re-run: nothing landed, so no frozen-install warning.
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            second.files.is_empty()
                && !second
                    .warnings
                    .iter()
                    .any(|w| w.code == "redirect_gem_frozen_install"),
            "a no-op re-run must not warn: files={:?} warnings={:?}",
            second.files.keys(),
            second.warnings
        );
    }

    /// The rewritten CHECKSUMS edit must carry the pre-edit line as
    /// `original` — with `None` the ledger cannot restore the upstream sha on
    /// a future revert.
    #[test]
    fn gem_lock_rewrite_records_original_checksum_line() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let edit = r
            .edits
            .iter()
            .find(|e| e.kind == "redirect_gemfile_lock_checksum" && e.action == "rewritten")
            .expect("lock checksum edit recorded");
        assert_eq!(
            edit.original,
            Some(Value::String(format!(
                "rails (7.0.0) sha256={}",
                "2".repeat(64)
            ))),
            "pre-edit CHECKSUMS line captured for revert"
        );
    }

    /// An unparseable package-lock.json must surface a warning, not silently
    /// skip the npm redirect entirely (missing-lockfile already warns; a
    /// corrupt lockfile is strictly worse and was silent).
    #[test]
    fn npm_unparseable_lockfile_warns() {
        let mut files = BTreeMap::new();
        files.insert("package-lock.json".to_string(), "{ not json".to_string());
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_npm_lock_unparseable"),
            "corrupt lockfile must warn: {:?}",
            r.warnings
        );
    }

    /// pnpm lockfileVersion 9 single-quotes `packages:` keys that begin with
    /// `@` (`'@scope/name@1.0.0':` — YAML forbids a plain scalar starting
    /// with `@`), so the rewriter must match the quoted form too. Without it,
    /// every scoped npm package silently fails to redirect (entry_not_found
    /// warning only) while unscoped deps in the same run succeed.
    #[test]
    fn pnpm_v9_quoted_scoped_key_is_rewritten() {
        let lock = "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      '@socktest/pkg':
        specifier: 1.0.0
        version: 1.0.0

packages:

  '@socktest/pkg@1.0.0':
    resolution: {integrity: sha512-UPSTREAM==}

snapshots:

  '@socktest/pkg@1.0.0': {}
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let ovr = npm_override(
            "@socktest/pkg",
            "1.0.0",
            "http://patch.test/socktest-pkg-1.0.0.tgz",
            "sha512-PATCHED==",
        );
        let first = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        let out = first.files.get("pnpm-lock.yaml").unwrap_or_else(|| {
            panic!(
                "the quoted scoped key must be rewritten; warnings={:?}",
                first.warnings
            )
        });
        assert!(
            out.contains(
                "  '@socktest/pkg@1.0.0':\n    resolution: {integrity: sha512-PATCHED==, \
                 tarball: http://patch.test/socktest-pkg-1.0.0.tgz}"
            ),
            "resolution spliced under the QUOTED key (quotes preserved): {out}"
        );
        assert!(
            !out.contains("sha512-UPSTREAM=="),
            "upstream integrity replaced: {out}"
        );
        assert!(
            first
                .edits
                .iter()
                .any(|e| e.kind == "redirect_pnpm_resolution"
                    && e.key.as_deref() == Some("@socktest/pkg@1.0.0")),
            "edit recorded under the unquoted name@version key: {:?}",
            first.edits
        );

        // Re-run over the rewritten output: no edits, no file changes.
        let mut again = files.clone();
        again.insert("pnpm-lock.yaml".to_string(), out.clone());
        let second = rewrite_registry_redirect(&again, std::slice::from_ref(&ovr));
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "re-run over a redirected scoped entry must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    fn pnpm_v9_lock(name: &str, version: &str) -> String {
        format!(
            "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {name}:
        specifier: {version}
        version: {version}

packages:
  {name}@{version}:
    resolution: {{integrity: sha512-UPSTREAM==}}

snapshots:
  {name}@{version}: {{}}
"
        )
    }

    /// A clean, fully-successful redirect must emit EXACTLY zero rewrite
    /// warnings — for the npm lock AND for a pnpm-only project. The pnpm leg
    /// regressed silently for a long time: `rewrite_npm_lock` pushed a
    /// spurious `redirect_npm_no_lockfile` onto every pnpm/yarn/bun/Rush run
    /// because those projects (correctly) have no package-lock.json.
    #[test]
    fn clean_success_run_emits_no_warnings_for_npm_and_pnpm() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );

        // npm: package-lock.json only.
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
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.contains_key("package-lock.json"),
            "anchor: the npm lock must have been rewritten"
        );
        assert_eq!(
            warning_codes(&r),
            Vec::<&str>::new(),
            "a clean npm success must emit NO warnings"
        );

        // pnpm: pnpm-lock.yaml only — no package-lock.json exists, by design.
        let mut files = BTreeMap::new();
        files.insert(
            "pnpm-lock.yaml".to_string(),
            pnpm_v9_lock("left-pad", "1.3.0"),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.contains_key("pnpm-lock.yaml"),
            "anchor: the pnpm lock must have been rewritten"
        );
        assert_eq!(
            warning_codes(&r),
            Vec::<&str>::new(),
            "a clean pnpm success must emit NO warnings (regression: spurious \
             redirect_npm_no_lockfile)"
        );
    }

    /// The `redirect_npm_no_lockfile` warning is gated on NO npm-family lock
    /// being present at all: yarn-only and Rush nested-pnpm-only projects are
    /// handled by their own rewriters and must not carry npm noise, while a
    /// genuinely lockfile-less project still gets the warning.
    #[test]
    fn npm_no_lockfile_warning_gated_on_sibling_npm_family_locks() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );

        // yarn classic only: rewritten by the yarn rewriter, zero warnings.
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \
             \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#ab\"\n  \
             integrity sha512-UPSTREAM==\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.contains_key("yarn.lock"),
            "anchor: yarn.lock must have been rewritten"
        );
        assert_eq!(
            warning_codes(&r),
            Vec::<&str>::new(),
            "a clean yarn-classic success must emit NO warnings"
        );

        // Rush: only a NESTED pnpm lock (no root lock of any kind).
        let mut files = BTreeMap::new();
        files.insert(
            "common/config/rush/pnpm-lock.yaml".to_string(),
            pnpm_v9_lock("left-pad", "1.3.0"),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.contains_key("common/config/rush/pnpm-lock.yaml"),
            "anchor: the nested Rush lock must have been rewritten"
        );
        assert_eq!(
            warning_codes(&r),
            Vec::<&str>::new(),
            "a clean Rush success must emit NO warnings"
        );

        // No lockfile anywhere: the warning still fires (unchanged contract).
        let files = BTreeMap::new();
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            warning_codes(&r).contains(&"redirect_npm_no_lockfile"),
            "a lockfile-less project must still warn: {:?}",
            r.warnings
        );
    }

    /// A CRLF berry lock must be diagnosed as a line-ending problem, not as
    /// `cacheKey is \`(missing)\`` — the lock's cacheKey IS 10c0; only the
    /// `\n\n` block grammar fails on `\r\n\r\n`. Fail-closed either way.
    #[test]
    fn berry_crlf_lock_diagnosed_as_crlf_not_missing_cache_key() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            berry_lock("10c0").replace('\n', "\r\n"),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty(), "CRLF lock must not be rewritten");
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_yarn_berry_crlf_unsupported"],
            "the refusal must name CRLF, not the cache key: {:?}",
            r.warnings
        );
        assert!(
            r.warnings[0].detail.contains("CRLF"),
            "detail must name the line endings: {}",
            r.warnings[0].detail
        );
    }

    /// A CRLF pnpm lock gets a dedicated CRLF warning instead of the
    /// misleading per-dep `redirect_pnpm_entry_not_found` (the entry exists;
    /// only the LF-anchored grammar cannot see it). Fail-closed either way.
    #[test]
    fn pnpm_crlf_lock_gets_dedicated_crlf_warning() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );
        let mut files = BTreeMap::new();
        files.insert(
            "pnpm-lock.yaml".to_string(),
            pnpm_v9_lock("left-pad", "1.3.0").replace('\n', "\r\n"),
        );
        let mut r = RewriteResult::default();
        rewrite_pnpm_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty(), "CRLF lock must not be rewritten");
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_pnpm_crlf_unsupported"],
            "the refusal must name CRLF, not entry-not-found: {:?}",
            r.warnings
        );
        assert!(
            r.warnings[0].detail.contains("pnpm-lock.yaml")
                && r.warnings[0].detail.contains("CRLF"),
            "detail must name the file and the line endings: {}",
            r.warnings[0].detail
        );
    }
}
