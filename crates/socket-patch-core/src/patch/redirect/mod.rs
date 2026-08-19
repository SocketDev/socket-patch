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

use crate::crawlers::composer_crawler::normalize_version;
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::vendor::yarn_berry_lock::yarnrc_compression_level;

pub mod golang_local;
mod state;
mod takeover;
pub use state::{
    drop_superseded_purl, load_redirect_state, persist_redirect_state, save_redirect_state,
    CorruptRedirectState, RedirectState, REDIRECT_STATE_REL,
};
pub use takeover::{
    redirect_revert_supported, revert_cargo_redirect_purl, revert_npm_redirect_purl,
    revert_redirect_purl, CargoRedirectRevert, RedirectRevert,
};

/// One ecosystem's integrity hashes (mirrors the TS `PatchArtifactIntegrity`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Integrity {
    pub sha512: Option<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub dirhash_h1: Option<String>,
    /// go.sum's second line for a Go module: `h1:` dirhash of the SERVED
    /// `/@v/<version>.mod` bytes (x/mod `HashGoMod`, i.e. `Hash1` over the
    /// single entry `go.mod`). Both this and `dirhash_h1` are required before
    /// the golang rewriter will touch anything — under `-mod=readonly` a
    /// missing go.sum line is a hard build error on every other machine.
    pub go_mod_h1: Option<String>,
    pub yarn_berry10c0: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryOverrideIdentifiers {
    pub name: String,
    pub version: String,
    pub cargo_cksum_sha256: Option<String>,
    /// Module path of the Socket-published patched Go module — grant-free and
    /// content-addressed under `go_mod_edit::HOSTED_GO_MODULE_PREFIX`
    /// (`patch.socket.dev/gopatch/<patch-uuid>`), served over the standard
    /// GOPROXY protocol. The rewriter fails closed on any path outside that
    /// namespace: the prefix is the only ownership signal a module-to-module
    /// `replace` (and its go.sum lines) carries.
    pub go_module_path: Option<String>,
    /// Version the Socket Go module is published under (the replace RHS,
    /// `<base>-socketpatch.<n>`). Always in the v0/v1 range regardless of the
    /// original's major version — a v2+ RHS would force a `/v2` module-path
    /// suffix, and the RHS version need not relate to the original's.
    pub go_module_version: Option<String>,
    /// `h1:` dirhash of the gopatch-flavor module zip. Rides the override's
    /// identifiers — NOT the tarball artifact's integrity, whose `dirhashH1`
    /// stays the original-path flavor for vendor-mode verification (the h1
    /// hashes entry NAMES, so the two flavors hash differently). The
    /// DepOverride builder merges it into `integrity.dirhash_h1` for the
    /// rewriter.
    pub go_zip_dirhash_h1: Option<String>,
    /// `h1:` dirhash of the served `.mod` bytes (x/mod `HashGoMod`) — the
    /// consumer's `/go.mod h1:` go.sum line. Merged into
    /// `integrity.go_mod_h1` alongside [`Self::go_zip_dirhash_h1`].
    pub go_mod_h1: Option<String>,
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
/// `PartialEq` so the ledger merge can skip byte-identical edits a retried
/// run re-plans (the ledger persists BEFORE the lockfile writes, so a
/// failed write's edit is re-planned by the retry).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Patch uuids whose cargo redirect FULLY landed — the Cargo.toml pin plus
    /// (when a Cargo.lock is present) the lock repoint, with the registry
    /// block wired in — whether written by this run or already in place from
    /// an earlier one. The cargo rewrite is transactional per dependency:
    /// a dep that is not in this set had NOTHING written for it. Hosted-mode
    /// confirmation MUST key off this set for cargo deps, never off substring
    /// presence in rewritten files (a `[registries.…]` config block alone
    /// pins nothing).
    pub confirmed_cargo_uuids: std::collections::BTreeSet<String>,
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
    rewrite_golang(files, overrides, &mut result);
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
            // Family selection is marker-aware: `shrinkwrap.yaml` is the
            // pnpm <=2-era lock (pnpm 3 renamed it to pnpm-lock.yaml; npm
            // never emits that filename), and `node_modules/.modules.yaml`
            // is pnpm's installer state file — either one proves the
            // project is pnpm, where the npm "no package-lock.json"
            // wording sends users to the wrong package manager. Both are
            // read-only markers handed in via the CLI's candidate list; no
            // rewriter edits them. The shrinkwrap check runs first so a
            // fresh clone (shrinkwrap.yaml committed, node_modules absent)
            // still names the legacy lock.
            let warning = if files.contains_key("shrinkwrap.yaml") {
                RewriteWarning {
                    code: "redirect_pnpm_legacy_lockfile".into(),
                    detail: "shrinkwrap.yaml is the pnpm <=2-era lockfile; the \
                             redirect only rewrites pnpm-lock.yaml — upgrade pnpm \
                             (>=3) and reinstall so it emits pnpm-lock.yaml, then \
                             re-run"
                        .into(),
                }
            } else if files.contains_key("node_modules/.modules.yaml") {
                RewriteWarning {
                    code: "redirect_pnpm_no_lockfile".into(),
                    detail: "pnpm project (node_modules/.modules.yaml present) but \
                             no pnpm-lock.yaml; run `pnpm install` to generate one, \
                             then re-run"
                        .into(),
                }
            } else {
                RewriteWarning {
                    code: "redirect_npm_no_lockfile".into(),
                    detail: "no package-lock.json / npm-shrinkwrap.json present".into(),
                }
            };
            result.warnings.push(warning);
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
        let mut matched_any = false;
        if let Some(packages) = lock.get_mut("packages").and_then(Value::as_object_mut) {
            for (key, entry) in packages.iter_mut() {
                // Only `node_modules/` keys are installable dependencies:
                // "" is the project root and other bare keys are workspace
                // members — SOURCE dirs a resolved/integrity insert would
                // corrupt.
                let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
                    continue;
                };
                // The package a lock entry stands for: the explicit `name`
                // field when present (npm writes it for aliases — `npm i
                // alias@npm:real` keys the entry by the ALIAS), else the
                // key's trailing path. Mirrors `vendor::npm_lock`'s
                // `entry_name`, so an alias install of the patched package
                // redirects and an entry that merely SHARES the key name
                // (`npm i <fname>@npm:other`) is never hijacked.
                let entry_nm = entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(key_name);
                let matches_ver =
                    entry.get("version").and_then(Value::as_str) == Some(dep.version.as_str());
                if entry_nm != fname || !matches_ver {
                    continue;
                }
                if entry.get("link").and_then(Value::as_bool) == Some(true) {
                    matched_any = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_npm_link_entry_skipped".into(),
                        detail: format!(
                            "lock entry `{key}` is a link (npm workspaces/file: dir); skipped"
                        ),
                    });
                    continue;
                }
                // npm reify extracts a bundled copy from its PARENT's tarball
                // and ignores the entry's resolved/integrity, so a rewrite
                // here would put the hosted URL in the lockfile (confirming
                // and VEX-attesting the patch) while the unpatched bundled
                // bytes keep installing. Mirrors the vendored backend's
                // `vendor_bundled_instance_skipped` refusal.
                if entry.get("inBundle").and_then(Value::as_bool) == Some(true) {
                    matched_any = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_npm_bundled_instance_skipped".into(),
                        detail: format!(
                            "lock entry `{key}` is bundled inside its parent's tarball and \
                             CANNOT be redirected — that copy stays UNPATCHED; vendor or \
                             update the bundling parent to cover it"
                        ),
                    });
                    continue;
                }
                matched_any = true;
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
        // v2 legacy `dependencies` tree (keyed by name), recursive.
        if let Some(deps) = lock.get_mut("dependencies").and_then(Value::as_object_mut) {
            changed = rewrite_npm_v2_deps(
                deps,
                &fname,
                dep,
                &sha512,
                lockfile,
                result,
                &mut matched_any,
            ) || changed;
        }
        // Parity with the pnpm/berry/uv rewriters: a granted dep the
        // lockfile cannot pin must be SAID, not silently dropped from the
        // redirected count.
        if !matched_any {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_entry_not_found".into(),
                detail: format!("no {lockfile} entry for {fname}@{}", dep.version),
            });
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
    matched_any: &mut bool,
) -> bool {
    let mut changed = false;
    for (name, entry) in deps.iter_mut() {
        if name == fname
            && entry.get("version").and_then(Value::as_str) == Some(dep.version.as_str())
        {
            // Legacy spelling of `inBundle`: same npm-ignores-the-rewrite
            // fail-open as the `packages` guard above.
            if entry.get("bundled").and_then(Value::as_bool) == Some(true) {
                *matched_any = true;
                result.warnings.push(RewriteWarning {
                    code: "redirect_npm_bundled_instance_skipped".into(),
                    detail: format!(
                        "legacy dependencies entry `{name}` is bundled inside its parent's \
                         tarball and CANNOT be redirected — that copy stays UNPATCHED; vendor \
                         or update the bundling parent to cover it"
                    ),
                });
            } else {
                *matched_any = true;
                if let Some(edit) =
                    rewrite_npm_entry(entry, dep, sha512, lockfile, "redirect_npm_lock_dep", name)
                {
                    result.edits.push(edit);
                    changed = true;
                }
            }
        }
        if let Some(nested) = entry.get_mut("dependencies").and_then(Value::as_object_mut) {
            changed =
                rewrite_npm_v2_deps(nested, fname, dep, sha512, lockfile, result, matched_any)
                    || changed;
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
    let name_re = Regex::new(r"^([A-Za-z0-9._-]+)\s*(?:[=<>~!]=?|@|;|\s|$)")
        .expect("static requirements-name regex is valid");
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
//
// TRANSACTIONAL per dependency: a dep is redirected ONLY if its Cargo.toml pin
// fully lands across EVERY occurrence ([dependencies], [dev-dependencies],
// [build-dependencies], target-specific tables, [workspace.dependencies], and
// the multi-line `[dependencies.<name>]` table form). If any occurrence cannot
// be rewritten — a foreign registry pin, a path/git dependency, an unsupported
// spelling — the dep is skipped ENTIRELY (no lock edit, no config block, no
// confirmation) with one clear warning. A partial edit set (lock repointed
// while the manifest still says crates.io, or an inert `[registries.…]` block
// with nothing referencing it) breaks `--locked` builds or silently drops the
// patch while attesting it — the exact failure mode this shape forbids.
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
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_missing_override".into(),
                detail: format!("{} has no cargo-sparse registry override", dep.name),
            });
            continue;
        }
        // Service-supplied strings are interpolated into raw TOML (a section
        // header, a quoted value) and into Cargo.lock — validate them against
        // their exact expected grammars BEFORE any write, mirroring the
        // vendored path's fail-closed uuid/path checks. A `]`+newline in a
        // patch uuid or a quote in an index URL would otherwise inject
        // arbitrary TOML (e.g. a `[source.crates-io]` replace-with hijacking
        // every crate in the project).
        if !crate::patch::path_safety::is_canonical_uuid(&dep.patch_uuid) {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_invalid_uuid".into(),
                detail: format!(
                    "{} has a malformed patch uuid; dependency skipped",
                    dep.name
                ),
            });
            continue;
        }
        if !is_valid_cargo_index_url(&ov.index_url) {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_invalid_index_url".into(),
                detail: format!(
                    "{} has a malformed sparse index URL; dependency skipped",
                    dep.name
                ),
            });
            continue;
        }
        // An empty-string cksum is MISSING (the TS twin's falsy check), not a
        // value to write into Cargo.lock — `checksum = ""` hard-fails the next
        // `cargo fetch --locked`.
        let Some(cksum) = ov
            .identifiers
            .cargo_cksum_sha256
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| dep.integrity.sha256.clone().filter(|s| !s.is_empty()))
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_missing_cksum".into(),
                detail: format!("{} has no sha256 cksum", dep.name),
            });
            continue;
        };
        if !is_hex64_lower(&cksum) {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_invalid_cksum".into(),
                detail: format!(
                    "{} has a malformed sha256 cksum; dependency skipped",
                    dep.name
                ),
            });
            continue;
        }
        let reg = format!("socket-patch-{}", dep.patch_uuid);
        let index_url = &ov.index_url;

        // 1. Plan the Cargo.toml pin FIRST — it is the gate for everything
        // else. Without a manifest pin nothing forces resolution through the
        // managed registry, so no other file may be touched for this dep.
        let Some(toml_text) = cargo_toml.as_ref() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_toml_dep_not_found".into(),
                detail: format!(
                    "no Cargo.toml present to pin {}; dependency skipped (nothing rewritten)",
                    dep.name
                ),
            });
            continue;
        };
        let toml_plan = match plan_cargo_toml(toml_text, &dep.name, &reg) {
            Ok(plan) => plan,
            Err(CargoTomlPlanError::NotFound) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_cargo_toml_dep_not_found".into(),
                    detail: format!(
                        "no [dependencies] entry for {} in Cargo.toml; dependency skipped \
                         (nothing rewritten)",
                        dep.name
                    ),
                });
                continue;
            }
            Err(CargoTomlPlanError::Refused(reason)) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_cargo_toml_dep_unrewritable".into(),
                    detail: format!(
                        "{} in Cargo.toml cannot be pinned ({reason}); dependency skipped \
                         (nothing rewritten)",
                        dep.name
                    ),
                });
                continue;
            }
        };

        // 2. Plan the Cargo.lock repoint. A lock that exists but has no
        // [[package]] for the dep means the project does not actually resolve
        // it — rewriting the manifest anyway would desync manifest and lock.
        // Skip the dep entirely (discarding the manifest plan). A project
        // with NO lockfile is fine: the manifest pin alone forces the next
        // resolution through the managed registry, which serves the patched
        // checksum.
        enum LockCommit {
            Write(String, Box<FileEdit>),
            InPlace,
            Absent,
        }
        let lock_commit = if let Some(lock_text) = cargo_lock.as_ref() {
            match plan_cargo_lock(lock_text, &dep.name, &dep.version, index_url, &cksum) {
                CargoLockPlan::Rewritten { content, edit } => LockCommit::Write(content, edit),
                CargoLockPlan::AlreadyRedirected => LockCommit::InPlace,
                CargoLockPlan::NotFound => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_cargo_lock_pkg_not_found".into(),
                        detail: format!(
                            "no [[package]] for {}@{} in Cargo.lock; dependency skipped \
                             (nothing rewritten)",
                            dep.name, dep.version
                        ),
                    });
                    continue;
                }
            }
        } else {
            LockCommit::Absent
        };

        // 3. Plan the managed `[registries.…]` block (never fails; `None`
        // when a healthy block is already wired in).
        let config_plan = plan_cargo_config(&cargo_config, cargo_config_key, &reg, index_url);

        // COMMIT — everything planned, nothing can fail past this point, so
        // the three files change together or not at all. Edit order matches
        // the historical ledger order: config, manifest, lock.
        if let Some(plan) = config_plan {
            cargo_config = plan.content;
            result.edits.push(plan.edit);
            config_changed = true;
        }
        if toml_plan.changed {
            cargo_toml = Some(toml_plan.content);
            result.edits.extend(toml_plan.edits);
            toml_changed = true;
        }
        match lock_commit {
            LockCommit::Write(content, edit) => {
                cargo_lock = Some(content);
                result.edits.push(*edit);
                lock_changed = true;
            }
            LockCommit::InPlace | LockCommit::Absent => {}
        }
        result.confirmed_cargo_uuids.insert(dep.patch_uuid.clone());
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

/// Sparse index URLs land verbatim inside quoted TOML strings in both
/// `.cargo/config.toml` and `Cargo.lock` — refuse anything that could break
/// out of the string (quote, backslash escape, control chars) or that is not
/// a sparse+http(s) URL at all.
fn is_valid_cargo_index_url(url: &str) -> bool {
    (url.starts_with("sparse+https://") || url.starts_with("sparse+http://"))
        && !url.contains('"')
        && !url.contains('\\')
        && !url.chars().any(char::is_control)
}

/// Gem index URLs land verbatim inside a quoted Ruby `source "<url>" do`
/// Gemfile string and on unquoted Gemfile.lock `remote:` lines — refuse
/// anything that could break out of either (quote, backslash, whitespace;
/// control chars cover newline injection into the lock) or that is not an
/// http(s) URL at all. Twin of [`is_valid_cargo_index_url`].
fn is_valid_gem_index_url(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://"))
        && !url.contains('"')
        && !url.contains('\\')
        && !url.chars().any(|c| c.is_control() || c == ' ')
}

/// The exact shape `hex::encode(sha256)` / the TS `Buffer.toString('hex')`
/// produce: 64 lowercase hex chars. Anything else written as a Cargo.lock
/// `checksum` breaks the next fetch.
fn is_hex64_lower(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A registry name THIS rewriter owns: `socket-patch-<canonical-uuid>`. An
/// existing pin matching this grammar was written by a previous run and may be
/// superseded in place; any other registry pin is the user's and is refused.
fn is_socket_patch_registry_name(value: &str) -> bool {
    value
        .strip_prefix("socket-patch-")
        .is_some_and(crate::patch::path_safety::is_canonical_uuid)
}

/// Split a TOML table-header path into dot segments, respecting quoted
/// segments (`target.'cfg(unix)'.dependencies`). `None` on unbalanced quotes.
fn split_toml_header_segments(inner: &str) -> Option<Vec<String>> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                segs.push(cur.trim().to_string());
                cur = String::new();
            }
            '"' | '\'' => {
                cur.push(c);
                let mut closed = false;
                for c2 in chars.by_ref() {
                    cur.push(c2);
                    if c2 == c {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return None;
                }
            }
            _ => cur.push(c),
        }
    }
    segs.push(cur.trim().to_string());
    Some(segs)
}

fn strip_toml_key_quotes(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum CargoTomlSection {
    /// `[dependencies]` & friends (dev/build/target-specific) plus
    /// `[workspace.dependencies]` — entries are `key = value` lines.
    DepTable {
        workspace: bool,
    },
    /// The multi-line table form `[dependencies.<key>]` (all variants).
    DepEntry {
        key: String,
        workspace: bool,
    },
    Other,
}

fn is_cargo_dep_kind(seg: &str) -> bool {
    matches!(
        seg,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    )
}

fn classify_cargo_section(header_inner: &str) -> CargoTomlSection {
    let Some(segs) = split_toml_header_segments(header_inner) else {
        return CargoTomlSection::Other;
    };
    let s: Vec<&str> = segs.iter().map(String::as_str).collect();
    match s.as_slice() {
        [k] if is_cargo_dep_kind(k) => CargoTomlSection::DepTable { workspace: false },
        ["workspace", "dependencies"] => CargoTomlSection::DepTable { workspace: true },
        [k, key] if is_cargo_dep_kind(k) => CargoTomlSection::DepEntry {
            key: strip_toml_key_quotes(key),
            workspace: false,
        },
        ["workspace", "dependencies", key] => CargoTomlSection::DepEntry {
            key: strip_toml_key_quotes(key),
            workspace: true,
        },
        ["target", .., k] if is_cargo_dep_kind(k) => {
            CargoTomlSection::DepTable { workspace: false }
        }
        ["target", mid @ .., key] if mid.len() >= 2 && is_cargo_dep_kind(mid[mid.len() - 1]) => {
            CargoTomlSection::DepEntry {
                key: strip_toml_key_quotes(key),
                workspace: false,
            }
        }
        _ => CargoTomlSection::Other,
    }
}

/// Parse the key at the start of a table-entry line: bare (`[A-Za-z0-9_-]+`)
/// or single/double quoted. Returns `(key, rest-after-key)`.
fn parse_cargo_entry_key(line: &str) -> Option<(String, &str)> {
    let b = line.as_bytes();
    match b.first()? {
        b'"' | b'\'' => {
            let quote = b[0] as char;
            let end = line[1..].find(quote)? + 1;
            Some((line[1..end].to_string(), &line[end + 1..]))
        }
        _ => {
            let end = line
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                .unwrap_or(line.len());
            if end == 0 {
                return None;
            }
            Some((line[..end].to_string(), &line[end..]))
        }
    }
}

struct CargoTomlPlan {
    content: String,
    edits: Vec<FileEdit>,
    /// `false` when every occurrence already carried our registry (idempotent
    /// re-run) — the pin is in place, nothing to write.
    changed: bool,
}

enum CargoTomlPlanError {
    /// The crate is not declared anywhere in this manifest (rename-aware:
    /// a key that matches but has `package = "<other>"` is NOT the crate).
    NotFound,
    /// At least one occurrence exists that cannot be pinned to the managed
    /// registry — the whole dep must be skipped.
    Refused(String),
}

/// How one occurrence of the dep will be handled.
enum CargoTomlAction {
    /// `key = "1.0"` → `key = { version = "1.0", registry = "<reg>" }`.
    ReplaceLine { idx: usize, new_text: String },
    /// `[dependencies.key]` table gains a `registry = "<reg>"` line after the
    /// header (recorded as a rewrite of the header line so revert-by-string
    /// replacement restores it).
    InsertAfterHeader { idx: usize, inserted: String },
    /// Already pinned to our registry — nothing to write.
    Already,
    /// `key.workspace = true` / `{ workspace = true }`: satisfied by the
    /// `[workspace.dependencies]` pin in this same manifest.
    InheritsWorkspace,
}

/// Plan the full-manifest pin: EVERY occurrence of `crate_name` across every
/// dependency table gains `registry = "<reg>"`, an existing
/// `socket-patch-<uuid>` pin is superseded in place, and any occurrence that
/// cannot be handled refuses the whole dep. Nothing is applied unless every
/// occurrence resolves.
fn plan_cargo_toml(
    content: &str,
    crate_name: &str,
    reg: &str,
) -> Result<CargoTomlPlan, CargoTomlPlanError> {
    let lines: Vec<&str> = content.split('\n').collect();
    let header_re =
        Regex::new(r"^\[([^\]]+)\]\s*(?:#.*)?$").expect("static section-header regex is valid");
    let package_re =
        Regex::new(r#"\bpackage\s*=\s*"([^"]*)""#).expect("static package-key regex is valid");
    let registry_val_re =
        Regex::new(r#"\bregistry\s*=\s*"([^"]*)""#).expect("static registry-value regex is valid");
    let registry_key_re =
        Regex::new(r"\bregistry\s*=").expect("static registry-key probe regex is valid");
    let registry_index_re =
        Regex::new(r"\bregistry-index\s*=").expect("static registry-index probe regex is valid");
    let workspace_key_re =
        Regex::new(r"\bworkspace\s*=").expect("static workspace-key probe regex is valid");
    let path_git_re =
        Regex::new(r"\b(?:path|git)\s*=").expect("static path/git probe regex is valid");

    // A pending occurrence: what was found, resolved to an action in pass 2
    // (workspace-inheriting entries need the whole file scanned first).
    enum Pending {
        Action(CargoTomlAction),
        NeedsWorkspacePin,
        Refuse(String),
    }
    let mut pending: Vec<Pending> = Vec::new();
    // Whether the `[workspace.dependencies]` entry for the crate lands (or
    // already carries) the pin — satisfies `workspace = true` inheritors.
    let mut workspace_pinned = false;

    let mut section = CargoTomlSection::Other;
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            section = match header_re.captures(trimmed) {
                Some(c) => classify_cargo_section(
                    c.get(1)
                        .expect("header_re always captures group 1 (section name)")
                        .as_str(),
                ),
                None => CargoTomlSection::Other,
            };
            if let CargoTomlSection::DepEntry { key, workspace } = section.clone() {
                let ws = workspace;
                // Table form: examine the whole block now.
                let mut end = lines.len();
                for (j, l) in lines.iter().enumerate().skip(idx + 1) {
                    if l.trim_start().starts_with('[') {
                        end = j;
                        break;
                    }
                }
                let block: Vec<(usize, &str)> = (idx + 1..end)
                    .map(|j| (j, lines[j].trim_start()))
                    .filter(|(_, t)| !t.is_empty() && !t.starts_with('#'))
                    .collect();
                let find_value = |key_name: &str| -> Option<(usize, String)> {
                    for (j, t) in &block {
                        if let Some((k, rest)) = parse_cargo_entry_key(t) {
                            if k == key_name {
                                let rest = rest.trim_start();
                                if let Some(v) = rest.strip_prefix('=') {
                                    let v = v.trim();
                                    let v = v
                                        .strip_prefix('"')
                                        .and_then(|s| s.split('"').next())
                                        .unwrap_or(v);
                                    return Some((*j, v.to_string()));
                                }
                            }
                        }
                    }
                    None
                };
                let package_val = find_value("package").map(|(_, v)| v);
                let is_ours = match &package_val {
                    Some(p) => p == crate_name,
                    None => key == crate_name,
                };
                if !is_ours {
                    continue;
                }
                let has = |name: &str| {
                    block.iter().any(|(_, t)| {
                        parse_cargo_entry_key(t).is_some_and(|(k, rest)| {
                            k == name && rest.trim_start().starts_with('=')
                        })
                    })
                };
                if has("workspace") {
                    pending.push(Pending::NeedsWorkspacePin);
                } else if has("path") || has("git") {
                    pending.push(Pending::Refuse(
                        "declared as a path/git dependency".to_string(),
                    ));
                } else if has("registry-index") {
                    // Inserting `registry = …` next to `registry-index` makes
                    // cargo reject the manifest as ambiguous — refuse, like
                    // the inline-table branch does.
                    pending.push(Pending::Refuse("pinned to another registry".to_string()));
                } else if let Some((line_idx, value)) = find_value("registry") {
                    if value == reg {
                        pending.push(Pending::Action(CargoTomlAction::Already));
                        if ws {
                            workspace_pinned = true;
                        }
                    } else if is_socket_patch_registry_name(&value) {
                        let old_line = lines[line_idx];
                        let new_text = registry_val_re
                            .replace(old_line, format!("registry = \"{reg}\"").as_str())
                            .into_owned();
                        pending.push(Pending::Action(CargoTomlAction::ReplaceLine {
                            idx: line_idx,
                            new_text,
                        }));
                        if ws {
                            workspace_pinned = true;
                        }
                    } else {
                        pending.push(Pending::Refuse(format!(
                            "pinned to another registry (\"{value}\")"
                        )));
                    }
                } else {
                    let indent = &raw[..raw.len() - trimmed.len()];
                    pending.push(Pending::Action(CargoTomlAction::InsertAfterHeader {
                        idx,
                        inserted: format!("{indent}registry = \"{reg}\""),
                    }));
                    if ws {
                        workspace_pinned = true;
                    }
                }
            }
            continue;
        }
        let CargoTomlSection::DepTable { workspace } = section else {
            continue;
        };
        let Some((key, rest)) = parse_cargo_entry_key(trimmed) else {
            continue;
        };
        let rest_trim = rest.trim_start();
        if let Some(dotted) = rest_trim.strip_prefix('.') {
            // Dotted entry (`serde.workspace = true`, `serde.version = "1"`,
            // `alias.package = "serde"`, …).
            let sub = parse_cargo_entry_key(dotted).map(|(k, _)| k);
            if key == crate_name {
                if sub.as_deref() == Some("workspace") {
                    pending.push(Pending::NeedsWorkspacePin);
                } else {
                    pending.push(Pending::Refuse(
                        "declared with dotted keys this rewriter does not edit".to_string(),
                    ));
                }
            } else if sub.as_deref() == Some("package")
                && package_re
                    .captures(trimmed)
                    .is_some_and(|c| &c[1] == crate_name)
            {
                pending.push(Pending::Refuse(
                    "declared with dotted keys this rewriter does not edit".to_string(),
                ));
            }
            continue;
        }
        let Some(value) = rest_trim.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        if value.starts_with('{') {
            // Inline table. Rename-aware: `package = "<other>"` under our key
            // means this entry is NOT the patched crate; `package =
            // "<crate>"` under any key means it IS.
            let Some(close) = value.find('}') else {
                if key == crate_name {
                    pending.push(Pending::Refuse(
                        "inline table does not close on its line".to_string(),
                    ));
                }
                continue;
            };
            let inner = &value[1..close];
            let package_val = package_re.captures(inner).map(|c| c[1].to_string());
            let is_ours = match &package_val {
                Some(p) => p == crate_name,
                None => key == crate_name,
            };
            if !is_ours {
                continue;
            }
            if workspace_key_re.is_match(inner) {
                pending.push(Pending::NeedsWorkspacePin);
            } else if path_git_re.is_match(inner) {
                pending.push(Pending::Refuse(
                    "declared as a path/git dependency".to_string(),
                ));
            } else if let Some(c) = registry_val_re.captures(inner) {
                let value = c[1].to_string();
                if value == reg {
                    pending.push(Pending::Action(CargoTomlAction::Already));
                    if workspace {
                        workspace_pinned = true;
                    }
                } else if is_socket_patch_registry_name(&value) {
                    let new_text = registry_val_re
                        .replace(raw, format!("registry = \"{reg}\"").as_str())
                        .into_owned();
                    pending.push(Pending::Action(CargoTomlAction::ReplaceLine {
                        idx,
                        new_text,
                    }));
                    if workspace {
                        workspace_pinned = true;
                    }
                } else {
                    pending.push(Pending::Refuse(format!(
                        "pinned to another registry (\"{value}\")"
                    )));
                }
            } else if registry_key_re.is_match(inner) || registry_index_re.is_match(inner) {
                pending.push(Pending::Refuse("pinned to another registry".to_string()));
            } else {
                // Rebuild the line: everything through `{`, the trimmed
                // inner, the registry pin, then `}` + any trailing bytes
                // (e.g. a comment). First `{`/`}` in the raw line are the
                // inline table's — keys and indents cannot contain braces.
                let inner_trim = inner.trim_end();
                let sep = if inner_trim.trim().ends_with(',') || inner_trim.trim().is_empty() {
                    ""
                } else {
                    ","
                };
                let brace = raw.find('{').unwrap_or_default();
                let close_raw = raw[brace..].find('}').unwrap_or_default() + brace;
                let new_text = format!(
                    "{}{inner_trim}{sep} registry = \"{reg}\" {}",
                    &raw[..=brace],
                    &raw[close_raw..]
                );
                pending.push(Pending::Action(CargoTomlAction::ReplaceLine {
                    idx,
                    new_text,
                }));
                if workspace {
                    workspace_pinned = true;
                }
            }
        } else if value.starts_with('"') {
            if key != crate_name {
                continue;
            }
            // Plain version: `crate = "1.0"` (+ optional trailing comment).
            // The rewrite is line-scoped, so the trailing newline / blank
            // line after the entry is untouched (the old `\s*$` regex
            // swallowed it).
            let c = regex::escape(crate_name);
            let line_re = Regex::new(&format!(
                r#"^(\s*(?:{c}|"{c}")\s*=\s*)"([^"]+)"([ \t]*(?:#.*)?)$"#
            ))
            .expect("line regex from the escaped crate name is valid");
            let Some(m) = line_re.captures(raw) else {
                pending.push(Pending::Refuse(
                    "unsupported version-entry spelling".to_string(),
                ));
                continue;
            };
            let new_text = format!(
                "{}{{ version = \"{}\", registry = \"{reg}\" }}{}",
                m.get(1)
                    .expect("line_re always captures group 1 (key prefix)")
                    .as_str(),
                m.get(2)
                    .expect("line_re always captures group 2 (version)")
                    .as_str(),
                m.get(3)
                    .expect("line_re always captures group 3 (trailing comment)")
                    .as_str()
            );
            pending.push(Pending::Action(CargoTomlAction::ReplaceLine {
                idx,
                new_text,
            }));
            if workspace {
                workspace_pinned = true;
            }
        } else if key == crate_name {
            pending.push(Pending::Refuse(
                "unsupported dependency-entry spelling".to_string(),
            ));
        }
    }

    if pending.is_empty() {
        return Err(CargoTomlPlanError::NotFound);
    }
    // Resolve: any refusal (including an unsatisfiable `workspace = true`
    // inheritor) refuses the WHOLE dep — no partial pin is ever applied.
    let mut actions: Vec<CargoTomlAction> = Vec::new();
    for p in pending {
        match p {
            Pending::Action(a) => actions.push(a),
            Pending::NeedsWorkspacePin => {
                if workspace_pinned {
                    actions.push(CargoTomlAction::InheritsWorkspace);
                } else {
                    return Err(CargoTomlPlanError::Refused(
                        "inherits from [workspace.dependencies] with no rewritable entry \
                         in this manifest"
                            .to_string(),
                    ));
                }
            }
            Pending::Refuse(reason) => return Err(CargoTomlPlanError::Refused(reason)),
        }
    }

    // Apply bottom-up so line indices stay valid; record edits top-down.
    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    let mut edits: Vec<FileEdit> = Vec::new();
    let mut writes: Vec<(usize, &CargoTomlAction)> = actions
        .iter()
        .filter_map(|a| match a {
            CargoTomlAction::ReplaceLine { idx, .. } => Some((*idx, a)),
            CargoTomlAction::InsertAfterHeader { idx, .. } => Some((*idx, a)),
            CargoTomlAction::Already | CargoTomlAction::InheritsWorkspace => None,
        })
        .collect();
    writes.sort_by_key(|(idx, _)| *idx);
    for (idx, action) in &writes {
        match action {
            CargoTomlAction::ReplaceLine { new_text, .. } => {
                edits.push(FileEdit {
                    path: "Cargo.toml".into(),
                    kind: "redirect_cargo_toml_dep".into(),
                    action: "rewritten".into(),
                    key: Some(crate_name.into()),
                    original: Some(Value::String(lines[*idx].to_string())),
                    new: Some(Value::String(new_text.clone())),
                });
            }
            CargoTomlAction::InsertAfterHeader { inserted, .. } => {
                edits.push(FileEdit {
                    path: "Cargo.toml".into(),
                    kind: "redirect_cargo_toml_dep".into(),
                    action: "rewritten".into(),
                    key: Some(crate_name.into()),
                    original: Some(Value::String(lines[*idx].to_string())),
                    new: Some(Value::String(format!("{}\n{inserted}", lines[*idx]))),
                });
            }
            CargoTomlAction::Already | CargoTomlAction::InheritsWorkspace => {}
        }
    }
    for (idx, action) in writes.iter().rev() {
        match action {
            CargoTomlAction::ReplaceLine { new_text, .. } => {
                new_lines[*idx] = new_text.clone();
            }
            CargoTomlAction::InsertAfterHeader { inserted, .. } => {
                new_lines.insert(idx + 1, inserted.clone());
            }
            CargoTomlAction::Already | CargoTomlAction::InheritsWorkspace => {}
        }
    }
    let changed = !edits.is_empty();
    Ok(CargoTomlPlan {
        content: new_lines.join("\n"),
        edits,
        changed,
    })
}

fn plan_cargo_lock(
    content: &str,
    crate_name: &str,
    version: &str,
    index_url: &str,
    cksum: &str,
) -> CargoLockPlan {
    // Rust's regex has NO lookahead, so bound the [[package]] block by string
    // search: from its header to the next `\n[[package]]` (or EOF), so the
    // trailing bytes after the block (incl. the final newline) are preserved.
    let head = format!("[[package]]\nname = \"{crate_name}\"\nversion = \"{version}\"\n");
    let Some(block_start) = content.find(&head) else {
        return CargoLockPlan::NotFound;
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
    let source_re =
        Regex::new(r#"(?m)^source = "[^"]*"$"#).expect("static lock source-line regex is valid");
    if source_re.is_match(&body) {
        body = source_re
            .replace(&body, format!("source = \"{index_url}\"").as_str())
            .to_string();
    } else {
        body = format!("source = \"{index_url}\"\n{body}");
    }
    let checksum_re = Regex::new(r#"(?m)^checksum = "[^"]*"$"#)
        .expect("static lock checksum-line regex is valid");
    if checksum_re.is_match(&body) {
        body = checksum_re
            .replace(&body, format!("checksum = \"{cksum}\"").as_str())
            .to_string();
    } else {
        let after_source = Regex::new(r#"(?m)^(source = "[^"]*"\n)"#)
            .expect("static source-line anchor regex is valid");
        body = after_source
            .replace(&body, format!("${{1}}checksum = \"{cksum}\"\n").as_str())
            .to_string();
    }
    let rebuilt = format!("{head}{body}");
    // Already redirected (re-run): the block is at the target values; a
    // recorded edit would have original == new and grow the ledger forever.
    if rebuilt == original {
        return CargoLockPlan::AlreadyRedirected;
    }
    let new_content = content.replacen(&original, &rebuilt, 1);
    CargoLockPlan::Rewritten {
        content: new_content,
        edit: Box::new(FileEdit {
            path: "Cargo.lock".into(),
            kind: "redirect_cargo_lock_entry".into(),
            action: "rewritten".into(),
            key: Some(format!("{crate_name}@{version}")),
            original: Some(Value::String(original)),
            new: Some(Value::String(rebuilt)),
        }),
    }
}

/// Outcome of the Cargo.lock `[[package]]` plan — distinguishes a re-run
/// over an already-redirected block (no edit, no warning) from a genuinely
/// missing package (the caller warns AND skips the dep entirely).
enum CargoLockPlan {
    Rewritten {
        content: String,
        edit: Box<FileEdit>,
    },
    AlreadyRedirected,
    NotFound,
}

struct CargoConfigPlan {
    content: String,
    edit: FileEdit,
}

/// Plan the managed `[registries.socket-patch-<uuid>]` block. `None` when a
/// HEALTHY block is already wired in — an uncommented header with an
/// uncommented `index = "<index_url>"` line. Comments never satisfy the
/// check: a user who commented the managed block out gets it restored on the
/// next run (the old substring test matched the commented text, reported
/// success, and left `registry = "socket-patch-…"` in Cargo.toml naming an
/// undefined registry). A degraded block (missing/stale index line) is
/// regenerated in place — it is ours, the header grammar proves it.
fn plan_cargo_config(
    config: &str,
    config_key: &str,
    reg: &str,
    index_url: &str,
) -> Option<CargoConfigPlan> {
    let header = format!("[registries.{reg}]");
    let index_line = format!("index = \"{index_url}\"");
    let lines: Vec<&str> = config.split('\n').collect();
    let header_idx = lines.iter().position(|l| l.trim() == header);
    if let Some(i) = header_idx {
        let mut end = lines.len();
        for (j, l) in lines.iter().enumerate().skip(i + 1) {
            if l.trim_start().starts_with('[') {
                end = j;
                break;
            }
        }
        // Keep trailing blank separator lines out of the managed region.
        while end > i + 1 && lines[end - 1].trim().is_empty() {
            end -= 1;
        }
        let healthy = lines[i + 1..end].iter().any(|l| l.trim() == index_line);
        if healthy {
            return None;
        }
        let original_region = lines[i..end].join("\n");
        let replacement = format!("{header}\n{index_line}");
        let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        new_lines.splice(i..end, [header.clone(), index_line.clone()]);
        return Some(CargoConfigPlan {
            content: new_lines.join("\n"),
            edit: FileEdit {
                path: config_key.into(),
                kind: "redirect_cargo_registry".into(),
                action: "rewritten".into(),
                key: Some(reg.to_string()),
                original: Some(Value::String(original_region)),
                new: Some(Value::String(replacement)),
            },
        });
    }
    // Absent (or surviving only in comments): append a fresh block.
    let block = format!("{header}\n{index_line}\n");
    let sep = if !config.is_empty() && !config.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let prefix = if config.is_empty() { "" } else { "\n" };
    Some(CargoConfigPlan {
        content: format!("{config}{sep}{prefix}{block}"),
        edit: FileEdit {
            path: config_key.into(),
            kind: "redirect_cargo_registry".into(),
            action: "added".into(),
            key: Some(reg.to_string()),
            original: None,
            new: Some(Value::String(block)),
        },
    })
}

// ── pnpm-lock.yaml ───────────────────────────────────────────────────────────

/// LOOSE post-splice residual probe for ONE dep over one pnpm lock text: the
/// lock instance keys of `<fname>@<version>` — in ANY grammar pnpm has
/// shipped (v9 `name@version`, quoted scoped spellings, v6
/// `/name@version(peers…)` including NESTED peer parens the splice regex
/// provably cannot match, v5 `/name/version` with `_` suffixes) and with ANY
/// suffix spelling, anticipated or not — whose own `resolution:` block does
/// NOT reference `artifact_url`.
///
/// The splice regex is the WRITER and must stay strict (it rebuilds the
/// resolution byte-surgically). This probe is the AUDITOR: it only answers
/// "does an instance of this exact name@version remain pointed somewhere
/// else?", so it is deliberately looser than the writer — an instance key
/// the writer's grammar cannot even parse still shows up here, and the
/// caller then refuses the dep instead of shipping a partial rewrite (the
/// fail-open the original pre-splice `redirect_pnpm_unsupported_lock_key`
/// refusal guarded against).
///
/// Keys are recognized version-exactly: `<fname>@<version>` / v5
/// `<fname>/<version>` followed by nothing or by a character that cannot
/// extend a version (so `left-pad@1.3.0` never claims `left-pad@1.3.01`).
/// v9 `snapshots:` instance keys carry no `resolution:` line and pin
/// nothing, so a key with no resolution in its block does not count.
fn pnpm_unrewritten_instances(
    content: &str,
    fname: &str,
    version: &str,
    artifact_url: &str,
) -> Vec<String> {
    let at_form = format!("{fname}@{version}");
    let slash_form = format!("{fname}/{version}");
    // A character that could extend `version` into a LONGER version string
    // (semver body chars) — anything else marks a suffix boundary.
    let extends_version = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+');
    let mut residual: Vec<String> = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        // Lock instance keys are 2-space-indented mapping keys: `  <key>:`.
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(' ') {
            continue;
        }
        let Some(raw_key) = rest.strip_suffix(':') else {
            continue;
        };
        let unquoted = raw_key.trim_matches(|c| c == '\'' || c == '"');
        let key = unquoted.strip_prefix('/').unwrap_or(unquoted);
        let Some(suffix) = key
            .strip_prefix(&at_form)
            .or_else(|| key.strip_prefix(&slash_form))
        else {
            continue;
        };
        if suffix.chars().next().is_some_and(extends_version) {
            continue;
        }
        // The entry's block: the following deeper-indented lines. A
        // `resolution:` pointing anywhere but the hosted artifact is a
        // residual; no resolution at all (v9 `snapshots:` keys) pins nothing.
        for entry_line in &lines[i + 1..] {
            if !entry_line.trim().is_empty() && !entry_line.starts_with("    ") {
                break;
            }
            if entry_line.trim_start().starts_with("resolution:")
                && !entry_line.contains(artifact_url)
            {
                residual.push(raw_key.to_string());
                break;
            }
        }
    }
    residual
}

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
        // One `packages:`-section entry per INSTANCE of the dep, across every
        // lock grammar pnpm has shipped (each carries its own `resolution:`
        // block — verified against locks emitted by corepack pnpm@7.33.5 and
        // pnpm@8.15.9, 2026-08-18):
        //   v9:   `<fn>@<ver>:` — single-quoted when the name starts with `@`
        //         (YAML forbids a plain scalar starting with `@`); resolved
        //         peers live in `snapshots:` keys, which carry no resolution.
        //   v6:   `/<fn>@<ver>:` plus one `/<fn>@<ver>(peerA@x)(peerB@y):`
        //         per resolved-peer combination.
        //   v5.x: `/<fn>/<ver>:` plus `/<fn>/<ver>_<peer-suffix>:` per
        //         combination (`_react@18.2.0`, or a hash for long sets).
        // EVERY matching instance is spliced. Rewriting only the first would
        // fail open: a v6 lock holding both `/pkg@1.0.0:` and
        // `/pkg@1.0.0(peer@2.0.0):` would confirm and attest the dep while
        // every dependent resolving through the peered entry still installs
        // the unpatched upstream tarball.
        let key = regex::escape(&fname) + "@" + &regex::escape(&dep.version);
        let pat = String::from(r"(?m)(^ {2}('")
            + &key
            + r"'|/?"
            + &key
            + r"(?:\([^)\n]*\))*|/"
            + &regex::escape(&fname)
            + "/"
            + &regex::escape(&dep.version)
            + r"(?:_[^:\n]*)?):\n(?: {4,}.*\n)*? {4,}resolution: )\{([^}\n]*)\}";
        let re =
            Regex::new(&pat).expect("resolution regex from the escaped name@version key is valid");
        let mut matched_any = false;
        // Per-lock rewrites are PLANNED first and committed only after the
        // residual gate below proves no instance of this dep escaped the
        // splice grammar in ANY lock — committing lock-by-lock as we go
        // would ship exactly the partial rewrite the gate exists to refuse.
        let mut planned: Vec<(usize, String, Vec<FileEdit>)> = Vec::new();
        let mut residuals: Vec<(&str, Vec<String>)> = Vec::new();
        for (idx, (lock_key, content, _)) in contents.iter().enumerate() {
            // (byte range to replace, replacement text) per instance, plus
            // one FileEdit per instance keyed by the canonical instance key —
            // per-instance edits keep the revert ledger lossless when several
            // instances of one dep live in the same lock.
            let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
            let mut instance_edits: Vec<FileEdit> = Vec::new();
            for caps in re.captures_iter(content) {
                matched_any = true;
                let whole = caps.get(0).expect("group 0 is the whole match");
                let prefix = caps
                    .get(1)
                    .expect("resolution regex always captures group 1 (prefix)")
                    .as_str();
                let key_text = caps
                    .get(2)
                    .expect("resolution regex always captures group 2 (the lock key)")
                    .as_str();
                let inner = caps
                    .get(3)
                    .expect("resolution regex always captures group 3 (inner)")
                    .as_str();
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
                // Canonical instance key: quotes and the leading `/` are lock
                // spelling, not identity, and v5's `/<fn>/<ver><suffix>` is
                // respelled `<fn>@<ver><suffix>` — so a plain instance's key
                // is `<fn>@<ver>` in every grammar (the shape the golden
                // fixtures pin) and peered instances stay distinct.
                let instance_key = if let Some(quoted) = key_text
                    .strip_prefix('\'')
                    .and_then(|k| k.strip_suffix('\''))
                {
                    quoted.to_string()
                } else if let Some(slashed) = key_text.strip_prefix('/') {
                    match slashed.strip_prefix(&format!("{fname}/")) {
                        Some(rest) => format!("{fname}@{rest}"),
                        None => slashed.to_string(),
                    }
                } else {
                    key_text.to_string()
                };
                splices.push((whole.range(), format!("{prefix}{rebuilt}")));
                instance_edits.push(FileEdit {
                    path: (*lock_key).clone(),
                    kind: "redirect_pnpm_resolution".into(),
                    action: "rewritten".into(),
                    key: Some(instance_key),
                    original: Some(Value::String(original)),
                    new: Some(Value::String(rebuilt)),
                });
            }
            // Splice by byte range (captures_iter yields non-overlapping
            // matches in order) — a string replace could hit the wrong
            // instance when two entries share identical surrounding bytes.
            let candidate: Option<String> = if splices.is_empty() {
                None
            } else {
                let mut out = String::with_capacity(content.len());
                let mut cursor = 0usize;
                for (range, replacement) in splices {
                    out.push_str(&content[cursor..range.start]);
                    out.push_str(&replacement);
                    cursor = range.end;
                }
                out.push_str(&content[cursor..]);
                Some(out)
            };
            // Residual gate, run over the POST-splice text: any instance of
            // this exact name@version still resolving somewhere other than
            // the hosted artifact — in a spelling the splice grammar cannot
            // parse (e.g. v6 NESTED peer parens) — makes this a partial
            // rewrite. Shipping it would confirm and VEX-attest the dep while
            // dependents through the unmatched instance keep installing the
            // unpatched upstream tarball, so the dep is refused instead.
            let leftover = pnpm_unrewritten_instances(
                candidate.as_deref().unwrap_or(content),
                &fname,
                &dep.version,
                &dep.artifact_url,
            );
            if !leftover.is_empty() {
                residuals.push(((*lock_key).as_str(), leftover));
                continue;
            }
            if let Some(out) = candidate {
                planned.push((idx, out, instance_edits));
            }
        }
        // ANY residual anywhere refuses the dep across the WHOLE lock set —
        // nothing rewritten, nothing recorded, nothing confirmed (the same
        // fail-closed contract the pre-splice v5/v6 refusal had): a rewrite
        // committed in one lock while another still resolves the dep
        // upstream would confirm the dep set-wide.
        if !residuals.is_empty() {
            for (lock_key, keys) in &residuals {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_unsupported_lock_key".into(),
                    detail: format!(
                        "{fname}@{} still resolves through pnpm lock key(s) whose \
                         resolution the redirect grammar cannot repoint: {} in \
                         {lock_key}; the dep is left unredirected in EVERY lock \
                         (nothing rewritten, nothing confirmed) — regenerate the \
                         lock with a current pnpm (lockfileVersion 9) and re-run",
                        dep.version,
                        keys.join(", ")
                    ),
                });
            }
            continue;
        }
        for (idx, out, mut instance_edits) in planned {
            let (_, content, changed) = &mut contents[idx];
            *content = out;
            *changed = true;
            result.edits.append(&mut instance_edits);
        }
        // The entry-not-found warning fires only when the dep matched in NO
        // pnpm lock across the whole set, not once per lock. A VENDORED dep
        // is named as such: `socket-patch vendor` removes the registry
        // resolution this grammar looks for (v9 respells the packages key
        // `<name>@file:.socket/vendor/…`; v5/v6 rekey it to a bare `file:`
        // key but keep the `<name>@<version>: file:…` overrides line), so
        // the generic not-locked wording would send users on a wild-goose
        // `pnpm install` when the real path is a mode switch. Fail-closed
        // either way: nothing is rewritten for the dep.
        if !matched_any {
            let v9_vendored_key = format!("{fname}@file:");
            let override_key = format!("{fname}@{}", dep.version);
            let vendored = contents.iter().any(|(_, content, _)| {
                content.lines().any(|line| {
                    let t = line.trim_start();
                    let t = t.strip_prefix('\'').unwrap_or(t);
                    // v9 packages/snapshots key (leading `/` in v6 spelling).
                    // The vendor backend always writes the RELATIVE
                    // `file:.socket/vendor/…` spelling here, so anchoring on
                    // it keeps a user's own `file:` dep of the same name
                    // from being misreported as vendored.
                    let key = t.strip_prefix('/').unwrap_or(t);
                    if key
                        .strip_prefix(&v9_vendored_key)
                        .is_some_and(|rest| rest.starts_with(".socket/vendor/"))
                    {
                        return true;
                    }
                    // overrides / root-dep line: `<name>@<version>: file:…`
                    // (pnpm <=8 absolutizes the value, so only the
                    // `.socket/vendor/` tail is stable enough to match).
                    t.strip_prefix(&override_key)
                        .map(|rest| rest.strip_prefix('\'').unwrap_or(rest))
                        .and_then(|rest| rest.strip_prefix(':'))
                        .is_some_and(|rest| {
                            rest.contains("file:") && rest.contains(".socket/vendor/")
                        })
                })
            });
            if vendored {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_entry_vendored".into(),
                    detail: format!(
                        "{fname}@{} has no registry resolution because it is \
                         VENDORED (the lock resolves it to a \
                         file:.socket/vendor/… tarball); the hosted redirect \
                         does not apply — run `socket-patch vendor --revert` to \
                         restore the registry resolution, then re-run `scan \
                         --mode hosted`",
                        dep.version
                    ),
                });
            } else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_entry_not_found".into(),
                    detail: format!("no inline resolution for {fname}@{}", dep.version),
                });
            }
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
    use crate::vendor::yarn_classic_lock::{pattern_real_name, split_key_patterns, split_pattern};

    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("yarn.lock") {
        return;
    }
    let raw = &files["yarn.lock"];
    if Regex::new(r"(?m)^__metadata:")
        .expect("static __metadata probe regex is valid")
        .is_match(raw)
    {
        return; // yarn-berry — not classic
    }
    // CRLF locks (core.autocrlf Windows checkouts — yarn v1 parses them fine)
    // are processed LF-normalized and re-expanded on output, so untouched
    // lines round-trip byte-identically. Without this, `split("\n\n")` never
    // splits a CRLF file: the whole lock becomes ONE block and the
    // leftmost-match replaces below would rewrite the FIRST entry in the
    // file, not the target's. Bare `\r`s outside a CRLF pair make the
    // round-trip lossy, so such a lock is refused untouched.
    let crlf = raw.contains('\r');
    let normalized: String;
    let content: &str = if crlf {
        normalized = raw.replace("\r\n", "\n");
        if normalized.contains('\r') {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_classic_unsupported_line_endings".into(),
                detail: "yarn.lock contains bare carriage returns (mixed line endings); \
                         leaving it untouched"
                    .into(),
            });
            return;
        }
        &normalized
    } else {
        raw
    };
    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolved_re =
        Regex::new(r#"\n {2}resolved "[^"]*""#).expect("static resolved-line regex is valid");
    let integrity_re =
        Regex::new(r"\n {2}integrity [^\n]*").expect("static integrity-line regex is valid");
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
        let version_re =
            Regex::new(&(String::from(r#"\n {2}version ""#) + &regex::escape(&dep.version) + "\""))
                .expect("version regex from the escaped version is valid");
        let mut matched_any = false;
        let mut alias_skipped = false;
        for block in blocks.iter_mut() {
            // The block's key line names its consumers; resolve every
            // comma-joined pattern to the REAL package it stands for
            // (`alias@npm:target@range` → target). A key like
            // `<fname>@npm:<other-pkg>@…` — yarn v1's fork-substitution
            // idiom — resolves to <other-pkg>, so it is NOT ours to touch:
            // matching on the alias name alone would hijack the fork.
            let Some(key_line) = block
                .lines()
                .find(|l| !l.is_empty() && !l.starts_with([' ', '\t', '#']))
            else {
                continue;
            };
            let Some(key) = key_line.strip_suffix(':') else {
                continue;
            };
            let patterns = split_key_patterns(key);
            if patterns.is_empty()
                || !patterns
                    .iter()
                    .all(|p| pattern_real_name(p) == Some(fname.as_str()))
            {
                continue;
            }
            if !version_re.is_match(block) {
                continue;
            }
            // A block reached only through `alias@npm:<fname>@range`
            // descriptors is left byte-identical (mirroring the berry
            // rewriter), but never silently: that copy keeps installing the
            // unpatched artifact.
            if !patterns
                .iter()
                .any(|p| split_pattern(p).is_some_and(|(n, _)| n == fname))
            {
                alias_skipped = true;
                result.warnings.push(RewriteWarning {
                    code: "redirect_yarn_classic_alias_skipped".into(),
                    detail: format!(
                        "lock entry `{key}` consumes {fname}@{} only through npm: alias \
                         descriptors; the hosted redirect does not rewrite alias entries, \
                         so this copy stays unpatched",
                        dep.version
                    ),
                });
                continue;
            }
            matched_any = true;
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
                // Ledger originals record the on-disk byte form, so a future
                // revert of a CRLF lock can match what the file really held.
                let (edit_original, edit_new) = if crlf {
                    (block.replace('\n', "\r\n"), rewritten.replace('\n', "\r\n"))
                } else {
                    (block.clone(), rewritten.clone())
                };
                result.edits.push(FileEdit {
                    path: "yarn.lock".into(),
                    kind: "redirect_yarn_classic_entry".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}", dep.version)),
                    original: Some(Value::String(edit_original)),
                    new: Some(Value::String(edit_new)),
                });
                *block = rewritten;
                changed = true;
            }
        }
        if !matched_any && !alias_skipped {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_classic_entry_not_found".into(),
                detail: format!("no yarn.lock entry resolving {fname}@{}", dep.version),
            });
        }
    }
    if changed {
        let mut out = blocks.join("\n\n");
        if crlf {
            out = out.replace('\n', "\r\n");
        }
        result.files.insert("yarn.lock".into(), out);
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
    if !Regex::new(r"(?m)^__metadata:")
        .expect("static __metadata probe regex is valid")
        .is_match(content)
    {
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
    let resolution_re =
        Regex::new(r#"\n {2}resolution: "[^"]*""#).expect("static resolution-line regex is valid");
    let checksum_re =
        Regex::new(r"\n {2}checksum: [^\n]*").expect("static checksum-line regex is valid");
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
                .expect("version regex from the escaped version is valid");
        let mut matched_any = false;
        let mut alias_skipped = false;
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
            let names: std::collections::BTreeSet<&str> = parsed
                .iter()
                .map(|p| {
                    p.expect("every pattern parsed — None-bearing keys are skipped above")
                        .0
                })
                .collect();
            if !names.contains(fname.as_str()) {
                // An `alias@npm:<fname>@range` descriptor resolves the
                // patched package under a different ident. The redirect
                // never rewrites those, but that must not be silent — this
                // copy keeps installing the unpatched artifact, and the
                // generic not-found warning would point at the wrong cause.
                if version_re.is_match(block)
                    && parsed.iter().any(|p| {
                        p.expect("every pattern parsed — None-bearing keys are skipped above")
                            .1
                            .strip_prefix("npm:")
                            .and_then(split_berry_descriptor)
                            .is_some_and(|(real, _)| real == fname)
                    })
                {
                    alias_skipped = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_yarn_berry_alias_skipped".into(),
                        detail: format!(
                            "lock entry `{raw_key}` consumes {fname}@{} only through an \
                             npm: alias descriptor; the hosted redirect does not rewrite \
                             alias entries, so this copy stays unpatched",
                            dep.version
                        ),
                    });
                }
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
            if !parsed.iter().all(|p| {
                p.expect("every pattern parsed — None-bearing keys are skipped above")
                    .1
                    .starts_with("npm:")
            }) {
                let ranges: Vec<&str> = parsed
                    .iter()
                    .map(|p| {
                        p.expect("every pattern parsed — None-bearing keys are skipped above")
                            .1
                    })
                    .collect();
                // A `file:` range into `.socket/vendor/` is socket-patch's
                // OWN vendored wiring (`scan --mode vendored`), not some
                // third-party protocol: the refusal stays fail-closed
                // (byte-identical — the vendored artifact is the live CVE
                // protection), but it must say what the entry IS and name
                // the real way out. `remove <purl>` is the per-package
                // retirement; `vendor --revert` works too but unwinds EVERY
                // vendored package, so it is scoped, not recommended. The
                // remedy holds whether or not a vendored→hosted pre-revert
                // ever lands for npm-family — today no berry counterpart of
                // the cargo takeover exists.
                if ranges
                    .iter()
                    .any(|r| r.starts_with("file:") && r.contains(".socket/vendor/"))
                {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_yarn_berry_vendored_entry".into(),
                        detail: format!(
                            "lock entry `{raw_key}` is socket-patch's own vendored wiring \
                             for {fname}@{} (a committed `.socket/vendor/` artifact); the \
                             hosted redirect does not take over a vendor-owned package — \
                             leaving it byte-identical. To move this package to hosted \
                             mode, first retire its vendored wiring: run `socket-patch \
                             remove <purl>` for this package (or `socket-patch vendor \
                             --revert`, which unwinds EVERY vendored package), then re-run \
                             `scan --mode hosted`",
                            dep.version
                        ),
                    });
                    continue;
                }
                // Name the entry's ACTUAL protocol(s) — a hardcoded example
                // list misdirects for anything outside it (`file:`, `exec:`,
                // …). `workspace:`/`patch:`/`portal:`/`link:` stay the
                // canonical examples of why the gate exists.
                let mut protocols: Vec<String> = ranges
                    .iter()
                    .filter(|r| !r.starts_with("npm:"))
                    .map(|r| match r.split_once(':') {
                        Some((proto, _)) => format!("{proto}:"),
                        None => "(none)".to_string(),
                    })
                    .collect();
                protocols.sort();
                protocols.dedup();
                result.warnings.push(RewriteWarning {
                    code: "redirect_yarn_berry_unsupported_protocol".into(),
                    detail: format!(
                        "lock entry `{raw_key}` resolves {fname}@{} through the `{}` \
                         protocol, which the hosted redirect cannot own (only npm: \
                         registry entries are rewritten; e.g. workspace:, patch:, \
                         portal:, link: blocks must survive untouched); leaving it \
                         byte-identical",
                        dep.version,
                        protocols.join("`/`")
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
        if !matched_any && !alias_skipped {
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
                url = serde_json::to_string(&url_spec)
                    .expect("a String serializes to JSON infallibly"),
                deps = deps_verbatim,
                integrity =
                    serde_json::to_string(&sha512).expect("a String serializes to JSON infallibly"),
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
        let scheme_end = url
            .find("://")
            .expect("url starts with http(s):// — checked above")
            + 3;
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
    let wheel_re = Regex::new(r#"\{ url = "[^"]*", hash = "sha256:[^"]*"([^}]*) \}"#)
        .expect("static uv wheel-entry regex is valid");
    let name_re = Regex::new(r#"name = "([^"]+)""#).expect("static name-field regex is valid");
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
/// Whether `text` points at `artifact_url` in any spelling a rewritten file may
/// carry: the raw url every rewriter emits — composer.lock included, since
/// composer writes its lock through PHP's `JSON_UNESCAPED_SLASHES` — or the
/// `\/`-escaped slashes an older composer wrote, which redirect the install just
/// as well. Shared by the composer rewriter's already-redirected check and the
/// CLI's post-rewrite confirmation probe so the writer's spelling and the
/// probe's cannot drift: the probe searched only raw and percent-encoded urls
/// while the composer rewriter emitted `\/`, so a fully successful composer
/// redirect reported nothing redirected — no patch record reached the ledger and
/// `vex` had nothing to attest.
pub fn artifact_url_present(text: &str, artifact_url: &str) -> bool {
    text.contains(artifact_url) || text.contains(&artifact_url.replace('/', "\\/"))
}

/// Byte offset of the `}` closing the JSON object that CONTAINS `from`, which
/// must be a position inside that object. Brace counting skips string literals,
/// so a brace inside a description or URL cannot move the boundary.
fn json_object_end_from(text: &str, from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in text[from..].char_indices() {
        if in_string {
            match ch {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' if depth == 0 => return Some(from + offset),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Value of the first `"<key>": "<value>"` pair in `text` (composer writes its
/// lock with exactly one space after the colon, the same shape the surgical
/// `dist` regexes below assume).
fn json_string_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let start = text.find(&pattern)? + pattern.len();
    let end = text[start..].find('"')? + start;
    Some(&text[start..end])
}

/// Outcome of locating a package entry in a composer.lock.
enum ComposerEntry {
    /// Inclusive byte range from the entry's `"name"` key to the `}` closing
    /// the entry — composer writes `name` first, so this covers every key the
    /// rewriter edits.
    Found(usize, usize),
    /// The name matched but the lock pins this OTHER version.
    VersionMismatch(String),
    NotFound,
}

/// Locate `pkg`'s entry in a composer.lock (either `packages[]` or
/// `packages-dev[]` — the scan is over the whole file).
///
/// Names match CASE-INSENSITIVELY, the way the composer crawler and the vendor
/// backend already match them: packagist canonicalizes to lowercase, but
/// hand-written mixed-case locks install fine and would otherwise silently miss
/// the redirect. The locked version must match the patched one through
/// composer's leading-`v` normalization (locks carry the pretty `v6.4.1`, PURLs
/// the bare `6.4.1`); matching on name alone repointed whatever version the
/// lock happened to hold at a patch built for a different one.
fn find_composer_entry(content: &str, pkg: &str, version: &str) -> ComposerEntry {
    let mut mismatched: Option<String> = None;
    for (name_idx, _) in content.match_indices("\"name\": \"") {
        let Some(end) = json_object_end_from(content, name_idx) else {
            continue;
        };
        let entry = &content[name_idx..=end];
        if !json_string_field(entry, "name").is_some_and(|n| n.eq_ignore_ascii_case(pkg)) {
            continue;
        }
        // Every package entry carries `version`; an `authors[]`/`support`
        // object that happens to have a matching `name` does not.
        let Some(locked) = json_string_field(entry, "version") else {
            continue;
        };
        if normalize_version(locked) == normalize_version(version) {
            return ComposerEntry::Found(name_idx, end);
        }
        mismatched = Some(locked.to_string());
    }
    match mismatched {
        Some(locked) => ComposerEntry::VersionMismatch(locked),
        None => ComposerEntry::NotFound,
    }
}

/// Append `"shasum": "<sha1>"` as the last key of a `"dist": { … }` block,
/// indented like the keys already in it. VCS/zipball dists omit `shasum`
/// entirely; redirecting such a block without inserting the pin left the hosted
/// artifact unverified, so composer would install whatever the URL returned.
/// `block` is the whole dist object and already holds at least a `url`.
fn append_composer_shasum(block: &str, sha1: &str) -> String {
    let Some(close) = block.rfind('}') else {
        return block.to_string();
    };
    let head = block[..close].trim_end();
    let indent: String = head[head.rfind('\n').map_or(0, |i| i + 1)..]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    format!(
        "{head},\n{indent}\"shasum\": \"{sha1}\"{}",
        &block[head.len()..]
    )
}

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
    const DIST_KEY: &str = "\"dist\": {";
    let mut content = files["composer.lock"].clone();
    let type_re = Regex::new(r#"("type": ")[^"]*(")"#).expect("static dist type regex is valid");
    let url_re = Regex::new(r#"("url": ")[^"]*(")"#).expect("static dist url regex is valid");
    let shasum_re =
        Regex::new(r#"("shasum": ")[^"]*(")"#).expect("static dist shasum regex is valid");
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
        let (entry_start, entry_end) =
            match find_composer_entry(&content, &composer_name, &dep.version) {
                ComposerEntry::Found(start, end) => (start, end),
                ComposerEntry::VersionMismatch(locked) => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_composer_version_mismatch".into(),
                        detail: format!(
                            "composer.lock pins {composer_name}@{locked}, not the patched {}",
                            dep.version
                        ),
                    });
                    continue;
                }
                ComposerEntry::NotFound => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_composer_pkg_not_found".into(),
                        detail: format!(
                            "no composer.lock package named {composer_name}@{}",
                            dep.version
                        ),
                    });
                    continue;
                }
            };
        // The dist block MUST belong to the located entry. Scanning forward
        // from the name for the next `"dist": {` walked into the FOLLOWING
        // package whenever the target was installed from source, repointing a
        // bystander's url + shasum — a checksum-clean install of the wrong
        // code. A target with no dist of its own pins nothing: fail closed.
        let Some(dist_start) = content[entry_start..=entry_end]
            .find(DIST_KEY)
            .map(|offset| entry_start + offset)
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist".into(),
                detail: format!("{composer_name} has no dist block"),
            });
            continue;
        };
        let Some(dist_end) = json_object_end_from(&content, dist_start + DIST_KEY.len()) else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_lock_malformed".into(),
                detail: format!("{composer_name}'s dist block is unterminated"),
            });
            continue;
        };
        let block = content[dist_start..=dist_end].to_string();
        // Already redirected (either slash spelling): recording an edit whose
        // `original` IS the hosted url would grow the ledger on every re-run
        // and poison a future revert.
        if artifact_url_present(&block, &dep.artifact_url) && block.contains(&sha1) {
            continue;
        }
        if !block.contains("\"url\": \"") {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist_url".into(),
                detail: format!("{composer_name}'s dist block has no url to redirect"),
            });
            continue;
        }
        let mut rewritten = type_re.replace(&block, "${1}zip${2}").to_string();
        rewritten = url_re
            .replace(
                &rewritten,
                format!("${{1}}{}${{2}}", dep.artifact_url).as_str(),
            )
            .to_string();
        rewritten = if rewritten.contains("\"shasum\": \"") {
            shasum_re
                .replace(&rewritten, format!("${{1}}{sha1}${{2}}").as_str())
                .to_string()
        } else {
            append_composer_shasum(&rewritten, &sha1)
        };
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
    let self_closing = Regex::new(r"<packageSources\s*/>")
        .expect("static self-closing packageSources regex is valid");
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
    let region_re = Regex::new(r"(?s)<packageSources>(.*?)</packageSources>")
        .expect("static packageSources region regex is valid");
    let scope = region_re
        .captures(config)
        .map(|c| {
            c.get(1)
                .expect("region_re always captures group 1")
                .as_str()
        })
        .unwrap_or("");
    Regex::new(r#"<add\s+key="([^"]+)""#)
        .expect("static add-key regex is valid")
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

/// The grant-token path segment of a hosted patch URL: the path level
/// immediately preceding the patch-uuid level (production shape
/// `…/patch-registry/gem/{token}/{uuid}/…`, same layout on the artifact
/// URLs). The reference endpoint hands the token back only inside its URLs,
/// so this is how a caller recovers it for `DepOverride.token`. Only path
/// levels count — the scheme/host prefix is skipped so a uuid sitting in the
/// first path segment can never elect the host as its "token". `None` when
/// the uuid is absent or nothing precedes it.
pub fn grant_token_path_segment(url: &str, patch_uuid: &str) -> Option<String> {
    if patch_uuid.is_empty() {
        return None;
    }
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (_, path) = after_scheme.split_once('/')?;
    let before = path
        .split_once(&format!("/{patch_uuid}/"))
        .map(|(before, _)| before)
        .or_else(|| path.strip_suffix(&format!("/{patch_uuid}")))?;
    let token = before.rsplit('/').next().unwrap_or("");
    (!token.is_empty()).then(|| token.to_string())
}

/// A dep's Socket index URL as a regex source with the per-request rotating
/// segments (grant token, patch uuid) wildcarded — an exact-URL pattern
/// misses the URL a previous run wrote under an older grant. The grant token
/// is wildcarded even when the caller left `dep.token` empty (the CLI
/// historically never populated it): the token path level is derived from
/// the index URL itself as the segment immediately preceding the patch-uuid
/// level, so the idempotency guard never silently degrades into the
/// nesting-corruption failure mode when a caller forgets the token.
fn gem_index_url_pattern(dep: &DepOverride, index_url: &str) -> String {
    let mut url_pat = regex::escape(index_url);
    let derived_token = grant_token_path_segment(index_url, &dep.patch_uuid);
    let rotating = [
        Some(dep.token.as_str()),
        derived_token.as_deref(),
        Some(dep.patch_uuid.as_str()),
    ];
    for rotating in rotating.into_iter().flatten() {
        if !rotating.is_empty() {
            url_pat = url_pat.replace(&regex::escape(&format!("/{rotating}/")), "/[^/\"]+/");
        }
    }
    url_pat
}

/// A gemfile spelling with the redirect's own footprint erased: every managed
/// Socket `source "…" do … end` block for a redirected dep (rotating grant
/// segments wildcarded) and the dep's own `gem` declaration line. The
/// gems.rb/Gemfile divergence guard compares these residues rather than raw
/// bytes: run 1 on byte-identical twins edits only gems.rb (the file bundler
/// reads), so a raw comparison would trap every later run — the rotated-grant
/// URL refresh included — behind `redirect_gem_gemfile_spellings_diverge`, a
/// divergence the rewriter itself created. Trailing whitespace is trimmed (a
/// block appended to a newline-less file adds a final newline the other
/// spelling never had). `\r?` mirrors the block recognizer in `rewrite_gem`:
/// a `core.autocrlf` checkout rewrites run 1's LF block to CRLF, and a block
/// the recognizer accepts must also be erased here or the re-run is trapped
/// behind the divergence warning before it can reach the recognizer.
fn gem_spelling_residue(content: &str, deps: &[&DepOverride]) -> String {
    let mut residue = content.to_string();
    for dep in deps {
        let Some(ov) = &dep.registry_override else {
            continue;
        };
        if ov.kind != "rubygems-compact-index" {
            continue;
        }
        let block_re = Regex::new(
            &(String::from(r#"(?m)^source ""#)
                + &gem_index_url_pattern(dep, &ov.index_url)
                + r#"" do\r?\n  gem ["']"#
                + &regex::escape(&dep.name)
                + r#"["'][^\n]*\nend\r?\n?"#),
        )
        .expect("source-block regex from the escaped gem name is valid");
        residue = block_re.replace_all(&residue, "").into_owned();
        let decl_re = Regex::new(
            &(String::from(r#"(?m)^[ \t]*gem\b[^\n]*["']"#)
                + &regex::escape(&dep.name)
                + r#"["'][^\n]*\n?"#),
        )
        .expect("gem-declaration regex from the escaped gem name is valid");
        residue = decl_re.replace_all(&residue, "").into_owned();
    }
    residue.trim_end().to_string()
}

/// A lock line without its `\r?\n` ending (never more than one of each).
fn gem_lock_line_content(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// The gem name of a 2-space DEPENDENCIES entry (`  rails`, `  rails!`,
/// `  rails (= 7.0.0)!`) — the text before any constraint, sans source pin.
fn gem_lock_dependency_name(entry: &str) -> &str {
    let entry = entry.trim_start();
    let entry = entry.split(" (").next().unwrap_or(entry);
    entry.trim_end_matches('!')
}

/// One parsed `GEM` section of a Gemfile.lock: its `remote:` lines (index +
/// URL) and the exclusive end index — the start of the next column-0 header
/// (trailing blank separator included) or EOF.
struct GemLockSection {
    remotes: Vec<(usize, String)>,
    end: usize,
}

/// Converge the lock's source attribution for one redirected dep so the
/// Gemfile + lock pair is what bundler itself would write after an install
/// from the redirected Gemfile (verified frozen-installable on bundler 4):
/// the dep's spec entry (+ its dependency sublines) moves out of the
/// upstream `GEM` section into a patch-registry `GEM` section
/// (`remote: <index-url>`), and DEPENDENCIES pins `<name> (= <version>)!`
/// (bundler's source-pin spelling for a block-scoped exact-version gem) —
/// added in sorted position when the dep was transitive. Without this the
/// CHECKSUMS pin leaves a MIXED state bundler refuses: the lock still
/// attributes the gem to the upstream remote, so the prescribed unfrozen
/// install exits 37 "mismatched checksums" and a frozen install exits 16.
///
/// Idempotent and rotation-aware: a section whose remote matches the
/// token-wildcard pattern is recognized as ours (never duplicated) and its
/// remote is refreshed in place under a rotated grant
/// (`redirect_gemfile_lock_source_url`, mirroring the Gemfile refresh).
///
/// Returns true when the lock ends converged (already, or via edits recorded
/// into `result`); false when the dep cannot be attributed safely — spec
/// entry absent or duplicated, a legacy multi-remote `GEM` section, or no
/// DEPENDENCIES section — in which case nothing is touched and the caller
/// surfaces the frozen-install caveat exactly as before.
fn converge_gem_lock_source(
    lk: &mut String,
    dep: &DepOverride,
    index_url: &str,
    lock_name: &str,
    lock_changed: &mut bool,
    result: &mut RewriteResult,
) -> bool {
    let eol = if lk.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = lk.split_inclusive('\n').map(str::to_string).collect();
    let is_header = |c: &str| !c.is_empty() && !c.starts_with(' ');

    // Parse: GEM sections, the dep's 4-space spec entry, DEPENDENCIES range.
    let spec_content = format!("    {} ({})", dep.name, dep.version);
    let mut sections: Vec<GemLockSection> = Vec::new();
    let mut spec_at: Vec<(usize, usize)> = Vec::new(); // (section idx, line idx)
    let mut deps_range: Option<(usize, usize)> = None; // exclusive of header
    let mut i = 0;
    while i < lines.len() {
        let c = gem_lock_line_content(&lines[i]);
        if !is_header(c) {
            i += 1;
            continue;
        }
        let header_is_gem = c == "GEM";
        let start = i;
        let mut remotes = Vec::new();
        let mut j = i + 1;
        while j < lines.len() && !is_header(gem_lock_line_content(&lines[j])) {
            let cj = gem_lock_line_content(&lines[j]);
            if header_is_gem {
                if let Some(url) = cj.strip_prefix("  remote: ") {
                    remotes.push((j, url.to_string()));
                }
                if cj == spec_content {
                    spec_at.push((sections.len(), j));
                }
            }
            j += 1;
        }
        if header_is_gem {
            sections.push(GemLockSection { remotes, end: j });
        } else if c == "DEPENDENCIES" {
            deps_range = Some((start + 1, j));
        }
        i = j;
    }

    let spec_pos = if spec_at.len() == 1 {
        Some(spec_at[0])
    } else {
        None
    };
    let (Some((sec_idx, spec_idx)), Some((deps_start, deps_end))) = (spec_pos, deps_range) else {
        return false;
    };
    if sections[sec_idx].remotes.len() != 1 {
        return false;
    }
    // Bundler always writes source sections before DEPENDENCIES — the pin
    // edit below runs first on that premise (its lines sit after the parsed
    // spec/remote/end indices, so they never shift). A hand-edited lock with
    // DEPENDENCIES before the dep's GEM section breaks the premise: the
    // transitive-dep pin INSERT would leave the spec-move splicing on stale
    // indices. Fail soft to the mixed state instead.
    if deps_start < sections[sec_idx].end {
        return false;
    }
    let (remote_idx, remote_url) = sections[sec_idx].remotes[0].clone();
    let socket_remote_re = Regex::new(&format!("^{}$", gem_index_url_pattern(dep, index_url)))
        .expect("anchored index-url pattern from the escaped URL is valid");
    let mut changed = false;

    // DEPENDENCIES pin first — its lines sit AFTER the GEM sections, so the
    // spec move below never invalidates these indices (and vice versa would).
    let target = format!("  {} (= {})!", dep.name, dep.version);
    let is_entry = |c: &str| c.starts_with("  ") && !c.starts_with("   ");
    let entry_idx = (deps_start..deps_end).find(|&k| {
        let ck = gem_lock_line_content(&lines[k]);
        is_entry(ck) && gem_lock_dependency_name(ck) == dep.name
    });
    match entry_idx {
        Some(k) if gem_lock_line_content(&lines[k]) == target => {}
        Some(k) => {
            let old = gem_lock_line_content(&lines[k]).trim_start().to_string();
            let ending = lines[k][gem_lock_line_content(&lines[k]).len()..].to_string();
            lines[k] = format!("{target}{ending}");
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_dependency_pin".into(),
                action: "rewritten".into(),
                key: Some(dep.name.clone()),
                original: Some(Value::String(old)),
                new: Some(Value::String(target.trim_start().to_string())),
            });
            changed = true;
        }
        None => {
            // Transitive dep: bundler keeps DEPENDENCIES sorted by name.
            let mut at = deps_end;
            for (k, line) in lines.iter().enumerate().take(deps_end).skip(deps_start) {
                let ck = gem_lock_line_content(line);
                if ck.is_empty()
                    || (is_entry(ck) && gem_lock_dependency_name(ck) > dep.name.as_str())
                {
                    at = k;
                    break;
                }
            }
            lines.insert(at, format!("{target}{eol}"));
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_dependency_pin".into(),
                action: "added".into(),
                key: Some(dep.name.clone()),
                original: None,
                new: Some(Value::String(target.trim_start().to_string())),
            });
            changed = true;
        }
    }

    if socket_remote_re.is_match(&remote_url) {
        // Already ours. Rotated grant: refresh the remote in place.
        if remote_url != index_url {
            let ending =
                lines[remote_idx][gem_lock_line_content(&lines[remote_idx]).len()..].to_string();
            lines[remote_idx] = format!("  remote: {index_url}{ending}");
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_source_url".into(),
                action: "rewritten".into(),
                key: Some(dep.name.clone()),
                original: Some(Value::String(remote_url)),
                new: Some(Value::String(index_url.to_string())),
            });
            changed = true;
        }
    } else {
        // Move the spec (+ sublines) into a patch-registry section of its
        // own, inserted where the section it leaves ends.
        let mut last = spec_idx;
        while last + 1 < lines.len()
            && gem_lock_line_content(&lines[last + 1]).starts_with("      ")
        {
            last += 1;
        }
        let moved: Vec<String> = lines.drain(spec_idx..=last).collect();
        let insert_at = sections[sec_idx].end - moved.len();
        let mut block: Vec<String> = Vec::with_capacity(moved.len() + 4);
        block.push(format!("GEM{eol}"));
        block.push(format!("  remote: {index_url}{eol}"));
        block.push(format!("  specs:{eol}"));
        for line in moved {
            // Moved lines keep their own bytes; only a final line that lacked
            // a newline (EOF) gains the file's ending.
            if line.ends_with('\n') {
                block.push(line);
            } else {
                block.push(format!("{line}{eol}"));
            }
        }
        block.push(eol.to_string());
        lines.splice(insert_at..insert_at, block);
        result.edits.push(FileEdit {
            path: lock_name.into(),
            kind: "redirect_gemfile_lock_gem_source".into(),
            action: "rewritten".into(),
            key: Some(dep.name.clone()),
            original: Some(Value::String(remote_url)),
            new: Some(Value::String(index_url.to_string())),
        });
        changed = true;
    }

    if changed {
        *lk = lines.concat();
        *lock_changed = true;
    }
    true
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
    // Bundler's modern manifest spelling: `gems.rb`/`gems.locked` wins over
    // `Gemfile`/`Gemfile.lock` when both sit in one directory (bundler's
    // `default_gemfile` tries gems.rb first — verified on bundler 4.0.15,
    // which warns "Multiple gemfiles (gems.rb and Gemfile) detected ...
    // bundler is ignoring them in favor of gems.rb and gems.locked"; same
    // order as `setup::gem::discover_bundler_project`). DIVERGING spellings
    // are ambiguous — the redirect would land in the file bundler reads while
    // tooling pinned to the other keeps resolving upstream — so fail closed
    // on the whole gem set. Divergence is judged on the redirect-footprint
    // residue (`gem_spelling_residue`), NOT raw bytes: run 1 on identical
    // twins edits only gems.rb (following bundler), so a raw comparison would
    // trap every later run behind the divergence the rewriter itself created.
    // Identical spellings follow bundler: edit gems.rb.
    let modern = files.contains_key("gems.rb");
    if modern
        && files.get("Gemfile").is_some_and(|c| {
            gem_spelling_residue(&files["gems.rb"], &gem) != gem_spelling_residue(c, &gem)
        })
    {
        result.warnings.push(RewriteWarning {
            code: "redirect_gem_gemfile_spellings_diverge".into(),
            detail: "both gems.rb and Gemfile are present with different contents; bundler \
                     reads gems.rb but the redirect cannot safely pick one — reconcile the \
                     two spellings and re-run"
                .into(),
        });
        return;
    }
    let (gemfile_name, lock_name) = if modern {
        ("gems.rb", "gems.locked")
    } else {
        ("Gemfile", "Gemfile.lock")
    };
    let mut gemfile = files.get(gemfile_name).cloned();
    let mut gemfile_changed = false;
    let mut lock = files.get(lock_name).cloned();
    let mut lock_changed = false;
    // Static regex — compile once, not per-dependency (clippy: regex-in-loop).
    // `\r?` throughout the lock handling: a CRLF Gemfile.lock is legal to
    // bundler (verified: `bundle check`/frozen install both accept one on
    // 4.0.15), and without the tolerance the CHECKSUMS header never matched,
    // misdiagnosing the lock as bundler <2.6.
    let checksums_re =
        Regex::new(r"(?m)^CHECKSUMS(\r?)$").expect("static CHECKSUMS header regex is valid");
    // True once any redirected dep leaves the pair MIXED: the lock still
    // attributes the dep to the upstream source (no CHECKSUMS section to key
    // the convergence on, or a lock shape the convergence refused). Only
    // that state earns the frozen-install caveat — a converged pair is
    // frozen-installable as written.
    let mut mixed_state = false;

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
        // The URL is interpolated into the Gemfile's quoted source string and
        // the lock's `remote:` lines — gate it before any write, like the
        // cargo arm gates sparse index URLs.
        if !is_valid_gem_index_url(&ov.index_url) {
            result.warnings.push(RewriteWarning {
                code: "redirect_gem_invalid_index_url".into(),
                detail: format!(
                    "{} has a malformed patch-registry index URL; dependency skipped",
                    dep.name
                ),
            });
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
            .expect("platform regex from the escaped name/version is valid");
            if platform_re.is_match(lk) {
                result.warnings.push(RewriteWarning {
                    code: "redirect_gem_platform_unsupported".into(),
                    detail: format!(
                        "{lock_name} CHECKSUMS carries platform-specific entries for {} {} — \
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
            let url_pat = gem_index_url_pattern(dep, &ov.index_url);
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
            .expect("source-block regex from the escaped index URL is valid");
            if let Some(m) = block_re.captures(gf) {
                let url = m
                    .get(1)
                    .expect("block_re always captures group 1 (index URL)");
                if url.as_str() == ov.index_url {
                    source_placed = true;
                } else {
                    // Rotated grant: refresh the URL in place — never nest.
                    let (range, old_url) = (url.range(), url.as_str().to_string());
                    gf.replace_range(range, &ov.index_url);
                    gemfile_changed = true;
                    result.edits.push(FileEdit {
                        path: gemfile_name.into(),
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
                .expect("gem-line regex from the escaped gem name is valid");
                // Looser "declared at all?" probe: gates the append branch —
                // appending next to a declaration the recognizer above cannot
                // parse would leave the gem declared twice (bundler
                // hard-fails on the duplicate).
                let declared_re = Regex::new(
                    &(String::from(r#"(?m)^[ \t]*gem\b[^\n]*["']"#)
                        + &regex::escape(&dep.name)
                        + r#"["']"#),
                )
                .expect("declaration probe regex from the escaped gem name is valid");
                if let Some(m) = gem_line_re.captures(gf) {
                    let range = m.get(0).expect("group 0 is the whole match").range();
                    let original = m
                        .get(0)
                        .expect("group 0 is the whole match")
                        .as_str()
                        .to_string();
                    let paren = m.get(1).is_some();
                    let raw_tail = m
                        .get(2)
                        .expect("gem_line_re always captures group 2 (tail)")
                        .as_str()
                        .to_string();
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
                    // silent no-op that still gets attested. Fail closed —
                    // and when the blocking `path:` is socket-patch's OWN
                    // vendored wiring, prescribe the eject path instead of
                    // leaving the user to puzzle over their own Gemfile.
                    if let Some(tok) = gem_tail_source_option(&tail) {
                        let socket_vendored = matches!(tok, "path:" | ":path")
                            && tail
                                .split('#')
                                .next()
                                .unwrap_or("")
                                .contains(".socket/vendor/");
                        let detail = if socket_vendored {
                            format!(
                                "the `gem \"{}\"` declaration carries `{tok}` pointing into \
                                 .socket/vendor — socket-patch's own vendored wiring, which \
                                 would override the Socket source block; un-vendor this gem \
                                 first (`socket-patch remove pkg:gem/{}@{}`, or `socket-patch \
                                 vendor --revert` to revert EVERY vendored dependency in the \
                                 project), then re-run the hosted scan",
                                dep.name, dep.name, dep.version
                            )
                        } else {
                            format!(
                                "the `gem \"{}\"` declaration carries `{tok}`, which would \
                                 override the Socket source block; redirect skipped",
                                dep.name
                            )
                        };
                        result.warnings.push(RewriteWarning {
                            code: "redirect_gem_source_option".into(),
                            detail,
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
                        path: gemfile_name.into(),
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
                        path: gemfile_name.into(),
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
                        "no {gemfile_name} source redirect is in place for {} — CHECKSUMS pin \
                         skipped",
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
                    + r"\)) sha256=([0-9a-f]+)(\r?)$"),
            )
            .expect("checksum-line regex from the escaped name/version is valid");
            let new_val = format!("{} ({}) sha256={sha256}", dep.name, dep.version);
            // Already redirected (re-run): the CHECKSUMS line is at the
            // target value; recording an edit would grow the ledger forever.
            let already_re =
                Regex::new(&(String::from(r"(?m)^  ") + &regex::escape(&new_val) + r"\r?$"))
                    .expect("already-redirected regex from the escaped line is valid");
            let mut checksums_era = true;
            if already_re.is_match(lk) {
                // no-op
            } else if let Some(m) = sum_line_re.captures(lk) {
                // The pre-edit line goes into the ledger as `original` so a
                // future `--revert` can restore the upstream sha.
                let old_val = format!(
                    "{} ({}) sha256={}",
                    dep.name,
                    dep.version,
                    m.get(2)
                        .expect("sum_line_re always captures group 2 (sha hex)")
                        .as_str()
                );
                *lk = sum_line_re
                    .replace(lk, format!("${{1}} sha256={sha256}${{3}}").as_str())
                    .to_string();
                lock_changed = true;
                result.edits.push(FileEdit {
                    path: lock_name.into(),
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
                            "CHECKSUMS${{1}}\n  {} ({}) sha256={sha256}${{1}}",
                            dep.name, dep.version
                        )
                        .as_str(),
                    )
                    .to_string();
                lock_changed = true;
                result.edits.push(FileEdit {
                    path: lock_name.into(),
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
                        "{lock_name} has no CHECKSUMS section (bundler <2.6) — cannot pin {}",
                        dep.name
                    ),
                });
                checksums_era = false;
            }
            // A CHECKSUMS-era lock must end FULLY CONVERGED — with only the
            // sha pinned, bundler still attributes the gem to the upstream
            // remote and refuses the pair outright (unfrozen: exit 37
            // "mismatched checksums"; frozen: exit 16). A pre-CHECKSUMS lock
            // has no sha to converge around, so it keeps today's
            // mixed-but-installable state + the frozen-install caveat.
            if !checksums_era
                || !converge_gem_lock_source(
                    lk,
                    dep,
                    &ov.index_url,
                    lock_name,
                    &mut lock_changed,
                    result,
                )
            {
                mixed_state = true;
            }
        }
    }

    // A MIXED pair breaks bundler's frozen/deployment mode: the lock's GEM
    // section still records the upstream source, so `bundle install` with
    // `frozen`/`--deployment` set rejects the Gemfile's new source block.
    // Mirror of the CLI's pnpm trust-lockfile warning. A converged pair (the
    // CHECKSUMS-era path) is frozen-installable as written — no caveat.
    if (gemfile_changed || lock_changed) && mixed_state {
        result.warnings.push(RewriteWarning {
            code: "redirect_gem_frozen_install".into(),
            detail: format!(
                "{gemfile_name} was repointed at the Socket patch registry but {lock_name}'s \
                 GEM section still records the upstream source; bundler rejects the pair \
                 under frozen/deployment mode — run `bundle install` (unfrozen) once to \
                 record the new source in {lock_name}"
            ),
        });
    }

    if gemfile_changed {
        if let Some(gf) = gemfile {
            result.files.insert(gemfile_name.into(), gf);
        }
    }
    if lock_changed {
        if let Some(lk) = lock {
            result.files.insert(lock_name.into(), lk);
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
    let re = Regex::new(&format!("(?s)<{tag}>(.*?)</{tag}>"))
        .expect("tag regex is valid — callers pass literal tag names");
    let caps = re.captures(&pom[from..to])?;
    let inner = caps
        .get(1)
        .expect("tag regex always captures group 1 (inner text)");
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
    let dep_re = Regex::new(r"(?s)<dependency\b[^>]*>.*?</dependency>")
        .expect("static dependency-block regex is valid");
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
            let pom_text = pom
                .as_ref()
                .expect("pom is Some — the is_none() guard above continues");
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
        let matches = find_maven_dependency_matches(
            pom.as_ref()
                .expect("pom is Some — the is_none() guard above continues"),
            &group_id,
            &artifact_id,
        );

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
            let mut rebuilt = pom
                .as_ref()
                .expect("pom is Some — the is_none() guard above continues")
                .clone();
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
                pom.as_ref()
                    .expect("pom is Some — the is_none() guard above continues"),
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
            .expect("pom is Some — the is_none() guard above continues")
            .contains(&format!("<id>{repo_id}</id>"))
        {
            pom = Some(insert_maven_repository(
                pom.as_ref()
                    .expect("pom is Some — the is_none() guard above continues"),
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
    let dm_re = Regex::new(r"(?s)<dependencyManagement>\s*<dependencies>")
        .expect("static dependencyManagement regex is valid");
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
        let key = key_of(arg).expect("every MVN_CONFIG_ARGS entry contains '='");
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

// ── golang (go.mod fork-replace + go.sum pin) ────────────────────────────────
/// go.mod and go.sum are whitespace-delimited line formats, and the golang
/// rewriter interpolates server-controlled strings into both — any embedded
/// whitespace/control character would split tokens or inject whole directives
/// (`"foo v1.0.0 => evil.example/x v1\nreplace …"`). Fail-closed token guard.
fn go_token_safe(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Strict `h1:` dirhash shape: exactly `h1:` + the 44-char standard-base64 of
/// a sha256. Anything else (wrong algorithm, embedded whitespace, truncation)
/// must not reach go.sum — a malformed line poisons the whole file.
fn go_h1_shape(s: &str) -> bool {
    s.strip_prefix("h1:").is_some_and(|b| {
        b.len() == 44
            && b.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    })
}

// The committable shape (validated empirically — `docs/design/golang-hosted.md`):
//
//   go.mod:  replace <orig> <ver> => patch.socket.dev/gopatch/<uuid> <sver>
//   go.sum:  patch.socket.dev/gopatch/<uuid> <sver> h1:…          (zip dirhash)
//            patch.socket.dev/gopatch/<uuid> <sver>/go.mod h1:…   (served .mod)
//
// Day-2 machines need NO machine-local configuration: go consults the checksum
// database only for modules ABSENT from go.sum, the Socket module path is
// grant-free/content-addressed (one build-once artifact per patch, public on
// the free tier), and with the pinned replace in force go never fetches or
// verifies the original module at all. A dep whose reference carries no
// `goproxy` override falls back to the historical `redirect_golang_unsupported`
// warning (the paid tier's tokened URLs remain a genuine no-go — see the
// design doc's paid-tier analysis).
fn rewrite_golang(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    use crate::vendor::go_mod_edit::{self, HOSTED_GO_MODULE_PREFIX};
    use crate::vendor::go_sum_edit;

    let golang: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "golang")
        .collect();
    if golang.is_empty() {
        return;
    }
    // The replace directive can only live in the MAIN module's go.mod.
    let Some(orig_go_mod) = files.get("go.mod") else {
        result.warnings.push(RewriteWarning {
            code: "redirect_golang_no_go_mod".into(),
            detail: "no go.mod present; golang redirect skipped".into(),
        });
        return;
    };
    let mut go_mod = orig_go_mod.clone();
    // An absent go.sum starts empty: the fully-replaced original needs no
    // lines of its own, so the two socket lines alone are a complete pin.
    let mut go_sum = files.get("go.sum").cloned().unwrap_or_default();
    let (mut mod_changed, mut sum_changed) = (false, false);

    for dep in &golang {
        let fname = full_name(dep);
        let Some(ov) = &dep.registry_override else {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_unsupported".into(),
                detail: format!(
                    "{fname}@{}: no hosted Go module is published for this patch; run \
                     `socket-patch vendor` (committable, offline-verified) instead",
                    dep.version
                ),
            });
            continue;
        };
        if ov.kind != "goproxy" {
            continue;
        }
        let (Some(rhs_module), Some(rhs_version)) = (
            &ov.identifiers.go_module_path,
            &ov.identifiers.go_module_version,
        ) else {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_missing_module".into(),
                detail: format!(
                    "{fname}@{} goproxy override lacks goModulePath/goModuleVersion",
                    dep.version
                ),
            });
            continue;
        };
        // Fail closed on a module path outside the socket namespace: the
        // prefix is the ONLY ownership signal — a directive we couldn't
        // recognize later would be unremovable, and go.sum removal keys on it.
        if !rhs_module.starts_with(HOSTED_GO_MODULE_PREFIX) {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_untrusted_module_path".into(),
                detail: format!(
                    "{fname}@{}: refusing hosted module path `{rhs_module}` outside \
                     `{HOSTED_GO_MODULE_PREFIX}`",
                    dep.version
                ),
            });
            continue;
        }
        // Every string interpolated into go.mod/go.sum must be a single clean
        // token — whitespace or control characters would inject directives.
        if [fname.as_str(), &dep.version, rhs_module, rhs_version]
            .iter()
            .any(|s| !go_token_safe(s))
        {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_unsafe_coords".into(),
                detail: format!(
                    "{fname}@{}: module/version tokens contain whitespace or control \
                     characters; refusing to write them into go.mod/go.sum",
                    dep.version
                ),
            });
            continue;
        }
        // BOTH go.sum hashes must be pinnable up front — a replace without
        // them (or with a malformed hash) bricks every `-mod=readonly` build.
        let (Some(zip_h1), Some(gomod_h1)) = (&dep.integrity.dirhash_h1, &dep.integrity.go_mod_h1)
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_missing_integrity".into(),
                detail: format!(
                    "{fname}@{} has no dirhashH1/goModH1 integrity pair",
                    dep.version
                ),
            });
            continue;
        };
        if !go_h1_shape(zip_h1) || !go_h1_shape(gomod_h1) {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_missing_integrity".into(),
                detail: format!(
                    "{fname}@{}: integrity hashes must be `h1:` + 44-char base64 dirhashes",
                    dep.version
                ),
            });
            continue;
        }
        // Any pre-existing socket-owned directive for the module (this run is
        // a refresh, or a takeover of a local/vendored redirect): capture its
        // text — the ledger's `original` is the only pre-redirect record.
        let prior = go_mod_edit::parse_replace_entries(&go_mod)
            .into_iter()
            .find(|e| e.module == fname && e.socket_owned());
        let prior_text = prior.as_ref().map(|e| {
            let target = e.path.clone().unwrap_or_else(|| match &e.rhs_version {
                Some(v) => format!("{} {v}", e.rhs_module.as_deref().unwrap_or_default()),
                None => e.rhs_module.clone().unwrap_or_default(),
            });
            let ver = e
                .version
                .as_deref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default();
            format!("replace {}{ver} => {target}", e.module)
        });

        // Stale-pin cross-check: `replace` is keyed on module+version, and a
        // pin the graph no longer selects is SILENTLY inert (the build links
        // the unpatched module with zero warning) — refuse to write one, and
        // reconcile away OUR OWN inert directive if one is already committed:
        // left in place, its module path keeps confirming the dep as
        // redirected (ledger + VEX attestation) while go links the unpatched
        // version.
        if let Some(required) = go_mod_edit::parse_required_versions(&go_mod).get(&fname) {
            if required != &dep.version {
                result.warnings.push(RewriteWarning {
                    code: "redirect_golang_version_mismatch".into(),
                    detail: format!(
                        "{fname}: go.mod requires {required} but the patch targets {} — \
                         a version-pinned replace would be silently ignored",
                        dep.version
                    ),
                });
                let stale_hosted = prior
                    .as_ref()
                    .filter(|e| e.owner == Some(go_mod_edit::ReplaceOwner::Hosted));
                if let Some(stale) = stale_hosted {
                    if let Ok(Some(new)) = go_mod_edit::remove_replace_entry(
                        &go_mod,
                        &fname,
                        go_mod_edit::ReplaceOwner::Hosted,
                    ) {
                        go_mod = new;
                        mod_changed = true;
                        result.edits.push(FileEdit {
                            path: "go.mod".into(),
                            kind: "redirect_golang_stale_replace_removed".into(),
                            action: "removed".into(),
                            key: Some(fname.clone()),
                            original: prior_text.clone().map(Value::String),
                            new: None,
                        });
                    }
                    if let Some(stale_rhs) = stale.rhs_module.as_deref() {
                        if let Some(new) =
                            go_sum_edit::remove_module_prefix_lines(&go_sum, stale_rhs)
                        {
                            go_sum = new;
                            sum_changed = true;
                            result.edits.push(FileEdit {
                                path: "go.sum".into(),
                                kind: "redirect_golang_stale_gosum_removed".into(),
                                action: "removed".into(),
                                key: Some(stale_rhs.to_string()),
                                original: None,
                                new: None,
                            });
                        }
                    }
                }
                continue;
            }
        }

        match go_mod_edit::upsert_hosted_replace_entry(
            &go_mod,
            &fname,
            &dep.version,
            rhs_module,
            rhs_version,
        ) {
            Err(e) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_golang_replace_conflict".into(),
                    detail: format!("{fname}@{}: {e}", dep.version),
                });
                continue;
            }
            // Re-run over an already-redirected go.mod: nothing to record.
            Ok(None) => {}
            Ok(Some(new)) => {
                go_mod = new;
                mod_changed = true;
                result.edits.push(FileEdit {
                    path: "go.mod".into(),
                    kind: "redirect_golang_replace".into(),
                    // A takeover/refresh of an existing socket directive must
                    // keep its text in `original` — the ledger is the only
                    // pre-redirect record a future revert can restore from.
                    action: if prior_text.is_some() {
                        "updated".into()
                    } else {
                        "added".into()
                    },
                    key: Some(fname.clone()),
                    original: prior_text.map(Value::String),
                    new: Some(Value::String(format!(
                        "replace {fname} {} => {rhs_module} {rhs_version}",
                        dep.version
                    ))),
                });
            }
        }
        if let Some(new) =
            go_sum_edit::upsert_module_lines(&go_sum, rhs_module, rhs_version, zip_h1, gomod_h1)
        {
            go_sum = new;
            sum_changed = true;
            result.edits.push(FileEdit {
                path: "go.sum".into(),
                kind: "redirect_golang_gosum".into(),
                action: "added".into(),
                key: Some(format!("{rhs_module}@{rhs_version}")),
                original: None,
                new: Some(Value::String(format!(
                    "{rhs_module} {rhs_version} {zip_h1}\n{rhs_module} {rhs_version}/go.mod {gomod_h1}"
                ))),
            });
        }
        // Prune the replaced original's lines: with the pinned replace in
        // force go never fetches or verifies the original, and `go mod tidy`
        // prunes exactly these — writing the tidy-stable state up front keeps
        // the first day-2 tidy a byte-level no-op. The removed lines ride in
        // `original` so the ledger can restore them on revert.
        if let Some((new, removed)) =
            go_sum_edit::remove_exact_module_version_lines(&go_sum, &fname, &dep.version)
        {
            go_sum = new;
            sum_changed = true;
            result.edits.push(FileEdit {
                path: "go.sum".into(),
                kind: "redirect_golang_gosum_prune".into(),
                action: "removed".into(),
                key: Some(format!("{fname}@{}", dep.version)),
                original: Some(Value::String(removed.join("\n"))),
                new: None,
            });
        }
    }

    if mod_changed {
        result.files.insert("go.mod".into(), go_mod);
    }
    if sum_changed {
        result.files.insert("go.sum".into(), go_sum);
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

    /// A `file:` lock entry carrying the `.socket/vendor/` signature is
    /// socket-patch's OWN vendored wiring (a `scan --mode vendored` project
    /// being converted to hosted). Refusing it under the generic
    /// `redirect_yarn_berry_unsupported_protocol` code misdiagnosed it —
    /// the detail hardcoded "(workspace:/patch:/portal:/link:)" (`file:`
    /// was not even listed) and named no way out. The refusal itself is
    /// correct (fail-closed, byte-identical), but it must carry a DISTINCT
    /// code and the real per-package remediation: retire the vendored
    /// wiring first (`socket-patch remove <purl>`; `vendor --revert`
    /// unwinds EVERY vendored package), then re-run `scan --mode hosted`.
    /// That remedy holds whether or not a vendored→hosted pre-revert ever
    /// lands for npm-family — today no berry counterpart of the cargo
    /// takeover exists, so manual retirement is the only path.
    #[test]
    fn yarn_berry_vendored_file_entry_refused_with_distinct_code_and_remediation() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("minimist", "1.2.2", "http://p.test/minimist.tgz", &checksum);
        let uuid = "80630680-4da6-45f9-bba8-b888e0ffd58c";
        let entry = format!(
            "minimist@file:./.socket/vendor/npm/{uuid}/minimist-1.2.2.tgz::\
             locator=root%40workspace%3A."
        );
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"{entry}\":\n  version: 1.2.2\n  resolution: \"{entry}\"\n  \
                 checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
                "3".repeat(128)
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "vendored entry must stay byte-identical: {:?}",
            r.files
        );
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_yarn_berry_vendored_entry")
            .unwrap_or_else(|| {
                panic!(
                    "a vendored file: entry must get the distinct vendored-entry \
                     code, not the generic protocol refusal: {:?}",
                    r.warnings
                )
            });
        // Names the refused entry and the real remediation sequence.
        assert!(
            w.detail.contains(&entry),
            "must name the entry: {}",
            w.detail
        );
        assert!(
            w.detail.contains("socket-patch remove"),
            "must name the per-package remediation: {}",
            w.detail
        );
        assert!(
            w.detail.contains("vendor --revert"),
            "must name (and scope) the mass-revert alternative: {}",
            w.detail
        );
        assert!(
            w.detail.contains("scan --mode hosted"),
            "must name the re-run step: {}",
            w.detail
        );
        // The old misdiagnosis must be gone: no four-protocol list that
        // does not even include `file:`.
        assert!(
            !w.detail.contains("(workspace:/patch:/portal:/link:)"),
            "must not misdiagnose the vendored entry with the generic \
             protocol list: {}",
            w.detail
        );
    }

    /// The generic unsupported-protocol refusal must name the entry's
    /// ACTUAL protocol (backticked), not a hardcoded four-item list that
    /// omits, e.g., `file:` — an operator debugging the refusal needs the
    /// real cause, and the old list actively misdirected for any protocol
    /// outside it.
    #[test]
    fn yarn_berry_unsupported_protocol_detail_names_actual_protocol() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let lock_with = |entry: &str| {
            format!(
                "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"{entry}\":\n  version: 1.3.0\n  resolution: \"{entry}\"\n  \
                 checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
                "3".repeat(128)
            )
        };

        // A portal: entry → generic code, detail names `portal:`.
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            lock_with("left-pad@portal:./vendor/left-pad::locator=root%40workspace%3A."),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_yarn_berry_unsupported_protocol")
            .expect("portal: entry keeps the generic refusal code");
        assert!(
            w.detail.contains("`portal:`"),
            "detail must name the actual protocol: {}",
            w.detail
        );

        // A user's own file: entry OUTSIDE `.socket/vendor/` → still the
        // generic code (not vendored-entry), detail names `file:`.
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            lock_with("left-pad@file:./local/left-pad.tgz::locator=root%40workspace%3A."),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_yarn_berry_unsupported_protocol")
            .unwrap_or_else(|| {
                panic!(
                    "a non-vendored file: entry keeps the generic refusal \
                     code: {:?}",
                    r.warnings
                )
            });
        assert!(
            w.detail.contains("`file:`"),
            "detail must name the actual protocol: {}",
            w.detail
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_yarn_berry_vendored_entry"),
            "vendored-entry code is reserved for `.socket/vendor/` wiring: {:?}",
            r.warnings
        );
    }

    /// Two-entry classic lock: a decoy entry FIRST, the target second — the
    /// shape that exposed the CRLF wrong-entry rewrite.
    fn classic_lock_two_entries() -> String {
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n\
         abbrev@^1.0.0:\n  version \"1.1.1\"\n  \
         resolved \"https://registry.yarnpkg.com/abbrev/-/abbrev-1.1.1.tgz#aaaa\"\n  \
         integrity sha512-DECOYdecoy==\n\n\
         left-pad@^1.3.0:\n  version \"1.3.0\"\n  \
         resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbb\"\n  \
         integrity sha512-UPSTREAMupstream==\n"
            .to_string()
    }

    /// A CRLF classic lock (Windows `core.autocrlf` checkout) must rewrite
    /// the TARGET entry, not whichever entry happens to come first, and every
    /// untouched line must keep its CRLF ending byte-exactly. Regression:
    /// `split("\n\n")` never matched in a CRLF file, so the whole lock was
    /// one block and the leftmost `resolved`/`integrity` — the decoy's —
    /// were rewritten (then confirmed and attested downstream).
    #[test]
    fn yarn_classic_crlf_lock_rewrites_only_the_target_entry() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );

        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            classic_lock_two_entries().replace('\n', "\r\n"),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "clean rewrite: {:?}", r.warnings);
        let out = r
            .files
            .get("yarn.lock")
            .expect("yarn.lock must be rewritten");
        assert!(
            out.contains(
                "abbrev@^1.0.0:\r\n  version \"1.1.1\"\r\n  \
                 resolved \"https://registry.yarnpkg.com/abbrev/-/abbrev-1.1.1.tgz#aaaa\"\r\n  \
                 integrity sha512-DECOYdecoy==\r\n"
            ),
            "the decoy entry must stay byte-identical: {out}"
        );
        assert!(
            out.contains(
                "left-pad@^1.3.0:\r\n  version \"1.3.0\"\r\n  \
                 resolved \"http://p.test/lp.tgz\"\r\n  integrity sha512-PATCHED==\r\n"
            ),
            "the target entry must pin the hosted artifact: {out}"
        );
        assert_eq!(
            out.matches('\n').count(),
            out.matches("\r\n").count(),
            "every line must keep its CRLF ending: {out}"
        );

        // The CRLF output is exactly the LF rewrite re-expanded.
        let mut lf_files = BTreeMap::new();
        lf_files.insert("yarn.lock".to_string(), classic_lock_two_entries());
        let mut lf_r = RewriteResult::default();
        rewrite_yarn_classic(&lf_files, std::slice::from_ref(&ovr), &mut lf_r);
        assert_eq!(
            out,
            &lf_r.files["yarn.lock"].replace('\n', "\r\n"),
            "CRLF rewrite must equal the LF rewrite modulo line endings"
        );

        // Ledger originals carry the on-disk (CRLF) byte form for revert.
        assert_eq!(r.edits.len(), 1);
        let original = r.edits[0].original.as_ref().unwrap().as_str().unwrap();
        assert!(
            original.contains("\r\n") && original.contains("left-pad@^1.3.0:"),
            "edit original must record the CRLF bytes: {original:?}"
        );
    }

    /// Bare carriage returns outside a CRLF pair make the normalize/expand
    /// round-trip lossy — the lock is refused untouched with a warning.
    #[test]
    fn yarn_classic_mixed_line_endings_are_refused() {
        let mixed =
            classic_lock_two_entries()
                .replace('\n', "\r\n")
                .replacen("UPSTREAM", "UP\rSTREAM", 1);
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), mixed);
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "mixed-EOL lock must stay untouched: {:?}",
            r.files
        );
        assert_eq!(
            r.warnings[0].code,
            "redirect_yarn_classic_unsupported_line_endings"
        );
    }

    /// `"<fname>@npm:<other-pkg>@…"` is yarn v1's fork-substitution idiom:
    /// the block resolves a DIFFERENT package that merely tracks the patched
    /// version. It must never be hijacked onto the upstream patched artifact;
    /// the dep surfaces as not-found instead.
    #[test]
    fn yarn_classic_fork_alias_block_is_not_hijacked() {
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "# yarn lockfile v1\n\n\n\
             \"left-pad@npm:totally-other@^1.3.0\":\n  version \"1.3.0\"\n  \
             resolved \"https://registry.yarnpkg.com/totally-other/-/totally-other-1.3.0.tgz#cccc\"\n  \
             integrity sha512-FORKfork==\n"
                .to_string(),
        );
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "the fork block must stay byte-identical: {:?}",
            r.files
        );
        assert_eq!(r.warnings[0].code, "redirect_yarn_classic_entry_not_found");
    }

    /// The opposite alias direction — `"alias@npm:<fname>@…"` consuming the
    /// patched package under another name — is skipped with a SPECIFIC
    /// warning (not silence, not a misleading not-found).
    #[test]
    fn yarn_classic_alias_only_consumer_warns_specifically() {
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "# yarn lockfile v1\n\n\n\
             \"safe-pad@npm:left-pad@^1.3.0\":\n  version \"1.3.0\"\n  \
             resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbb\"\n  \
             integrity sha512-UPSTREAMupstream==\n"
                .to_string(),
        );
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_yarn_classic_alias_skipped");
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_yarn_classic_entry_not_found"),
            "the alias warning replaces the generic not-found: {:?}",
            r.warnings
        );
    }

    /// A merged key serving BOTH a direct and an alias descriptor of the
    /// patched package (yarn v1 merges patterns resolving identically) is
    /// still rewritten — every pattern resolves to the patched package.
    #[test]
    fn yarn_classic_merged_direct_and_alias_key_is_rewritten() {
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "# yarn lockfile v1\n\n\n\
             left-pad@^1.3.0, \"safe-pad@npm:left-pad@^1.3.0\":\n  version \"1.3.0\"\n  \
             resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbb\"\n  \
             integrity sha512-UPSTREAMupstream==\n"
                .to_string(),
        );
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "no warnings: {:?}", r.warnings);
        let out = r.files.get("yarn.lock").expect("must rewrite");
        assert!(
            out.contains("resolved \"http://p.test/lp.tgz\"")
                && out.contains("left-pad@^1.3.0, \"safe-pad@npm:left-pad@^1.3.0\":"),
            "merged key preserved, resolution repointed: {out}"
        );
    }

    /// A granted dep with no matching lock entry (version drift, not
    /// installed) must warn instead of vanishing silently — every sibling
    /// npm-family rewriter already surfaces this.
    #[test]
    fn yarn_classic_entry_not_found_warns() {
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "# yarn lockfile v1\n\n\n\
             left-pad@^1.2.0:\n  version \"1.2.0\"\n  \
             resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.0.tgz#dddd\"\n  \
             integrity sha512-OLDold==\n"
                .to_string(),
        );
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_yarn_classic_entry_not_found");
    }

    /// Berry flavor of the alias hole: the lock key's descriptor ident is the
    /// alias, but the entry plainly resolves the patched package — the skip
    /// must name the alias cause, not claim the entry is missing.
    #[test]
    fn yarn_berry_alias_only_consumer_warns_specifically() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"safe-pad@npm:left-pad@^1.3.0\":\n  version: 1.3.0\n  \
                 resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  \
                 languageName: node\n  linkType: hard\n",
                "3".repeat(128)
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_yarn_berry_alias_skipped");
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_yarn_berry_entry_not_found"),
            "the alias warning replaces the generic not-found: {:?}",
            r.warnings
        );
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

    /// Canonical lowercase patch uuid — the rewriter validates the uuid
    /// grammar fail-closed before interpolating it into TOML.
    const CARGO_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn cargo_reg() -> String {
        format!("socket-patch-{CARGO_UUID}")
    }

    fn cargo_index_url() -> String {
        format!("sparse+https://patch.test/cargo/{CARGO_UUID}/index/")
    }

    fn cargo_sparse_override() -> DepOverride {
        DepOverride {
            ecosystem: "cargo".into(),
            name: "serde".into(),
            namespace: None,
            version: "1.0.190".into(),
            token: "tok".into(),
            patch_uuid: CARGO_UUID.into(),
            artifact_url: "https://patch.test/serde-1.0.190.crate".into(),
            berry_zip_url: None,
            registry_override: Some(RegistryOverride {
                kind: "cargo-sparse".into(),
                index_url: cargo_index_url(),
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
            written.contains(&format!("[registries.{}]", cargo_reg())),
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
    /// With no Cargo.lock at all the manifest pin alone forces the next
    /// resolution through the managed registry, so the dep still counts as
    /// fully landed.
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
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    fn cargo_lock_with(name: &str, version: &str) -> String {
        format!(
            "# This file is automatically @generated by Cargo.\n\
             version = 3\n\
             \n\
             [[package]]\n\
             name = \"{name}\"\n\
             version = \"{version}\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"91f70896d6720bc714a4a57d22fc91f1db634680e65c8efe13323f1fa38d53f5\"\n"
        )
    }

    fn cargo_files(toml: &str) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), toml.to_string());
        files.insert(
            "Cargo.lock".to_string(),
            cargo_lock_with("serde", "1.0.190"),
        );
        files
    }

    /// AUDIT A1+A7: a crate declared in BOTH [dev-dependencies] and
    /// [dependencies] must gain the registry pin in BOTH sections — a
    /// first-match-only rewrite gives the two sections different sources for
    /// the same dep, which cargo rejects at manifest-parse time, bricking
    /// every cargo command. The blank separator line after each entry must
    /// survive (the old `\s*$` regex swallowed it).
    #[test]
    fn cargo_two_sections_rewrites_all_occurrences_and_preserves_blank_lines() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dev-dependencies]\nserde = \"1.0.190\"\n\n\
             [dependencies]\nserde = \"1.0.190\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
        let pinned = format!(
            "serde = {{ version = \"1.0.190\", registry = \"{}\" }}",
            cargo_reg()
        );
        assert_eq!(
            toml.matches(&pinned).count(),
            2,
            "BOTH sections must be pinned: {toml}"
        );
        assert!(
            toml.contains(&format!("{pinned}\n\n[dependencies]")),
            "the blank line before [dependencies] must be preserved: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
        // One manifest edit per occurrence.
        assert_eq!(
            r.edits
                .iter()
                .filter(|e| e.kind == "redirect_cargo_toml_dep")
                .count(),
            2
        );
    }

    /// AUDIT A2: the multi-line `[dependencies.<name>]` table form is a
    /// completely standard manifest shape — it gains a `registry = "…"` line
    /// instead of being reported not-found (which used to leave the lock
    /// repointed while the manifest still said crates.io: `--locked` builds
    /// broke, unlocked builds silently dropped the patch).
    #[test]
    fn cargo_table_form_dep_gains_registry_line() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies.serde]\nversion = \"1.0.190\"\nfeatures = [\"derive\"]\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
        assert!(
            toml.contains(&format!(
                "[dependencies.serde]\nregistry = \"{}\"\nversion = \"1.0.190\"",
                cargo_reg()
            )),
            "the table must gain a registry line: {toml}"
        );
        assert!(r.files.contains_key("Cargo.lock"));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // Idempotent re-run over the rewritten output: silent no-op.
        let mut again = files.clone();
        for (name, content) in &r.files {
            again.insert(name.clone(), content.clone());
        }
        let second = rewrite_registry_redirect(&again, &[cargo_sparse_override()]);
        assert!(
            second.files.is_empty() && second.edits.is_empty() && second.warnings.is_empty(),
            "re-run must be a silent no-op: files={:?} warnings={:?}",
            second.files.keys(),
            second.warnings
        );
        assert!(second.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// AUDIT A5: rename-aware matching. An entry whose KEY matches the
    /// patched crate but whose `package = "<other>"` names a different crate
    /// is NOT the patched crate (pinning it would point a foreign package at
    /// the single-crate socket registry — resolution hard-fails); the patched
    /// crate consumed under an ALIAS key (`iffy = { package = "serde" }`) IS.
    #[test]
    fn cargo_rename_aware_matching() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\n\
             serde = { package = \"leftpad\", version = \"1.0.0\" }\n\
             iffy = { package = \"serde\", version = \"1.0.190\" }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
        assert!(
            toml.contains("serde = { package = \"leftpad\", version = \"1.0.0\" }"),
            "the key-colliding entry for a DIFFERENT crate must be untouched: {toml}"
        );
        assert!(
            toml.contains(&format!(
                "iffy = {{ package = \"serde\", version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "the aliased entry for the patched crate must be pinned: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// AUDIT A5(a) alone: when the ONLY key match renames a different crate,
    /// the dep is genuinely not declared → not-found, and NOTHING is written
    /// (no config block, no lock repoint).
    #[test]
    fn cargo_key_collision_only_is_not_found_and_writes_nothing() {
        let mut files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = { package = \"leftpad\", version = \"1.0.0\" }\n",
        );
        files.insert(
            "Cargo.lock".to_string(),
            cargo_lock_with("leftpad", "1.0.0"),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty(),
            "nothing may be written: {:?}",
            r.files.keys()
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_toml_dep_not_found"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// AUDIT A4: a re-scan that selects a NEWER patch uuid over an existing
    /// redirect must supersede the old `registry = "socket-patch-<old>"` pin
    /// in place — the old code classified it as a foreign registry and left
    /// the manifest on the OLD uuid while moving the lock to the NEW one
    /// (broken `--locked` builds, unlocked builds resolving the superseded
    /// patch, VEX attesting the new one).
    #[test]
    fn cargo_supersede_replaces_previous_socket_registry_pin() {
        const OLD_UUID: &str = "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";
        let old_reg = format!("socket-patch-{OLD_UUID}");
        let old_index = format!("sparse+https://patch.test/cargo/{OLD_UUID}/index/");
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                 [dependencies]\nserde = {{ version = \"1.0.190\", registry = \"{old_reg}\" }}\n"
            ),
        );
        files.insert(
            "Cargo.lock".to_string(),
            cargo_lock_with("serde", "1.0.190").replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                &old_index,
            ),
        );
        files.insert(
            ".cargo/config.toml".to_string(),
            format!("[registries.{old_reg}]\nindex = \"{old_index}\"\n"),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("manifest re-pinned");
        assert!(
            toml.contains(&format!("registry = \"{}\"", cargo_reg())) && !toml.contains(&old_reg),
            "the manifest must move to the NEW registry: {toml}"
        );
        let lock = r.files.get("Cargo.lock").expect("lock re-pinned");
        assert!(lock.contains(&cargo_index_url()), "{lock}");
        let cfg = r.files.get(".cargo/config.toml").expect("config updated");
        assert!(
            cfg.contains(&format!("[registries.{}]", cargo_reg())),
            "{cfg}"
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_cargo_toml_dep_not_found"),
            "supersession is not 'dependency missing': {:?}",
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// A pin to a registry this rewriter does NOT own is the user's — refuse
    /// the whole dep (no lock edit, no config block) with one clear warning.
    #[test]
    fn cargo_foreign_registry_pin_refuses_whole_dep() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = { version = \"1.0.190\", registry = \"corp\" }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty(),
            "nothing may be written: {:?}",
            r.files.keys()
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_cargo_toml_dep_unrewritable"),
            "{:?}",
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A table-form block that carries `registry-index` cannot take a
    /// `registry` pin — cargo rejects a dependency naming both keys as
    /// ambiguous, so inserting the pin bricks every cargo command. Refuse
    /// the whole dep (zero writes, no confirmation), like the inline-table
    /// branch already does.
    #[test]
    fn cargo_table_form_registry_index_refuses_whole_dep() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies.serde]\nversion = \"1.0.190\"\n\
             registry-index = \"sparse+https://index.crates.io/\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty(),
            "nothing may be written: {:?}",
            r.files.keys()
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_cargo_toml_dep_unrewritable"),
            "{:?}",
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// AUDIT A2/A3 (transactionality): when ONE occurrence is rewritable but
    /// ANOTHER is not, the dep is skipped ENTIRELY — a partial pin (one
    /// section redirected, one not) gives the dep two different sources and
    /// cargo refuses the manifest.
    #[test]
    fn cargo_unrewritable_occurrence_skips_dep_entirely() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = \"1.0.190\"\n\n\
             [dev-dependencies]\nserde.version = \"1.0.190\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty(),
            "no partial pin may be written: {:?}",
            r.files.keys()
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_toml_dep_unrewritable"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// AUDIT A3 (the cargo analogue of npm's
    /// `no_lockfile_redirect_is_not_attested`): a granted dep the project
    /// does not declare at all (e.g. surfaced by the machine-wide
    /// $CARGO_HOME crawl) must produce NO writes — the old code still wrote
    /// the inert `[registries.…]` block, whose index URL then satisfied the
    /// hosted confirmed check and produced a false VEX attestation.
    #[test]
    fn cargo_undeclared_dep_writes_nothing_not_even_the_config_block() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nanyhow = \"1.0\"\n"
                .to_string(),
        );
        files.insert("Cargo.lock".to_string(), cargo_lock_with("anyhow", "1.0.0"));
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty(),
            "no file (config block included) may be written: {:?}",
            r.files.keys()
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_toml_dep_not_found"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A Cargo.lock that exists but has no [[package]] for the dep means the
    /// project does not resolve it — pinning the manifest anyway desyncs
    /// manifest and lock. Skip the dep entirely.
    #[test]
    fn cargo_missing_lock_entry_skips_dep_entirely() {
        let mut files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        files.insert("Cargo.lock".to_string(), cargo_lock_with("anyhow", "1.0.0"));
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty(),
            "no partial edit set may be written: {:?}",
            r.files.keys()
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_lock_pkg_not_found"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// AUDIT A6: a user who commented the managed [registries] block out (to
    /// debug an install) and re-runs the scan gets the block RESTORED. The
    /// old substring idempotence check matched the commented text, wrote
    /// nothing, and the run still reported the dep redirected while every
    /// cargo command failed on the undefined registry.
    #[test]
    fn cargo_commented_config_block_is_restored() {
        // First run to produce the redirected state.
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        let first = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let mut redirected = files.clone();
        for (name, content) in &first.files {
            redirected.insert(name.clone(), content.clone());
        }
        // Comment out every line of the managed config block.
        let commented = redirected[".cargo/config.toml"]
            .lines()
            .map(|l| {
                if l.is_empty() {
                    l.to_string()
                } else {
                    format!("#{l}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        redirected.insert(".cargo/config.toml".to_string(), commented.clone());

        let second = rewrite_registry_redirect(&redirected, &[cargo_sparse_override()]);
        let cfg = second
            .files
            .get(".cargo/config.toml")
            .expect("the managed block must be restored");
        assert!(
            cfg.contains(&format!(
                "[registries.{}]\nindex = \"{}\"",
                cargo_reg(),
                cargo_index_url()
            )),
            "an UNCOMMENTED block must exist after the re-run: {cfg}"
        );
        assert!(
            cfg.contains(&format!("#[registries.{}]", cargo_reg())),
            "the user's commented lines are preserved: {cfg}"
        );
        assert!(second.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// A degraded managed block (header intact, index line commented or
    /// stale) is regenerated in place rather than trusted.
    #[test]
    fn cargo_degraded_config_block_is_regenerated() {
        let mut files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = { version = \"1.0.190\", registry = \"socket-patch-9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f\" }\n",
        );
        files.insert(
            "Cargo.lock".to_string(),
            cargo_lock_with("serde", "1.0.190").replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                &cargo_index_url(),
            ),
        );
        files.insert(
            ".cargo/config.toml".to_string(),
            format!(
                "[registries.{}]\n#index = \"{}\"\n",
                cargo_reg(),
                cargo_index_url()
            ),
        );
        // The lock checksum still differs from the override's — rewritten.
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let cfg = r
            .files
            .get(".cargo/config.toml")
            .expect("degraded block regenerated");
        assert!(
            cfg.contains(&format!("\nindex = \"{}\"", cargo_index_url())),
            "an uncommented index line must exist: {cfg}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// AUDIT A9: an empty-string `cargoCksumSha256` is MISSING (the TS twin's
    /// falsy check), never written as `checksum = ""` into Cargo.lock — that
    /// hard-fails the next `cargo fetch --locked`.
    #[test]
    fn cargo_empty_string_cksum_skips_dep() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        let mut dep = cargo_sparse_override();
        if let Some(ov) = dep.registry_override.as_mut() {
            ov.identifiers.cargo_cksum_sha256 = Some(String::new());
        }
        dep.integrity = Integrity::default();
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(
            r.files.is_empty(),
            "nothing may be written: {:?}",
            r.files.keys()
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_cargo_missing_cksum"),
            "{:?}",
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// AUDIT A8: service-supplied strings are validated against their exact
    /// grammars before interpolation into raw TOML — a hostile patch uuid,
    /// index URL, or cksum must be refused, never written (TOML injection:
    /// a `]`+newline uuid can define `[source.crates-io] replace-with = …`
    /// redirecting EVERY crate).
    #[test]
    fn cargo_hostile_service_inputs_are_refused() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        // Hostile uuid.
        let mut dep = cargo_sparse_override();
        dep.patch_uuid = "x]\n[source.crates-io]\nreplace-with = \"evil\"\n[registries.y".into();
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_invalid_uuid"));
        assert!(r.confirmed_cargo_uuids.is_empty());

        // Hostile index URL (quote breaks out of the TOML string).
        let mut dep = cargo_sparse_override();
        if let Some(ov) = dep.registry_override.as_mut() {
            ov.index_url = "sparse+https://x/\"\nreplace-with = \"evil\"".into();
        }
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_invalid_index_url"));

        // Non-sparse index URL.
        let mut dep = cargo_sparse_override();
        if let Some(ov) = dep.registry_override.as_mut() {
            ov.index_url = "https://patch.test/cargo/index/".into();
        }
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_invalid_index_url"));

        // Malformed cksum (not 64 lowercase hex).
        let mut dep = cargo_sparse_override();
        if let Some(ov) = dep.registry_override.as_mut() {
            ov.identifiers.cargo_cksum_sha256 = Some("\"\nevil = 1\n".into());
        }
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_invalid_cksum"));
    }

    /// Workspace inheritance: the pin lands on the [workspace.dependencies]
    /// entry (which member `workspace = true` entries inherit), and the
    /// inheriting occurrences are then satisfied.
    #[test]
    fn cargo_workspace_inheritance_pins_the_workspace_table() {
        let files = cargo_files(
            "[workspace]\nmembers = [\"member\"]\n\n\
             [workspace.dependencies]\nserde = \"1.0.190\"\n\n\
             [dependencies]\nserde.workspace = true\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("workspace table pinned");
        assert!(
            toml.contains(&format!(
                "[workspace.dependencies]\nserde = {{ version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(
            toml.contains("serde.workspace = true"),
            "the inheriting entry is untouched: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// `workspace = true` with NO [workspace.dependencies] entry in this
    /// manifest (deps declared in member manifests the rewriter cannot see)
    /// must refuse the whole dep — fail closed, nothing written.
    #[test]
    fn cargo_workspace_inheritance_without_entry_refuses() {
        let files = cargo_files(
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = { workspace = true }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_toml_dep_unrewritable"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A plain-version entry with a trailing comment keeps the comment.
    #[test]
    fn cargo_plain_version_trailing_comment_preserved() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = \"1.0.190\" # pinned for CVE-2024-XXXX\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("rewritten");
        assert!(
            toml.contains(&format!(
                "serde = {{ version = \"1.0.190\", registry = \"{}\" }} # pinned for CVE-2024-XXXX",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// A path/git dependency never resolves through a registry — pinning it
    /// would be a lie; refuse the whole dep.
    #[test]
    fn cargo_path_dep_is_refused() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = { path = \"../serde\" }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_toml_dep_unrewritable"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A cargo dep whose override kind is not `cargo-sparse` warns (the TS
    /// twin's behavior) instead of vanishing silently.
    #[test]
    fn cargo_kind_mismatch_warns() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        let mut dep = cargo_sparse_override();
        if let Some(ov) = dep.registry_override.as_mut() {
            ov.kind = "goproxy".into();
        }
        let r = rewrite_registry_redirect(&files, &[dep]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "redirect_cargo_missing_override"));
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A target-specific dependency table is a rewrite target like the plain
    /// sections.
    #[test]
    fn cargo_target_specific_table_is_rewritten() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [target.'cfg(unix)'.dependencies]\nserde = \"1.0.190\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("rewritten");
        assert!(
            toml.contains(&format!(
                "[target.'cfg(unix)'.dependencies]\nserde = {{ version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
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

    /// A service-supplied index URL is interpolated into the Gemfile's quoted
    /// source string and the lock's `remote:` lines — a quote, backslash, or
    /// control character (a newline would inject whole lock lines) must be
    /// refused at intake with nothing written, like the cargo sparse gate.
    #[test]
    fn gem_malformed_index_url_is_refused_before_any_write() {
        for bad in [
            "https://patch.test/gem/tok\"/uuid/",
            "https://patch.test/gem\\tok/uuid/",
            "https://patch.test/gem/tok/uuid/\nGEM",
            "https://patch.test/gem/t k/uuid/",
            "ftp://patch.test/gem/tok/uuid/",
        ] {
            let mut files = BTreeMap::new();
            files.insert(
                "Gemfile".to_string(),
                "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
            );
            files.insert(
                "Gemfile.lock".to_string(),
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\n\
                 BUNDLED WITH\n   2.6.2\n"
                    .to_string(),
            );
            let mut ov = gem_override("rails", "7.0.0");
            ov.registry_override
                .as_mut()
                .expect("gem_override always carries a registry override")
                .index_url = bad.into();
            let r = rewrite_registry_redirect(&files, &[ov]);
            assert!(
                r.files.is_empty() && r.edits.is_empty(),
                "malformed index URL [{bad}] must write nothing: {:?}",
                r.edits
            );
            assert!(
                r.warnings
                    .iter()
                    .any(|w| w.code == "redirect_gem_invalid_index_url"),
                "malformed index URL [{bad}] must warn: {:?}",
                r.warnings
            );
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

    /// The CLI's ONLY production `DepOverride` construction site
    /// (`scan/hosted.rs`) builds every override with an EMPTY `token` — the
    /// reference endpoint hands the grant token back only inside the URLs it
    /// returns. The rotated-grant idempotency guard must therefore never
    /// depend on the caller populating `token`: a re-scan under a rotated
    /// grant must still recognize the source block a previous run wrote and
    /// refresh its URL in place. With a token-dependent guard the recognizer
    /// misses the old block, `gem_line_re` matches the INDENTED gem line
    /// inside it, and every re-scan wraps it in one more nested source block
    /// while keeping the stale (soon-dead) token URL live and reporting
    /// success.
    #[test]
    fn gemfile_rerun_with_rotated_grant_and_cli_empty_token_never_nests() {
        const PATCH_UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
        fn ov(token: &str) -> DepOverride {
            let mut o = gem_override("rails", "7.0.0");
            // Exactly as the CLI builds it: the grant token never populated.
            o.token = String::new();
            o.patch_uuid = PATCH_UUID.into();
            if let Some(r) = o.registry_override.as_mut() {
                r.index_url =
                    format!("https://patch.test/patch-registry/gem/{token}/{PATCH_UUID}/");
            }
            o
        }
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        let first = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        files.insert(
            "Gemfile".to_string(),
            first
                .files
                .get("Gemfile")
                .expect("first run rewrites")
                .clone(),
        );

        let second = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        let out = second
            .files
            .get("Gemfile")
            .expect("rotated grant refreshes the URL");
        assert_eq!(
            out.matches("source \"https://patch.test/patch-registry/gem/")
                .count(),
            1,
            "exactly one Socket source block, never nested: {out}"
        );
        assert!(!out.contains("tok-one"), "old grant token gone: {out}");
        assert!(
            out.contains(&format!(
                "source \"https://patch.test/patch-registry/gem/tok-two/{PATCH_UUID}/\" do\n  gem \"rails\", \"7.0.0\"\nend"
            )),
            "URL refreshed in place: {out}"
        );
        assert!(
            second
                .edits
                .iter()
                .any(|e| e.kind == "redirect_gemfile_source_url"),
            "the refresh must be recorded as a redirect_gemfile_source_url edit: {:?}",
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

    /// The gems.rb/Gemfile divergence guard erases the redirect's own
    /// footprint with the same token-wildcard pattern, so it too must not
    /// depend on `DepOverride.token` being populated: identical twins
    /// re-scanned under a rotated grant with the CLI's empty token must reach
    /// the in-place refresh, not be trapped behind
    /// `redirect_gem_gemfile_spellings_diverge` by run 1's own edit.
    #[test]
    fn gems_rb_twins_rotated_grant_with_cli_empty_token_refreshes() {
        const PATCH_UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
        fn ov(token: &str) -> DepOverride {
            let mut o = gem_override("rails", "7.0.0");
            o.token = String::new();
            o.patch_uuid = PATCH_UUID.into();
            if let Some(r) = o.registry_override.as_mut() {
                r.index_url =
                    format!("https://patch.test/patch-registry/gem/{token}/{PATCH_UUID}/");
            }
            o
        }
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string();
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), gemfile.clone());
        files.insert("Gemfile".to_string(), gemfile);
        let first = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        assert!(
            !second
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "run 1's own edit must not read as divergence: {:?}",
            second.warnings
        );
        let out = second
            .files
            .get("gems.rb")
            .expect("rotated grant refreshes gems.rb");
        assert_eq!(
            out.matches("source \"https://patch.test/patch-registry/gem/")
                .count(),
            1,
            "exactly one Socket source block, never nested: {out}"
        );
        assert!(!out.contains("tok-one"), "old grant token gone: {out}");
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

    /// When the blocking `path:` option is socket-patch's OWN vendored wiring
    /// (`.socket/vendor/gem/<uuid>/…`), the refusal must prescribe the eject
    /// paths instead of pointing the user at a Gemfile line the tool itself
    /// wrote — and state their blast radius honestly: `remove <purl>` is the
    /// per-gem undo, `vendor --revert` reverts EVERY vendored dependency.
    #[test]
    fn gemfile_source_option_refusal_prescribes_vendor_revert_for_own_wiring() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\n\
             gem \"rails\", \"7.0.0\", path: \".socket/vendor/gem/11111111-1111-4111-8111-111111111111/rails-7.0.0\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        let warning = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_gem_source_option")
            .unwrap_or_else(|| panic!("skip must warn: {:?}", r.warnings));
        assert!(
            warning.detail.contains("socket-patch remove pkg:gem/rails@7.0.0")
                && warning.detail.contains("socket-patch vendor --revert")
                && warning.detail.contains("EVERY vendored dependency"),
            "socket's own vendored wiring must prescribe the per-gem eject and \
             state vendor --revert's whole-project blast radius: {}",
            warning.detail
        );
        // A USER path: dep keeps the generic refusal — no bogus prescription.
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\n\
             gem \"rails\", \"7.0.0\", path: \"../rails\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let warning = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_gem_source_option")
            .unwrap_or_else(|| panic!("skip must warn: {:?}", r.warnings));
        assert!(
            !warning.detail.contains("vendor --revert"),
            "a user path: dep is not socket wiring: {}",
            warning.detail
        );
    }

    /// `grant_token_path_segment` recovers the grant token from the hosted
    /// URL shapes the reference endpoint hands back (the path level before
    /// the patch uuid) and answers `None` — never a host or empty segment —
    /// on anything else.
    #[test]
    fn grant_token_path_segment_shapes() {
        let uuid = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
        assert_eq!(
            grant_token_path_segment(
                &format!("https://patch.socket.dev/patch-registry/gem/tok-a/{uuid}/"),
                uuid
            )
            .as_deref(),
            Some("tok-a"),
            "index-url shape"
        );
        assert_eq!(
            grant_token_path_segment(
                &format!(
                    "https://patch.socket.dev/patch/gem/rails/7.0.0/tok-b/{uuid}/rails-7.0.0.gem"
                ),
                uuid
            )
            .as_deref(),
            Some("tok-b"),
            "artifact-url shape"
        );
        assert_eq!(
            grant_token_path_segment(
                &format!("https://patch.socket.dev/patch-registry/gem/tok-c/{uuid}"),
                uuid
            )
            .as_deref(),
            Some("tok-c"),
            "no trailing slash"
        );
        assert_eq!(
            grant_token_path_segment(&format!("https://patch.socket.dev/{uuid}/"), uuid),
            None,
            "uuid in the first path level has no token before it"
        );
        assert_eq!(
            grant_token_path_segment("https://patch.socket.dev/gem/tok/other/", uuid),
            None,
            "uuid absent"
        );
        assert_eq!(
            grant_token_path_segment(&format!("https://{uuid}/x/"), uuid),
            None,
            "a uuid-shaped HOST is not a path level"
        );
        assert_eq!(
            grant_token_path_segment("https://patch.socket.dev/gem/tok/x/", ""),
            None,
            "empty uuid never matches"
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

    /// A MIXED-state gem redirect breaks bundler frozen/deployment installs
    /// (the lock's GEM section still records the upstream source), so the
    /// rewrite must say so — and only when it actually changed something.
    /// Only the pre-CHECKSUMS lock (bundler <2.6, or `lockfile_checksums
    /// false`) stays mixed today; a CHECKSUMS-era lock converges instead and
    /// must NOT carry the caveat (pinned in
    /// `gem_checksums_lock_converges_gem_section_and_pins_dependency`).
    #[test]
    fn gem_redirect_warns_about_frozen_installs() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        // No CHECKSUMS section: nothing to converge around, GEM attribution
        // stays upstream — the caveat is truthful here.
        files.insert(
            "Gemfile.lock".to_string(),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nBUNDLED WITH\n   2.5.0\n"
                .to_string(),
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

    /// CHECKSUMS-era locks (bundler >= 4 writes the section by default) must
    /// come out FULLY CONVERGED, not mixed-state: the dep's spec entry moves
    /// out of the upstream GEM section into a patch-registry GEM section
    /// (`remote: <index-url>`), DEPENDENCIES pins `<name> (= <ver>)!`, and
    /// CHECKSUMS carries the patched sha. The old mixed rewrite (CHECKSUMS
    /// pinned, GEM section left upstream) made bundler refuse the prescribed
    /// unfrozen install with exit 37 "mismatched checksums" — and the
    /// converged pair needs no frozen-install caveat at all.
    #[test]
    fn gem_checksums_lock_converges_gem_section_and_pins_dependency() {
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
        let expected = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
             GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n\n\
             CHECKSUMS\n  rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   2.6.2\n",
            "f".repeat(64)
        );
        assert_eq!(
            r.files.get("Gemfile.lock"),
            Some(&expected),
            "the lock must converge: patch-registry GEM section + dependency pin + patched sha"
        );
        let source_edit = r
            .edits
            .iter()
            .find(|e| e.kind == "redirect_gemfile_lock_gem_source")
            .unwrap_or_else(|| panic!("GEM-section move edit recorded: {:?}", r.edits));
        assert_eq!(source_edit.path, "Gemfile.lock");
        assert_eq!(
            source_edit.original,
            Some(Value::String("https://rubygems.org/".into())),
            "the upstream remote is the revert original"
        );
        assert_eq!(
            source_edit.new,
            Some(Value::String("https://patch.test/gem/tok/uuid/".into()))
        );
        let dep_edit = r
            .edits
            .iter()
            .find(|e| e.kind == "redirect_gemfile_lock_dependency_pin")
            .unwrap_or_else(|| panic!("DEPENDENCIES pin edit recorded: {:?}", r.edits));
        assert_eq!(
            dep_edit.original,
            Some(Value::String("rails (= 7.0.0)".into()))
        );
        assert_eq!(dep_edit.new, Some(Value::String("rails (= 7.0.0)!".into())));
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_frozen_install"),
            "a converged pair is frozen-install-ready — the caveat would be a lie: {:?}",
            r.warnings
        );
    }

    /// Feeding the converged pair back must be a true no-op (the ledger would
    /// otherwise grow forever) — and the converged lock shape must be
    /// RECOGNIZED, not re-converged into a duplicate section.
    #[test]
    fn gem_checksums_converged_lock_rerun_is_noop() {
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
        let lock = first
            .files
            .get("Gemfile.lock")
            .expect("run 1 rewrites the lock");
        assert!(
            lock.contains(
                "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)"
            ),
            "run 1 must converge the lock: {lock}"
        );
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "converged re-run must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    /// A rotated grant must refresh the CONVERGED lock's GEM remote in place
    /// (token-wildcard recognition, exactly like the Gemfile source block) —
    /// leaving the stale remote live would send every install to the dead
    /// grant URL.
    #[test]
    fn gem_checksums_converged_lock_rotated_grant_refreshes_remote() {
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
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let first = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        let lock = second
            .files
            .get("Gemfile.lock")
            .expect("rotated grant refreshes the lock remote");
        assert_eq!(
            lock.matches("remote: https://patch.test/gem/").count(),
            1,
            "exactly one Socket GEM section: {lock}"
        );
        assert!(
            lock.contains("  remote: https://patch.test/gem/tok-two/uuid/\n"),
            "lock remote refreshed in place: {lock}"
        );
        assert!(!lock.contains("tok-one"), "stale grant gone: {lock}");
        assert!(
            second
                .edits
                .iter()
                .any(|e| e.kind == "redirect_gemfile_lock_source_url"
                    && e.original
                        == Some(Value::String("https://patch.test/gem/tok-one/uuid/".into()))
                    && e.new == Some(Value::String("https://patch.test/gem/tok-two/uuid/".into()))),
            "remote refresh recorded with the old URL as original: {:?}",
            second.edits
        );
    }

    /// A TRANSITIVE redirected dep (undeclared in the Gemfile, appended as a
    /// source block) becomes a direct source-pinned dependency, so the
    /// converged lock must gain its `<name> (= <ver>)!` DEPENDENCIES entry —
    /// inserted in bundler's sorted position — and the spec's dependency
    /// sublines must travel with the spec into the patch-registry section.
    #[test]
    fn gem_checksums_lock_transitive_dep_converges_with_sorted_dependency() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rack\", \"3.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n    rails (7.0.0)\n      rack (>= 2)\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.0.0)\n\n\
                 CHECKSUMS\n  rack (3.0.0) sha256={}\n  rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   2.6.2\n",
                "4".repeat(64),
                "2".repeat(64)
            ),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let expected = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n\n\
             GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n      rack (>= 2)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.0.0)\n  rails (= 7.0.0)!\n\n\
             CHECKSUMS\n  rack (3.0.0) sha256={}\n  rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   2.6.2\n",
            "4".repeat(64),
            "f".repeat(64)
        );
        assert_eq!(
            r.files.get("Gemfile.lock"),
            Some(&expected),
            "spec + sublines moved, dependency added sorted, sibling gem untouched"
        );
        let dep_edit = r
            .edits
            .iter()
            .find(|e| e.kind == "redirect_gemfile_lock_dependency_pin")
            .unwrap_or_else(|| panic!("DEPENDENCIES pin edit recorded: {:?}", r.edits));
        assert_eq!(dep_edit.action, "added");
        assert_eq!(dep_edit.original, None);
    }

    /// Convergence orders its edits on bundler's invariant that source
    /// sections precede DEPENDENCIES (the pin insert runs first because its
    /// lines sit after the spec-move indices). A hand-edited lock with
    /// DEPENDENCIES before GEM breaks that premise — it must fail soft to the
    /// mixed state (checksum pinned, GEM attribution untouched, frozen-install
    /// caveat), never splice with stale indices and corrupt the lock.
    #[test]
    fn gem_checksums_lock_dependencies_before_gem_fails_soft_to_mixed() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            format!(
                "DEPENDENCIES\n  rails (= 7.0.0)\n\n\
                 GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
                 PLATFORMS\n  ruby\n\nCHECKSUMS\n  rails (7.0.0) sha256={}\n\n\
                 BUNDLED WITH\n   2.6.2\n",
                "2".repeat(64)
            ),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let expected = format!(
            "DEPENDENCIES\n  rails (= 7.0.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nCHECKSUMS\n  rails (7.0.0) sha256={}\n\n\
             BUNDLED WITH\n   2.6.2\n",
            "f".repeat(64)
        );
        assert_eq!(
            r.files.get("Gemfile.lock"),
            Some(&expected),
            "only the CHECKSUMS pin lands — the unconvergeable lock keeps its shape"
        );
        assert!(
            !r.edits
                .iter()
                .any(|e| e.kind == "redirect_gemfile_lock_gem_source"
                    || e.kind == "redirect_gemfile_lock_dependency_pin"),
            "no convergence edits on the fail-soft path: {:?}",
            r.edits
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_frozen_install"),
            "the mixed pair keeps the frozen-install caveat: {:?}",
            r.warnings
        );
    }

    /// Bundler's modern `gems.rb`/`gems.locked` spelling must be redirected
    /// exactly like the classic pair — before this, a gems.rb project was a
    /// silent no-op (the rewriter keyed on the literal "Gemfile" names).
    #[test]
    fn gems_rb_pair_is_rewritten_with_modern_paths() {
        let mut files = BTreeMap::new();
        files.insert(
            "gems.rb".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "gems.locked".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let gf = r.files.get("gems.rb").expect("gems.rb rewritten");
        assert!(
            gf.contains(
                "source \"https://patch.test/gem/tok/uuid/\" do\n  gem \"rails\", \"7.0.0\"\nend"
            ),
            "source block lands in gems.rb: {gf}"
        );
        let lk = r.files.get("gems.locked").expect("gems.locked rewritten");
        assert!(
            lk.contains(&format!("  rails (7.0.0) sha256={}", "f".repeat(64))),
            "CHECKSUMS pin lands in gems.locked: {lk}"
        );
        assert!(
            !r.files.contains_key("Gemfile") && !r.files.contains_key("Gemfile.lock"),
            "classic spellings must not be invented: {:?}",
            r.files.keys()
        );
        // The ledger edits must name the files actually written, or a future
        // revert restores the wrong pair.
        assert!(
            r.edits
                .iter()
                .any(|e| e.kind == "redirect_gemfile_source_block" && e.path == "gems.rb"),
            "source-block edit keyed to gems.rb: {:?}",
            r.edits
        );
        assert!(
            r.edits
                .iter()
                .any(|e| e.kind == "redirect_gemfile_lock_checksum" && e.path == "gems.locked"),
            "lock edit keyed to gems.locked: {:?}",
            r.edits
        );
    }

    /// Both spellings present and byte-identical: follow bundler (which reads
    /// gems.rb and ignores the Gemfile) — edit gems.rb, leave Gemfile alone.
    #[test]
    fn gems_rb_beats_identical_gemfile() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string();
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), gemfile.clone());
        files.insert("Gemfile".to_string(), gemfile);
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.contains_key("gems.rb") && !r.files.contains_key("Gemfile"),
            "bundler reads gems.rb, so only gems.rb may be edited: {:?}",
            r.files.keys()
        );
    }

    /// Both spellings present and DIVERGING outside the redirect's own
    /// footprint (an unrelated gem only one file declares): editing either is
    /// a guess (the redirect could land in the file bundler ignores, or
    /// tooling pinned to the classic name keeps resolving upstream). Fail
    /// closed with a warning.
    #[test]
    fn gems_rb_and_gemfile_diverging_fail_closed() {
        let mut files = BTreeMap::new();
        files.insert(
            "gems.rb".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\ngem \"puma\", \"6.0.0\"\n"
                .to_string(),
        );
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "diverging spellings must not be edited: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "fail-closed skip must warn: {:?}",
            r.warnings
        );
    }

    /// Divergence confined to the redirected dep's OWN declaration line is
    /// tolerated: the rewriter canonicalizes that line into the managed block
    /// either way, and bundler reads gems.rb regardless (verified on 4.0.15,
    /// which warns it is ignoring the Gemfile). Only divergence outside the
    /// redirect's footprint is ambiguous enough to fail closed on.
    #[test]
    fn gems_rb_divergence_only_in_redirected_dep_line_proceeds() {
        let mut files = BTreeMap::new();
        files.insert(
            "gems.rb".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"6.1.0\"\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "the redirected dep's own line is not ambient divergence: {:?}",
            r.warnings
        );
        assert!(
            r.files.contains_key("gems.rb") && !r.files.contains_key("Gemfile"),
            "redirect proceeds on the file bundler reads: {:?}",
            r.files.keys()
        );
    }

    /// Run 1 on byte-identical twins edits only gems.rb (bundler's file),
    /// which makes the pair diverge on raw bytes. The divergence guard judges
    /// the redirect-footprint residue instead: feeding run 1's output back
    /// must be a plain no-op re-run, not a
    /// `redirect_gem_gemfile_spellings_diverge` trap that blocks every later
    /// run against the state run 1 itself created.
    #[test]
    fn gems_rb_identical_twins_rerun_is_a_no_op_not_a_diverge_trap() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string();
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), gemfile.clone());
        files.insert("Gemfile".to_string(), gemfile);
        files.insert(
            "gems.locked".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))),
        );
        let ovr = gem_override("rails", "7.0.0");
        let first = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            first.files.contains_key("gems.rb") && first.files.contains_key("gems.locked"),
            "run 1 lands on the modern pair: files={:?} warnings={:?}",
            first.files.keys(),
            first.warnings
        );
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            !second
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "the divergence run 1 itself created must not trap run 2: {:?}",
            second.warnings
        );
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "same-grant re-run is a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    /// The identical-twins re-run with a ROTATED grant (the token/uuid URL
    /// segments rotate per request) must still reach the in-place URL
    /// refresh — with a raw-byte divergence guard, run 1's edit tripped the
    /// trap and the redirect went permanently stale under the old grant.
    #[test]
    fn gems_rb_identical_twins_rerun_refreshes_rotated_grant_url() {
        fn ov(token: &str) -> DepOverride {
            let mut o = gem_override("rails", "7.0.0");
            o.token = token.into();
            if let Some(r) = o.registry_override.as_mut() {
                r.index_url = format!("https://patch.test/gem/{token}/uuid/");
            }
            o
        }
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string();
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), gemfile.clone());
        files.insert("Gemfile".to_string(), gemfile);
        let first = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        assert!(
            !second
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "run 1's own edit must not read as divergence: {:?}",
            second.warnings
        );
        let out = second
            .files
            .get("gems.rb")
            .expect("rotated grant refreshes gems.rb");
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
                .any(|e| e.kind == "redirect_gemfile_source_url" && e.path == "gems.rb"),
            "refresh recorded against gems.rb: {:?}",
            second.edits
        );
    }

    /// Twins where the redirected dep is TRANSITIVE (undeclared): run 1
    /// appends a source block to gems.rb — a footprint shape the residue
    /// comparison must also erase, including the final newline the append
    /// adds to a newline-less file.
    #[test]
    fn gems_rb_identical_twins_rerun_after_appended_block_is_no_op() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rack\", \"3.0.0\"".to_string();
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), gemfile.clone());
        files.insert("Gemfile".to_string(), gemfile);
        let ovr = gem_override("rails", "7.0.0");
        let first = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            first
                .files
                .get("gems.rb")
                .is_some_and(|gf| gf.contains("source \"https://patch.test/gem/tok/uuid/\" do")),
            "run 1 appends the block for the undeclared dep: {:?}",
            first.files
        );
        for (name, content) in first.files {
            files.insert(name, content);
        }
        let second = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            !second
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "an appended block is the redirect's own footprint, not divergence: {:?}",
            second.warnings
        );
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "re-run is a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    /// The block recognizer accepts a CRLF Socket source block (a
    /// `core.autocrlf` checkout rewrites run 1's LF output), so the residue
    /// comparison must erase that CRLF spelling too: after the checkout
    /// rewrites BOTH twins to CRLF, only gems.rb carries the block — if the
    /// residue regex stays LF-only the block survives into gems.rb's residue
    /// and every later run (the rotated-grant URL refresh included) is
    /// trapped behind `redirect_gem_gemfile_spellings_diverge`.
    #[test]
    fn gems_rb_crlf_twins_rerun_is_no_op_and_rotated_grant_refreshes() {
        fn ov(token: &str) -> DepOverride {
            let mut o = gem_override("rails", "7.0.0");
            o.token = token.into();
            if let Some(r) = o.registry_override.as_mut() {
                r.index_url = format!("https://patch.test/gem/{token}/uuid/");
            }
            o
        }
        // gems.rb exactly as run 1 wrote it, after a CRLF checkout; the
        // Gemfile twin got the same CRLF treatment but never had the block.
        let mut files = BTreeMap::new();
        files.insert(
            "gems.rb".to_string(),
            "source \"https://rubygems.org\"\r\n\r\n\
             source \"https://patch.test/gem/tok-one/uuid/\" do\r\n  \
             gem \"rails\", \"7.0.0\"\r\nend\r\n"
                .to_string(),
        );
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\r\n\r\ngem \"rails\", \"7.0.0\"\r\n".to_string(),
        );

        // Same grant: recognized in place, a true no-op — not a diverge trap.
        let same = rewrite_registry_redirect(&files, &[ov("tok-one")]);
        assert!(
            !same
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "the CRLF block is the redirect's own footprint, not divergence: {:?}",
            same.warnings
        );
        assert!(
            same.files.is_empty() && same.edits.is_empty(),
            "same-grant re-run on CRLF twins is a no-op: files={:?} edits={:?}",
            same.files.keys(),
            same.edits
        );

        // Rotated grant: URL refreshed in place inside gems.rb, never nested.
        let rotated = rewrite_registry_redirect(&files, &[ov("tok-two")]);
        assert!(
            !rotated
                .warnings
                .iter()
                .any(|w| w.code == "redirect_gem_gemfile_spellings_diverge"),
            "rotated grant must reach the refresh, not the diverge trap: {:?}",
            rotated.warnings
        );
        let out = rotated
            .files
            .get("gems.rb")
            .expect("rotated grant refreshes gems.rb on a CRLF checkout");
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
        assert!(
            !rotated.files.contains_key("Gemfile"),
            "bundler reads gems.rb; the Gemfile twin stays untouched: {:?}",
            rotated.files.keys()
        );
    }

    /// A CRLF Gemfile.lock is legal to bundler (`bundle check` and a frozen
    /// install both accept one — verified on 4.0.15). The CHECKSUMS pin must
    /// land in place, byte-preserving the `\r\n` endings — before this, the
    /// `(?m)^…$` matchers never saw the `\r`-terminated lines and the lock
    /// was misdiagnosed as bundler <2.6 (`redirect_gem_no_checksums_section`).
    #[test]
    fn gem_crlf_lock_checksum_pinned_preserving_crlf() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64))).replace('\n', "\r\n"),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_gem_no_checksums_section"),
            "a CRLF CHECKSUMS section must be recognized: {:?}",
            r.warnings
        );
        let expected = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
             GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n\n\
             CHECKSUMS\n  rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   2.6.2\n",
            "f".repeat(64)
        )
        .replace('\n', "\r\n");
        assert_eq!(
            r.files.get("Gemfile.lock"),
            Some(&expected),
            "pin + convergence rewritten in place with every \\r\\n preserved"
        );
        let edit = r
            .edits
            .iter()
            .find(|e| e.kind == "redirect_gemfile_lock_checksum")
            .expect("lock checksum edit recorded");
        assert_eq!(
            edit.original,
            Some(Value::String(format!(
                "rails (7.0.0) sha256={}",
                "2".repeat(64)
            ))),
            "recorded original carries no line-ending bytes"
        );
    }

    /// CRLF lock whose CHECKSUMS section has no entry for the gem yet: the
    /// added pin line must use the file's `\r\n` endings, not introduce a
    /// lone `\n` into an otherwise-CRLF file.
    #[test]
    fn gem_crlf_lock_checksums_header_gains_crlf_entry() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            gem_lock(&format!("  nokogiri (1.16.0) sha256={}", "4".repeat(64)))
                .replace('\n', "\r\n"),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let lk = r.files.get("Gemfile.lock").expect("lock rewritten");
        assert!(
            lk.contains(&format!(
                "CHECKSUMS\r\n  rails (7.0.0) sha256={}\r\n",
                "f".repeat(64)
            )),
            "added pin keeps the CRLF endings: {lk:?}"
        );

        // Re-run on the rewritten pair: recognizing the at-target CRLF line
        // must be a no-op (the ledger would otherwise grow forever).
        files.insert("Gemfile.lock".to_string(), lk.clone());
        files.insert(
            "Gemfile".to_string(),
            r.files.get("Gemfile").expect("Gemfile rewritten").clone(),
        );
        let second = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "CRLF re-run must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
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

    /// A bundled (`inBundle: true`) lock entry must NOT be rewritten: npm
    /// reify extracts that copy from its parent's tarball and ignores the
    /// entry's resolved/integrity, so a rewrite would put the hosted URL in
    /// the lockfile — confirming, ledger-recording, and VEX-attesting a patch
    /// whose bytes never install. It must be skipped with a loud
    /// stays-UNPATCHED warning instead (mirroring the vendored backend).
    #[test]
    fn npm_inbundle_entry_is_skipped_with_loud_warning() {
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "0.0.0" },
    "node_modules/parent": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/parent/-/parent-2.0.0.tgz",
      "integrity": "sha512-PARENT=="
    },
    "node_modules/parent/node_modules/left-pad": {
      "version": "1.3.0",
      "inBundle": true,
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#
            .to_string(),
        );
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a bundled-only dep must change nothing: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        let bundled = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_npm_bundled_instance_skipped")
            .unwrap_or_else(|| panic!("bundled skip must warn: {:?}", r.warnings));
        assert!(
            bundled.detail.contains("UNPATCHED")
                && bundled
                    .detail
                    .contains("node_modules/parent/node_modules/left-pad"),
            "the warning must say the copy stays unpatched and name the entry: {}",
            bundled.detail
        );
        assert!(
            !warning_codes(&r).contains(&"redirect_npm_entry_not_found"),
            "a bundled skip is a MATCH — not-found must stay quiet: {:?}",
            r.warnings
        );
    }

    /// When the patched dep has both a regular entry and a bundled nested
    /// copy, the regular entry is redirected and the bundled copy is left
    /// byte-untouched behind the stays-UNPATCHED warning (partial coverage
    /// must be surfaced, not silently absorbed).
    #[test]
    fn npm_inbundle_skip_leaves_sibling_rewrite_intact() {
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
    },
    "node_modules/parent/node_modules/left-pad": {
      "version": "1.3.0",
      "inBundle": true,
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#
            .to_string(),
        );
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert_eq!(r.edits.len(), 1, "only the regular entry: {:?}", r.edits);
        assert_eq!(
            r.edits[0].key.as_deref(),
            Some("node_modules/left-pad"),
            "the rewritten entry is the non-bundled one"
        );
        let out = r.files.get("package-lock.json").expect("lock rewritten");
        let lock: Value =
            serde_json::from_str(out).expect("the rewritten lock must stay valid JSON");
        let bundled_entry = &lock["packages"]["node_modules/parent/node_modules/left-pad"];
        assert_eq!(
            bundled_entry["integrity"], "sha512-UPSTREAM==",
            "the bundled copy must keep its upstream pin: {out}"
        );
        assert!(
            bundled_entry.get("resolved").is_none(),
            "no resolved may be inserted into the bundled entry: {out}"
        );
        assert!(
            warning_codes(&r).contains(&"redirect_npm_bundled_instance_skipped"),
            "partial coverage must be surfaced: {:?}",
            r.warnings
        );
    }

    /// The v1/v2 legacy `dependencies` tree spells the bundled flag
    /// `bundled: true` — same guard as `inBundle` in `packages`.
    #[test]
    fn npm_legacy_bundled_dependency_is_skipped() {
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "parent": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/parent/-/parent-2.0.0.tgz",
      "integrity": "sha512-PARENT==",
      "dependencies": {
        "left-pad": {
          "version": "1.3.0",
          "bundled": true
        }
      }
    }
  }
}
"#
            .to_string(),
        );
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "legacy bundled dep must change nothing: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            warning_codes(&r).contains(&"redirect_npm_bundled_instance_skipped"),
            "legacy bundled skip must warn: {:?}",
            r.warnings
        );
    }

    /// An alias install (`npm i my-alias@npm:left-pad@1.3.0`) keys the lock
    /// entry by the ALIAS with the real package in `name`. Discovery is
    /// alias-aware (the crawler reads the installed package.json name), so
    /// the rewriter must be too — matching on the entry's `name`, mirroring
    /// `vendor::npm_lock::entry_name`.
    #[test]
    fn npm_alias_entry_is_redirected() {
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "0.0.0" },
    "node_modules/my-alias": {
      "name": "left-pad",
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#
            .to_string(),
        );
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert_eq!(r.edits.len(), 1, "alias entry redirected: {:?}", r.warnings);
        assert_eq!(r.edits[0].key.as_deref(), Some("node_modules/my-alias"));
        let out = r.files.get("package-lock.json").expect("lock rewritten");
        let lock: Value =
            serde_json::from_str(out).expect("the rewritten lock must stay valid JSON");
        assert_eq!(
            lock["packages"]["node_modules/my-alias"]["resolved"],
            "http://patch.test/lp.tgz"
        );
        assert_eq!(
            lock["packages"]["node_modules/my-alias"]["integrity"],
            "sha512-PATCHED=="
        );
        assert!(
            !warning_codes(&r).contains(&"redirect_npm_entry_not_found"),
            "{:?}",
            r.warnings
        );
    }

    /// The reverse alias direction: `npm i left-pad@npm:other-pkg` keys an
    /// entry `node_modules/left-pad` whose `name` is the OTHER package. A
    /// deliberate fork substitution must never be hijacked back to the
    /// patched upstream artifact just because the versions coincide.
    #[test]
    fn npm_alias_of_other_package_is_not_hijacked() {
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "0.0.0" },
    "node_modules/left-pad": {
      "name": "totally-other",
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/totally-other/-/totally-other-1.3.0.tgz",
      "integrity": "sha512-FORK=="
    }
  }
}
"#
            .to_string(),
        );
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "the fork substitution must survive: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            warning_codes(&r).contains(&"redirect_npm_entry_not_found"),
            "nothing redirectable matched, which must be said: {:?}",
            r.warnings
        );
    }

    /// A granted npm override matching no lock entry (not installed, or the
    /// lock drifted to another version) must warn — parity with
    /// `redirect_pnpm_entry_not_found` / `redirect_yarn_berry_entry_not_found`.
    /// Silence here made every npm redirect miss unreadable in CI.
    #[test]
    fn npm_entry_not_found_warns() {
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "0.0.0" },
    "node_modules/left-pad": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz",
      "integrity": "sha512-OLD=="
    }
  }
}
"#
            .to_string(),
        );
        let overrides = vec![npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/lp.tgz",
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty());
        let nf = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_npm_entry_not_found")
            .unwrap_or_else(|| panic!("version drift must warn: {:?}", r.warnings));
        assert!(
            nf.detail.contains("left-pad@1.3.0") && nf.detail.contains("package-lock.json"),
            "the warning names the dep and the lockfile: {}",
            nf.detail
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

    const COMPOSER_ARTIFACT_URL: &str =
        "https://patch.socket.dev/patch/composer/acme/target/1.0.0/\
                                         11111111-1111-1111-1111-111111111111/\
                                         44444444-4444-4444-4444-444444444444/target-1.0.0.zip";
    const COMPOSER_SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";

    fn composer_override(version: &str) -> DepOverride {
        DepOverride {
            ecosystem: "composer".into(),
            name: "target".into(),
            namespace: Some("acme".into()),
            version: version.into(),
            token: String::new(),
            patch_uuid: "44444444-4444-4444-4444-444444444444".into(),
            artifact_url: COMPOSER_ARTIFACT_URL.into(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha1: Some(COMPOSER_SHA1.into()),
                ..Default::default()
            },
        }
    }

    /// A composer.lock holding `acme/target` (dist shaped by `target_dist`)
    /// followed by an untouchable bystander that DOES have a dist.
    fn composer_lock_with(target_dist: &str) -> String {
        format!(
            "{{
    \"packages\": [
        {{
            \"name\": \"acme/target\",
            \"version\": \"1.0.0\",{target_dist}
        }},
        {{
            \"name\": \"innocent/bystander\",
            \"version\": \"2.0.0\",
            \"dist\": {{
                \"type\": \"zip\",
                \"url\": \"https://api.github.com/repos/innocent/bystander/zipball/beef\",
                \"reference\": \"beef\",
                \"shasum\": \"\"
            }}
        }}
    ],
    \"packages-dev\": []
}}
"
        )
    }

    fn composer_result(lock: &str, version: &str) -> RewriteResult {
        let mut files = BTreeMap::new();
        files.insert("composer.lock".to_string(), lock.to_string());
        rewrite_registry_redirect(&files, &[composer_override(version)])
    }

    /// A source-only target (composer.lock records `source`, no `dist` — a VCS
    /// install) must fail closed. The rewriter used to find the package by name
    /// and then scan FORWARD for the next `"dist": {` with no package boundary,
    /// so it repointed the FOLLOWING package's url AND shasum at the target's
    /// patch: a checksum-clean install of the wrong code.
    #[test]
    fn composer_source_only_target_never_touches_the_next_package() {
        let lock = composer_lock_with(
            "
            \"source\": {
                \"type\": \"git\",
                \"url\": \"https://github.com/acme/target.git\",
                \"reference\": \"cafe\"
            }",
        );
        let r = composer_result(&lock, "1.0.0");
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "no dist belongs to acme/target, so nothing may be rewritten: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(warning_codes(&r), vec!["redirect_composer_no_dist"]);
    }

    /// A dist block with NO `shasum` key (VCS/zipball dists omit it) must get
    /// the pin inserted, not redirected unpinned: composer would otherwise
    /// install whatever the hosted url returned with nothing verifying it.
    #[test]
    fn composer_dist_without_shasum_key_gets_the_pin_inserted() {
        let lock = composer_lock_with(
            "
            \"dist\": {
                \"type\": \"zip\",
                \"url\": \"https://example.test/vcs/acme/target/zipball/cafe\",
                \"reference\": \"cafe\"
            }",
        );
        let r = composer_result(&lock, "1.0.0");
        let out = r
            .files
            .get("composer.lock")
            .unwrap_or_else(|| panic!("the dist must be redirected; warnings={:?}", r.warnings));
        assert!(
            out.contains(&format!(
                "\"reference\": \"cafe\",\n                \"shasum\": \"{COMPOSER_SHA1}\""
            )),
            "the sha1 must be pinned as the dist's last key, at the block's own indent: {out}"
        );
        assert!(
            serde_json::from_str::<Value>(out).is_ok(),
            "the surgical insertion must leave valid JSON: {out}"
        );
        assert!(
            out.contains("zipball/beef") && !out.contains("bystander/zipball/cafe"),
            "the bystander's dist must be untouched: {out}"
        );
        assert!(r.warnings.is_empty(), "no warnings: {:?}", r.warnings);

        // Re-run over the pinned output: nothing left to change.
        let mut again = BTreeMap::new();
        again.insert("composer.lock".to_string(), out.clone());
        let second = rewrite_registry_redirect(&again, &[composer_override("1.0.0")]);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "re-run must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
    }

    /// The locked version must match the patched one. Matching on name alone
    /// repointed whichever version the lock happened to hold at a patch built
    /// for a different one.
    #[test]
    fn composer_version_mismatch_fails_closed() {
        let lock = composer_lock_with(
            "
            \"dist\": {
                \"type\": \"zip\",
                \"url\": \"https://example.test/acme/target/zipball/cafe\",
                \"reference\": \"cafe\",
                \"shasum\": \"\"
            }",
        );
        let r = composer_result(&lock, "9.9.9");
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a lock pinning another version must not be rewritten: {:?}",
            r.files.keys()
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_composer_version_mismatch"]
        );
    }

    /// An already-redirected lock is left alone whichever way it spells the
    /// hosted url — a lock written by older composer carries `\/`-escaped
    /// slashes. Re-recording an edit whose `original` IS the hosted url would
    /// grow the committed ledger on every run and poison a future revert.
    #[test]
    fn composer_rerun_over_an_escaped_slash_redirect_is_a_noop() {
        let escaped = COMPOSER_ARTIFACT_URL.replace('/', "\\/");
        let lock = composer_lock_with(&format!(
            "
            \"dist\": {{
                \"type\": \"zip\",
                \"url\": \"{escaped}\",
                \"reference\": \"cafe\",
                \"shasum\": \"{COMPOSER_SHA1}\"
            }}"
        ));
        let r = composer_result(&lock, "1.0.0");
        assert!(
            r.files.is_empty() && r.edits.is_empty() && r.warnings.is_empty(),
            "an already-redirected lock must be a no-op: files={:?} edits={:?} warnings={:?}",
            r.files.keys(),
            r.edits,
            r.warnings
        );
    }

    /// pnpm lockfileVersion 6 embeds resolved peers in the `packages:` key
    /// itself, so one name@version can appear as BOTH `/pkg@1.0.0:` and
    /// `/pkg@1.0.0(peer@2.0.0):`. Rewriting only the plain entry would be
    /// silent fail-open — every dependent resolving through the peered entry
    /// would keep installing the unpatched upstream tarball — so EVERY
    /// instance is spliced, each under its own per-instance ledger key
    /// (lossless revert), and a re-run over the result is a byte-stable
    /// no-op with zero new edits.
    #[test]
    fn pnpm_v6_mixed_plain_and_peered_rewrites_every_instance() {
        let lock = "lockfileVersion: '6.0'

dependencies:
  left-pad:
    specifier: 1.3.0
    version: 1.3.0

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false

  /left-pad@1.3.0(react@18.2.0):
    resolution: {integrity: sha512-UPSTREAM==}
    peerDependencies:
      react: '*'
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r
            .files
            .get("pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("v6 mixed lock must be rewritten: {:?}", r.warnings));
        let spliced = format!("resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}");
        assert!(
            out.contains(&format!(
                "  /left-pad@1.3.0:\n    {spliced}\n    dev: false\n"
            )) && out.contains(&format!(
                "  /left-pad@1.3.0(react@18.2.0):\n    {spliced}\n    peerDependencies:"
            )),
            "BOTH the plain and the peered instance must be spliced: {out}"
        );
        assert!(
            !out.contains("sha512-UPSTREAM=="),
            "no instance may keep the upstream integrity: {out}"
        );
        // Per-instance ledger edits, keyed by the canonical instance key.
        let keys: Vec<&str> = r.edits.iter().filter_map(|e| e.key.as_deref()).collect();
        assert_eq!(
            keys,
            vec!["left-pad@1.3.0", "left-pad@1.3.0(react@18.2.0)"],
            "one lossless ledger edit per instance: {:?}",
            r.edits
        );
        assert!(
            r.edits.iter().all(|e| {
                e.kind == "redirect_pnpm_resolution"
                    && e.original == Some(Value::String("{integrity: sha512-UPSTREAM==}".into()))
            }),
            "every edit must preserve its instance's original resolution for revert: {:?}",
            r.edits
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code.starts_with("redirect_pnpm_")),
            "a fully-rewritten v6 lock emits no pnpm warnings: {:?}",
            r.warnings
        );

        // Idempotency: a re-run over the rewritten lock changes nothing.
        let mut files2 = BTreeMap::new();
        files2.insert("pnpm-lock.yaml".to_string(), out.clone());
        let r2 = rewrite_registry_redirect(&files2, &overrides);
        assert!(
            r2.files.is_empty() && r2.edits.is_empty(),
            "re-run must be byte-stable with zero new edits: files={:?} edits={:?}",
            r2.files.keys(),
            r2.edits
        );
        assert!(
            !r2.warnings
                .iter()
                .any(|w| w.code == "redirect_pnpm_entry_not_found"),
            "an already-redirected instance still counts as matched: {:?}",
            r2.warnings
        );
    }

    /// pnpm v6 peers-of-peers NEST the parens in the `packages:` key
    /// (`/pkg@1.0.0(react@18.2.0(scheduler@0.23.2)):`) — a spelling the
    /// splice regex's `\([^)\n]*\)` groups provably cannot match. Splicing
    /// AROUND it would be the exact fail-open the old pre-splice refusal
    /// guarded: the plain instance rewritten, the dep confirmed and
    /// VEX-attested, while every dependent resolving through the nested-peer
    /// instance keeps installing the unpatched upstream tarball. The
    /// post-splice residual gate must refuse the dep — nothing rewritten,
    /// no edits, a `redirect_pnpm_unsupported_lock_key` warning naming the
    /// residual key.
    #[test]
    fn pnpm_v6_nested_paren_peer_key_refuses_the_dep_fail_closed() {
        let lock = "lockfileVersion: '6.0'

dependencies:
  left-pad:
    specifier: 1.3.0
    version: 1.3.0

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false

  /left-pad@1.3.0(react@18.2.0(scheduler@0.23.2)):
    resolution: {integrity: sha512-UPSTREAM==}
    peerDependencies:
      react: '*'
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a partial rewrite must not ship: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        let warning = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_pnpm_unsupported_lock_key")
            .unwrap_or_else(|| panic!("the residual must be warned about: {:?}", r.warnings));
        assert!(
            warning
                .detail
                .contains("/left-pad@1.3.0(react@18.2.0(scheduler@0.23.2))"),
            "the warning must name the residual key: {}",
            warning.detail
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "redirect_pnpm_entry_not_found"),
            "the residual refusal must not double-report as not-found: {:?}",
            r.warnings
        );
    }

    /// The residual gate is SET-WIDE: a Rush-style repo whose root v9 lock
    /// splices fully while a nested lock resolves the same dep only through
    /// a nested-peer key must refuse the dep in EVERY lock. Committing the
    /// root rewrite alone would land the artifact URL in the project — the
    /// CLI's substring confirmation probe would then confirm and attest the
    /// dep while the nested lock's dependents stay on the upstream tarball.
    #[test]
    fn pnpm_residual_in_one_lock_refuses_the_dep_in_every_lock() {
        let v9_root = "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}

snapshots:
  left-pad@1.3.0: {}
";
        let v6_nested = "lockfileVersion: '6.0'

packages:

  /left-pad@1.3.0(react@18.2.0(scheduler@0.23.2)):
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), v9_root.to_string());
        files.insert(
            "common/config/rush/pnpm-lock.yaml".to_string(),
            v6_nested.to_string(),
        );
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "the dep must be refused in every lock, the fully-spliceable root \
             included: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        let warning = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_pnpm_unsupported_lock_key")
            .unwrap_or_else(|| panic!("the residual must be warned about: {:?}", r.warnings));
        assert!(
            warning.detail.contains("common/config/rush/pnpm-lock.yaml"),
            "the warning must name the lock holding the residual: {}",
            warning.detail
        );
    }

    /// Boundary contract of the loose residual probe: it flags exactly the
    /// unrewritten registry-resolved instances of THIS name@version — never
    /// v9 `snapshots:` keys (no resolution, nothing to repoint), never a
    /// longer version sharing the prefix, never an instance already pointing
    /// at the hosted artifact — while catching every suffix grammar (v6
    /// nested parens, v5 `_`) and quoted scoped spellings.
    #[test]
    fn pnpm_residual_probe_respects_version_and_section_boundaries() {
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let content = format!(
            "lockfileVersion: '9.0'

packages:
  left-pad@1.3.0:
    resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}
  left-pad@1.3.01:
    resolution: {{integrity: sha512-OTHERVERSION==}}
  '@scope/left-pad@1.3.0':
    resolution: {{integrity: sha512-OTHERPACKAGE==}}

snapshots:
  left-pad@1.3.0(react@18.2.0):
    dependencies:
      react: 18.2.0
"
        );
        assert!(
            pnpm_unrewritten_instances(&content, "left-pad", "1.3.0", url).is_empty(),
            "rewritten instances, other versions/packages, and resolution-less \
             snapshots keys must not count"
        );
        let v6 = "lockfileVersion: '6.0'

packages:

  /left-pad@1.3.0(react@18.2.0(scheduler@0.23.2)):
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
";
        assert_eq!(
            pnpm_unrewritten_instances(v6, "left-pad", "1.3.0", url),
            vec!["/left-pad@1.3.0(react@18.2.0(scheduler@0.23.2))"],
            "a nested-paren v6 instance still on the registry is a residual"
        );
        let v5 = "lockfileVersion: 5.4

packages:

  /left-pad/1.3.0_react@18.2.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
";
        assert_eq!(
            pnpm_unrewritten_instances(v5, "left-pad", "1.3.0", url),
            vec!["/left-pad/1.3.0_react@18.2.0"],
            "a v5 `_`-suffixed instance still on the registry is a residual"
        );
    }

    /// A dist block with no `url` has nothing to redirect: pinning a shasum
    /// onto it would claim a redirect that cannot happen.
    #[test]
    fn composer_dist_without_url_fails_closed() {
        let lock = composer_lock_with(
            "
            \"dist\": {
                \"type\": \"path\",
                \"reference\": \"cafe\"
            }",
        );
        let r = composer_result(&lock, "1.0.0");
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "nothing may be rewritten: {:?}",
            r.files.keys()
        );
        assert_eq!(warning_codes(&r), vec!["redirect_composer_no_dist_url"]);
    }

    /// A v6 dep resolved ONLY through a peer-suffixed key (pnpm 8 dedupes a
    /// workspace onto the peered instantiation — captured live from corepack
    /// pnpm@8.15.9, 2026-08-18) is spliced in place like any other instance,
    /// scoped names included, with the peered key preserved verbatim in the
    /// ledger edit.
    #[test]
    fn pnpm_v6_pure_peered_key_is_rewritten_in_place() {
        let lock = "lockfileVersion: '6.0'

packages:

  /@socktest/pkg@1.0.0(react@18.2.0):
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/socktest-pkg-1.0.0.tgz";
        let overrides = vec![npm_override(
            "@socktest/pkg",
            "1.0.0",
            url,
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r
            .files
            .get("pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("pure-peered v6 key must be rewritten: {:?}", r.warnings));
        assert!(
            out.contains(&format!(
                "  /@socktest/pkg@1.0.0(react@18.2.0):\n    resolution: \
                 {{integrity: sha512-PATCHED==, tarball: {url}}}\n    dev: false\n"
            )),
            "the peered entry must be spliced with its key untouched: {out}"
        );
        assert_eq!(
            r.edits.len(),
            1,
            "exactly one instance, one edit: {:?}",
            r.edits
        );
        assert_eq!(
            r.edits[0].key.as_deref(),
            Some("@socktest/pkg@1.0.0(react@18.2.0)"),
            "the ledger edit is keyed by the canonical peered instance key: {:?}",
            r.edits[0]
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code.starts_with("redirect_pnpm_")),
            "{:?}",
            r.warnings
        );
    }

    /// pnpm lockfileVersion 5.x keys are path-style (`/name/version:`, peers
    /// suffixed `_peer@ver`): BOTH instances are spliced (rewriting only one
    /// would leave the other installing upstream) and each edit is keyed by
    /// the canonical `name@version<suffix>` respelling — plain instances thus
    /// share the `name@version` key shape with every other lock grammar.
    /// Idempotency: a re-run over the result is a no-op.
    #[test]
    fn pnpm_v5_path_style_keys_rewrite_every_instance() {
        let lock = "lockfileVersion: 5.4

specifiers:
  left-pad: 1.3.0

dependencies:
  left-pad: 1.3.0

packages:

  /left-pad/1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false

  /left-pad/1.3.0_react@18.2.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r
            .files
            .get("pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("v5 lock must be rewritten: {:?}", r.warnings));
        let spliced = format!("resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}");
        assert!(
            out.contains(&format!("  /left-pad/1.3.0:\n    {spliced}\n"))
                && out.contains(&format!("  /left-pad/1.3.0_react@18.2.0:\n    {spliced}\n")),
            "BOTH v5 instances must be spliced with their path-style keys untouched: {out}"
        );
        assert!(
            !out.contains("sha512-UPSTREAM=="),
            "no instance may keep the upstream integrity: {out}"
        );
        let keys: Vec<&str> = r.edits.iter().filter_map(|e| e.key.as_deref()).collect();
        assert_eq!(
            keys,
            vec!["left-pad@1.3.0", "left-pad@1.3.0_react@18.2.0"],
            "per-instance ledger keys use the canonical respelling: {:?}",
            r.edits
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code.starts_with("redirect_pnpm_")),
            "{:?}",
            r.warnings
        );

        // Idempotency over the rewritten bytes.
        let mut files2 = BTreeMap::new();
        files2.insert("pnpm-lock.yaml".to_string(), out.clone());
        let r2 = rewrite_registry_redirect(&files2, &overrides);
        assert!(
            r2.files.is_empty() && r2.edits.is_empty(),
            "re-run must be a no-op: files={:?} edits={:?}",
            r2.files.keys(),
            r2.edits
        );
    }

    /// When a dep lives in a rewritable v9 lock AND a legacy lock in the same
    /// set (e.g. a Rush nested lock still on pnpm 7), BOTH locks are
    /// rewritten — rewriting just the v9 lock would confirm the dep while the
    /// legacy lock kept installing upstream. Each lock's edit rides its own
    /// `path` so the ledger stays lossless per file.
    #[test]
    fn pnpm_legacy_lock_in_set_is_rewritten_alongside_v9() {
        let v9_lock = "lockfileVersion: '9.0'

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}
";
        let v5_lock = "lockfileVersion: 5.4

packages:

  /left-pad/1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), v9_lock.to_string());
        files.insert(
            "common/config/rush/pnpm-lock.yaml".to_string(),
            v5_lock.to_string(),
        );
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let r = rewrite_registry_redirect(&files, &overrides);
        let spliced = format!("resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}");
        let v9_out = r
            .files
            .get("pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("the v9 lock must be rewritten: {:?}", r.warnings));
        assert!(
            v9_out.contains(&format!("  left-pad@1.3.0:\n    {spliced}\n")),
            "{v9_out}"
        );
        let v5_out = r
            .files
            .get("common/config/rush/pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("the nested v5 lock must be rewritten: {:?}", r.warnings));
        assert!(
            v5_out.contains(&format!("  /left-pad/1.3.0:\n    {spliced}\n")),
            "{v5_out}"
        );
        // One edit per lock, both under the canonical plain-instance key, each
        // carrying its own path for a lossless per-file revert.
        let mut paths: Vec<&str> = r
            .edits
            .iter()
            .filter(|e| e.key.as_deref() == Some("left-pad@1.3.0"))
            .map(|e| e.path.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["common/config/rush/pnpm-lock.yaml", "pnpm-lock.yaml"],
            "both locks' edits must be recorded: {:?}",
            r.edits
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code.starts_with("redirect_pnpm_")),
            "{:?}",
            r.warnings
        );
    }

    /// Byte-accurate pnpm 7 (lockfileVersion 5.4) grammar, captured live from
    /// `corepack pnpm@7.33.5 install` of a workspace where pkg-a consumes
    /// use-sync-external-store@1.2.0 bare and pkg-b consumes it beside
    /// react@18.2.0 (2026-08-18): the plain and `_react@18.2.0`-suffixed
    /// instances each carry their own resolution and BOTH get spliced, with
    /// every sibling line (`peerDependencies:`, `dependencies:`, `dev:`)
    /// byte-preserved. The spliced shape is exactly what pnpm@7.33.5 then
    /// frozen-installed from an empty store in the capture session.
    #[test]
    fn pnpm_v5_real_captured_peered_grammar_rewrites_both_instances() {
        let lock = "lockfileVersion: 5.4

importers:

  .:
    specifiers: {}

  pkg-a:
    specifiers:
      use-sync-external-store: 1.2.0
    dependencies:
      use-sync-external-store: 1.2.0

  pkg-b:
    specifiers:
      react: 18.2.0
      use-sync-external-store: 1.2.0
    dependencies:
      react: 18.2.0
      use-sync-external-store: 1.2.0_react@18.2.0

packages:

  /react/18.2.0:
    resolution: {integrity: sha512-/3IjMdb2L9QbBdWiW5e3P2/npwMBaU9mHCSCUzNln0ZCYbcfTsGbTJrU/kGemdH2IWmB2ioZ+zkxtmq6g09fGQ==}
    engines: {node: '>=0.10.0'}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /use-sync-external-store/1.2.0:
    resolution: {integrity: sha512-eEgnFxGQ1Ife9bzYs6VLi8/4X6CObHMw9Qr9tPY43iKwsPw8xE8+EFsf/2cFZ5S3esXgpWgtSCtLNS41F+sKPA==}
    peerDependencies:
      react: ^16.8.0 || ^17.0.0 || ^18.0.0
    dev: false

  /use-sync-external-store/1.2.0_react@18.2.0:
    resolution: {integrity: sha512-eEgnFxGQ1Ife9bzYs6VLi8/4X6CObHMw9Qr9tPY43iKwsPw8xE8+EFsf/2cFZ5S3esXgpWgtSCtLNS41F+sKPA==}
    peerDependencies:
      react: ^16.8.0 || ^17.0.0 || ^18.0.0
    dependencies:
      react: 18.2.0
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/use-sync-external-store-1.2.0.tgz";
        let overrides = vec![npm_override(
            "use-sync-external-store",
            "1.2.0",
            url,
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r
            .files
            .get("pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("captured v5 lock must be rewritten: {:?}", r.warnings));
        let spliced = format!("resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}");
        assert!(
            out.contains(&format!(
                "  /use-sync-external-store/1.2.0:\n    {spliced}\n    peerDependencies:\n      \
                 react: ^16.8.0 || ^17.0.0 || ^18.0.0\n    dev: false\n"
            )),
            "plain instance spliced, siblings byte-preserved: {out}"
        );
        assert!(
            out.contains(&format!(
                "  /use-sync-external-store/1.2.0_react@18.2.0:\n    {spliced}\n    \
                 peerDependencies:\n      react: ^16.8.0 || ^17.0.0 || ^18.0.0\n    \
                 dependencies:\n      react: 18.2.0\n    dev: false\n"
            )),
            "peered instance spliced, siblings byte-preserved: {out}"
        );
        // react's entry (whose resolution the lazy scan must not leak into)
        // stays byte-untouched.
        assert!(
            out.contains("  /react/18.2.0:\n    resolution: {integrity: sha512-/3IjMdb2L9"),
            "unrelated entries stay untouched: {out}"
        );
        let keys: Vec<&str> = r.edits.iter().filter_map(|e| e.key.as_deref()).collect();
        assert_eq!(
            keys,
            vec![
                "use-sync-external-store@1.2.0",
                "use-sync-external-store@1.2.0_react@18.2.0"
            ],
            "{:?}",
            r.edits
        );
    }

    /// Byte-accurate pnpm 8 (lockfileVersion '6.0') grammar from the same
    /// live capture (`corepack pnpm@8.15.9`, 2026-08-18): pnpm 8 deduped both
    /// importers onto the single peer-suffixed instance
    /// `/use-sync-external-store@1.2.0(react@18.2.0):` — the real-world v6
    /// peered shape — and the spliced lock frozen-installed from an empty
    /// store in the capture session.
    #[test]
    fn pnpm_v6_real_captured_peered_grammar_rewrites_in_place() {
        let lock = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: false
  excludeLinksFromLockfile: false

importers:

  .: {}

  pkg-a:
    dependencies:
      use-sync-external-store:
        specifier: 1.2.0
        version: 1.2.0(react@18.2.0)

packages:

  /use-sync-external-store@1.2.0(react@18.2.0):
    resolution: {integrity: sha512-eEgnFxGQ1Ife9bzYs6VLi8/4X6CObHMw9Qr9tPY43iKwsPw8xE8+EFsf/2cFZ5S3esXgpWgtSCtLNS41F+sKPA==}
    peerDependencies:
      react: ^16.8.0 || ^17.0.0 || ^18.0.0
    dependencies:
      react: 18.2.0
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/use-sync-external-store-1.2.0.tgz";
        let overrides = vec![npm_override(
            "use-sync-external-store",
            "1.2.0",
            url,
            "sha512-PATCHED==",
        )];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r
            .files
            .get("pnpm-lock.yaml")
            .unwrap_or_else(|| panic!("captured v6 lock must be rewritten: {:?}", r.warnings));
        assert!(
            out.contains(&format!(
                "  /use-sync-external-store@1.2.0(react@18.2.0):\n    resolution: \
                 {{integrity: sha512-PATCHED==, tarball: {url}}}\n    peerDependencies:"
            )),
            "the peered v6 instance must be spliced in place: {out}"
        );
        assert_eq!(r.edits.len(), 1, "{:?}", r.edits);
        assert_eq!(
            r.edits[0].key.as_deref(),
            Some("use-sync-external-store@1.2.0(react@18.2.0)"),
            "{:?}",
            r.edits[0]
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code.starts_with("redirect_pnpm_")),
            "{:?}",
            r.warnings
        );
    }

    /// A v6 lock whose target dep has ONLY a plain `/name@version:` key (no
    /// peered sibling anywhere) stays rewritable — the refusal must not
    /// overreach to every v6 lock.
    #[test]
    fn pnpm_v6_plain_key_without_peered_sibling_still_rewrites() {
        let lock = "lockfileVersion: '6.0'

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false

  /other-dep@2.0.0(react@18.2.0):
    resolution: {integrity: sha512-OTHER==}
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r.files.get("pnpm-lock.yaml").unwrap_or_else(|| {
            panic!(
                "plain v6 key must still be rewritten; warnings={:?}",
                r.warnings
            )
        });
        assert!(
            out.contains(&format!(
                "  /left-pad@1.3.0:\n    resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}"
            )),
            "{out}"
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code.starts_with("redirect_pnpm_")),
            "an unrelated dep's peered key must not trip the refusal: {:?}",
            r.warnings
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

    /// pnpm 1/2 projects lock with `shrinkwrap.yaml` (the pre-rename v5
    /// grammar — real layout captured in the 2026-08-18 legacy matrix:
    /// shrinkwrap.yaml + node_modules/.modules.yaml, no pnpm-lock.yaml and
    /// no package-lock.json). The no-lockfile diagnostic must be
    /// pnpm-flavored there — the npm "no package-lock.json" wording
    /// dead-ends (running `npm i --package-lock-only` would fork the
    /// project onto npm). Marker-aware family selection, fail-closed:
    /// nothing is rewritten either way.
    #[test]
    fn no_lockfile_warning_is_pnpm_flavored_when_pnpm_markers_present() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );

        // shrinkwrap.yaml present (with or without node_modules — a fresh
        // clone has only the committed lock): name the legacy lock.
        for with_marker in [true, false] {
            let mut files = BTreeMap::new();
            files.insert(
                "shrinkwrap.yaml".to_string(),
                "dependencies:\n  left-pad: 1.3.0\npackages:\n  /left-pad/1.3.0:\n    \
                 dev: false\n    resolution:\n      integrity: sha512-UPSTREAM==\n\
                 shrinkwrapVersion: 3\n"
                    .to_string(),
            );
            if with_marker {
                files.insert(
                    "node_modules/.modules.yaml".to_string(),
                    "packageManager: pnpm@2.17.0\n".to_string(),
                );
            }
            let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
            assert!(
                r.files.is_empty(),
                "nothing may be rewritten (markers are read-only): {:?}",
                r.files.keys()
            );
            assert_eq!(
                warning_codes(&r),
                vec!["redirect_pnpm_legacy_lockfile"],
                "shrinkwrap.yaml (with_marker={with_marker}) must select the \
                 pnpm-legacy wording, never redirect_npm_no_lockfile: {:?}",
                r.warnings
            );
            assert!(
                r.warnings[0].detail.contains("shrinkwrap.yaml")
                    && r.warnings[0].detail.contains("pnpm-lock.yaml"),
                "detail must name the legacy lock and the upgrade target: {}",
                r.warnings[0].detail
            );
        }

        // pnpm marker only (lock deleted / never committed): pnpm-flavored
        // "no lockfile", pointing at pnpm install — not npm.
        let mut files = BTreeMap::new();
        files.insert(
            "node_modules/.modules.yaml".to_string(),
            "packageManager: pnpm@10.0.0\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_pnpm_no_lockfile"],
            "a pnpm layout without any lock must warn pnpm-flavored: {:?}",
            r.warnings
        );
        assert!(
            r.warnings[0].detail.contains("pnpm install"),
            "detail must point at pnpm, not npm: {}",
            r.warnings[0].detail
        );
    }

    /// A VENDORED pnpm dep has no registry resolution by design — the lock
    /// key is `<name>@file:.socket/vendor/…` (v9) and the generic
    /// entry-not-found wording invites a wild-goose `pnpm install`. The
    /// warning must name the vendored state and the `vendor --revert` path
    /// instead, while a genuinely unlocked dep keeps the old code, and a
    /// same-name USER `file:` dep (not under .socket/vendor/) is never
    /// misreported as vendored. Fail-closed in all three: zero rewrites.
    #[test]
    fn pnpm_vendored_entry_is_named_vendored_not_entry_not_found() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );

        // Byte-real v9 vendored lock shape (2026-08-18 mode-conversion
        // matrix, projB snap): overrides + file:-keyed packages/snapshots.
        let vendored_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

importers:

  .:
    dependencies:
      left-pad:
        specifier: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
        version: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

packages:

  left-pad@file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-VENDORED==, tarball: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz}
    version: 1.3.0

snapshots:

  left-pad@file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz: {}
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), vendored_lock.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a vendored lock must not be rewritten (fail-closed unchanged): {:?}",
            r.files.keys()
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_pnpm_entry_vendored"],
            "the vendored dep must be named vendored: {:?}",
            r.warnings
        );
        assert!(
            r.warnings[0].detail.contains("vendor --revert")
                && r.warnings[0].detail.contains("left-pad@1.3.0"),
            "detail must name the dep and the mode-switch path: {}",
            r.warnings[0].detail
        );

        // Legacy vendored spelling (pnpm 7/8): packages rekeyed to a BARE
        // `file:` key; the `<name>@<version>: file:…` overrides line (pnpm
        // <=8 absolutizes the value) is what still carries name+version.
        let legacy_vendored = "lockfileVersion: '6.0'

overrides:
  left-pad@1.3.0: file:/abs/project/.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

packages:

  file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-VENDORED==, tarball: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz}
    name: left-pad
    version: 1.3.0
    dev: false
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), legacy_vendored.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_pnpm_entry_vendored"],
            "the legacy vendored spelling must also be recognized: {:?}",
            r.warnings
        );

        // A user's own file: dep of the same name (NOT under .socket/vendor/)
        // stays the generic entry-not-found — telling them to run `vendor
        // --revert` would be wrong.
        let user_file_lock = "lockfileVersion: '9.0'

packages:

  left-pad@file:vendor/local/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-LOCAL==, tarball: file:vendor/local/left-pad-1.3.0.tgz}
    version: 1.3.0
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), user_file_lock.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_pnpm_entry_not_found"],
            "a non-socket file: dep keeps the generic warning: {:?}",
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

    // ── golang ───────────────────────────────────────────────────────────────

    const GO_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const GO_ZIP_H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
    const GO_GOMOD_H1: &str = "h1:XgagPTRZSCprrzR+3Ro36/XJpibdovhAbsKThYI8bxg=";

    fn golang_socket_module() -> String {
        format!("patch.socket.dev/gopatch/{GO_UUID}")
    }

    /// A hosted golang reference for `github.com/foo/bar@v1.4.2`, patched
    /// module published at `patch.socket.dev/gopatch/<uuid> v1.4.2-socketpatch.1`.
    fn golang_override() -> DepOverride {
        DepOverride {
            ecosystem: "golang".into(),
            name: "github.com/foo/bar".into(),
            namespace: None,
            version: "v1.4.2".into(),
            token: String::new(),
            patch_uuid: GO_UUID.into(),
            artifact_url: format!(
                "https://patch.socket.dev/patch-registry/golang/{}/@v/v1.4.2-socketpatch.1.zip",
                golang_socket_module()
            ),
            berry_zip_url: None,
            registry_override: Some(RegistryOverride {
                kind: "goproxy".into(),
                index_url: "https://patch.socket.dev/patch-registry/golang".into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: "github.com/foo/bar".into(),
                    version: "v1.4.2".into(),
                    go_module_path: Some(golang_socket_module()),
                    go_module_version: Some("v1.4.2-socketpatch.1".into()),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                dirhash_h1: Some(GO_ZIP_H1.into()),
                go_mod_h1: Some(GO_GOMOD_H1.into()),
                ..Default::default()
            },
        }
    }

    fn golang_files() -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n".to_string(),
        );
        files.insert(
            "go.sum".to_string(),
            "github.com/foo/bar v1.4.2 h1:UPSTREAM=\ngithub.com/foo/bar v1.4.2/go.mod h1:UPSTREAMM=\n".to_string(),
        );
        files
    }

    #[test]
    fn golang_writes_replace_and_gosum_pair() {
        let files = golang_files();
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));

        assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
        let go_mod = &out.files["go.mod"];
        assert!(go_mod.contains(&format!(
            "replace github.com/foo/bar v1.4.2 => {} v1.4.2-socketpatch.1",
            golang_socket_module()
        )));
        assert!(
            go_mod.contains("require github.com/foo/bar v1.4.2"),
            "user content preserved"
        );
        let go_sum = &out.files["go.sum"];
        assert!(go_sum.contains(&format!(
            "{} v1.4.2-socketpatch.1 {GO_ZIP_H1}",
            golang_socket_module()
        )));
        assert!(go_sum.contains(&format!(
            "{} v1.4.2-socketpatch.1/go.mod {GO_GOMOD_H1}",
            golang_socket_module()
        )));
        // The replaced original's lines are PRUNED (the tidy-stable state: go
        // never fetches the fully-replaced version, and the first `go mod
        // tidy` would remove exactly these lines otherwise).
        assert!(!go_sum.contains("h1:UPSTREAM="));
        let prune = out
            .edits
            .iter()
            .find(|e| e.kind == "redirect_golang_gosum_prune")
            .expect("prune edit recorded");
        assert_eq!(prune.action, "removed");
        assert!(
            prune
                .original
                .as_ref()
                .is_some_and(|o| o.as_str().unwrap_or_default().contains("h1:UPSTREAM=")),
            "removed lines ride in `original` for revert"
        );
        // Replace + go.sum add + prune, informatively keyed.
        assert_eq!(out.edits.len(), 3);
        assert!(out.edits.iter().any(|e| e.path == "go.mod"
            && e.kind == "redirect_golang_replace"
            && e.key.as_deref() == Some("github.com/foo/bar")));
        assert!(out
            .edits
            .iter()
            .any(|e| e.path == "go.sum" && e.kind == "redirect_golang_gosum"));
    }

    #[test]
    fn golang_second_pass_is_noop() {
        let files = golang_files();
        let ovr = golang_override();
        let first = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        let mut again = files.clone();
        again.extend(first.files.clone());
        let second = rewrite_registry_redirect(&again, std::slice::from_ref(&ovr));
        assert!(
            second.files.is_empty() && second.edits.is_empty() && second.warnings.is_empty(),
            "re-run must be a no-op: files={:?} edits={:?} warnings={:?}",
            second.files.keys(),
            second.edits,
            second.warnings
        );
    }

    #[test]
    fn golang_creates_go_sum_when_absent() {
        let mut files = golang_files();
        files.remove("go.sum");
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
        let go_sum = &out.files["go.sum"];
        assert_eq!(
            go_sum.lines().count(),
            2,
            "fresh go.sum carries exactly the socket module's two lines"
        );
    }

    #[test]
    fn golang_without_override_falls_back_to_unsupported_warning() {
        let files = golang_files();
        let mut ovr = golang_override();
        ovr.registry_override = None;
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty() && out.edits.is_empty());
        assert_eq!(out.warnings.len(), 1);
        assert_eq!(out.warnings[0].code, "redirect_golang_unsupported");
        assert!(out.warnings[0].detail.contains("socket-patch vendor"));
    }

    #[test]
    fn golang_no_go_mod_warns_and_skips() {
        let mut files = golang_files();
        files.remove("go.mod");
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty());
        assert_eq!(out.warnings[0].code, "redirect_golang_no_go_mod");
    }

    /// Both go.sum hashes are load-bearing: a replace committed without them
    /// bricks every `-mod=readonly` build downstream. Missing either one must
    /// fail closed — warning, zero file changes.
    #[test]
    fn golang_missing_either_hash_fails_closed() {
        for strip in ["zip", "gomod"] {
            let files = golang_files();
            let mut ovr = golang_override();
            match strip {
                "zip" => ovr.integrity.dirhash_h1 = None,
                _ => ovr.integrity.go_mod_h1 = None,
            }
            let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
            assert!(
                out.files.is_empty() && out.edits.is_empty(),
                "{strip}: must not write a partial redirect"
            );
            assert_eq!(out.warnings[0].code, "redirect_golang_missing_integrity");
        }
    }

    #[test]
    fn golang_malformed_hash_fails_closed() {
        let files = golang_files();
        let mut ovr = golang_override();
        ovr.integrity.dirhash_h1 = Some("sha256:nope".into());
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty());
        assert_eq!(out.warnings[0].code, "redirect_golang_missing_integrity");
    }

    /// The hosted namespace prefix is the ONLY ownership signal a
    /// module-to-module replace carries — a server handing us any other path
    /// must be refused (we could never recognize or remove the directive).
    #[test]
    fn golang_module_path_outside_namespace_refused() {
        let files = golang_files();
        let mut ovr = golang_override();
        ovr.registry_override
            .as_mut()
            .unwrap()
            .identifiers
            .go_module_path = Some("evil.example/gopatch/x".into());
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty());
        assert_eq!(
            out.warnings[0].code,
            "redirect_golang_untrusted_module_path"
        );
    }

    /// `replace` is keyed on module+version and goes SILENTLY inert when the
    /// graph resolves a different version (validated empirically) — writing
    /// one against a mismatched require would claim protection it doesn't
    /// deliver.
    #[test]
    fn golang_require_version_mismatch_skips() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.5.0\n".to_string(),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty());
        assert_eq!(out.warnings[0].code, "redirect_golang_version_mismatch");
        assert!(out.warnings[0].detail.contains("v1.5.0"));
    }

    /// A module NOT in the main go.mod's require block may still be resolved
    /// (transitively) at the patched version — the cross-check only fires on a
    /// positive mismatch, never on absence.
    #[test]
    fn golang_transitive_dep_absent_from_require_still_redirects() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire example.com/direct v2.0.0\n".to_string(),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
        assert!(out.files["go.mod"].contains("replace github.com/foo/bar v1.4.2 =>"));
    }

    #[test]
    fn golang_user_authored_replace_conflict_warns() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n\nreplace github.com/foo/bar v1.4.2 => ../my-fork\n"
                .to_string(),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty(), "must not override the user's fork");
        assert_eq!(out.warnings[0].code, "redirect_golang_replace_conflict");
        // go.sum must not gain socket lines for a redirect that wasn't written.
        assert!(out.edits.is_empty());
    }

    /// Mode takeover: a local `.socket/go-patches/` replace from `apply` is
    /// rewritten in place to the hosted module — one directive, no duplicate.
    #[test]
    fn golang_takes_over_local_redirect_in_place() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n"
                .to_string(),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
        let go_mod = &out.files["go.mod"];
        assert!(!go_mod.contains("go-patches"), "local target gone");
        assert_eq!(
            go_mod.matches("replace github.com/foo/bar").count(),
            1,
            "exactly one directive for the module: {go_mod}"
        );
        // The takeover is recorded faithfully: the replaced local directive's
        // text rides in `original` (the ledger is the only pre-redirect
        // record), and the action says updated, not added.
        let edit = out
            .edits
            .iter()
            .find(|e| e.kind == "redirect_golang_replace")
            .unwrap();
        assert_eq!(edit.action, "updated");
        assert!(
            edit.original
                .as_ref()
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains(".socket/go-patches/")),
            "taken-over directive captured: {:?}",
            edit.original
        );
    }

    /// Server-controlled tokens with embedded whitespace would inject whole
    /// directives into the line-oriented go.mod/go.sum — refuse them all.
    #[test]
    fn golang_whitespace_in_tokens_fails_closed() {
        for (mutate, what) in [
            (
                Box::new(|o: &mut DepOverride| o.name = "github.com/foo/bar v0 => x".into())
                    as Box<dyn Fn(&mut DepOverride)>,
                "name",
            ),
            (
                Box::new(|o: &mut DepOverride| o.version = "v1.4.2\nreplace evil".into()),
                "version",
            ),
            (
                Box::new(|o: &mut DepOverride| {
                    o.registry_override
                        .as_mut()
                        .unwrap()
                        .identifiers
                        .go_module_version = Some("v1.0.0 h1:evil".into())
                }),
                "rhs version",
            ),
        ] {
            let files = golang_files();
            let mut ovr = golang_override();
            mutate(&mut ovr);
            let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
            assert!(
                out.files.is_empty(),
                "{what}: nothing may be written for a hostile token"
            );
            assert!(
                out.warnings
                    .iter()
                    .any(|w| w.code == "redirect_golang_unsafe_coords"
                        || w.code == "redirect_golang_version_mismatch"),
                "{what}: expected a refusal warning, got {:?}",
                out.warnings
            );
        }
        // Hash with embedded newline: strict h1 shape refuses it.
        let files = golang_files();
        let mut ovr = golang_override();
        ovr.integrity.dirhash_h1 = Some("h1:AAAA\nBBBB".into());
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty());
        assert_eq!(out.warnings[0].code, "redirect_golang_missing_integrity");
    }

    /// A committed socket pin whose version the graph no longer selects is
    /// silently inert — the rewriter must reconcile it away (and its go.sum
    /// lines), otherwise the stale module path keeps confirming the dep as
    /// redirected while go links the unpatched version.
    #[test]
    fn golang_version_mismatch_reconciles_stale_pin() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            format!(
                "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.5.0\n\n\
                 replace github.com/foo/bar v1.4.2 => {} v1.4.2-socketpatch.1\n",
                golang_socket_module()
            ),
        );
        files.insert(
            "go.sum".to_string(),
            format!(
                "{} v1.4.2-socketpatch.1 h1:{}\n",
                golang_socket_module(),
                "A".repeat(43) + "="
            ),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert_eq!(out.warnings[0].code, "redirect_golang_version_mismatch");
        let go_mod = &out.files["go.mod"];
        assert!(
            !go_mod.contains("gopatch"),
            "stale inert directive reconciled away: {go_mod}"
        );
        assert!(
            !out.files["go.sum"].contains("gopatch"),
            "stale go.sum lines reconciled away"
        );
        assert!(out
            .edits
            .iter()
            .any(|e| e.kind == "redirect_golang_stale_replace_removed"
                && e.original.as_ref().is_some_and(|v| v
                    .as_str()
                    .unwrap_or_default()
                    .contains("v1.4.2-socketpatch.1"))));
    }
}
