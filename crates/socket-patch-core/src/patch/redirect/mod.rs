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
//! Python lockfiles use TOML-aware edits to keep source identities consistent.
//! Other non-JSON formats use targeted text edits; JSON uses `serde_json` with
//! `preserve_order` (2-space pretty + trailing newline) to match the TS
//! `JSON.stringify(v, null, 2) + '\n'`.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::crawlers::composer_crawler::normalize_version;
use crate::utils::digest::is_hex64_lower;
use crate::utils::line_endings::{to_lf, LineEndings};
use crate::vendor::yarn_berry_lock::yarnrc_compression_level;

mod bun_binary;
pub use bun_binary::{preflight_bun_binary, rewrite_bun_binary};
#[cfg(test)]
mod cargo_lock_equivalence_tests;
pub mod golang_local;
#[cfg(test)]
mod lock_index_equivalence_tests;
pub mod npmrc;
mod pdm;
mod pipenv;
// pub(crate): manifest-less VEX discovery (`vex::discover::npm`) reads
// hosted pnpm locks with the SAME grammar this rewriter writes them in.
pub(crate) mod pnpm;
#[cfg(test)]
mod pnpm_equivalence_tests;
mod poetry;
mod replay;
mod requirements;
#[cfg(test)]
mod rewrite_oracle_support;
mod staged;
mod state;
mod takeover;
pub use replay::{revert_remaining_redirect_edits, GroupRefusal, ReplayOutcome};
pub use state::{
    drop_superseded_purl, load_redirect_state, persist_redirect_state, save_redirect_state,
    CorruptRedirectState, RedirectState, REDIRECT_STATE_REL,
};
/// Hosted-artifact leaf ownership rule, shared with `vex`'s bun lockfile
/// discovery (which recovers a URL tuple's version from that leaf).
pub(crate) use takeover::hosted_url_version;
pub use takeover::{
    redirect_revert_supported, revert_cargo_redirect_purl, revert_golang_redirect_purl,
    revert_npm_redirect_purl, revert_redirect_purl, RedirectRevert,
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
    /// Binary lockfiles rewritten natively, without text conversion.
    pub binary_files: BTreeMap<String, Vec<u8>>,
    pub confirmed_bun_binary_uuids: std::collections::BTreeSet<String>,
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
    /// Patch uuids whose golang redirect landed: the go.mod replace plus the
    /// socket module's go.sum pair, written by this run or already in place.
    /// Like cargo, hosted confirmation keys off this set — substring presence
    /// cannot prove it (the goproxy `indexUrl` is the bare patch-server
    /// origin, which any other hosted lockfile contains, and go.sum lines
    /// outlive a removed replace).
    pub confirmed_golang_uuids: std::collections::BTreeSet<String>,
    pub confirmed_pipenv_uuids: std::collections::BTreeSet<String>,
    pub refused_pipenv_uuids: std::collections::BTreeSet<String>,
    /// Patch uuids whose `pdm.lock` redirect fully landed (written by this run
    /// or already present). Like cargo, pdm confirmation keys off this set,
    /// never off substring presence: a lock can carry the URL in one extras
    /// variant while another variant still resolves the registry wheel.
    pub confirmed_pdm_uuids: std::collections::BTreeSet<String>,
    /// Patch uuids the pdm rewriter REFUSED (unsupported lock format, forked
    /// package, conflicting source, malformed hashes). When pdm.lock is the
    /// project's PyPI install driver they are withheld from every later pypi
    /// rewriter, so no sibling file can attest a patch the installing lock will
    /// never honor.
    pub refused_pdm_uuids: std::collections::BTreeSet<String>,
    /// An incomplete pnpm rewrite must not be confirmed by finding its URL
    /// in another instance, a comment, or another lockfile.
    pub refused_pnpm_uuids: std::collections::BTreeSet<String>,
    pub python_lock_uuids: std::collections::BTreeSet<String>,
    pub confirmed_python_lock_uuids: std::collections::BTreeSet<String>,
    pub refused_python_lock_uuids: std::collections::BTreeSet<String>,
    pub hatch_uuids: std::collections::BTreeSet<String>,
    pub confirmed_hatch_uuids: std::collections::BTreeSet<String>,
    pub confirmed_requirements_uuids: std::collections::BTreeSet<String>,
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
    // A `Value` into an in-memory buffer cannot fail; swallowing an `Err`
    // into an empty string would truncate the user's lockfile to "\n".
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).expect("serde_json::Value serializes infallibly")
    )
}

/// The dep's registry override when it is of `kind`. `None` for an absent
/// AND for a foreign-kind override alike — neither can drive this
/// ecosystem's rewrite, so every rewriter warns its missing-override code
/// for both: a granted dep the rewriter cannot honor must be SAID, never
/// silently dropped from the redirected count.
fn registry_override_of_kind<'a>(dep: &'a DepOverride, kind: &str) -> Option<&'a RegistryOverride> {
    dep.registry_override.as_ref().filter(|ov| ov.kind == kind)
}

/// Run every rewriter and merge the results (each owns distinct files).
pub fn rewrite_registry_redirect(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
) -> RewriteResult {
    rewrite_registry_redirect_with_python_metadata(files, overrides, &BTreeMap::new())
}

pub fn rewrite_registry_redirect_with_python_metadata(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    python_metadata: &BTreeMap<String, String>,
) -> RewriteResult {
    rewrite_registry_redirect_with_pipenv_version(files, overrides, python_metadata, None)
}

/// Whether any pypi override targets an entry of `files["Pipfile.lock"]` —
/// callers use it to decide whether probing the installed Pipenv release is
/// worth a subprocess and whether its absence deserves a warning.
pub fn pipenv_lock_targets(files: &BTreeMap<String, String>, overrides: &[DepOverride]) -> bool {
    pipenv::lock_targets(files, overrides)
}

/// Whether a live Pipfile.lock entry is the one Socket wrote, re-serialized by
/// a Pipenv relock (same `file`/`path` reference; only `hashes`/`version`/
/// `index` may differ). Shared with the vendored backend's revert.
pub fn pipenv_reserialized_around_reference(
    live: &serde_json::Value,
    ours: &serde_json::Value,
) -> bool {
    pipenv::reserialized_around_reference(live, ours)
}

/// Whether `pdm.lock` is the project's PyPI install driver: present, with no
/// `uv.lock` or `poetry.lock` beside it (mirroring the vendored flavor
/// precedence uv > poetry > pdm > pipenv). A leftover `pdm.lock` beside one
/// of those neither blocks nor is attested through them. `pub` so the CLI's
/// hosted confirmation gate can share the predicate instead of re-deriving it.
pub fn pdm_drives(files: &BTreeMap<String, String>) -> bool {
    files.contains_key("pdm.lock")
        && !files.contains_key("uv.lock")
        && !files.contains_key("poetry.lock")
}

/// `overrides` minus the deps whose patch uuid is in `refused` — borrowed
/// untouched when nothing was refused (the common case), cloned only when a
/// veto actually applies.
fn withhold<'a>(
    overrides: &'a [DepOverride],
    refused: &std::collections::BTreeSet<String>,
) -> Cow<'a, [DepOverride]> {
    if refused.is_empty() {
        Cow::Borrowed(overrides)
    } else {
        Cow::Owned(
            overrides
                .iter()
                .filter(|dep| !refused.contains(&dep.patch_uuid))
                .cloned()
                .collect(),
        )
    }
}

pub fn rewrite_registry_redirect_with_pipenv_version(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    python_metadata: &BTreeMap<String, String>,
    pipenv_major: Option<u32>,
) -> RewriteResult {
    let mut result = RewriteResult::default();
    // pdm runs FIRST, but only when `pdm.lock` is the project's PyPI install
    // driver (see [`pdm_drives`]). When it does, a patch it refuses is
    // withheld from every other pypi rewriter so a sibling `Pipfile.lock` /
    // `requirements.txt` cannot attest a patch the installing lock will never
    // honor.
    if pdm_drives(files) {
        pdm::rewrite(files, overrides, &mut result);
    }
    let overrides = withhold(overrides, &result.refused_pdm_uuids);
    // Pipenv next: a CONFLICT in a live Pipfile.lock vetoes the sibling pypi
    // rewriters too (see `pipenv::rewrite`).
    pipenv::rewrite(files, &overrides, pipenv_major, &mut result);
    let overrides = withhold(&overrides, &result.refused_pipenv_uuids);
    let overrides: &[DepOverride] = &overrides;
    rewrite_npm_lock(files, overrides, &mut result);
    rewrite_pnpm_lock(files, overrides, &mut result);
    rewrite_yarn_classic(files, overrides, &mut result);
    rewrite_yarn_berry(files, overrides, &mut result);
    rewrite_bun_lock(files, overrides, &mut result);
    requirements::rewrite(files, overrides, &mut result);
    rewrite_hatch(files, overrides, &mut result);
    rewrite_uv_lock(files, overrides, python_metadata, &mut result);
    poetry::rewrite_poetry(files, overrides, &mut result);
    rewrite_cargo(files, overrides, &mut result);
    rewrite_composer_lock(files, overrides, &mut result);
    rewrite_nuget(files, overrides, &mut result);
    rewrite_gem(files, overrides, &mut result);
    rewrite_maven_pom(files, overrides, &mut result);
    rewrite_golang(files, overrides, &mut result);
    result
}

fn rewrite_hatch(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    if !crate::utils::hatch::is_hatch(files) {
        return;
    }
    result.hatch_uuids.extend(
        overrides
            .iter()
            .filter(|dep| dep.ecosystem == "pypi")
            .map(|dep| dep.patch_uuid.clone()),
    );
    if files.keys().any(|file| {
        matches!(
            file.as_str(),
            "uv.lock" | "poetry.lock" | "pdm.lock" | "Pipfile.lock"
        ) || crate::utils::python_lock::is_python_lock_name(file)
    }) {
        return;
    }
    if files.contains_key("requirements.txt") {
        result
            .confirmed_hatch_uuids
            .extend(result.confirmed_requirements_uuids.iter().cloned());
        return;
    }
    // Overlay only the two documents the hatch planner reads, so the second
    // pypi dep sees the first dep's rewritten pyproject — without cloning
    // every candidate lockfile in `files` for it.
    let mut current: BTreeMap<String, String> = crate::utils::hatch::HATCH_FILES
        .into_iter()
        .filter_map(|k| files.get(k).map(|v| (k.to_owned(), v.clone())))
        .collect();
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        let Some(hash) =
            dep.integrity.sha256.as_ref().filter(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_hatch_missing_sha256".into(),
                detail: format!("{} has no valid wheel digest", dep.name),
            });
            continue;
        };
        let url = format!("{}#sha256={hash}", dep.artifact_url);
        match crate::utils::hatch::rewrite(&current, &dep.name, &dep.version, &url) {
            Ok(edits) => {
                result.confirmed_hatch_uuids.insert(dep.patch_uuid.clone());
                for (path, new) in edits {
                    result.edits.push(FileEdit {
                        path: path.clone(),
                        kind: "redirect_hatch_document".into(),
                        action: "rewritten".into(),
                        key: Some(format!("{}@{}", dep.name, dep.version)),
                        original: current.get(&path).cloned().map(Value::String),
                        new: Some(Value::String(new.clone())),
                    });
                    current.insert(path.clone(), new.clone());
                    result.files.insert(path, new);
                }
            }
            Err(detail) => result.warnings.push(RewriteWarning {
                code: "redirect_hatch_unsupported".into(),
                detail,
            }),
        }
    }
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
    // BOTH npm locks can legitimately co-exist and BOTH must be rewritten.
    // `npm shrinkwrap` was removed in npm 12, which now auto-creates a
    // `package-lock.json` beside any committed `npm-shrinkwrap.json` on first
    // install and reifies the install FROM `package-lock.json`. So the
    // dual-lock state is the DEFAULT for a shrinkwrap repo under npm 12.
    // Rewriting only the first present lock patched the file npm doesn't
    // install from — a silent FALSE SUCCESS. Rewrite EVERY present npm lock so
    // a fresh `npm install`/`npm ci` from EITHER is redirected (shrinkwrap-only
    // repos on npm <= 6 keep working: only that one file is present).
    let present: Vec<&str> = crate::constants::npm_family::NPM_LOCKS
        .into_iter()
        .filter(|f| files.contains_key(*f))
        .collect();
    if present.is_empty() {
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
                || k == "shrinkwrap.yaml"
                || k.ends_with("/shrinkwrap.yaml")
        });
        if !sibling_lock_present {
            // Without a lock, the installer-state marker still identifies
            // pnpm so the diagnostic names the right package manager.
            let warning = if files.contains_key("node_modules/.modules.yaml") {
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
    }
    for lockfile in present {
        rewrite_one_npm_lock(&files[lockfile], lockfile, &npm, result);
    }
}

/// Rewrite a single npm lockfile (`package-lock.json` or `npm-shrinkwrap.json`)
/// in place. Factored out of `rewrite_npm_lock` so co-present locks each get
/// the identical override rewrite (see the dual-lock note there).
fn rewrite_one_npm_lock(
    content: &str,
    lockfile: &str,
    npm: &[&DepOverride],
    result: &mut RewriteResult,
) {
    let Ok(mut lock) = serde_json::from_str::<Value>(content) else {
        // A corrupt lockfile is strictly worse than a missing one (which
        // warns in the caller) — never skip the whole npm redirect silently.
        result.warnings.push(RewriteWarning {
            code: "redirect_npm_lock_unparseable".into(),
            detail: format!("{lockfile} is not valid JSON; npm redirect skipped"),
        });
        return;
    };
    // The (package, version) each `packages` entry stands for, by map
    // position, computed once: the per-dep scan below compares against it
    // instead of re-deriving it for every entry for every dep. Sound
    // because a rewrite only ever touches an entry's `resolved`/`integrity`
    // (never a key, `name` or `version`), so positions and identities hold.
    let package_ids: Vec<Option<(String, Option<String>)>> = lock
        .get("packages")
        .and_then(Value::as_object)
        .map(|packages| {
            packages
                .iter()
                .map(|(key, entry)| {
                    // Only `node_modules/` keys are installable dependencies:
                    // "" is the project root and other bare keys are workspace
                    // members — SOURCE dirs a resolved/integrity insert would
                    // corrupt.
                    let (_, key_name) = key.rsplit_once("node_modules/")?;
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
                    let version = entry.get("version").and_then(Value::as_str);
                    Some((entry_nm.to_string(), version.map(str::to_string)))
                })
                .collect()
        })
        .unwrap_or_default();
    let mut changed = false;
    for dep in npm {
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
            for ((key, entry), id) in packages.iter_mut().zip(&package_ids) {
                let Some((entry_nm, version)) = id else {
                    continue;
                };
                if *entry_nm != fname || version.as_deref() != Some(dep.version.as_str()) {
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
        // npm <= 6 (the only writer of lockfileVersion 1) installs a registry
        // dependency from the CONFIGURED registry and ignores the entry's
        // `resolved` — verified against real npm 6.14.18, while npm 7 / 11
        // fetch the rewritten url from the same v1 lock. Under npm 6 the
        // redirected lock therefore fails EINTEGRITY against the patched
        // sha512 pin (fail-closed: the unpatched bytes never install). Say
        // so instead of letting an npm 6 CI discover it.
        if lock.get("lockfileVersion").and_then(Value::as_u64) == Some(1) {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_legacy_client".into(),
                detail: format!(
                    "{lockfile} is lockfileVersion 1 (written by npm <= 6). npm <= 6 installs \
                     registry dependencies from the configured registry and ignores the \
                     redirected `resolved` url, so its installs fail EINTEGRITY against the \
                     patched sha512 pin (the unpatched bytes are never installed); install \
                     with npm >= 7, which fetches the hosted patch (and upgrades the lock)"
                ),
            });
        }
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
    // The root manifest first, then every workspace-member manifest the
    // caller supplied (`<dir>/Cargo.toml`): a member's own declaration of the
    // crate resolves exactly like the root's, so it must be pinned too, or
    // the lock's repointed entry is unsatisfiable (`--locked` fails) while
    // the dep is reported redirected.
    let mut manifests: Vec<(String, String)> = files
        .iter()
        .filter(|(k, _)| k.as_str() == "Cargo.toml")
        .chain(
            files
                .iter()
                .filter(|(k, _)| is_cargo_member_manifest_key(k)),
        )
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Every planner below matches LF text. A file whose every line ends in
    // CRLF (a Windows checkout) is planned as LF and written back — edit
    // fragments included, so `remove` finds them — as CRLF. Mixed endings
    // stay as they are (and refuse where the LF grammar does not match).
    let mut crlf_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut to_lf = |path: &str, text: String| -> String {
        match crlf_to_lf(&text) {
            Some(lf) => {
                crlf_paths.insert(path.to_string());
                lf
            }
            None => text,
        }
    };
    for (path, text) in manifests.iter_mut() {
        *text = to_lf(path, std::mem::take(text));
    }
    // Each manifest's own `[package] name` — how Cargo.lock names the
    // source-less (workspace / path) package it declares.
    let manifest_packages: Vec<Option<String>> = manifests
        .iter()
        .map(|(_, text)| cargo_manifest_package_name(text))
        .collect();
    let edits_before = result.edits.len();
    let mut changed_manifests: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut cargo_lock = files
        .get("Cargo.lock")
        .cloned()
        .map(|t| to_lf("Cargo.lock", t));
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
    let mut cargo_config = files
        .get(cargo_config_key)
        .cloned()
        .map(|t| to_lf(cargo_config_key, t))
        .unwrap_or_default();
    let (mut lock_changed, mut config_changed) = (false, false);

    for dep in &cargo {
        let Some(ov) = registry_override_of_kind(dep, "cargo-sparse") else {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_missing_override".into(),
                detail: format!("{} has no cargo-sparse registry override", dep.name),
            });
            continue;
        };
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
        if !manifests.iter().any(|(k, _)| k == "Cargo.toml") {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_toml_dep_not_found".into(),
                detail: format!(
                    "no Cargo.toml present to pin {}; dependency skipped (nothing rewritten)",
                    dep.name
                ),
            });
            continue;
        }
        let other_versions =
            cargo_lock_other_versions(cargo_lock.as_deref(), &dep.name, &dep.version);
        // The root manifest's `[workspace.dependencies]` verdicts feed its
        // members' `workspace = true` inheritors.
        let mut root_workspace: BTreeMap<String, CargoWorkspaceEntry> = BTreeMap::new();
        let mut toml_plans: Vec<(usize, CargoTomlPlan)> = Vec::new();
        let mut excluded: Vec<(String, String)> = Vec::new();
        let mut refused: Option<(String, String)> = None;
        for (i, (path, text)) in manifests.iter().enumerate() {
            match plan_cargo_toml(
                text,
                path,
                &dep.name,
                &dep.version,
                &other_versions,
                &reg,
                &root_workspace,
            ) {
                Ok(plan) => {
                    if path == "Cargo.toml" {
                        root_workspace = plan.workspace.clone();
                    }
                    excluded.extend(plan.excluded.iter().map(|req| (path.clone(), req.clone())));
                    if plan.found {
                        toml_plans.push((i, plan));
                    }
                }
                Err(reason) => {
                    refused = Some((path.clone(), reason));
                    break;
                }
            }
        }
        if let Some((path, reason)) = refused {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_toml_dep_unrewritable".into(),
                detail: format!(
                    "{} in {path} cannot be pinned ({reason}); dependency skipped \
                     (nothing rewritten)",
                    dep.name
                ),
            });
            continue;
        }
        // Declared, but no declaration's requirement accepts the patched
        // version: cargo resolves each to another version, so a pin cannot
        // reach the locked one (the TS twin's requirement-coverage refusal).
        if toml_plans.is_empty() && !excluded.is_empty() {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_toml_dep_unrewritable".into(),
                detail: cargo_requirement_excludes_detail(
                    &dep.name,
                    &dep.version,
                    &excluded,
                    cargo_lock.as_deref(),
                ),
            });
            continue;
        }
        if toml_plans.is_empty() {
            result.warnings.push(RewriteWarning {
                code: "redirect_cargo_toml_dep_not_found".into(),
                detail: cargo_not_declared_detail(
                    &dep.name,
                    &dep.version,
                    manifests.len(),
                    cargo_lock.as_deref(),
                ),
            });
            continue;
        }
        // A pin reaches only the declarations it sits on: every OTHER lock
        // package depending on the crate — a registry/git crate, or a path
        // package whose manifest was not planned (outside the project, behind
        // a symlink) — keeps resolving it from crates.io, so the repointed
        // lock is unsatisfiable and that consumer compiles the unpatched copy.
        if let Some(lock_text) = cargo_lock.as_deref() {
            let pinned_packages: std::collections::BTreeSet<&str> = toml_plans
                .iter()
                .filter_map(|(i, _)| manifest_packages[*i].as_deref())
                .collect();
            let blocking =
                cargo_unpinnable_dependents(lock_text, &dep.name, &dep.version, &pinned_packages);
            if !blocking.is_empty() {
                result.warnings.push(RewriteWarning {
                    code: "redirect_cargo_transitive_dependents".into(),
                    detail: cargo_transitive_dependents_detail(&dep.name, &dep.version, &blocking),
                });
                continue;
            }
        } else {
            // NO Cargo.lock: the resolved graph the check above reads does
            // not exist, so nothing here can say whether some other
            // dependency's own graph also pulls in the crate. Any other
            // declared dependency might, and the pin reaches only the
            // declarations it sits on — that consumer would compile the
            // unpatched crates.io copy while the scan reports the crate
            // redirected and VEX attests it. Fail closed, exactly as the
            // locked path does for a dependent it CAN see; a project whose
            // only dependency is the patched crate has nothing that could
            // pull it in, and still redirects.
            let others = cargo_lockless_other_dependencies(&manifests, &dep.name);
            if !others.is_empty() {
                result.warnings.push(RewriteWarning {
                    code: "redirect_cargo_lockless_dependents".into(),
                    detail: cargo_lockless_dependents_detail(&dep.name, &dep.version, &others),
                });
                continue;
            }
        }

        // 2. Plan the Cargo.lock repoint. A lock that exists but has no
        // [[package]] for the dep means the project does not actually resolve
        // it — rewriting the manifest anyway would desync manifest and lock.
        // Skip the dep entirely (discarding the manifest plan). A project
        // with NO lockfile reaches here only when the patched crate is its
        // one declared dependency (the dependents gate above): the manifest
        // pin alone then forces the next resolution through the managed
        // registry, which serves the patched checksum.
        enum LockCommit {
            Write(String, Vec<FileEdit>),
            InPlace,
            Absent,
        }
        let lock_commit = if let Some(lock_text) = cargo_lock.as_ref() {
            match plan_cargo_lock(lock_text, &dep.name, &dep.version, index_url, &cksum) {
                CargoLockPlan::Rewritten { content, edits } => LockCommit::Write(content, edits),
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
                CargoLockPlan::Ambiguous => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_cargo_lock_pkg_ambiguous".into(),
                        detail: format!(
                            "Cargo.lock holds more than one [[package]] for {}@{} (several \
                             sources) and none of them is the socket registry copy; cannot \
                             tell which to repoint — dependency skipped (nothing rewritten)",
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
        for (i, plan) in toml_plans {
            if plan.changed {
                changed_manifests.insert(manifests[i].0.clone());
                manifests[i].1 = plan.content;
                result.edits.extend(plan.edits);
            }
        }
        match lock_commit {
            LockCommit::Write(content, edits) => {
                cargo_lock = Some(content);
                result.edits.extend(edits);
                lock_changed = true;
            }
            LockCommit::InPlace | LockCommit::Absent => {}
        }
        result.confirmed_cargo_uuids.insert(dep.patch_uuid.clone());
    }

    let restore = |path: &str, text: String| -> String {
        if crlf_paths.contains(path) {
            text.replace('\n', "\r\n")
        } else {
            text
        }
    };
    for edit in &mut result.edits[edits_before..] {
        if crlf_paths.contains(&edit.path) {
            for fragment in [&mut edit.original, &mut edit.new] {
                if let Some(Value::String(text)) = fragment {
                    *text = text.replace('\n', "\r\n");
                }
            }
        }
    }
    for (path, text) in manifests {
        if changed_manifests.contains(&path) {
            let text = restore(&path, text);
            result.files.insert(path, text);
        }
    }
    if lock_changed {
        if let Some(l) = cargo_lock {
            result
                .files
                .insert("Cargo.lock".into(), restore("Cargo.lock", l));
        }
    }
    if config_changed {
        result.files.insert(
            cargo_config_key.into(),
            restore(cargo_config_key, cargo_config),
        );
    }
}

/// `text` with every CRLF turned into LF, when every line break in it is a
/// CRLF (and there is at least one); `None` for LF-only or mixed text.
fn crlf_to_lf(text: &str) -> Option<String> {
    let crlf = text.matches("\r\n").count();
    (crlf > 0 && crlf == text.matches('\n').count()).then(|| text.replace("\r\n", "\n"))
}

/// A workspace-member manifest key the caller supplied: `<dir>/Cargo.toml`,
/// a plain repo-relative path (never absolute, never `..`, never under the
/// ledger's `.socket/` or a build `target/`).
fn is_cargo_member_manifest_key(key: &str) -> bool {
    let Some(dir) = key.strip_suffix("/Cargo.toml") else {
        return false;
    };
    !dir.is_empty()
        && !key.starts_with('/')
        && !key.contains('\\')
        && !key.contains(':')
        && dir.split('/').all(|seg| {
            !seg.is_empty() && seg != "." && seg != ".." && seg != ".socket" && seg != "target"
        })
}

/// The not-declared warning for a crate no manifest names at the patched
/// version. A crate Cargo.lock nonetheless resolves is a TRANSITIVE-only
/// dependency: a `registry = "…"` pin reaches only the declaration it sits
/// on, so hosted mode cannot redirect it at all — say so, and name the mode
/// that can (vendored `[patch.crates-io]` applies to the whole graph).
fn cargo_not_declared_detail(
    crate_name: &str,
    version: &str,
    manifests: usize,
    lock: Option<&str>,
) -> String {
    let scope = if manifests > 1 {
        format!("any of the {manifests} workspace manifests")
    } else {
        "Cargo.toml".to_string()
    };
    let head = format!("[[package]]\nname = \"{crate_name}\"\nversion = \"{version}\"\n");
    let transitive = lock.is_some_and(|lock| {
        lock.match_indices(head.as_str())
            .any(|(at, _)| at == 0 || lock.as_bytes()[at - 1] == b'\n')
    });
    if transitive {
        format!(
            "{crate_name}@{version} is a transitive-only dependency (Cargo.lock resolves it, \
             but no [dependencies] entry in {scope} declares it); hosted mode can pin only \
             direct dependencies, so it was NOT redirected and stays unpatched — patch it with \
             `socket-patch scan --mode vendored`, or declare it directly and re-run \
             (nothing rewritten)"
        )
    } else {
        format!(
            "no [dependencies] entry for {crate_name} in {scope}; dependency skipped \
             (nothing rewritten)"
        )
    }
}

/// The refusal for a crate every declaration of which requires another
/// version (`excluded`: each declaring manifest and its requirement).
fn cargo_requirement_excludes_detail(
    crate_name: &str,
    version: &str,
    excluded: &[(String, String)],
    lock: Option<&str>,
) -> String {
    let declared = excluded
        .iter()
        .map(|(path, req)| format!("\"{req}\" in {path}"))
        .collect::<Vec<_>>()
        .join(", ");
    let head = format!("[[package]]\nname = \"{crate_name}\"\nversion = \"{version}\"\n");
    let locked = lock.is_some_and(|lock| {
        lock.match_indices(head.as_str())
            .any(|(at, _)| at == 0 || lock.as_bytes()[at - 1] == b'\n')
    });
    let remedy = if locked {
        "; Cargo.lock resolves it for another package, which a pin cannot reach — patch it \
         with `socket-patch scan --mode vendored`"
    } else {
        ""
    };
    format!(
        "{crate_name} is declared as {declared}, which {version} does not satisfy (cargo \
         resolves that declaration to another version){remedy}; dependency skipped (nothing \
         rewritten)"
    )
}

/// The `[package] name` a manifest declares (`None` for a virtual workspace
/// root or an unparseable file).
fn cargo_manifest_package_name(text: &str) -> Option<String> {
    let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
    doc.get("package")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// The Cargo.lock packages that depend on `crate_name@version` and that a
/// manifest pin cannot reach: any package with a `source` (a registry or
/// git crate), and any source-less (workspace / path) package whose
/// manifest is not among `pinned_packages`. Dependency edges are matched
/// in every spelling — `"name"`, `"name version"` and the full
/// `"name version (source)"` id — so a v1 lock and a twin's full id are
/// covered alike. A lock that does not parse yields one entry saying so.
fn cargo_unpinnable_dependents(
    lock: &str,
    crate_name: &str,
    version: &str,
    pinned_packages: &std::collections::BTreeSet<&str>,
) -> Vec<String> {
    let Ok(doc) = lock.parse::<toml_edit::DocumentMut>() else {
        return vec!["Cargo.lock (it does not parse as TOML)".to_string()];
    };
    let Some(packages) = doc
        .get("package")
        .and_then(toml_edit::Item::as_array_of_tables)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for package in packages.iter() {
        let field = |key: &str| package.get(key).and_then(toml_edit::Item::as_str);
        let (Some(name), Some(pkg_version)) = (field("name"), field("version")) else {
            continue;
        };
        let depends = package
            .get("dependencies")
            .and_then(toml_edit::Item::as_array)
            .is_some_and(|deps| {
                deps.iter().filter_map(|d| d.as_str()).any(|d| {
                    let mut parts = d.splitn(3, ' ');
                    parts.next() == Some(crate_name) && parts.next().is_none_or(|v| v == version)
                })
            });
        if !depends {
            continue;
        }
        match field("source") {
            Some(source) => {
                let kind = if source.starts_with("git+") {
                    "git"
                } else {
                    "registry"
                };
                out.push(format!("{name} {pkg_version} ({kind})"));
            }
            None if !pinned_packages.contains(name) => {
                out.push(format!(
                    "{name} {pkg_version} (a path package whose Cargo.toml is outside the \
                     project or not rewritable)"
                ));
            }
            None => {}
        }
    }
    out
}

/// Dependencies OTHER than `crate_name` declared across the manifests this
/// rewriter can pin, as `<name> (in <manifest>)`. This is the question a
/// Cargo.lock answers outright; without one, every such dependency is a
/// possible second consumer of the patched crate. A path dependency on a
/// manifest in this same list is NOT one of them — that package's own
/// declarations are listed here too — and a `workspace = true` inheritor
/// resolves to the root's `[workspace.dependencies]` entry, which is.
/// A manifest that does not parse is itself blocking (fail closed).
fn cargo_lockless_other_dependencies(
    manifests: &[(String, String)],
    crate_name: &str,
) -> Vec<String> {
    fn field<'a>(entry: &'a toml_edit::Item, key: &str) -> Option<&'a str> {
        match entry {
            toml_edit::Item::Table(t) => t.get(key).and_then(toml_edit::Item::as_str),
            toml_edit::Item::Value(v) => v
                .as_inline_table()
                .and_then(|t| t.get(key))
                .and_then(toml_edit::Value::as_str),
            _ => None,
        }
    }
    fn flag(entry: &toml_edit::Item, key: &str) -> bool {
        match entry {
            toml_edit::Item::Table(t) => t.get(key).and_then(toml_edit::Item::as_bool),
            toml_edit::Item::Value(v) => v
                .as_inline_table()
                .and_then(|t| t.get(key))
                .and_then(toml_edit::Value::as_bool),
            _ => None,
        }
        .unwrap_or(false)
    }
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let known: std::collections::BTreeSet<&str> =
        manifests.iter().map(|(k, _)| k.as_str()).collect();
    let mut out: Vec<String> = Vec::new();
    for (path, text) in manifests {
        let dir = path.strip_suffix("/Cargo.toml").unwrap_or("");
        let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
            out.push(format!("{path} (it does not parse as TOML)"));
            continue;
        };
        let scan = |item: Option<&toml_edit::Item>, out: &mut Vec<String>| {
            let Some(table) = item.and_then(toml_edit::Item::as_table_like) else {
                return;
            };
            for (key, entry) in table.iter() {
                let name = field(entry, "package").unwrap_or(key);
                if name == crate_name || flag(entry, "workspace") {
                    continue;
                }
                if let Some(rel) = field(entry, "path") {
                    let inside = crate::utils::cargo_workspace::normalize_rel(dir, rel)
                        .is_some_and(|d| {
                            d.is_empty() || known.contains(format!("{d}/Cargo.toml").as_str())
                        });
                    if inside {
                        continue;
                    }
                }
                let named = if path == "Cargo.toml" {
                    name.to_string()
                } else {
                    format!("{name} (in {path})")
                };
                if !out.contains(&named) {
                    out.push(named);
                }
            }
        };
        for kind in KINDS {
            scan(doc.get(kind), &mut out);
        }
        if let Some(targets) = doc.get("target").and_then(toml_edit::Item::as_table) {
            for (_, target) in targets.iter() {
                let Some(target) = target.as_table() else {
                    continue;
                };
                for kind in KINDS {
                    scan(target.get(kind), &mut out);
                }
            }
        }
        if let Some(ws) = doc.get("workspace").and_then(toml_edit::Item::as_table) {
            scan(ws.get("dependencies"), &mut out);
            // A member manifest this run did not read is a second consumer
            // nothing can rule out: it may declare the crate itself (a pin
            // never reaches it) or a dependency that pulls it in. Member
            // discovery drops what it must not follow — a symbolic link, a
            // path outside the project — and a glob's expansion is not
            // visible here at all, so only a literal member whose manifest
            // IS in this run's set is accounted for.
            let members = ws
                .get("members")
                .and_then(toml_edit::Item::as_array)
                .into_iter()
                .flat_map(|a| a.iter().filter_map(toml_edit::Value::as_str));
            for member in members {
                let named = if member.contains(['*', '?']) {
                    format!("the workspace members pattern `{member}`")
                } else if crate::utils::cargo_workspace::normalize_rel(dir, member)
                    .is_some_and(|d| known.contains(format!("{d}/Cargo.toml").as_str()))
                {
                    continue;
                } else {
                    format!("the workspace member `{member}`")
                };
                if !out.contains(&named) {
                    out.push(named);
                }
            }
        }
    }
    out
}

/// The refusal for a lockless project that declares other dependencies.
fn cargo_lockless_dependents_detail(crate_name: &str, version: &str, others: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut names = others
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if others.len() > SHOWN {
        names.push_str(&format!(" and {} more", others.len() - SHOWN));
    }
    format!(
        "this project has no Cargo.lock, so nothing says whether {names} also pull in \
         {crate_name}@{version}; a `registry = …` pin reaches only the declarations it sits \
         on, so such a consumer would compile the unpatched crates.io copy while \
         {crate_name} is reported redirected — commit a lockfile (`cargo generate-lockfile`) \
         and re-run, or patch it with `socket-patch scan --mode vendored`, whose \
         `[patch.crates-io]` covers the whole graph (nothing rewritten)"
    )
}

/// The refusal for a crate other lock packages also depend on.
fn cargo_transitive_dependents_detail(
    crate_name: &str,
    version: &str,
    blocking: &[String],
) -> String {
    const SHOWN: usize = 5;
    let mut names = blocking
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if blocking.len() > SHOWN {
        names.push_str(&format!(" and {} more", blocking.len() - SHOWN));
    }
    format!(
        "{crate_name}@{version} is also a dependency of {names} in Cargo.lock; a `registry = …` \
         pin reaches only the declarations it sits on, so those would keep resolving \
         {crate_name} from crates.io (a `--locked` build fails, and the unpatched copy is \
         compiled) — it was NOT redirected and stays unpatched; patch it with \
         `socket-patch scan --mode vendored` (nothing rewritten)"
    )
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

/// The uuid of a Socket-owned registry / repository / source NAME in its
/// EXACT grammar: `socket-patch-<canonical-uuid>`, or with `vendored`
/// `socket-patch-vendor-<canonical-uuid>` (maven's vendored repository id).
/// No trimming: the rewriter must never treat a user's padded pin as its
/// own, while lockfile discovery trims at its call site
/// (`vex::discover::socket_patch_name_uuid`).
pub(crate) fn socket_patch_name_uuid_exact(name: &str, vendored: bool) -> Option<&str> {
    let prefix = if vendored {
        "socket-patch-vendor-"
    } else {
        "socket-patch-"
    };
    name.strip_prefix(prefix)
        .filter(|uuid| crate::patch::path_safety::is_canonical_uuid(uuid))
}

/// A registry name THIS rewriter owns: `socket-patch-<canonical-uuid>`. An
/// existing pin matching this grammar was written by a previous run and may be
/// superseded in place; any other registry pin is the user's and is refused.
fn is_socket_patch_registry_name(value: &str) -> bool {
    socket_patch_name_uuid_exact(value, false).is_some()
}

/// The `socket-patch-<uuid>` registry name pinning `crate_name` in this
/// manifest, in EVERY declaration shape [`plan_cargo_toml`] writes: a
/// `[…dependencies.<key>]` header table (whose pin is a standalone
/// `registry = …` line), an inline table, a quoted key, and a rename
/// (`package = "<crate>"` under any key). Readers that probe for a LIVE
/// hosted redirect use this rather than a single-line regex, which saw only
/// the inline spelling and read the other three as "not redirected".
pub(crate) fn cargo_socket_registry_pin(content: &str, crate_name: &str) -> Option<String> {
    let lines: Vec<&str> = content.split('\n').collect();
    let socket_value = |text: &str| -> Option<String> {
        CARGO_TOML_REGISTRY_VAL_RE
            .captures(text)
            .map(|c| c[1].to_string())
            .filter(|v| is_socket_patch_registry_name(v))
    };
    let mut section = CargoTomlSection::Other;
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            section = match CARGO_TOML_HEADER_RE.captures(trimmed) {
                Some(c) => classify_cargo_section(
                    c.get(1)
                        .expect("header_re always captures group 1 (section name)")
                        .as_str(),
                ),
                None => CargoTomlSection::Other,
            };
            let CargoTomlSection::DepEntry { key, .. } = section.clone() else {
                continue;
            };
            let end = lines
                .iter()
                .enumerate()
                .skip(idx + 1)
                .find(|(_, l)| l.trim_start().starts_with('['))
                .map_or(lines.len(), |(j, _)| j);
            let block: Vec<&str> = (idx + 1..end)
                .map(|j| lines[j].trim_start())
                .filter(|t| !t.is_empty() && !t.starts_with('#'))
                .collect();
            let value_of = |name: &str| -> Option<String> {
                block.iter().find_map(|t| {
                    let (k, rest) = parse_cargo_entry_key(t)?;
                    if k != name {
                        return None;
                    }
                    let v = rest.trim_start().strip_prefix('=')?.trim();
                    Some(
                        v.strip_prefix('"')
                            .and_then(|s| s.split('"').next())
                            .unwrap_or(v)
                            .to_string(),
                    )
                })
            };
            let is_ours = match value_of("package") {
                Some(package) => package == crate_name,
                None => key == crate_name,
            };
            if is_ours {
                if let Some(reg) = value_of("registry").filter(|v| is_socket_patch_registry_name(v))
                {
                    return Some(reg);
                }
            }
            continue;
        }
        let CargoTomlSection::DepTable { .. } = section else {
            continue;
        };
        let Some((key, rest)) = parse_cargo_entry_key(trimmed) else {
            continue;
        };
        let rest_trim = rest.trim_start();
        if let Some(dotted) = rest_trim.strip_prefix('.') {
            // `<crate>.registry = "socket-patch-…"`: a spelling this rewriter
            // refuses to write, but a hand edit can leave one behind.
            if key == crate_name
                && parse_cargo_entry_key(dotted).is_some_and(|(k, _)| k == "registry")
            {
                if let Some(reg) = socket_value(trimmed) {
                    return Some(reg);
                }
            }
            continue;
        }
        let Some(value) = rest_trim.strip_prefix('=').map(str::trim_start) else {
            continue;
        };
        if !value.starts_with('{') {
            continue;
        }
        let Some(close) = value.find('}') else {
            continue;
        };
        let inner = &value[1..close];
        let is_ours = match CARGO_TOML_PACKAGE_RE.captures(inner) {
            Some(c) => c[1] == *crate_name,
            None => key == crate_name,
        };
        if is_ours {
            if let Some(reg) = socket_value(inner) {
                return Some(reg);
            }
        }
    }
    None
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
    /// Whether this manifest declares the crate at the patched version at
    /// all (rename-aware: a key that matches but has `package = "<other>"`
    /// is NOT the crate). `false` plans nothing.
    found: bool,
    /// This manifest's `[workspace.dependencies]` verdicts, per key — what
    /// its members' `workspace = true` inheritors resolve against.
    workspace: BTreeMap<String, CargoWorkspaceEntry>,
    /// The requirements of this manifest's declarations of the crate that
    /// do NOT accept the patched version (cargo resolves each to another
    /// version).
    excluded: Vec<String>,
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
// The Cargo.toml planner's fixed probes, compiled once: `plan_cargo_toml`
// runs once per cargo dep, and a regex compile per probe per dep is pure
// waste on a manifest with many patched crates.
static CARGO_TOML_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[([^\]]+)\]\s*(?:#.*)?$").expect("static section-header regex is valid")
});
static CARGO_TOML_PACKAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bpackage\s*=\s*"([^"]*)""#).expect("static package-key regex is valid")
});
static CARGO_TOML_REGISTRY_VAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bregistry\s*=\s*"([^"]*)""#).expect("static registry-value regex is valid")
});
static CARGO_TOML_REGISTRY_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bregistry\s*=").expect("static registry-key probe regex is valid")
});
static CARGO_TOML_REGISTRY_INDEX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bregistry-index\s*=").expect("static registry-index probe regex is valid")
});
static CARGO_TOML_WORKSPACE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bworkspace\s*=").expect("static workspace-key probe regex is valid")
});
static CARGO_TOML_PATH_GIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:path|git)\s*=").expect("static path/git probe regex is valid")
});

static CARGO_TOML_VERSION_VAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bversion\s*=\s*"([^"]*)""#).expect("static version-value regex is valid")
});

/// Whether one declaration's version requirement selects the patched
/// version. Cargo resolves a declaration to ONE version, so a project that
/// locks several versions of a crate (`cfg-if = "1"` beside a renamed
/// `cfg-if-legacy = { package = "cfg-if", version = "0.1" }`) must pin
/// only the declaration whose requirement matches the patched version —
/// pinning every same-named declaration to one registry leaves the other
/// requirement unsatisfiable there.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum CargoReqMatch {
    Ours,
    NotOurs,
    /// The requirement also matches another locked version (or cannot be
    /// read while another version is locked): which one cargo picked for
    /// this declaration cannot be told from the manifest.
    Ambiguous,
}

pub(crate) fn cargo_req_selects(
    req: Option<&str>,
    version: &str,
    other_versions: &[String],
) -> CargoReqMatch {
    let unknown = if other_versions.is_empty() {
        CargoReqMatch::Ours
    } else {
        CargoReqMatch::Ambiguous
    };
    let (Some(req), Ok(patched)) = (req, semver::Version::parse(version)) else {
        return unknown;
    };
    let Ok(req) = semver::VersionReq::parse(req.trim()) else {
        return unknown;
    };
    if !req.matches(&patched) {
        return CargoReqMatch::NotOurs;
    }
    let also_other = other_versions
        .iter()
        .any(|v| semver::Version::parse(v).is_ok_and(|v| req.matches(&v)));
    if also_other {
        CargoReqMatch::Ambiguous
    } else {
        CargoReqMatch::Ours
    }
}

/// What a `[workspace.dependencies]` entry means for the patched version —
/// resolved per entry KEY, since `workspace = true` inherits by key.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CargoWorkspaceEntry {
    /// The entry lands (or already carries) the pin.
    Pinned,
    /// The entry names the crate at another version.
    OtherVersion,
}

/// Every version of `crate_name` a Cargo.lock holds other than `version`.
fn cargo_lock_other_versions(lock: Option<&str>, crate_name: &str, version: &str) -> Vec<String> {
    let Some(lock) = lock else {
        return Vec::new();
    };
    let head = format!("[[package]]\nname = \"{crate_name}\"\nversion = \"");
    let mut versions: Vec<String> = lock
        .match_indices(head.as_str())
        .filter(|&(at, _)| at == 0 || lock.as_bytes()[at - 1] == b'\n')
        .filter_map(|(at, _)| {
            let rest = &lock[at + head.len()..];
            rest.split_once('"').map(|(v, _)| v.to_string())
        })
        .filter(|v| v != version)
        .collect();
    versions.sort();
    versions.dedup();
    versions
}

/// `Err` carries the refusal reason: an occurrence exists that cannot be
/// pinned to the managed registry, so the whole dep must be skipped.
/// `inherited` is the workspace root's verdicts when planning a member.
fn plan_cargo_toml(
    content: &str,
    path: &str,
    crate_name: &str,
    version: &str,
    other_versions: &[String],
    reg: &str,
    inherited: &BTreeMap<String, CargoWorkspaceEntry>,
) -> Result<CargoTomlPlan, String> {
    let lines: Vec<&str> = content.split('\n').collect();
    let header_re: &Regex = &CARGO_TOML_HEADER_RE;
    let package_re: &Regex = &CARGO_TOML_PACKAGE_RE;
    let registry_val_re: &Regex = &CARGO_TOML_REGISTRY_VAL_RE;
    let registry_key_re: &Regex = &CARGO_TOML_REGISTRY_KEY_RE;
    let registry_index_re: &Regex = &CARGO_TOML_REGISTRY_INDEX_RE;
    let workspace_key_re: &Regex = &CARGO_TOML_WORKSPACE_KEY_RE;
    let path_git_re: &Regex = &CARGO_TOML_PATH_GIT_RE;
    let version_val_re: &Regex = &CARGO_TOML_VERSION_VAL_RE;
    let ambiguous =
        || format!("its version requirement also matches another locked version of {crate_name}");

    // A pending occurrence: what was found, resolved to an action in pass 2
    // (workspace-inheriting entries need the whole file scanned first).
    enum Pending {
        Action(CargoTomlAction),
        /// `workspace = true` under this key.
        NeedsWorkspacePin(String),
        Refuse(String),
    }
    let mut pending: Vec<Pending> = Vec::new();
    // Per `[workspace.dependencies]` key naming the crate: whether that
    // entry lands (or already carries) the pin — satisfies `workspace =
    // true` inheritors of the same key — or names another version.
    let mut ws_entries: BTreeMap<String, CargoWorkspaceEntry> = BTreeMap::new();
    let mut excluded: Vec<String> = Vec::new();

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
                let req = find_value("version").map(|(_, v)| v);
                let selects = if has("workspace") {
                    CargoReqMatch::Ours
                } else {
                    cargo_req_selects(req.as_deref(), version, other_versions)
                };
                if selects == CargoReqMatch::NotOurs {
                    excluded.extend(req);
                    if ws {
                        ws_entries.insert(key.clone(), CargoWorkspaceEntry::OtherVersion);
                    }
                    continue;
                }
                if has("workspace") {
                    pending.push(Pending::NeedsWorkspacePin(key.clone()));
                } else if selects == CargoReqMatch::Ambiguous {
                    pending.push(Pending::Refuse(ambiguous()));
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
                            ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
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
                            ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
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
                        ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
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
                    pending.push(Pending::NeedsWorkspacePin(key.clone()));
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
                pending.push(Pending::NeedsWorkspacePin(key.clone()));
                continue;
            }
            let req = version_val_re.captures(inner).map(|c| c[1].to_string());
            match cargo_req_selects(req.as_deref(), version, other_versions) {
                CargoReqMatch::NotOurs => {
                    excluded.extend(req);
                    if workspace {
                        ws_entries.insert(key.clone(), CargoWorkspaceEntry::OtherVersion);
                    }
                    continue;
                }
                CargoReqMatch::Ambiguous => {
                    pending.push(Pending::Refuse(ambiguous()));
                    continue;
                }
                CargoReqMatch::Ours => {}
            }
            if path_git_re.is_match(inner) {
                pending.push(Pending::Refuse(
                    "declared as a path/git dependency".to_string(),
                ));
            } else if let Some(c) = registry_val_re.captures(inner) {
                let value = c[1].to_string();
                if value == reg {
                    pending.push(Pending::Action(CargoTomlAction::Already));
                    if workspace {
                        ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
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
                        ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
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
                    ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
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
            let req = m
                .get(2)
                .expect("line_re always captures group 2 (version)")
                .as_str();
            match cargo_req_selects(Some(req), version, other_versions) {
                CargoReqMatch::NotOurs => {
                    excluded.push(req.to_string());
                    if workspace {
                        ws_entries.insert(key.clone(), CargoWorkspaceEntry::OtherVersion);
                    }
                    continue;
                }
                CargoReqMatch::Ambiguous => {
                    pending.push(Pending::Refuse(ambiguous()));
                    continue;
                }
                CargoReqMatch::Ours => {}
            }
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
                ws_entries.insert(key.clone(), CargoWorkspaceEntry::Pinned);
            }
        } else if key == crate_name {
            pending.push(Pending::Refuse(
                "unsupported dependency-entry spelling".to_string(),
            ));
        }
    }

    let not_found = |ws_entries: BTreeMap<String, CargoWorkspaceEntry>| CargoTomlPlan {
        content: content.to_string(),
        edits: Vec::new(),
        changed: false,
        found: false,
        workspace: ws_entries,
        excluded: excluded.clone(),
    };
    if pending.is_empty() {
        return Ok(not_found(ws_entries));
    }
    // Resolve: any refusal (including an unsatisfiable `workspace = true`
    // inheritor) refuses the WHOLE dep — no partial pin is ever applied.
    let mut actions: Vec<CargoTomlAction> = Vec::new();
    for p in pending {
        match p {
            Pending::Action(a) => actions.push(a),
            Pending::NeedsWorkspacePin(key) => match ws_entries.get(&key).or(inherited.get(&key)) {
                Some(CargoWorkspaceEntry::Pinned) => {
                    actions.push(CargoTomlAction::InheritsWorkspace);
                }
                // Inherits another version of the crate: not this dep.
                Some(CargoWorkspaceEntry::OtherVersion) => {}
                None => {
                    return Err("inherits from [workspace.dependencies] with no rewritable \
                                entry for it"
                        .to_string());
                }
            },
            Pending::Refuse(reason) => return Err(reason),
        }
    }
    // Every occurrence named another version (inheritors included).
    if actions.is_empty() {
        return Ok(not_found(ws_entries));
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
                    path: path.into(),
                    kind: "redirect_cargo_toml_dep".into(),
                    action: "rewritten".into(),
                    key: Some(crate_name.into()),
                    original: Some(Value::String(lines[*idx].to_string())),
                    new: Some(Value::String(new_text.clone())),
                });
            }
            CargoTomlAction::InsertAfterHeader { inserted, .. } => {
                edits.push(FileEdit {
                    path: path.into(),
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
        found: true,
        workspace: ws_entries,
        excluded,
    })
}

/// The Cargo.lock edit kind for dependents' full-id references: `original`
/// / `new` are the quoted `"<name> <version> (<source>)"` ids, keyed
/// `<name>@<version>`, and the inverse replaces EVERY occurrence of `new`.
pub(crate) const CARGO_LOCK_REFERENCE_KIND: &str = "redirect_cargo_lock_reference";

static CARGO_LOCK_SOURCE_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^source = "([^"]*)"$"#).expect("static lock source-line regex is valid")
});
static CARGO_LOCK_CHECKSUM_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^checksum = "[^"]*"$"#).expect("static lock checksum-line regex is valid")
});
// `$` (not `\n`) so it also anchors a source line that ENDS the block: the
// trailing newline sits outside the block region.
static CARGO_LOCK_AFTER_SOURCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^(source = "[^"]*")$"#).expect("static source-line anchor regex is valid")
});

/// Repoint the crate's `[[package]]` at the hosted index with the patched
/// `.crate`'s checksum, in whichever Cargo.lock format the file is:
///
/// * v2–v4: `source` + an inline `checksum` in the entry;
/// * v1 (cargo < 1.41, still read by every cargo): the entry carries only
///   `source`; the checksum lives in the trailing `[metadata]` table under
///   `"checksum <name> <version> (<source>)"`, and every dependent names the
///   crate by its FULL package id `"<name> <version> (<source>)"`. Both are
///   keyed by the source, so both must follow it — a v1 lock with only the
///   entry repointed names a package that no longer exists (cargo discards
///   the lock and re-resolves; `--locked` fails) and pins nothing.
///
/// Full-id references are rewritten in any format (v2+ spells them that way
/// when a name + version is ambiguous). Each changed fragment is its own
/// `redirect_cargo_lock_entry` edit (unique text, so the fragment revert is
/// unambiguous) — the entry and the `[metadata]` line — and the dependents'
/// references are one `redirect_cargo_lock_reference` edit holding the
/// quoted full id, reverted at every occurrence.
fn plan_cargo_lock(
    content: &str,
    crate_name: &str,
    version: &str,
    index_url: &str,
    cksum: &str,
) -> CargoLockPlan {
    // Rust's regex has NO lookahead, so bound the [[package]] block by string
    // search (see [`lock_block_end`]): from its header to the next block or
    // trailing table (or EOF), so the bytes after the block (incl. the final
    // newline) are preserved.
    let head = format!("[[package]]\nname = \"{crate_name}\"\nversion = \"{version}\"\n");
    // Every line-anchored header for this name@version. A Cargo.lock may
    // legitimately hold TWO blocks for one name@version from different
    // sources — after a redirect, a transitive crates.io copy resolves beside
    // the socket-registry copy, and cargo sorts the crates.io block FIRST —
    // so the first hit alone would repoint the wrong twin.
    let heads: Vec<usize> = content
        .match_indices(head.as_str())
        .map(|(at, _)| at)
        .filter(|&at| at == 0 || content.as_bytes()[at - 1] == b'\n')
        .collect();
    let block_start = match heads.as_slice() {
        [] => return CargoLockPlan::NotFound,
        [only] => *only,
        twins => {
            // Exactly one twin already at the target index is OURS (a re-run
            // over a redirected lock); anything else cannot be attributed and
            // the dep is skipped transactionally.
            let target_source = format!("source = \"{index_url}\"");
            let mut ours = twins.iter().copied().filter(|&at| {
                let body_start = at + head.len();
                content[body_start..lock_block_end(content, body_start)]
                    .lines()
                    .any(|line| line == target_source)
            });
            match (ours.next(), ours.next()) {
                (Some(at), None) => at,
                _ => return CargoLockPlan::Ambiguous,
            }
        }
    };
    let body_start = block_start + head.len();
    let block_end = lock_block_end(content, body_start);
    let original = content[block_start..block_end].to_string();
    let mut body = content[body_start..block_end].to_string();
    let old_source = CARGO_LOCK_SOURCE_LINE_RE
        .captures(&body)
        .map(|c| c[1].to_string());
    if old_source.is_some() {
        body = CARGO_LOCK_SOURCE_LINE_RE
            .replace(&body, format!("source = \"{index_url}\"").as_str())
            .to_string();
    } else {
        body = format!("source = \"{index_url}\"\n{body}");
    }
    // A v1 lock keeps the checksum in `[metadata]`, keyed by the package id
    // — the chosen block's OWN source when it has one, so a multi-source
    // twin's line is never taken for ours.
    let metadata_source = old_source
        .as_deref()
        .map_or_else(|| r#"[^)"]*"#.to_string(), regex::escape);
    let metadata_re = Regex::new(&format!(
        r#"(?m)^"checksum {} {} \({metadata_source}\)" = "[^"]*"$"#,
        regex::escape(crate_name),
        regex::escape(version)
    ))
    .expect("escaped lock metadata-line regex is valid");
    let metadata_line = metadata_re.find(content).map(|m| m.as_str().to_string());
    if metadata_line.is_none() {
        if CARGO_LOCK_CHECKSUM_LINE_RE.is_match(&body) {
            body = CARGO_LOCK_CHECKSUM_LINE_RE
                .replace(&body, format!("checksum = \"{cksum}\"").as_str())
                .to_string();
        } else {
            body = CARGO_LOCK_AFTER_SOURCE_RE
                .replace(&body, format!("${{1}}\nchecksum = \"{cksum}\"").as_str())
                .to_string();
        }
    }
    let rebuilt = format!("{head}{body}");
    let key = format!("{crate_name}@{version}");
    let edit = |original: &str, new: &str| FileEdit {
        path: "Cargo.lock".into(),
        kind: "redirect_cargo_lock_entry".into(),
        action: "rewritten".into(),
        key: Some(key.clone()),
        original: Some(Value::String(original.to_string())),
        new: Some(Value::String(new.to_string())),
    };
    let mut edits = Vec::new();
    let mut new_content = content.to_string();
    if rebuilt != original {
        new_content.replace_range(block_start..block_end, &rebuilt);
        edits.push(edit(&original, &rebuilt));
    }
    if let Some(line) = metadata_line {
        let pinned = format!("\"checksum {crate_name} {version} ({index_url})\" = \"{cksum}\"");
        if line != pinned {
            new_content = new_content.replacen(&line, &pinned, 1);
            edits.push(edit(&line, &pinned));
        }
    }
    // Dependents' full-id references to the OLD source, recorded as ONE
    // `redirect_cargo_lock_reference` edit holding just the quoted id —
    // never a dependent's whole block: a block referencing two patched
    // packages (the root of a v1 lock) would hold two overlapping block
    // edits, and reverting the first-applied one alone found neither of its
    // fragments. The id names this name + version + source exactly, so its
    // inverse puts back EVERY occurrence, independently of any other
    // package's edits and in any removal order.
    if let Some(old) = old_source.filter(|old| old != index_url) {
        let from = format!("\"{crate_name} {version} ({old})\"");
        let to = format!("\"{crate_name} {version} ({index_url})\"");
        let mut repointed_any = false;
        // The oldest v1 locks keep the ROOT package in a standalone `[root]`
        // table instead of the `[[package]]` array, with its own full-id
        // `dependencies`. It precedes the array, so the block walk below
        // never reaches it and the lock would keep naming a package it no
        // longer contains (`--locked` fails; an unlocked build silently
        // re-resolves).
        if let Some((start, end)) = lock_root_table(&new_content) {
            if new_content[start..end].contains(&from) {
                let repointed = new_content[start..end].replace(&from, &to);
                new_content.replace_range(start..end, &repointed);
                repointed_any = true;
            }
        }
        let mut cursor = 0;
        while let Some((start, end)) = next_lock_block(&new_content, cursor) {
            if new_content[start..end].contains(&from) {
                let repointed = new_content[start..end].replace(&from, &to);
                new_content.replace_range(start..end, &repointed);
                repointed_any = true;
                cursor = start + repointed.len();
            } else {
                cursor = end;
            }
        }
        if repointed_any {
            edits.push(FileEdit {
                kind: CARGO_LOCK_REFERENCE_KIND.into(),
                ..edit(&from, &to)
            });
        }
    }
    // Already redirected (re-run): every fragment is at the target values; a
    // recorded edit would have original == new and grow the ledger forever.
    if edits.is_empty() {
        return CargoLockPlan::AlreadyRedirected;
    }
    CargoLockPlan::Rewritten {
        content: new_content,
        edits,
    }
}

/// The v1 `[root]` table's span, when the lock has one: cargo before the
/// `[root]` removal recorded the root package there rather than in the
/// `[[package]]` array, and its `dependencies` spell full package ids the
/// same way. Bounded by [`lock_block_end`], like a package block.
fn lock_root_table(content: &str) -> Option<(usize, usize)> {
    const HEADER: &str = "[root]\n";
    let at = content
        .match_indices(HEADER)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || content.as_bytes()[at - 1] == b'\n')?;
    Some((at, lock_block_end(content, at + HEADER.len())))
}

/// The next `[[package]]` block starting at or after `from`, as
/// [`lock_block_end`] bounds it.
fn next_lock_block(content: &str, from: usize) -> Option<(usize, usize)> {
    let rel = content.get(from..)?.find("[[package]]\n")?;
    let start = from + rel;
    if start != 0 && content.as_bytes()[start - 1] != b'\n' {
        return next_lock_block(content, start + 1);
    }
    Some((
        start,
        lock_block_end(content, start + "[[package]]\n".len()),
    ))
}

/// End of the `[[package]]` block whose body starts at `body_start`,
/// excluding the newline(s) before the next block / trailing table / EOF (so
/// a recorded original/new stops after the block's last content byte — the
/// TS rewriter's `(?=\n*$)` lookahead — while the file keeps its newlines).
fn lock_block_end(content: &str, body_start: usize) -> usize {
    // The next block, or the `[metadata]` / `[[patch.unused]]` tables that
    // trail the packages. The trailing tables are searched only up to the
    // next block: they sit after every `[[package]]` (absent entirely from
    // v3/v4 locks), and an unbounded search per block scanned to EOF for
    // every block of every dep. Each marker holds its only `\n` at offset 0,
    // so a hit starting before the next block also ends by it — the bounded
    // minimum is the unbounded one.
    let rest = &content[body_start..];
    let next_block = rest.find("\n[[package]]").unwrap_or(rest.len());
    let mut end = ["\n[metadata]", "\n[[patch.unused]]", "\n[patch"]
        .iter()
        .filter_map(|marker| rest[..next_block].find(marker))
        .min()
        .map_or(body_start + next_block, |rel| body_start + rel);
    while end > body_start && content.as_bytes()[end - 1] == b'\n' {
        end -= 1;
    }
    end
}

/// The previous, unbounded [`lock_block_end`], kept as the equivalence
/// oracle.
#[cfg(test)]
fn lock_block_end_unbounded(content: &str, body_start: usize) -> usize {
    let mut end = [
        "\n[[package]]",
        "\n[metadata]",
        "\n[[patch.unused]]",
        "\n[patch",
    ]
    .iter()
    .filter_map(|marker| content[body_start..].find(marker))
    .min()
    .map_or(content.len(), |rel| body_start + rel);
    while end > body_start && content.as_bytes()[end - 1] == b'\n' {
        end -= 1;
    }
    end
}

/// Outcome of the Cargo.lock `[[package]]` plan — distinguishes a re-run
/// over an already-redirected block (no edit, no warning) from a genuinely
/// missing package (the caller warns AND skips the dep entirely).
enum CargoLockPlan {
    Rewritten {
        content: String,
        edits: Vec<FileEdit>,
    },
    AlreadyRedirected,
    NotFound,
    /// Several `[[package]]` blocks for the name@version (multi-source twins)
    /// and not exactly one of them at the target index — which twin is ours
    /// cannot be decided, so the caller warns AND skips the dep entirely.
    Ambiguous,
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
    // The newline a config without a final one needed rides in the recorded
    // fragment, so the revert (which also drops the one blank separator
    // before the fragment) restores the config's exact bytes.
    let recorded = format!("{sep}{block}");
    Some(CargoConfigPlan {
        content: format!("{config}{sep}{prefix}{block}"),
        edit: FileEdit {
            path: config_key.into(),
            kind: "redirect_cargo_registry".into(),
            action: "added".into(),
            key: Some(reg.to_string()),
            original: None,
            new: Some(Value::String(recorded)),
        },
    })
}

// ── pnpm-lock.yaml ───────────────────────────────────────────────────────────

/// Test-only reference for the residual gate: every instance of this exact
/// name@version in `content` that does not resolve to `artifact_url`.
/// Production judges the same predicate inline, per instance, on each
/// indexed hit's post-splice body in `rewrite_pnpm_lock`; snapshots and
/// other versions do not participate in resolution.
#[cfg(test)]
fn pnpm_unrewritten_instances(
    content: &str,
    fname: &str,
    version: &str,
    artifact_url: &str,
) -> Vec<String> {
    pnpm::entries(content)
        .into_iter()
        .filter_map(|entry| {
            pnpm::suffix(entry.key, fname, version)?;
            (!pnpm_resolves_to(&entry, artifact_url)).then(|| entry.key.to_string())
        })
        .collect()
}

/// Whether `entry` resolves to exactly `artifact_url` — the per-instance
/// residual-gate predicate.
fn pnpm_resolves_to(entry: &pnpm::Entry<'_>, artifact_url: &str) -> bool {
    pnpm::resolution(entry).is_some_and(|r| r.tarball() == Some(artifact_url))
}

/// One pnpm lock under rewrite. `text` is the lock as of the last
/// materialization; `pending` holds the resolution splices committed since,
/// in `text`'s byte coordinates, and `spliced` the entries they touch.
///
/// The logical (post-splice) lock is `text` with `pending` applied. Parsing
/// once and indexing is sound because a resolution splice never changes the
/// entry structure: the replaced range and its replacement are only
/// resolution-field material (6-space-indented `k: v` child lines of a block
/// resolution, or the `{…}` flow value after `    resolution:`), and no raw
/// newline can enter a value (`Resolution::rewrite` JSON-quotes whitespace).
/// So every column-0 line (the shrinkwrap-version sniff) and every entry
/// boundary line survives unchanged, and an entry no pending splice touched
/// has byte-identical key and body. An entry that WAS touched is re-read
/// only after materializing, so a later dep with the same name@version (a
/// duplicate override) sees the rewritten text exactly as before.
struct PnpmLockState<'f> {
    path: &'f String,
    text: Cow<'f, str>,
    early_shrinkwrap: bool,
    /// (key span, body span) per `packages:` entry, in file order.
    entries: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>,
    /// Entry indices sorted by normalized (unquoted, `/`-stripped) key.
    sorted: Vec<usize>,
    pending: Vec<(std::ops::Range<usize>, String)>,
    spliced: std::collections::HashSet<usize>,
    changed: bool,
}

impl<'f> PnpmLockState<'f> {
    fn new(path: &'f String, text: &'f str) -> Self {
        let mut state = PnpmLockState {
            path,
            text: Cow::Borrowed(text),
            early_shrinkwrap: pnpm::unsupported_early_shrinkwrap(text),
            entries: Vec::new(),
            sorted: Vec::new(),
            pending: Vec::new(),
            spliced: Default::default(),
            changed: false,
        };
        state.reindex();
        state
    }

    fn reindex(&mut self) {
        let text: &str = &self.text;
        let base = text.as_ptr() as usize;
        self.entries = pnpm::entries(text)
            .iter()
            .map(|e| {
                let key_start = e.key.as_ptr() as usize - base;
                (
                    key_start..key_start + e.key.len(),
                    e.offset..e.offset + e.body.len(),
                )
            })
            .collect();
        let mut sorted: Vec<usize> = (0..self.entries.len()).collect();
        sorted.sort_by(|&a, &b| self.norm_key(a).cmp(self.norm_key(b)).then(a.cmp(&b)));
        self.sorted = sorted;
    }

    fn entry(&self, i: usize) -> pnpm::Entry<'_> {
        let (key, body) = &self.entries[i];
        pnpm::Entry {
            key: &self.text[key.clone()],
            body: &self.text[body.clone()],
            offset: body.start,
        }
    }

    /// The key as [`pnpm::suffix`] compares it.
    fn norm_key(&self, i: usize) -> &str {
        let key = pnpm::unquote(&self.text[self.entries[i].0.clone()]);
        key.strip_prefix('/').unwrap_or(key)
    }

    /// Entries whose key names `fname@version` (any suffix), in file order —
    /// the same set a full [`pnpm::suffix`] scan of the logical lock yields.
    fn hits(&mut self, fname: &str, version: &str) -> Vec<usize> {
        let hits = self.lookup(fname, version);
        if hits.iter().any(|i| self.spliced.contains(i)) {
            self.materialize();
            return self.lookup(fname, version);
        }
        hits
    }

    fn lookup(&self, fname: &str, version: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for sep in ['@', '/'] {
            let prefix = format!("{fname}{sep}{version}");
            let start = self
                .sorted
                .partition_point(|&i| self.norm_key(i) < prefix.as_str());
            out.extend(
                self.sorted[start..]
                    .iter()
                    .take_while(|&&i| self.norm_key(i).starts_with(prefix.as_str()))
                    .copied(),
            );
        }
        out.sort_unstable();
        out.dedup();
        out.retain(|&i| pnpm::suffix(self.entry(i).key, fname, version).is_some());
        out
    }

    /// Fold `pending` into `text` and re-parse.
    fn materialize(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        #[cfg(debug_assertions)]
        let keys_before: Vec<String> = (0..self.entries.len())
            .map(|i| self.entry(i).key.to_string())
            .collect();
        let mut pending = std::mem::take(&mut self.pending);
        pending.sort_by_key(|(range, _)| range.start);
        let mut out = String::with_capacity(self.text.len());
        let mut cursor = 0usize;
        for (range, replacement) in pending {
            out.push_str(&self.text[cursor..range.start]);
            out.push_str(&replacement);
            cursor = range.end;
        }
        out.push_str(&self.text[cursor..]);
        self.text = Cow::Owned(out);
        self.spliced.clear();
        self.reindex();
        #[cfg(debug_assertions)]
        debug_assert_eq!(
            keys_before,
            (0..self.entries.len())
                .map(|i| self.entry(i).key.to_string())
                .collect::<Vec<_>>(),
            "a resolution splice changed the pnpm entry structure"
        );
    }

    fn into_rewritten(mut self) -> Option<(&'f String, String)> {
        if !self.changed {
            return None;
        }
        self.materialize();
        Some((self.path, self.text.into_owned()))
    }
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
        .filter(|k| {
            matches!(
                k.rsplit('/').next(),
                Some("pnpm-lock.yaml" | "shrinkwrap.yaml")
            )
        })
        .collect();
    if npm.is_empty() || lock_keys.is_empty() {
        return;
    }
    // Each lock is parsed and indexed ONCE; splices accumulate per lock and
    // are applied in one pass at the end (see `PnpmLockState`).
    let mut locks: Vec<PnpmLockState> = lock_keys
        .iter()
        .map(|k| PnpmLockState::new(k, &files[*k]))
        .collect();
    for dep in &npm {
        let fname = full_name(dep);
        let hits: Vec<Vec<usize>> = locks
            .iter_mut()
            .map(|lock| lock.hits(&fname, &dep.version))
            .collect();
        let unsafe_locks: Vec<_> = locks
            .iter()
            .zip(&hits)
            .filter(|(lock, hits)| lock.early_shrinkwrap && !hits.is_empty())
            .map(|(lock, _)| lock.path.as_str())
            .collect();
        if !unsafe_locks.is_empty() {
            result.refused_pnpm_uuids.insert(dep.patch_uuid.clone());
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_legacy_lockfile_unsupported".into(),
                detail: format!("{} uses early pnpm 1 shrinkwrapVersion 3 without a supported minor version. Those installers discard hosted tarball URLs; {fname}@{} was left unchanged in every lock. Upgrade to a tested pnpm release (1.43.1 or newer) and regenerate the lock, or use `scan --mode agent` for installed-file patching.", unsafe_locks.join(", "), dep.version),
            });
            continue;
        }
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        // Every peer instance must be redirected, including nested peer
        // contexts and the block resolutions emitted by pnpm 1–5.
        let mut matched_any = false;
        // Per-lock rewrites are PLANNED first and committed only after the
        // residual gate below proves no instance of this dep escaped the
        // splice grammar in ANY lock — committing lock-by-lock as we go
        // would ship exactly the partial rewrite the gate exists to refuse.
        type Splice = (usize, std::ops::Range<usize>, String);
        let mut planned: Vec<(usize, Vec<Splice>, Vec<FileEdit>)> = Vec::new();
        let mut residuals: Vec<(&str, Vec<String>)> = Vec::new();
        for (idx, (lock, hits)) in locks.iter().zip(&hits).enumerate() {
            // (entry, byte range to replace, replacement text) per instance,
            // plus one FileEdit per instance keyed by the canonical instance
            // key — per-instance edits keep the revert ledger lossless when
            // several instances of one dep live in the same lock.
            let mut splices: Vec<Splice> = Vec::new();
            let mut instance_edits: Vec<FileEdit> = Vec::new();
            // Residual gate, judged per instance on its POST-splice body:
            // any instance of this exact name@version still resolving
            // somewhere other than the hosted artifact — in a spelling the
            // splice grammar cannot parse (e.g. an unbalanced peer suffix) —
            // makes this a partial rewrite. Shipping it would confirm and
            // VEX-attest the dep while dependents through the unmatched
            // instance keep installing the unpatched upstream tarball, so
            // the dep is refused instead.
            let mut leftover: Vec<String> = Vec::new();
            for &i in hits {
                let entry = lock.entry(i);
                let suffix = pnpm::suffix(entry.key, &fname, &dep.version)
                    .expect("hits only holds entries naming this dep");
                let resolution = if pnpm::supported_suffix(suffix) {
                    pnpm::resolution(&entry)
                } else {
                    None
                };
                let Some(resolution) = resolution else {
                    if !pnpm_resolves_to(&entry, &dep.artifact_url) {
                        leftover.push(entry.key.to_string());
                    }
                    continue;
                };
                matched_any = true;
                let original = &lock.text[resolution.range.clone()];
                let rebuilt = resolution.rewrite(&sha512, &dep.artifact_url);
                let rel =
                    resolution.range.start - entry.offset..resolution.range.end - entry.offset;
                let body = format!(
                    "{}{rebuilt}{}",
                    &entry.body[..rel.start],
                    &entry.body[rel.end..]
                );
                let after = pnpm::Entry {
                    key: entry.key,
                    body: &body,
                    offset: 0,
                };
                if !pnpm_resolves_to(&after, &dep.artifact_url) {
                    leftover.push(entry.key.to_string());
                }
                if rebuilt == original {
                    continue;
                }
                instance_edits.push(FileEdit {
                    path: lock.path.clone(),
                    kind: "redirect_pnpm_resolution".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}{suffix}", dep.version)),
                    original: Some(Value::String(original.to_string())),
                    new: Some(Value::String(rebuilt.clone())),
                });
                splices.push((i, resolution.range, rebuilt));
            }
            if !leftover.is_empty() {
                residuals.push((lock.path.as_str(), leftover));
                continue;
            }
            if !splices.is_empty() {
                planned.push((idx, splices, instance_edits));
            }
        }
        // ANY residual anywhere refuses the dep across the WHOLE lock set —
        // nothing rewritten, nothing recorded, nothing confirmed (the same
        // fail-closed contract the pre-splice v5/v6 refusal had): a rewrite
        // committed in one lock while another still resolves the dep
        // upstream would confirm the dep set-wide.
        if !residuals.is_empty() {
            result.refused_pnpm_uuids.insert(dep.patch_uuid.clone());
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
        for (idx, splices, mut instance_edits) in planned {
            let lock = &mut locks[idx];
            for (i, range, replacement) in splices {
                lock.spliced.insert(i);
                lock.pending.push((range, replacement));
            }
            lock.changed = true;
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
            // Scanned over the post-splice text, so fold pending splices in.
            for lock in locks.iter_mut() {
                lock.materialize();
            }
            let vendored = locks.iter().any(|lock| {
                lock.text.lines().any(|line| {
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
                    detail: format!("no resolution for {fname}@{}", dep.version),
                });
            }
        }
    }
    for lock in locks {
        if let Some((key, content)) = lock.into_rewritten() {
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
    use crate::vendor::yarn_classic_lock::{split_key_patterns, split_pattern};

    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("yarn.lock") {
        return;
    }
    let raw = &files["yarn.lock"];
    if is_berry_lock(raw) {
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
    // Each block's key and the one real package all its patterns stand for
    // (see `yarn_classic_block_head`), computed once per block and redone
    // only for a block this run rewrites — not re-split per block per dep.
    let mut heads: Vec<Option<(String, Option<String>)>> =
        blocks.iter().map(|b| yarn_classic_block_head(b)).collect();
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
        for (i, block) in blocks.iter_mut().enumerate() {
            // The block's key line names its consumers; resolve every
            // comma-joined pattern to the REAL package it stands for
            // (`alias@npm:target@range` → target). A key like
            // `<fname>@npm:<other-pkg>@…` — yarn v1's fork-substitution
            // idiom — resolves to <other-pkg>, so it is NOT ours to touch:
            // matching on the alias name alone would hijack the fork.
            let Some((key, real_name)) = &heads[i] else {
                continue;
            };
            if real_name.as_deref() != Some(fname.as_str()) {
                continue;
            }
            if !version_re.is_match(block) {
                continue;
            }
            let patterns = split_key_patterns(key);
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
                heads[i] = yarn_classic_block_head(block);
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

/// A classic yarn.lock block's key (its first non-indented, non-comment
/// line, minus the trailing `:`) and the real package EVERY comma-joined
/// pattern of that key resolves to — `None` when the key has no pattern,
/// one does not parse, or they name different packages. `None` overall
/// when the block has no key line.
fn yarn_classic_block_head(block: &str) -> Option<(String, Option<String>)> {
    use crate::vendor::yarn_classic_lock::{pattern_real_name, split_key_patterns};
    let key_line = block
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with([' ', '\t', '#']))?;
    let key = key_line.strip_suffix(':')?;
    let patterns = split_key_patterns(key);
    let mut names = patterns.iter().map(|p| pattern_real_name(p));
    let real_name = match names.next() {
        Some(Some(first)) => names.all(|n| n == Some(first)).then(|| first.to_string()),
        _ => None,
    };
    Some((key.to_string(), real_name))
}

// ── yarn.lock (berry / v2+) ──────────────────────────────────────────────────
// Berry derives its fetch URL from the descriptor's `npm:` resolution and
// verifies the CONVERTED CACHE ZIP against the lock's `checksum:` (a
// `10c0/<sha512-hex>` over the zip, not the tarball). To redirect ONE dep we
// rewrite only the lock entry: `resolution:` gains yarn's own
// `::__archiveUrl=<encodeURIComponent(url)>` binding, and `checksum:` becomes
// our precomputed `integrity.yarnBerry10c0`. The descriptor KEY + package.json
// are untouched (the `name@npm:^range` descriptor still satisfies, so
// `--immutable` passes). Byte-for-byte twin of the TS `rewriteYarnBerry` on
// LF locks; the CRLF / BOM round trip below has no TS counterpart yet.

/// Only cacheKey `10c0` (yarn 4, compressionLevel 0 default) has a checksum we
/// can reproduce offline; matches the vendored backend's `SUPPORTED_CACHE_KEY`.
const YARN_BERRY_SUPPORTED_CACHE_KEY: &str = "10c0";

/// Whether ledger edits of `kind` are yarn.lock blocks — the fragments the
/// yarn rewriters record in the lock's ON-DISK line endings, which the
/// reverts (the per-purl takeover and the whole-ledger replay) may respell
/// in the live lock's ending when a `core.autocrlf` checkout changed it
/// ([`crate::utils::line_endings::fragments_in_eol_of`]).
pub(crate) fn yarn_lock_fragment_kind(kind: &str) -> bool {
    matches!(
        kind,
        "redirect_yarn_berry_entry" | "redirect_yarn_classic_entry"
    )
}

/// A yarn.lock is berry (v2+) when it carries the `__metadata:` header block;
/// anything else is a classic v1 lock. Shared by both yarn rewriters and
/// lockfile discovery (`vex::discover::yarn`) so the grammar split cannot
/// drift. A leading BOM is encoding, not key text (yarn's YAML parser drops
/// it), so a header-less lock opening with `\u{feff}__metadata:` is berry
/// too.
pub(crate) fn is_berry_lock(content: &str) -> bool {
    content
        .strip_prefix('\u{feff}')
        .unwrap_or(content)
        .lines()
        .any(|line| line.starts_with("__metadata:"))
}

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

/// The project-level refusals of the yarn berry hosted rewriter — the gates
/// that hold for every dep of the lock, whatever the overrides: a MIXED
/// line-ending lock, an unsupported `cacheKey`, and a `.yarnrc.yml`
/// `compressionLevel` other than 0. `Ok` for a lock that is not berry (the
/// classic rewriter owns those).
///
/// Exposed so the vendored→hosted mode takeover (`scan`/`get --mode hosted`
/// over a vendored berry purl) can refuse BEFORE it reverts the vendored
/// wiring: the vendored revert never refuses on line endings (it keeps a
/// mixed lock mixed), so without this preflight the takeover stripped the
/// live vendored patch and then this rewriter refused the lock, leaving the
/// package unpatched in both modes — the bun twin is
/// [`preflight_bun_hosted`].
///
/// Line endings: yarn berry writes a NEW lockfile with the OS line ending
/// (`os.EOL`: CRLF on Windows) and keeps an existing file's majority ending
/// on every later write (`normalizeLineEndings` in yarnpkg-fslib
/// `FakeFS.ts`, called by `Project.persistLockfile`); a `core.autocrlf`
/// checkout turns an LF lock into CRLF on any OS. A uniform CRLF lock is
/// supported (rewritten LF-normalized and re-expanded). A MIXED lock has no
/// single style to restore, and yarn cannot keep one either: `--immutable`
/// compares the file with its own majority-normalized re-render and fails
/// (YN0028), while a plain install rewrites every minority line — so it is
/// refused untouched, `yarn install` normalizes it first.
pub fn preflight_yarn_berry_hosted(lock: &str, yarnrc: Option<&str>) -> Result<(), RewriteWarning> {
    if !is_berry_lock(lock) {
        return Ok(());
    }
    let body = lock.strip_prefix('\u{feff}').unwrap_or(lock);
    if LineEndings::of(body) == LineEndings::Mixed {
        return Err(RewriteWarning {
            code: "redirect_yarn_berry_mixed_line_endings".into(),
            detail: "yarn.lock mixes CRLF and LF line endings (or holds a bare carriage \
                     return), so no single line ending can be kept, and yarn itself \
                     rejects it under `--immutable` (YN0028) — run `yarn install` once to \
                     normalize the lock, then re-run; leaving it untouched"
                .into(),
        });
    }
    // Refuse any lock whose cache checksum we can't reproduce
    // offline. A guessed `checksum:` bricks installs (YN0018).
    let key = berry_cache_key(&to_lf(body));
    if key.as_deref() != Some(YARN_BERRY_SUPPORTED_CACHE_KEY) {
        return Err(RewriteWarning {
            code: "redirect_yarn_berry_cache_unsupported".into(),
            detail: format!(
                "yarn.lock cacheKey is `{}`; only `{YARN_BERRY_SUPPORTED_CACHE_KEY}` \
                 (yarn 4, compressionLevel 0 default) has an offline-reproducible cache checksum",
                key.as_deref().unwrap_or("(missing)")
            ),
        });
    }
    if let Some(level) = yarnrc.and_then(yarnrc_compression_level) {
        if level != "0" {
            return Err(RewriteWarning {
                code: "redirect_yarn_berry_cache_unsupported".into(),
                detail: format!(
                    ".yarnrc.yml sets `compressionLevel: {level}`, which changes berry's \
                     cache checksums; only compressionLevel 0 (the yarn 4 default) is supported"
                ),
            });
        }
    }
    Ok(())
}

fn rewrite_yarn_berry(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    // Descriptors split with the classic grammar's `name@range` rule.
    use crate::vendor::yarn_classic_lock::{split_berry_key_patterns, split_pattern};
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("yarn.lock") {
        return;
    }
    let raw = &files["yarn.lock"];
    // The classic rewriter handles a v1 lock; berry stays out of its way.
    if !is_berry_lock(raw) {
        return;
    }

    // Line endings (see [`preflight_yarn_berry_hosted`] for when yarn writes
    // CRLF): a CRLF lock is rewritten LF-normalized (the `\n\n` block
    // grammar never splits a `\r\n\r\n` file) and re-expanded, so every
    // untouched byte round-trips and the ledger records the lock's on-disk
    // CRLF fragments. A leading BOM rides outside the blocks; a mixed lock
    // is refused by the preflight.
    let (bom, body) = match raw.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", raw.as_str()),
    };
    // Project-level gates (line endings, cacheKey, compressionLevel), shared
    // with the vendored→hosted takeover preflight so a takeover never
    // reverts vendored wiring this rewriter then refuses.
    if let Err(warning) =
        preflight_yarn_berry_hosted(raw, files.get(".yarnrc.yml").map(String::as_str))
    {
        result.warnings.push(warning);
        return;
    }
    let eol = LineEndings::of(body);
    let normalized = to_lf(body);
    let content: &str = &normalized;

    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolution_re =
        Regex::new(r#"\n {2}resolution: "[^"]*""#).expect("static resolution-line regex is valid");
    let checksum_re =
        Regex::new(r"\n {2}checksum: [^\n]*").expect("static checksum-line regex is valid");
    let mut changed = false;
    for dep in &npm {
        let fname = full_name(dep);
        // The API hands the prefixed `10c0/<hex>`; a yarn 4.0.x lock spells
        // its checksums bare, and `--immutable` rejects a respelled one.
        let Some(checksum) = dep
            .integrity
            .yarn_berry10c0
            .as_deref()
            .map(|c| crate::vendor::yarn_berry_lock::checksum_in_lock_spelling(content, c))
        else {
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
                patterns.iter().map(|p| split_pattern(p)).collect();
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
                            .and_then(split_pattern)
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
                // The ledger records the lock's on-disk bytes (CRLF lines for
                // a CRLF lock), so every revert's byte-exact `replacen`
                // matches what the file really holds.
                result.edits.push(FileEdit {
                    path: "yarn.lock".into(),
                    kind: "redirect_yarn_berry_entry".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}", dep.version)),
                    original: Some(Value::String(eol.restore(block).into_owned())),
                    new: Some(Value::String(eol.restore(&rewritten).into_owned())),
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
        let out = blocks.join("\n\n");
        result
            .files
            .insert("yarn.lock".into(), format!("{bom}{}", eol.restore(&out)));
    }
}

// ── bun.lock (text lockfile) ─────────────────────────────────────────────────
// A registry 4-tuple `["name@version", "<registry>", {deps}, "sha512-…"]` is
// rewritten to a URL 3-tuple `["name@<artifactUrl>", {deps verbatim},
// "<sha512>"]`: bun then fetches `<artifactUrl>` directly and verifies the SRI.
// Binary locks use `rewrite_bun_binary`, which accepts bytes directly.
// The text path uses the shared `bun_lock_text` grammar (fail-closed on
// deviations). Byte-for-byte twin of the TS `rewriteBun`.
/// Check a text Bun lock before reverting any existing vendored wiring.
/// Uses the rewriter's own version, grammar and workspace compatibility rules.
pub fn preflight_bun_hosted(content: &str) -> Result<(), RewriteWarning> {
    parse_bun_hosted_lock(content).map(|_| ())
}

fn parse_bun_hosted_lock(
    content: &str,
) -> Result<(Vec<String>, Vec<crate::vendor::bun_lock_text::BunEntry>), RewriteWarning> {
    use crate::vendor::bun_lock_text::{
        check_lock_version, has_workspace_packages, lock_version, parse_packages_section,
    };

    // The shared gate's `Err` text IS the detail: hosted and vendored refuse
    // an unsupported head with one message (and one remedy per arm — a
    // future version means "update socket-patch", a missing integer means
    // "re-lock"), so the two modes cannot drift apart.
    if let Err(detail) = check_lock_version(content) {
        return Err(RewriteWarning {
            code: "redirect_bun_lock_unsupported".into(),
            detail,
        });
    }
    let lines: Vec<String> = content.split('\n').map(str::to_string).collect();
    let entries = match parse_packages_section(&lines) {
        Ok(entries) => entries,
        Err(_) => {
            // Fail-closed: never line-splice a lock whose packages section
            // deviates from bun's emitted single-line grammar.
            return Err(RewriteWarning {
                code: "redirect_bun_lock_unsupported".into(),
                detail: "bun.lock packages section is not in bun's emitted single-line shape"
                    .into(),
            });
        }
    };

    // Version-0 locks (bun 1.1.39–1.1.45's opt-in text lockfile) with a
    // `workspace:` member are refused. The remedy that converges on every
    // release (measured against real Bun 1.2.0, 1.2.23, 1.3.0, 1.3.9,
    // 1.3.14, 1.4.0–1.4.2) is `rm bun.lock && bun install` with Bun ≥ 1.2:
    // 1.2–1.3 write lockfileVersion 1, 1.4 writes 2, both accepted here. A
    // plain IN-PLACE `bun install` bumps a v0 workspace lock to 1 only when
    // some workspace depends on another workspace (root → member, as in the
    // backtest's `workspace` shapes, or member → member): Bun ≥ 1.2 re-saves
    // the bare-path spelling of that dependency as `workspace:*`, which
    // forces the save. Without such a dependency (a root that only lists
    // `workspaces`), 1.2.0 exits 0 and keeps 0, and 1.2.23–1.4.2 exit 1 with
    // `<pkg>@<ver> failed to resolve` and keep 0 — so the in-place bump is
    // stated as conditional, never as the remedy. (A v0 lock WITHOUT
    // workspaces is kept at 0 by an in-place install on 1.2.0, 1.2.23 and
    // 1.3.0 and bumped to 1 by 1.3.9 and every later release; that case is
    // accepted here either way.)
    if lock_version(content) == Some(0) && has_workspace_packages(&entries) {
        return Err(RewriteWarning {
            code: "redirect_bun_workspace_unsupported".into(),
            detail: "Bun version-0 workspace locks cannot preserve hosted tarballs on frozen \
                     installs; delete bun.lock and re-run `bun install` with Bun >= 1.2 (which \
                     writes lockfileVersion 1, accepted by hosted mode) — a plain in-place `bun \
                     install` bumps the version only when a workspace depends on another \
                     workspace (e.g. root -> member); otherwise it keeps version 0 or fails to \
                     resolve"
                .into(),
        });
    }

    Ok((lines, entries))
}

fn rewrite_bun_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    use crate::vendor::bun_lock_text::decode_json_string;

    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() {
        return;
    }
    // This API carries UTF-8 text. Binary callers must use the byte API.
    // Pure-API guard only: the CLI (scan/hosted.rs) never puts `bun.lockb`
    // in `files` — it strips the key and feeds the bytes to
    // `rewrite_bun_binary` — so this arm is reached only by direct callers
    // of `rewrite_registry_redirect` (the `npm/bun/lockb-only-refusal`
    // golden and `bun_lock_warning_branches`).
    if files.contains_key("bun.lockb") && !files.contains_key("bun.lock") {
        result.warnings.push(RewriteWarning {
            code: "redirect_bun_lockb_bytes_required".into(),
            detail: "bun.lockb requires the native byte API: pass its original bytes to rewrite_bun_binary"
                .into(),
        });
        return;
    }
    let Some(content) = files.get("bun.lock") else {
        return;
    };
    let (mut lines, entries) = match parse_bun_hosted_lock(content) {
        Ok(parsed) => parsed,
        Err(warning) => {
            result.warnings.push(warning);
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
            } else if matches!(entry.elems.len(), 2 | 3) && spec == url_spec {
                // Already one of our URL tuples for this exact URL. A 3-tuple
                // is idempotent if the integrity already matches and is
                // refreshed otherwise. A 2-tuple is our wiring with its digest
                // DROPPED: Bun 1.1.39–1.3.9 re-save a URL tuple without its
                // `"sha512-…"` on any lock re-save (`bun add`, `bun install`
                // after a manifest change) — the spec bun installs from is
                // intact, so the patch still lands, but ≥ 1.3.10 consumers of
                // the same lock lose digest verification. HEAL it back to the
                // canonical 3-tuple; the edit below records the 2-tuple as its
                // `original`, and replay accepts that spelling of a recorded
                // `new` (`bun_lock_text::same_wiring_modulo_integrity`), so
                // the chain still unwinds to the pristine registry line.
                matched_any = true;
                if entry.elems.len() == 3 && entry.elems[2] == format!("\"{sha512}\"") {
                    continue;
                }
                deps_verbatim = entry.elems[1].clone();
            } else if matches!(entry.elems.len(), 2 | 3)
                && entry.elems[1].starts_with('{')
                && is_prior_hosted_bun_spec(&spec, &fname, &dep.artifact_url)
            {
                // A URL tuple written by an EARLIER redirect whose artifact
                // URL has since changed (a patch republish rotates the uuid
                // path segment; grant-token rotation changes the token — the
                // registry `name@version` spec was destroyed by that first
                // rewrite, so exact-URL matching alone would strand the stale
                // pin forever). Re-pin to the current URL — from the 3-tuple
                // or from its digest-less 2-tuple re-save alike. Ownership is
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
            // Lines come from a bare `split('\n')`, so a CRLF lock's lines
            // carry a trailing `\r` (the grammar trims it away when parsing).
            // Re-emit it verbatim — mirroring `vendor/bun_lock.rs` — so the
            // rewritten line never becomes the lone LF line of a CRLF file,
            // and the ledger `new` fragment matches the on-disk bytes the
            // way `original` already does (replay matches fragments exactly).
            let cr = if original.ends_with('\r') { "\r" } else { "" };
            let rebuilt = format!(
                "{indent}{key}: [{url}, {deps}, {integrity}]{comma}{cr}",
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
fn python_lock_blocks(text: &str) -> Vec<&str> {
    let mut starts = vec![0];
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if offset != 0
            && matches!(
                line.trim(),
                "[[package]]" | "[[packages]]" | "[[distribution]]"
            )
        {
            starts.push(offset);
        }
        offset += line.len();
    }
    starts.push(text.len());
    starts
        .windows(2)
        .map(|bounds| &text[bounds[0]..bounds[1]])
        .collect()
}

fn record_python_lock_edits(
    path: &str,
    dep: &DepOverride,
    original: &str,
    rewritten: &str,
    result: &mut RewriteResult,
) {
    let original_blocks = python_lock_blocks(original);
    let rewritten_blocks = python_lock_blocks(rewritten);
    let blocks = if original_blocks.len() == rewritten_blocks.len() {
        original_blocks.into_iter().zip(rewritten_blocks).collect()
    } else {
        vec![(original, rewritten)]
    };
    for (original, rewritten) in blocks {
        if original != rewritten {
            result.edits.push(FileEdit {
                path: path.to_string(),
                kind: "redirect_uv_lock_wheel".into(),
                action: "rewritten".into(),
                key: Some(format!("{}@{}", dep.name, dep.version)),
                original: Some(Value::String(original.to_string())),
                new: Some(Value::String(rewritten.to_string())),
            });
        }
    }
}

struct PythonMetadataEdit {
    path: String,
    original: String,
    rewritten: String,
    script: bool,
}

fn plan_python_metadata(
    path: &str,
    lock: &str,
    files: &BTreeMap<String, String>,
    dep: &DepOverride,
    result: &RewriteResult,
) -> Result<(Option<PythonMetadataEdit>, Option<String>), RewriteWarning> {
    use crate::utils::python_lock::{
        check_python_lock_source_scope, is_script_lock_name, paired_metadata_rel, ArtifactSource,
    };
    use crate::utils::python_script::{rewrite_project_metadata, rewrite_script_metadata};

    // A script lock always needs its script; uv.lock is edited alone in a
    // lock-only checkout.
    let script = is_script_lock_name(path);
    let Some(metadata_path) = paired_metadata_rel(path)
        .filter(|metadata| script || files.contains_key(*metadata))
        .map(str::to_string)
    else {
        return Ok((None, None));
    };
    let Some(original) = result
        .files
        .get(&metadata_path)
        .or_else(|| files.get(&metadata_path))
        .cloned()
    else {
        return Err(RewriteWarning {
            code: "redirect_uv_script_missing".into(),
            detail: format!("{path} requires its paired {metadata_path}"),
        });
    };
    let unsupported = |detail| RewriteWarning {
        code: if script {
            "redirect_uv_script_unsupported"
        } else {
            "redirect_uv_project_unsupported"
        }
        .into(),
        detail: format!("{metadata_path}: {detail}"),
    };
    check_python_lock_source_scope(lock, &dep.name, &dep.version).map_err(unsupported)?;
    let rewritten = if script {
        rewrite_script_metadata(
            &original,
            &dep.name,
            &dep.version,
            ArtifactSource::Url(&dep.artifact_url),
        )
    } else {
        rewrite_project_metadata(
            &original,
            &dep.name,
            &dep.version,
            ArtifactSource::Url(&dep.artifact_url),
        )
    }
    .map_err(unsupported)?;
    let project = (!script).then(|| rewritten.as_ref().unwrap_or(&original).clone());
    let edit = rewritten.map(|rewritten| PythonMetadataEdit {
        path: metadata_path,
        original,
        rewritten,
        script,
    });
    Ok((edit, project))
}

fn record_python_metadata_edit(
    edit: PythonMetadataEdit,
    dep: &DepOverride,
    result: &mut RewriteResult,
) {
    let (original, rewritten) = if edit.script {
        let original_span = crate::utils::python_script::script_metadata(&edit.original)
            .expect("validated script metadata")
            .0;
        let rewritten_span = crate::utils::python_script::script_metadata(&edit.rewritten)
            .expect("validated script metadata")
            .0;
        (
            edit.original[original_span].to_string(),
            edit.rewritten[rewritten_span].to_string(),
        )
    } else {
        (edit.original, edit.rewritten.clone())
    };
    result.edits.push(FileEdit {
        path: edit.path.clone(),
        kind: "redirect_uv_lock_wheel".into(),
        action: "rewritten".into(),
        key: Some(format!("{}@{}", dep.name, dep.version)),
        original: Some(Value::String(original)),
        new: Some(Value::String(rewritten)),
    });
    result.files.insert(edit.path, edit.rewritten);
}

fn rewrite_uv_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    python_metadata: &BTreeMap<String, String>,
    result: &mut RewriteResult,
) {
    use crate::utils::python_lock::{
        complete_python_lock_metadata, is_python_lock_name, rewrite_python_lock, ArtifactSource,
    };

    let locks: Vec<(&String, &String)> = files
        .iter()
        .filter(|(path, _)| is_python_lock_name(path))
        .collect();
    if locks.is_empty() {
        return;
    }
    // Intake gate ONCE per dep, not once per lock file: a project carrying
    // uv.lock + pylock.toml + a script lock would otherwise repeat the same
    // missing-integrity warning three times.
    let mut usable: Vec<(&DepOverride, &str)> = Vec::new();
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        result.python_lock_uuids.insert(dep.patch_uuid.clone());
        match dep.integrity.sha256.as_deref() {
            Some(sha256) => usable.push((dep, sha256)),
            None => result.warnings.push(RewriteWarning {
                code: "redirect_uv_missing_sha256".into(),
                detail: format!("{} has no sha256 integrity", dep.name),
            }),
        }
    }
    for (path, original) in locks {
        let mut content = original.clone();
        for &(dep, sha256) in &usable {
            let rewritten = match rewrite_python_lock(
                &content,
                &dep.name,
                &dep.version,
                ArtifactSource::Url(&dep.artifact_url),
                sha256,
            ) {
                Ok(Some(rewritten)) => rewritten,
                Ok(None) => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_uv_entry_not_found".into(),
                        detail: format!("no {path} archive entry for {}@{}", dep.name, dep.version),
                    });
                    continue;
                }
                Err(detail) => {
                    result
                        .refused_python_lock_uuids
                        .insert(dep.patch_uuid.clone());
                    result.warnings.push(RewriteWarning {
                        code: "redirect_uv_lock_unsupported".into(),
                        detail: format!("{path}: {detail}"),
                    });
                    continue;
                }
            };
            let (metadata_edit, project) =
                match plan_python_metadata(path, &content, files, dep, result) {
                    Ok(plan) => plan,
                    Err(warning) => {
                        result
                            .refused_python_lock_uuids
                            .insert(dep.patch_uuid.clone());
                        result.warnings.push(warning);
                        continue;
                    }
                };
            let rewritten = match complete_python_lock_metadata(
                &rewritten,
                project.as_deref(),
                &dep.name,
                &dep.version,
                ArtifactSource::Url(&dep.artifact_url),
                python_metadata.get(&dep.artifact_url).map(String::as_str),
            ) {
                Ok(rewritten) => rewritten,
                Err(detail) => {
                    result
                        .refused_python_lock_uuids
                        .insert(dep.patch_uuid.clone());
                    result.warnings.push(RewriteWarning {
                        code: "redirect_uv_metadata_unsupported".into(),
                        detail: format!("{path}: {detail}"),
                    });
                    continue;
                }
            };
            result
                .confirmed_python_lock_uuids
                .insert(dep.patch_uuid.clone());
            if let Some(edit) = metadata_edit {
                record_python_metadata_edit(edit, dep, result);
            }
            if rewritten != content {
                record_python_lock_edits(path, dep, &content, &rewritten, result);
                content = rewritten;
            }
        }
        if content != *original {
            result.files.insert(path.clone(), content);
        }
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

static COMPOSER_DIST_TYPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("type": ")[^"]*(")"#).expect("static dist type regex is valid")
});
static COMPOSER_DIST_URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"("url": ")[^"]*(")"#).expect("static dist url regex is valid"));
static COMPOSER_DIST_SHASUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("shasum": ")[^"]*(")"#).expect("static dist shasum regex is valid")
});

/// Byte offset of the entry's `"source": {` key when that object is the
/// dist block's IMMEDIATE predecessor (only `,` + whitespace between them) —
/// the layout composer itself always writes (`source` then `dist`).
/// `None` when the entry has no source object there.
fn composer_source_before_dist(
    content: &str,
    entry_start: usize,
    dist_start: usize,
) -> Option<usize> {
    const SOURCE_KEY: &str = "\"source\": {";
    let source_start = entry_start + content[entry_start..dist_start].rfind(SOURCE_KEY)?;
    let source_end = json_object_end_from(content, source_start + SOURCE_KEY.len())?;
    (source_end < dist_start && content[source_end + 1..dist_start].trim() == ",")
        .then_some(source_start)
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
    if composer.is_empty() {
        return;
    }
    // Parity with `redirect_npm_no_lockfile`: a granted dep the project has
    // no lock to pin must be SAID, not silently dropped from the redirected
    // count (a composer.json + installed vendor tree without a lock is
    // discovered and granted like any other).
    if !files.contains_key("composer.lock") {
        result.warnings.push(RewriteWarning {
            code: "redirect_composer_no_lockfile".into(),
            detail: "no composer.lock present; composer redirect skipped".into(),
        });
        return;
    }
    const DIST_KEY: &str = "\"dist\": {";
    let mut content = files["composer.lock"].clone();
    let type_re: &Regex = &COMPOSER_DIST_TYPE_RE;
    let url_re: &Regex = &COMPOSER_DIST_URL_RE;
    let shasum_re: &Regex = &COMPOSER_DIST_SHASUM_RE;
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
        // Drop the entry's `source` (the vendored backend does the same):
        // when the dist download fails — checksum mismatch, an expired grant
        // token, a patch-server outage — composer 1 and composer 2 before its
        // source-fallback cutoff (2.2 LTS included) print "Now trying to
        // download from source" and silently install the PRISTINE upstream
        // commit from git, and `--prefer-source` / `preferred-install:
        // source` always does. With the source gone the hosted archive is
        // the only way to install the package, so a failed fetch fails the
        // install instead of shipping the vulnerable code. The edit then
        // spans `"source": {…},\n<indent>"dist": {…}`, so the ledger's
        // fragment revert puts both blocks back byte-for-byte.
        let (edit_start, original) =
            match composer_source_before_dist(&content, entry_start, dist_start) {
                Some(source_start) => (source_start, content[source_start..=dist_end].to_string()),
                None => {
                    if content[entry_start..=entry_end].contains("\"source\": {") {
                        result.warnings.push(RewriteWarning {
                            code: "redirect_composer_source_kept".into(),
                            detail: format!(
                                "{composer_name}'s source block does not directly precede its \
                                 dist and was left in place; a failed hosted download may fall \
                                 back to it"
                            ),
                        });
                    }
                    (dist_start, block.clone())
                }
            };
        if rewritten != original {
            content = format!(
                "{}{}{}",
                &content[..edit_start],
                rewritten,
                &content[dist_end + 1..]
            );
            changed = true;
            result.edits.push(FileEdit {
                path: "composer.lock".into(),
                kind: "redirect_composer_dist".into(),
                action: "rewritten".into(),
                key: Some(composer_name),
                original: Some(Value::String(original)),
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

/// `None` when an insert found no anchor (no `<packageSources>` form and no
/// `<configuration>` root, or no close tag for a from-scratch mapping): the
/// caller must skip the dep fail-closed — writing the mapping without its
/// source (or recording the edit at all) routes the patched id to a source
/// that was never defined while the ledger claims the redirect landed.
fn add_nuget_source(config: &str, reg: &str, index_url: &str, pkg_id: &str) -> Option<String> {
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
    // "Already has one" is decided by the parsed <packageSources> keys ALONE:
    // a whole-file "nuget.org" probe is satisfied by text that defines no
    // source (a defaultPushSource URL, a <disabledPackageSources> entry, a
    // comment), and suppressing the seed on it leaves the from-scratch
    // mapping socket-only — NU1100 for every other package.
    let seed_nuget_org = creating_mapping && pre_existing_keys.is_empty();
    if seed_nuget_org {
        out = insert_nuget_source(&out, NUGET_ORG_KEY, NUGET_ORG_URL)?;
        pre_existing_keys.push(NUGET_ORG_KEY.to_string());
    }

    out = insert_nuget_source(&out, reg, index_url)?;

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
        // The close tag may carry whitespace (`</configuration >` is valid
        // XML); a literal replacen would silently drop the mapping.
        let close_re = Regex::new(r"</configuration\s*>")
            .expect("static configuration close-tag regex is valid");
        let m = close_re.find(&out)?;
        let at = m.start();
        out = format!("{}{map_block}\n{}", &out[..at], &out[at..]);
    }
    Some(out)
}

/// Insert an `<add key="…" value="…" />` source under `<packageSources>`,
/// creating the element (right after the `<configuration>` root open tag,
/// whatever whitespace or attributes it carries) when absent. A self-closing
/// `<packageSources />` (any whitespace before `/>`) is expanded in place
/// into an open/close pair rather than left dangling beside a duplicate
/// element. `None` when no anchor exists at all — the caller must treat the
/// insert as failed rather than proceed on unchanged text.
fn insert_nuget_source(config: &str, key: &str, url: &str) -> Option<String> {
    let source_line = format!("    <add key=\"{key}\" value=\"{url}\" />");
    // A self-closing element carries no children, so expand it to an open/close
    // pair holding the new source. Matched before the open-tag check because
    // the tolerant open-tag regex below also matches the whitespace-carrying
    // `<packageSources />` form, and inserting after its `>` would land the
    // source OUTSIDE the element.
    let self_closing = Regex::new(r"<packageSources\s*/>")
        .expect("static self-closing packageSources regex is valid");
    // The open tag may carry whitespace (`<packageSources >` is valid XML
    // NuGet parses); a literal `<packageSources>` probe reads it as absent
    // and the from-scratch branch below authors a DUPLICATE element — the
    // vendor/nuget_feed twin already tolerates the spelling.
    let open_tag = Regex::new(r"<packageSources(?:\s[^>]*)?>")
        .expect("static packageSources open-tag regex is valid");
    if let Some(m) = self_closing.find(config) {
        let mut out = String::with_capacity(config.len() + source_line.len() + 40);
        out.push_str(&config[..m.start()]);
        out.push_str(&format!(
            "<packageSources>\n{source_line}\n  </packageSources>"
        ));
        out.push_str(&config[m.end()..]);
        Some(out)
    } else if let Some(m) = open_tag
        .find(config)
        // An attribute-carrying self-closing form (`<packageSources … />`,
        // schema-invalid but cheap to guard) has no children span: fall
        // through to the from-scratch branch rather than insert outside it.
        .filter(|m| !m.as_str().ends_with("/>"))
    {
        let end = m.end();
        Some(format!(
            "{}\n{source_line}{}",
            &config[..end],
            &config[end..]
        ))
    } else {
        // The root open tag may carry whitespace or attributes
        // (`<configuration >`, `<configuration xmlns=…>`) — all valid XML a
        // literal `<configuration>` match would silently miss, leaving the
        // source undefined while the mapping still lands.
        let open_re = Regex::new(r"<configuration(\s[^>]*)?>")
            .expect("static configuration open-tag regex is valid");
        let end = open_re.find(config)?.end();
        Some(format!(
            "{}\n  <packageSources>\n{source_line}\n  </packageSources>{}",
            &config[..end],
            &config[end..]
        ))
    }
}

/// The `key` of every `<add … />` under `<packageSources>` (empty when there
/// is no such element). Used to preserve resolution for non-patched packages
/// when a `<packageSourceMapping>` is introduced.
// The open tag may carry whitespace (`<packageSources >` is valid XML NuGet
// parses); a literal match reads a real source list as "no sources" —
// duplicate nuget.org seed, missed catch-all fan-out — while the
// vendor/nuget_feed twin already tolerates the spelling. A self-closing
// `<packageSources />` has no close tag, so the regex (correctly) finds no
// children span.
static NUGET_PACKAGE_SOURCES_REGION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<packageSources(?:\s[^>]*)?>(.*?)</packageSources>")
        .expect("static packageSources region regex is valid")
});
// Tolerates any attribute order, whitespace around `=`, and single-quoted
// values (all valid XML NuGet accepts): a real source the scan misses would
// read as "no sources", triggering a duplicate nuget.org seed and leaving the
// missed source out of the catch-all fan-out. `[^>]` keeps the match inside
// one element.
static NUGET_ADD_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<add\s[^>]*?key\s*=\s*(?:"([^"]+)"|'([^']+)')"#)
        .expect("static add-key regex is valid")
});

fn nuget_package_source_keys(config: &str) -> Vec<String> {
    let scope = NUGET_PACKAGE_SOURCES_REGION_RE
        .captures(config)
        .map(|c| {
            c.get(1)
                .expect("region_re always captures group 1")
                .as_str()
        })
        .unwrap_or("");
    NUGET_ADD_KEY_RE
        .captures_iter(scope)
        .map(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .expect("one quote alternative always captures")
                .as_str()
                .to_string()
        })
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
    // A config this run authors from scratch records its source edits as
    // `added` — the spelling every other rewriter uses for a created file.
    let source_action = if files.contains_key("nuget.config") {
        "rewritten"
    } else {
        "added"
    };
    let mut config_changed = false;
    // A present-but-corrupt lock is strictly worse than a missing one: the
    // source + mapping would land while the lock kept the upstream
    // contentHash (NU1403 on restore) and the ledger claimed the redirect.
    // Warn once and skip the whole nuget redirect before anything is planned
    // (the npm twin does the same). An ABSENT lock is fine — config-only.
    let mut lock: Option<Value> = match files.get("packages.lock.json") {
        None => None,
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(parsed) => Some(parsed),
            Err(_) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_nuget_lock_unparseable".into(),
                    detail: "packages.lock.json is not valid JSON; nuget redirect skipped".into(),
                });
                return;
            }
        },
    };
    let mut lock_changed = false;

    for dep in &nuget {
        let Some(ov) = registry_override_of_kind(dep, "nuget-v3") else {
            result.warnings.push(RewriteWarning {
                code: "redirect_nuget_missing_override".into(),
                detail: format!("{} has no nuget-v3 registry override", dep.name),
            });
            continue;
        };
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

        // Idempotency probe over the parsed `<packageSources>` keys — the
        // same reader `add_nuget_source` fans the catch-all out with — so a
        // hand-normalized spelling (`key = 'socket-patch-…'`) is recognized
        // as already wired instead of being duplicated on a re-run.
        if !nuget_package_source_keys(&config)
            .iter()
            .any(|key| key == &reg)
        {
            // A failed insert skips the WHOLE dep (no edit record, no lock
            // re-pin): a mapping without its source routes the patched id to
            // a source that was never defined, and a lock pinned at the
            // patched contentHash over an upstream fetch fails NU1403 — both
            // while the ledger would claim the redirect landed.
            let Some(updated) = add_nuget_source(&config, &reg, &ov.index_url, &dep.name) else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_nuget_config_unwritable".into(),
                    detail: format!(
                        "nuget.config has no <configuration> element to wire {} into; \
                         not redirected",
                        dep.name
                    ),
                });
                continue;
            };
            config = updated;
            config_changed = true;
            result.edits.push(FileEdit {
                path: "nuget.config".into(),
                kind: "redirect_nuget_source".into(),
                action: source_action.into(),
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

/// Public host of Socket's patch server: the origin every production hosted
/// artifact / registry URL is served from (`https://patch.socket.dev/patch/…`,
/// `…/patch-registry/…`), and the root of the Go module namespace
/// [`crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX`].
pub const SOCKET_PATCH_SERVER_HOST: &str = "patch.socket.dev";

/// The Socket patch uuid a lockfile-recorded HOSTED reference names, or
/// `None` when `url` is not a Socket-hosted patch URL — the inverse of the
/// rewriters, used by `vex`'s manifest-less lockfile discovery.
///
/// Recognition is deliberately strict, because the answer decides whether a
/// committed (tamper-able) lockfile line becomes an attestation input:
///
/// * the ORIGIN must be Socket's patch server (`https://` +
///   [`SOCKET_PATCH_SERVER_HOST`]) or one of `extra_origins` — the
///   operator's `--patch-server-url` deployment, compared on scheme + host +
///   port. A uuid inside any other host's URL is a user's own dependency
///   source, never a patch reference;
/// * no userinfo — a Socket-written URL never carries credentials;
/// * the uuid is the LAST path segment passing the canonical-uuid grammar:
///   hosted URLs carry the grant token in the level before the uuid
///   (`…/patch/npm/<name>/<ver>/<token>/<uuid>/<leaf>`,
///   `…/patch-registry/<eco>/<token>/<uuid>/…`), and grant tokens may
///   themselves be uuid-shaped, so "the first uuid" would elect the token.
///
/// Every spelling the lock formats record the same URL in is accepted: a
/// `#fragment` (yarn classic `#<sha1>`, pip `#sha256=`) and a `?query` are
/// ignored; `\/`-escaped slashes (older composer locks) are unescaped; a
/// wholly percent-encoded URL (yarn berry's `__archiveUrl=` binding) is
/// decoded; a cargo source-kind prefix (`sparse+`, `registry+`) is dropped.
/// Path segments are percent-decoded AFTER splitting, so an encoded `/`
/// can never manufacture a segment.
pub fn hosted_patch_uuid(url: &str, extra_origins: &[String]) -> Option<String> {
    hosted_patch_url_uuids(url, extra_origins)?.pop()
}

/// EVERY canonical-uuid path segment of a Socket-HOSTED url, in path order
/// (the grant token first when it is uuid-shaped, the patch uuid last), or
/// `None` when `url` is not on an accepted origin — [`hosted_patch_uuid`]'s
/// exact acceptance rules, without electing one segment. `vex` discovery
/// uses it to RECOGNIZE every Socket identity a lockfile mentions, including
/// the malformed or rejected shapes whose "last uuid" is not a patch.
pub fn hosted_patch_url_uuids(url: &str, extra_origins: &[String]) -> Option<Vec<String>> {
    use crate::patch::path_safety::is_canonical_uuid;
    use crate::utils::purl::percent_decode_purl_component;

    let unescaped = url.trim().replace("\\/", "/");
    let lower = unescaped.to_ascii_lowercase();
    let decoded = if lower.starts_with("https%3a%2f%2f") || lower.starts_with("http%3a%2f%2f") {
        percent_decode_purl_component(&unescaped).into_owned()
    } else {
        unescaped
    };
    // `sparse+https://…` / `registry+https://…` (Cargo.lock `source`).
    let (scheme, _) = decoded.split_once("://")?;
    let text = match scheme.rsplit_once('+') {
        Some((kind, _)) if !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_alphabetic()) => {
            &decoded[kind.len() + 1..]
        }
        _ => decoded.as_str(),
    };
    let parsed = reqwest::Url::parse(text).ok()?;
    if !matches!(parsed.scheme(), "https" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let socket_host = parsed.scheme() == "https"
        && parsed.host_str() == Some(SOCKET_PATCH_SERVER_HOST)
        && parsed.port_or_known_default() == Some(443);
    let configured = extra_origins.iter().any(|origin| {
        reqwest::Url::parse(origin.trim()).is_ok_and(|o| {
            o.scheme() == parsed.scheme()
                && o.host_str().is_some()
                && o.host_str() == parsed.host_str()
                && o.port_or_known_default() == parsed.port_or_known_default()
        })
    });
    if !socket_host && !configured {
        return None;
    }
    Some(
        parsed
            .path_segments()?
            .map(|segment| percent_decode_purl_component(segment).into_owned())
            .filter(|segment| is_canonical_uuid(segment))
            .collect(),
    )
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
        // Silent here: this is the residue helper, the rewrite loop warns.
        let Some(ov) = registry_override_of_kind(dep, "rubygems-compact-index") else {
            continue;
        };
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

/// One parsed `GEM` section of a Gemfile.lock: its header line index, its
/// `remote:` lines (index + URL) and the exclusive end index — the start of
/// the next column-0 header (trailing blank separator included) or EOF.
struct GemLockSection {
    start: usize,
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
            sections.push(GemLockSection {
                start,
                remotes,
                end: j,
            });
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
        // own, inserted where bundler itself writes it: bundler emits the
        // rubygems `GEM` sections sorted by source identifier
        // (`SourceList#lock_rubygems_sources`: `sort_by(&:identifier)`, i.e.
        // by the section's remote URLs), so the new section goes before the
        // first `GEM` section whose remotes sort after the index URL, else
        // after the last one. A frozen install re-renders the lock, and
        // since bundler 4.0.19 (rubygems#9750, "fail instead of warning when
        // frozen mode can't update the lockfile") any difference is fatal:
        // "Your lockfile needs to be updated, but it can't be because frozen
        // mode is set". Appending after `https://rubygems.org/` when the
        // patch registry (`https://patch.socket.dev/…`) sorts first broke
        // every converged hosted pair under `BUNDLE_FROZEN` / deployment
        // mode (verified: 4.0.15 installs it, 4.0.21 refuses it).
        let mut last = spec_idx;
        while last + 1 < lines.len()
            && gem_lock_line_content(&lines[last + 1]).starts_with("      ")
        {
            last += 1;
        }
        let moved: Vec<String> = lines.drain(spec_idx..=last).collect();
        let n = moved.len();
        // Section bounds after the drain (every drained line sat inside
        // section `sec_idx`, which keeps its start).
        let bounds = |k: usize| -> (usize, usize) {
            let s = &sections[k];
            match k.cmp(&sec_idx) {
                std::cmp::Ordering::Less => (s.start, s.end),
                std::cmp::Ordering::Equal => (s.start, s.end - n),
                std::cmp::Ordering::Greater => (s.start - n, s.end - n),
            }
        };
        let identifier = |k: usize| -> String {
            sections[k]
                .remotes
                .iter()
                .map(|(_, url)| url.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let insert_at = (0..sections.len())
            .find(|&k| identifier(k).as_str() > index_url)
            .map(|k| bounds(k).0)
            .unwrap_or_else(|| bounds(sections.len() - 1).1);
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
    let mut warned_no_gemfile = false;

    for dep in &gem {
        let Some(ov) = registry_override_of_kind(dep, "rubygems-compact-index") else {
            result.warnings.push(RewriteWarning {
                code: "redirect_gem_missing_override".into(),
                detail: format!("{} has no rubygems-compact-index override", dep.name),
            });
            continue;
        };
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
        // Neither manifest nor lock in the chosen spelling: nothing to pin.
        // Say so once (parity with `redirect_npm_no_lockfile`) instead of
        // silently dropping the dep from the redirected count. A lock-only
        // project keeps its own per-dep `redirect_gem_lock_without_source`.
        if gemfile.is_none() && lock.is_none() {
            if !warned_no_gemfile {
                warned_no_gemfile = true;
                result.warnings.push(RewriteWarning {
                    code: "redirect_gem_no_gemfile".into(),
                    detail: format!(
                        "no {gemfile_name} / {lock_name} present; gem redirect skipped"
                    ),
                });
            }
            continue;
        }

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
    TRUSTED_CHECKSUMS_ON,
    "-Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256",
    "-Daether.artifactResolver.postProcessor.trustedChecksums.failIfMissing=false",
    "-Daether.trustedChecksumsSource.summaryFile=true",
    "-Daether.trustedChecksumsSource.summaryFile.basedir=${session.rootDirectory}/.mvn/checksums",
    "-Daether.trustedChecksumsSource.summaryFile.originAware=false",
];

/// The resolver switch (the first [`MVN_CONFIG_ARGS`] line) that makes the
/// checksums file an enforced pin; without it the file is inert.
pub(crate) const TRUSTED_CHECKSUMS_ON: &str =
    "-Daether.artifactResolver.postProcessor.trustedChecksums=true";

pub(crate) const MVN_CONFIG: &str = ".mvn/maven.config";
pub(crate) const MVN_CHECKSUMS: &str = ".mvn/checksums/checksums.sha256";

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
/// None. Offsets are into the FULL `pom`. Plain substring search — the tags
/// are literals, and the leftmost open tag followed by the first close tag
/// after it is exactly what the lazy `(?s)<tag>(.*?)</tag>` regex matched,
/// without a regex compile per tag per `<dependency>` block.
fn maven_tag_inner_range(pom: &str, tag: &str, from: usize, to: usize) -> Option<(usize, usize)> {
    let hay = &pom[from..to];
    let open = format!("<{tag}>");
    let inner_start = hay.find(open.as_str())? + open.len();
    let inner_end = inner_start + hay[inner_start..].find(format!("</{tag}>").as_str())?;
    Some((from + inner_start, from + inner_end))
}

static MAVEN_DEPENDENCY_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<dependency\b[^>]*>.*?</dependency>")
        .expect("static dependency-block regex is valid")
});

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
    let mut matches = vec![];
    for m in MAVEN_DEPENDENCY_BLOCK_RE.find_iter(pom) {
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
    let mut warned_no_pom = false;

    for dep in &maven {
        let Some(ov) = registry_override_of_kind(dep, "maven2") else {
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

        // The pom for the rest of this iteration; edits land in place.
        let Some(pom_text) = pom.as_mut() else {
            // A Gradle-only project is legitimately pom-less — the snippet
            // above IS its redirect path. Otherwise say why nothing landed
            // (parity with `redirect_npm_no_lockfile`), once per run.
            if !gradle_build_present && !warned_no_pom {
                warned_no_pom = true;
                result.warnings.push(RewriteWarning {
                    code: "redirect_maven_no_pom".into(),
                    detail: "no pom.xml present; maven redirect skipped".into(),
                });
            }
            continue;
        };
        // Unique-per-patch repository id (valid chars: alnum, `-`, `_`, `.`).
        let repo_id = format!("socket-patch-{}", dep.patch_uuid);

        // LEGACY same-GAV fallback: no suffixed version means the patched jar is
        // served under its original GAV. Add the repository (transport checksum
        // policy `fail`) exactly as before and warn that this is NOT
        // fail-closed.
        let Some(suffixed_version) = suffixed_version else {
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
            *pom_text = insert_maven_repository(pom_text, &repo_id, &ov.index_url);
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
        let matches = find_maven_dependency_matches(pom_text, &group_id, &artifact_id);

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
            pom_text.replace_range(*start..*end, &suffixed_version);
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
            *pom_text = insert_maven_dependency_management(
                pom_text,
                &group_id,
                &artifact_id,
                &suffixed_version,
            );
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
        if !pom_text.contains(&format!("<id>{repo_id}</id>")) {
            *pom_text = insert_maven_repository(pom_text, &repo_id, &ov.index_url);
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
pub(crate) fn local_repo_artifact_path(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    ext: &str,
) -> String {
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
        let Some(ov) = registry_override_of_kind(dep, "goproxy") else {
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
        if !go_mod_edit::is_hosted_module_path(rhs_module) {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_untrusted_module_path".into(),
                detail: format!(
                    "{fname}@{}: refusing hosted module path `{rhs_module}`: not \
                     `{HOSTED_GO_MODULE_PREFIX}<patch uuid>`",
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
        if !go_sum_edit::is_h1_dirhash(zip_h1) || !go_sum_edit::is_h1_dirhash(gomod_h1) {
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
        let required = go_mod_edit::parse_required_versions(&go_mod);
        if let Some(required) = required.get(&fname) {
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
        } else if !go_sum_edit::has_module_version(&go_sum, &fname, &dep.version)
            && prior
                .as_ref()
                .is_none_or(|e| e.version.as_deref() != Some(dep.version.as_str()))
        {
            // Not required, not in go.sum at this version, and not already
            // redirected by us: the module is outside this project's graph
            // (local discovery crawls the whole module cache). Its replace
            // would be inert, and confirming it would attest a patch no
            // build links.
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_not_in_module_graph".into(),
                detail: format!(
                    "{fname}@{}: not required by go.mod and absent from go.sum — the \
                     module is not in this project's build graph; nothing redirected",
                    dep.version
                ),
            });
            continue;
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
        result.confirmed_golang_uuids.insert(dep.patch_uuid.clone());
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

    /// An inline comment after the marker must not swallow the appended
    /// `--hash=…` (pip would then treat the hash as comment text and skip
    /// enforcement). The comment is split off and re-appended AFTER the hash
    /// so the pin stays active and the user's note survives.
    #[test]
    fn requirements_marker_comment_keeps_hash_active() {
        let original = "requests==2.28.1 ; python_version >= \"3.7\" # explanation\n";
        let files = BTreeMap::from([("requirements.txt".to_string(), original.to_string())]);
        let sha256 = "c".repeat(64);
        let url = "https://patch.socket.dev/requests-2.28.1-py3-none-any.whl";
        let overrides = vec![pypi_override("requests", "2.28.1", url, &sha256)];
        let first = rewrite_registry_redirect(&files, &overrides);
        let output = first.files.get("requirements.txt").expect("rewritten");
        assert_eq!(
            output,
            &format!(
                "requests @ {url} ; python_version >= \"3.7\" --hash=sha256:{sha256} # explanation\n"
            )
        );
        let again = BTreeMap::from([("requirements.txt".to_string(), output.clone())]);
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(second.files.is_empty());
        assert!(second.edits.is_empty());
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

    /// The nuget.org seed must not be suppressed by "nuget.org" TEXT outside
    /// the `<packageSources>` element — a `defaultPushSource` URL, a
    /// `<disabledPackageSources>` entry, or a comment is not a package
    /// source. Suppressing the seed there leaves the from-scratch mapping
    /// socket-only, and a mapping is exclusive: every other package NU1100s.
    #[test]
    fn nuget_seed_not_suppressed_by_nugetorg_text_outside_sources() {
        for extra in [
            // The push URL mentions nuget.org but defines no source.
            "  <config>\n    <add key=\"defaultPushSource\" value=\"https://api.nuget.org/v3/index.json\" />\n  </config>\n",
            // So does a comment.
            "  <!-- nuget.org supplied by machine config -->\n",
        ] {
            let mut files = BTreeMap::new();
            files.insert(
                "nuget.config".to_string(),
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n  </packageSources>\n{extra}</configuration>\n"
                ),
            );
            let r = rewrite_registry_redirect(&files, &[nuget_override()]);
            let out = r.files.get("nuget.config").expect("config rewritten");
            assert!(
                out.contains(
                    "<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />"
                ),
                "nuget.org source seeded despite unrelated mention: {out}"
            );
            assert!(
                out.contains(
                    "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
                ),
                "catch-all present (socket-only mapping NU1100s everything): {out}"
            );
        }
    }

    /// An `<add>` keyed nuget.org that the strict scan used to miss (XML
    /// allows whitespace around `=` and any attribute order) is a REAL
    /// source: it must be harvested as the catch-all target — not
    /// double-added by the seed, and not left out of the `*` fan-out.
    #[test]
    fn nuget_whitespace_variant_add_is_harvested_not_reseeded() {
        let mut files = BTreeMap::new();
        files.insert(
            "nuget.config".to_string(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key = \"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>\n</configuration>\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        let out = r.files.get("nuget.config").expect("config rewritten");
        assert!(
            !out.contains("<add key=\"nuget.org\""),
            "the existing source must not be duplicated by the seed: {out}"
        );
        assert!(
            out.contains(
                "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
            ),
            "the existing source takes the catch-all: {out}"
        );
    }

    /// A `<packageSources >`-style open tag, or single-quoted `<add>`
    /// attributes — both valid XML NuGet parses — is a REAL source list: its
    /// keys must be harvested and the socket source inserted into the
    /// EXISTING element. The literal probes used to read it as zero sources:
    /// a SECOND `<packageSources>` element appeared carrying a duplicate
    /// nuget.org seed, and the catch-all fanned `*` only to nuget.org —
    /// every corp-feed-only package then NU1100s. Mirrors the tolerant
    /// vendor/nuget_feed twin.
    #[test]
    fn nuget_open_tag_whitespace_and_single_quotes_harvested_not_reseeded() {
        for config in [
            // Whitespace inside the <packageSources> open tag.
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources >\n    <add key=\"corp-feed\" value=\"https://nuget.corp.example/v3/index.json\" />\n  </packageSources>\n</configuration>\n",
            // Single-quoted <add> attribute values.
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key='corp-feed' value='https://nuget.corp.example/v3/index.json' />\n  </packageSources>\n</configuration>\n",
        ] {
            let mut files = BTreeMap::new();
            files.insert("nuget.config".to_string(), config.to_string());
            let r = rewrite_registry_redirect(&files, &[nuget_override()]);
            let out = r.files.get("nuget.config").expect("config rewritten");
            // Exactly ONE opening <packageSources> element, whatever its
            // spelling — no from-scratch duplicate beside the real one.
            assert_eq!(
                out.matches("<packageSources").count(),
                1,
                "single packageSources element (no duplicate): {out}"
            );
            assert!(
                !out.contains("nuget.org"),
                "the harvested corp feed suppresses the nuget.org seed: {out}"
            );
            assert!(
                out.contains("<add key=\"socket-patch-uuid\""),
                "socket source inserted into the existing element: {out}"
            );
            assert!(
                out.contains(
                    "    <packageSource key=\"corp-feed\">\n      <package pattern=\"*\" />\n    </packageSource>"
                ),
                "the corp feed takes the catch-all: {out}"
            );
        }
    }

    /// A root open tag that isn't the literal `<configuration>` — trailing
    /// whitespace or attributes, both valid XML NuGet parses fine — must
    /// still receive the source insert. The literal `replacen` used to no-op
    /// silently while the mapping (anchored on the close tag) still landed,
    /// routing the patched id to a source that was never defined.
    #[test]
    fn nuget_config_root_tag_with_whitespace_still_wired() {
        for open_tag in ["<configuration >", "<configuration\n    >"] {
            let mut files = BTreeMap::new();
            files.insert(
                "nuget.config".to_string(),
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n{open_tag}\n</configuration>\n"
                ),
            );
            let r = rewrite_registry_redirect(&files, &[nuget_override()]);
            let out = r.files.get("nuget.config").expect("config rewritten");
            assert!(
                out.contains("<add key=\"socket-patch-uuid\""),
                "socket source defined for root tag {open_tag:?}: {out}"
            );
            assert!(
                out.contains("<package pattern=\"Newtonsoft.Json\" />"),
                "socket mapping present: {out}"
            );
        }
    }

    /// When NO anchor exists for the source insert, the dep must be skipped
    /// fail-closed with a warning: no config write, no recorded edit whose
    /// `new` claims the source landed, and no lock re-pin (a patched
    /// contentHash over an upstream fetch fails restore with NU1403).
    #[test]
    fn nuget_config_without_configuration_root_skips_dep_with_warning() {
        let mut files = BTreeMap::new();
        files.insert(
            "nuget.config".to_string(),
            "<packages>\n</packages>\n".to_string(),
        );
        files.insert(
            "packages.lock.json".to_string(),
            r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "ORIGINALHASH=="
      }
    }
  }
}
"#
            .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "an unwritable config must not record a half-write: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(
            warning_codes(&r).contains(&"redirect_nuget_config_unwritable"),
            "the failed insert must be SAID: {:?}",
            r.warnings
        );
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

    /// REGRESSION (yarn 4.0.x): a lock that spells its `10c0` checksums
    /// bare (yarn 4.0.0–4.0.2) gets the hosted entry's checksum spelled bare
    /// — the API's prefixed `yarnBerry10c0` made `yarn install --immutable`
    /// reject the rewritten lock (YN0028). A 4.1+ (prefixed) lock keeps it.
    #[test]
    fn yarn_berry_checksum_follows_the_lock_spelling() {
        let hex = "7".repeat(128);
        let ovr = berry_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            &format!("10c0/{hex}"),
        );
        for (lock, want) in [
            (
                berry_lock("10c0").replace("checksum: 10c0/", "checksum: "),
                format!("\n  checksum: {hex}\n"),
            ),
            (berry_lock("10c0"), format!("\n  checksum: 10c0/{hex}\n")),
        ] {
            let mut files = BTreeMap::new();
            files.insert("yarn.lock".to_string(), lock.clone());
            let mut r = RewriteResult::default();
            rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
            let out = &r.files["yarn.lock"];
            assert!(out.contains("::__archiveUrl="), "{out}");
            assert!(out.contains(&want), "want {want:?} in:\n{out}");
            assert_eq!(out.matches("checksum:").count(), 1, "{out}");
        }
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
        assert_eq!(r.warnings[0].code, "redirect_bun_lockb_bytes_required");

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
            .any(|w| w.code == "redirect_bun_lockb_bytes_required"));

        // lockfileVersion 2 (bun >= 1.4): SAME emitted grammar as 1 — the
        // bump gates stricter parse checks, not new entry shapes — so the
        // rewrite proceeds and the version line survives verbatim.
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
        let out = r
            .files
            .get("bun.lock")
            .expect("a lockfileVersion-2 lock must be rewritten like a v1 lock");
        assert!(out.contains("\"lockfileVersion\": 2,"), "{out}");
        assert!(out.contains("http://p.test/lp.tgz"), "{out}");
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);

        // Unsupported lockfileVersion (a future 3) → refusal.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"]",
                3,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_lock_unsupported");
        assert!(
            r.warnings[0]
                .detail
                .contains("lockfileVersion 3, newer than this socket-patch release supports")
                && r.warnings[0].detail.contains("(0, 1 and 2)")
                && r.warnings[0].detail.contains("update socket-patch"),
            "the refusal must name the found version, the supported set and a remedy that \
             can work (a v3 lock was written by a NEWER Bun): {}",
            r.warnings[0].detail
        );
        // One message for both modes: the hosted detail IS the shared gate's
        // error text, so vendored and hosted refusals cannot drift apart.
        assert_eq!(
            r.warnings[0].detail,
            crate::vendor::bun_lock_text::check_lock_version(&files["bun.lock"]).unwrap_err()
        );

        // No integer lockfileVersion at all → the OTHER remedy (re-lock).
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            "{\n  \"packages\": {\n    \
             \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],\n  }\n}\n"
                .to_string(),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(r.warnings[0].code, "redirect_bun_lock_unsupported");
        assert!(
            r.warnings[0].detail.contains("no integer lockfileVersion")
                && r.warnings[0]
                    .detail
                    .contains("re-lock with Bun ≥ 1.2 (`bun install`)"),
            "a head without an integer version must point at a Bun re-lock: {}",
            r.warnings[0].detail
        );
        assert_eq!(
            r.warnings[0].detail,
            crate::vendor::bun_lock_text::check_lock_version(&files["bun.lock"]).unwrap_err()
        );

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

    /// bun's REAL emitted workspace-lock shape (captured from bun 1.1.45 at
    /// lockfileVersion 0 and from 1.3.14 / 1.4.2 at 1 / 2): trailing commas
    /// throughout and a blank line between packages entries. Only the
    /// version integer and the packages entries vary per test; the root
    /// workspace dep is spelled as the bare path bun 1.1.x writes (≥ 1.2
    /// writes `workspace:*`) — the rewriter never reads that block.
    fn bun_workspace_lock(version: u64, entries: &[&str]) -> String {
        format!(
            "{{\n  \"lockfileVersion\": {version},\n  \"workspaces\": {{\n    \"\": {{\n      \
             \"name\": \"bun-patch-backtest\",\n      \"dependencies\": {{\n        \
             \"consumer\": \"packages/consumer\",\n      }},\n    }},\n    \
             \"packages/consumer\": {{\n      \"name\": \"consumer\",\n      \"version\": \
             \"1.0.0\",\n      \"dependencies\": {{\n        \"left-pad\": \"1.3.0\",\n      \
             }},\n    }},\n  }},\n  \"packages\": {{\n{}\n  }}\n}}\n",
            entries.join("\n\n")
        )
    }

    /// The bun 1.1.39–1.1.45 (lockfileVersion 0) workspace refusal, on the
    /// grammar those releases actually write — the 2-tuple
    /// `["consumer@workspace:packages/consumer", { "dependencies": {…} }]`
    /// (v1/v2 write a 1-tuple) — and its positive twins: the SAME entries at
    /// lockfileVersion 1 and 2 must rewrite with the workspace line kept
    /// byte-identical, proving the gate is version-0-only and not "any
    /// workspace lock". Mutations this pins: dropping the `Some(0)` half of
    /// the gate, renaming the code, or regressing the remedy text.
    #[test]
    fn bun_lock_v0_workspace_refuses_and_v1_v2_workspace_rewrite() {
        let sha512 = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &sha512);
        let ws_v0 = "    \"consumer\": [\"consumer@workspace:packages/consumer\", \
                     { \"dependencies\": { \"left-pad\": \"1.3.0\" } }],";
        let registry = "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],";

        // Version 0 + workspace member → refused, byte-untouched, exactly one
        // warning (no entry-not-found double-warn) with the verified remedy.
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_workspace_lock(0, &[ws_v0, registry]),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.files);
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
        assert_eq!(r.warnings[0].code, "redirect_bun_workspace_unsupported");
        let detail = &r.warnings[0].detail;
        assert_eq!(
            detail,
            "Bun version-0 workspace locks cannot preserve hosted tarballs on frozen installs; \
             delete bun.lock and re-run `bun install` with Bun >= 1.2 (which writes \
             lockfileVersion 1, accepted by hosted mode) — a plain in-place `bun install` bumps \
             the version only when a workspace depends on another workspace (e.g. root -> \
             member); otherwise it keeps version 0 or fails to resolve",
            "the refusal must lead with the remedy that converges on every release \
             (delete + re-lock) and state the in-place bump as CONDITIONAL"
        );
        assert!(
            !detail.contains("rewrites the lock as lockfileVersion 1"),
            "the old unconditional in-place claim must be gone: {detail}"
        );

        // The SAME entries at lockfileVersion 1 and 2 → rewritten; the
        // workspace line survives byte-for-byte; no warning of any kind.
        for version in [1u64, 2] {
            let mut files = BTreeMap::new();
            files.insert(
                "bun.lock".to_string(),
                bun_workspace_lock(version, &[ws_v0, registry]),
            );
            let mut r = RewriteResult::default();
            rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
            assert!(r.warnings.is_empty(), "v{version}: {:?}", r.warnings);
            let out = r
                .files
                .get("bun.lock")
                .unwrap_or_else(|| panic!("a v{version} workspace lock must be rewritten"));
            assert!(
                out.contains(&format!("\"lockfileVersion\": {version},")),
                "{out}"
            );
            assert!(
                out.contains(&format!("{ws_v0}\n")),
                "v{version}: the workspace line must be byte-identical: {out}"
            );
            assert!(
                out.contains("\"left-pad\": [\"left-pad@http://p.test/lp.tgz\", {}, \"sha512-"),
                "v{version}: the registry tuple must become the URL 3-tuple: {out}"
            );
            assert_eq!(r.edits.len(), 1, "v{version}: {:?}", r.edits);
            assert_eq!(r.edits[0].key.as_deref(), Some("left-pad"));
            assert_eq!(
                out,
                &bun_workspace_lock(
                    version,
                    &[
                        ws_v0,
                        &format!(
                            "    \"left-pad\": [\"left-pad@http://p.test/lp.tgz\", {{}}, \
                             \"{sha512}\"],"
                        )
                    ]
                ),
                "v{version}: only the target line may change"
            );
        }

        // The 1-tuple spelling bun ≥ 1.2 actually writes for a workspace
        // member is rewritten the same way (the gate reads the spec only).
        let ws_v1 = "    \"consumer\": [\"consumer@workspace:packages/consumer\"],";
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_workspace_lock(1, &[ws_v1, registry]),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = r
            .files
            .get("bun.lock")
            .expect("real v1 grammar must rewrite");
        assert!(out.contains(&format!("{ws_v1}\n")), "{out}");
        assert!(out.contains("left-pad@http://p.test/lp.tgz"), "{out}");
    }

    /// A version-0 lock whose only `workspaces` key is the root `""` (bun
    /// 1.1.45 `--save-text-lockfile` on a plain project — captured grammar:
    /// no `configVersion`, trailing commas) has no `workspace:` member and
    /// must be rewritten, not refused: the gate is "v0 AND a workspace
    /// member", not "v0".
    #[test]
    fn bun_lock_v0_root_only_workspace_rewrites() {
        let sha512 = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &sha512);
        let lock = "{\n  \"lockfileVersion\": 0,\n  \"workspaces\": {\n    \"\": {\n      \
                    \"name\": \"bun-patch-backtest\",\n      \"dependencies\": {\n        \
                    \"left-pad\": \"1.3.0\",\n      },\n    },\n  },\n  \"packages\": {\n    \
                    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],\n  }\n}\n";
        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), lock.to_string());
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = r
            .files
            .get("bun.lock")
            .expect("a root-only v0 lock must be rewritten");
        assert_eq!(
            out,
            &lock.replace(
                "[\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"]",
                &format!("[\"left-pad@http://p.test/lp.tgz\", {{}}, \"{sha512}\"]")
            )
        );
        assert_eq!(r.edits.len(), 1);
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

    /// A CRLF bun.lock (Windows `core.autocrlf` checkout) must keep CRLF on
    /// the REWRITTEN line too — the vendored engine already does — so the
    /// file never ends up mixed-EOL, and the ledger `new` fragment carries
    /// the same on-disk `\r` as `original` (replay matches fragments
    /// byte-exactly: an LF `new` would no longer be found after an autocrlf
    /// commit/checkout round-trip, leaving `\r\r\n` on revert). Modelled on
    /// `yarn_classic_crlf_lock_rewrites_only_the_target_entry`.
    #[test]
    fn bun_crlf_lock_keeps_crlf_on_rewritten_line() {
        let sha512 = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &sha512);
        let decoy = "    \"abbrev\": [\"abbrev@1.1.1\", \"\", {}, \"sha512-DECOYdecoy==\"],";
        let target = "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],";
        let lf_lock = bun_workspace_lock(2, &[decoy, target]);

        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), lf_lock.replace('\n', "\r\n"));
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "clean rewrite: {:?}", r.warnings);
        let out = r.files.get("bun.lock").expect("bun.lock must be rewritten");
        assert!(
            out.contains(&format!("{decoy}\r\n")),
            "the decoy entry must stay byte-identical: {out}"
        );
        assert!(
            out.contains(&format!(
                "    \"left-pad\": [\"left-pad@http://p.test/lp.tgz\", {{}}, \"{sha512}\"],\r\n"
            )),
            "the target entry must pin the hosted artifact AND keep its CRLF: {out}"
        );
        assert_eq!(
            out.matches('\n').count(),
            out.matches("\r\n").count(),
            "every line must keep its CRLF ending: {out}"
        );

        // The CRLF output is exactly the LF rewrite re-expanded.
        let mut lf_files = BTreeMap::new();
        lf_files.insert("bun.lock".to_string(), lf_lock);
        let mut lf_r = RewriteResult::default();
        rewrite_bun_lock(&lf_files, std::slice::from_ref(&ovr), &mut lf_r);
        assert_eq!(
            out,
            &lf_r.files["bun.lock"].replace('\n', "\r\n"),
            "CRLF rewrite must equal the LF rewrite modulo line endings"
        );

        // Ledger fragments carry the on-disk (CR-bearing) byte form on BOTH
        // sides, so revert finds `new` and restores `original` byte-exactly.
        assert_eq!(r.edits.len(), 1);
        let original = r.edits[0].original.as_ref().unwrap().as_str().unwrap();
        let new = r.edits[0].new.as_ref().unwrap().as_str().unwrap();
        assert_eq!(
            original,
            format!("{target}\r"),
            "original must carry the \\r"
        );
        assert!(new.ends_with("],\r"), "new must carry the \\r too: {new:?}");
        assert!(!new.contains('\n') && !original.contains('\n'));
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

    #[test]
    fn uv_lock_uses_direct_source_and_matching_archive() {
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
            "direct source and wheel URL agree: {out}"
        );
        assert_eq!(
            out.matches(&format!("hash = \"sha256:{}\"", "c".repeat(64)))
                .count(),
            1,
            "one patched wheel hash is pinned: {out}"
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

    /// The residue probe (`vendor`'s fail-closed guard against wiring
    /// `[patch.crates-io]` on top of a live hosted redirect) reads back
    /// EVERY declaration shape this rewriter pins — driven through the
    /// rewriter itself so the two can never drift apart. A single-line
    /// `<name> = { … }` regex saw only the first of these.
    #[test]
    fn cargo_socket_registry_pin_reads_back_every_written_shape() {
        let head = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n";
        let shapes = [
            ("plain version", "[dependencies]\nserde = \"1.0.190\"\n"),
            ("quoted key", "[dependencies]\n\"serde\" = \"1.0.190\"\n"),
            (
                "inline table",
                "[dependencies]\nserde = { version = \"1.0.190\" }\n",
            ),
            (
                "renamed inline table",
                "[dependencies]\nlegacy = { package = \"serde\", version = \"1.0.190\" }\n",
            ),
            (
                "table form",
                "[dependencies.serde]\nversion = \"1.0.190\"\n",
            ),
            (
                "renamed table form",
                "[dependencies.legacy]\npackage = \"serde\"\nversion = \"1.0.190\"\n",
            ),
            (
                "dev-dependency table form",
                "[dev-dependencies.serde]\nversion = \"1.0.190\"\n",
            ),
            (
                "target table",
                "[target.'cfg(unix)'.dependencies]\nserde = \"1.0.190\"\n",
            ),
            (
                "workspace dependencies table form",
                "[workspace.dependencies.serde]\nversion = \"1.0.190\"\n",
            ),
        ];
        for (shape, body) in shapes {
            let pristine = format!("{head}{body}");
            assert_eq!(
                cargo_socket_registry_pin(&pristine, "serde"),
                None,
                "{shape}: an unpinned manifest is not residue"
            );
            let r = rewrite_registry_redirect(&cargo_files(&pristine), &[cargo_sparse_override()]);
            assert!(r.warnings.is_empty(), "{shape}: {:?}", r.warnings);
            let written = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
            assert_eq!(
                cargo_socket_registry_pin(written, "serde").as_deref(),
                Some(cargo_reg().as_str()),
                "{shape}: the probe must read back what the rewriter wrote: {written}"
            );
        }
        // Another crate's pin, and a registry that is not ours, are not this
        // crate's residue.
        let other = format!(
            "{head}[dependencies]\nother = {{ version = \"1\", registry = \"{}\" }}\n\
             serde = {{ version = \"1.0.190\", registry = \"corp-mirror\" }}\n",
            cargo_reg()
        );
        assert_eq!(cargo_socket_registry_pin(&other, "serde"), None);
        // A renamed key declaring ANOTHER crate never answers for `serde`.
        let renamed_other = format!(
            "{head}[dependencies]\nserde = {{ package = \"serde_json\", version = \"1\", \
             registry = \"{}\" }}\n",
            cargo_reg()
        );
        assert_eq!(cargo_socket_registry_pin(&renamed_other, "serde"), None);
    }

    /// NO Cargo.lock: the transitive-dependents refusal reads the resolved
    /// graph, and without one nothing says whether another dependency also
    /// pulls in the patched crate — a pin reaches only the declarations it
    /// sits on, so that consumer would compile the unpatched crates.io copy
    /// while the scan reported the crate redirected and VEX attested it.
    /// Every OTHER declared dependency is therefore blocking; a path
    /// dependency on a manifest this run pins is not (its own declarations
    /// are pinned too), and neither is a `workspace = true` inheritor of the
    /// root table this run scans.
    #[test]
    fn cargo_lockless_other_dependencies_are_refused() {
        let head = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n";
        let refused = |files: BTreeMap<String, String>| {
            let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
            assert!(r.files.is_empty(), "nothing rewritten: {:?}", r.files);
            assert!(r.edits.is_empty(), "{:?}", r.edits);
            assert!(r.confirmed_cargo_uuids.is_empty(), "never confirmed");
            assert_eq!(
                warning_codes(&r),
                vec!["redirect_cargo_lockless_dependents"]
            );
            r.warnings[0].detail.clone()
        };
        let one = |toml: &str| {
            let mut files = BTreeMap::new();
            files.insert("Cargo.toml".to_string(), toml.to_string());
            files
        };

        // A registry dependency beside the patched crate.
        let detail = refused(one(&format!(
            "{head}[dependencies]\nserde = \"1.0.190\"\ntokio = \"1\"\n"
        )));
        assert!(detail.contains("tokio"), "{detail}");
        assert!(detail.contains("cargo generate-lockfile"), "{detail}");
        assert!(detail.contains("--mode vendored"), "{detail}");
        // A dev-dependency counts (it is linked into the test build too).
        refused(one(&format!(
            "{head}[dependencies]\nserde = \"1.0.190\"\n\n\
             [dev-dependencies]\ntokio = \"1\"\n"
        )));
        // A path dependency this run cannot pin (outside the project).
        let detail = refused(one(&format!(
            "{head}[dependencies]\nserde = \"1.0.190\"\n\
             shared = {{ path = \"../shared\" }}\n"
        )));
        assert!(detail.contains("shared"), "{detail}");
        // A member's own other dependency blocks as well.
        let mut files = one(&format!(
            "[workspace]\nmembers = [\"b\"]\n\n{head}\
             [dependencies]\nserde = \"1.0.190\"\n"
        ));
        files.insert(
            "b/Cargo.toml".to_string(),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nrand = \"0.8\"\n"
                .to_string(),
        );
        let detail = refused(files);
        assert!(detail.contains("rand (in b/Cargo.toml)"), "{detail}");

        // A member manifest this run did NOT read — dropped by member
        // discovery (a symbolic link, a path outside the project) or hidden
        // behind a glob it cannot expand — may declare the crate itself or
        // pull it in, and nothing here can tell.
        let detail = refused(one(
            "[workspace]\nmembers = [\"b\"]\n\n[package]\nname = \"app\"\n\
             version = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        ));
        assert!(detail.contains("the workspace member `b`"), "{detail}");
        let detail = refused(one(
            "[workspace]\nmembers = [\"crates/*\"]\n\n[package]\nname = \"app\"\n\
             version = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        ));
        assert!(
            detail.contains("the workspace members pattern `crates/*`"),
            "{detail}"
        );
    }

    /// The lockless shapes that stay redirectable: the patched crate alone,
    /// the same crate declared again by a member this run pins, and a path
    /// dependency on that member (whose own declarations are pinned too).
    #[test]
    fn cargo_lockless_self_contained_workspace_still_redirects() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            "[workspace]\nmembers = [\"b\"]\n\n\
             [package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = \"1.0.190\"\nb = { path = \"b\" }\n"
                .to_string(),
        );
        files.insert(
            "b/Cargo.toml".to_string(),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = \"1.0.190\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
        for key in ["Cargo.toml", "b/Cargo.toml"] {
            assert!(
                r.files
                    .get(key)
                    .is_some_and(|t| t.contains(&format!("registry = \"{}\"", cargo_reg()))),
                "{key} must be pinned: {:?}",
                r.files.get(key)
            );
        }
        assert!(!r.files.contains_key("Cargo.lock"));
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

    /// A second patched version of the crate, uuid distinct from
    /// [`CARGO_UUID`].
    const CARGO_UUID_2: &str = "3c5d7e9f-2a4b-4c6d-8e0f-1a3b5c7d9e1f";

    fn cfg_if_override(version: &str, uuid: &str) -> DepOverride {
        let mut dep = cargo_sparse_override();
        dep.name = "cfg-if".into();
        dep.version = version.into();
        dep.patch_uuid = uuid.into();
        let ov = dep.registry_override.as_mut().expect("fixture override");
        ov.index_url = format!("sparse+https://patch.test/cargo/{uuid}/index/");
        ov.identifiers.name = "cfg-if".into();
        ov.identifiers.version = version.into();
        dep
    }

    /// Both cfg-if versions locked from crates.io (the `multi-version` shape).
    fn cfg_if_multi_files(manifest_deps: &str) -> BTreeMap<String, String> {
        let block = |v: &str| {
            format!(
                "[[package]]\nname = \"cfg-if\"\nversion = \"{v}\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n",
                "1".repeat(64)
            )
        };
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n{manifest_deps}"),
        );
        files.insert(
            "Cargo.lock".to_string(),
            format!("version = 3\n\n{}\n{}", block("0.1.10"), block("1.0.4")),
        );
        files
    }

    const CFG_IF_MULTI_DEPS: &str = "[dependencies]\ncfg-if = \"1.0.4\"\n\
         cfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n";

    /// Bug B: the manifest pin matched the crate NAME only, so every
    /// same-named declaration — `cfg-if-legacy = { package = "cfg-if",
    /// version = "0.1.10" }` too — was pinned to the one patched version's
    /// registry, where `^0.1.10` cannot resolve. Each declaration is pinned
    /// only by the patch its version requirement selects.
    #[test]
    fn cargo_multi_version_pins_only_the_declaration_the_version_selects() {
        let files = cfg_if_multi_files(CFG_IF_MULTI_DEPS);
        let reg1 = format!("socket-patch-{CARGO_UUID}");
        let reg2 = format!("socket-patch-{CARGO_UUID_2}");

        let r = rewrite_registry_redirect(&files, &[cfg_if_override("1.0.4", CARGO_UUID)]);
        let toml = r.files.get("Cargo.toml").expect("manifest pinned");
        assert!(
            toml.contains(&format!(
                "cfg-if = {{ version = \"1.0.4\", registry = \"{reg1}\" }}\n"
            )),
            "{toml}"
        );
        assert!(
            toml.contains("cfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n"),
            "the 0.1.10 declaration is not the patched version's: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);

        let r = rewrite_registry_redirect(&files, &[cfg_if_override("0.1.10", CARGO_UUID_2)]);
        let toml = r.files.get("Cargo.toml").expect("manifest pinned");
        assert!(toml.contains("cfg-if = \"1.0.4\"\n"), "{toml}");
        assert!(
            toml.contains(&format!(
                "cfg-if-legacy = {{ package = \"cfg-if\", version = \"0.1.10\", registry = \"{reg2}\" }}"
            )),
            "{toml}"
        );
        let lock = r.files.get("Cargo.lock").expect("lock repointed");
        assert!(
            lock.contains(&format!(
                "version = \"0.1.10\"\nsource = \"sparse+https://patch.test/cargo/{CARGO_UUID_2}/index/\""
            )) && lock.contains(
                "version = \"1.0.4\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\""
            ),
            "only the 0.1.10 entry moves: {lock}"
        );

        let r = rewrite_registry_redirect(
            &files,
            &[
                cfg_if_override("1.0.4", CARGO_UUID),
                cfg_if_override("0.1.10", CARGO_UUID_2),
            ],
        );
        let toml = r.files.get("Cargo.toml").expect("manifest pinned");
        assert!(
            toml.contains(&format!("version = \"1.0.4\", registry = \"{reg1}\""))
                && toml.contains(&format!("version = \"0.1.10\", registry = \"{reg2}\"")),
            "{toml}"
        );
        assert_eq!(r.confirmed_cargo_uuids.len(), 2);
    }

    /// A requirement that also matches another locked version cannot be
    /// attributed to the patched one — refuse the dep, write nothing.
    #[test]
    fn cargo_requirement_matching_several_locked_versions_refuses() {
        let files = cfg_if_multi_files(
            "[dependencies]\ncfg-if = \">=0.1\"\n\
             cfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cfg_if_override("1.0.4", CARGO_UUID)]);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.files);
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A declaration whose requirement excludes the patched version is not
    /// the patched crate, and a pin there cannot reach the locked one: the
    /// requirement-coverage refusal (the TS twin's code), nothing written.
    #[test]
    fn cargo_requirement_excluding_the_patched_version_is_unrewritable() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"2\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty(), "{:?}", r.files);
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
        assert!(
            r.warnings[0].detail.contains("\"2\" in Cargo.toml"),
            "{:?}",
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// A `workspace = true` inheritor of the entry that names ANOTHER
    /// version is not this dep (and does not refuse it).
    #[test]
    fn cargo_workspace_inheritor_of_another_version_is_skipped() {
        let files = cfg_if_multi_files(
            "[workspace.dependencies]\ncfg-if = \"1.0.4\"\n\
             cfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n\n\
             [dependencies]\ncfg-if = { workspace = true }\n\
             cfg-if-legacy = { workspace = true }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cfg_if_override("0.1.10", CARGO_UUID_2)]);
        let toml = r.files.get("Cargo.toml").expect("workspace entry pinned");
        assert!(
            toml.contains(&format!(
                "cfg-if-legacy = {{ package = \"cfg-if\", version = \"0.1.10\", registry = \"socket-patch-{CARGO_UUID_2}\" }}"
            )) && toml.contains("[workspace.dependencies]\ncfg-if = \"1.0.4\"\n"),
            "{toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID_2));
    }

    /// A project the name-only matcher already damaged (the 0.1.10
    /// declaration pinned to the 1.0.4 patch's registry) is repaired: the
    /// 0.1.10 patch supersedes its own declaration's socket pin, and the
    /// 1.0.4 patch leaves it alone.
    #[test]
    fn cargo_mispinned_other_version_declaration_is_repaired() {
        let reg1 = format!("socket-patch-{CARGO_UUID}");
        let reg2 = format!("socket-patch-{CARGO_UUID_2}");
        let files = cfg_if_multi_files(&format!(
            "[dependencies]\ncfg-if = {{ version = \"1.0.4\", registry = \"{reg1}\" }}\n\
             cfg-if-legacy = {{ package = \"cfg-if\", version = \"0.1.10\", registry = \"{reg1}\" }}\n"
        ));
        let r = rewrite_registry_redirect(
            &files,
            &[
                cfg_if_override("1.0.4", CARGO_UUID),
                cfg_if_override("0.1.10", CARGO_UUID_2),
            ],
        );
        let toml = r.files.get("Cargo.toml").expect("legacy pin superseded");
        assert!(
            toml.contains(&format!("version = \"1.0.4\", registry = \"{reg1}\""))
                && toml.contains(&format!("version = \"0.1.10\", registry = \"{reg2}\"")),
            "{toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// A virtual workspace: the root pins `[workspace.dependencies]`, member
    /// `a` inherits, member `b` declares serde itself.
    fn cargo_workspace_files(b_manifest: &str) -> BTreeMap<String, String> {
        let mut files = cargo_files(
            "[workspace]\nmembers = [\"a\", \"b\"]\n\n\
             [workspace.dependencies]\nserde = \"1.0.190\"\n",
        );
        files.insert(
            "a/Cargo.toml".to_string(),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
             serde.workspace = true\n"
                .to_string(),
        );
        files.insert("b/Cargo.toml".to_string(), b_manifest.to_string());
        files
    }

    /// Bug F: only the root's `[workspace.dependencies]` was pinned; member
    /// `b`'s own `serde = "1.0.190"` stayed on crates.io, so `--locked`
    /// failed against the repointed lock while the dep was reported
    /// redirected. Every member manifest the caller supplies is planned in
    /// the same transaction; inheritors are satisfied by the root's pin.
    #[test]
    fn cargo_workspace_member_direct_declaration_is_pinned() {
        let files = cargo_workspace_files(
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let pin = format!(
            "serde = {{ version = \"1.0.190\", registry = \"{}\" }}",
            cargo_reg()
        );
        assert!(r.files["Cargo.toml"].contains(&pin), "{:?}", r.files);
        assert!(r.files["b/Cargo.toml"].contains(&pin), "{:?}", r.files);
        assert!(
            !r.files.contains_key("a/Cargo.toml"),
            "the inheriting member needs no edit"
        );
        assert!(r
            .edits
            .iter()
            .any(|e| e.path == "b/Cargo.toml" && e.kind == "redirect_cargo_toml_dep"));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// A member that cannot be pinned (a path dependency here) refuses the
    /// WHOLE dep: the root stays untouched too.
    #[test]
    fn cargo_workspace_member_refusal_refuses_every_manifest() {
        let files = cargo_workspace_files(
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
             serde = { path = \"../serde\" }\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.files);
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
        assert!(
            r.warnings[0].detail.contains("b/Cargo.toml"),
            "{:?}",
            r.warnings
        );
    }

    /// Only a member declares the crate (the root has no workspace entry):
    /// that member is pinned, and a member inheriting an entry the root
    /// does not have refuses.
    #[test]
    fn cargo_member_only_declaration_and_unsatisfied_inheritor() {
        let mut files = cargo_files("[workspace]\nmembers = [\"b\"]\n");
        files.insert(
            "b/Cargo.toml".to_string(),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert_eq!(
            r.files.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![".cargo/config.toml", "Cargo.lock", "b/Cargo.toml"]
        );
        files.insert(
            "b/Cargo.toml".to_string(),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
             serde = { workspace = true }\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty(), "{:?}", r.files);
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
    }

    /// Manifest keys outside a plain repo-relative `<dir>/Cargo.toml` are
    /// never treated as members.
    #[test]
    fn cargo_member_manifest_keys() {
        for ok in ["a/Cargo.toml", "crates/x-y/Cargo.toml"] {
            assert!(is_cargo_member_manifest_key(ok), "{ok}");
        }
        for bad in [
            "Cargo.toml",
            "/abs/Cargo.toml",
            "../up/Cargo.toml",
            "a/../b/Cargo.toml",
            "./a/Cargo.toml",
            ".socket/vendor/cargo/x/Cargo.toml",
            "target/generated/Cargo.toml",
            "crates/a/target/gen/Cargo.toml",
            "a//Cargo.toml",
            "a/Cargo.toml.orig",
        ] {
            assert!(!is_cargo_member_manifest_key(bad), "{bad}");
        }
    }

    /// Bug K: CRLF manifests and locks (Windows checkouts) were refused —
    /// every planner matched LF text only. A CRLF-only file is now planned
    /// as LF and written back CRLF, recorded fragments included, and a
    /// re-run over the output is a silent no-op.
    #[test]
    fn cargo_crlf_files_are_rewritten_with_crlf_kept() {
        let lf = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        let crlf: BTreeMap<String, String> = lf
            .iter()
            .map(|(k, v)| (k.clone(), v.replace('\n', "\r\n")))
            .collect();
        let want = rewrite_registry_redirect(&lf, &[cargo_sparse_override()]);
        let got = rewrite_registry_redirect(&crlf, &[cargo_sparse_override()]);
        assert!(got.warnings.is_empty(), "{:?}", got.warnings);
        assert!(got.confirmed_cargo_uuids.contains(CARGO_UUID));
        for key in ["Cargo.toml", "Cargo.lock"] {
            assert_eq!(
                got.files[key],
                want.files[key].replace('\n', "\r\n"),
                "{key}"
            );
        }
        assert_eq!(
            got.files[".cargo/config.toml"], want.files[".cargo/config.toml"],
            "a created config stays LF"
        );
        let lock_edit = got
            .edits
            .iter()
            .find(|e| e.kind == "redirect_cargo_lock_entry")
            .unwrap();
        let (Some(Value::String(orig)), Some(Value::String(new))) =
            (&lock_edit.original, &lock_edit.new)
        else {
            panic!("lock edit fragments");
        };
        assert!(crlf["Cargo.lock"].contains(orig.as_str()));
        assert!(got.files["Cargo.lock"].contains(new.as_str()));

        let mut again = crlf.clone();
        again.extend(got.files.clone());
        let rerun = rewrite_registry_redirect(&again, &[cargo_sparse_override()]);
        assert!(
            rerun.files.is_empty() && rerun.edits.is_empty() && rerun.warnings.is_empty(),
            "{:?} {:?}",
            rerun.files.keys(),
            rerun.warnings
        );
    }

    /// Mixed line endings are not normalized: the LF grammar still refuses
    /// what it cannot match, writing nothing.
    #[test]
    fn cargo_mixed_line_endings_still_refuse() {
        let mut files = cargo_files(
            "[package]\r\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\r\nserde = \"1.0.190\"\r\n",
        );
        files.insert(
            "Cargo.lock".into(),
            files["Cargo.lock"].replace('\n', "\r\n"),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.files);
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
    }

    /// Bug J (kept a refusal): a crate only reached transitively cannot be
    /// pinned by a manifest `registry` key. Nothing is written or
    /// confirmed, and the warning says it is transitive-only, unpatched, and
    /// which mode can patch it.
    #[test]
    fn cargo_transitive_only_crate_is_refused_loudly() {
        let mut files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nother = \"1\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.files);
        assert!(r.confirmed_cargo_uuids.is_empty());
        assert_eq!(warning_codes(&r), vec!["redirect_cargo_toml_dep_not_found"]);
        let detail = &r.warnings[0].detail;
        assert!(
            detail.contains("transitive-only")
                && detail.contains("NOT redirected")
                && detail.contains("--mode vendored"),
            "{detail}"
        );
        // Not in the lock either: the plain not-declared wording.
        files.remove("Cargo.lock");
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.warnings[0]
                .detail
                .starts_with("no [dependencies] entry for serde"),
            "{:?}",
            r.warnings
        );
    }

    /// A cargo dep whose override kind is not `cargo-sparse` warns (the TS
    /// twin's behavior) instead of vanishing silently.
    #[test]
    fn cargo_lock_multi_source_twins_refuse_ambiguous_and_skip_the_dep() {
        // Two [[package]] blocks for one name@version from different sources
        // (a crates.io copy beside a git copy), neither at the socket index:
        // which twin is ours cannot be decided, so the dep is skipped
        // transactionally with its own warning — repointing the first hit
        // would desync the lock's qualified package ids.
        let manifest =
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n";
        let lock = format!(
            "version = 3\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
             source = \"git+https://github.com/serde-rs/serde?rev=abc#abc\"\n",
            "1".repeat(64)
        );
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock);
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "ambiguous twins must write NOTHING: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_lock_pkg_ambiguous"],
            "{:?}",
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    #[test]
    fn cargo_lock_rerun_beside_a_crates_io_twin_is_a_noop() {
        // After a redirect, a transitive crates.io copy of the crate can
        // resolve beside the socket-registry copy — and cargo sorts the
        // crates.io block FIRST. A re-run must recognize the socket copy as
        // its own (already redirected: no edit, no warning) instead of
        // repointing the crates.io twin into a duplicate block.
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
        );
        let overrides = vec![cargo_sparse_override()];
        let first = rewrite_registry_redirect(&files, &overrides);
        let redirected_lock = first.files.get("Cargo.lock").expect("lock redirected");
        let twin = format!(
            "[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n\n",
            "2".repeat(64)
        );
        let with_twin = redirected_lock.replacen(
            "[[package]]\nname = \"serde\"",
            &format!("{twin}[[package]]\nname = \"serde\""),
            1,
        );
        assert_eq!(
            with_twin.matches("name = \"serde\"").count(),
            2,
            "{with_twin}"
        );
        let mut again = files.clone();
        for (name, content) in &first.files {
            again.insert(name.clone(), content.clone());
        }
        again.insert("Cargo.lock".to_string(), with_twin);
        let second = rewrite_registry_redirect(&again, &overrides);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "the socket twin is already redirected: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
        assert!(second.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

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
            warning
                .detail
                .contains("socket-patch remove pkg:gem/rails@7.0.0")
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
            "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
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

    /// REGRESSION (bundler 4.0.19+): the patch-registry `GEM` section must
    /// land where bundler itself renders it — rubygems sections sorted by
    /// remote (`SourceList#lock_rubygems_sources`) — because a frozen install
    /// re-renders the lock and, since rubygems#9750, FAILS on any difference.
    /// Appending after the upstream section produced a lock bundler 4.0.21
    /// refuses under `BUNDLE_FROZEN=true` whenever the patch registry sorts
    /// first (`https://patch.socket.dev/` < `https://rubygems.org/`), i.e. on
    /// every production pair. Pinned both ways, with a third section present.
    #[test]
    fn gem_converged_section_is_inserted_in_bundler_source_order() {
        for (upstream, other, want) in [
            // Patch registry sorts before both: first.
            (
                "https://rubygems.org/",
                "https://zz.example/",
                ["patch", "up", "other"],
            ),
            // Between the two.
            (
                "https://rubygems.org/",
                "https://aa.example/",
                ["other", "patch", "up"],
            ),
            // After both: appended after the last GEM section.
            (
                "https://aa.example/",
                "https://ab.example/",
                ["up", "other", "patch"],
            ),
        ] {
            let (first, second) = if upstream < other {
                (upstream, other)
            } else {
                (other, upstream)
            };
            let section = |url: &str| {
                if url == upstream {
                    format!("GEM\n  remote: {url}\n  specs:\n    rails (7.0.0)\n\n")
                } else {
                    format!("GEM\n  remote: {url}\n  specs:\n    puma (6.0.0)\n\n")
                }
            };
            let lock = format!(
                "{}{}PLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n  rails (= 7.0.0)\n\n\
                 CHECKSUMS\n  puma (6.0.0) sha256={}\n  rails (7.0.0) sha256={}\n\n\
                 BUNDLED WITH\n   4.0.21\n",
                section(first),
                section(second),
                "1".repeat(64),
                "2".repeat(64)
            );
            let mut files = BTreeMap::new();
            files.insert(
                "Gemfile".to_string(),
                format!(
                    "source \"{upstream}\"\n\ngem \"rails\", \"7.0.0\"\n\
                     source \"{other}\" do\n  gem \"puma\"\nend\n"
                ),
            );
            files.insert("Gemfile.lock".to_string(), lock);
            let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
            let out = r.files.get("Gemfile.lock").expect("lock rewritten");
            let remotes: Vec<&str> = out
                .lines()
                .filter_map(|l| l.strip_prefix("  remote: "))
                .map(|url| match url {
                    u if u == upstream => "up",
                    u if u == other => "other",
                    u if u.starts_with("https://patch.test/") => "patch",
                    u => panic!("unexpected remote {u}"),
                })
                .collect();
            assert_eq!(remotes, want, "{upstream} / {other}:\n{out}");
            let urls: Vec<&str> = out
                .lines()
                .filter_map(|l| l.strip_prefix("  remote: "))
                .collect();
            let mut sorted = urls.clone();
            sorted.sort_unstable();
            assert_eq!(
                urls, sorted,
                "bundler's sort_by(&:identifier) order:\n{out}"
            );
            assert!(
                out.contains("GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n\n"),
                "{out}"
            );
        }
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
            "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n      rack (>= 2)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n\n\
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
            "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
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

    /// REGRESSION (npm 6): a lockfileVersion 1 lock is only ever written by
    /// npm <= 6, which ignores `resolved` for registry deps (verified against
    /// real npm 6.14.18) — so its installs of the redirected lock fail
    /// EINTEGRITY. The rewrite still happens (npm >= 7 installs it), but the
    /// run must say so; a v2/v3 lock (npm >= 7) gets no such caveat.
    #[test]
    fn npm_v1_lock_redirect_warns_about_npm_6_clients() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );
        let v1 = r#"{
  "name": "app",
  "version": "0.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#;
        let mut files = BTreeMap::new();
        files.insert("package-lock.json".to_string(), v1.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        let out = r.files.get("package-lock.json").expect("v1 lock rewritten");
        assert!(
            out.contains("http://patch.test/left-pad-1.3.0.tgz"),
            "{out}"
        );
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_npm_legacy_client")
            .unwrap_or_else(|| panic!("missing legacy-client caveat: {:?}", r.warnings));
        assert!(
            w.detail.contains("npm <= 6") && w.detail.contains("EINTEGRITY"),
            "{}",
            w.detail
        );

        let v3 = v1.replace("\"lockfileVersion\": 1", "\"lockfileVersion\": 3");
        let mut files = BTreeMap::new();
        files.insert("package-lock.json".to_string(), v3);
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(r.files.contains_key("package-lock.json"));
        assert!(
            !warning_codes(&r).contains(&"redirect_npm_legacy_client"),
            "{:?}",
            r.warnings
        );
    }

    /// npm 12 removed `npm shrinkwrap` and now auto-creates a
    /// `package-lock.json` beside any committed `npm-shrinkwrap.json` on first
    /// install — and reifies the install from `package-lock.json`. So a
    /// shrinkwrap repo's DEFAULT state under npm 12 is BOTH locks present,
    /// byte-divergent but pinning the same versions. The old rewriter rewrote
    /// only the FIRST present lock (`npm-shrinkwrap.json`) and left
    /// `package-lock.json` — the file npm actually installs from — pristine,
    /// with no warning: a silent FALSE SUCCESS. EVERY present npm lock must be
    /// rewritten so a fresh install/ci from EITHER is redirected.
    #[test]
    fn npm_dual_lock_shrinkwrap_and_package_lock_both_rewritten() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );
        // Same pinned dep in both locks, but byte-divergent (shrinkwrap carries
        // the extra top-level `version`/`requires` fields npm 12 writes) —
        // exactly the npm 12 shrinkwrap + auto-package-lock pair.
        let shrinkwrap = r#"{
  "name": "app",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "version": "0.0.0" },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#;
        let package_lock = r#"{
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
"#;
        let mut files = BTreeMap::new();
        files.insert("npm-shrinkwrap.json".to_string(), shrinkwrap.to_string());
        files.insert("package-lock.json".to_string(), package_lock.to_string());

        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));

        for lock in ["npm-shrinkwrap.json", "package-lock.json"] {
            let out = r.files.get(lock).unwrap_or_else(|| {
                panic!(
                    "{lock} must be rewritten in the dual-lock case; rewritten files={:?}",
                    r.files.keys().collect::<Vec<_>>()
                )
            });
            let v: Value = serde_json::from_str(out).expect("rewritten lock stays valid JSON");
            assert_eq!(
                v["packages"]["node_modules/left-pad"]["resolved"],
                "http://patch.test/left-pad-1.3.0.tgz",
                "{lock} left-pad must point at the hosted URL: {out}"
            );
            assert_eq!(
                v["packages"]["node_modules/left-pad"]["integrity"], "sha512-PATCHED==",
                "{lock} left-pad must carry the patched integrity: {out}"
            );
        }
        // Both locks pin the dep, so nothing is left unmatched.
        assert!(
            !warning_codes(&r).contains(&"redirect_npm_entry_not_found"),
            "both locks pin the dep — no not-found warning expected: {:?}",
            r.warnings
        );

        // Idempotent: re-running over the rewritten pair must change nothing.
        let mut files2 = files.clone();
        for lock in ["npm-shrinkwrap.json", "package-lock.json"] {
            files2.insert(
                lock.to_string(),
                r.files.get(lock).expect("rewritten lock present").clone(),
            );
        }
        let second = rewrite_registry_redirect(&files2, std::slice::from_ref(&ovr));
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "dual-lock re-run must be a no-op: files={:?} edits={:?}",
            second.files.keys().collect::<Vec<_>>(),
            second.edits
        );
    }

    /// A shrinkwrap-ONLY project (the npm <= 6 world, where `npm shrinkwrap`
    /// wrote the sole lock and no `package-lock.json` was auto-created) must
    /// still be rewritten with zero warnings — the dual-lock fix must not
    /// perturb the single-lock path.
    #[test]
    fn npm_shrinkwrap_only_still_rewritten_no_warnings() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );
        let mut files = BTreeMap::new();
        files.insert(
            "npm-shrinkwrap.json".to_string(),
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
            !r.files.contains_key("package-lock.json"),
            "no package-lock.json exists, so none may be emitted: {:?}",
            r.files.keys().collect::<Vec<_>>()
        );
        let out = r
            .files
            .get("npm-shrinkwrap.json")
            .expect("the sole shrinkwrap must be rewritten");
        let v: Value = serde_json::from_str(out).expect("valid JSON");
        assert_eq!(
            v["packages"]["node_modules/left-pad"]["resolved"],
            "http://patch.test/left-pad-1.3.0.tgz"
        );
        assert_eq!(
            warning_codes(&r),
            Vec::<&str>::new(),
            "a clean shrinkwrap-only success must emit NO warnings: {:?}",
            r.warnings
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

    /// composer writes `source` right before `dist`, and composer 1 / 2.2
    /// LTS fall back to it ("Now trying to download from source") whenever
    /// the hosted dist fails its checksum or cannot be fetched — silently
    /// installing the pristine upstream commit. The redirect must drop the
    /// target's source (only the target's), record ONE fragment edit
    /// spanning both blocks, and that fragment's inverse must restore the
    /// original lock byte-for-byte. A re-run over the output is a no-op.
    #[test]
    fn composer_redirect_drops_the_target_source_fallback_and_reverts_it() {
        let target_source = "
            \"source\": {
                \"type\": \"git\",
                \"url\": \"https://github.com/acme/target.git\",
                \"reference\": \"cafe\"
            },";
        let lock = composer_lock_with(&format!(
            "{target_source}
            \"dist\": {{
                \"type\": \"zip\",
                \"url\": \"https://api.github.com/repos/acme/target/zipball/cafe\",
                \"reference\": \"cafe\",
                \"shasum\": \"\"
            }}"
        ))
        .replace(
            "\"version\": \"2.0.0\",\n            \"dist\": {",
            "\"version\": \"2.0.0\",\n            \"source\": {\n                \"type\": \"git\",\n                \"url\": \"https://github.com/innocent/bystander.git\",\n                \"reference\": \"beef\"\n            },\n            \"dist\": {",
        );
        let r = composer_result(&lock, "1.0.0");
        assert!(r.warnings.is_empty(), "no warnings: {:?}", r.warnings);
        let out = r
            .files
            .get("composer.lock")
            .expect("the dist is redirected");
        let doc: Value = serde_json::from_str(out).expect("valid JSON");
        let target = &doc["packages"][0];
        assert_eq!(target["name"], "acme/target");
        assert!(
            target.get("source").is_none(),
            "the target's git source must be dropped so a failed hosted download cannot \
             fall back to the pristine upstream: {target}"
        );
        assert_eq!(target["dist"]["url"], COMPOSER_ARTIFACT_URL);
        assert_eq!(target["dist"]["shasum"], COMPOSER_SHA1);
        assert_eq!(
            doc["packages"][1]["source"]["url"], "https://github.com/innocent/bystander.git",
            "a bystander's source is untouched"
        );

        // One edit whose fragments invert the whole change (the ledger's
        // ReplaceFragment revert: `new` → `original`).
        assert_eq!(r.edits.len(), 1, "{:?}", r.edits);
        let edit = &r.edits[0];
        assert_eq!(edit.kind, "redirect_composer_dist");
        let original = edit.original.as_ref().and_then(Value::as_str).unwrap();
        let new = edit.new.as_ref().and_then(Value::as_str).unwrap();
        assert!(original.starts_with("\"source\": {") && original.contains("acme/target.git"));
        assert!(new.starts_with("\"dist\": {") && !new.contains("\"source\""));
        assert_eq!(out.matches(new).count(), 1, "the fragment is unambiguous");
        assert_eq!(
            out.replacen(new, original, 1),
            lock,
            "revert restores the lock"
        );

        // Re-run over the redirected lock: nothing left to change.
        let mut again = BTreeMap::new();
        again.insert("composer.lock".to_string(), out.clone());
        let second = rewrite_registry_redirect(&again, &[composer_override("1.0.0")]);
        assert!(
            second.files.is_empty() && second.edits.is_empty() && second.warnings.is_empty(),
            "re-run must be a no-op: {:?} {:?}",
            second.edits,
            second.warnings
        );
    }

    /// A hand-ordered entry whose `source` does NOT directly precede its
    /// `dist` keeps the source (the fragment edit cannot span it losslessly)
    /// and says so; the dist is still redirected and pinned.
    #[test]
    fn composer_non_adjacent_source_is_kept_with_a_warning() {
        let lock = composer_lock_with(
            "
            \"dist\": {
                \"type\": \"zip\",
                \"url\": \"https://api.github.com/repos/acme/target/zipball/cafe\",
                \"reference\": \"cafe\",
                \"shasum\": \"\"
            },
            \"source\": {
                \"type\": \"git\",
                \"url\": \"https://github.com/acme/target.git\",
                \"reference\": \"cafe\"
            }",
        );
        let r = composer_result(&lock, "1.0.0");
        assert_eq!(warning_codes(&r), vec!["redirect_composer_source_kept"]);
        let out = r
            .files
            .get("composer.lock")
            .expect("the dist is redirected");
        let doc: Value = serde_json::from_str(out).expect("valid JSON");
        assert_eq!(doc["packages"][0]["dist"]["url"], COMPOSER_ARTIFACT_URL);
        assert!(doc["packages"][0].get("source").is_some());
        let edit = &r.edits[0];
        let (original, new) = (
            edit.original.as_ref().and_then(Value::as_str).unwrap(),
            edit.new.as_ref().and_then(Value::as_str).unwrap(),
        );
        assert_eq!(
            out.replacen(new, original, 1),
            lock,
            "revert restores the lock"
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

    #[test]
    fn pnpm_v6_nested_paren_peer_key_rewrites_every_instance() {
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
        let rewritten = &r.files["pnpm-lock.yaml"];
        assert_eq!(rewritten.matches("tarball: http://patch.test/").count(), 2);
        assert!(rewritten.contains("/left-pad@1.3.0(react@18.2.0(scheduler@0.23.2)):"));
        assert_eq!(r.edits.len(), 2);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// The residual gate is SET-WIDE: a Rush-style repo whose root v9 lock
    /// splices fully while a nested lock resolves the same dep only through
    /// an unbalanced peer key must refuse the dep in EVERY lock. Committing the
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

  /left-pad@1.3.0(react@18.2.0(scheduler@0.23.2):
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

    /// The same boundaries, judged by the PRODUCTION inline residual gate
    /// (`rewrite_pnpm_lock` over indexed hits), not the reference probe: an
    /// instance already on the hosted artifact, a longer version sharing
    /// the prefix, a different quoted scoped package and resolution-less
    /// `snapshots:` keys never count as residuals, v6 nested-paren and v5
    /// `_` instances are repointed rather than refused, and the one
    /// instance whose suffix the grammar cannot parse is the only key the
    /// refusal names.
    #[test]
    fn pnpm_residual_gate_respects_version_and_section_boundaries() {
        let url = "http://patch.test/left-pad-1.3.0.tgz";
        let overrides = vec![npm_override("left-pad", "1.3.0", url, "sha512-PATCHED==")];
        let residual_warnings = |r: &RewriteResult| -> Vec<String> {
            r.warnings
                .iter()
                .filter(|w| w.code == "redirect_pnpm_unsupported_lock_key")
                .map(|w| w.detail.clone())
                .collect()
        };
        let boundaries = format!(
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
        let files = BTreeMap::from([("pnpm-lock.yaml".to_string(), boundaries.clone())]);
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            residual_warnings(&r).is_empty() && r.refused_pnpm_uuids.is_empty(),
            "rewritten instances, other versions/packages, and resolution-less \
             snapshots keys must not count: {:?}",
            r.warnings
        );
        let out = r.files.get("pnpm-lock.yaml").unwrap_or(&boundaries);
        assert!(
            out.contains("sha512-OTHERVERSION==") && out.contains("sha512-OTHERPACKAGE=="),
            "{out}"
        );

        for lock in [
            "lockfileVersion: '6.0'

packages:

  /left-pad@1.3.0(react@18.2.0(scheduler@0.23.2)):
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
",
            "lockfileVersion: 5.4

packages:

  /left-pad/1.3.0_react@18.2.0:
    resolution: {integrity: sha512-UPSTREAM==}
    dev: false
",
        ] {
            let files = BTreeMap::from([("pnpm-lock.yaml".to_string(), lock.to_string())]);
            let r = rewrite_registry_redirect(&files, &overrides);
            assert!(
                residual_warnings(&r).is_empty() && r.refused_pnpm_uuids.is_empty(),
                "a spliceable suffixed instance is repointed, not refused: {:?}",
                r.warnings
            );
            assert!(
                r.files["pnpm-lock.yaml"].contains(url) && r.edits.len() == 1,
                "{:?}",
                r.edits
            );
        }

        let with_unparseable = boundaries.replace(
            "\nsnapshots:",
            "  left-pad@1.3.0(react@18.2.0:
    resolution: {integrity: sha512-UPSTREAM==}

snapshots:",
        );
        assert_ne!(with_unparseable, boundaries);
        let files = BTreeMap::from([("pnpm-lock.yaml".to_string(), with_unparseable)]);
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.edits);
        assert_eq!(
            r.refused_pnpm_uuids.len(),
            1,
            "the dep is refused: {:?}",
            r.warnings
        );
        let details = residual_warnings(&r);
        assert_eq!(details.len(), 1, "{details:?}");
        assert!(
            details[0].contains("cannot repoint: left-pad@1.3.0(react@18.2.0 in pnpm-lock.yaml;"),
            "only the unparseable instance is named: {}",
            details[0]
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

    /// Legacy shrinkwrap files are rewritten; a marker without a lock still
    /// produces a pnpm-specific missing-lock diagnostic.
    #[test]
    fn no_lockfile_warning_is_pnpm_flavored_when_pnpm_markers_present() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );

        // shrinkwrap.yaml present (with or without node_modules — a fresh
        // clone has only the committed lock): rewrite its block resolution.
        for with_marker in [true, false] {
            let mut files = BTreeMap::new();
            files.insert(
                "shrinkwrap.yaml".to_string(),
                "dependencies:\n  left-pad: 1.3.0\npackages:\n  /left-pad/1.3.0:\n    \
                 dev: false\n    resolution:\n      integrity: sha512-UPSTREAM==\n\
                 shrinkwrapMinorVersion: 6\nshrinkwrapVersion: 3\n"
                    .to_string(),
            );
            if with_marker {
                files.insert(
                    "node_modules/.modules.yaml".to_string(),
                    "packageManager: pnpm@2.17.0\n".to_string(),
                );
            }
            let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
            assert!(r.files["shrinkwrap.yaml"]
                .contains("tarball: http://patch.test/left-pad-1.3.0.tgz"));
            assert!(r.warnings.is_empty(), "{:?}", r.warnings);
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

    /// A berry lock the way real yarn 4 writes it — header, `__metadata`,
    /// a decoy entry, the target, the root workspace — for the line-ending
    /// cells below.
    fn berry_lock_two_entries() -> String {
        format!(
            "# This file is generated by running \"yarn install\" inside your project.\n\
             # Manual changes might be lost - proceed with caution!\n\n\
             __metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
             \"aaa-decoy@npm:^1.0.0\":\n  version: 1.0.0\n  \
             resolution: \"aaa-decoy@npm:1.0.0\"\n  checksum: 10c0/{}\n  \
             languageName: node\n  linkType: hard\n\n\
             \"app@workspace:.\":\n  version: 0.0.0-use.local\n  \
             resolution: \"app@workspace:.\"\n  dependencies:\n    \
             aaa-decoy: \"npm:^1.0.0\"\n    left-pad: \"npm:^1.3.0\"\n  \
             languageName: unknown\n  linkType: soft\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  \
             resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  \
             languageName: node\n  linkType: hard\n",
            "1".repeat(128),
            "3".repeat(128)
        )
    }

    /// A CRLF berry lock — what yarn itself writes on Windows (a new
    /// lockfile gets `os.EOL`) and what a `core.autocrlf` checkout hands
    /// any OS — is rewritten in place: exactly the target entry changes,
    /// every line keeps its CRLF, a leading BOM survives, and the ledger
    /// records the ON-DISK (CRLF) fragments, so the revert's byte-exact
    /// `replacen(new, original)` restores the input and a re-run is a no-op.
    #[test]
    fn berry_crlf_and_bom_locks_round_trip_byte_exact() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let url = "http://p.test/patch/npm/left-pad/1.3.0/t/u/left-pad-1.3.0.tgz";
        let ovr = berry_override("left-pad", "1.3.0", url, &checksum);
        let lf = berry_lock_two_entries();
        let mut lf_files = BTreeMap::new();
        lf_files.insert("yarn.lock".to_string(), lf.clone());
        let mut lf_result = RewriteResult::default();
        rewrite_yarn_berry(&lf_files, std::slice::from_ref(&ovr), &mut lf_result);
        let lf_out = lf_result.files["yarn.lock"].clone();

        for (label, bom, crlf) in [
            ("crlf", "", true),
            ("bom+lf", "\u{feff}", false),
            ("bom+crlf", "\u{feff}", true),
        ] {
            let respell = |s: &str| {
                let s = if crlf {
                    s.replace('\n', "\r\n")
                } else {
                    s.to_string()
                };
                format!("{bom}{s}")
            };
            let input = respell(&lf);
            let mut files = BTreeMap::new();
            files.insert("yarn.lock".to_string(), input.clone());
            let mut r = RewriteResult::default();
            rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
            assert!(r.warnings.is_empty(), "{label}: {:?}", r.warnings);
            let out = &r.files["yarn.lock"];
            assert_eq!(
                *out,
                respell(&lf_out),
                "{label}: the LF rewrite, in the input's own line ending"
            );
            if crlf {
                assert_eq!(
                    out.matches('\n').count(),
                    out.matches("\r\n").count(),
                    "{label}: every line keeps CRLF"
                );
            }
            assert_eq!(
                out.starts_with('\u{feff}'),
                !bom.is_empty(),
                "{label}: BOM kept"
            );
            assert!(
                out.contains(&crate::utils::uri::encode_uri_component(url)),
                "{label}: {out}"
            );

            // One edit; its fragments are the on-disk bytes of the entry.
            assert_eq!(r.edits.len(), 1, "{label}");
            let edit = &r.edits[0];
            let (orig, new) = (
                edit.original.as_ref().and_then(Value::as_str).unwrap(),
                edit.new.as_ref().and_then(Value::as_str).unwrap(),
            );
            assert_eq!(
                (orig, new),
                (
                    respell(
                        lf_result.edits[0]
                            .original
                            .as_ref()
                            .unwrap()
                            .as_str()
                            .unwrap()
                    )
                    .trim_start_matches('\u{feff}'),
                    respell(lf_result.edits[0].new.as_ref().unwrap().as_str().unwrap())
                        .trim_start_matches('\u{feff}'),
                ),
                "{label}: fragments in the lock's on-disk form"
            );
            assert!(input.contains(orig) && out.contains(new), "{label}");
            assert!(
                orig.contains("\"left-pad@npm:^1.3.0\":") && !orig.contains("aaa-decoy@npm"),
                "{label}: the fragment is the target entry alone: {orig:?}"
            );
            assert_eq!(
                out.replacen(new, orig, 1),
                input,
                "{label}: the ledger revert restores the input byte-exactly"
            );

            // Re-run over the rewritten lock: nothing to do.
            let mut files = BTreeMap::new();
            files.insert("yarn.lock".to_string(), out.clone());
            let mut again = RewriteResult::default();
            rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut again);
            assert!(
                again.files.is_empty() && again.edits.is_empty() && again.warnings.is_empty(),
                "{label}: re-run must be a no-op: {:?}",
                again.warnings
            );
        }
    }

    /// A lock mixing CRLF and LF (or holding a bare CR) has no single line
    /// ending to keep — and yarn itself rejects it under `--immutable`
    /// (YN0028) — so it is refused untouched with a code that names the
    /// line endings, never rewritten half-and-half.
    #[test]
    fn berry_mixed_line_endings_are_refused_untouched() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let crlf = berry_lock_two_entries().replace('\n', "\r\n");
        let first_crlf = crlf.find("\r\n").unwrap();
        let mixed_lf = format!("{}\n{}", &crlf[..first_crlf], &crlf[first_crlf + 2..]);
        let bare_cr = crlf.replacen("proceed with caution!", "proceed\rwith caution!", 1);
        for (label, lock) in [("crlf+lf", mixed_lf), ("bare cr", bare_cr)] {
            let mut files = BTreeMap::new();
            files.insert("yarn.lock".to_string(), lock);
            let mut r = RewriteResult::default();
            rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
            assert!(r.files.is_empty() && r.edits.is_empty(), "{label}");
            assert_eq!(
                warning_codes(&r),
                vec!["redirect_yarn_berry_mixed_line_endings"],
                "{label}"
            );
            let detail = &r.warnings[0].detail;
            assert!(
                detail.contains("CRLF") && detail.contains("yarn install"),
                "{label}: detail names the cause and the remedy: {detail}"
            );
        }
    }

    /// The public takeover preflight is the rewriter's own project gate:
    /// the same codes for a mixed lock, an unsupported cacheKey (CRLF lock
    /// included) and a non-zero compressionLevel; `Ok` for a supported LF /
    /// CRLF / BOM'd berry lock and for any classic lock.
    #[test]
    fn berry_hosted_preflight_mirrors_the_rewriter_gates() {
        let lf = berry_lock_two_entries();
        let crlf = lf.replace('\n', "\r\n");
        for ok in [
            lf.clone(),
            crlf.clone(),
            format!("\u{feff}{crlf}"),
            classic_lock_two_entries().replacen("\n", "\r\n", 1),
        ] {
            assert_eq!(
                preflight_yarn_berry_hosted(&ok, None).map_err(|w| w.code),
                Ok(()),
                "{ok:?}"
            );
        }
        let code = |lock: &str, rc: Option<&str>| {
            preflight_yarn_berry_hosted(lock, rc).map_err(|w| w.code)
        };
        assert_eq!(
            code(&crlf.replacen("\r\n", "\n", 1), None),
            Err("redirect_yarn_berry_mixed_line_endings".to_string())
        );
        assert_eq!(
            code(&crlf.replace("cacheKey: 10c0", "cacheKey: 8"), None),
            Err("redirect_yarn_berry_cache_unsupported".to_string())
        );
        assert_eq!(
            code(&crlf, Some("compressionLevel: 9\r\n")),
            Err("redirect_yarn_berry_cache_unsupported".to_string())
        );
        assert_eq!(code(&crlf, Some("compressionLevel: 0\n")), Ok(()));
    }

    /// The whole-file gates read the NORMALIZED lock: a CRLF lock at an
    /// unsupported cacheKey is refused naming THAT key — never
    /// "`(missing)`", which is what the `\n\n` grammar made of a CRLF
    /// `__metadata` block before line endings were handled.
    #[test]
    fn berry_crlf_lock_cache_key_gate_names_the_real_key() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            berry_lock("8").replace('\n', "\r\n"),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_yarn_berry_cache_unsupported"]
        );
        assert!(
            r.warnings[0].detail.contains("`8`"),
            "the detail names the lock's cacheKey: {}",
            r.warnings[0].detail
        );
    }

    /// A BOM directly in front of `__metadata:` (a header-less lock saved
    /// by a Windows editor) is still berry: the classic rewriter stays out,
    /// the berry one rewrites it and keeps the BOM.
    #[test]
    fn berry_bom_before_metadata_is_still_berry() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let lock = berry_lock("10c0").replace("# header\n\n", "\u{feff}");
        assert!(lock.starts_with("\u{feff}__metadata:"), "{lock:?}");
        assert!(is_berry_lock(&lock));
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock);
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = &r.files["yarn.lock"];
        assert!(out.starts_with("\u{feff}__metadata:"), "{out:?}");
        assert!(out.contains("::__archiveUrl="), "{out}");
    }

    /// CRLF locks preserve their newline style through hosted rewriting.
    #[test]
    fn pnpm_crlf_lock_is_rewritten_without_changing_line_endings() {
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
        let out = &r.files["pnpm-lock.yaml"];
        assert!(out.contains("tarball: http://patch.test/left-pad-1.3.0.tgz"));
        assert!(!out.replace("\r\n", "").contains('\n'));
        assert!(r.warnings.is_empty());
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

    /// Local-mode discovery crawls the WHOLE module cache, so a module another
    /// project downloaded can be granted here. Absent from `require` AND from
    /// go.sum at the patched version, it is not in this module's graph: a
    /// replace for it is inert, and confirming it would attest a patch no
    /// build links.
    #[test]
    fn golang_module_outside_the_graph_is_refused() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire example.com/direct v2.0.0\n".to_string(),
        );
        files.insert(
            "go.sum".to_string(),
            "example.com/direct v2.0.0 h1:DIRECT=\nexample.com/direct v2.0.0/go.mod h1:DIRECTM=\n\
             github.com/foo/bar v1.3.0/go.mod h1:OLDER=\n"
                .to_string(),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty(), "nothing written: {:?}", out.files);
        assert_eq!(
            out.warnings
                .iter()
                .map(|w| w.code.as_str())
                .collect::<Vec<_>>(),
            ["redirect_golang_not_in_module_graph"]
        );
    }

    /// Hosted confirmation keys off `confirmed_golang_uuids`: set when the
    /// redirect lands or is already in place, never for a refused dep.
    #[test]
    fn golang_confirms_only_landed_redirects() {
        let files = golang_files();
        let ovr = golang_override();
        let first = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(first.confirmed_golang_uuids.contains(GO_UUID));
        let mut again = files.clone();
        again.extend(first.files.clone());
        let second = rewrite_registry_redirect(&again, std::slice::from_ref(&ovr));
        assert!(second.files.is_empty());
        assert!(second.confirmed_golang_uuids.contains(GO_UUID));

        let mut conflict = golang_files();
        conflict.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n\nreplace github.com/foo/bar v1.4.2 => ../my-fork\n"
                .to_string(),
        );
        let refused = rewrite_registry_redirect(&conflict, std::slice::from_ref(&ovr));
        assert!(refused.confirmed_golang_uuids.is_empty());
    }

    /// Only `patch.socket.dev/gopatch/<canonical uuid>` is a hosted module;
    /// anything deeper would be written but never recognized as ours again.
    #[test]
    fn golang_module_path_with_extra_segments_refused() {
        let files = golang_files();
        let mut ovr = golang_override();
        ovr.registry_override
            .as_mut()
            .unwrap()
            .identifiers
            .go_module_path = Some(format!("{}/extra", golang_socket_module()));
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty());
        assert_eq!(
            out.warnings[0].code,
            "redirect_golang_untrusted_module_path"
        );
        assert!(out.confirmed_golang_uuids.is_empty());
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

    // ── coverage-audit 2026-09 additions ─────────────────────────────────────
    // Warning/refusal legs and rare-lock-shape branches the golden fixtures
    // deliberately do not pin (they are byte-shared with the TS backend).

    /// A crafted lock entry that carries BOTH `link: true` and a version gets
    /// the specific link diagnosis; the REAL npm-emitted link shape (no
    /// `version` key at all) falls through to the generic not-found today —
    /// pinned here so a future link-aware diagnosis flips this test
    /// deliberately (audit bug anchor #2).
    #[test]
    fn npm_link_entry_versioned_skips_loudly_versionless_is_generic_not_found() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );

        // Versioned link entry → the specific skip diagnosis, nothing written.
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "packages/left-pad": { "version": "1.3.0" },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "packages/left-pad",
      "link": true
    }
  }
}
"#
            .to_string(),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a link entry must never gain resolved/integrity: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_npm_link_entry_skipped"],
            "a matched link entry is SKIPPED, not not-found: {:?}",
            r.warnings
        );
        assert!(
            r.warnings[0].detail.contains("node_modules/left-pad"),
            "the detail names the lock key: {}",
            r.warnings[0].detail
        );

        // Real npm link shape: NO version key — the version gate skips the
        // entry before the link check, so today the diagnosis is the generic
        // not-found. Flip this assertion when the link check learns to match
        // versionless entries.
        let mut files = BTreeMap::new();
        files.insert(
            "package-lock.json".to_string(),
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "packages/left-pad": { "version": "1.3.0" },
    "node_modules/left-pad": {
      "resolved": "packages/left-pad",
      "link": true
    }
  }
}
"#
            .to_string(),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_npm_entry_not_found"],
            "versionless link entries are not diagnosed as links today: {:?}",
            r.warnings
        );
    }

    /// A granted npm dep with NO sha512 must be SAID per lock family — every
    /// npm-family rewriter carries its own missing-integrity leg — and nothing
    /// may be written anywhere.
    #[test]
    fn missing_sha512_warns_once_per_npm_family_lock() {
        let mut ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", "unused");
        ovr.integrity.sha512 = None;

        let mut files = BTreeMap::new();
        files.insert("package-lock.json".to_string(), "{}".to_string());
        files.insert(
            "pnpm-lock.yaml".to_string(),
            "lockfileVersion: '9.0'\n".to_string(),
        );
        files.insert(
            "yarn.lock".to_string(),
            "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://x/lp.tgz\"\n".to_string(),
        );
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file("\"other\": [\"other@1.0.0\", \"\", {}, \"sha512-X==\"]", 1),
        );
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "no integrity, no writes: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_npm_missing_sha512",
                "redirect_pnpm_missing_sha512",
                "redirect_yarn_classic_missing_sha512",
                "redirect_bun_missing_sha512",
            ],
            "one missing-integrity warning per lock family: {:?}",
            r.warnings
        );
    }

    /// The pypi twins of the missing-integrity legs: requirements.txt and
    /// uv.lock each warn for a granted dep with no sha256.
    #[test]
    fn missing_sha256_warns_for_requirements_and_uv() {
        let mut ovr = pypi_override(
            "requests",
            "2.28.1",
            "http://patch.test/requests-2.28.1-py3-none-any.whl",
            "unused",
        );
        ovr.integrity.sha256 = None;

        let mut files = BTreeMap::new();
        files.insert(
            "requirements.txt".to_string(),
            "requests==2.28.1\n".to_string(),
        );
        files.insert("uv.lock".to_string(), "version = 1\n".to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_requirements_missing_sha256",
                "redirect_uv_missing_sha256",
            ],
            "{:?}",
            r.warnings
        );
        assert!(
            r.warnings.iter().all(|w| w.detail.contains("requests")),
            "each detail names the dep: {:?}",
            r.warnings
        );
    }

    /// The registry-config ecosystems' intake gates: a dep with no (or the
    /// wrong kind of) registry override, or with its required integrity field
    /// blank, is skipped with ITS OWN warning code and nothing written.
    #[test]
    fn missing_override_or_integrity_warns_for_registry_ecosystems() {
        let mut cargo_dep = cargo_sparse_override();
        cargo_dep.registry_override = None;

        let mut composer_dep = composer_override("1.0.0");
        composer_dep.integrity.sha1 = None;

        let mut nuget_no_override = nuget_override();
        nuget_no_override.registry_override = None;
        let mut nuget_no_sha = nuget_override();
        nuget_no_sha.integrity.sha512 = None;

        let mut gem_no_override = gem_override("rails", "7.0.0");
        gem_no_override.registry_override = None;
        let mut gem_no_sha = gem_override("rails", "7.0.0");
        gem_no_sha
            .registry_override
            .as_mut()
            .expect("gem_override always carries a registry override")
            .identifiers
            .gem_checksum_sha256 = None;

        let mut maven_dep = maven_override();
        maven_dep.registry_override = None;

        let mut golang_dep = golang_override();
        golang_dep
            .registry_override
            .as_mut()
            .expect("golang_override always carries a registry override")
            .identifiers
            .go_module_path = None;

        let mut files = BTreeMap::new();
        files.insert("composer.lock".to_string(), "{}\n".to_string());
        files.insert(
            "go.mod".to_string(),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n".to_string(),
        );
        let overrides = vec![
            cargo_dep,
            composer_dep,
            nuget_no_override,
            nuget_no_sha,
            gem_no_override,
            gem_no_sha,
            maven_dep,
            golang_dep,
        ];
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "gated deps must write NOTHING: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_cargo_missing_override",
                "redirect_composer_missing_sha1",
                "redirect_nuget_missing_override",
                "redirect_nuget_missing_sha512",
                "redirect_gem_missing_override",
                "redirect_gem_missing_sha256",
                "redirect_maven_missing_override",
                "redirect_golang_missing_module",
            ],
            "{:?}",
            r.warnings
        );
    }

    /// A composer grant against a project with no composer.lock is SAID
    /// (parity with `redirect_npm_no_lockfile`), not silently dropped from the
    /// redirected count.
    #[test]
    fn composer_without_lockfile_warns_and_skips() {
        let mut files = BTreeMap::new();
        files.insert("composer.json".to_string(), "{}\n".to_string());
        let r = rewrite_registry_redirect(&files, &[composer_override("1.0.0")]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_composer_no_lockfile"],
            "{:?}",
            r.warnings
        );
    }

    /// Neither Gemfile nor Gemfile.lock: one warning per run, however many
    /// gem deps were granted (a lock-only project keeps its per-dep
    /// `redirect_gem_lock_without_source` path).
    #[test]
    fn gem_without_gemfile_or_lock_warns_once_and_skips() {
        let files = BTreeMap::new();
        let r = rewrite_registry_redirect(
            &files,
            &[
                gem_override("rails", "7.0.0"),
                gem_override("rack", "3.0.0"),
            ],
        );
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_gem_no_gemfile"],
            "{:?}",
            r.warnings
        );
        assert!(
            r.warnings[0].detail.contains("Gemfile / Gemfile.lock"),
            "{}",
            r.warnings[0].detail
        );
    }

    /// No pom.xml and no Gradle build script: the maven grants are SAID once.
    /// (A Gradle-only project is legitimately pom-less — its snippet IS the
    /// redirect path; see `maven_pom_gradle_manual_snippet`.)
    #[test]
    fn maven_without_pom_or_gradle_warns_once_and_skips() {
        let files = BTreeMap::new();
        let r = rewrite_registry_redirect(&files, &[maven_override(), maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_maven_no_pom"],
            "{:?}",
            r.warnings
        );
    }

    /// A cargo grant against a files map with NO Cargo.toml at all (only a
    /// lock) is skipped fail-closed with the no-manifest flavor of the
    /// not-found warning — the lock alone can never pin the registry.
    #[test]
    fn cargo_lock_only_project_skips_dep_with_no_manifest_warning() {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.lock".to_string(),
            cargo_lock_with("serde", "1.0.190"),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "no manifest, no writes: {:?}",
            r.files.keys()
        );
        assert_eq!(warning_codes(&r), vec!["redirect_cargo_toml_dep_not_found"]);
        assert!(
            r.warnings[0].detail.contains("no Cargo.toml present"),
            "the detail must name the missing manifest, not a missing entry: {}",
            r.warnings[0].detail
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// The TABLE-FORM twins of the inline-table registry matrix: an existing
    /// socket pin is superseded in place, a current pin is recognized as
    /// Already (silent, still confirmed), and a foreign pin refuses the whole
    /// dep. The trailing `[package.metadata]` section bounds the block scan.
    #[test]
    fn cargo_table_form_supersede_already_and_foreign_registry() {
        const OLD_UUID: &str = "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";

        // Supersede: an older socket-patch pin is rewritten in place.
        let manifest = format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies.serde]\nversion = \"1.0.190\"\nregistry = \"socket-patch-{OLD_UUID}\"\n\n\
             [package.metadata]\nnote = \"trailing\"\n"
        );
        let r = rewrite_registry_redirect(&cargo_files(&manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("manifest re-pinned");
        assert!(
            toml.contains(&format!(
                "[dependencies.serde]\nversion = \"1.0.190\"\nregistry = \"{}\"\n\n\
                 [package.metadata]\nnote = \"trailing\"",
                cargo_reg()
            )),
            "the registry line must be superseded IN PLACE: {toml}"
        );
        assert!(!toml.contains(OLD_UUID), "old uuid gone: {toml}");
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
        let toml_edits: Vec<_> = r.edits.iter().filter(|e| e.path == "Cargo.toml").collect();
        assert_eq!(toml_edits.len(), 1, "{:?}", r.edits);
        assert!(
            toml_edits[0]
                .original
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains(OLD_UUID)),
            "the edit's original records the OLD pin: {:?}",
            toml_edits[0]
        );

        // Already at the current registry everywhere: a silent no-op that
        // still confirms the dep.
        let manifest = format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies.serde]\nversion = \"1.0.190\"\nregistry = \"{}\"\n",
            cargo_reg()
        );
        let mut files = cargo_files(&manifest);
        files.insert(
            "Cargo.lock".to_string(),
            cargo_lock_with("serde", "1.0.190")
                .replace(
                    "registry+https://github.com/rust-lang/crates.io-index",
                    &cargo_index_url(),
                )
                .replace(
                    "91f70896d6720bc714a4a57d22fc91f1db634680e65c8efe13323f1fa38d53f5",
                    &"e".repeat(64),
                ),
        );
        files.insert(
            ".cargo/config.toml".to_string(),
            format!(
                "[registries.{}]\nindex = \"{}\"\n",
                cargo_reg(),
                cargo_index_url()
            ),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.files.is_empty() && r.edits.is_empty() && r.warnings.is_empty(),
            "fully-redirected table form must be silent: files={:?} warnings={:?}",
            r.files.keys(),
            r.warnings
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // A foreign registry pin refuses the WHOLE dep.
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies.serde]\nversion = \"1.0.190\"\nregistry = \"corp\"\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
        assert!(
            r.warnings[0].detail.contains("\"corp\""),
            "the refusal names the foreign registry: {}",
            r.warnings[0].detail
        );
        assert!(r.confirmed_cargo_uuids.is_empty());
    }

    /// Table-form path refusal and rename-aware matching: a `path =` block
    /// refuses the dep; a `package = "<crate>"` alias table IS the crate (and
    /// gains the pin) while a key-colliding table renaming ANOTHER crate is
    /// never touched.
    #[test]
    fn cargo_table_form_path_refusal_and_rename_matching() {
        // path dep in table form → refuse whole dep.
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies.serde]\npath = \"../serde\"\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_toml_dep_unrewritable"]
        );
        assert!(
            r.warnings[0].detail.contains("path/git"),
            "{}",
            r.warnings[0].detail
        );
        assert!(r.confirmed_cargo_uuids.is_empty());

        // Rename-aware: the alias table gains the pin, the collision doesn't.
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies.serde]\npackage = \"leftpad\"\nversion = \"1.0.0\"\n\n\
                        [dependencies.iffy]\npackage = \"serde\"\nversion = \"1.0.190\"\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("alias table pinned");
        assert!(
            toml.contains(&format!(
                "[dependencies.iffy]\nregistry = \"{}\"\npackage = \"serde\"\nversion = \"1.0.190\"",
                cargo_reg()
            )),
            "the alias table gains the registry line: {toml}"
        );
        assert!(
            toml.contains("[dependencies.serde]\npackage = \"leftpad\"\nversion = \"1.0.0\""),
            "the key-colliding rename of another crate is untouched: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// Workspace inheritance in BOTH table spellings: a
    /// `[workspace.dependencies.<name>]` table satisfies an inline
    /// `{ workspace = true }` inheritor, and a `[dependencies.<name>]` table
    /// carrying `workspace = true` is satisfied by a `[workspace.dependencies]`
    /// entry — the inheritor line stays byte-identical either way.
    #[test]
    fn cargo_workspace_table_forms_satisfy_inheritors() {
        // [workspace.dependencies.serde] table + inline inheritor.
        let manifest = "[workspace]\nmembers = []\n\n\
                        [workspace.dependencies.serde]\nversion = \"1.0.190\"\n\n\
                        [dependencies]\nserde = { workspace = true }\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("workspace table pinned");
        assert!(
            toml.contains(&format!(
                "[workspace.dependencies.serde]\nregistry = \"{}\"\nversion = \"1.0.190\"",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(
            toml.contains("serde = { workspace = true }"),
            "the inheritor is untouched: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // [dependencies.serde] table with workspace = true + plain workspace
        // entry.
        let manifest = "[workspace]\nmembers = []\n\n\
                        [workspace.dependencies]\nserde = \"1.0.190\"\n\n\
                        [dependencies.serde]\nworkspace = true\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("workspace entry pinned");
        assert!(
            toml.contains(&format!(
                "[workspace.dependencies]\nserde = {{ version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(
            toml.contains("[dependencies.serde]\nworkspace = true"),
            "the table-form inheritor is untouched: {toml}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// Quoted keys and target-specific table entries are first-class rewrite
    /// targets: `[dependencies."serde"]`, `[target.….dependencies.serde]`, and
    /// a quoted plain entry `"serde" = "…"`.
    #[test]
    fn cargo_quoted_keys_and_target_table_entries_are_rewritten() {
        // Quoted table-header key.
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies.\"serde\"]\nversion = \"1.0.190\"\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("quoted-key table pinned");
        assert!(
            toml.contains(&format!(
                "[dependencies.\"serde\"]\nregistry = \"{}\"\nversion = \"1.0.190\"",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // Target-specific TABLE entry (not just the target dep-table).
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [target.'cfg(unix)'.dependencies.serde]\nversion = \"1.0.190\"\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("target table pinned");
        assert!(
            toml.contains(&format!(
                "[target.'cfg(unix)'.dependencies.serde]\nregistry = \"{}\"\nversion = \"1.0.190\"",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // Quoted plain entry key under [dependencies].
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\n\"serde\" = \"1.0.190\"\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("quoted entry pinned");
        assert!(
            toml.contains(&format!(
                "\"serde\" = {{ version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "{toml}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// Every dependency-entry spelling the planner cannot pin refuses the
    /// WHOLE dep — one warning, zero writes, zero confirmations. Guards the
    /// transactional nothing-written contract across the refusal matrix.
    #[test]
    fn cargo_unsupported_spellings_refuse_whole_dep() {
        for entry in [
            // Dotted keys (both the crate's own and an alias renaming it).
            "serde.version = \"1.0.190\"\n",
            "iffy.package = \"serde\"\n",
            // Inline table that does not close on its line.
            "serde = {\n  version = \"1.0.190\" }\n",
            // registry-index beside a would-be registry pin is ambiguous.
            "serde = { version = \"1.0.190\", registry-index = \"sparse+https://index.example/\" }\n",
            // Single-quoted and non-string values.
            "serde = '1.0.190'\n",
            "serde = 13\n",
            // A quoted version with trailing junk the line grammar rejects.
            "serde = \"1.0.190\" trailing junk\n",
        ] {
            let manifest = format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n{entry}"
            );
            let r = rewrite_registry_redirect(&cargo_files(&manifest), &[cargo_sparse_override()]);
            assert!(
                r.files.is_empty() && r.edits.is_empty(),
                "[{entry:?}] must write nothing: files={:?} edits={:?}",
                r.files.keys(),
                r.edits
            );
            assert_eq!(
                warning_codes(&r),
                vec!["redirect_cargo_toml_dep_unrewritable"],
                "[{entry:?}] must refuse with one warning: {:?}",
                r.warnings
            );
            assert!(
                r.confirmed_cargo_uuids.is_empty(),
                "[{entry:?}] must not confirm"
            );
        }
    }

    /// An inline table whose inner already ends with a trailing comma gains
    /// the registry pin without doubling the separator.
    #[test]
    fn cargo_inline_table_trailing_comma_is_not_doubled() {
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = { version = \"1.0.190\", }\n";
        let r = rewrite_registry_redirect(&cargo_files(manifest), &[cargo_sparse_override()]);
        let toml = r.files.get("Cargo.toml").expect("rewritten");
        assert!(
            toml.contains(&format!(
                "serde = {{ version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "single separator between the fields: {toml}"
        );
        assert!(
            !toml.contains(",,") && !toml.contains(", ,"),
            "no doubled comma: {toml}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// Cargo.lock blocks missing their `checksum` (a `[patch]`-resolved or
    /// git-sourced entry) or missing BOTH `source` and `checksum` are rebuilt
    /// with the lines inserted in canonical order, and the neighbor blocks
    /// stay byte-identical.
    /// Cargo.lock v1 (cargo < 1.41; every cargo still reads it and, under
    /// `--locked`, never rewrites it): the checksum lives in `[metadata]`
    /// keyed by the source, and dependents reference the crate by its full
    /// `"name version (source)"` id. REGRESSION: only the entry's `source`
    /// was repointed — the dependent's reference then named a package no
    /// longer in the lock (real cargo discards the lock and re-resolves;
    /// `cargo fetch --locked` fails) and nothing pinned the patched
    /// `.crate` (the v1 entry has no inline checksum, and the insert after a
    /// block-final `source` line never matched). Every fragment now follows
    /// the source, each as its own revertible edit.
    #[test]
    fn cargo_lock_v1_repoints_metadata_checksum_and_full_id_references() {
        const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = \"1.0.190\"\nlog = \"0.4\"\n";
        let cksum = "e".repeat(64);
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"log 0.4.20 ({CRATES_IO})\",\n \"serde 1.0.190 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"{CRATES_IO}\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"{CRATES_IO}\"\n\n\
             [metadata]\n\"checksum log 0.4.20 ({CRATES_IO})\" = \"{a}\"\n\
             \"checksum serde 1.0.190 ({CRATES_IO})\" = \"{b}\"\n",
            a = "a".repeat(64),
            b = "b".repeat(64),
        );
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock.clone());
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let out = r.files.get("Cargo.lock").expect("lock rewritten");
        let idx = cargo_index_url();
        let want = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"log 0.4.20 ({CRATES_IO})\",\n \"serde 1.0.190 ({idx})\",\n]\n\n\
             [[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"{CRATES_IO}\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"{idx}\"\n\n\
             [metadata]\n\"checksum log 0.4.20 ({CRATES_IO})\" = \"{a}\"\n\
             \"checksum serde 1.0.190 ({idx})\" = \"{cksum}\"\n",
            a = "a".repeat(64),
        );
        assert_eq!(out, &want, "v1 lock stays v1, fully repointed");
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // Three fragment edits (entry, metadata line, the dependent's
        // reference), each unique in the rewritten file, and reverting them
        // newest-first (the replay order) restores the original
        // byte-for-byte.
        let edits: Vec<&FileEdit> = r
            .edits
            .iter()
            .filter(|e| {
                e.kind == "redirect_cargo_lock_entry" || e.kind == CARGO_LOCK_REFERENCE_KIND
            })
            .collect();
        assert_eq!(edits.len(), 3, "{edits:#?}");
        assert_eq!(edits[2].kind, CARGO_LOCK_REFERENCE_KIND, "{edits:#?}");
        let mut reverted = out.clone();
        for e in edits.iter().rev() {
            assert_eq!(e.key.as_deref(), Some("serde@1.0.190"));
            let new = e.new.as_ref().and_then(Value::as_str).unwrap();
            let orig = e.original.as_ref().and_then(Value::as_str).unwrap();
            assert_eq!(reverted.matches(new).count(), 1, "unique fragment: {new}");
            reverted = reverted.replacen(new, orig, 1);
        }
        assert_eq!(reverted, lock);

        // Re-run over the redirected lock: nothing to do, no new edits.
        files.insert("Cargo.lock".to_string(), out.clone());
        files.insert(
            "Cargo.toml".to_string(),
            r.files.get("Cargo.toml").expect("manifest pinned").clone(),
        );
        files.insert(
            ".cargo/config.toml".to_string(),
            r.files.get(".cargo/config.toml").expect("config").clone(),
        );
        let again = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            !again.edits.iter().any(|e| e.path == "Cargo.lock"),
            "{:?}",
            again.edits
        );
    }

    /// The OLDEST v1 locks (cargo before the `[root]` removal) record the
    /// root package in a standalone `[root]` table — not in the
    /// `[[package]]` array — and its `dependencies` spell full package ids
    /// the same way. REGRESSION: the reference walk searched `[[package]]`
    /// blocks only, so `[root]` kept naming the crates.io id of a package
    /// the repointed lock no longer contained: `cargo build --locked` fails
    /// and an unlocked build silently discards the lock, while the scan
    /// reports the crate redirected. The vendored twin has handled this
    /// table since `dependency_tables_mut`.
    #[test]
    fn cargo_lock_v1_root_table_references_are_repointed() {
        const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = \"1.0.190\"\nlog = \"0.4\"\n";
        let cksum = "e".repeat(64);
        let lock = format!(
            "[root]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"log 0.4.20 ({CRATES_IO})\",\n \"serde 1.0.190 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"{CRATES_IO}\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"{CRATES_IO}\"\n\n\
             [metadata]\n\"checksum log 0.4.20 ({CRATES_IO})\" = \"{a}\"\n\
             \"checksum serde 1.0.190 ({CRATES_IO})\" = \"{b}\"\n",
            a = "a".repeat(64),
            b = "b".repeat(64),
        );
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock.clone());
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let out = r.files.get("Cargo.lock").expect("lock rewritten");
        let idx = cargo_index_url();
        let want = format!(
            "[root]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"log 0.4.20 ({CRATES_IO})\",\n \"serde 1.0.190 ({idx})\",\n]\n\n\
             [[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"{CRATES_IO}\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"{idx}\"\n\n\
             [metadata]\n\"checksum log 0.4.20 ({CRATES_IO})\" = \"{a}\"\n\
             \"checksum serde 1.0.190 ({idx})\" = \"{cksum}\"\n",
            a = "a".repeat(64),
        );
        assert_eq!(out, &want, "the [root] table is repointed with the rest");
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // The reference edit's inverse puts back EVERY occurrence, so the
        // recorded fragments restore the lock byte for byte whether the id
        // sat in `[root]`, in a package block, or in both.
        let mut reverted = out.clone();
        for e in r
            .edits
            .iter()
            .filter(|e| {
                e.kind == "redirect_cargo_lock_entry" || e.kind == CARGO_LOCK_REFERENCE_KIND
            })
            .rev()
        {
            let new = e.new.as_ref().and_then(Value::as_str).unwrap();
            let orig = e.original.as_ref().and_then(Value::as_str).unwrap();
            reverted = if e.kind == CARGO_LOCK_REFERENCE_KIND {
                reverted.replace(new, orig)
            } else {
                reverted.replacen(new, orig, 1)
            };
        }
        assert_eq!(reverted, lock);
    }

    /// Both places at once: a `[root]` table AND a package block reference
    /// the patched crate by full id, and one reference edit repoints both.
    #[test]
    fn cargo_lock_v1_root_and_package_references_share_one_edit() {
        const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = \"1.0.190\"\n";
        let lock = format!(
            "[root]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"serde 1.0.190 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"helper\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"serde 1.0.190 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"{CRATES_IO}\"\n\n\
             [metadata]\n\"checksum serde 1.0.190 ({CRATES_IO})\" = \"{b}\"\n",
            b = "b".repeat(64),
        );
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock.clone());
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        // `helper` is a source-less path package that no manifest pins, so
        // the dependents refusal owns this shape: nothing is rewritten.
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_cargo_transitive_dependents"]
        );
        assert!(r.files.is_empty(), "{:?}", r.files);
    }

    /// A lock of `app` (source-less, declares serde + `extra`) where `extra`
    /// resolves from `extra_source` and depends on serde via `edge`.
    fn cargo_shared_dependency_files(
        extra: &str,
        extra_source: Option<&str>,
        edge: &str,
    ) -> BTreeMap<String, String> {
        const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
        let source = extra_source.map_or(String::new(), |s| format!("source = \"{s}\"\n"));
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_string(),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                 serde = \"1.0.190\"\n{extra} = {{ path = \"../{extra}\" }}\n"
            ),
        );
        files.insert(
            "Cargo.lock".to_string(),
            format!(
                "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\n \"{extra}\",\n \"serde\",\n]\n\n\
                 [[package]]\nname = \"{extra}\"\nversion = \"0.2.0\"\n{source}\
                 dependencies = [\n \"{edge}\",\n]\n\n\
                 [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"{CRATES_IO}\"\n\
                 checksum = \"{}\"\n",
                "1".repeat(64)
            ),
        );
        files
    }

    /// A crate that is BOTH a direct dependency and a dependency of another
    /// crate (cfg-if, libc, serde…) cannot be hosted-redirected: the pin
    /// reaches only the root's declaration, the other crate keeps resolving
    /// it from crates.io, so the repointed lock fails `--locked` and the
    /// unpatched copy is compiled. REGRESSION: it was pinned, repointed and
    /// confirmed (reported redirected, attested by VEX).
    #[test]
    fn cargo_crate_another_lock_package_depends_on_is_refused() {
        const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
        let git = "git+https://example.test/extra#0123456789abcdef";
        for (source, edge, kind) in [
            (Some(CRATES_IO), "serde".to_string(), "registry"),
            (Some(CRATES_IO), "serde 1.0.190".to_string(), "registry"),
            (
                Some(CRATES_IO),
                format!("serde 1.0.190 ({CRATES_IO})"),
                "registry",
            ),
            (Some(git), "serde".to_string(), "git"),
            // A source-less path package whose manifest was never supplied
            // (outside the project root, or behind a symlink).
            (None, "serde".to_string(), "a path package"),
        ] {
            let files = cargo_shared_dependency_files("extra", source, &edge);
            let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
            assert!(r.files.is_empty(), "{edge}: {:?}", r.files.keys());
            assert!(r.edits.is_empty(), "{edge}: {:?}", r.edits);
            assert!(r.confirmed_cargo_uuids.is_empty(), "{edge}");
            let [w] = r.warnings.as_slice() else {
                panic!("{edge}: one warning: {:?}", r.warnings);
            };
            assert_eq!(w.code, "redirect_cargo_transitive_dependents", "{edge}");
            assert!(
                w.detail.contains(&format!("extra 0.2.0 ({kind}")),
                "{edge}: {}",
                w.detail
            );
            assert!(w.detail.contains("--mode vendored"), "{}", w.detail);
        }
    }

    /// The dependent check is edge-exact: another VERSION of the crate is
    /// not ours, and a source-less dependent whose manifest is planned (and
    /// pinned) resolves through the pin.
    #[test]
    fn cargo_dependents_that_the_pin_reaches_or_another_version_do_not_refuse() {
        let files = cargo_shared_dependency_files(
            "extra",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            "serde 1.0.100",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        let mut files = cargo_shared_dependency_files("extra", None, "serde");
        files.insert(
            "extra/Cargo.toml".to_string(),
            "[package]\nname = \"extra\"\nversion = \"0.2.0\"\n\n[dependencies]\nserde = \"1\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
        assert!(
            r.files["extra/Cargo.toml"].contains(&format!("registry = \"{}\"", cargo_reg())),
            "{:?}",
            r.files
        );
    }

    /// A checksum-less entry whose `source` line ends the block (the
    /// trailing newline sits outside the block region) still gets its pin.
    #[test]
    fn cargo_lock_checksum_is_inserted_after_a_block_final_source_line() {
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = \"1.0.190\"\n";
        let cksum = "e".repeat(64);
        let lock = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock.to_string());
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let out = r.files.get("Cargo.lock").expect("lock rewritten");
        assert_eq!(
            out,
            &format!(
                "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
                 source = \"{}\"\nchecksum = \"{cksum}\"\n",
                cargo_index_url()
            )
        );
    }

    #[test]
    fn cargo_lock_blocks_without_source_or_checksum_lines_are_rebuilt() {
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = \"1.0.190\"\n";
        let cksum = "e".repeat(64);

        // source present, checksum absent → checksum inserted AFTER source.
        let lock = "version = 3\n\n\
                    [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                    dependencies = [\n \"serde_derive\",\n]\n\n\
                    [[package]]\nname = \"serde_derive\"\nversion = \"1.0.190\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                    checksum = \"abcd\"\n";
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock.to_string());
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let out = r.files.get("Cargo.lock").expect("lock rewritten");
        assert!(
            out.contains(&format!(
                "name = \"serde\"\nversion = \"1.0.190\"\nsource = \"{}\"\nchecksum = \"{cksum}\"\ndependencies = [\n \"serde_derive\",\n]",
                cargo_index_url()
            )),
            "checksum inserted right after source: {out}"
        );
        assert!(
            out.contains(
                "name = \"serde_derive\"\nversion = \"1.0.190\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abcd\"\n"
            ),
            "the neighbor block is byte-identical: {out}"
        );
        let lock_edit = r
            .edits
            .iter()
            .find(|e| e.kind == "redirect_cargo_lock_entry")
            .unwrap_or_else(|| panic!("lock edit recorded: {:?}", r.edits));
        let original = lock_edit
            .original
            .as_ref()
            .and_then(Value::as_str)
            .expect("original recorded");
        assert!(
            original.contains("registry+https") && !original.contains("checksum"),
            "original records the checksum-less block: {original}"
        );
        assert!(
            lock_edit
                .new
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains(&format!("checksum = \"{cksum}\""))),
            "new records the inserted checksum: {:?}",
            lock_edit.new
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // NEITHER source nor checksum → source prepended, checksum after it.
        let lock = "version = 3\n\n\
                    [[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\n\
                    [[package]]\nname = \"zzz\"\nversion = \"0.1.0\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                    checksum = \"ffff\"\n";
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".to_string(), manifest.to_string());
        files.insert("Cargo.lock".to_string(), lock.to_string());
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let out = r.files.get("Cargo.lock").expect("lock rewritten");
        assert!(
            out.contains(&format!(
                "name = \"serde\"\nversion = \"1.0.190\"\nsource = \"{}\"\nchecksum = \"{cksum}\"\n\n[[package]]\nname = \"zzz\"",
                cargo_index_url()
            )),
            "source prepended then checksum, neighbor untouched: {out}"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// Managed-config splice edges: a degraded managed block followed by a
    /// user section is regenerated WITHOUT touching that section, and a
    /// pre-existing config lacking a trailing newline gains one before the
    /// appended block.
    #[test]
    fn cargo_config_splice_stops_at_next_section_and_handles_missing_newline() {
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                        [dependencies]\nserde = \"1.0.190\"\n";

        // Degraded block followed by [build]: regenerate only the block.
        let mut files = cargo_files(manifest);
        files.insert(
            ".cargo/config.toml".to_string(),
            format!(
                "[registries.{}]\n# stale, hand-edited\nindex = \"sparse+https://old.example/\"\n\n[build]\njobs = 4\n",
                cargo_reg()
            ),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let cfg = r
            .files
            .get(".cargo/config.toml")
            .expect("degraded block regenerated");
        assert_eq!(
            cfg,
            &format!(
                "[registries.{}]\nindex = \"{}\"\n\n[build]\njobs = 4\n",
                cargo_reg(),
                cargo_index_url()
            ),
            "the splice must stop at the next section header"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));

        // Newline-less user config: exactly one blank line before the block.
        let mut files = cargo_files(manifest);
        files.insert(
            ".cargo/config.toml".to_string(),
            "[net]\nretry = 3".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        let cfg = r.files.get(".cargo/config.toml").expect("block appended");
        assert_eq!(
            cfg,
            &format!(
                "[net]\nretry = 3\n\n[registries.{}]\nindex = \"{}\"\n",
                cargo_reg(),
                cargo_index_url()
            ),
            "a newline must be added before the separator blank line"
        );
        assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
    }

    /// A custom-registry pnpm lock carries extra `resolution:` fields
    /// (`registry:`) beside integrity/tarball — the splice must preserve them
    /// while replacing the integrity and tarball values.
    #[test]
    fn pnpm_resolution_splice_preserves_extra_fields() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );
        let lock = "lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-OLD==, tarball: https://old.example/x.tgz, registry: https://r.example/}\n    dev: false\n";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        let out = r.files.get("pnpm-lock.yaml").expect("lock rewritten");
        assert!(
            out.contains(
                "    resolution: {integrity: sha512-PATCHED==, tarball: http://patch.test/left-pad-1.3.0.tgz, registry: https://r.example/}"
            ),
            "integrity+tarball replaced, registry field preserved: {out}"
        );
        assert!(
            !out.contains("https://old.example/x.tgz") && !out.contains("sha512-OLD=="),
            "old values dropped: {out}"
        );
        assert_eq!(r.edits.len(), 1, "{:?}", r.edits);
        assert_eq!(r.edits[0].key.as_deref(), Some("left-pad@1.3.0"));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// Old yarn v1 emitted blocks WITHOUT an `integrity` line: the rewrite
    /// must insert one right after the repointed `resolved`, leaving the
    /// decoy entry byte-identical.
    #[test]
    fn yarn_classic_block_without_integrity_gains_inserted_line() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let lock = "# yarn lockfile v1\n\n\n\
                    abbrev@^1.0.0:\n  version \"1.1.1\"\n  \
                    resolved \"https://registry.yarnpkg.com/abbrev/-/abbrev-1.1.1.tgz#aaaa\"\n  \
                    integrity sha512-DECOYdecoy==\n\n\
                    left-pad@^1.3.0:\n  version \"1.3.0\"\n  \
                    resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbb\"\n";
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock.to_string());
        let mut r = RewriteResult::default();
        rewrite_yarn_classic(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r.files.get("yarn.lock").expect("lock rewritten");
        assert!(
            out.contains(
                "left-pad@^1.3.0:\n  version \"1.3.0\"\n  \
                 resolved \"http://p.test/lp.tgz\"\n  integrity sha512-PATCHED=="
            ),
            "integrity inserted after the repointed resolved: {out}"
        );
        assert!(
            out.contains(
                "abbrev@^1.0.0:\n  version \"1.1.1\"\n  \
                 resolved \"https://registry.yarnpkg.com/abbrev/-/abbrev-1.1.1.tgz#aaaa\"\n  \
                 integrity sha512-DECOYdecoy=="
            ),
            "the decoy entry stays byte-identical: {out}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.edits.len(), 1);
    }

    /// A berry `__metadata` block with NO cacheKey line must refuse with the
    /// honest `(missing)` detail — not guess a checksum scheme.
    #[test]
    fn yarn_berry_metadata_without_cache_key_refuses_with_missing_detail() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let lock = format!(
            "# header\n\n__metadata:\n  version: 8\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
             checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
            "3".repeat(128)
        );
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock);
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_yarn_berry_cache_unsupported"]
        );
        assert!(
            r.warnings[0].detail.contains("`(missing)`"),
            "the detail must say the cacheKey is missing: {}",
            r.warnings[0].detail
        );
    }

    /// An UNQUOTED single-descriptor berry key (yarn emits unquoted keys for
    /// names that need no YAML quoting) whose entry has no `checksum:` line:
    /// the resolution gains `::__archiveUrl=` and a checksum line is INSERTED
    /// after it.
    #[test]
    fn yarn_berry_unquoted_key_without_checksum_gains_inserted_line() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let lock = "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                    left-pad@npm:^1.3.0:\n  version: 1.3.0\n  \
                    resolution: \"left-pad@npm:1.3.0\"\n  languageName: node\n  linkType: hard\n";
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        let out = r.files.get("yarn.lock").expect("lock rewritten");
        assert!(
            out.contains("\n  resolution: \"left-pad@npm:1.3.0::__archiveUrl="),
            "resolution gains the archiveUrl binding: {out}"
        );
        assert!(
            out.contains(&format!("\"\n  checksum: {checksum}\n  languageName: node")),
            "checksum inserted right after the resolution: {out}"
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.edits.len(), 1);
    }

    /// A bun URL 3-tuple already at the CURRENT artifact URL but with a stale
    /// integrity (a patch republish rotating only the hash) is refreshed in
    /// place.
    #[test]
    fn bun_lock_current_url_tuple_with_stale_integrity_is_refreshed() {
        let new_sha = format!("sha512-{}==", "N".repeat(86));
        let ovr = npm_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &new_sha);
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"left-pad\": [\"left-pad@http://p.test/lp.tgz\", {}, \"sha512-STALE==\"],",
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r.files.get("bun.lock").expect("integrity refreshed");
        assert!(
            out.contains(&format!(
                "\"left-pad\": [\"left-pad@http://p.test/lp.tgz\", {{}}, \"{new_sha}\"]"
            )),
            "the tuple keeps its URL and gains the new integrity: {out}"
        );
        assert!(!out.contains("sha512-STALE=="), "{out}");
        assert_eq!(r.edits.len(), 1);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// Bun 1.1.39–1.3.9 re-save our URL 3-tuple WITHOUT its sha512 on any
    /// later lock re-save (`bun add`, `bun install` after a manifest
    /// change) — verified on real 1.2.23 and 1.3.9; 1.3.10+ keep it. A
    /// 2-tuple at the CURRENT artifact URL is our wiring with its digest
    /// dropped: heal it back to the 3-tuple (the edit records the 2-tuple
    /// as `original`), never warn `redirect_bun_entry_not_found`, and stay
    /// a no-op on the healed lock.
    #[test]
    fn bun_lock_digestless_current_url_tuple_is_healed() {
        let sha = format!("sha512-{}==", "N".repeat(86));
        let url = "https://patch.socket.dev/patch/npm/tok-1111/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz";
        let ovr = npm_override("left-pad", "1.3.0", url, &sha);
        let digestless = format!("\"left-pad\": [\"left-pad@{url}\", {{}}],");
        let healed = format!("\"left-pad\": [\"left-pad@{url}\", {{}}, \"{sha}\"],");

        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), bun_lock_file(&digestless, 1));
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r
            .files
            .get("bun.lock")
            .expect("the digest-less tuple must be healed");
        assert_eq!(
            out,
            &bun_lock_file(&healed, 1),
            "healed back to the canonical 3-tuple, byte-exact"
        );
        assert!(
            r.warnings.is_empty(),
            "a digest-less instance of our own wiring is not `entry_not_found`: {:?}",
            r.warnings
        );
        assert_eq!(r.edits.len(), 1, "{:?}", r.edits);
        assert_eq!(r.edits[0].key.as_deref(), Some("left-pad"));
        assert_eq!(
            r.edits[0].original.as_ref().and_then(Value::as_str),
            Some(format!("    {digestless}").as_str()),
            "the heal records the 2-tuple it found as its original"
        );
        assert_eq!(
            r.edits[0].new.as_ref().and_then(Value::as_str),
            Some(format!("    {healed}").as_str())
        );

        // The healed lock is in sync: no files, no edits, no warnings.
        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), out.clone());
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty() && r.edits.is_empty(), "{:?}", r.edits);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);

        // CRLF lock: the healed line keeps its `\r`, and both ledger
        // fragments carry it (replay matches bytes).
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(&digestless, 1).replace('\n', "\r\n"),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r.files.get("bun.lock").expect("CRLF heal");
        assert_eq!(out, &bun_lock_file(&healed, 1).replace('\n', "\r\n"));
        assert_eq!(
            r.edits[0].original.as_ref().and_then(Value::as_str),
            Some(format!("    {digestless}\r").as_str())
        );
        assert_eq!(
            r.edits[0].new.as_ref().and_then(Value::as_str),
            Some(format!("    {healed}\r").as_str())
        );
    }

    /// The digest-less re-save of a STALE hosted URL (an earlier grant's
    /// token/uuid) is re-pinned to the current URL exactly like its 3-tuple
    /// form; ownership stays origin + `<name>-<version>.tgz` leaf, so a
    /// foreign-origin or other-version 2-tuple is never claimed and a
    /// 2-tuple carrying the bare registry spec (not a shape bun emits for a
    /// registry package) is not rewritten either.
    #[test]
    fn bun_lock_digestless_stale_url_tuple_is_repinned_and_unowned_ones_are_not() {
        let new_sha = format!("sha512-{}==", "N".repeat(86));
        let old_url = "https://patch.socket.dev/patch/npm/oldtoken-1111/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz";
        let new_url = "https://patch.socket.dev/patch/npm/newtoken-2222/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/left-pad-1.3.0.tgz";
        let ovr = npm_override("left-pad", "1.3.0", new_url, &new_sha);

        let stale = format!("\"left-pad\": [\"left-pad@{old_url}\", {{}}],");
        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), bun_lock_file(&stale, 1));
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r
            .files
            .get("bun.lock")
            .expect("stale digest-less URL must be re-pinned");
        assert_eq!(
            out,
            &bun_lock_file(
                &format!("\"left-pad\": [\"left-pad@{new_url}\", {{}}, \"{new_sha}\"],"),
                1
            )
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.edits.len(), 1);
        assert_eq!(
            r.edits[0].original.as_ref().and_then(Value::as_str),
            Some(format!("    {stale}").as_str())
        );

        for unowned in [
            // Foreign origin, same leaf: a user's own URL dep.
            "\"left-pad\": [\"left-pad@https://example.com/mirror/left-pad-1.3.0.tgz\", {}],",
            // Our origin, another version's leaf.
            "\"left-pad\": [\"left-pad@https://patch.socket.dev/patch/npm/oldtoken-1111/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.2.0.tgz\", {}],",
            // Registry spec in a 2-tuple: not bun's registry grammar.
            "\"left-pad\": [\"left-pad@1.3.0\", {}],",
        ] {
            let mut files = BTreeMap::new();
            files.insert("bun.lock".to_string(), bun_lock_file(unowned, 1));
            let mut r = RewriteResult::default();
            rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
            assert!(
                r.files.is_empty() && r.edits.is_empty(),
                "unowned 2-tuple must stay untouched: {unowned}"
            );
            assert_eq!(
                r.warnings.iter().map(|w| w.code.as_str()).collect::<Vec<_>>(),
                vec!["redirect_bun_entry_not_found"],
                "{unowned}"
            );
        }

        // A version-1 workspace lock's 2-tuple workspace entry (the v0
        // grammar hand-carried forward) beside the target: the registry
        // tuple is redirected, the workspace 2-tuple is never touched.
        let ws = "    \"consumer\": [\"consumer@workspace:packages/consumer\", { \"dependencies\": { \"left-pad\": \"1.3.0\" } }],";
        let target = "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"],";
        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), bun_workspace_lock(1, &[ws, target]));
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r.files.get("bun.lock").expect("target rewritten");
        assert!(out.contains(ws), "{out}");
        assert!(out.contains(&format!("\"left-pad@{new_url}\"")), "{out}");
        assert_eq!(r.edits.len(), 1);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// Fail-closed ownership legs of the URL-tuple takeover: an OTHER-name
    /// spec, a non-http `file:` spec, and a foreign-origin URL all survive
    /// byte-identically while the target registry tuple in the same lock is
    /// rewritten.
    #[test]
    fn bun_lock_unowned_url_and_file_tuples_survive_untouched() {
        let sha = format!("sha512-{}==", "A".repeat(86));
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/left-pad-1.3.0.tgz",
            &sha,
        );
        let unowned = [
            "\"other-pkg\": [\"other-pkg@https://user.example/other-1.0.0.tgz\", {}, \"sha512-UUU==\"]",
            "\"nested/left-pad\": [\"left-pad@file:./local\", {}, \"sha512-VVV==\"]",
            "\"mirror/left-pad\": [\"left-pad@https://mirror.example/left-pad-1.3.0.tgz\", {}, \"sha512-WWW==\"]",
        ];
        let entries = format!(
            "\"left-pad\": [\"left-pad@1.3.0\", \"\", {{}}, \"sha512-OLD==\"],\n    {},\n    {},\n    {}",
            unowned[0], unowned[1], unowned[2]
        );
        let mut files = BTreeMap::new();
        files.insert("bun.lock".to_string(), bun_lock_file(&entries, 1));
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        let out = r.files.get("bun.lock").expect("target rewritten");
        assert!(
            out.contains("\"left-pad\": [\"left-pad@http://p.test/left-pad-1.3.0.tgz\", {}, "),
            "the registry tuple is redirected: {out}"
        );
        for entry in unowned {
            assert!(
                out.contains(entry),
                "unowned tuple must stay byte-identical: {entry}\n{out}"
            );
        }
        assert_eq!(r.edits.len(), 1, "only the target is edited: {:?}", r.edits);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// The uv block iteration must find the target mid-file and leave both
    /// neighbor [[package]] blocks byte-identical.
    #[test]
    fn uv_lock_target_mid_file_leaves_neighbors_untouched() {
        let alpha = "[[package]]\nname = \"alpha\"\nversion = \"0.1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/aa/alpha-0.1.0.tar.gz\", hash = \"sha256:1111\" }\n";
        let target = "[[package]]\nname = \"requests\"\nversion = \"2.28.1\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/aa/requests-2.28.1.tar.gz\", hash = \"sha256:aaaa\" }\nwheels = [\n    { url = \"https://files.pythonhosted.org/packages/bb/requests-2.28.1-py3-none-any.whl\", hash = \"sha256:bbbb\" },\n]\n";
        let zulu = "[[package]]\nname = \"zulu\"\nversion = \"9.9.9\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/zz/zulu-9.9.9.tar.gz\", hash = \"sha256:9999\" }\n";
        let lock = format!("version = 1\n\n{alpha}\n{target}\n{zulu}");
        let mut files = BTreeMap::new();
        files.insert("uv.lock".to_string(), lock);
        let url = "http://patch.test/requests-2.28.1-py3-none-any.whl";
        let overrides = vec![pypi_override("requests", "2.28.1", url, &"c".repeat(64))];
        let r = rewrite_registry_redirect(&files, &overrides);
        let out = r.files.get("uv.lock").expect("uv.lock rewritten");
        assert!(out.contains(alpha), "alpha block byte-identical: {out}");
        assert!(out.contains(zulu), "zulu block byte-identical: {out}");
        assert_eq!(
            out.matches(url).count(),
            2,
            "source and wheel repointed: {out}"
        );
        assert_eq!(r.edits.len(), 1, "{:?}", r.edits);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// A matched uv block with no `{ url, hash }` entries (a git/directory
    /// source) and a lock with no block for the dep at all both surface the
    /// entry-not-found warning with nothing rewritten.
    #[test]
    fn uv_lock_git_source_or_absent_block_warns_not_found() {
        let overrides = vec![pypi_override(
            "requests",
            "2.28.1",
            "http://patch.test/requests-2.28.1-py3-none-any.whl",
            &"c".repeat(64),
        )];

        // Name+version match, but the source is git: nothing to repoint.
        let mut files = BTreeMap::new();
        files.insert(
            "uv.lock".to_string(),
            "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.28.1\"\nsource = { git = \"https://github.com/psf/requests?rev=abc\" }\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(warning_codes(&r), vec!["redirect_uv_entry_not_found"]);

        // No block for the dep at all.
        let mut files = BTreeMap::new();
        files.insert(
            "uv.lock".to_string(),
            "version = 1\n\n[[package]]\nname = \"alpha\"\nversion = \"0.1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/aa/alpha-0.1.0.tar.gz\", hash = \"sha256:1111\" }\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &overrides);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(warning_codes(&r), vec!["redirect_uv_entry_not_found"]);
    }

    /// An `authors[]` object whose `name` collides with the package
    /// coordinate is NOT a package entry (it has no `version`): the dep is
    /// reported not-found and nothing is written — the collision must never
    /// elect the surrounding package's dist.
    #[test]
    fn composer_authors_name_collision_is_not_found() {
        let lock = r#"{
    "packages": [
        {
            "name": "other/lib",
            "version": "3.2.1",
            "authors": [
                {
                    "name": "acme/target"
                }
            ],
            "dist": {
                "type": "zip",
                "url": "https://example.test/other-lib.zip",
                "reference": "beef",
                "shasum": ""
            }
        }
    ],
    "packages-dev": []
}
"#;
        let r = composer_result(lock, "1.0.0");
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "the bystander's dist must never be elected: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(warning_codes(&r), vec!["redirect_composer_pkg_not_found"]);
    }

    /// With NO nuget.config in the candidate map the rewriter authors the
    /// DEFAULT config from scratch: nuget.org source kept, socket source
    /// added, socket mapping first, `*` catch-all fanned to nuget.org — and
    /// the lock is still re-pinned in the same run.
    #[test]
    fn nuget_missing_config_authors_default_and_pins_lock() {
        let mut files = BTreeMap::new();
        files.insert(
            "packages.lock.json".to_string(),
            r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "ORIGINALHASH=="
      }
    }
  }
}
"#
            .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        let config = r
            .files
            .get("nuget.config")
            .expect("default config authored");
        assert!(
            config.contains(
                "<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />"
            ),
            "default nuget.org source kept: {config}"
        );
        assert!(
            config.contains(
                "<add key=\"socket-patch-uuid\" value=\"https://patch.test/nuget/index.json\" />"
            ),
            "socket source added: {config}"
        );
        assert!(
            config.contains(
                "    <packageSource key=\"socket-patch-uuid\">\n      <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>"
            ),
            "socket mapping present: {config}"
        );
        assert!(
            config.contains(
                "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
            ),
            "catch-all fanned to nuget.org: {config}"
        );
        let lock = r.files.get("packages.lock.json").expect("lock re-pinned");
        assert!(
            lock.contains("\"contentHash\": \"PATCHED==\"") && !lock.contains("ORIGINALHASH=="),
            "contentHash pinned to the patched artifact: {lock}"
        );
        let kinds: Vec<&str> = r.edits.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["redirect_nuget_source", "redirect_nuget_lock"]);
        assert_eq!(
            r.edits[0].action, "added",
            "a nuget.config authored from scratch records `added`, like every \
             other created file: {:?}",
            r.edits[0]
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// A PRESENT but unparseable packages.lock.json refuses the whole nuget
    /// redirect up front: landing the source + mapping while the lock kept
    /// the upstream contentHash would NU1403 every restore, with the ledger
    /// claiming the redirect. One warning per run (the lock is shared by
    /// every nuget dep), mirroring `redirect_npm_lock_unparseable`.
    #[test]
    fn nuget_unparseable_lock_warns_once_and_skips_everything() {
        let mut files = BTreeMap::new();
        files.insert("nuget.config".to_string(), default_nuget_config());
        files.insert("packages.lock.json".to_string(), "{ not json".to_string());
        let r = rewrite_registry_redirect(&files, &[nuget_override(), nuget_override()]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "nothing may land over a corrupt lock: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_nuget_lock_unparseable"],
            "{:?}",
            r.warnings
        );
    }

    /// The re-run probe reads the parsed `<packageSources>` keys, so a
    /// hand-normalized spelling of the socket source (single quotes, spaces
    /// around `=`) is recognized as already wired instead of being added a
    /// second time.
    #[test]
    fn nuget_hand_normalized_source_key_is_not_duplicated_on_rerun() {
        let mut files = BTreeMap::new();
        files.insert(
            "nuget.config".to_string(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n    <add key = 'socket-patch-uuid' value = 'https://patch.test/nuget/index.json' />\n  </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"socket-patch-uuid\">\n      <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>\n  </packageSourceMapping>\n</configuration>\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[nuget_override()]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "the source is already wired: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    /// Re-running the nuget rewriter over its own output must record nothing:
    /// the config already carries the socket key and the lock entry is
    /// already at the patched resolved/contentHash.
    #[test]
    fn nuget_rerun_over_rewritten_output_is_a_noop() {
        let mut files = BTreeMap::new();
        files.insert(
            "nuget.config".to_string(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>\n</configuration>\n"
                .to_string(),
        );
        files.insert(
            "packages.lock.json".to_string(),
            r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "ORIGINALHASH=="
      }
    }
  }
}
"#
            .to_string(),
        );
        let first = rewrite_registry_redirect(&files, &[nuget_override()]);
        assert!(
            first.files.contains_key("nuget.config")
                && first.files.contains_key("packages.lock.json"),
            "anchor: the first pass rewrites both files"
        );
        assert!(
            first
                .edits
                .iter()
                .any(|e| e.kind == "redirect_nuget_source" && e.action == "rewritten"),
            "an edit to a PRE-EXISTING nuget.config stays `rewritten`: {:?}",
            first.edits
        );
        let mut again = files.clone();
        for (name, content) in &first.files {
            again.insert(name.clone(), content.clone());
        }
        let second = rewrite_registry_redirect(&again, &[nuget_override()]);
        assert!(
            second.files.is_empty() && second.edits.is_empty(),
            "the second pass must be a no-op: files={:?} edits={:?}",
            second.files.keys(),
            second.edits
        );
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
    }

    /// A parenthesized `gem(...)` call whose closing paren is NOT on the
    /// declaration line (the call continues) cannot be safely edited: warn
    /// and leave the Gemfile byte-identical — no source block, no append.
    #[test]
    fn gemfile_paren_call_spanning_lines_fails_closed() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem(\"rails\",\n  \"7.0.0\")\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a spanning call must not be edited or duplicated: files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_gem_unrecognized_declaration"],
            "{:?}",
            r.warnings
        );
    }

    /// Lock shapes `converge_gem_lock_source` refuses — a legacy multi-remote
    /// GEM section, a spec duplicated across GEM sections, and a lock with no
    /// DEPENDENCIES section — fall back to the mixed state: the CHECKSUMS pin
    /// still lands, the GEM attribution is untouched, and the frozen-install
    /// caveat is emitted.
    #[test]
    fn gem_lock_converge_refusals_fall_back_to_mixed_state() {
        let pinned = format!("  rails (7.0.0) sha256={}", "2".repeat(64));
        let locks = [
            // Legacy multi-remote GEM section (bundler <1.7 wrote these).
            format!(
                "GEM\n  remote: https://rubygems.org/\n  remote: https://gems.mirror.example/\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nCHECKSUMS\n{pinned}\n\nBUNDLED WITH\n   2.6.2\n"
            ),
            // Spec entry duplicated across two GEM sections.
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nGEM\n  remote: https://gems.mirror.example/\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nCHECKSUMS\n{pinned}\n\nBUNDLED WITH\n   2.6.2\n"
            ),
            // No DEPENDENCIES section at all.
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nCHECKSUMS\n{pinned}\n\nBUNDLED WITH\n   2.6.2\n"
            ),
        ];
        for lock in &locks {
            let mut files = BTreeMap::new();
            files.insert(
                "Gemfile".to_string(),
                "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
            );
            files.insert("Gemfile.lock".to_string(), lock.clone());
            let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
            let out = r
                .files
                .get("Gemfile.lock")
                .unwrap_or_else(|| panic!("checksum still pinned for lock:\n{lock}"));
            assert!(
                out.contains(&format!("  rails (7.0.0) sha256={}", "f".repeat(64))),
                "the CHECKSUMS pin must still land: {out}"
            );
            assert!(
                !out.contains("remote: https://patch.test/gem/tok/uuid/"),
                "the refused convergence must not touch GEM attribution: {out}"
            );
            assert!(
                r.edits.iter().all(|e| {
                    e.kind != "redirect_gemfile_lock_gem_source"
                        && e.kind != "redirect_gemfile_lock_dependency_pin"
                        && e.kind != "redirect_gemfile_lock_source_url"
                }),
                "no convergence edits may be recorded: {:?}",
                r.edits
            );
            assert!(
                warning_codes(&r).contains(&"redirect_gem_frozen_install"),
                "the mixed state must carry the frozen-install caveat: {:?}",
                r.warnings
            );
        }
    }

    /// The legacy same-GAV verify-only inspection: dep-not-found still adds
    /// the repository; a non-jar type skips everything; a missing literal
    /// version and a `${property}` version each warn dep_unpinned but keep
    /// the repository (legacy is NOT fail-closed).
    #[test]
    fn maven_legacy_verify_only_inspection_matrix() {
        // (a) No matching <dependency>: warn, repository still added.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>ch.qos.logback</groupId>\n      <artifactId>logback-classic</artifactId>\n      <version>1.4.14</version>\n    </dependency>\n  </dependencies>\n</project>\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        let out = r.files.get("pom.xml").expect("repository still added");
        assert!(out.contains("<id>socket-patch-uuid</id>"), "{out}");
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_maven_dep_not_found",
                "redirect_maven_same_gav_fallback",
            ]
        );
        let kinds: Vec<&str> = r.edits.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["redirect_maven_repository"]);

        // (b) Non-jar <type>: nothing written, only the packaging warning.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep(
                "\n      <version>1.7.36</version>",
                "\n      <type>pom</type>",
            ),
        );
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_maven_unsupported_packaging"]
        );

        // (c) No literal <version> (inherited/managed): unpinned + repo added.
        let mut files = BTreeMap::new();
        files.insert("pom.xml".to_string(), pom_with_dep("", ""));
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        let out = r.files.get("pom.xml").expect("repository still added");
        assert!(out.contains("<id>socket-patch-uuid</id>"), "{out}");
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_maven_dep_unpinned",
                "redirect_maven_same_gav_fallback",
            ]
        );
        assert!(
            r.warnings[0].detail.contains("no literal <version>"),
            "{}",
            r.warnings[0].detail
        );

        // (d) ${property} version: unpinned + repo added (contrast with the
        // fail-closed path, which refuses the dep entirely).
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>${slf4j.version}</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        let out = r.files.get("pom.xml").expect("repository still added");
        assert!(out.contains("<id>socket-patch-uuid</id>"), "{out}");
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_maven_dep_unpinned",
                "redirect_maven_same_gav_fallback",
            ]
        );
        assert!(
            r.warnings[0].detail.contains("property placeholder"),
            "{}",
            r.warnings[0].detail
        );
    }

    /// The LEGACY gradle snippet pins the BASE version and omits the "Also
    /// bump" sentence (there is no suffixed version to bump to).
    #[test]
    fn maven_legacy_gradle_snippet_pins_base_version() {
        let mut files = BTreeMap::new();
        files.insert(
            "build.gradle".to_string(),
            "plugins { id 'java' }\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        assert!(r.files.is_empty() && r.edits.is_empty());
        assert_eq!(warning_codes(&r), vec!["redirect_gradle_manual_snippet"]);
        let detail = &r.warnings[0].detail;
        assert!(
            detail.contains("includeVersion(\"org.slf4j\", \"slf4j-api\", \"1.7.36\")"),
            "snippet pins the BASE version: {detail}"
        );
        assert!(
            !detail.contains("Also bump"),
            "no bump reminder in legacy mode: {detail}"
        );
    }

    /// A pom that already carries `<dependencyManagement><dependencies>` gets
    /// the suffixed pin inserted INSIDE it — never a duplicate section.
    #[test]
    fn maven_existing_dependency_management_is_extended_in_place() {
        let pom = "<project>\n  <dependencyManagement>\n    <dependencies>\n      <dependency>\n        <groupId>com.other</groupId>\n        <artifactId>thing</artifactId>\n        <version>1.0.0</version>\n      </dependency>\n    </dependencies>\n  </dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>org.slf4j</groupId>\n      <artifactId>slf4j-api</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n";
        let mut files = BTreeMap::new();
        files.insert("pom.xml".to_string(), pom.to_string());
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        let out = r.files.get("pom.xml").expect("pom rewritten");
        assert_eq!(
            out.matches("<dependencyManagement>").count(),
            1,
            "no duplicate section: {out}"
        );
        assert!(
            out.contains(&format!(
                "<dependencies>\n      <dependency>\n        <groupId>org.slf4j</groupId>\n        <artifactId>slf4j-api</artifactId>\n        <version>{MAVEN_SUFFIXED}</version>\n      </dependency>"
            )),
            "the pin lands inside the existing element: {out}"
        );
        assert!(
            out.contains("<artifactId>thing</artifactId>"),
            "the user's own managed entry survives: {out}"
        );
        assert!(warning_codes(&r).contains(&"redirect_maven_dep_management_added"));
    }

    /// merge_mvn_config edges through the full pipeline: a user config already
    /// carrying ALL six args (no trailing newline) is left untouched — no
    /// config edit, checksums still written — and a config holding only an
    /// unrelated line (no trailing newline) gains a newline before the merged
    /// args.
    #[test]
    fn maven_config_fully_present_is_untouched_and_newline_less_config_merges() {
        // All six args present, no trailing newline: identical-line arm.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        files.insert(".mvn/maven.config".to_string(), MVN_CONFIG_ARGS.join("\n"));
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        assert!(
            !r.files.contains_key(".mvn/maven.config"),
            "an already-complete config must not be rewritten: {:?}",
            r.files.keys()
        );
        assert!(
            r.edits.iter().all(|e| e.kind != "redirect_maven_config"),
            "no config edit may be recorded: {:?}",
            r.edits
        );
        assert!(
            r.files.contains_key(".mvn/checksums/checksums.sha256"),
            "the checksums file is still written: {:?}",
            r.files.keys()
        );
        assert!(
            !warning_codes(&r).contains(&"redirect_maven_trusted_checksums_conflict"),
            "identical lines are not conflicts: {:?}",
            r.warnings
        );

        // Unrelated line without a trailing newline: newline added, args
        // appended after it.
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        files.insert(
            ".mvn/maven.config".to_string(),
            "-Dmaven.wagon.http.retryHandler.count=3".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[maven_override()]);
        let config = r.files.get(".mvn/maven.config").expect("config merged");
        assert_eq!(
            config,
            &format!(
                "-Dmaven.wagon.http.retryHandler.count=3\n{}\n",
                MVN_CONFIG_ARGS.join("\n")
            ),
            "the user line keeps its place and gains a newline"
        );
    }

    /// A `sha256:`-prefixed hash (the colon SRI spelling) is stripped to bare
    /// hex before it lands in the trusted-checksums file, like `sha256-`.
    #[test]
    fn maven_sha256_colon_prefix_is_stripped() {
        let mut dep = maven_override();
        dep.integrity.sha256 = Some(format!("sha256:{}", "c".repeat(64)));
        dep.registry_override
            .as_mut()
            .expect("maven_override always carries a registry override")
            .identifiers
            .maven_pom_sha256 = Some(format!("sha256:{}", "d".repeat(64)));
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep("\n      <version>1.7.36</version>", ""),
        );
        let r = rewrite_registry_redirect(&files, &[dep]);
        let checksums = r
            .files
            .get(".mvn/checksums/checksums.sha256")
            .expect("checksums written");
        assert!(
            !checksums.contains("sha256:"),
            "colon prefix stripped: {checksums}"
        );
        assert!(checksums.contains(&format!("{}  ", "c".repeat(64))));
        assert!(checksums.contains(&format!("{}  ", "d".repeat(64))));
    }

    // ── coverage mop-up 2026-09 (final wave) ─────────────────────────────────
    // Residual branches the earlier audit passes did not pin: malformed-input
    // tolerance legs, workspace-inheritance satisfaction, and the remaining
    // diagnosis spellings.

    /// Malformed Cargo.toml section headers (unbalanced quote in a segment,
    /// an unclosed `[dependencies`) must classify as non-dependency sections
    /// — their entries stay byte-identical — and garbage lines inside the
    /// real [dependencies] table are skipped while the real entry still
    /// gains the pin.
    #[test]
    fn cargo_malformed_headers_and_table_lines_are_skipped_not_fatal() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [target.'cfg(unix).dependencies]\nserde = \"9.9.9\"\n\n\
             [dependencies\nserde = \"8.8.8\"\n\n\
             [dependencies]\n= \"junk\"\njunk\nserde = \"1.0.190\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(
            r.warnings.is_empty(),
            "garbage headers/lines are skipped, not refused: {:?}",
            r.warnings
        );
        let toml = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
        let pinned = format!(
            "serde = {{ version = \"1.0.190\", registry = \"{}\" }}",
            cargo_reg()
        );
        assert_eq!(
            toml.matches(&pinned).count(),
            1,
            "only the real [dependencies] entry is pinned: {toml}"
        );
        assert!(
            toml.contains("serde = \"9.9.9\"") && toml.contains("serde = \"8.8.8\""),
            "entries under malformed headers stay byte-identical: {toml}"
        );
        assert!(
            toml.contains("= \"junk\"\njunk\n"),
            "garbage table lines survive untouched: {toml}"
        );
    }

    /// Unparseable lines INSIDE a `[dependencies.<key>]` table block (a bare
    /// `= …`, a key token with no `=`) are skipped by the block scanner while
    /// the block still gains its `registry` pin right after the header.
    #[test]
    fn cargo_dep_entry_block_garbage_lines_are_skipped() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies.serde]\n= \"zap\"\npackage \"serde\"\nversion = \"1.0.190\"\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let toml = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
        assert!(
            toml.contains(&format!(
                "[dependencies.serde]\nregistry = \"{}\"\n= \"zap\"\npackage \"serde\"\nversion = \"1.0.190\"",
                cargo_reg()
            )),
            "registry pin inserted after the header, garbage lines untouched: {toml}"
        );
    }

    /// A `[workspace.dependencies]` entry ALREADY pinned to the managed
    /// registry satisfies `workspace = true` inheritors: no Cargo.toml write
    /// (no ledger growth), no refusal, and the lock is still repointed —
    /// both the `[workspace.dependencies.<key>]` table form and the
    /// inline-table form.
    #[test]
    fn cargo_workspace_already_pinned_satisfies_inheritor_without_toml_write() {
        for manifest in [
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                 [workspace.dependencies.serde]\nversion = \"1.0.190\"\nregistry = \"{reg}\"\n\n\
                 [dependencies]\nserde.workspace = true\n",
                reg = cargo_reg()
            ),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                 [workspace.dependencies]\nserde = {{ version = \"1.0.190\", registry = \"{reg}\" }}\n\n\
                 [dependencies]\nserde = {{ workspace = true }}\n",
                reg = cargo_reg()
            ),
        ] {
            let files = cargo_files(&manifest);
            let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
            assert!(
                r.warnings.is_empty(),
                "a satisfied inheritor must not refuse: {:?}",
                r.warnings
            );
            assert!(
                !r.files.contains_key("Cargo.toml"),
                "an already-pinned workspace entry writes no manifest: {:?}",
                r.files.keys()
            );
            assert!(
                r.files.contains_key("Cargo.lock"),
                "the lock is still repointed: {:?}",
                r.files.keys()
            );
            assert!(r.confirmed_cargo_uuids.contains(CARGO_UUID));
        }
    }

    /// A STALE socket-patch pin on the `[workspace.dependencies]` entry is
    /// superseded in place (table and inline forms) and still satisfies the
    /// `workspace = true` inheritor — no refusal, old uuid gone.
    #[test]
    fn cargo_workspace_stale_socket_pin_superseded_in_both_forms() {
        const OLD: &str = "socket-patch-0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";
        for manifest in [
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                 [workspace.dependencies.serde]\nversion = \"1.0.190\"\nregistry = \"{OLD}\"\n\n\
                 [dependencies]\nserde.workspace = true\n"
            ),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                 [workspace.dependencies]\nserde = {{ version = \"1.0.190\", registry = \"{OLD}\" }}\n\n\
                 [dependencies]\nserde.workspace = true\n"
            ),
        ] {
            let files = cargo_files(&manifest);
            let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
            assert!(
                r.warnings.is_empty(),
                "superseding our own stale pin must not refuse: {:?}",
                r.warnings
            );
            let toml = r
                .files
                .get("Cargo.toml")
                .expect("the stale pin is superseded in place");
            assert!(
                toml.contains(&cargo_reg()) && !toml.contains(OLD),
                "old uuid replaced by the current registry: {toml}"
            );
        }
    }

    /// A bare `[workspace.dependencies]` inline entry gains the registry pin
    /// and thereby satisfies the `workspace = true` inheritor in the same
    /// manifest.
    #[test]
    fn cargo_workspace_inline_entry_gains_pin_and_satisfies_inheritor() {
        let files = cargo_files(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [workspace.dependencies]\nserde = { version = \"1.0.190\" }\n\n\
             [dependencies]\nserde.workspace = true\n",
        );
        let r = rewrite_registry_redirect(&files, &[cargo_sparse_override()]);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let toml = r.files.get("Cargo.toml").expect("Cargo.toml rewritten");
        assert!(
            toml.contains(&format!(
                "serde = {{ version = \"1.0.190\", registry = \"{}\" }}",
                cargo_reg()
            )),
            "the workspace inline table gains the registry pin: {toml}"
        );
    }

    /// v9 vendored lock WITHOUT the `overrides:` respelling (packages key
    /// only): the `<name>@file:.socket/vendor/…` packages key ALONE must
    /// drive the vendored diagnosis — not the generic entry-not-found.
    #[test]
    fn pnpm_v9_packages_key_alone_is_diagnosed_vendored() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://patch.test/left-pad-1.3.0.tgz",
            "sha512-PATCHED==",
        );
        let lock = "lockfileVersion: '9.0'

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
";
        let mut files = BTreeMap::new();
        files.insert("pnpm-lock.yaml".to_string(), lock.to_string());
        let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "a vendored lock must stay untouched: {:?}",
            r.files.keys()
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_pnpm_entry_vendored"],
            "the packages key alone must carry the vendored diagnosis: {:?}",
            r.warnings
        );
    }

    /// A classic-lock block whose first line is not a `key:` line
    /// (hand-mangled) is skipped without derailing the rewrite of the real
    /// entry — and survives byte-identically.
    #[test]
    fn yarn_classic_keyless_block_is_skipped() {
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            "# yarn lockfile v1\n\nnot-a-key-line\n\n\
             left-pad@^1.3.0:\n  version \"1.3.0\"\n  \
             resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbb\"\n  \
             integrity sha512-UPSTREAM==\n"
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
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = r.files.get("yarn.lock").expect("real entry rewritten");
        assert!(
            out.contains("not-a-key-line"),
            "keyless block preserved: {out}"
        );
        assert!(out.contains("resolved \"http://p.test/lp.tgz\""), "{out}");
    }

    /// An EXPLICIT `.yarnrc.yml` `compressionLevel: 0` (the supported value,
    /// spelled out rather than defaulted) must proceed — only non-zero
    /// levels refuse.
    #[test]
    fn yarn_berry_explicit_compression_level_zero_proceeds() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), berry_lock("10c0"));
        files.insert(
            ".yarnrc.yml".to_string(),
            "compressionLevel: 0\n".to_string(),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = r
            .files
            .get("yarn.lock")
            .expect("explicit level 0 must not refuse");
        assert!(
            out.contains("__archiveUrl=") && out.contains(&checksum),
            "{out}"
        );
    }

    /// A berry key whose descriptor has no range after `@` and an EMPTY block
    /// (two consecutive blank lines) are both skipped; the real entry in the
    /// same lock is still rewritten and the malformed bytes survive verbatim.
    #[test]
    fn yarn_berry_malformed_key_and_empty_block_are_skipped() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let lock = format!(
            "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
             \"left-pad@\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/333\n\n\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
            "3".repeat(128)
        );
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock);
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = r
            .files
            .get("yarn.lock")
            .expect("the real entry is rewritten");
        assert!(
            out.contains(
                "\"left-pad@\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/333"
            ),
            "the rangeless key stays byte-identical: {out}"
        );
        assert_eq!(
            r.edits.len(),
            1,
            "only the real entry is edited: {:?}",
            r.edits
        );
        assert!(out.contains("__archiveUrl="), "{out}");
    }

    /// A descriptor with NO protocol at all (`left-pad@1.3.0`) is refused
    /// through the unsupported-protocol arm, and the diagnosis names the
    /// missing protocol as `(none)` instead of misquoting one.
    #[test]
    fn yarn_berry_protocolless_descriptor_names_none_protocol() {
        let checksum = format!("10c0/{}", "7".repeat(128));
        let ovr = berry_override("left-pad", "1.3.0", "http://p.test/lp.tgz", &checksum);
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "# header\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"left-pad@1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n",
                "3".repeat(128)
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_yarn_berry(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.files.is_empty(), "{:?}", r.files.keys());
        assert_eq!(
            r.warnings[0].code,
            "redirect_yarn_berry_unsupported_protocol"
        );
        assert!(
            r.warnings[0].detail.contains("`(none)`"),
            "the diagnosis must name the absent protocol: {}",
            r.warnings[0].detail
        );
    }

    /// A packages entry whose first tuple element is not a JSON string (a
    /// grammar-balanced but non-bun shape) is skipped; the real registry
    /// tuple in the same lock is still rewritten.
    #[test]
    fn bun_lock_non_string_first_element_entry_is_skipped() {
        let ovr = npm_override(
            "left-pad",
            "1.3.0",
            "http://p.test/lp.tgz",
            "sha512-PATCHED==",
        );
        let mut files = BTreeMap::new();
        files.insert(
            "bun.lock".to_string(),
            bun_lock_file(
                "\"weird\": [{ \"dep\": \"1.0.0\" }],\n    \
                 \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-OLD==\"]",
                1,
            ),
        );
        let mut r = RewriteResult::default();
        rewrite_bun_lock(&files, std::slice::from_ref(&ovr), &mut r);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let out = r.files.get("bun.lock").expect("registry tuple rewritten");
        assert!(
            out.contains("\"weird\": [{ \"dep\": \"1.0.0\" }],"),
            "non-string entry untouched: {out}"
        );
        assert!(
            out.contains(
                "\"left-pad\": [\"left-pad@http://p.test/lp.tgz\", {}, \"sha512-PATCHED==\"]"
            ),
            "{out}"
        );
    }

    /// A truncated composer.lock (the entry object never closes before EOF)
    /// must fail closed as pkg-not-found — the brace scan runs off the end
    /// instead of electing a bogus boundary.
    #[test]
    fn composer_truncated_lock_is_pkg_not_found() {
        let mut files = BTreeMap::new();
        files.insert(
            "composer.lock".to_string(),
            "{\n    \"packages\": [\n        {\n            \"name\": \"acme/target\",\n            \"version\": \"6.4.1\"\n"
                .to_string(),
        );
        let r = rewrite_registry_redirect(&files, &[composer_override("6.4.1")]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_composer_pkg_not_found"],
            "{:?}",
            r.warnings
        );
    }

    /// packages.lock.json shapes the walker must skip without touching the
    /// lock: a non-object framework value, a non-matching id, a matching id
    /// whose entry is not an object, and a lock with no `dependencies` at
    /// all. The nuget.config wiring still lands in every case.
    #[test]
    fn nuget_lock_walker_skips_unrewritable_shapes() {
        for lock in [
            "{\n  \"version\": 1,\n  \"dependencies\": {\n    \"net6.0\": {\n      \"Aardvark.Zebra\": { \"resolved\": \"1.0.0\", \"contentHash\": \"AAA\" },\n      \"Newtonsoft.Json\": \"not-an-entry-object\"\n    },\n    \"net472\": [\"not-an-object\"]\n  }\n}\n",
            "{\n  \"version\": 1\n}\n",
        ] {
            let mut files = BTreeMap::new();
            files.insert("packages.lock.json".to_string(), lock.to_string());
            let r = rewrite_registry_redirect(&files, &[nuget_override()]);
            assert!(
                r.files.contains_key("nuget.config"),
                "config wiring still lands: {:?}",
                r.files.keys()
            );
            assert!(
                !r.files.contains_key("packages.lock.json"),
                "an unrewritable lock stays untouched: {:?}",
                r.files.keys()
            );
            let kinds: Vec<&str> = r.edits.iter().map(|e| e.kind.as_str()).collect();
            assert_eq!(
                kinds,
                vec!["redirect_nuget_source"],
                "no lock edit may be recorded"
            );
        }
    }

    /// A dep whose registry override is of a FOREIGN kind writes nothing —
    /// the nuget and golang arms skip it rather than misinterpreting the
    /// override's fields (silently, matching the TS twin).
    #[test]
    fn foreign_override_kind_warns_missing_override_for_nuget_and_golang() {
        let mut nuget = nuget_override();
        nuget
            .registry_override
            .as_mut()
            .expect("nuget_override always carries an override")
            .kind = "nuget-v2".into();
        let mut golang = golang_override();
        golang
            .registry_override
            .as_mut()
            .expect("golang_override always carries an override")
            .kind = "nuget-v3".into();
        let files = golang_files();
        let r = rewrite_registry_redirect(&files, &[nuget, golang]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        // A foreign kind is no more usable than an absent override, and every
        // arm SAYS so with its missing-override code (`registry_override_of_kind`).
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_nuget_missing_override",
                "redirect_golang_unsupported"
            ],
            "{:?}",
            r.warnings
        );
    }

    /// gems.rb + Gemfile twins with deps that carry NO usable compact-index
    /// override (absent, or a foreign kind): the divergence residue skips
    /// those deps (nothing of theirs to erase), the rewrite loop skips them
    /// too — BOTH warn the missing override, nothing is written.
    #[test]
    fn gem_deps_without_compact_index_override_are_skipped() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), gemfile.to_string());
        files.insert("Gemfile".to_string(), gemfile.to_string());
        let mut no_override = gem_override("rails", "7.0.0");
        no_override.registry_override = None;
        let mut foreign = gem_override("rack", "3.0.0");
        foreign
            .registry_override
            .as_mut()
            .expect("gem_override always carries an override")
            .kind = "cargo-sparse".into();
        let r = rewrite_registry_redirect(&files, &[no_override, foreign]);
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "files={:?} edits={:?}",
            r.files.keys(),
            r.edits
        );
        assert_eq!(
            warning_codes(&r),
            vec![
                "redirect_gem_missing_override",
                "redirect_gem_missing_override"
            ],
            "{:?}",
            r.warnings
        );
    }

    /// The documented bail-to-empty legs of `gem_line_trailing_options`: a
    /// dangling comma and an unbalanced quote both yield "" (options dropped
    /// rather than a panic or a mangled tail). Shared with vendor::gem.
    #[test]
    fn gem_line_trailing_options_bails_empty_on_unparseable_tails() {
        assert_eq!(gem_line_trailing_options(","), "");
        assert_eq!(gem_line_trailing_options(", \"7.0"), "");
        assert_eq!(
            gem_line_trailing_options(", \"7.0\", require: false"),
            "require: false"
        );
    }

    /// A Gemfile.lock with a leading blank line (hand-edited) still
    /// converges: the section parser steps over non-header lines at the top
    /// instead of misparsing the file, and the leading byte survives.
    #[test]
    fn gem_lock_with_leading_blank_line_still_converges() {
        let mut files = BTreeMap::new();
        files.insert(
            "Gemfile".to_string(),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n".to_string(),
        );
        files.insert(
            "Gemfile.lock".to_string(),
            format!(
                "\n{}",
                gem_lock(&format!("  rails (7.0.0) sha256={}", "2".repeat(64)))
            ),
        );
        let r = rewrite_registry_redirect(&files, &[gem_override("rails", "7.0.0")]);
        let lock = r.files.get("Gemfile.lock").expect("the lock converges");
        assert!(
            lock.starts_with('\n'),
            "leading blank line preserved: {lock:?}"
        );
        assert!(
            lock.contains(
                "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)"
            ),
            "{lock}"
        );
        assert!(lock.contains("  rails (= 7.0.0)!"), "{lock}");
    }

    /// LEGACY same-GAV path: an explicit `<type>jar</type>` is the supported
    /// packaging — the repository must still be added (only non-jar types
    /// refuse the dep).
    #[test]
    fn maven_legacy_explicit_jar_type_is_redirected() {
        let mut files = BTreeMap::new();
        files.insert(
            "pom.xml".to_string(),
            pom_with_dep(
                "\n      <version>1.7.36</version>",
                "\n      <type>jar</type>",
            ),
        );
        let r = rewrite_registry_redirect(&files, &[legacy_maven_override()]);
        let out = r.files.get("pom.xml").expect("repository added");
        assert!(out.contains("<id>socket-patch-uuid</id>"), "{out}");
        assert_eq!(
            warning_codes(&r),
            vec!["redirect_maven_same_gav_fallback"],
            "{:?}",
            r.warnings
        );
    }

    /// A committed hosted replace that LACKS its rhs version (hand-mangled)
    /// is still recognized as ours: the ledger `original` records the
    /// version-less spelling and the directive is repaired in place.
    #[test]
    fn golang_versionless_hosted_replace_is_repaired_with_original_recorded() {
        let mut files = golang_files();
        files.insert(
            "go.mod".to_string(),
            format!(
                "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n\n\
                 replace github.com/foo/bar v1.4.2 => {}\n",
                golang_socket_module()
            ),
        );
        let ovr = golang_override();
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        let go_mod = &out.files["go.mod"];
        assert!(
            go_mod.contains(&format!(
                "replace github.com/foo/bar v1.4.2 => {} v1.4.2-socketpatch.1",
                golang_socket_module()
            )),
            "the directive is repaired in place: {go_mod}"
        );
        let edit = out
            .edits
            .iter()
            .find(|e| e.kind == "redirect_golang_replace")
            .expect("replace edit recorded");
        assert_eq!(edit.action, "updated");
        assert_eq!(
            edit.original,
            Some(Value::String(format!(
                "replace github.com/foo/bar v1.4.2 => {}",
                golang_socket_module()
            )))
        );
    }
}

#[cfg(test)]
mod python_lock_warning_tests {
    use super::*;

    #[test]
    fn missing_sha256_warns_once_across_python_lock_files() {
        let dep = DepOverride {
            ecosystem: "pypi".into(),
            name: "requests".into(),
            namespace: None,
            version: "2.28.1".into(),
            token: "11111111-1111-4111-8111-111111111111".into(),
            patch_uuid: "22222222-2222-4222-8222-222222222222".into(),
            artifact_url: "https://patch.socket.dev/requests-2.28.1-py3-none-any.whl".into(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity::default(),
        };
        let files = BTreeMap::from([
            ("uv.lock".to_string(), "version = 1\n".to_string()),
            (
                "pylock.toml".to_string(),
                "lock-version = \"1.0\"\n".to_string(),
            ),
            ("tool.py.lock".to_string(), "version = 1\n".to_string()),
        ]);
        let result = rewrite_registry_redirect(&files, &[dep]);
        assert!(result.files.is_empty() && result.edits.is_empty());
        let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == "redirect_uv_missing_sha256")
                .count(),
            1,
            "{codes:?}"
        );
    }
}

/// Which metadata file `plan_python_metadata` pairs a native Python lock
/// with, and what it does when that file is missing — pinned at the lib
/// level (the `uv_hosted` integration suite is not part of the lib run).
#[cfg(test)]
mod python_metadata_pairing_tests {
    use super::*;

    fn dep() -> DepOverride {
        DepOverride {
            ecosystem: "pypi".into(),
            name: "click".into(),
            namespace: None,
            version: "8.1.7".into(),
            token: "11111111-1111-4111-8111-111111111111".into(),
            patch_uuid: "22222222-2222-4222-8222-222222222222".into(),
            artifact_url: "https://patch.socket.dev/click-8.1.7-py3-none-any.whl".into(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity::default(),
        }
    }

    const LOCK: &str = "version = 1\n";
    const PYPROJECT: &str =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"click==8.1.7\"]\n";
    const SCRIPT: &str = "# /// script\n# dependencies = [\"click==8.1.7\"]\n# ///\nimport click\n";

    fn plan(
        path: &str,
        files: &[(&str, &str)],
        planned: &[(&str, &str)],
    ) -> Result<(Option<PythonMetadataEdit>, Option<String>), RewriteWarning> {
        let files: BTreeMap<String, String> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut result = RewriteResult::default();
        for (k, v) in planned {
            result.files.insert(k.to_string(), v.to_string());
        }
        plan_python_metadata(path, LOCK, &files, &dep(), &result)
    }

    #[test]
    fn uv_lock_pairs_with_pyproject_only_when_present() {
        let (edit, project) = plan("uv.lock", &[("pyproject.toml", PYPROJECT)], &[])
            .unwrap_or_else(|w| panic!("{}: {}", w.code, w.detail));
        let edit = edit.expect("pyproject rewritten");
        assert_eq!(edit.path, "pyproject.toml");
        assert!(!edit.script);
        assert_eq!(edit.original, PYPROJECT);
        assert_eq!(project.as_deref(), Some(edit.rewritten.as_str()));

        // No pyproject: the lock is edited alone.
        assert!(matches!(plan("uv.lock", &[], &[]), Ok((None, None))));
        // Other native locks have no paired metadata at all.
        for lock in ["pylock.toml", "pylock.dev.toml", "tool.lock", ".py.lockx"] {
            assert!(
                matches!(
                    plan(lock, &[("pyproject.toml", PYPROJECT)], &[]),
                    Ok((None, None))
                ),
                "{lock}"
            );
        }
    }

    #[test]
    fn script_lock_pairs_with_its_script_and_requires_it() {
        let (edit, project) = plan("tool.py.lock", &[("tool.py", SCRIPT)], &[])
            .unwrap_or_else(|w| panic!("{}: {}", w.code, w.detail));
        let edit = edit.expect("script rewritten");
        assert_eq!(edit.path, "tool.py");
        assert!(edit.script);
        assert_eq!(project, None);

        // An earlier dependency's planned rewrite of the script wins over the
        // file on disk.
        let (edit, _) = plan(
            "tool.py.lock",
            &[("tool.py", "not a script")],
            &[("tool.py", SCRIPT)],
        )
        .unwrap_or_else(|w| panic!("{}: {}", w.code, w.detail));
        assert_eq!(edit.expect("script rewritten").original, SCRIPT);

        let Err(missing) = plan("tool.py.lock", &[("pyproject.toml", PYPROJECT)], &[]) else {
            panic!("a script lock without its script must refuse");
        };
        assert_eq!(missing.code, "redirect_uv_script_missing");
        assert_eq!(missing.detail, "tool.py.lock requires its paired tool.py");

        let Err(bad) = plan("tool.py.lock", &[("tool.py", "print(1)\n")], &[]) else {
            panic!("a script without PEP 723 metadata must refuse");
        };
        assert_eq!(bad.code, "redirect_uv_script_unsupported");
        assert!(bad.detail.starts_with("tool.py: "), "{}", bad.detail);

        let Err(bad) = plan("uv.lock", &[("pyproject.toml", "[tool]\n")], &[]) else {
            panic!("a pyproject without [project] must refuse");
        };
        assert_eq!(bad.code, "redirect_uv_project_unsupported");
    }
}

#[cfg(test)]
mod hatch_tests {
    use super::*;

    fn patch() -> DepOverride {
        DepOverride {
            ecosystem: "pypi".into(),
            name: "urllib3".into(),
            namespace: None,
            version: "1.26.18".into(),
            token: String::new(),
            patch_uuid: "test-uuid".into(),
            artifact_url: "https://patch.test/urllib3-1.26.18-py2.py3-none-any.whl".into(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha256: Some("a".repeat(64)),
                ..Default::default()
            },
        }
    }

    #[test]
    fn hatch_confirmation_ignores_inactive_sources_and_comments() {
        let dep = patch();
        let files = [
            ("pyproject.toml".into(), format!("[project]\ndependencies=[]\n[tool.hatch.envs.default]\ndependencies=[\"urllib3 @ {}#sha256={}\"]\n", dep.artifact_url, "a".repeat(64))),
            ("hatch.toml".into(), format!("[envs.default]\ndependencies=[\"urllib3>=1\"]\n# {}\n", dep.artifact_url)),
        ].into_iter().collect();
        let result = rewrite_registry_redirect(&files, &[dep]);
        assert!(result.hatch_uuids.contains("test-uuid"));
        assert!(result.confirmed_hatch_uuids.is_empty());
        assert!(result.files.is_empty());
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.code == "redirect_hatch_unsupported"));
        let mut files = files;
        files.insert("requirements.txt".into(), String::new());
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.hatch_uuids.contains("test-uuid"));
        assert!(result.confirmed_hatch_uuids.is_empty());
        files.insert("requirements.txt".into(), "urllib3==1.26.18\n".into());
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.confirmed_hatch_uuids.contains("test-uuid"));
    }

    #[test]
    fn hatch_confirmation_uses_successful_lock_writers() {
        let base: BTreeMap<String, String> = [
            ("pyproject.toml".into(), format!("[project]\ndependencies=[]\n[tool.hatch.envs.default]\ndependencies=[\"urllib3 @ {}\"]\n", patch().artifact_url)),
            ("hatch.toml".into(), "[envs.default]\ndependencies=[\"urllib3>=1\"]\n".into()),
        ].into_iter().collect();
        for (filename, text) in [
            ("uv.lock", "version = 2"),
            ("pylock.toml", "lock-version = '2.0'"),
            // A real PDM lock that CONTAINS the package: the pdm writer runs
            // ahead of hatch and confirms through its own transactional set
            // (asserted below); a package-less stub would instead be refused
            // and withheld from every later pypi rewriter, hatch included.
            (
                "pdm.lock",
                include_str!("../../../tests/fixtures/pdm-native/2.29.2.lock"),
            ),
            ("Pipfile.lock", "{}"),
            (
                "poetry.lock",
                include_str!("../../../tests/fixtures/poetry/0.12.17/poetry.lock"),
            ),
        ] {
            let mut files = base.clone();
            files.insert(filename.into(), text.into());
            let result = rewrite_registry_redirect(&files, &[patch()]);
            assert!(result.hatch_uuids.contains("test-uuid"), "{filename}");
            assert!(result.confirmed_hatch_uuids.is_empty(), "{filename}");
            assert!(result.confirmed_python_lock_uuids.is_empty(), "{filename}");
        }
        let mut files = base.clone();
        files.insert(
            "pdm.lock".into(),
            include_str!("../../../tests/fixtures/pdm-native/2.29.2.lock").into(),
        );
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.confirmed_pdm_uuids.contains("test-uuid"));
        assert!(result.refused_pdm_uuids.is_empty());
        assert!(result.files.contains_key("pdm.lock"));
        assert!(!result.files.contains_key("pyproject.toml"));
        let mut files = base;
        files.insert(
            "poetry.lock".into(),
            include_str!("../../../tests/fixtures/poetry/1.0.10/poetry.lock").into(),
        );
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.confirmed_python_lock_uuids.contains("test-uuid"));
        assert!(result.refused_python_lock_uuids.is_empty());
        files.extend(result.files);
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.confirmed_python_lock_uuids.contains("test-uuid"));
        assert!(result.files.is_empty());
        files.insert("uv.lock".into(), "version = 2".into());
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.refused_python_lock_uuids.contains("test-uuid"));
    }

    #[test]
    fn hatch_confirmation_requires_success_and_reruns_stay_confirmed() {
        let files = [(
            "pyproject.toml".into(),
            "[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\n".into(),
        )]
        .into_iter()
        .collect();
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.confirmed_hatch_uuids.contains("test-uuid"));
        let second = rewrite_registry_redirect(&result.files, &[patch()]);
        assert!(second.confirmed_hatch_uuids.contains("test-uuid"));
        assert!(second.files.is_empty());
    }
}

#[cfg(test)]
mod hosted_patch_uuid_tests {
    //! `hosted_patch_uuid` is the trust gate between a committed lockfile
    //! line and a VEX attestation input: pin the accepted spellings AND the
    //! rejections (foreign hosts, credentials, non-canonical tokens).
    use super::*;

    const UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    /// A uuid-SHAPED grant token: the fixtures use them, and production
    /// tokens are not guaranteed otherwise — the LAST uuid segment must win.
    const TOKEN: &str = "11111111-2222-4333-8444-555555555555";

    fn none() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn artifact_and_registry_shapes_yield_the_patch_uuid_not_the_token() {
        for url in [
            format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{TOKEN}/{UUID}/left-pad-1.3.0.tgz"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/left-pad-1.3.0.tgz"),
            format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}/{UUID}/"),
            format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}/{UUID}/gems/rack-2.2.3.gem"),
            format!("https://patch.socket.dev/patch-registry/maven/{TOKEN}/{UUID}/maven2"),
            format!("https://patch.socket.dev/patch-registry/nuget/{TOKEN}/{UUID}/index.json"),
            format!("sparse+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID}/index/"),
            format!("registry+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID}/index/"),
        ] {
            assert_eq!(
                hosted_patch_uuid(&url, &none()).as_deref(),
                Some(UUID),
                "{url}"
            );
        }
    }

    #[test]
    fn lock_format_spellings_are_normalized() {
        let url = format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/left-pad-1.3.0.tgz");
        // yarn classic `#<sha1>`, pip/hatch `#sha256=`, a stray query.
        for spelled in [
            format!("{url}#0123456789abcdef0123456789abcdef01234567"),
            format!("{url}#sha256=abc"),
            format!("{url}?x=1"),
            // composer's `\/`-escaped slashes.
            url.replace('/', "\\/"),
            // yarn berry's percent-encoded `__archiveUrl=` binding value.
            url.replace(':', "%3A").replace('/', "%2F"),
            format!("  {url}  "),
        ] {
            assert_eq!(
                hosted_patch_uuid(&spelled, &none()).as_deref(),
                Some(UUID),
                "{spelled}"
            );
        }
    }

    #[test]
    fn foreign_hosts_credentials_and_plain_http_are_refused() {
        for url in [
            format!("https://registry.npmjs.org/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev.evil.example/{TOKEN}/{UUID}/x.tgz"),
            format!("https://evil.example/patch.socket.dev/{TOKEN}/{UUID}/x.tgz"),
            format!("http://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev:8443/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://user:pw@patch.socket.dev/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("git+ssh://patch.socket.dev/{UUID}"),
            format!("file:.socket/vendor/npm/{UUID}/x.tgz"),
            format!("patch.socket.dev/gopatch/{UUID}"),
        ] {
            assert_eq!(hosted_patch_uuid(&url, &none()), None, "{url}");
        }
    }

    #[test]
    fn non_canonical_segments_are_not_patch_uuids() {
        for url in [
            // Placeholder tokens (fixtures use `uuid`, `tok`, `some-uuid`).
            "https://patch.socket.dev/patch/npm/tok/uuid/x.tgz".to_string(),
            // Uppercase is not the canonical grammar.
            format!(
                "https://patch.socket.dev/patch/npm/tok/{}/x.tgz",
                UUID.to_ascii_uppercase()
            ),
            // A uuid only in the query / fragment is not a path level.
            format!("https://patch.socket.dev/patch/npm/x.tgz?u={UUID}"),
            format!("https://patch.socket.dev/patch/npm/x.tgz#{UUID}"),
            // An encoded `/` cannot split a segment into a uuid.
            format!("https://patch.socket.dev/patch/npm/tok%2F{UUID}/x.tgz"),
        ] {
            assert_eq!(hosted_patch_uuid(&url, &none()), None, "{url}");
        }
    }

    #[test]
    fn configured_patch_server_origin_is_accepted_exactly() {
        let origins = vec!["http://127.0.0.1:4545/some/base".to_string()];
        let url = format!("http://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID}/x.tgz");
        assert_eq!(hosted_patch_uuid(&url, &origins).as_deref(), Some(UUID));
        // Same host, other port / scheme: a different origin.
        for other in [
            format!("http://127.0.0.1:4546/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID}/x.tgz"),
        ] {
            assert_eq!(hosted_patch_uuid(&other, &origins), None, "{other}");
        }
        // The default host stays accepted alongside the override, and a
        // malformed override is ignored rather than widening the allowlist.
        let default = format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/x.tgz");
        assert_eq!(hosted_patch_uuid(&default, &origins).as_deref(), Some(UUID));
        assert_eq!(hosted_patch_uuid(&url, &["not a url".to_string()]), None);
    }

    /// The Go hosted namespace lives on the same host the URL allowlist
    /// pins — the two spellings of "Socket's patch server" cannot drift.
    #[test]
    fn go_module_namespace_is_on_the_patch_server_host() {
        assert!(crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX
            .starts_with(&format!("{SOCKET_PATCH_SERVER_HOST}/")));
    }
}
