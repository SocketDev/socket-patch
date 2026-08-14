//! The hosted-mode (`--mode hosted` / `--redirect`) flow: rewrite ONLY the
//! patched dependencies' lockfile / registry-config entries to point at
//! Socket's hosted vendored patches. Self-contained — reuses `run`'s
//! discovery, then returns without touching the apply/vendor branches.

use socket_patch_core::api::types::BatchPackagePatches;

use crate::commands::vex::generate_vex_from_manifest_path;

use super::{discover_selected, ScanArgs};

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to `rewrite_registry_redirect`.
const REDIRECT_CANDIDATE_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    // A berry lock's cache-config gate reads `.yarnrc.yml`; bun's text lock is
    // `bun.lock` (its binary `bun.lockb` is auto-migrated in `run_redirect`).
    ".yarnrc.yml",
    "bun.lock",
    "requirements.txt",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    // The LEGACY extensionless spelling: cargo reads `.cargo/config` in
    // preference to `config.toml` when both exist, so the rewriter must see
    // it (it wires the managed registry into whichever one is present) —
    // otherwise the `[registries.…]` block lands in a file cargo ignores.
    ".cargo/config",
    "composer.lock",
    "nuget.config",
    "packages.lock.json",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    // Maven Trusted Checksums files the fail-closed maven rewriter merges into
    // (read so an existing user config / checksum set is preserved, not
    // clobbered).
    ".mvn/maven.config",
    ".mvn/checksums/checksums.sha256",
    // Gradle build scripts are never edited — their presence only feeds the
    // maven rewriter's paste-able `exclusiveContent` snippet warning.
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    // deno.lock is knowingly absent: deno is its own ecosystem and no
    // redirect rewriter edits its integrity entries today — recording the
    // decision here so the omission reads as deliberate, not forgotten.
];

/// `pkg:<type>/<coordinate>@<version>` → `(type, coordinate, version)`. The
/// coordinate keeps its full slash-bearing form (npm `@scope/name`, composer
/// `vendor/pkg`, golang module path) — the rewriters treat that as the `name`
/// (their `full_name()` is `name` when `namespace` is `None`).
fn parse_purl_simple(purl: &str) -> Option<(String, String, String)> {
    let stripped = socket_patch_core::utils::purl::strip_purl_qualifiers(purl);
    let rest = stripped.strip_prefix("pkg:")?;
    let (typ, after) = rest.split_once('/')?;
    let (coord, version) = after.rsplit_once('@')?;
    let name = socket_patch_core::utils::purl::percent_decode_purl_component(coord).into_owned();
    Some((typ.to_string(), name, version.to_string()))
}

/// The hosted-mode JSON error envelope, for bail-outs that return before the
/// success envelope at the bottom of [`run_redirect`] is built. When the
/// classic scan object (`scan_result`, threaded in from `run`) is present it
/// is reused so the error envelope carries the SAME top-level scan keys as
/// the success path — folding in `status`/`error` and a minimal `redirect`
/// block — instead of a bare shape that flips the schema. When absent (never
/// in JSON mode today) the bare envelope is emitted. A `--json` consumer must
/// always get parseable stdout — never empty output plus an exit code.
fn emit_json_error(scan_result: Option<serde_json::Value>, message: &str) {
    let mut result = scan_result.unwrap_or_else(|| serde_json::json!({ "status": "error" }));
    result["status"] = serde_json::json!("error");
    result["error"] = serde_json::json!(message);
    if !result.get("redirect").is_some_and(|r| r.is_object()) {
        result["redirect"] = serde_json::json!({ "mode": "hosted" });
    }
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}

/// Build the hosted `--json` success envelope: the classic scan object
/// (`scan_result`, built by `run` — scannedPackages / totalPatches /
/// canAccessPaidPatches plus the `packages` enumeration) with the redirect
/// summary NESTED under `redirect`, mirroring vendored mode's nested `vendor`
/// block. Extracted so the schema (classic scan keys + nested `redirect`) is
/// unit-testable without a live API. When `scan_result` is absent (never in
/// JSON mode today) a minimal `{status:"success"}` base is used so stdout is
/// still parseable.
fn build_redirect_json_envelope(
    scan_result: Option<serde_json::Value>,
    redirect: serde_json::Value,
) -> serde_json::Value {
    let mut result = scan_result.unwrap_or_else(|| serde_json::json!({ "status": "success" }));
    result["status"] = serde_json::json!("success");
    result["redirect"] = redirect;
    result
}

/// `scan --redirect`: resolve hosted-patch references for the selected patches,
/// then rewrite ONLY those dependencies' lockfile/registry-config entries to
/// point at the hosted vendored patches (the byte-identical counterpart of the
/// GitHub-app registry mode). No artifact bytes land in the repo.
pub(super) async fn run_redirect(
    args: &ScanArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&str>,
    all_packages_with_patches: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    // The classic scan object `run` builds for the `--json` path (`Some` in
    // JSON mode, `None` for human output). The redirect result is NESTED into
    // it so the hosted `--json` envelope stays schema-consistent with every
    // other scan; `.take()` at each terminal (error or success) folds it in.
    mut scan_result: Option<serde_json::Value>,
) -> i32 {
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::patch::redirect::{
        rewrite_registry_redirect, DepOverride, RedirectState,
    };

    // Same discovery/selection as `--apply`/`--vendor`.
    let selected = match discover_selected(
        api_client,
        effective_org_slug,
        all_packages_with_patches,
        can_access_paid_patches,
    )
    .await
    {
        Ok(s) => s,
        // Hosted mode has no discovery envelope to fold the message into at
        // this point (it builds its `redirect` result further down).
        // `discover_selected` already printed the message to stderr; a
        // `--json` run additionally gets the machine-readable envelope so
        // stdout is never empty on failure.
        Err((code, message)) => {
            if args.common.json {
                emit_json_error(scan_result.take(), &message);
            }
            return code;
        }
    };

    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut overrides: Vec<DepOverride> = Vec::new();
    // (purl, uuid, artifact_url, registry index_url, maven suffixed version)
    // per granted reference — used AFTER the rewrite to decide which deps were
    // actually redirected (their target URL / index / suffixed version landed
    // in a file) before persisting records or attesting anything. The last
    // element is Some only for fail-closed maven overrides.
    type RedirectCandidate = (String, String, String, Option<String>, Option<String>);
    let mut candidates: Vec<RedirectCandidate> = Vec::new();

    if !selected.is_empty() {
        let uuids: Vec<String> = selected.iter().map(|s| s.uuid.clone()).collect();
        let references = match api_client.fetch_registry_references(&uuids).await {
            Ok(r) => r,
            Err(e) => {
                let message = format!("failed to resolve patch references: {e}");
                eprintln!("{message}");
                if args.common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        };
        for sel in &selected {
            let Some(reference) = references.get(&sel.uuid) else {
                skipped.push(serde_json::json!({ "purl": sel.purl, "uuid": sel.uuid, "reason": "not_found" }));
                continue;
            };
            if reference.status != "granted" && reference.status != "reused" {
                skipped.push(serde_json::json!({ "purl": sel.purl, "uuid": sel.uuid, "reason": reference.status }));
                continue;
            }
            let purl = reference.purl.as_deref().unwrap_or(&sel.purl);
            let Some((ecosystem, name, version)) = parse_purl_simple(purl) else {
                skipped.push(
                    serde_json::json!({ "purl": purl, "uuid": sel.uuid, "reason": "bad_purl" }),
                );
                continue;
            };
            let Some(url) = reference.url.clone() else {
                skipped.push(
                    serde_json::json!({ "purl": purl, "uuid": sel.uuid, "reason": "no_url" }),
                );
                continue;
            };
            let mut integrity = reference
                .artifacts
                .iter()
                .flatten()
                .find(|a| a.kind == "tarball")
                .map(|a| a.integrity.clone())
                .unwrap_or_default();
            // The yarn-berry cache zip carries the `yarnBerry10c0` checksum the
            // berry rewriter pins (berry verifies the zip, not the tarball).
            // Merge it in and carry the zip URL (None when not stored yet).
            let berry_zip = reference
                .artifacts
                .iter()
                .flatten()
                .find(|a| a.kind == "yarn-berry-zip");
            if let Some(c) = berry_zip.and_then(|a| a.integrity.yarn_berry10c0.clone()) {
                integrity.yarn_berry10c0 = Some(c);
            }
            candidates.push((
                purl.to_string(),
                sel.uuid.clone(),
                url.clone(),
                reference
                    .registry_override
                    .as_ref()
                    .map(|o| o.index_url.clone()),
                reference
                    .registry_override
                    .as_ref()
                    .and_then(|o| o.identifiers.maven_suffixed_version.clone()),
            ));
            overrides.push(DepOverride {
                ecosystem,
                name,
                namespace: None,
                version,
                token: String::new(),
                patch_uuid: sel.uuid.clone(),
                artifact_url: url,
                berry_zip_url: berry_zip.and_then(|a| a.url.clone()),
                registry_override: reference.registry_override.clone(),
                integrity,
            });
        }
    }

    // Cross-mode takeover (cargo): a purl this run is about to redirect may
    // still be VENDORED — a committed `[patch.crates-io]` path entry, a
    // detached Cargo.lock entry, a committed copy, and a vendored ledger
    // entry. The hosted rewriters know nothing about that wiring, so
    // redirecting on top of it would leave BOTH wirings in place and cargo
    // then refuses every `--locked` build over the now-unused `[patch]`
    // entry while this run reports success. A takeover must leave the
    // project FULLY hosted: revert each such purl's vendored state first
    // (the exact per-purl machinery `vendor --revert` runs — restore the
    // lock originals from the ledger, drop the `[patch]` entry, remove the
    // committed tree and the ledger entry), and only then redirect. This
    // ordering also hands the redirect the PRISTINE crates.io lock fragment
    // to record as its own revert original, keeping the originals chain
    // intact across repeated mode migrations. A purl whose vendored state
    // cannot be cleanly reverted (revert failure, or vendored wiring with a
    // missing/corrupt ledger) is REFUSED — skipped with an actionable
    // error — never half-migrated.
    let mut takeover_pre_warnings: Vec<serde_json::Value> = Vec::new();
    if !candidates.iter().any(|(p, ..)| p.starts_with("pkg:cargo/")) {
        // No cargo candidates — nothing to reconcile.
    } else {
        use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
        let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
        let vendor_state = socket_patch_core::vendor::load_state(&args.common.cwd).await;
        let patch_entries =
            socket_patch_core::vendor::cargo_config::read_patch_entries(&args.common.cwd).await;
        let mut refused: Vec<String> = Vec::new();
        for (purl, _uuid, ..) in &candidates {
            if !purl.starts_with("pkg:cargo/") {
                continue;
            }
            let stripped = strip_purl_qualifiers(purl);
            let ledger_entry = vendor_state
                .as_ref()
                .ok()
                .and_then(|s| socket_patch_core::vendor::lookup_entry(&s.entries, stripped))
                .cloned();
            if let Some(entry) = ledger_entry {
                if args.common.dry_run {
                    takeover_pre_warnings.push(serde_json::json!({
                        "code": "redirect_would_revert_vendored",
                        "detail": format!(
                            "{purl} is currently vendored; the hosted redirect will \
                             revert its vendored wiring, ledger entry, and committed \
                             artifact first, then redirect (mode takeover)"
                        ),
                    }));
                    continue;
                }
                let outcome =
                    crate::commands::vendor::dispatch_revert_one(&entry, &args.common.cwd, false)
                        .await;
                if !outcome.success {
                    refused.push(purl.clone());
                    takeover_pre_warnings.push(serde_json::json!({
                        "code": "redirect_vendored_revert_failed",
                        "detail": format!(
                            "{purl} is vendored and its vendored state could not be \
                             reverted ({}); NOT redirected — run `socket-patch vendor \
                             --revert` to clean up, then re-run `scan --mode hosted`",
                            outcome.error.as_deref().unwrap_or("unknown error")
                        ),
                    }));
                    continue;
                }
                // Drop the reverted entry and persist per purl so a crash
                // mid-run leaves a ledger matching the on-disk wiring.
                // Re-loaded fresh each iteration (each iteration saves): the
                // saved file is the truth.
                let mut state = match socket_patch_core::vendor::load_state(&args.common.cwd).await
                {
                    Ok(s) => s,
                    Err(e) => {
                        refused.push(purl.clone());
                        takeover_pre_warnings.push(serde_json::json!({
                            "code": "redirect_vendored_revert_failed",
                            "detail": format!(
                                "{purl}: vendored wiring reverted but the vendored \
                                 ledger could not be re-read ({e}); NOT redirected — \
                                 fix .socket/vendor/state.json and re-run"
                            ),
                        }));
                        continue;
                    }
                };
                state
                    .entries
                    .retain(|k, e| canon(k) != canon(purl) && canon(&e.base_purl) != canon(purl));
                if let Err(e) =
                    socket_patch_core::vendor::save_state(&args.common.cwd, &state).await
                {
                    // The wiring is reverted but the ledger still claims it;
                    // redirecting now would leave a ledger asserting wiring
                    // that is gone. Fail closed for this purl.
                    refused.push(purl.clone());
                    takeover_pre_warnings.push(serde_json::json!({
                        "code": "redirect_vendored_revert_failed",
                        "detail": format!(
                            "{purl}: vendored wiring reverted but the vendored ledger \
                             could not be updated ({e}); NOT redirected — fix \
                             .socket/vendor/state.json and re-run"
                        ),
                    }));
                    continue;
                }
                takeover_pre_warnings.push(serde_json::json!({
                    "code": "redirect_takeover_reverted_vendored",
                    "detail": format!(
                        "{purl} was vendored; reverted its vendored wiring, ledger \
                         entry, and committed artifact before redirecting (mode \
                         takeover: the project is now fully hosted for this package)"
                    ),
                }));
            } else {
                // No usable ledger entry. If socket-owned vendored wiring for
                // this crate is nevertheless present, the ledger is missing or
                // corrupt — the originals needed to revert are unrecoverable,
                // so redirecting on top would wedge the project. Refuse.
                let name = parse_purl_simple(purl).map(|(_, name, _)| name);
                let wired = name
                    .as_deref()
                    .is_some_and(|n| patch_entries.get(n).is_some_and(|i| i.socket_owned));
                if wired {
                    refused.push(purl.clone());
                    takeover_pre_warnings.push(serde_json::json!({
                        "code": "redirect_vendored_revert_failed",
                        "detail": format!(
                            "{purl} has socket-owned vendored wiring in \
                             .cargo/config.toml but no usable vendored ledger entry \
                             (.socket/vendor/state.json is missing or corrupt); NOT \
                             redirected — restore the ledger or remove the vendored \
                             wiring manually, then re-run"
                        ),
                    }));
                }
            }
        }
        if !refused.is_empty() {
            for purl in &refused {
                if let Some((_, uuid, ..)) = candidates.iter().find(|(p, ..)| p == purl) {
                    skipped.push(serde_json::json!({
                        "purl": purl, "uuid": uuid, "reason": "vendored_revert_failed",
                    }));
                }
            }
            let refused_names: std::collections::HashSet<(String, String)> = candidates
                .iter()
                .filter(|(p, ..)| refused.contains(p))
                .filter_map(|(p, ..)| {
                    parse_purl_simple(p).map(|(_, name, version)| (name, version))
                })
                .collect();
            candidates.retain(|(p, ..)| !refused.contains(p));
            overrides.retain(|o| {
                o.ecosystem != "cargo"
                    || !refused_names.contains(&(o.name.clone(), o.version.clone()))
            });
        }
    }

    // bun.lockb auto-migration: the redirect rewriter only edits the TEXT
    // lockfile, so a project locked to a binary `bun.lockb` must be re-locked
    // to `bun.lock` first. `bun install --save-text-lockfile --frozen-lockfile
    // --lockfile-only` writes bun.lock, DELETES bun.lockb, needs no network,
    // and fails closed on drift. Dry-run only warns; a failure degrades to the
    // rewriter's own presence-only refusal (the .lockb stays a candidate file).
    // Gated on an npm-ecosystem override: the migration exists solely so the
    // bun rewriter has a text lock to edit — with nothing to redirect it would
    // re-lock (and delete) the user's lockfile as a side effect of a no-op run.
    let mut migration_warnings: Vec<serde_json::Value> = Vec::new();
    let mut migration_edits: Vec<socket_patch_core::patch::redirect::FileEdit> = Vec::new();
    let has_lockb = args.common.cwd.join("bun.lockb").exists();
    let has_bun_lock = args.common.cwd.join("bun.lock").exists();
    let has_npm_override = overrides.iter().any(|o| o.ecosystem == "npm");
    if has_lockb && !has_bun_lock && has_npm_override {
        if args.common.dry_run {
            migration_warnings.push(serde_json::json!({
                "code": "redirect_bun_lockb_would_migrate",
                "detail": "bun.lockb would be migrated to a text bun.lock \
                           (`bun install --save-text-lockfile`) before redirecting; \
                           re-run without --dry-run to apply",
            }));
        } else {
            // `.output()` (not `.status()`): bun's install chatter must not
            // interleave with the machine `--json` envelope on stdout.
            let output = std::process::Command::new("bun")
                .args([
                    "install",
                    "--save-text-lockfile",
                    "--frozen-lockfile",
                    "--lockfile-only",
                ])
                .current_dir(&args.common.cwd)
                .output();
            let migrated = matches!(output, Ok(o) if o.status.success())
                && args.common.cwd.join("bun.lock").exists();
            if migrated {
                // bun deleted bun.lockb itself. Record the removal so `--revert`
                // knows the file was replaced (binary — git history is the
                // restore path, so no `original` bytes are captured).
                migration_edits.push(socket_patch_core::patch::redirect::FileEdit {
                    path: "bun.lockb".into(),
                    kind: "redirect_bun_lockb_migrated".into(),
                    action: "removed".into(),
                    key: None,
                    original: None,
                    new: None,
                });
            } else {
                migration_warnings.push(serde_json::json!({
                    "code": "redirect_bun_lockb_unsupported",
                    "detail": "bun.lockb could not be migrated to a text bun.lock \
                               (`bun install --save-text-lockfile` failed or is unavailable); \
                               the redirect cannot pin a binary lockfile",
                }));
            }
        }
    }

    // Read the project's candidate files, run the rewriters.
    let mut files: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for name in REDIRECT_CANDIDATE_FILES {
        if let Ok(content) = std::fs::read_to_string(args.common.cwd.join(name)) {
            files.insert((*name).to_string(), content);
        }
    }

    // Rush monorepos have no root package.json/lock pair: the single pnpm
    // source-of-truth lock lives at common/config/rush/pnpm-lock.yaml, and
    // (when subspaces are enabled) one lock per subspace under
    // common/config/subspaces/<name>/. Add them under their repo-relative
    // keys — the pnpm rewriter is basename-generalized, so nested keys are
    // rewritten in place, and the write-back below is already path-generic.
    let mut rush_warnings: Vec<serde_json::Value> = Vec::new();
    let mut rush_lock_keys: Vec<String> = Vec::new();
    if args.common.cwd.join("rush.json").is_file() {
        let common_lock = socket_patch_core::constants::npm_family::RUSH_COMMON_LOCK_REL;
        if let Ok(content) = std::fs::read_to_string(args.common.cwd.join(common_lock)) {
            files.insert(common_lock.to_string(), content);
            rush_lock_keys.push(common_lock.to_string());
        }
        let subspaces_dir = args.common.cwd.join("common/config/subspaces");
        if let Ok(read_dir) = std::fs::read_dir(&subspaces_dir) {
            // read_dir order is unspecified — sort for deterministic output.
            let mut subspace_dirs: Vec<std::path::PathBuf> = read_dir
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.path())
                .collect();
            subspace_dirs.sort();
            for dir in subspace_dirs {
                let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let key = format!("common/config/subspaces/{name}/pnpm-lock.yaml");
                if let Ok(content) = std::fs::read_to_string(dir.join("pnpm-lock.yaml")) {
                    files.insert(key.clone(), content);
                    rush_lock_keys.push(key);
                }
            }
        }
    }

    let rewrite = rewrite_registry_redirect(&files, &overrides);
    let rewritten: Vec<String> = rewrite.files.keys().cloned().collect();

    // Editing a Rush lock outside `rush update` desyncs the
    // pnpmShrinkwrapHash recorded in repo-state.json. When
    // preventManualShrinkwrapChanges is enabled, `rush install` then
    // refuses until `rush update` refreshes that hash — but the redirect
    // survives `rush update` (pnpm preserves locked resolutions for
    // unchanged specifiers). Warn only when the rewrite actually landed in a
    // Rush lock and the repo-state file that carries the hash is present.
    if rush_lock_keys
        .iter()
        .any(|key| rewrite.files.contains_key(key))
        && args
            .common
            .cwd
            .join("common/config/rush/repo-state.json")
            .is_file()
    {
        rush_warnings.push(serde_json::json!({
            "code": "redirect_rush_repo_state_stale",
            "detail":
                "pnpm-lock.yaml was edited outside `rush update`; if \
                 preventManualShrinkwrapChanges is enabled, `rush install` fails until \
                 `rush update` refreshes repo-state.json (the redirect survives `rush \
                 update`)",
        }));
    }

    // pnpm >=11 enforces a lockfile supply-chain policy: it compares each
    // resolution's tarball URL against the registry's published metadata and
    // REFUSES the lock when they differ
    // (`ERR_PNPM_TARBALL_URL_MISMATCH … has a tarball URL (https://patch.socket.dev/…)
    // that does not match the registry's published metadata`). The hosted
    // rewrite deliberately repoints tarball URLs at patch.socket.dev, so a
    // pnpm >=11 install rejects the rewritten lock until the user opts in with
    // `pnpm install --trust-lockfile` (which installs the patched artifact
    // cleanly). Warn whenever the rewrite actually landed in ANY pnpm-lock.yaml
    // — the plain root lock or a Rush nested/subspace lock (basename check).
    let mut pnpm_warnings: Vec<serde_json::Value> = Vec::new();
    if rewrite.files.keys().any(|key| {
        std::path::Path::new(key)
            .file_name()
            .and_then(|n| n.to_str())
            == Some("pnpm-lock.yaml")
    }) {
        pnpm_warnings.push(serde_json::json!({
            "code": "redirect_pnpm_trust_lockfile",
            "detail":
                "pnpm-lock.yaml was repointed at patch.socket.dev; pnpm >=11 rejects \
                 the rewritten lock with ERR_PNPM_TARBALL_URL_MISMATCH (its tarball \
                 URL no longer matches the registry's published metadata). Install \
                 with `pnpm install --trust-lockfile` to accept the patched artifacts",
        }));
    }

    // A dep counts as REDIRECTED only if its hosted-artifact URL (or its
    // per-dependency registry index URL) actually landed in the project's
    // files — either written by this run or already present from an earlier
    // one. A granted reference whose rewriter found nothing to edit (e.g. no
    // lockfile) must NOT be recorded or attested: nothing pins the patch.
    let final_texts: Vec<&String> = files
        .iter()
        .map(|(name, content)| rewrite.files.get(name).unwrap_or(content))
        .chain(
            rewrite
                .files
                .iter()
                .filter(|(name, _)| !files.contains_key(*name))
                .map(|(_, content)| content),
        )
        .collect();
    let confirmed: Vec<(String, String)> = candidates
        .iter()
        .filter(|(_, _, artifact_url, index_url, suffixed_version)| {
            let encoded = socket_patch_core::utils::uri::encode_uri_component(artifact_url);
            final_texts.iter().any(|text| {
                text.contains(artifact_url.as_str())
                    // The berry rewriter writes the URL percent-encoded into the
                    // lock's `::__archiveUrl=` binding, so the raw form is absent.
                    || text.contains(encoded.as_str())
                    || index_url.as_deref().is_some_and(|iu| text.contains(iu))
                    // Fail-closed maven pins the globally-unique
                    // `-socket.<hex8>` suffixed version (never the `.pom` URL),
                    // so match on that string.
                    || suffixed_version
                        .as_deref()
                        .is_some_and(|sv| text.contains(sv))
            })
        })
        .map(|(purl, uuid, _, _, _)| (purl.clone(), uuid.clone()))
        .collect();

    // Fetch the full patch view (file hashes + vulnerabilities) for each
    // CONFIRMED redirect and persist it so a post-install `socket-patch vex`
    // can attest the patch. A fetch failure does not undo the redirect, but
    // it leaves the patch unattestable — surface it as a warning (JSON +
    // stderr) so CI can detect the attestation gap and re-run.
    let mut records: std::collections::BTreeMap<String, PatchRecord> =
        std::collections::BTreeMap::new();
    let mut record_warnings: Vec<serde_json::Value> = Vec::new();
    if !args.common.dry_run {
        for (purl, uuid) in &confirmed {
            match api_client.fetch_patch(effective_org_slug, uuid).await {
                Ok(Some(resp)) => {
                    let (rec_purl, record) =
                        crate::commands::get::record_from_patch_response(&resp);
                    records.insert(rec_purl, record);
                }
                Ok(None) | Err(_) => {
                    record_warnings.push(serde_json::json!({
                        "code": "record_fetch_failed",
                        "detail": format!(
                            "{purl} redirected, but its patch record could not be fetched; \
                             it will be missing from VEX until `scan --redirect` is re-run"
                        ),
                    }));
                }
            }
        }
    }

    if !args.common.dry_run {
        for (rel, content) in &rewrite.files {
            let path = args.common.cwd.join(rel);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&path, content) {
                let message = format!("failed to write {rel}: {e}");
                eprintln!("{message}");
                if args.common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        }
        // Ledger (mirrors the vendor state.json shape): recorded edits for a
        // future revert + the patch records (file hashes + vulnerabilities) so
        // a post-install `socket-patch vex` can attest the redirected patches.
        // MERGE with any existing ledger rather than overwriting: an idempotent
        // re-run produces no new edits (the lockfile already points at the
        // hosted patch), and clobbering the file would lose the original
        // pre-redirect values a future revert needs. New edits APPEND (revert
        // walks them in reverse); records are keyed by PURL, newest wins.
        if !rewrite.edits.is_empty() || !records.is_empty() || !migration_edits.is_empty() {
            let vendor_dir = args.common.cwd.join(".socket").join("vendor");
            let _ = std::fs::create_dir_all(&vendor_dir);
            let mut ledger =
                socket_patch_core::patch::redirect::load_redirect_state(&args.common.cwd)
                    .await
                    .unwrap_or_else(RedirectState::new);
            // Ledgers written before the mode-string rename carry
            // `"mode": "redirect"`; normalize on rewrite so the on-disk
            // ledger converges on the documented "hosted" name (the
            // loader accepts either — mode is an opaque string to it).
            ledger.mode = "hosted".to_string();
            // The bun.lockb→bun.lock migration removal precedes the rewrite
            // edits so `--revert` unwinds it last (after restoring bun.lock).
            ledger.edits.extend(migration_edits.iter().cloned());
            ledger.edits.extend(rewrite.edits.iter().cloned());
            ledger.records.extend(records.clone());
            // The ledger is the only revert path and the VEX record store —
            // a swallowed write failure would leave the rewritten lockfiles
            // unrevertable while reporting success.
            if let Err(e) = std::fs::write(
                vendor_dir.join("redirect-state.json"),
                format!("{}\n", serde_json::to_string_pretty(&ledger).unwrap()),
            ) {
                let message = format!("failed to write .socket/vendor/redirect-state.json: {e}");
                eprintln!("{message}");
                if args.common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        }
    }

    // Cross-mode takeover: a committed vendored ledger (`.socket/vendor/state.json`)
    // may still claim package(s) this project also has a hosted redirect ledger
    // for — their tarballs would then be orphaned and that ledger stale. But the
    // overlap alone does NOT prove hosted won: only warn for the package(s) the
    // LIVE lockfile actually routes to `patch.socket.dev` (see
    // `classify_overlap_takeover`), so a dry-run / no-op over a lock that still
    // points at the vendored files stays silent instead of pointing cleanup at
    // the live vendored ledger. Warn (JSON `warnings[]` and stderr) WITHOUT
    // deleting the other mode's ledger; reconciliation is deferred (see PR Scope).
    // Read after the ledger write above so a non-dry-run reflects this run.
    let mut takeover_warnings: Vec<serde_json::Value> = Vec::new();
    let superseded = super::classify_overlap_takeover(&args.common.cwd)
        .await
        .redirect;
    if !superseded.is_empty() {
        takeover_warnings.push(serde_json::json!({
            "code": super::REDIRECT_SUPERSEDES_VENDORED,
            "detail": super::mode_takeover_detail(&superseded, /*current_is_hosted=*/ true),
        }));
    }

    // Emit an OpenVEX attestation when `--vex` was requested. The redirected
    // bytes are fetched from the hosted patch server at install time, so the
    // PURLs CONFIRMED REDIRECTED BY THIS RUN are attested from the ledger
    // records WITHOUT hash verification (`assume_applied` — the integrity
    // pins written into the lockfile are the evidence), while any OTHER
    // manifest patches (previously applied / vendored — and any stale ledger
    // records this run did not confirm) still verify normally. A post-install
    // `socket-patch vex` hash-verifies the redirected patches against the
    // installed tree (it reads the records back from the redirect ledger via
    // augment_with_redirect). Requested-but-failed VEX (including "nothing to
    // attest") flips the exit code, matching `scan --vex`.
    let mut vex_statements: Option<usize> = None;
    let mut vex_error: Option<(&'static str, String)> = None;
    let mut vex_code = 0;
    if args.vex.vex.is_some() && !args.common.dry_run {
        let mut params = args.vex.to_build_params();
        params.assume_applied = confirmed.iter().map(|(purl, _)| purl.clone()).collect();
        let manifest_path = args.common.resolved_manifest_path();
        match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
            Ok(summary) => vex_statements = Some(summary.statements),
            Err(e) => {
                vex_code = 1;
                vex_error = Some((e.code, e.message));
            }
        }
    }

    if args.common.json {
        let mut warnings: Vec<serde_json::Value> = rewrite
            .warnings
            .iter()
            .map(|w| {
                serde_json::json!({
                    "code": w.code, "detail": w.detail,
                })
            })
            .collect();
        warnings.extend(record_warnings.iter().cloned());
        warnings.extend(migration_warnings.iter().cloned());
        warnings.extend(rush_warnings.iter().cloned());
        warnings.extend(pnpm_warnings.iter().cloned());
        warnings.extend(takeover_pre_warnings.iter().cloned());
        warnings.extend(takeover_warnings.iter().cloned());
        // Nest the redirect result under `redirect` inside the classic scan
        // object (built by `run`, threaded in via `scan_result`), mirroring
        // vendored mode's nested `vendor` block. This keeps the hosted `--json`
        // envelope schema-consistent with the zero-discovery and non-hosted
        // scan envelopes — same top-level scan keys (scannedPackages,
        // totalPatches, canAccessPaidPatches) plus the `packages` enumeration —
        // instead of the bare `{status, redirect}` it used to emit.
        let redirect = serde_json::json!({
            // Final mode naming: `--redirect` IS hosted mode. Additive key so
            // JSON consumers can dispatch on the mode without inferring it from
            // which sub-object is present.
            "mode": "hosted",
            "redirected": confirmed.len(),
            "rewrittenFiles": rewritten,
            "skipped": skipped,
            "warnings": warnings,
            "dryRun": args.common.dry_run,
        });
        let mut result = build_redirect_json_envelope(scan_result.take(), redirect);
        if let Some(statements) = vex_statements {
            result["vex"] = serde_json::json!({
                "path": args.vex.vex.as_ref().unwrap().display().to_string(),
                "statements": statements,
                "format": "openvex-0.2.0",
                "verified": false,
            });
        } else if let Some((code, message)) = &vex_error {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({ "code": code, "message": message });
        }
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        if !args.common.silent {
            let verb = if args.common.dry_run {
                "would rewrite"
            } else {
                "rewrote"
            };
            println!(
                "Redirected {} package(s); {verb} {} file(s).",
                confirmed.len(),
                rewritten.len()
            );
            // Human output prints the bare strings — `Value`'s `Display`
            // would JSON-quote them (`skipped "pkg:npm/x" ("forbidden")`).
            for s in &skipped {
                eprintln!(
                    "  skipped {} ({})",
                    s["purl"].as_str().unwrap_or_default(),
                    s["reason"].as_str().unwrap_or_default()
                );
            }
            // Same warning set as the JSON envelope, same order: the
            // rewriter's own warnings first (e.g. `no package-lock.json`),
            // then the record/migration/rush extras.
            for w in &rewrite.warnings {
                eprintln!("  warning: {}", w.detail);
            }
            for w in &record_warnings {
                eprintln!("  warning: {}", w["detail"].as_str().unwrap_or_default());
            }
            for w in &migration_warnings {
                eprintln!("  warning: {}", w["detail"].as_str().unwrap_or_default());
            }
            for w in &rush_warnings {
                eprintln!("  warning: {}", w["detail"].as_str().unwrap_or_default());
            }
            for w in &pnpm_warnings {
                eprintln!("  warning: {}", w["detail"].as_str().unwrap_or_default());
            }
            for w in &takeover_pre_warnings {
                eprintln!("  warning: {}", w["detail"].as_str().unwrap_or_default());
            }
            for w in &takeover_warnings {
                eprintln!("  warning: {}", w["detail"].as_str().unwrap_or_default());
            }
            if let Some(statements) = vex_statements {
                eprintln!(
                    "Wrote OpenVEX document with {} statement(s) to {} (redirected patches are \
                     attested from the ledger, not hash-verified — their bytes are fetched at \
                     install time; run `socket-patch vex` after installing to verify against \
                     the installed tree).",
                    statements,
                    args.vex.vex.as_ref().unwrap().display(),
                );
            } else if args.vex.vex.is_some() && args.common.dry_run {
                eprintln!("Skipping VEX generation (--dry-run).");
            }
        }
        // Errors print even under --silent ("errors only", never
        // "nothing"): exit 1 with no message would be undiagnosable.
        if let Some((_, message)) = &vex_error {
            eprintln!("Error: VEX generation failed: {message}");
        }
    }
    vex_code
}

#[cfg(test)]
mod tests {
    use super::{build_redirect_json_envelope, REDIRECT_CANDIDATE_FILES};
    use socket_patch_core::constants::npm_family;

    /// The classic scan object `run` builds for the `--json` path with ≥1
    /// discovered package (scannedPackages/totalPatches/… + the `packages`
    /// enumeration). Mirrors the `serde_json::json!` in `scan::run`.
    fn classic_scan_result() -> serde_json::Value {
        serde_json::json!({
            "status": "success",
            "scannedPackages": 3,
            "lockfileOnlyPackages": 0,
            "packagesWithPatches": 1,
            "totalPatches": 2,
            "freePatches": 2,
            "paidPatches": 0,
            "canAccessPaidPatches": false,
            "packages": [
                { "purl": "pkg:npm/minimist@1.2.2", "patches": [ { "uuid": "abc-123" } ] }
            ],
            "updates": [],
        })
    }

    #[test]
    fn hosted_json_envelope_nests_redirect_into_classic_scan_object() {
        // Regression for hosted-scan-json-schema-flips-with-discovery /
        // hosted-scan-json-omits-enumeration: with ≥1 package, the hosted
        // `--json` envelope must carry the SAME top-level scan keys as a
        // zero-discovery / non-hosted scan (the old bare `{status, redirect}`
        // dropped them) AND nest the redirect summary under `redirect`.
        let redirect = serde_json::json!({
            "mode": "hosted",
            "redirected": 1,
            "rewrittenFiles": ["package-lock.json"],
            "skipped": [],
            "warnings": [],
            "dryRun": false,
        });
        let envelope = build_redirect_json_envelope(Some(classic_scan_result()), redirect);

        // Classic scan keys survive — the bug was that they did not.
        assert_eq!(envelope["status"], "success");
        assert_eq!(envelope["scannedPackages"], 3);
        assert_eq!(envelope["packagesWithPatches"], 1);
        assert_eq!(envelope["totalPatches"], 2);
        assert_eq!(envelope["freePatches"], 2);
        assert_eq!(envelope["paidPatches"], 0);
        assert_eq!(envelope["canAccessPaidPatches"], false);
        assert!(envelope["updates"].is_array());

        // Per-package / patch-uuid enumeration is present (the omission).
        assert!(envelope["packages"].is_array());
        assert_eq!(envelope["packages"][0]["purl"], "pkg:npm/minimist@1.2.2");
        assert_eq!(envelope["packages"][0]["patches"][0]["uuid"], "abc-123");

        // Redirect result is NESTED, preserving every sub-field, not replacing
        // the whole envelope.
        let r = &envelope["redirect"];
        assert!(r.is_object());
        assert_eq!(r["mode"], "hosted");
        assert_eq!(r["redirected"], 1);
        assert_eq!(r["rewrittenFiles"][0], "package-lock.json");
        assert!(r["skipped"].is_array());
        assert!(r["warnings"].is_array());
        assert_eq!(r["dryRun"], false);
    }

    #[test]
    fn redirect_candidates_match_the_shared_npm_family_table() {
        // Drift guard, both directions, without classifying the non-npm
        // rows: every table row flagged redirect_candidate must be in the
        // candidate list, and no npm-family row NOT so flagged may appear
        // (bun.lockb's absence is deliberate — run_redirect auto-migrates
        // it before rewriting).
        for name in npm_family::names_with(|r| r.redirect_candidate) {
            assert!(
                REDIRECT_CANDIDATE_FILES.contains(&name),
                "{name} is flagged redirect_candidate but missing from \
                 REDIRECT_CANDIDATE_FILES"
            );
        }
        for name in npm_family::names_with(|r| !r.redirect_candidate) {
            assert!(
                !REDIRECT_CANDIDATE_FILES.contains(&name),
                "{name} is deliberately NOT a redirect candidate (see the \
                 npm_family table) but appears in REDIRECT_CANDIDATE_FILES"
            );
        }
    }
}
