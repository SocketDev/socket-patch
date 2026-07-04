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
        Err(code) => return code,
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
                eprintln!("failed to resolve patch references: {e}");
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
        let common_lock = "common/config/rush/pnpm-lock.yaml";
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
                eprintln!("failed to write {rel}: {e}");
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
                eprintln!("failed to write .socket/vendor/redirect-state.json: {e}");
                return 1;
            }
        }
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
        let mut result = serde_json::json!({
            "status": "success",
            "redirect": {
                // Final mode naming: `--redirect` IS hosted mode. Additive
                // key so JSON consumers can dispatch on the mode without
                // inferring it from which sub-object is present.
                "mode": "hosted",
                "redirected": confirmed.len(),
                "rewrittenFiles": rewritten,
                "skipped": skipped,
                "warnings": warnings,
                "dryRun": args.common.dry_run,
            }
        });
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
    } else if !args.common.silent {
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
        for s in &skipped {
            eprintln!("  skipped {} ({})", s["purl"], s["reason"]);
        }
        for w in &record_warnings {
            eprintln!("  warning: {}", w["detail"]);
        }
        for w in &migration_warnings {
            eprintln!("  warning: {}", w["detail"]);
        }
        for w in &rush_warnings {
            eprintln!("  warning: {}", w["detail"]);
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
        } else if let Some((_, message)) = &vex_error {
            eprintln!("Error: VEX generation failed: {message}");
        } else if args.vex.vex.is_some() && args.common.dry_run {
            eprintln!("Skipping VEX generation (--dry-run).");
        }
    }
    vex_code
}
