//! The hosted-mode (`--mode hosted` / `--redirect`) flow: rewrite ONLY the
//! patched dependencies' lockfile / registry-config entries to point at
//! Socket's hosted vendored patches. Self-contained — reuses `run`'s
//! discovery, then returns without touching the apply/vendor branches.

use std::path::Path;

use socket_patch_core::api::types::BatchPackagePatches;

use crate::commands::vex::generate_vex_from_manifest_path;

use super::{discover_selected, ScanArgs};

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to `rewrite_registry_redirect`.
const REDIRECT_CANDIDATE_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    // pnpm-family MARKERS, never rewritten: `shrinkwrap.yaml` is the
    // pnpm <=2-era lock (npm never emits that filename) and
    // `node_modules/.modules.yaml` is pnpm's installer state file. The npm
    // rewriter's no-lockfile diagnostic keys its family wording off their
    // presence — without them a pnpm 1/2 project gets told "no
    // package-lock.json present", npm advice that dead-ends.
    "shrinkwrap.yaml",
    "node_modules/.modules.yaml",
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
    // Bundler's modern manifest spelling — preferred over Gemfile when both
    // exist (the gem rewriter picks the pair bundler reads and fails closed
    // on diverging spellings).
    "gems.rb",
    "gems.locked",
    // The golang rewriter edits the main module's go.mod (fork-style
    // `replace`) and go.sum (the socket module's two h1: lines). go.sum may
    // legitimately be absent — the rewriter creates it in that case.
    "go.mod",
    "go.sum",
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
    // The API serves canonical percent-encoded purls, so the version needs
    // decoding just like the coordinate — npm build metadata arrives as
    // `1.2.3%2Bbuild` while lockfiles store `1.2.3+build`; an undecoded
    // version would silently match no lock entry.
    let version =
        socket_patch_core::utils::purl::percent_decode_purl_component(version).into_owned();
    Some((typ.to_string(), name, version))
}

/// `scheme://[user[:pass]@]host[:port]/…` → `host[:port]`, NEVER userinfo.
/// For user-facing messages that name where a lockfile now points — the
/// hosted artifact host follows `--api-url`, so hardcoding `patch.socket.dev`
/// would misname it in custom-server environments. The port is kept (it is
/// part of the authority the lock records); credentials are stripped: a
/// credentialed artifact URL (`https://user:secret@host/…`) must never leak
/// `user:secret` into the warning text or the persisted `--json` envelope —
/// both land in CI logs. Split by hand because this crate has no URL-parser
/// dependency (reqwest is dev-only here); per RFC 3986 a raw `@` in the
/// authority can ONLY be the userinfo terminator (it is percent-encoded
/// everywhere else), so the tail after the LAST `@` is exactly host[:port].
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!host.is_empty()).then_some(host)
}

/// Repo-relative path of the pnpm workspace manifest the trustLockfile
/// auto-config edits (the same file the vendor backend's override surface
/// uses).
const PNPM_WORKSPACE_REL: &str = "pnpm-workspace.yaml";

/// `FileEdit.kind` recorded when the hosted flow ensures `trustLockfile:
/// true` in pnpm-workspace.yaml. `action: "created"` — the workspace file
/// itself was created (a revert deletes it); `action: "added"` — the single
/// `trustLockfile: true` line was appended to an existing file (a revert
/// removes exactly that line). Additive ledger vocabulary: older ledgers
/// without it load unchanged (kind is an opaque string to the loader).
const REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND: &str = "redirect_pnpm_workspace_trust";

/// The honest-tradeoff + don't-rebuild tail shared by every trustLockfile
/// warning variant. The tradeoff sentence is a security disclosure, not
/// prose garnish: `trustLockfile: true` disables pnpm's lockfile
/// re-verification for the WHOLE lock, so it must be stated wherever the
/// setting is written or recommended.
const PNPM_TRUST_TRADEOFF_AND_CAUTION: &str =
    "Note: trustLockfile makes pnpm skip its lockfile re-verification \
     (minimumReleaseAge / trustPolicy re-checks) for ALL lockfile entries, \
     not just the patched ones — the per-entry sha512 integrity pins are \
     still enforced. Do NOT follow pnpm's advice to rebuild the lockfile \
     (`pnpm clean --lockfile`): that silently discards the redirect and \
     reinstalls the vulnerable upstream artifact. pnpm <=10 ignores the \
     setting and installs work unchanged";

/// The policy preamble shared by every trustLockfile warning variant:
/// what was repointed, and how pnpm >=11 fails without trust.
fn pnpm_trust_policy_preamble(server: &str) -> String {
    format!(
        "pnpm-lock.yaml was repointed at {server}; pnpm >=11 rejects the \
         rewritten lock (pnpm 11: ERR_PNPM_TARBALL_URL_MISMATCH, pnpm 12: \
         ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION)"
    )
}

/// The pre-auto-config guidance, kept verbatim for the runs where the
/// auto-config does not apply (legacy 5.x/6.0 locks, Rush nested locks,
/// `--no-trust-lockfile-config`): both verified recoveries, spelled exactly.
fn pnpm_trust_manual_guidance(server: &str) -> String {
    format!(
        "{}. Install with `pnpm install --trust-lockfile`, or commit \
         `trustLockfile: true` in pnpm-workspace.yaml so every install \
         accepts the patched artifacts. Do NOT follow pnpm's advice to \
         rebuild the lockfile (`pnpm clean --lockfile`): that silently \
         discards the redirect and reinstalls the vulnerable upstream \
         artifact. pnpm <=10 installs work unchanged",
        pnpm_trust_policy_preamble(server),
    )
}

/// The LEGACY-lock variant (lockfileVersion 5.x/6.0 — pnpm 7/8): those
/// majors have neither the pnpm >=11 lockfile trust policy nor any trust
/// flag or setting, so installs consume the redirected lock unchanged and
/// no trust step exists or is needed. Deliberately NEVER mentions
/// `pnpm install --trust-lockfile`: pnpm 7/8 reject the flag as an unknown
/// option, so headlining it here would hand users a command that errors.
fn pnpm_trust_legacy_detail(server: &str) -> String {
    format!(
        "pnpm-lock.yaml was repointed at {server}. This is a legacy \
         (lockfileVersion 5.x/6.0) lock read by pnpm 7/8, which have no \
         lockfile trust policy: installs work unchanged on pnpm 7/8 and no \
         trust step exists or is needed. Do NOT regenerate the lockfile \
         (deleting it, or re-resolving on a newer pnpm): that silently \
         discards the redirect and reinstalls the vulnerable upstream \
         artifact. If the project later moves to pnpm >=9, re-run \
         `socket-patch scan --mode hosted` so the regenerated lock is \
         redirected (and trust-configured) again"
    )
}

/// The unreadable-workspace fallback: pnpm-workspace.yaml EXISTS but could
/// not be read (permissions, invalid UTF-8, I/O error). Planning a Create
/// here would OVERWRITE the user's file with the root-only scaffold —
/// destroying their `packages:` globs — so the auto-config stands down and
/// the warning names the file, the error, and both manual recoveries.
fn pnpm_trust_workspace_unreadable_detail(server: &str, err: &std::io::Error) -> String {
    format!(
        "{}. {PNPM_WORKSPACE_REL} exists but could not be read ({err}); it \
         was left untouched — auto-configuring trust would risk overwriting \
         it. Fix the file, then install with `pnpm install --trust-lockfile` \
         or add `trustLockfile: true` to it yourself so every install \
         accepts the patched artifacts. Do NOT follow pnpm's advice to \
         rebuild the lockfile (`pnpm clean --lockfile`): that silently \
         discards the redirect and reinstalls the vulnerable upstream \
         artifact. pnpm <=10 installs work unchanged",
        pnpm_trust_policy_preamble(server),
    )
}

/// The pnpm-workspace.yaml read, classified for the trust auto-config:
/// `Ok(Some(text))` — read fine; `Ok(None)` — ABSENT (`ErrorKind::NotFound`,
/// the only state where planning a Create is safe); `Err(e)` — present but
/// unreadable, so the caller must fall back to warning-only guidance. It
/// was: a bare `.ok()` collapsed EVERY read error to `None`, so a
/// present-but-unreadable workspace file was planned as a Create and
/// OVERWRITTEN with the root-only scaffold, destroying the user's
/// `packages:` globs.
fn read_workspace_for_trust(path: &std::path::Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// HEAL-ON-RERUN probe: does this (unspliced) root pnpm-lock.yaml already
/// carry a granted hosted artifact URL from an EARLIER run? Same spelling
/// set as the confirmation probe (raw / `\/`-escaped via
/// `artifact_url_present`, plus the percent-encoded form) so a writer's
/// spelling can never be one this probe misses. Lets an idempotent re-scan
/// plan the trust config for a project that missed it once (opted-out first
/// run, or a crash between the lock write and the workspace write) — the
/// splice-only trigger skipped both forever on such projects.
fn pnpm_lock_carries_hosted_redirect(
    lock_text: &str,
    overrides: &[socket_patch_core::patch::redirect::DepOverride],
) -> bool {
    overrides.iter().filter(|o| o.ecosystem == "npm").any(|o| {
        let encoded = socket_patch_core::utils::uri::encode_uri_component(&o.artifact_url);
        socket_patch_core::patch::redirect::artifact_url_present(lock_text, &o.artifact_url)
            || lock_text.contains(encoded.as_str())
    })
}

/// The HEAL-ON-RERUN gate: when this run spliced no root pnpm-lock.yaml
/// (`root_spliced` false) but the on-disk root lock is v9 and already
/// carries a granted hosted artifact URL, return its text so the trust
/// block engages anyway. Legacy (<9) and unparseable-version locks stay
/// `None` (fail closed: never write config for a lock era we can't read),
/// as does a root lock this run DID splice (the splice path covers it).
fn pnpm_heal_root<'a>(
    root_spliced: bool,
    disk_root: Option<&'a String>,
    overrides: &[socket_patch_core::patch::redirect::DepOverride],
) -> Option<&'a String> {
    if root_spliced {
        return None;
    }
    disk_root.filter(|text| {
        pnpm_lock_version_major(text).is_some_and(|major| major >= 9)
            && pnpm_lock_carries_hosted_redirect(text, overrides)
    })
}

/// The auto-config variant: trust was (or, on `--dry-run`, would be)
/// configured in pnpm-workspace.yaml, so installs need no flags.
fn pnpm_trust_configured_detail(server: &str, created: bool, dry_run: bool) -> String {
    let how = match (created, dry_run) {
        (true, false) => "`trustLockfile: true` was written to a new",
        (false, false) => "`trustLockfile: true` was merged into the existing",
        (true, true) => "`trustLockfile: true` would be written to a new (--dry-run)",
        (false, true) => "`trustLockfile: true` would be merged into the existing (--dry-run)",
    };
    format!(
        "{}, so {how} {PNPM_WORKSPACE_REL} — commit it alongside the lock; \
         installs need no extra flags. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// `lockfileVersion` major sniffed from a pnpm-lock.yaml head. pnpm 9-12
/// emit `lockfileVersion: '9.0'` (single doc, first line — verified against
/// real 7/8/9/10/11/12-rc locks in the 2026-08-18 matrix); pnpm 8 emits
/// `'6.0'`, pnpm 7 an unquoted `5.4`. `None` when no parseable version line
/// exists — callers treat that as "not trust-policy era" and stay
/// hands-off (fail closed: never write config for a lock we can't read).
fn pnpm_lock_version_major(lock_text: &str) -> Option<u32> {
    lock_text.lines().find_map(|line| {
        let rest = line.strip_prefix("lockfileVersion:")?;
        let value = rest.trim().trim_matches(|c| c == '\'' || c == '"');
        value.split('.').next()?.parse::<u32>().ok()
    })
}

/// The planned pnpm-workspace.yaml `trustLockfile: true` edit.
enum TrustPlan {
    /// No workspace file: create it (root-only `packages` scaffold — pnpm 9
    /// refuses a workspace file with no `packages` field — plus the trust
    /// key; the same scaffold shape the vendor backend creates).
    Create(String),
    /// Workspace file exists without a `trustLockfile:` key: append exactly
    /// one line after the last non-empty line, every other byte preserved.
    Append(String),
    /// Already `trustLockfile: true` — nothing to write.
    AlreadyTrue,
    /// The user explicitly set `trustLockfile: <value>` (non-true). Their
    /// call is respected — flipping an explicit security setting behind the
    /// user's back is worse than a failing install with a clear warning.
    UserSet(String),
}

/// Decide how to ensure `trustLockfile: true` in pnpm-workspace.yaml.
/// Line splices only (never a YAML library), mirroring the vendor backend's
/// workspace surgery: untouched lines stay byte-identical, so a revert can
/// remove exactly what was added.
fn plan_workspace_trust(existing: Option<&str>) -> TrustPlan {
    let Some(text) = existing else {
        return TrustPlan::Create("packages:\n  - '.'\ntrustLockfile: true\n".to_string());
    };
    // Top-level key only: an indented `trustLockfile:` under some other
    // mapping is not the setting pnpm reads.
    for line in text.split('\n') {
        if let Some(rest) = line.strip_prefix("trustLockfile:") {
            let value = rest.trim().trim_matches(|c| c == '\'' || c == '"');
            if value == "true" {
                return TrustPlan::AlreadyTrue;
            }
            return TrustPlan::UserSet(value.to_string());
        }
    }
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    // After the last non-empty line (no blank separator): a revert removes
    // exactly one line and the file's trailing bytes stay put.
    let anchor = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map(|i| i + 1)
        .unwrap_or(lines.len());
    lines.insert(anchor, "trustLockfile: true".to_string());
    TrustPlan::Append(lines.join("\n"))
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
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .expect("serializing an in-memory JSON value cannot fail")
    );
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

/// The gem stale-install probe's outcome: warnings for both output channels,
/// plus the stale purls STRUCTURALLY, so the same-run `--vex` can exclude
/// them from `assume_applied` — an envelope must never attest a CVE its own
/// warnings say is live. Excluded purls fall back to `vex`'s normal
/// installed-tree verification: a patched install still attests (with hash
/// evidence), a stale one is omitted.
#[derive(Default)]
struct GemStaleOutcome {
    warnings: Vec<serde_json::Value>,
    stale_purls: std::collections::BTreeSet<String>,
}

/// The `redirect_gem_stale_install` warning for one stale installed
/// materialization (defect facts + verified/disproven remedies: the "Gem
/// stale-install guard" section of CLI_CONTRACT.md). Wording splits on
/// blast radius: a PROJECT-LOCAL dir gets the verified delete-list remedy —
/// installed dir + cache `.gem` + `specifications` entry, plus the project's
/// committed `vendor/cache` archive when the caller passes one (bundler
/// installs from it in preference to fetching, so a remedy that leaves it
/// behind silently reinstates the stale bytes) — while a SHARED gem-env
/// home affects every project on the machine, so that flavor prefers moving
/// the project to a local bundle path and only conditionally names the
/// shared files.
fn gem_stale_install_warning(
    purl: &str,
    gem_dir: &Path,
    leaf: &str,
    cwd: &Path,
    project_cache_gem: Option<&Path>,
) -> serde_json::Value {
    let home = gem_dir
        .parent()
        .and_then(Path::parent)
        .expect("crawler-resolved gem dirs always live under <home>/gems/<leaf>");
    let cache = home.join("cache").join(format!("{leaf}.gem"));
    let spec = home.join("specifications").join(format!("{leaf}.gemspec"));
    let mut paths = vec![
        gem_dir.display().to_string(),
        cache.display().to_string(),
        spec.display().to_string(),
    ];
    if let Some(extra) = project_cache_gem {
        paths.push(extra.display().to_string());
    }
    let list = paths.join(", ");
    let detail = if gem_dir.starts_with(cwd) {
        format!(
            "{purl} was redirected to the Socket patch registry, but a stale \
             UNPATCHED install is already materialized at {} — `bundle install` \
             reuses the installed gem (and its cached .gem) without refetching, \
             and `--force`/`--redownload` reinstall from the stale cache, so \
             the vulnerable upstream code stays live. Remove the stale \
             materialization — {list} — then run `bundle install` so bundler \
             fetches the patched gem",
            gem_dir.display()
        )
    } else {
        format!(
            "{purl} was redirected to the Socket patch registry, but a stale \
             UNPATCHED install is materialized in the shared gem home at {} — \
             `bundle install` reuses it without refetching, so the vulnerable \
             upstream code stays live. That gem home is shared by every \
             project on this machine: prefer switching this project to a \
             project-local bundle path (`bundle config set --local path \
             vendor/bundle`, then `bundle install`); remove {list} directly \
             only if no other project relies on the stale gem",
            gem_dir.display()
        )
    };
    serde_json::json!({ "code": "redirect_gem_stale_install", "detail": detail })
}

/// The vendor/cache flavor of `redirect_gem_stale_install`: the project's
/// committed `bundle cache` archive (`vendor/cache/<leaf>.gem`) is not the
/// patched artifact. Bundler installs from vendor/cache in preference to
/// fetching, so every install — a fresh checkout included — re-materializes
/// the unpatched bytes no matter what the redirected Gemfile + lock say.
fn gem_stale_cache_warning(purl: &str, cache_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "code": "redirect_gem_stale_install",
        "detail": format!(
            "{purl} was redirected to the Socket patch registry, but the \
             project's committed bundler cache still holds an UNPATCHED \
             archive at {} — bundler installs from vendor/cache in preference \
             to fetching, so installs (fresh checkouts included) keep \
             materializing the vulnerable upstream bytes. Remove that file, \
             run `bundle install` so bundler fetches the patched gem, and \
             re-run `bundle cache` if the project commits its cache",
            cache_path.display()
        ),
    })
}

/// POSITIVE staleness evidence: at least one record file whose on-disk
/// content was actually read and hashed to something other than its
/// `afterHash` (`Ready` = pristine upstream bytes, `HashMismatch` = neither
/// hash). Missing or unreadable files are NEVER evidence — `verify_file_patch`
/// folds IO errors into `NotFound`, and a transiently unreadable file in an
/// already-patched install must not produce a delete prescription.
/// (`current_hash` is `Some` only when the bytes were really hashed, which
/// also excludes the absent-new-file `Ready`.)
async fn gem_stale_positive_evidence(
    gem_dir: &Path,
    record: &socket_patch_core::manifest::schema::PatchRecord,
) -> bool {
    use socket_patch_core::patch::apply::{verify_file_patch, VerifyStatus};
    for (file_name, info) in &record.files {
        let result = verify_file_patch(gem_dir, file_name, info).await;
        if matches!(
            result.status,
            VerifyStatus::Ready | VerifyStatus::HashMismatch
        ) && result.current_hash.is_some()
        {
            return true;
        }
    }
    false
}

/// Post-rewrite stale-materialization probe for gem redirects — the guard
/// for the live-verified warm-path defect where `bundle install` never
/// refetches an already-materialized gem (full narrative: the "Gem
/// stale-install guard" section of CLI_CONTRACT.md).
///
/// Judgment sources and rules:
/// * Discovery is [`socket_patch_core::crawlers::RubyCrawler`] — the same
///   installed-gem APIs `apply` uses, honoring `--global`/`--global-prefix`
///   exactly like scan's own discovery; layouts the crawler grows into are
///   covered automatically.
/// * Records are found BY UUID (the fetch key, stable across purl
///   spellings): this run's fetched records first, then the redirect
///   ledger's persisted ones — a re-scan whose `/patches/view` fetch failed
///   transiently still re-fires from the ledger instead of silently
///   dropping the warning (`record_fetch_failed` covers the fetch failure
///   itself). Record availability is part of the candidate filter, and the
///   probe returns before any crawler work (or `gem env` subprocess spawn)
///   when no judgment is possible.
/// * PATCHED means [`verify_patch_record`] `Ok` — the one shared oracle.
///   Judgments are grouped BY INSTALLED DIR: platform-variant purls of one
///   gem resolve to the same dir, and if ANY variant's record proves the
///   dir patched, the dir is patched — never warned.
/// * STALE requires [`gem_stale_positive_evidence`] — never inferred from
///   missing/unreadable files.
/// * A committed `vendor/cache/<leaf>.gem` whose sha256 differs from the
///   patched artifact's is stale too (bundler installs from it first, fresh
///   checkouts included): folded into a project-local install warning's
///   delete list, or warned standalone.
///
/// Read-only by contract: nothing is ever deleted — the remedy is
/// prescribed to the user.
async fn gem_stale_install_warnings(
    cwd: &Path,
    global: bool,
    global_prefix: Option<std::path::PathBuf>,
    confirmed: &[(String, String)],
    records: &std::collections::BTreeMap<String, socket_patch_core::manifest::schema::PatchRecord>,
    ledger_records: &std::collections::BTreeMap<
        String,
        socket_patch_core::manifest::schema::PatchRecord,
    >,
    gem_artifact_shas: &std::collections::BTreeMap<(String, String), String>,
) -> GemStaleOutcome {
    use socket_patch_core::crawlers::types::CrawlerOptions;
    use socket_patch_core::crawlers::RubyCrawler;
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::vendor::file_sha256_hex;
    use socket_patch_core::vex::verify::verify_patch_record;

    let mut out = GemStaleOutcome::default();
    let find_record = |uuid: &str| -> Option<&PatchRecord> {
        records
            .values()
            .chain(ledger_records.values())
            .find(|r| r.uuid == uuid)
    };
    // Record availability folds into the candidate filter (a zero-file map
    // included: nothing to hash means no judgment either way) so the no-op
    // cases return here, before the crawler is built. On `--dry-run` the
    // caller skips the probe entirely — see the call site.
    let candidates: Vec<(&str, &PatchRecord)> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:gem/"))
        .filter_map(|(purl, uuid)| find_record(uuid).map(|r| (purl.as_str(), r)))
        .filter(|(_, r)| !r.files.is_empty())
        .collect();
    if candidates.is_empty() {
        return out;
    }

    // Pass 1: resolve every candidate's installed materializations and judge
    // them, grouped by installed dir (see the fn doc's variant rule).
    struct DirJudgment {
        purl: String,
        leaf: String,
        patched: bool,
        positive: bool,
    }
    let crawler = RubyCrawler::new();
    let options = CrawlerOptions {
        cwd: cwd.to_path_buf(),
        global,
        global_prefix,
    };
    let gem_paths = crawler.get_gem_paths(&options).await.unwrap_or_default();
    let mut dir_state: std::collections::BTreeMap<std::path::PathBuf, DirJudgment> =
        std::collections::BTreeMap::new();
    for (purl, record) in &candidates {
        let stripped = socket_patch_core::utils::purl::strip_purl_qualifiers(purl).to_string();
        for gems_dir in &gem_paths {
            let found = crawler
                .find_by_purls(gems_dir, std::slice::from_ref(&stripped))
                .await
                .unwrap_or_default();
            let Some(pkg) = found.get(&stripped) else {
                continue;
            };
            // A dir whose leaf isn't clean UTF-8 cannot be a real crawler
            // coordinate — skip it rather than interpolate a garbled leaf
            // into the remedy paths.
            let Some(leaf) = pkg.path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let entry = dir_state
                .entry(pkg.path.clone())
                .or_insert_with(|| DirJudgment {
                    purl: (*purl).to_string(),
                    leaf: leaf.to_string(),
                    patched: false,
                    positive: false,
                });
            if verify_patch_record(&pkg.path, record).await.is_ok() {
                entry.patched = true;
            } else if !entry.positive && gem_stale_positive_evidence(&pkg.path, record).await {
                entry.positive = true;
                entry.purl = (*purl).to_string();
            }
        }
    }

    // Pass 2: warn per stale dir. A project-local dir's delete list also
    // carries the committed vendor/cache archive when one is present and not
    // proven to be the patched artifact — bundler installs from it first, so
    // a remedy that leaves it behind silently reinstates the stale bytes.
    let mut cache_covered: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (dir, j) in &dir_state {
        if j.patched || !j.positive {
            continue;
        }
        let mut folded_cache: Option<std::path::PathBuf> = None;
        if dir.starts_with(cwd) {
            let project_cache = cwd
                .join("vendor")
                .join("cache")
                .join(format!("{}.gem", j.leaf));
            if project_cache.is_file() {
                let proven_patched = match (
                    gem_artifact_shas.get(&gem_sha_key(&j.purl)),
                    file_sha256_hex(&project_cache).await,
                ) {
                    (Some(want), Some(got)) => &got == want,
                    // Unknown sha (or unreadable archive): include it —
                    // removal is safe either way, `bundle install` refetches.
                    _ => false,
                };
                if !proven_patched {
                    folded_cache = Some(project_cache);
                }
            }
        }
        if folded_cache.is_some() {
            if let Some((purl, _)) = candidates.iter().find(|(p, _)| *p == j.purl) {
                cache_covered.insert(purl);
            }
        }
        out.warnings.push(gem_stale_install_warning(
            &j.purl,
            dir,
            &j.leaf,
            cwd,
            folded_cache.as_deref(),
        ));
        out.stale_purls.insert(j.purl.clone());
    }

    // Pass 3: standalone vendor/cache staleness — a committed archive whose
    // sha256 is readable and differs from the patched artifact's, for purls
    // whose project-local install warning did not already fold it in (a
    // fresh checkout with a committed stale cache has no installed dir at
    // all, and would otherwise never warn).
    for (purl, _) in &candidates {
        if cache_covered.contains(purl) {
            continue;
        }
        let Some(want_sha) = gem_artifact_shas.get(&gem_sha_key(purl)) else {
            continue;
        };
        let Some((_, name, version)) = parse_purl_simple(purl) else {
            continue;
        };
        let cache_path = cwd
            .join("vendor")
            .join("cache")
            .join(format!("{name}-{version}.gem"));
        if !cache_path.is_file() {
            continue;
        }
        // Unreadable → no positive evidence, never a guess.
        let Some(got) = file_sha256_hex(&cache_path).await else {
            continue;
        };
        if &got == want_sha {
            continue; // the PATCHED archive — healthy commit, nothing stale
        }
        out.warnings
            .push(gem_stale_cache_warning(purl, &cache_path));
        out.stale_purls.insert((*purl).to_string());
    }
    out
}

/// The `(name, version)` key the gem artifact-sha map uses — derived from
/// the purl so overrides (which carry no purl) and confirmed purls meet on
/// neutral ground.
fn gem_sha_key(purl: &str) -> (String, String) {
    parse_purl_simple(purl)
        .map(|(_, name, version)| (name, version))
        .unwrap_or_default()
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

    // The redirect body consumes the selection only as (purl, uuid) pairs —
    // the seam `get --mode hosted` injects its advisory-pinned selection
    // through (see `run_redirect_selected`).
    let pairs: Vec<(String, String)> = selected
        .iter()
        .map(|s| (s.purl.clone(), s.uuid.clone()))
        .collect();
    run_redirect_selected(
        &args.common,
        &args.vex,
        args.prune || args.sync,
        api_client,
        effective_org_slug,
        &pairs,
        scan_result,
    )
    .await
}

/// The hosted-redirect engine over an ALREADY-SELECTED `(purl, uuid)` set:
/// reference grants → DepOverride build → vendored→hosted takeover pre-revert
/// → bun.lockb migration → candidate-file read → rewrite → pnpm trust config →
/// confirmation probe → ledger merge-then-persist → file writes → gem stale
/// probe → warnings → optional VEX. Shared VERBATIM by `scan --mode hosted`
/// (whose `run_redirect` wrapper selects via `discover_selected`) and
/// `get --mode hosted` (which pins the advisory-resolved uuid), so both
/// produce identical on-disk results for the same selection.
///
/// `scan_result` must be `Some` exactly when `common.json` is set (the
/// human/JSON split keys on `common.json`; a `--json` caller passing `None`
/// would get a minimal envelope that drops its own keys). `prune_requested`
/// only feeds the `redirect_prune_ignored` warning — `get` passes `false`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_redirect_selected(
    common: &crate::args::GlobalArgs,
    vex: &crate::commands::vex::VexEmbedArgs,
    prune_requested: bool,
    api_client: &socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&str>,
    selected: &[(String, String)],
    mut scan_result: Option<serde_json::Value>,
) -> i32 {
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::patch::redirect::{
        rewrite_registry_redirect, DepOverride, RedirectState,
    };

    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut overrides: Vec<DepOverride> = Vec::new();
    // (purl, uuid, artifact_url, registry index_url, maven suffixed version,
    // go module path) per granted reference — used AFTER the rewrite to decide
    // which deps were actually redirected (their target URL / index / suffixed
    // version / socket module path landed in a file) before persisting records
    // or attesting anything. The fifth element is Some only for fail-closed
    // maven overrides; the sixth only for golang (whose go.mod/go.sum edits
    // carry the content-addressed `patch.socket.dev/gopatch/<uuid>` module
    // path, never the artifact or index URL).
    type RedirectCandidate = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut candidates: Vec<RedirectCandidate> = Vec::new();

    if !selected.is_empty() {
        let uuids: Vec<String> = selected.iter().map(|(_, uuid)| uuid.clone()).collect();
        let references = match api_client.fetch_registry_references(&uuids).await {
            Ok(r) => r,
            Err(e) => {
                let message = format!("failed to resolve patch references: {e}");
                eprintln!("{message}");
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        };
        for (sel_purl, sel_uuid) in selected {
            let Some(reference) = references.get(sel_uuid) else {
                skipped.push(serde_json::json!({ "purl": sel_purl, "uuid": sel_uuid, "reason": "not_found" }));
                continue;
            };
            if reference.status != "granted" && reference.status != "reused" {
                skipped.push(serde_json::json!({ "purl": sel_purl, "uuid": sel_uuid, "reason": reference.status }));
                continue;
            }
            let purl = reference.purl.as_deref().unwrap_or(sel_purl);
            let Some((ecosystem, name, version)) = parse_purl_simple(purl) else {
                skipped.push(
                    serde_json::json!({ "purl": purl, "uuid": sel_uuid, "reason": "bad_purl" }),
                );
                continue;
            };
            let Some(url) = reference.url.clone() else {
                skipped.push(
                    serde_json::json!({ "purl": purl, "uuid": sel_uuid, "reason": "no_url" }),
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
            // goproxy: the hosted-Go hash pair rides the override's
            // identifiers (the tarball's dirhashH1 is the original-path
            // flavor, kept for vendor-mode verification); the golang
            // rewriter reads the normalized integrity, so merge — the
            // gopatch-flavor zip h1 REPLACES dirhashH1 here. Only both
            // together: a half-merged pair would trip the rewriter's
            // fail-closed integrity check by design.
            if let Some(ov) = reference
                .registry_override
                .as_ref()
                .filter(|o| o.kind == "goproxy")
            {
                if let (Some(zip_h1), Some(gomod_h1)) = (
                    ov.identifiers.go_zip_dirhash_h1.clone(),
                    ov.identifiers.go_mod_h1.clone(),
                ) {
                    integrity.dirhash_h1 = Some(zip_h1);
                    integrity.go_mod_h1 = Some(gomod_h1);
                }
            }
            candidates.push((
                purl.to_string(),
                sel_uuid.clone(),
                url.clone(),
                reference
                    .registry_override
                    .as_ref()
                    .map(|o| o.index_url.clone()),
                reference
                    .registry_override
                    .as_ref()
                    .and_then(|o| o.identifiers.maven_suffixed_version.clone()),
                reference
                    .registry_override
                    .as_ref()
                    .and_then(|o| o.identifiers.go_module_path.clone()),
            ));
            // The grant token is never a top-level reference field — it only
            // rides the URLs the reference endpoint hands back, as the path
            // level before the patch uuid. Recover it so the rewriters'
            // rotation-idempotency guards (which wildcard the token path
            // level of a previously-written URL) don't depend on it being
            // derivable from the URL alone: with an empty token the gem
            // guard used to miss the previous grant's source block and NEST
            // a new one around it on every re-scan.
            let token = reference
                .registry_override
                .as_ref()
                .and_then(|o| {
                    socket_patch_core::patch::redirect::grant_token_path_segment(
                        &o.index_url,
                        sel_uuid,
                    )
                })
                .or_else(|| {
                    socket_patch_core::patch::redirect::grant_token_path_segment(&url, sel_uuid)
                })
                .unwrap_or_default();
            overrides.push(DepOverride {
                ecosystem,
                name,
                namespace: None,
                version,
                token,
                patch_uuid: sel_uuid.clone(),
                artifact_url: url,
                berry_zip_url: berry_zip.and_then(|a| a.url.clone()),
                registry_override: reference.registry_override.clone(),
                integrity,
            });
        }
    }

    // Load the existing redirect ledger BEFORE any file is written — the
    // cargo takeover reverts and the bun migration included. The ledger is
    // the only store of the pre-redirect originals a future revert needs, so
    // a malformed (torn/hand-mangled) ledger must abort the run while the
    // project is still untouched: the old tolerant load treated it as "no
    // ledger" and the merge below would have started fresh, silently
    // overwriting that revert data. The malformed file is moved aside to
    // redirect-state.json.corrupt (never clobbered) so recovery stays
    // possible; a dry-run reports the same hard error but moves nothing.
    let existing_ledger =
        match socket_patch_core::patch::redirect::load_redirect_state(&common.cwd).await {
            Ok(state) => state,
            Err(mut corrupt) => {
                if !common.dry_run {
                    corrupt.quarantine().await;
                }
                let message = corrupt.to_string();
                eprintln!("{message}");
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        };

    // Snapshot the persisted patch records BEFORE the ledger value is
    // consumed by the write below: they are the gem stale-install probe's
    // fallback judgment source when this run's /patches/view fetch fails
    // transiently (the warning must keep firing until the stale
    // materialization is gone, not until the first flaky fetch).
    let ledger_records: std::collections::BTreeMap<
        String,
        socket_patch_core::manifest::schema::PatchRecord,
    > = existing_ledger
        .as_ref()
        .map(|l| l.records.clone())
        .unwrap_or_default();

    // Cross-mode takeover: a purl this run is about to redirect may still be
    // VENDORED — for cargo a committed `[patch.crates-io]` path entry, a
    // detached Cargo.lock entry, a committed copy, and a vendored ledger
    // entry; for the npm family a `file:./.socket/vendor/…` lock resolution
    // (plus a berry `resolutions` pin) and its committed tarball. The hosted
    // rewriters know nothing about that wiring: cargo then refuses every
    // `--locked` build over the now-unused `[patch]` entry while this run
    // reports success, and the npm rewriters either hijack the vendored
    // resolution while the vendored ledger still claims it (yarn classic)
    // or fail-closed refuse the `file:` protocol entirely (yarn berry). A
    // takeover must leave the project FULLY hosted: revert each such purl's
    // vendored state first (the exact per-purl machinery `vendor --revert`
    // runs — restore the lock originals from the ledger, drop the vendored
    // wiring, remove the committed artifact and the ledger entry), and only
    // then redirect. This ordering also hands the redirect the PRISTINE
    // registry lock fragment to record as its own revert original, keeping
    // the originals chain intact across repeated mode migrations. A purl
    // whose vendored state cannot be cleanly reverted (revert failure, or
    // vendored wiring with a missing/corrupt ledger) is REFUSED — skipped
    // with an actionable error — never half-migrated.
    let takeover_capable = |p: &str| p.starts_with("pkg:cargo/") || p.starts_with("pkg:npm/");
    let mut takeover_pre_warnings: Vec<serde_json::Value> = Vec::new();
    // Dry-run takeover previews: `(purl, uuid)` pairs whose vendored state
    // the wet run would revert and then redirect. Withheld from the
    // rewriters (their lock fragments still carry the vendored wiring the
    // wet run reverts FIRST) and counted as redirected below, so the
    // preview's envelope matches the wet run's outcome.
    let mut dry_run_takeover: Vec<(String, String)> = Vec::new();
    if !candidates.iter().any(|(p, ..)| takeover_capable(p)) {
        // No takeover-capable candidates — nothing to reconcile.
    } else {
        use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
        let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
        let vendor_state = socket_patch_core::vendor::load_state(&common.cwd).await;
        let patch_entries =
            socket_patch_core::vendor::cargo_config::read_patch_entries(&common.cwd).await;
        let mut refused: Vec<String> = Vec::new();
        for (purl, uuid, ..) in &candidates {
            if !takeover_capable(purl) {
                continue;
            }
            let stripped = strip_purl_qualifiers(purl);
            let ledger_entry = vendor_state
                .as_ref()
                .ok()
                .and_then(|s| socket_patch_core::vendor::lookup_entry(&s.entries, stripped))
                .cloned();
            if let Some(entry) = ledger_entry {
                if common.dry_run {
                    // Preview through the same per-purl revert machinery the
                    // wet run dispatches (write-free under dry_run): a
                    // vendored state the wet run would refuse to revert is
                    // refused here too, and one it would revert is announced
                    // as a takeover — never handed to the rewriters, which
                    // would preview against the still-vendored wiring and
                    // fail-closed refuse it, prescribing a manual
                    // `vendor --revert` for a purl this run just promised to
                    // revert itself while reporting `redirected: 0` for a
                    // migration the wet run lands.
                    let outcome =
                        crate::commands::vendor::dispatch_revert_one(&entry, &common.cwd, true)
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
                    takeover_pre_warnings.push(serde_json::json!({
                        "code": "redirect_would_revert_vendored",
                        "detail": format!(
                            "{purl} is currently vendored; the hosted redirect will \
                             revert its vendored wiring, ledger entry, and committed \
                             artifact first, then redirect (mode takeover)"
                        ),
                    }));
                    dry_run_takeover.push((purl.clone(), uuid.clone()));
                    continue;
                }
                let outcome =
                    crate::commands::vendor::dispatch_revert_one(&entry, &common.cwd, false).await;
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
                let mut state = match socket_patch_core::vendor::load_state(&common.cwd).await {
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
                if let Err(e) = socket_patch_core::vendor::save_state(&common.cwd, &state).await {
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
                // (Cargo-only probe: `.cargo/config.toml` `[patch]` entries.
                // An npm purl in this state falls through to the rewriters'
                // own per-flavor diagnostics.)
                let name = purl
                    .starts_with("pkg:cargo/")
                    .then(|| parse_purl_simple(purl).map(|(_, name, _)| name))
                    .flatten();
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
        }
        // Purls leaving the rewrite set: refused takeovers, plus the dry-run
        // takeover previews (still vendored on disk — the wet run reverts
        // them before the rewriters ever see their files).
        let withheld: Vec<&String> = refused
            .iter()
            .chain(dry_run_takeover.iter().map(|(p, _)| p))
            .collect();
        if !withheld.is_empty() {
            let withheld_names: std::collections::HashSet<(String, String, String)> = candidates
                .iter()
                .filter(|(p, ..)| withheld.contains(&p))
                .filter_map(|(p, ..)| parse_purl_simple(p))
                .collect();
            candidates.retain(|(p, ..)| !withheld.contains(&p));
            overrides.retain(|o| {
                // Overrides built here carry the full coordinate in `name`
                // (namespace unset) — the same shape parse_purl_simple emits.
                let coord = match o.namespace.as_deref() {
                    Some(ns) if !ns.is_empty() => format!("{ns}/{}", o.name),
                    _ => o.name.clone(),
                };
                !withheld_names.contains(&(o.ecosystem.clone(), coord, o.version.clone()))
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
    // The pre-migration bun.lockb bytes, held so the migration can be undone
    // when the subsequent rewrite lands NOTHING in the migrated bun.lock: an
    // npm override whose version doesn't match the lock (or whose entry is
    // refused) must not permanently convert the user's lockfile format as a
    // side effect of a zero-redirect run.
    let mut lockb_backup: Option<Vec<u8>> = None;
    let has_lockb = common.cwd.join("bun.lockb").exists();
    let has_bun_lock = common.cwd.join("bun.lock").exists();
    let has_npm_override = overrides.iter().any(|o| o.ecosystem == "npm");
    if has_lockb && !has_bun_lock && has_npm_override {
        if common.dry_run {
            migration_warnings.push(serde_json::json!({
                "code": "redirect_bun_lockb_would_migrate",
                "detail": "bun.lockb would be migrated to a text bun.lock \
                           (`bun install --save-text-lockfile`) before redirecting; \
                           re-run without --dry-run to apply",
            }));
        } else {
            // Read the binary lock BEFORE bun deletes it, so a zero-rewrite
            // run can restore it below.
            let lockb_bytes = std::fs::read(common.cwd.join("bun.lockb")).ok();
            // `.output()` (not `.status()`): bun's install chatter must not
            // interleave with the machine `--json` envelope on stdout.
            let output = std::process::Command::new("bun")
                .args([
                    "install",
                    "--save-text-lockfile",
                    "--frozen-lockfile",
                    "--lockfile-only",
                ])
                .current_dir(&common.cwd)
                .output();
            let migrated = matches!(output, Ok(o) if o.status.success())
                && common.cwd.join("bun.lock").exists();
            if migrated {
                lockb_backup = lockb_bytes;
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
        if let Ok(content) = std::fs::read_to_string(common.cwd.join(name)) {
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
    if common.cwd.join("rush.json").is_file() {
        let common_lock = socket_patch_core::constants::npm_family::RUSH_COMMON_LOCK_REL;
        if let Ok(content) = std::fs::read_to_string(common.cwd.join(common_lock)) {
            files.insert(common_lock.to_string(), content);
            rush_lock_keys.push(common_lock.to_string());
        }
        let subspaces_dir = common.cwd.join("common/config/subspaces");
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

    // `mut`: the pnpm trustLockfile auto-config below may fold a
    // pnpm-workspace.yaml write (plus its ledger edit) into the rewrite set so
    // it rides the same atomic-write / ledger-first machinery as the locks.
    let mut rewrite = rewrite_registry_redirect(&files, &overrides);

    // The lockb→text migration is only KEPT when the rewrite actually landed
    // in the migrated bun.lock. Otherwise nothing was redirected there and the
    // migration was pure side effect: restore the saved bun.lockb bytes,
    // remove the generated text lock, and drop the ledger removal record so
    // the no-op run leaves the lockfile format untouched. The rewriter's own
    // warning (entry-not-found / unsupported) explains WHY nothing landed.
    if !migration_edits.is_empty() && !rewrite.files.contains_key("bun.lock") {
        let restored = lockb_backup
            .as_deref()
            .is_some_and(|bytes| std::fs::write(common.cwd.join("bun.lockb"), bytes).is_ok());
        if restored {
            let _ = std::fs::remove_file(common.cwd.join("bun.lock"));
            migration_edits.clear();
            migration_warnings.push(serde_json::json!({
                "code": "redirect_bun_lockb_migration_reverted",
                "detail": "bun.lockb was migrated to a text bun.lock but no redirect landed \
                           in it; the original bun.lockb was restored",
            }));
        } else {
            // Restore failed (unreadable pre-migration or unwritable now):
            // keep the migration record and say loudly that the format was
            // converted by a run that redirected nothing.
            migration_warnings.push(serde_json::json!({
                "code": "redirect_bun_lockb_migrated_without_redirect",
                "detail": "bun.lockb was migrated to a text bun.lock but no redirect landed \
                           in it, and the original bun.lockb could not be restored; git \
                           history is the restore path",
            }));
        }
    }

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
        && common
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
    // REFUSES a lock whose URLs differ. The failure spelling changed across
    // majors (both observed against real installs): pnpm 11 fails with
    // ERR_PNPM_TARBALL_URL_MISMATCH (ERR_PNPM_META_FETCH_FAIL when the
    // registry is unreachable); pnpm 12 fails with
    // ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION, and its OWN error text tells
    // users to rebuild the lock (`pnpm clean --lockfile` + install) — which
    // silently discards the redirect and reinstalls the vulnerable upstream,
    // so the warning must pre-empt that advice. The recoveries verified on
    // both majors are the per-run `pnpm install --trust-lockfile` flag and
    // the committable pnpm-workspace.yaml `trustLockfile: true` key; the
    // `.npmrc` `trust-lockfile=true` spelling is IGNORED by pnpm and must
    // never be recommended.
    //
    // ZERO-TOUCH DEFAULT: when this run rewrote the ROOT pnpm-lock.yaml and
    // its lockfileVersion is >= 9 (pnpm 9-12 emit '9.0'; 5.x/6.0 locks mean
    // pnpm 7/8, which have neither the policy nor the flag — those legacy
    // locks get their own installs-work-unchanged guidance instead, never
    // the `--trust-lockfile` headline pnpm 7/8 reject as an unknown option),
    // the run auto-ensures `trustLockfile: true` in pnpm-workspace.yaml so
    // CI needs no modification and installs need no flags. The same
    // auto-config re-engages on a run that spliced NOTHING when the root v9
    // lock already carries a granted hosted artifact URL (see HEAL-ON-RERUN
    // below), so a missed config is healed by re-running the scan. Verified against real installs (2026-08-18 matrix +
    // tolerance spikes): pnpm 9.15.9 / 10.34.5 silently ignore the key
    // (frozen installs stay green), pnpm 11.22.0 / 12.0.0-rc.7 accept the
    // redirected lock with it, and the per-entry sha512 integrity pin still
    // fails closed on tampered bytes. An explicit user `trustLockfile:
    // <non-true>` is RESPECTED (never flipped — the warning explains the
    // manual recoveries instead), and `--no-trust-lockfile-config` opts out
    // entirely. Rush nested/subspace locks are excluded: rush runs pnpm in
    // common/temp, which never reads the repo-root pnpm-workspace.yaml, so a
    // root write would be config theater — those runs keep the manual
    // guidance. The warning names the host(s) the lock now points at: the
    // hosted artifact host follows --api-url, so it is not always
    // patch.socket.dev.
    let mut pnpm_warnings: Vec<serde_json::Value> = Vec::new();
    // The pnpm-workspace.yaml content + ledger edit this run will fold into
    // the rewrite set (decided inside the borrow scope, applied after it).
    let mut trust_config_write: Option<(String, socket_patch_core::patch::redirect::FileEdit)> =
        None;
    {
        // pnpm locks spliced THIS run (any depth — the rewriter is
        // basename-generalized).
        let mut pnpm_lock_texts: Vec<&String> = rewrite
            .files
            .iter()
            .filter(|(key, _)| {
                std::path::Path::new(key)
                    .file_name()
                    .and_then(|n| n.to_str())
                    == Some("pnpm-lock.yaml")
            })
            .map(|(_, content)| content)
            .collect();
        // HEAL-ON-RERUN: a root v9 lock that ALREADY carries a granted hosted
        // artifact URL (spliced by an earlier run) still plans the trust
        // config even though this run spliced nothing — so a project that
        // missed the config once (opted-out first run, or a crash between the
        // lock write and the workspace write) is healed by simply re-running
        // the scan. Without this, the idempotent no-op re-scan skipped both
        // the config and the warning forever. An AlreadyTrue workspace keeps
        // the re-run a byte-stable no-op.
        let heal_root: Option<&String> = pnpm_heal_root(
            rewrite.files.contains_key("pnpm-lock.yaml"),
            files.get("pnpm-lock.yaml"),
            &overrides,
        );
        if let Some(text) = heal_root {
            pnpm_lock_texts.push(text);
        }
        if !pnpm_lock_texts.is_empty() {
            // Name only the hosts whose artifact URL actually landed in a
            // touched pnpm lock's final text (spliced this run, or the
            // already-redirected heal root): an npm override may have matched
            // only a sibling lock (e.g. package-lock.json), and naming its host
            // here would point users at a server the pnpm lock never references.
            // Same presence predicate as the confirmation probe below (raw /
            // `\/`-escaped via artifact_url_present, plus the percent-encoded
            // spelling) so a writer's spelling can never be one this filter
            // misses.
            let mut hosts: Vec<&str> = overrides
                .iter()
                .filter(|o| o.ecosystem == "npm")
                .filter(|o| {
                    let encoded =
                        socket_patch_core::utils::uri::encode_uri_component(&o.artifact_url);
                    pnpm_lock_texts.iter().any(|text| {
                        socket_patch_core::patch::redirect::artifact_url_present(
                            text,
                            &o.artifact_url,
                        ) || text.contains(encoded.as_str())
                    })
                })
                .filter_map(|o| url_host(&o.artifact_url))
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            let server = if hosts.is_empty() {
                "the hosted patch server".to_string()
            } else {
                format!("the hosted patch server ({})", hosts.join(", "))
            };
            // Root-lock gate (see the block comment above): only the plain
            // project lock at lockfileVersion >= 9 gets the auto-config —
            // spliced this run, or detected already-redirected (heal path).
            let root_lock_v9 = heal_root.is_some()
                || rewrite
                    .files
                    .get("pnpm-lock.yaml")
                    .and_then(|text| pnpm_lock_version_major(text))
                    .is_some_and(|major| major >= 9);
            // Every touched pnpm lock is a KNOWN legacy (5.x/6.0) format —
            // pnpm 7/8 territory, where neither the trust policy nor the
            // `--trust-lockfile` flag exists (the flag is rejected as an
            // unknown option), so the manual guidance's headline would hand
            // users a command that errors. An unparseable version stays on
            // the manual guidance: never claim "no trust step needed" for a
            // lock whose era is unknown.
            let all_locks_legacy = pnpm_lock_texts
                .iter()
                .all(|text| pnpm_lock_version_major(text).is_some_and(|major| major < 9));
            let detail = if all_locks_legacy {
                pnpm_trust_legacy_detail(&server)
            } else if !root_lock_v9 || common.no_trust_lockfile_config {
                pnpm_trust_manual_guidance(&server)
            } else {
                match read_workspace_for_trust(&common.cwd.join(PNPM_WORKSPACE_REL)) {
                    // Present but UNREADABLE: never plan a Create (it would
                    // overwrite the user's workspace file) — fall back to
                    // warning-only guidance naming the file and the error.
                    Err(e) => pnpm_trust_workspace_unreadable_detail(&server, &e),
                    Ok(ws_existing) => match plan_workspace_trust(ws_existing.as_deref()) {
                        TrustPlan::Create(text) => {
                            trust_config_write = Some((
                                text,
                                socket_patch_core::patch::redirect::FileEdit {
                                    path: PNPM_WORKSPACE_REL.into(),
                                    kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
                                    action: "created".into(),
                                    key: Some("trustLockfile".into()),
                                    original: None,
                                    new: Some(serde_json::json!("true")),
                                },
                            ));
                            pnpm_trust_configured_detail(&server, true, common.dry_run)
                        }
                        TrustPlan::Append(text) => {
                            trust_config_write = Some((
                                text,
                                socket_patch_core::patch::redirect::FileEdit {
                                    path: PNPM_WORKSPACE_REL.into(),
                                    kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
                                    action: "added".into(),
                                    key: Some("trustLockfile".into()),
                                    original: None,
                                    new: Some(serde_json::json!("true")),
                                },
                            ));
                            pnpm_trust_configured_detail(&server, false, common.dry_run)
                        }
                        TrustPlan::AlreadyTrue => format!(
                            "{}, and {PNPM_WORKSPACE_REL} already carries `trustLockfile: \
                         true` — keep it committed alongside the lock; installs need \
                         no extra flags. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
                            pnpm_trust_policy_preamble(&server),
                        ),
                        TrustPlan::UserSet(value) => format!(
                            "{}. {PNPM_WORKSPACE_REL} explicitly sets `trustLockfile: \
                         {value}`, which was respected and left untouched — install \
                         with `pnpm install --trust-lockfile`, or set `trustLockfile: \
                         true` yourself so every install accepts the patched \
                         artifacts. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
                            pnpm_trust_policy_preamble(&server),
                        ),
                    },
                }
            };
            pnpm_warnings.push(serde_json::json!({
                "code": "redirect_pnpm_trust_lockfile",
                "detail": detail,
            }));
        }
    }
    if let Some((text, edit)) = trust_config_write {
        rewrite.files.insert(PNPM_WORKSPACE_REL.to_string(), text);
        // Appended last: `--revert` walks edits in reverse, so the trust key
        // is unwound before the lock originals are restored.
        rewrite.edits.push(edit);
    }
    let rewritten: Vec<String> = rewrite.files.keys().cloned().collect();

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
        .filter(
            |(purl, uuid, artifact_url, index_url, suffixed_version, go_module_path)| {
                // Cargo is transactional: the rewriter reports exactly which
                // patch uuids FULLY landed (manifest pin + lock + registry
                // block). Substring presence must never confirm a cargo dep —
                // the `[registries.…]` config block contains the index URL while
                // pinning nothing, so a config-block-only rewrite would be
                // attested with zero enforcement in any build.
                if purl.starts_with("pkg:cargo/") {
                    return rewrite.confirmed_cargo_uuids.contains(uuid);
                }
                let encoded = socket_patch_core::utils::uri::encode_uri_component(artifact_url);
                final_texts.iter().any(|text| {
                    // The rewriters' own predicate — raw, or the `\/`-escaped
                    // slashes an old composer.lock spells them with — so a
                    // writer's spelling can never be one this probe misses. It
                    // was: the composer rewriter emitted `\/`-escaped urls this
                    // probe never looked for, so a fully successful composer
                    // redirect reported `redirected: 0`, fetched no patch record
                    // into the ledger, and left the patch unattestable by `vex`.
                    socket_patch_core::patch::redirect::artifact_url_present(text, artifact_url)
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
                        // golang pins the content-addressed
                        // `patch.socket.dev/gopatch/<uuid>` module path into
                        // go.mod + go.sum (no URL ever lands in either file).
                        || go_module_path
                            .as_deref()
                            .is_some_and(|gm| text.contains(gm))
                })
            },
        )
        .map(|(purl, uuid, _, _, _, _)| (purl.clone(), uuid.clone()))
        .collect();
    // Dry-run mode-takeover previews were withheld from the rewriters (their
    // lock fragments still carry the vendored wiring the wet run reverts
    // first), so the presence probe above cannot see them: the wet run
    // reverts then redirects each one, and the preview's `redirected` count
    // must report that outcome. Populated only under --dry-run.
    let mut confirmed = confirmed;
    confirmed.extend(dry_run_takeover);

    // Fetch the full patch view (file hashes + vulnerabilities) for each
    // CONFIRMED redirect and persist it so a post-install `socket-patch vex`
    // can attest the patch. A fetch failure does not undo the redirect, but
    // it leaves the patch unattestable — surface it as a warning (JSON +
    // stderr) so CI can detect the attestation gap and re-run.
    let mut records: std::collections::BTreeMap<String, PatchRecord> =
        std::collections::BTreeMap::new();
    let mut record_warnings: Vec<serde_json::Value> = Vec::new();
    if !common.dry_run {
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

    if !common.dry_run {
        // Ledger (mirrors the vendor state.json shape): recorded edits for a
        // future revert + the patch records (file hashes + vulnerabilities) so
        // a post-install `socket-patch vex` can attest the redirected patches.
        // MERGE with any existing ledger rather than overwriting: an idempotent
        // re-run produces no new edits (the lockfile already points at the
        // hosted patch), and clobbering the file would lose the original
        // pre-redirect values a future revert needs. New edits APPEND (revert
        // walks them in reverse), skipping byte-identical re-plans from a
        // retried partial failure; records are keyed by PURL, newest wins.
        //
        // Persisted BEFORE the project files, and atomically (stage + fsync +
        // rename, like the sibling vendor ledger): a crash between the two
        // then leaves a complete ledger whose recorded originals simply match
        // files that were never rewritten — instead of rewritten files whose
        // pre-redirect originals never reached any ledger (a healing re-run
        // records no edits for already-redirected entries).
        if !rewrite.edits.is_empty() || !records.is_empty() || !migration_edits.is_empty() {
            let mut ledger = existing_ledger.unwrap_or_else(RedirectState::new);
            // Ledgers written before the mode-string rename carry
            // `"mode": "redirect"`; normalize on rewrite so the on-disk
            // ledger converges on the documented "hosted" name (the
            // loader accepts either — mode is an opaque string to it).
            ledger.mode = "hosted".to_string();
            // The bun.lockb→bun.lock migration removal precedes the rewrite
            // edits so `--revert` unwinds it last (after restoring bun.lock).
            for edit in migration_edits.iter().chain(rewrite.edits.iter()) {
                if !ledger.edits.contains(edit) {
                    ledger.edits.push(edit.clone());
                }
            }
            ledger.records.extend(records.clone());
            // The ledger is the only revert path and the VEX record store —
            // a swallowed write failure would let the lockfile writes below
            // proceed with no revert data persisted while reporting success.
            if let Err(e) =
                socket_patch_core::patch::redirect::save_redirect_state(&common.cwd, &ledger).await
            {
                let message = format!("failed to write .socket/vendor/redirect-state.json: {e}");
                eprintln!("{message}");
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        }
        for (rel, content) in &rewrite.files {
            let path = common.cwd.join(rel);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // Atomic stage+rename, mode-preserving (the vendored backend's
            // writer): a bare `fs::write` truncates first, so a crash
            // mid-write could leave a torn lockfile behind.
            if let Err(e) = socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(
                &path,
                content.as_bytes(),
            )
            .await
            {
                let message = format!("failed to write {rel}: {e}");
                eprintln!("{message}");
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        }
    }

    // Gem stale-install probe (see `gem_stale_install_warnings`): runs after
    // the writes so the warning describes the project as this run leaves it.
    // Idempotent re-scans re-confirm and re-probe, so the warning keeps
    // firing until the stale materialization is actually gone. The gate is
    // deliberately EXPLICIT, not derived from empty fresh records: --dry-run
    // rewrites nothing (there is no post-rewrite state to warn about), but
    // the probe's ledger-record fallback could still judge an
    // already-redirected project, so without this gate a dry-run would warn
    // about state the run did not (re)create.
    let gem_stale: GemStaleOutcome = if common.dry_run {
        GemStaleOutcome::default()
    } else {
        // purl-coordinate → the PATCHED .gem artifact's sha256 (registry
        // override identifier, tarball integrity fallback) — judges a
        // committed vendor/cache archive.
        let gem_artifact_shas: std::collections::BTreeMap<(String, String), String> = overrides
            .iter()
            .filter(|o| o.ecosystem == "gem")
            .filter_map(|o| {
                let sha = o
                    .registry_override
                    .as_ref()
                    .and_then(|ro| ro.identifiers.gem_checksum_sha256.clone())
                    .or_else(|| o.integrity.sha256.clone())?;
                Some(((o.name.clone(), o.version.clone()), sha))
            })
            .collect();
        gem_stale_install_warnings(
            &common.cwd,
            common.global,
            common.global_prefix.clone(),
            &confirmed,
            &records,
            &ledger_records,
            &gem_artifact_shas,
        )
        .await
    };

    // Cross-mode takeover: a committed vendored ledger (`.socket/vendor/state.json`)
    // may still claim package(s) this project also has a hosted redirect ledger
    // for — their tarballs would then be orphaned and that ledger stale. But the
    // overlap alone does NOT prove hosted won: only warn for the package(s) the
    // LIVE lockfile actually routes to the hosted patch server (see
    // `classify_overlap_takeover`), so a dry-run / no-op over a lock that still
    // points at the vendored files stays silent instead of pointing cleanup at
    // the live vendored ledger. Warn (JSON `warnings[]` and stderr) WITHOUT
    // deleting the other mode's ledger; reconciliation is deferred (see PR Scope).
    // Read after the ledger write above so a non-dry-run reflects this run.
    let mut takeover_warnings: Vec<serde_json::Value> = Vec::new();
    let superseded = super::classify_overlap_takeover(&common.cwd).await.redirect;
    if !superseded.is_empty() {
        takeover_warnings.push(serde_json::json!({
            "code": super::REDIRECT_SUPERSEDES_VENDORED,
            "detail": super::mode_takeover_detail(&superseded, /*current_is_hosted=*/ true),
        }));
    }

    // `--prune` is a no-op in hosted mode (both hosted terminals return
    // before the GC blocks): make that explicit in the JSON `warnings[]`
    // rather than silently dropping the flag — a bot migrating from
    // `--mode agent --prune` must see WHY it stopped pruning. The human
    // path warns once up front in `run` (before this flow is entered).
    let mut prune_warnings: Vec<serde_json::Value> = Vec::new();
    if prune_requested {
        prune_warnings.push(serde_json::json!({
            "code": super::REDIRECT_PRUNE_IGNORED,
            "detail": super::REDIRECT_PRUNE_IGNORED_DETAIL,
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
    if vex.vex.is_some() && !common.dry_run {
        let mut params = vex.to_build_params();
        // Stale-flagged purls are EXCLUDED from assume_applied: the same-run
        // envelope carries a redirect_gem_stale_install warning proving the
        // installed materialization unpatched, so attesting that purl from
        // the ledger would contradict the run's own warning. Excluded purls
        // fall back to `vex`'s normal installed-tree verification — a
        // patched install still attests (with hash evidence), a stale one is
        // omitted (and "nothing to attest" fails the command, per the
        // embedded-VEX contract).
        params.assume_applied = confirmed
            .iter()
            .map(|(purl, _)| purl.clone())
            .filter(|purl| !gem_stale.stale_purls.contains(purl))
            .collect();
        let manifest_path = common.resolved_manifest_path();
        match generate_vex_from_manifest_path(common, &params, &manifest_path).await {
            Ok(summary) => vex_statements = Some(summary.statements),
            Err(e) => {
                vex_code = 1;
                vex_error = Some((e.code, e.message));
            }
        }
    }

    if common.json {
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
        warnings.extend(gem_stale.warnings.iter().cloned());
        warnings.extend(takeover_pre_warnings.iter().cloned());
        warnings.extend(takeover_warnings.iter().cloned());
        warnings.extend(prune_warnings.iter().cloned());
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
            "dryRun": common.dry_run,
        });
        let mut result = build_redirect_json_envelope(scan_result.take(), redirect);
        if let Some(statements) = vex_statements {
            result["vex"] = serde_json::json!({
                "path": vex.vex.as_ref().expect("vex_statements is Some only when --vex was given").display().to_string(),
                "statements": statements,
                "format": "openvex-0.2.0",
                "verified": false,
            });
        } else if let Some((code, message)) = &vex_error {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({ "code": code, "message": message });
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("serializing an in-memory JSON value cannot fail")
        );
    } else {
        if !common.silent {
            let verb = if common.dry_run {
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
            for w in &gem_stale.warnings {
                // Code included: the stale-install hazard is a silent-CVE
                // state, so the stderr line must be greppable by its stable
                // code in CI logs, same as the JSON envelope.
                eprintln!(
                    "  warning ({}): {}",
                    w["code"].as_str().unwrap_or_default(),
                    w["detail"].as_str().unwrap_or_default()
                );
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
                    vex.vex
                        .as_ref()
                        .expect("vex_statements is Some only when --vex was given")
                        .display(),
                );
            } else if vex.vex.is_some() && common.dry_run {
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

/// Transient-frame boxed constructor for [`run_redirect_selected`] — the
/// future embeds the whole hosted engine, and callers outside scan (`get
/// --mode hosted`) must not materialize it in their own poll frame (Windows
/// 1 MiB main-thread stack; same rationale as scan's `boxed_*` family).
#[allow(clippy::too_many_arguments)]
pub(crate) fn boxed_run_redirect_selected<'a>(
    common: &'a crate::args::GlobalArgs,
    vex: &'a crate::commands::vex::VexEmbedArgs,
    prune_requested: bool,
    api_client: &'a socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&'a str>,
    selected: &'a [(String, String)],
    scan_result: Option<serde_json::Value>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_redirect_selected(
        common,
        vex,
        prune_requested,
        api_client,
        effective_org_slug,
        selected,
        scan_result,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        build_redirect_json_envelope, gem_stale_cache_warning, gem_stale_install_warning,
        gem_stale_install_warnings, gem_stale_positive_evidence, parse_purl_simple,
        plan_workspace_trust, pnpm_heal_root, pnpm_lock_carries_hosted_redirect,
        pnpm_lock_version_major, pnpm_trust_configured_detail, pnpm_trust_legacy_detail,
        pnpm_trust_manual_guidance, pnpm_trust_workspace_unreadable_detail,
        read_workspace_for_trust, TrustPlan, REDIRECT_CANDIDATE_FILES,
    };
    use socket_patch_core::constants::npm_family;
    use socket_patch_core::patch::redirect::DepOverride;

    /// Lock-head version sniff against the byte-real heads the 2026-08-18
    /// matrix captured from pnpm 7/8/9-12: quoted `'9.0'` and `'6.0'`,
    /// unquoted `5.4`; a headless/garbled lock yields `None` (hands-off).
    #[test]
    fn pnpm_lock_version_major_sniffs_real_lock_heads() {
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: '9.0'\n\nsettings:\n"),
            Some(9),
            "pnpm 9-12 emit a quoted '9.0'"
        );
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: '6.0'\n\nsettings:\n"),
            Some(6),
            "pnpm 8 emits a quoted '6.0'"
        );
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: 5.4\n\nspecifiers:\n"),
            Some(5),
            "pnpm 7 emits an unquoted 5.4"
        );
        // Not necessarily the first line (a comment/BOM-damaged head).
        assert_eq!(
            pnpm_lock_version_major("# managed\nlockfileVersion: \"9.0\"\n"),
            Some(9)
        );
        assert_eq!(
            pnpm_lock_version_major("importers:\n  .:\n"),
            None,
            "no version line → None, callers stay hands-off"
        );
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: banana\n"),
            None,
            "unparseable version → None, never a guess"
        );
    }

    /// No pnpm-workspace.yaml → create the root-only scaffold + trust key
    /// (the exact bytes the vendor backend's scaffold precedent uses, with
    /// `trustLockfile: true` in place of the override).
    #[test]
    fn plan_workspace_trust_creates_the_scaffold() {
        match plan_workspace_trust(None) {
            TrustPlan::Create(text) => {
                assert_eq!(text, "packages:\n  - '.'\ntrustLockfile: true\n");
            }
            _ => panic!("no workspace file must plan a Create"),
        }
    }

    /// An existing workspace file gains exactly one line after its last
    /// non-empty line; every other byte — including a trailing blank line and
    /// comments — is preserved so a revert can remove exactly that line.
    #[test]
    fn plan_workspace_trust_appends_preserving_user_bytes() {
        let user = "# team workspace\npackages:\n  - 'apps/*'\n  - 'libs/*'\n\ncatalog:\n  react: ^18.0.0\n";
        match plan_workspace_trust(Some(user)) {
            TrustPlan::Append(text) => {
                assert_eq!(
                    text,
                    "# team workspace\npackages:\n  - 'apps/*'\n  - 'libs/*'\n\ncatalog:\n  react: ^18.0.0\ntrustLockfile: true\n",
                    "one line appended after the last non-empty line, all user bytes intact"
                );
            }
            _ => panic!("a file without the key must plan an Append"),
        }
        // No trailing newline: the file's (lack of) trailing bytes stays put.
        match plan_workspace_trust(Some("packages:\n  - '.'")) {
            TrustPlan::Append(text) => {
                assert_eq!(text, "packages:\n  - '.'\ntrustLockfile: true");
            }
            _ => panic!("expected Append"),
        }
    }

    /// `trustLockfile: true` already present (any quoting) → nothing to do;
    /// an explicit non-true value is the USER's security call and is
    /// respected, never flipped.
    #[test]
    fn plan_workspace_trust_respects_existing_key() {
        for spelled in [
            "packages:\n  - '.'\ntrustLockfile: true\n",
            "trustLockfile: 'true'\npackages:\n  - '.'\n",
            "trustLockfile: \"true\"\n",
        ] {
            assert!(
                matches!(plan_workspace_trust(Some(spelled)), TrustPlan::AlreadyTrue),
                "already-true must be a no-op for {spelled:?}"
            );
        }
        match plan_workspace_trust(Some("packages:\n  - '.'\ntrustLockfile: false\n")) {
            TrustPlan::UserSet(value) => assert_eq!(value, "false"),
            _ => panic!("an explicit false must be respected as UserSet"),
        }
        // An INDENTED trustLockfile under some other mapping is not the
        // top-level setting pnpm reads — it must not be mistaken for one.
        match plan_workspace_trust(Some(
            "catalogMode:\n  trustLockfile: false\npackages:\n  - '.'\n",
        )) {
            TrustPlan::Append(text) => assert!(text.ends_with("trustLockfile: true\n")),
            _ => panic!("an indented key must not block the top-level append"),
        }
    }

    /// The warning variants: the configured text says trust is in place and
    /// installs need no flags; the dry-run text says WOULD; both carry the
    /// whole-lock tradeoff disclosure and the don't-rebuild caution; the
    /// manual-guidance text keeps both verified recoveries. None may leak a
    /// URL authority `@` (the userinfo-stripping contract).
    #[test]
    fn pnpm_trust_warning_variants_carry_the_load_bearing_sentences() {
        let server = "the hosted patch server (patch.test)";
        for created in [true, false] {
            let configured = pnpm_trust_configured_detail(server, created, false);
            assert!(configured.contains("trustLockfile: true"), "{configured}");
            assert!(configured.contains("pnpm-workspace.yaml"), "{configured}");
            assert!(
                configured.contains("commit it alongside the lock"),
                "{configured}"
            );
            assert!(configured.contains("no extra flags"), "{configured}");
            assert!(!configured.contains("would be"), "{configured}");
            let dry = pnpm_trust_configured_detail(server, created, true);
            assert!(dry.contains("would be"), "{dry}");
            assert!(dry.contains("--dry-run"), "{dry}");
            for text in [&configured, &dry] {
                assert!(text.contains("ALL lockfile entries"), "{text}");
                assert!(text.contains("minimumReleaseAge"), "{text}");
                assert!(text.contains("sha512 integrity pins are"), "{text}");
                assert!(text.contains("pnpm clean --lockfile"), "{text}");
                assert!(text.contains("pnpm <=10"), "{text}");
                assert!(
                    text.contains("ERR_PNPM_TARBALL_URL_MISMATCH")
                        && text.contains("ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION"),
                    "{text}"
                );
                assert!(!text.contains('@'), "no URL authority may leak: {text}");
                assert!(!text.contains(".npmrc"), "{text}");
            }
        }
        let manual = pnpm_trust_manual_guidance(server);
        assert!(manual.contains("--trust-lockfile"), "{manual}");
        assert!(
            manual.contains("trustLockfile: true") && manual.contains("pnpm-workspace.yaml"),
            "{manual}"
        );
        assert!(manual.contains("pnpm clean --lockfile"), "{manual}");
        assert!(manual.contains("pnpm <=10"), "{manual}");
        assert!(!manual.contains('@'), "{manual}");
    }

    /// FINDING-10 regression: the legacy-lock (5.x/6.0 — pnpm 7/8) guidance
    /// must NEVER mention `--trust-lockfile` (pnpm 7/8 reject the flag as an
    /// unknown option) nor the `trustLockfile` setting (pnpm 7/8 ignore it);
    /// it must say installs work unchanged with no trust step, keep the
    /// don't-regenerate caution, and leak no URL authority. RED-verified: the
    /// pre-fix manual guidance headlined `pnpm install --trust-lockfile` for
    /// legacy locks, which errors out on pnpm 7/8.
    #[test]
    fn pnpm_trust_legacy_detail_never_recommends_the_trust_flag() {
        let server = "the hosted patch server (patch.test)";
        let legacy = pnpm_trust_legacy_detail(server);
        assert!(
            !legacy.contains("trust-lockfile"),
            "pnpm 7/8 reject --trust-lockfile as an unknown option: {legacy}"
        );
        assert!(
            !legacy.contains("trustLockfile"),
            "pnpm 7/8 ignore the setting — recommending it is noise: {legacy}"
        );
        assert!(legacy.contains("pnpm 7/8"), "{legacy}");
        assert!(legacy.contains("installs work unchanged"), "{legacy}");
        assert!(legacy.contains("no trust step"), "{legacy}");
        // The vulnerable-reinstall caution survives the split: regenerating
        // the lock still silently discards the redirect.
        assert!(legacy.contains("Do NOT regenerate"), "{legacy}");
        assert!(legacy.contains("vulnerable upstream"), "{legacy}");
        assert!(!legacy.contains('@'), "no URL authority may leak: {legacy}");
    }

    /// FINDING-5 regression: a PRESENT-but-unreadable pnpm-workspace.yaml
    /// must classify as `Err` — never as `Ok(None)`, which plans a Create
    /// that overwrites the user's file (destroying their `packages:` globs).
    /// Absent stays `Ok(None)` (the only Create-safe state); readable stays
    /// `Ok(Some)`. RED-verified: the pre-fix `.ok()` collapsed the
    /// invalid-UTF-8 read error below to `None`.
    #[test]
    fn read_workspace_for_trust_distinguishes_unreadable_from_absent() {
        let tmp = tempfile::tempdir().unwrap();
        // Absent → Ok(None).
        assert!(matches!(
            read_workspace_for_trust(&tmp.path().join("pnpm-workspace.yaml")),
            Ok(None)
        ));
        // Readable → Ok(Some(text)).
        let readable = tmp.path().join("readable.yaml");
        std::fs::write(&readable, "packages:\n  - '.'\n").unwrap();
        assert!(matches!(
            read_workspace_for_trust(&readable),
            Ok(Some(text)) if text.contains("packages")
        ));
        // Invalid UTF-8 → Err(InvalidData), cross-platform.
        let invalid = tmp.path().join("invalid.yaml");
        std::fs::write(&invalid, b"packages:\n  - 'apps/*'\n\xff\xfe\x80").unwrap();
        let err = read_workspace_for_trust(&invalid)
            .expect_err("invalid UTF-8 must classify as Err, never as absent→Create");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // chmod 000 (unix): PermissionDenied → Err. Root ignores mode bits,
        // so only the failing-read outcome is asserted strictly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = tmp.path().join("locked.yaml");
            std::fs::write(&locked, "packages:\n  - '.'\n").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            match read_workspace_for_trust(&locked) {
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
                // Running as root: mode bits don't apply; the invalid-UTF-8
                // case above already proved the Err classification.
                Ok(Some(_)) => {}
                Ok(None) => panic!("an unreadable file must never classify as absent"),
            }
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // The fallback detail names the file, the error, and both manual
        // recoveries — and never plans a write (it returns prose only).
        let server = "the hosted patch server (patch.test)";
        let detail = pnpm_trust_workspace_unreadable_detail(
            server,
            &std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
        );
        assert!(detail.contains("pnpm-workspace.yaml"), "{detail}");
        assert!(detail.contains("could not be read"), "{detail}");
        assert!(detail.contains("permission denied"), "{detail}");
        assert!(detail.contains("left untouched"), "{detail}");
        assert!(
            detail.contains("--trust-lockfile") && detail.contains("trustLockfile: true"),
            "{detail}"
        );
        assert!(detail.contains("pnpm clean --lockfile"), "{detail}");
    }

    fn npm_override(artifact_url: &str) -> DepOverride {
        DepOverride {
            ecosystem: "npm".to_string(),
            name: "in-proc-heal".to_string(),
            namespace: None,
            version: "1.0.0".to_string(),
            token: "tok".to_string(),
            patch_uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            artifact_url: artifact_url.to_string(),
            berry_zip_url: None,
            registry_override: None,
            integrity: Default::default(),
        }
    }

    /// FINDING-6 regression (heal-on-rerun probe): a root lock ALREADY
    /// carrying a granted hosted artifact URL from an earlier run — raw,
    /// `\/`-escaped, or percent-encoded — is detected even when this run
    /// spliced nothing, so the trust config can be (re)planned for a project
    /// that missed it (opted-out first run, or a crash between the lock
    /// write and the workspace write). A pristine lock, and a lock whose
    /// only match is a NON-npm override's URL, must stay undetected.
    #[test]
    fn pnpm_lock_carries_hosted_redirect_detects_prior_run_splices() {
        let url = "http://patch.test/patch/npm/in-proc-heal/1.0.0/tok/uuid/in-proc-heal-1.0.0.tgz";
        let mut cargo = npm_override("http://patch.test/crates/heal-1.0.0.crate");
        cargo.ecosystem = "cargo".to_string();
        let overrides = vec![npm_override(url), cargo];

        // The exact splice shape an earlier run wrote (heal-on-rerun with a
        // pre-redirected lock and a missing workspace file: this probe is
        // what re-engages the trust planning on the re-scan).
        let redirected = format!(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );
        assert!(pnpm_lock_carries_hosted_redirect(&redirected, &overrides));

        // The percent-encoded spelling counts too (same predicate set as the
        // confirmation probe).
        let encoded = socket_patch_core::utils::uri::encode_uri_component(url);
        let encoded_lock = format!("lockfileVersion: '9.0'\npackages:\n  x: {encoded}\n");
        assert!(pnpm_lock_carries_hosted_redirect(&encoded_lock, &overrides));

        // Pristine lock: nothing to heal.
        assert!(!pnpm_lock_carries_hosted_redirect(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {integrity: sha512-UPSTREAM==}\n",
            &overrides
        ));

        // A non-npm override's URL in the text is not a pnpm redirect.
        assert!(!pnpm_lock_carries_hosted_redirect(
            "lockfileVersion: '9.0'\n# http://patch.test/crates/heal-1.0.0.crate\n",
            &overrides
        ));

        // No grants at all → never engages.
        assert!(!pnpm_lock_carries_hosted_redirect(&redirected, &[]));
    }

    /// FINDING-6 regression (heal-on-rerun gate, the production
    /// `pnpm_heal_root` wiring): a re-scan that spliced NOTHING over a
    /// pre-redirected root v9 lock with a MISSING pnpm-workspace.yaml must
    /// engage the trust block (heal → plan Create), while a legacy
    /// pre-redirected lock, an unparseable-version lock, a pristine lock,
    /// and a root lock this run DID splice all stay out of the heal path.
    /// RED-verified by construction: the pre-fix trigger was
    /// `!spliced.is_empty()` alone, i.e. this gate always answered None.
    #[test]
    fn pnpm_heal_root_re_engages_trust_planning_for_pre_redirected_v9_locks() {
        let url = "http://patch.test/patch/npm/in-proc-heal/1.0.0/tok/uuid/in-proc-heal-1.0.0.tgz";
        let overrides = vec![npm_override(url)];
        let redirected_v9 = format!(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );

        // The heal scenario: nothing spliced this run, root lock already
        // redirected, workspace file missing → the gate engages and the
        // planning it feeds produces the Create the crashed/opted-out first
        // run never wrote.
        let healed = pnpm_heal_root(false, Some(&redirected_v9), &overrides)
            .expect("a pre-redirected root v9 lock must re-engage the trust block");
        assert_eq!(healed, &redirected_v9);
        assert!(
            matches!(plan_workspace_trust(None), TrustPlan::Create(_)),
            "with the workspace file missing, the healed run must plan the Create"
        );

        // Root lock spliced THIS run: the splice path covers it — no heal.
        assert!(pnpm_heal_root(true, Some(&redirected_v9), &overrides).is_none());

        // Pristine v9 lock (no redirect landed): nothing to heal.
        let pristine = "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
                        resolution: {integrity: sha512-UPSTREAM==}\n"
            .to_string();
        assert!(pnpm_heal_root(false, Some(&pristine), &overrides).is_none());

        // Legacy pre-redirected lock: pnpm 7/8 need no trust config — the
        // heal gate must not drag a 5.x/6.0 lock into the v9 auto-config.
        let redirected_v6 = format!(
            "lockfileVersion: '6.0'\n\npackages:\n  /in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );
        assert!(pnpm_heal_root(false, Some(&redirected_v6), &overrides).is_none());

        // Unparseable version: fail closed, hands off.
        let headless = format!("packages:\n  x:\n    resolution: {{tarball: {url}}}\n");
        assert!(pnpm_heal_root(false, Some(&headless), &overrides).is_none());

        // No root lock at all (e.g. Rush): nothing to heal.
        assert!(pnpm_heal_root(false, None, &overrides).is_none());
    }

    #[test]
    fn parse_purl_simple_percent_decodes_name_and_version() {
        // The API serves canonical percent-encoded purls: npm build metadata
        // `1.2.3+build` arrives as `1.2.3%2Bbuild`. Lock entries store the
        // decoded form, so an undecoded version silently matches nothing.
        assert_eq!(
            parse_purl_simple("pkg:npm/foo@1.2.3%2Bbuild"),
            Some((
                "npm".to_string(),
                "foo".to_string(),
                "1.2.3+build".to_string()
            ))
        );
        // The coordinate keeps decoding too (scoped npm name).
        assert_eq!(
            parse_purl_simple("pkg:npm/%40scope/name@1.0.0"),
            Some((
                "npm".to_string(),
                "@scope/name".to_string(),
                "1.0.0".to_string()
            ))
        );
        // Plain versions pass through unchanged.
        assert_eq!(
            parse_purl_simple("pkg:npm/left-pad@1.3.0"),
            Some((
                "npm".to_string(),
                "left-pad".to_string(),
                "1.3.0".to_string()
            ))
        );
    }

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

    // ── gem stale-install probe (redirect_gem_stale_install) ──────────
    //
    // Defect facts + verified/disproven remedies live in CLI_CONTRACT.md's
    // "Gem stale-install guard" section; these tests pin the probe's
    // judgment rules and the warning wording's load-bearing parts.

    use std::path::PathBuf;

    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};

    const GEM_UUID: &str = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d";
    const GEM_PURL: &str = "pkg:gem/stale-unit@1.0.0";
    const GEM_LEAF: &str = "stale-unit-1.0.0";
    const GEM_UPSTREAM: &[u8] = b"module StaleUnit; STATUS = :vulnerable; end\n";
    const GEM_PATCHED: &[u8] = b"module StaleUnit; STATUS = :patched; end\n";

    fn gem_record() -> PatchRecord {
        gem_record_with(GEM_UUID, GEM_UPSTREAM, GEM_PATCHED)
    }

    fn gem_record_with(uuid: &str, before: &[u8], after: &[u8]) -> PatchRecord {
        let mut files = std::collections::HashMap::new();
        files.insert(
            "lib/stale_unit.rb".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(before),
                after_hash: compute_git_sha256_from_bytes(after),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: std::collections::HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: "free".to_string(),
        }
    }

    /// Bundler's deployment gem home under `cwd`, built COMPONENT-WISE —
    /// the same join operations the crawler uses, so `display()` matches
    /// the production paths byte-for-byte on every platform (embedded
    /// `a/b/c` literals diverge from Windows' backslash joins).
    fn gem_home(cwd: &std::path::Path) -> PathBuf {
        cwd.join("vendor").join("bundle").join("ruby").join("3.3.0")
    }

    /// Materialize the gem in the deployment layout (installed dir + cached
    /// .gem + specifications entry — what a real `bundle install` leaves).
    /// Returns the installed gem dir.
    fn materialize_gem(cwd: &std::path::Path, lib: &[u8]) -> PathBuf {
        let home = gem_home(cwd);
        let gem_dir = home.join("gems").join(GEM_LEAF);
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::write(gem_dir.join("lib").join("stale_unit.rb"), lib).unwrap();
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(
            home.join("cache").join(format!("{GEM_LEAF}.gem")),
            b"upstream .gem",
        )
        .unwrap();
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications")
                .join(format!("{GEM_LEAF}.gemspec")),
            b"#",
        )
        .unwrap();
        gem_dir
    }

    fn one_confirmed() -> Vec<(String, String)> {
        vec![(GEM_PURL.to_string(), GEM_UUID.to_string())]
    }

    fn one_record() -> std::collections::BTreeMap<String, PatchRecord> {
        let mut records = std::collections::BTreeMap::new();
        records.insert(GEM_PURL.to_string(), gem_record());
        records
    }

    /// Probe invocation with the default surface (project-local discovery,
    /// no ledger fallback, no artifact shas) — tests override the knobs
    /// they exercise.
    async fn probe(
        cwd: &std::path::Path,
        confirmed: &[(String, String)],
        records: &std::collections::BTreeMap<String, PatchRecord>,
    ) -> super::GemStaleOutcome {
        gem_stale_install_warnings(
            cwd,
            false,
            None,
            confirmed,
            records,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        )
        .await
    }

    fn detail_of(w: &serde_json::Value) -> &str {
        assert_eq!(w["code"], "redirect_gem_stale_install");
        w["detail"].as_str().expect("detail is a string")
    }

    /// PROJECT-LOCAL flavor: names the purl and all three stale paths —
    /// each built with the same joins production uses, so this holds on
    /// Windows' backslash-joined paths too — steers away from the
    /// empirically disproven `--force`/`--redownload`, and prescribes the
    /// verified removal + `bundle install` remedy.
    #[test]
    fn gem_stale_install_warning_project_local_names_paths_and_remedy() {
        let cwd = PathBuf::from("proj");
        let home = gem_home(&cwd);
        let gem_dir = home.join("gems").join(GEM_LEAF);
        let w = gem_stale_install_warning(GEM_PURL, &gem_dir, GEM_LEAF, &cwd, None);
        let detail = detail_of(&w);
        assert!(detail.contains(GEM_PURL), "{detail}");
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
        let cache = home.join("cache").join(format!("{GEM_LEAF}.gem"));
        let spec = home
            .join("specifications")
            .join(format!("{GEM_LEAF}.gemspec"));
        assert!(detail.contains(&cache.display().to_string()), "{detail}");
        assert!(detail.contains(&spec.display().to_string()), "{detail}");
        assert!(detail.contains("UNPATCHED"), "{detail}");
        assert!(
            detail.contains("--force") && detail.contains("--redownload"),
            "the disproven flags must be steered away from: {detail}"
        );
        assert!(
            detail.contains("Remove the stale materialization")
                && detail.contains("`bundle install`"),
            "the verified remedy must be prescribed: {detail}"
        );
        assert!(
            !detail.contains("shared gem home"),
            "a project-local dir must not get the shared-home caveat: {detail}"
        );
    }

    /// SHARED-HOME flavor: a materialization outside the project must NOT
    /// get an unconditional delete prescription — the home is shared by
    /// every project on the machine — and must prefer the project-local
    /// bundle-path migration instead.
    #[test]
    fn gem_stale_install_warning_shared_home_prefers_local_path_over_deletion() {
        let cwd = PathBuf::from("proj");
        let home = PathBuf::from("shared-gem-home").join("ruby").join("3.3.0");
        let gem_dir = home.join("gems").join(GEM_LEAF);
        let w = gem_stale_install_warning(GEM_PURL, &gem_dir, GEM_LEAF, &cwd, None);
        let detail = detail_of(&w);
        assert!(detail.contains("shared gem home"), "{detail}");
        assert!(
            detail.contains("bundle config set --local path"),
            "the shared flavor must prefer the project-local migration: {detail}"
        );
        assert!(
            detail.contains("only if no other project relies"),
            "shared files must never get an unconditional delete: {detail}"
        );
        assert!(
            !detail.contains("Remove the stale materialization —"),
            "the unconditional delete-list phrasing is project-local only: {detail}"
        );
        // The paths are still named (inside the conditional clause).
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
    }

    /// A committed project `vendor/cache` archive passed by the caller joins
    /// the delete list — bundler installs from it in preference to fetching,
    /// so a remedy that leaves it behind silently reinstates stale bytes.
    #[test]
    fn gem_stale_install_warning_folds_project_cache_into_delete_list() {
        let cwd = PathBuf::from("proj");
        let gem_dir = gem_home(&cwd).join("gems").join(GEM_LEAF);
        let committed = cwd
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        let w = gem_stale_install_warning(GEM_PURL, &gem_dir, GEM_LEAF, &cwd, Some(&committed));
        let detail = detail_of(&w);
        assert!(
            detail.contains(&committed.display().to_string()),
            "the committed cache archive must be in the delete list: {detail}"
        );
    }

    /// Staleness needs POSITIVE evidence — readable bytes hashing to
    /// something other than afterHash. Missing files, unreadable paths
    /// (a directory where a file is expected — the same NotFound that IO
    /// errors fold into), and absent new-files are never evidence: a
    /// transiently unreadable file in a patched install must not produce
    /// a delete prescription.
    #[tokio::test]
    async fn gem_stale_positive_evidence_requires_readable_mismatched_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let record = gem_record();

        // Pristine upstream bytes → evidence.
        let upstream = tmp.path().join("upstream");
        std::fs::create_dir_all(upstream.join("lib")).unwrap();
        std::fs::write(upstream.join("lib").join("stale_unit.rb"), GEM_UPSTREAM).unwrap();
        assert!(gem_stale_positive_evidence(&upstream, &record).await);

        // Tampered bytes (neither hash) → evidence.
        let tampered = tmp.path().join("tampered");
        std::fs::create_dir_all(tampered.join("lib")).unwrap();
        std::fs::write(tampered.join("lib").join("stale_unit.rb"), b"other").unwrap();
        assert!(gem_stale_positive_evidence(&tampered, &record).await);

        // Patched bytes → no evidence.
        let patched = tmp.path().join("patched");
        std::fs::create_dir_all(patched.join("lib")).unwrap();
        std::fs::write(patched.join("lib").join("stale_unit.rb"), GEM_PATCHED).unwrap();
        assert!(!gem_stale_positive_evidence(&patched, &record).await);

        // Missing file → no evidence (never a guess).
        let hollow = tmp.path().join("hollow");
        std::fs::create_dir_all(hollow.join("lib")).unwrap();
        assert!(!gem_stale_positive_evidence(&hollow, &record).await);

        // A DIRECTORY at the file path (the unreadable-NotFound class) →
        // no evidence.
        let blocked = tmp.path().join("blocked");
        std::fs::create_dir_all(blocked.join("lib").join("stale_unit.rb")).unwrap();
        assert!(!gem_stale_positive_evidence(&blocked, &record).await);

        // Absent new-file (empty beforeHash routes to Ready with NO
        // current_hash) → no evidence.
        let mut new_file = gem_record();
        new_file
            .files
            .get_mut("lib/stale_unit.rb")
            .expect("fixture file entry")
            .before_hash = String::new();
        assert!(!gem_stale_positive_evidence(&hollow, &new_file).await);
    }

    /// The probe end to end over a real deployment layout: a STALE
    /// materialization of a confirmed gem redirect produces exactly one
    /// warning naming the on-disk paths and lands the purl in
    /// `stale_purls` (the same-run `--vex` exclusion set); already-patched,
    /// missing-record, zero-file-record, missing-file, and non-gem inputs
    /// all stay silent; and the probe never touches the tree.
    #[tokio::test]
    async fn gem_stale_install_warnings_probe_end_to_end() {
        let confirmed = one_confirmed();
        let records = one_record();

        // STALE: upstream bytes materialized → one warning, real paths named.
        let stale = tempfile::tempdir().unwrap();
        let gem_dir = materialize_gem(stale.path(), GEM_UPSTREAM);
        let out = probe(stale.path(), &confirmed, &records).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "one stale materialization, one warning"
        );
        let detail = detail_of(&out.warnings[0]);
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
        let home = gem_home(stale.path());
        let cache = home.join("cache").join(format!("{GEM_LEAF}.gem"));
        let spec = home
            .join("specifications")
            .join(format!("{GEM_LEAF}.gemspec"));
        assert!(detail.contains(&cache.display().to_string()), "{detail}");
        assert!(detail.contains(&spec.display().to_string()), "{detail}");
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()]),
            "the stale purl must be returned structurally for the vex exclusion"
        );
        // Read-only: the stale tree is intact after the probe.
        assert_eq!(
            std::fs::read(gem_dir.join("lib").join("stale_unit.rb")).unwrap(),
            GEM_UPSTREAM
        );
        assert!(cache.is_file() && spec.is_file(), "probe must not delete");

        // PATCHED: every record file at afterHash → silent (the
        // cannot-false-positive contract; agent-mode applies leave exactly
        // this state with an upstream cache .gem beside it).
        let patched = tempfile::tempdir().unwrap();
        materialize_gem(patched.path(), GEM_PATCHED);
        let out = probe(patched.path(), &confirmed, &records).await;
        assert!(out.warnings.is_empty(), "patched install must never warn");
        assert!(out.stale_purls.is_empty());

        // MISSING RECORD (fresh AND ledger): no afterHash map, no judgment.
        let none = std::collections::BTreeMap::new();
        let out = probe(stale.path(), &confirmed, &none).await;
        assert!(out.warnings.is_empty());

        // ZERO-FILE RECORD: nothing to hash → silent, never a guess.
        let mut hollow_records = std::collections::BTreeMap::new();
        let mut hollow = gem_record();
        hollow.files.clear();
        hollow_records.insert(GEM_PURL.to_string(), hollow);
        let out = probe(stale.path(), &confirmed, &hollow_records).await;
        assert!(out.warnings.is_empty());

        // NON-GEM confirmed purls never engage the probe.
        let npm_confirmed = vec![("pkg:npm/x@1.0.0".to_string(), GEM_UUID.to_string())];
        let out = probe(stale.path(), &npm_confirmed, &records).await;
        assert!(out.warnings.is_empty());
    }

    /// FALSE-POSITIVE hardening: an install whose record file is MISSING
    /// (or unreadable — same NotFound class) is not positive evidence, so
    /// the probe stays quiet instead of prescribing deletion on a tree it
    /// could not actually read.
    #[tokio::test]
    async fn gem_stale_probe_never_warns_without_positive_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let gem_dir = materialize_gem(tmp.path(), GEM_UPSTREAM);
        std::fs::remove_file(gem_dir.join("lib").join("stale_unit.rb")).unwrap();
        let out = probe(tmp.path(), &one_confirmed(), &one_record()).await;
        assert!(
            out.warnings.is_empty(),
            "a missing/unreadable file is never staleness evidence: {:?}",
            out.warnings
        );
        assert!(out.stale_purls.is_empty());
    }

    /// Records are found BY UUID — the fetch key, stable across purl
    /// spellings — so a record keyed under a qualified purl still judges
    /// the bare confirmed purl.
    #[tokio::test]
    async fn gem_stale_probe_record_lookup_is_uuid_keyed() {
        let stale = tempfile::tempdir().unwrap();
        materialize_gem(stale.path(), GEM_UPSTREAM);
        let mut records = std::collections::BTreeMap::new();
        records.insert(format!("{GEM_PURL}?platform=ruby"), gem_record());
        let out = probe(stale.path(), &one_confirmed(), &records).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "the uuid lookup must find the record under any purl spelling"
        );
    }

    /// RE-FIRE guarantee: when this run's record fetch failed (fresh records
    /// empty) the probe falls back to the redirect ledger's persisted
    /// records, so a transient /patches/view failure cannot silently retire
    /// the warning while the stale materialization is still there.
    #[tokio::test]
    async fn gem_stale_probe_falls_back_to_ledger_records() {
        let stale = tempfile::tempdir().unwrap();
        materialize_gem(stale.path(), GEM_UPSTREAM);
        let fresh = std::collections::BTreeMap::new();
        let out = gem_stale_install_warnings(
            stale.path(),
            false,
            None,
            &one_confirmed(),
            &fresh,
            &one_record(), // the ledger snapshot
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert_eq!(
            out.warnings.len(),
            1,
            "the ledger records must keep the warning firing across flaky fetches"
        );
    }

    /// `--global-prefix` discovery parity: the probe threads the run's
    /// global surface into the crawler exactly like scan's own discovery,
    /// so a stale materialization in the prefix store is found too.
    #[tokio::test]
    async fn gem_stale_probe_honors_global_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        // The prefix IS a gems dir (the crawler's global_prefix contract).
        let store = tmp.path().join("prefix-store").join("gems");
        let gem_dir = store.join(GEM_LEAF);
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::write(gem_dir.join("lib").join("stale_unit.rb"), GEM_UPSTREAM).unwrap();
        let out = gem_stale_install_warnings(
            &cwd,
            true,
            Some(store.clone()),
            &one_confirmed(),
            &one_record(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert_eq!(
            out.warnings.len(),
            1,
            "the global-prefix store must be probed like scan's own discovery"
        );
        let detail = detail_of(&out.warnings[0]);
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
        assert!(
            detail.contains("shared gem home"),
            "a store outside the project gets the shared-home flavor: {detail}"
        );
    }

    /// PLATFORM-VARIANT guard: multiple confirmed purls of one gem resolve
    /// to the same installed dir; when ANY of their records judges the dir
    /// fully patched, the dir is patched — the sibling record's stale
    /// judgment must not warn.
    #[tokio::test]
    async fn gem_stale_probe_variant_records_stay_quiet_when_any_judges_patched() {
        const UUID_B: &str = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e";
        let tmp = tempfile::tempdir().unwrap();
        // On disk: content X.
        materialize_gem(tmp.path(), GEM_PATCHED);
        // Record A (uuid GEM_UUID): afterHash == hash(X) → judges PATCHED.
        // Record B (uuid B): beforeHash == hash(X), different afterHash →
        // judges positive-stale.
        let mut records = std::collections::BTreeMap::new();
        records.insert(GEM_PURL.to_string(), gem_record());
        records.insert(
            format!("{GEM_PURL}?platform=java"),
            gem_record_with(UUID_B, GEM_PATCHED, b"some other patched bytes"),
        );
        let confirmed = vec![
            (GEM_PURL.to_string(), GEM_UUID.to_string()),
            (format!("{GEM_PURL}?platform=java"), UUID_B.to_string()),
        ];
        let out = probe(tmp.path(), &confirmed, &records).await;
        assert!(
            out.warnings.is_empty(),
            "any variant judging the dir patched must suppress the warning: {:?}",
            out.warnings
        );
        assert!(out.stale_purls.is_empty());
    }

    /// Committed `vendor/cache` handling, folded flavor: a stale install
    /// whose project also commits `vendor/cache/<leaf>.gem` gets that
    /// archive in the SAME delete list — bundler installs from it first,
    /// so a remedy that leaves it behind silently reinstates stale bytes.
    #[tokio::test]
    async fn gem_stale_probe_folds_committed_vendor_cache_into_the_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        materialize_gem(tmp.path(), GEM_UPSTREAM);
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, b"upstream archive bytes").unwrap();
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64), // the patched artifact's sha — differs
        );
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &std::collections::BTreeMap::new(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "one warning, cache folded in");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&committed.display().to_string()),
            "the committed archive must join the delete list: {detail}"
        );
    }

    /// Committed `vendor/cache` handling, standalone flavor: a fresh
    /// checkout (no installed dir at all) whose committed archive hashes to
    /// something other than the patched artifact still warns — bundler
    /// installs from vendor/cache first, so that checkout materializes
    /// stale bytes forever. The PATCHED archive, an unknown artifact sha,
    /// and an absent archive all stay quiet.
    #[tokio::test]
    async fn gem_stale_probe_warns_on_stale_committed_vendor_cache_without_install() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        let stale_bytes: &[u8] = b"upstream archive bytes";
        std::fs::write(&committed, stale_bytes).unwrap();
        let key = ("stale-unit".to_string(), "1.0.0".to_string());
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(key.clone(), "0".repeat(64));

        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &std::collections::BTreeMap::new(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "stale committed cache must warn");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&committed.display().to_string()),
            "{detail}"
        );
        assert!(detail.contains("bundle cache"), "{detail}");
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()])
        );

        // The PATCHED archive (sha matches) is a healthy commit — quiet.
        let mut patched_shas = std::collections::BTreeMap::new();
        patched_shas.insert(key, hex::encode(Sha256::digest(stale_bytes)));
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &std::collections::BTreeMap::new(),
            &patched_shas,
        )
        .await;
        assert!(out.warnings.is_empty(), "a patched archive must not warn");

        // No artifact sha known → no sound judgment → quiet.
        let out = probe(tmp.path(), &one_confirmed(), &one_record()).await;
        assert!(out.warnings.is_empty(), "unknown sha must never guess");

        // Archive absent → quiet.
        std::fs::remove_file(&committed).unwrap();
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64),
        );
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &std::collections::BTreeMap::new(),
            &shas,
        )
        .await;
        assert!(out.warnings.is_empty());
    }

    /// The standalone cache-flavor warning's load-bearing wording.
    #[test]
    fn gem_stale_cache_warning_names_archive_and_remedy() {
        let cache = PathBuf::from("proj")
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        let w = gem_stale_cache_warning(GEM_PURL, &cache);
        let detail = detail_of(&w);
        assert!(detail.contains(GEM_PURL), "{detail}");
        assert!(detail.contains(&cache.display().to_string()), "{detail}");
        assert!(detail.contains("UNPATCHED"), "{detail}");
        assert!(detail.contains("fresh checkouts included"), "{detail}");
        assert!(
            detail.contains("`bundle install`") && detail.contains("bundle cache"),
            "{detail}"
        );
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
