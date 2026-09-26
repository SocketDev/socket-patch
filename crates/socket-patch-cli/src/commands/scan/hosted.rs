//! The hosted-mode (`--mode hosted` / `--redirect`) flow: rewrite ONLY the
//! patched dependencies' lockfile / registry-config entries to point at
//! Socket's hosted vendored patches. Self-contained — reuses `run`'s
//! discovery, then returns without touching the apply/vendor branches.

use std::path::Path;
use std::time::Duration;

use socket_patch_core::api::types::BatchPackagePatches;
use socket_patch_core::patch::apply_lock::LockGuard;
use socket_patch_core::patch::redirect::DepOverride;
use socket_patch_core::utils::purl::purl_parts;

use crate::commands::vex::generate_vex_from_manifest_path;

use super::{discover_selected, ScanArgs};

mod python;

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to `rewrite_registry_redirect`.
/// Fragment-edit kinds whose lockfile the package manager re-lays in place
/// (keeping the Socket source) — a re-scan REBASES their ledger edits instead
/// of appending; see the ledger merge below.
const REBASE_KINDS: &[&str] = &["redirect_poetry_lock_package", "redirect_pdm_lock_package"];

const REDIRECT_CANDIDATE_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    // pnpm <=2 uses the same package identities under the old filename.
    "shrinkwrap.yaml",
    "node_modules/.modules.yaml",
    "yarn.lock",
    // A berry lock's cache-config gate reads `.yarnrc.yml`; bun's text lock is
    // `bun.lock`; binary locks are read separately below.
    ".yarnrc.yml",
    "bun.lock",
    "bun.lockb",
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "hatch.toml",
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
        "The pnpm lockfile was repointed at {server}. This is a legacy \
         lock read by pnpm 1–8, which have no \
         lockfile trust policy: no trust step exists or is needed. Do NOT regenerate the lockfile \
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
///
/// FIFO-safe (`read_regular_to_string_sync`: non-blocking open + fstat): a
/// FIFO planted at the path classifies as unreadable (`InvalidInput`) instead
/// of wedging the run in `open(2)`.
fn read_workspace_for_trust(path: &std::path::Path) -> std::io::Result<Option<String>> {
    match socket_patch_core::utils::fs::read_regular_to_string_sync(path) {
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
        (true, true) => "`trustLockfile: true` would be written to a new",
        (false, true) => "`trustLockfile: true` would be merged into the existing",
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

/// Whether a pnpm lock may belong to pnpm 1–4, which spell the store flag
/// `--store` (pnpm 1–3 can silently ignore `--store-dir`; early pnpm 4
/// rejects it): a `shrinkwrapVersion` lock (pnpm 1–2) or lockfileVersion
/// 5.0–5.2 (pnpm 3–5). Later locks never get the `--store` note.
fn pnpm_lock_may_need_store_flag(lock_text: &str) -> bool {
    lock_text.lines().any(|line| {
        if line.starts_with("shrinkwrapVersion:") {
            return true;
        }
        let Some(rest) = line.strip_prefix("lockfileVersion:") else {
            return false;
        };
        let value = rest.trim().trim_matches(|c| c == '\'' || c == '"');
        let mut parts = value.split('.');
        let major = parts.next().and_then(|m| m.parse::<u32>().ok());
        let minor = parts
            .next()
            .and_then(|m| m.parse::<u32>().ok())
            .unwrap_or(0);
        major == Some(5) && minor <= 2
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

/// The root npm locks the hosted rewriter edits (`rewrite_npm_lock` rewrites
/// every one present — npm 12 installs from package-lock.json beside a
/// committed shrinkwrap).
const NPM_LOCKS: [&str; 2] = ["npm-shrinkwrap.json", "package-lock.json"];

/// The honest-tradeoff + opt-out tail shared by every `allow-remote`
/// warning variant. The tradeoff sentence is a security disclosure, not
/// prose garnish: `allow-remote=all` lifts npm 12's remote-tarball refusal
/// for the WHOLE dependency tree, so it must be stated wherever the setting
/// is written or recommended (the pnpm `trustLockfile` precedent).
const NPM_ALLOW_REMOTE_TRADEOFF: &str =
    "Note: allow-remote=all lets npm install ANY url-resolved (remote tarball) \
     dependency, not just the patched ones Socket serves — the per-entry sha512 \
     integrity pins are still enforced. `allow-remote=root` only admits direct \
     dependencies. npm <=11 installs work unchanged (npm 11 already defaults to \
     `all`; npm <=10 has no such setting)";

/// The policy preamble shared by every `allow-remote` warning variant: what
/// was repointed, and how npm >= 12 fails without the setting.
fn npm_allow_remote_preamble(hosts: &[&str]) -> String {
    format!(
        "the npm lockfile now resolves patched dependencies from the hosted patch server ({}); \
         npm >=12 refuses tarballs from any host other than the configured registry by \
         default (`allow-remote=none`, error EALLOWREMOTE)",
        hosts.join(", ")
    )
}

/// The auto-config variant: `allow-remote=all` was (or, on `--dry-run`,
/// would be) written to the project `.npmrc`, so installs need no flags.
fn npm_allow_remote_configured_detail(hosts: &[&str], created: bool, dry_run: bool) -> String {
    let how = match (created, dry_run) {
        (true, false) => "`allow-remote=all` was written to a new",
        (false, false) => "`allow-remote=all` was appended to the existing",
        (true, true) => "`allow-remote=all` would be written to a new",
        (false, true) => "`allow-remote=all` would be appended to the existing",
    };
    format!(
        "{}, so {how} project .npmrc — commit it alongside the lock; `npm ci` needs no \
         extra flags. {NPM_ALLOW_REMOTE_TRADEOFF}. To keep npm's default instead, re-run \
         with --no-npm-allow-remote-config (SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG) and install \
         with `npm ci --allow-remote=all`",
        npm_allow_remote_preamble(hosts),
    )
}

/// The project `.npmrc` already resolves to `allow-remote=all`.
fn npm_allow_remote_already_detail(hosts: &[&str]) -> String {
    format!(
        "{}, and the project .npmrc already sets `allow-remote=all` — keep it committed \
         alongside the lock; `npm ci` needs no extra flags. {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
    )
}

/// The user explicitly set another value: respected, never flipped (the
/// pnpm `trustLockfile: false` precedent) — the warning names the manual
/// recoveries instead.
fn npm_allow_remote_user_set_detail(hosts: &[&str], value: &str) -> String {
    format!(
        "{}. The project .npmrc explicitly sets `allow-remote={value}`, which was respected \
         and left untouched — set `allow-remote=all` there yourself (or install with \
         `npm ci --allow-remote=all`) so npm >=12 installs the patched artifacts. \
         {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
    )
}

/// An `npm_config_allow_remote` environment variable sets another value.
/// npm's env layer beats every `.npmrc`, so a project write could not take
/// effect in this environment — and an explicit setting is respected.
fn npm_allow_remote_env_set_detail(hosts: &[&str], var: &str, value: &str) -> String {
    format!(
        "{}. The environment variable {var}={value} explicitly sets `allow-remote`, which \
         was respected: npm's environment layer overrides every .npmrc, so a project \
         `allow-remote=all` would not take effect here and the project .npmrc was left \
         untouched — unset {var} (or install with `npm ci --allow-remote=all`) so npm >=12 \
         installs the patched artifacts. {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
    )
}

/// A lower npm config layer (user / global / builtin file) explicitly sets
/// another value. A committed project `allow-remote=all` would silently
/// override that machine / org policy on every checkout, so it is
/// respected like a project value and the override is left to the user.
fn npm_allow_remote_outer_set_detail(
    hosts: &[&str],
    layer: &str,
    path: &std::path::Path,
    value: &str,
) -> String {
    format!(
        "{}. The {layer} npm config ({}) explicitly sets `allow-remote={value}`, which was \
         respected: socket-patch does not commit a project .npmrc that overrides it, and \
         the project .npmrc was left untouched — to accept the patched artifacts in this \
         project anyway, set `allow-remote=all` in the project .npmrc yourself (it outranks \
         the {layer} config) or install with `npm ci --allow-remote=all`. \
         {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
        path.display(),
    )
}

/// The opt-out (`--no-npm-allow-remote-config`) variant: nothing written,
/// both manual recoveries spelled out.
fn npm_allow_remote_manual_detail(hosts: &[&str]) -> String {
    format!(
        "{}. Commit `allow-remote=all` in the project .npmrc (or install with \
         `npm ci --allow-remote=all`) so npm >=12 installs the patched artifacts. \
         {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
    )
}

/// The unreadable/unsafe `.npmrc` fallback: the file exists but could not
/// be read, or is a symlink / non-regular file the atomic writer would
/// replace. Planning a Create here would OVERWRITE the user's registry /
/// auth config, so the auto-config stands down and names the problem.
fn npm_allow_remote_unreadable_detail(hosts: &[&str], why: &str) -> String {
    format!(
        "{}. The project .npmrc exists but {why}; it was left untouched. Add \
         `allow-remote=all` to it yourself (or install with `npm ci --allow-remote=all`) \
         so npm >=12 installs the patched artifacts. {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
    )
}

/// The project `.npmrc` read, classified for the allow-remote auto-config:
/// `Ok(Some(text))` — a regular file read fine; `Ok(None)` — ABSENT (the
/// only state where planning a Create is safe); `Err(why)` — present but
/// unreadable, a symlink (the atomic stage+rename writer would replace the
/// link with a detached copy — and the whole-run symlink guard would refuse
/// the redirect), or not a regular file (FIFO-safe: never opened blocking).
fn read_npmrc_for_allow_remote(path: &std::path::Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not be inspected ({e})")),
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err("is a symbolic link (socket-patch never writes through one)".into())
        }
        Ok(_) => {}
    }
    socket_patch_core::utils::fs::read_regular_to_string_sync(path)
        .map(Some)
        .map_err(|e| format!("could not be read ({e})"))
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
    emit_json_error_with_code(scan_result, None, message);
}

/// `emit_json_error` plus an additive top-level `errorCode` (the stable
/// routing tag the CLI contract gives every classified failure) when the
/// refusal has one; `error` stays the human message.
fn emit_json_error_with_code(
    scan_result: Option<serde_json::Value>,
    code: Option<&str>,
    message: &str,
) {
    let mut result = scan_result.unwrap_or_else(|| serde_json::json!({ "status": "error" }));
    result["status"] = serde_json::json!("error");
    result["error"] = serde_json::json!(message);
    if let Some(code) = code {
        result["errorCode"] = serde_json::json!(code);
    }
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

/// The nested `redirect` block of every hosted `--json` envelope — the ONE
/// spelling of its key set (`mode`, `redirected`, `rewrittenFiles`,
/// `skipped`, `warnings`, `dryRun`), shared by the ≥1-package path here and
/// the zero-discovery arm in `run`, so the two cannot drift by convention.
/// `mode` is `"hosted"` (the final mode name for `--redirect`): an additive
/// key so consumers dispatch on the mode without inferring it from which
/// sub-object is present.
pub(super) fn redirect_json_block(
    redirected: usize,
    rewritten: Vec<String>,
    skipped: Vec<serde_json::Value>,
    warnings: Vec<serde_json::Value>,
    dry_run: bool,
) -> serde_json::Value {
    serde_json::json!({
        "mode": "hosted",
        "redirected": redirected,
        "rewrittenFiles": rewritten,
        "skipped": skipped,
        "warnings": warnings,
        "dryRun": dry_run,
    })
}

/// The `redirect_prune_ignored` warning object (`--prune` is a no-op in
/// hosted mode; see the constants' doc in `run`'s module).
pub(super) fn prune_ignored_warning() -> serde_json::Value {
    serde_json::json!({
        "code": super::REDIRECT_PRUNE_IGNORED,
        "detail": super::REDIRECT_PRUNE_IGNORED_DETAIL,
    })
}

/// The fail-closed refusal for a symlinked rewrite target (both the general
/// SYMLINK GUARD and the takeover pre-check in [`run_redirect_selected`]):
/// stderr line + `--json` envelope, exit 1. The writers stage next to the
/// path and rename over it, which REPLACES a symbolic link with a detached
/// regular copy — the link target goes stale and a revert restores bytes but
/// never the link — so nothing may be written.
fn refuse_symlinked_file(
    common: &crate::args::GlobalArgs,
    scan_result: Option<serde_json::Value>,
    linked: &str,
) -> i32 {
    let message = format!(
        "{linked} is a symbolic link; socket-patch rewrites files in place with an atomic \
         rename, which would replace the link — replace the link with a regular file (or \
         run socket-patch in the directory it points to) and re-run; nothing was written"
    );
    eprintln!("Error (redirect_symlinked_file_unsupported): {message}");
    if common.json {
        emit_json_error_with_code(
            scan_result,
            Some("redirect_symlinked_file_unsupported"),
            &message,
        );
    }
    1
}

/// The apply lock for a WET hosted run: the same `<manifest dir>/apply.lock`
/// `apply`/`rollback`/`remove`/`vendor` hold, so the takeover pre-reverts,
/// the ledger merge and the lockfile writes never race them. `acquire`
/// creates a missing `.socket/` and the guard's drop unlinks the lock file
/// and prunes an otherwise-empty `.socket/`, so a run that ends up writing
/// nothing leaves no residue. Contention / IO failures render through the
/// shared [`crate::commands::lock_cli::lock_failure`] mapping — the
/// `lock_held` / `lock_io` codes and the "(waited …)" clause match every
/// other mutating command — into the hosted error envelope (NOT
/// `acquire_or_emit`, whose `Envelope` would replace the classic scan / get
/// object) plus the stderr line and, for a live holder, the wait hint.
fn acquire_hosted_lock(
    common: &crate::args::GlobalArgs,
    scan_result: &mut Option<serde_json::Value>,
) -> Result<LockGuard, i32> {
    let socket_dir = common.socket_dir();
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    match crate::commands::lock_cli::acquire_with_status(&socket_dir, timeout) {
        Ok(guard) => Ok(guard),
        Err(err) => {
            let (code, message) = crate::commands::lock_cli::lock_failure(&err, timeout);
            // Errors print even under --silent ("errors only", never
            // "nothing"): exit 1 with no message would be undiagnosable.
            eprint!(
                "{}",
                crate::commands::lock_cli::format_lock_error(&socket_dir, &err, timeout)
            );
            if common.json {
                emit_json_error_with_code(scan_result.take(), Some(code), &message);
            }
            Err(1)
        }
    }
}

/// The installed-tree probes' outcome: warnings for both output channels,
/// plus the stale purls STRUCTURALLY, so the same-run `--vex` can exclude
/// them from `assume_applied` — an envelope must never attest a CVE its own
/// warnings say is live. Python also carries positive evidence through VEX
/// so a different, healthy interpreter cannot mask a stale installation.
#[derive(Default)]
struct StaleInstallOutcome {
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
async fn installed_stale_positive_evidence(
    package_dir: &Path,
    record: &socket_patch_core::manifest::schema::PatchRecord,
) -> bool {
    use socket_patch_core::patch::apply::{verify_file_patch, VerifyStatus};
    for (file_name, info) in &record.files {
        let result = verify_file_patch(package_dir, file_name, info).await;
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
/// * STALE requires [`installed_stale_positive_evidence`] — never inferred from
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
    // This run's fetched records MERGED with the ledger's persisted ones
    // (the caller hands the post-merge ledger map): the persisted half is
    // the fallback judgment source when this run's /patches/view fetch
    // failed transiently, so the warning keeps firing until the stale
    // materialization is gone.
    records: &std::collections::BTreeMap<String, socket_patch_core::manifest::schema::PatchRecord>,
    gem_artifact_shas: &std::collections::BTreeMap<(String, String), String>,
) -> StaleInstallOutcome {
    use socket_patch_core::crawlers::types::CrawlerOptions;
    use socket_patch_core::crawlers::RubyCrawler;
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::vendor::file_sha256_hex;
    use socket_patch_core::vex::verify::verify_patch_record;

    let mut out = StaleInstallOutcome::default();
    let find_record =
        |uuid: &str| -> Option<&PatchRecord> { records.values().find(|r| r.uuid == uuid) };
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
            } else if !entry.positive && installed_stale_positive_evidence(&pkg.path, record).await
            {
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
        let Some((_, name, version)) = purl_parts(purl) else {
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
    purl_parts(purl)
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
        all_packages_with_patches,
        can_access_paid_patches,
        &args.common,
        false,
        false,
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
            } else if code == 0 && !args.common.silent {
                // Exit 0 without an error is the cancelled selection
                // (`Selection cancelled.` already printed).
                eprintln!("Nothing was redirected.");
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
        &pairs,
        scan_result,
    )
    .await
}

/// The hosted-redirect engine over an ALREADY-SELECTED `(purl, uuid)` set:
/// reference grants → DepOverride build → apply lock (wet runs with a grant)
/// → ledger load → vendored→hosted takeover pre-revert (symlink-checked
/// first) → candidate-file read → rewrite → pnpm trust config → npm `.npmrc`
/// allow-remote config →
/// confirmation probe → ledger merge-then-persist → file writes → gem stale
/// probe → warnings → optional VEX. Shared VERBATIM by `scan --mode hosted`
/// — its `--json` arm through the `run_redirect` wrapper (which selects via
/// `discover_selected`), its human arm through
/// [`boxed_run_redirect_selected`] directly, after its own table + confirm
/// prompt (`scan/mod.rs`) — and by `get --mode hosted` (which pins the
/// advisory-resolved uuid), so all produce identical on-disk results for
/// the same selection. The redirect ledger is loaded HERE, under the apply
/// lock whenever this run holds one (never handed in pre-loaded: a copy
/// read before the lock could merge over a concurrent writer's edits); a
/// dry run or a zero-grant run reads it strictly but writes nothing,
/// quarantine included.
///
/// `scan_result` must be `Some` exactly when `common.json` is set (the
/// human/JSON split keys on `common.json`; a `--json` caller passing `None`
/// would get a minimal envelope that drops its own keys). `prune_requested`
/// only feeds the `redirect_prune_ignored` warning — `get` passes `false`.
pub(crate) async fn run_redirect_selected(
    common: &crate::args::GlobalArgs,
    vex: &crate::commands::vex::VexEmbedArgs,
    prune_requested: bool,
    api_client: &socket_patch_core::api::client::ApiClient,
    selected: &[(String, String)],
    mut scan_result: Option<serde_json::Value>,
) -> i32 {
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::patch::redirect::{
        rewrite_registry_redirect_with_pipenv_version, RedirectState,
    };

    let mut skipped: Vec<serde_json::Value> = Vec::new();
    /// One granted reference: the purl it was granted for plus the rewriter
    /// override built from it. The purl is what the takeover, the skip
    /// records and the confirmation probe key on; everything the probe
    /// needs AFTER the rewrite to decide whether the dep was actually
    /// redirected (artifact URL, registry index URL, fail-closed maven's
    /// suffixed version) already rides the override. The single vector is
    /// filtered in place by every withhold/refusal step, and the rewriters'
    /// `overrides` slice is materialized from it once, after the last filter.
    struct Candidate {
        purl: String,
        dep: DepOverride,
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    // The network phases below (reference grants, wheel metadata, patch
    // records) would otherwise be silent gaps on a terminal. Inert under
    // --json/--silent and off a terminal.
    let mut status = crate::ui::StatusLine::stderr(common.json, common.silent);

    if !selected.is_empty() {
        let uuids: Vec<String> = selected.iter().map(|(_, uuid)| uuid.clone()).collect();
        status.set(format!(
            "Resolving hosted artifacts for {}...",
            crate::ui::plural(uuids.len(), "patch", "patches")
        ));
        let fetched = api_client.fetch_registry_references(&uuids).await;
        status.finish();
        let references = match fetched {
            Ok(r) => r,
            Err(e) => {
                let message = format!("failed to resolve patch references: {e}");
                eprintln!(
                    "{} (nothing was changed; re-run to retry)",
                    format_error_line(&message)
                );
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
            let Some((ecosystem, name, version)) = purl_parts(purl) else {
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
            candidates.push(Candidate {
                purl: purl.to_string(),
                dep: DepOverride {
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
                },
            });
        }
    }

    // Text retains Bun's precedence when both lock spellings are present;
    // the takeover reverts rewrite locks in place (never create or remove
    // one), so the probe holds for the binary-lock decision below too.
    let bun_lock_present = common.cwd.join("bun.lock").exists();
    // Check binary lock symlinks before a mode takeover changes any wiring.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && !bun_lock_present
        && socket_patch_core::utils::fs::first_symlink(&common.cwd, ["bun.lockb"])
            .await
            .is_some()
    {
        // Atomic replacement cannot preserve a link; previews refuse too.
        let message = "bun.lockb is a symbolic link; replace it with a regular file (or run \
                       socket-patch in the directory it points to) before patching; nothing \
                       was written";
        eprintln!("Error (redirect_symlinked_file_unsupported): {message}");
        if common.json {
            emit_json_error_with_code(
                scan_result.take(),
                Some("redirect_symlinked_file_unsupported"),
                message,
            );
        }
        return 1;
    }

    // The apply lock (see `acquire_hosted_lock`), taken only by a WET run
    // that holds at least one granted reference — the only runs that can
    // write anything: the takeover pre-reverts (lockfiles + the vendored
    // ledger), the redirect-ledger merge and the lockfile writes. Dry runs
    // and zero-grant runs never touch `.socket/`, so they never lock (a
    // preview must not create `.socket/`, flip to `lock_held` under a
    // concurrent wet run, or fail on a read-only checkout). Acquired BEFORE
    // the ledger load so load → merge → persist is one critical section
    // (rollback's rule: a ledger a run will persist is loaded under the
    // lock) and held to the end of the function. Read below: it also gates
    // the corrupt-ledger quarantine, the one write the load itself can make.
    let lock: Option<LockGuard> = if !common.dry_run && !candidates.is_empty() {
        match acquire_hosted_lock(common, &mut scan_result) {
            Ok(guard) => Some(guard),
            Err(code) => return code,
        }
    } else {
        None
    };

    // Load the existing redirect ledger before any file changes, including
    // Cargo takeover reverts. It stores the originals a future revert needs, so
    // a malformed (torn/hand-mangled) ledger must abort the run while the
    // project is still untouched: the old tolerant load treated it as "no
    // ledger" and the merge below would have started fresh, silently
    // overwriting that revert data. The malformed file is moved aside to
    // redirect-state.json.corrupt (never clobbered) so recovery stays
    // possible. Only a run holding the apply lock moves it: a dry run or a
    // zero-grant run — neither holds the lock, neither would have written
    // anything — reports the same hard error but moves nothing (the message
    // then names the repair-or-move-aside remedy instead of the `.corrupt`
    // path), so no `.socket/vendor/` mutation ever happens lock-free.
    //
    // Held as the ONE in-memory ledger for the whole run: the write below
    // merges into it in place, the stale-install probes read its records
    // (persisted ones included — their fallback judgment source when this
    // run's /patches/view fetch fails transiently: the warning must keep
    // firing until the stale materialization is gone, not until the first
    // flaky fetch), and the takeover classification at the end reads the
    // merged state.
    let mut ledger =
        match socket_patch_core::patch::redirect::load_redirect_state(&common.cwd).await {
            Ok(state) => state.unwrap_or_else(RedirectState::new),
            Err(mut corrupt) => {
                if lock.is_some() {
                    corrupt.quarantine().await;
                }
                let message = corrupt.to_string();
                eprintln!("{}", format_error_line(&message));
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        };
    // The vendored ledger, loaded ONCE per run (under the same lock, so no
    // other writer can move the on-disk file under it): the takeover below
    // mutates it in place per reverted purl (saving after each), and the
    // post-write overlap classification reads that post-takeover state —
    // never a pre-takeover snapshot, which would flag every migrated purl
    // as still vendored. `Err` (unreadable / malformed) is "no vendored
    // ownership known" for both consumers.
    let mut vendor_state = socket_patch_core::vendor::load_state(&common.cwd).await;

    // Cross-mode takeover: a purl this run is about to redirect may still be
    // VENDORED — for cargo a committed `[patch.crates-io]` path entry, a
    // detached Cargo.lock entry, a committed copy, and a vendored ledger
    // entry; for the npm family a `file:./.socket/vendor/…` lock resolution
    // (plus a berry `resolutions` pin) and its committed tarball; for golang
    // the vendor-owned go.mod `replace`, its committed module copy, and its
    // ledger entry (left behind, a later `vendor` run takes the module back
    // and the modes flip-flop). The hosted
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
    let takeover_capable = |p: &str| {
        p.starts_with("pkg:cargo/") || p.starts_with("pkg:npm/") || p.starts_with("pkg:golang/")
    };
    let mut takeover_pre_warnings: Vec<serde_json::Value> = Vec::new();
    // Dry-run takeover previews: `(purl, uuid)` pairs whose vendored state
    // the wet run would revert and then redirect. Withheld from the
    // rewriters (their lock fragments still carry the vendored wiring the
    // wet run reverts FIRST) and counted as redirected below, so the
    // preview's envelope matches the wet run's outcome.
    let mut dry_run_takeover: Vec<(String, String)> = Vec::new();
    // Human output: the purls migrated (or, on --dry-run, to be migrated)
    // from vendored to hosted, and the files their revert touches (or would
    // touch). Both modes count `rewritten ∪ takeover_files`, so the
    // preview's file count matches the wet run's even for wiring files the
    // hosted rewriter does not also rewrite (a Gemfile line, a uv source).
    let mut takeover_migrated: Vec<String> = Vec::new();
    let mut takeover_files: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Which root locks each dry-run takeover purl is vendored into (from
    // its vendor ledger wiring): the wet run reverts that wiring and then
    // splices the hosted URL there, so the install-policy auto-configs
    // (npm `.npmrc` allow-remote, pnpm `trustLockfile`) must be PREVIEWED
    // for those locks even though the rewriters never see these purls.
    let mut dry_run_takeover_locks: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    // `(artifact_url, wired root locks)` of the withheld dry-run takeover
    // candidates — filled when they leave the rewrite set below.
    let mut dry_run_takeover_urls: Vec<(String, Vec<String>)> = Vec::new();
    if !candidates.iter().any(|c| takeover_capable(&c.purl)) {
        // No takeover-capable candidates — nothing to reconcile.
    } else {
        use socket_patch_core::utils::purl::{canonical_purl as canon, strip_purl_qualifiers};
        // Each takeover-capable candidate with its vendored ledger entry, if
        // any (cloned out so the loop can mutate the state).
        let takeover: Vec<(&Candidate, Option<socket_patch_core::vendor::VendorEntry>)> =
            candidates
                .iter()
                .filter(|c| takeover_capable(&c.purl))
                .map(|c| {
                    let entry = vendor_state
                        .as_ref()
                        .ok()
                        .and_then(|s| {
                            socket_patch_core::vendor::lookup_entry(
                                &s.entries,
                                strip_purl_qualifiers(&c.purl),
                            )
                        })
                        .cloned();
                    (c, entry)
                })
                .collect();
        // Compatibility must be known before the takeover removes a live
        // patch. In particular, a v0 workspace can keep an existing local
        // tuple even though hosted mode cannot replace it with a URL. Only
        // an npm purl WITH a vendored entry can be taken over, so the bun
        // locks are read here only when one exists — the candidate-file
        // read below covers every other run.
        let bun_takeover_refusal = if takeover
            .iter()
            .any(|(c, entry)| entry.is_some() && c.purl.starts_with("pkg:npm/"))
        {
            match socket_patch_core::utils::fs::read_regular_to_string(&common.cwd.join("bun.lock"))
                .await
            {
                Ok(content) => {
                    socket_patch_core::patch::redirect::preflight_bun_hosted(&content).err()
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match socket_patch_core::utils::fs::read_regular_to_bytes_sync(
                        &common.cwd.join("bun.lockb"),
                    ) {
                        Ok(bytes) => {
                            socket_patch_core::patch::redirect::preflight_bun_binary(&bytes).err()
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => Some(socket_patch_core::patch::redirect::RewriteWarning {
                            code: "redirect_bun_lockb_invalid".into(),
                            detail: format!("cannot read bun.lockb: {e}"),
                        }),
                    }
                }
                Err(e) => Some(socket_patch_core::patch::redirect::RewriteWarning {
                    code: "redirect_bun_lock_unsupported".into(),
                    detail: format!("cannot read bun.lock before mode takeover: {e}"),
                }),
            }
        } else {
            None
        };
        // Yarn berry twin of the bun gate: the berry rewriter's project-level
        // refusals (mixed line endings, cacheKey, `.yarnrc.yml`
        // compressionLevel) must be known before the takeover reverts a
        // vendored berry purl — the vendored revert keeps a mixed lock mixed
        // (it never refuses on line endings), so reverting first stripped
        // the live vendored patch and then the rewriter refused the lock,
        // leaving the package unpatched in both modes. Only entries the
        // vendor ledger wired through the yarn-berry backend are gated (the
        // lock is read only when one exists); an unreadable lock is left to
        // the revert's own diagnostics.
        let berry_entry = |entry: &socket_patch_core::vendor::VendorEntry| {
            entry.ecosystem == "npm" && entry.flavor.as_deref() == Some("yarn-berry")
        };
        let berry_takeover_refusal = if takeover
            .iter()
            .any(|(_, entry)| entry.as_ref().is_some_and(berry_entry))
        {
            match socket_patch_core::utils::fs::read_regular_to_string(
                &common.cwd.join("yarn.lock"),
            )
            .await
            {
                Ok(lock) => {
                    let yarnrc = socket_patch_core::utils::fs::read_regular_to_string(
                        &common.cwd.join(".yarnrc.yml"),
                    )
                    .await
                    .ok();
                    socket_patch_core::patch::redirect::preflight_yarn_berry_hosted(
                        &lock,
                        yarnrc.as_deref(),
                    )
                    .err()
                }
                Err(_) => None,
            }
        } else {
            None
        };
        // The takeover refusal (if any) for one candidate: bun gates every
        // npm purl, berry only its vendored-berry entries. A refused purl is
        // never dispatched (see the loop), so its wiring is not a write
        // target here.
        let takeover_refusal =
            |c: &Candidate,
             entry: Option<&socket_patch_core::vendor::VendorEntry>|
             -> Option<&socket_patch_core::patch::redirect::RewriteWarning> {
                if !c.purl.starts_with("pkg:npm/") {
                    return None;
                }
                bun_takeover_refusal.as_ref().or_else(|| {
                    berry_takeover_refusal
                        .as_ref()
                        .filter(|_| entry.is_some_and(berry_entry))
                })
            };
        // SYMLINK PRE-CHECK for the takeover reverts — the same rule as the
        // SYMLINK GUARD below, applied to the files the reverts rewrite
        // (each ledger entry's recorded wiring): the revert backends stage
        // and rename over the lock like the rewriters do, so a symlinked
        // package-lock.json would be detached — or a later refusal would
        // find the purl neither vendored nor hosted — before the general
        // guard ever ran. Checked in one pass BEFORE any revert dispatches
        // (and under --dry-run too) so "nothing was written" stays true.
        let revert_targets = takeover
            .iter()
            .filter_map(|(c, entry)| {
                entry
                    .as_ref()
                    .filter(|e| takeover_refusal(c, Some(e)).is_none())
            })
            .flat_map(|entry| entry.wiring.iter().map(|w| w.file.as_str()));
        if let Some(linked) =
            socket_patch_core::utils::fs::first_symlink(&common.cwd, revert_targets).await
        {
            return refuse_symlinked_file(common, scan_result.take(), linked);
        }
        let mut refused: Vec<String> = Vec::new();
        for (candidate, ledger_entry) in &takeover {
            let purl = &candidate.purl;
            let uuid = &candidate.dep.patch_uuid;
            if let Some(entry) = ledger_entry {
                if let Some(warning) = takeover_refusal(candidate, Some(entry)) {
                    refused.push(purl.clone());
                    if !takeover_pre_warnings
                        .iter()
                        .any(|w| w["code"] == warning.code)
                    {
                        takeover_pre_warnings.push(serde_json::json!(warning));
                    }
                    continue;
                }
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
                        crate::commands::vendor::dispatch_revert_one(entry, &common.cwd, true)
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
                    takeover_migrated.push(purl.clone());
                    takeover_files.extend(entry.wiring.iter().map(|w| w.file.clone()));
                    dry_run_takeover_locks.insert(
                        purl.clone(),
                        entry.wiring.iter().map(|w| w.file.clone()).collect(),
                    );
                    continue;
                }
                let outcome =
                    crate::commands::vendor::dispatch_revert_one(entry, &common.cwd, false).await;
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
                // Drop the reverted entry from the in-memory ledger and
                // persist per purl so a crash mid-run leaves a ledger
                // matching the on-disk wiring. The entry stays dropped even
                // when the save fails: its wiring and artifact ARE gone, so
                // a later successful save in this loop writes the truth.
                let state = vendor_state
                    .as_mut()
                    .expect("a vendored ledger entry was looked up in this state, so it loaded");
                state
                    .entries
                    .retain(|k, e| canon(k) != canon(purl) && canon(&e.base_purl) != canon(purl));
                if let Err(e) = socket_patch_core::vendor::save_state(&common.cwd, state).await {
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
                takeover_migrated.push(purl.clone());
                takeover_files.extend(entry.wiring.iter().map(|w| w.file.clone()));
            } else {
                // No usable ledger entry. If socket-owned vendored wiring for
                // this crate is nevertheless present, the ledger is missing or
                // corrupt — the originals needed to revert are unrecoverable,
                // so redirecting on top would wedge the project. Refuse.
                // (Cargo-only probe: Socket-owned `[patch.crates-io]` entries
                // for exactly this name@version in the root Cargo.toml or a
                // legacy `.cargo/config*` — another vendored version of the
                // crate has its own ledger entry. An npm purl in this state
                // falls through to the rewriters' own per-flavor
                // diagnostics.)
                let coords = purl
                    .starts_with("pkg:cargo/")
                    .then(|| purl_parts(purl).map(|(_, name, version)| (name, version)))
                    .flatten();
                let wired = match &coords {
                    Some((n, v)) => {
                        socket_patch_core::vendor::cargo::socket_wiring_present(&common.cwd, n, v)
                            .await
                    }
                    None => false,
                };
                if wired {
                    refused.push(purl.clone());
                    takeover_pre_warnings.push(serde_json::json!({
                        "code": "redirect_vendored_revert_failed",
                        "detail": format!(
                            "{purl} has socket-owned vendored `[patch.crates-io]` \
                             wiring but no usable vendored ledger entry \
                             (.socket/vendor/state.json is missing or corrupt); NOT \
                             redirected — restore the ledger or remove the vendored \
                             wiring manually, then re-run"
                        ),
                    }));
                }
            }
        }
        for purl in &refused {
            if let Some((c, entry)) = takeover.iter().find(|(c, _)| &c.purl == purl) {
                let reason = takeover_refusal(c, entry.as_ref())
                    .map_or("vendored_revert_failed", |w| w.code.as_str());
                skipped.push(serde_json::json!({
                    "purl": purl, "uuid": c.dep.patch_uuid, "reason": reason,
                }));
            }
        }
        // Purls leaving the rewrite set: refused takeovers, plus the dry-run
        // takeover previews (still vendored on disk — the wet run reverts
        // them before the rewriters ever see their files).
        let withheld: std::collections::HashSet<&str> = refused
            .iter()
            .map(String::as_str)
            .chain(dry_run_takeover.iter().map(|(p, _)| p.as_str()))
            .collect();
        if !withheld.is_empty() {
            // Keep the dry-run takeover candidates' URLs (and the root locks
            // their purl is vendored into) for the install-policy previews.
            for (purl, _) in &dry_run_takeover {
                let locks = dry_run_takeover_locks
                    .get(purl)
                    .cloned()
                    .unwrap_or_default();
                for c in candidates.iter().filter(|c| &c.purl == purl) {
                    dry_run_takeover_urls.push((c.dep.artifact_url.clone(), locks.clone()));
                }
            }
            candidates.retain(|c| !withheld.contains(c.purl.as_str()));
        }
    }

    // The binary lock is read and rewritten directly.
    let binary_bun = !bun_lock_present && common.cwd.join("bun.lockb").exists();
    // Read the project's candidate files, run the rewriters. Every read goes
    // through the FIFO-safe reader (non-blocking open + fstat regular-file
    // check): a FIFO planted under any candidate name — pyproject.toml,
    // uv.lock, a paired script, a rush lock — wedged `scan`/`get --mode
    // hosted` forever in a plain `read_to_string` open(2) waiting for a
    // writer. A non-regular file now reads as "unreadable" and is skipped
    // exactly like a missing one.
    //
    // Skipped entirely when no candidate survived (every reference skipped
    // or refused) and no dry-run takeover preview is pending: the rewriters
    // place nothing and warn about nothing without a dep, so the ~45 reads
    // would only feed an empty rewrite. Everything after the rewrite still
    // runs — the skips and warnings reported, a requested VEX still
    // attempted. A dry-run takeover preview still needs the root locks: the
    // install-policy previews below (pnpm `trustLockfile`, npm `.npmrc`)
    // judge the lock the wet run splices after its revert.
    use socket_patch_core::utils::fs::read_regular_to_string;
    let mut files: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    // Rush monorepos have no root package.json/lock pair: the single pnpm
    // source-of-truth lock lives at common/config/rush/pnpm-lock.yaml, and
    // (when subspaces are enabled) one lock per subspace under
    // common/config/subspaces/<name>/. Add them under their repo-relative
    // keys — the pnpm rewriter is basename-generalized, so nested keys are
    // rewritten in place, and the write-back below is already path-generic.
    let mut rush_warnings: Vec<serde_json::Value> = Vec::new();
    let mut rush_lock_keys: Vec<String> = Vec::new();
    if !candidates.is_empty() || !dry_run_takeover_urls.is_empty() {
        for name in REDIRECT_CANDIDATE_FILES {
            if *name == "bun.lockb" {
                continue;
            }
            if let Ok(content) = read_regular_to_string(&common.cwd.join(name)).await {
                files.insert((*name).to_string(), content);
            }
        }

        // Cargo workspace members (and in-root path dependencies) declare
        // dependencies of their own: a member's direct `cfg-if = "1"` must
        // be pinned alongside the root's, or the redirected lock entry is
        // unsatisfiable. Keyed `<dir>/Cargo.toml` for the cargo rewriter.
        if files.contains_key("Cargo.toml") && candidates.iter().any(|c| c.dep.ecosystem == "cargo")
        {
            for rel in socket_patch_core::utils::cargo_workspace::member_manifests(&common.cwd) {
                if let Ok(content) = read_regular_to_string(&common.cwd.join(&rel)).await {
                    files.insert(rel, content);
                }
            }
        }

        if let Ok(paths) = socket_patch_core::utils::python_lock::python_lock_paths(&common.cwd) {
            for path in paths {
                if let Some(script_path) =
                    socket_patch_core::utils::python_lock::script_of_lock(&path).map(str::to_string)
                {
                    if let Ok(content) =
                        read_regular_to_string(&common.cwd.join(&script_path)).await
                    {
                        files.insert(script_path, content);
                    }
                }
                if let Ok(content) = read_regular_to_string(&common.cwd.join(&path)).await {
                    files.insert(path, content);
                }
            }
        }

        if common.cwd.join("rush.json").is_file() {
            let common_lock = socket_patch_core::constants::npm_family::RUSH_COMMON_LOCK_REL;
            if let Ok(content) = read_regular_to_string(&common.cwd.join(common_lock)).await {
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
                    if let Ok(content) = read_regular_to_string(&dir.join("pnpm-lock.yaml")).await {
                        files.insert(key.clone(), content);
                        rush_lock_keys.push(key);
                    }
                }
            }
        }
    }

    // `mut`: the pnpm trustLockfile auto-config below may fold a
    // pnpm-workspace.yaml write (plus its ledger edit) into the rewrite set so
    // it rides the same atomic-write / ledger-first machinery as the locks.
    let mut python_metadata = std::collections::BTreeMap::new();
    let mut unavailable_python_artifacts = std::collections::BTreeSet::new();
    for dep in candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "pypi")
    {
        let Some(sha256) = dep.integrity.sha256.as_deref() else {
            continue;
        };
        if !dep
            .artifact_url
            .split(['?', '#'])
            .next()
            .is_some_and(|path| path.ends_with(".whl"))
        {
            continue;
        }
        let native_target = files
            .iter()
            .filter(|(path, _)| {
                *path == "uv.lock"
                    || socket_patch_core::utils::python_lock::is_script_lock_name(path)
            })
            .any(|(_, text)| {
                socket_patch_core::utils::python_lock::rewrite_python_lock(
                    text,
                    &dep.name,
                    &dep.version,
                    socket_patch_core::utils::python_lock::ArtifactSource::Url(&dep.artifact_url),
                    sha256,
                )
                .ok()
                .flatten()
                .is_some()
            });
        if !native_target {
            continue;
        }
        status.set(format!(
            "Fetching hosted wheel metadata for {}...",
            dep.name
        ));
        match socket_patch_core::vendor::pypi::fetch_hosted_wheel_metadata(
            api_client,
            &dep.artifact_url,
            sha256,
        )
        .await
        {
            Ok(Some(metadata)) => {
                python_metadata.insert(dep.artifact_url.clone(), metadata);
            }
            Ok(None) => {}
            Err(detail) => {
                unavailable_python_artifacts.insert(dep.artifact_url.clone());
                skipped.push(serde_json::json!({
                    "purl": format!("pkg:pypi/{}@{}", dep.name, dep.version),
                    "uuid": dep.patch_uuid,
                    "reason": "python_metadata_unavailable",
                    "detail": detail.replace(&dep.artifact_url, "<hosted artifact>"),
                }));
            }
        }
    }
    status.finish();
    candidates.retain(|c| !unavailable_python_artifacts.contains(&c.dep.artifact_url));
    // The rewriters' override slice — materialized ONCE, after the last
    // candidate filter, so it can never disagree with `candidates`.
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
    // The Pipfile.lock reference shape depends on the installing Pipenv
    // (`path` for 7–11, `file` from 2018 on), so the installed release is
    // probed (`pipenv --version`, up to 10 s) — but only when a pypi patch
    // actually targets an entry of THIS lock: a stray Pipfile.lock in a uv /
    // Poetry project, a re-scan with nothing left to do and any non-Python
    // run must neither spawn Pipenv nor warn about its absence.
    let targets_pipenv_lock =
        socket_patch_core::patch::redirect::pipenv_lock_targets(&files, &overrides);
    let pipenv_major = if targets_pipenv_lock {
        socket_patch_core::utils::pipenv::installed_major(&common.cwd).await
    } else {
        None
    };
    let binary_content = if binary_bun && overrides.iter().any(|o| o.ecosystem == "npm") {
        Some(
            socket_patch_core::utils::fs::read_regular_to_bytes(&common.cwd.join("bun.lockb"))
                .await
                .map_err(|e| socket_patch_core::patch::redirect::RewriteWarning {
                    code: "redirect_bun_lockb_invalid".into(),
                    detail: format!("cannot read bun.lockb: {e}"),
                })
                .and_then(|bytes| {
                    socket_patch_core::patch::redirect::preflight_bun_binary(&bytes)?;
                    Ok(bytes)
                }),
        )
    } else {
        None
    };
    // A malformed primary lock must not cause edits to stale npm siblings.
    let rewrite_overrides: Vec<_> = overrides
        .iter()
        .filter(|o| !(binary_content.as_ref().is_some_and(Result::is_err) && o.ecosystem == "npm"))
        .cloned()
        .collect();
    let mut rewrite = rewrite_registry_redirect_with_pipenv_version(
        &files,
        &rewrite_overrides,
        &python_metadata,
        pipenv_major,
        common.cwd.join("bun.lockb").exists(),
    );
    if let Some(content) = binary_content {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_npm_no_lockfile");
        match content {
            Ok(bytes) => socket_patch_core::patch::redirect::rewrite_bun_binary(
                &bytes,
                &overrides,
                &mut rewrite,
            ),
            Err(warning) => rewrite.warnings.push(warning),
        }
    }

    // Unknown installer → the modern `file` shape was chosen; say so only
    // when the lock was (or, on --dry-run, would be) rewritten.
    if targets_pipenv_lock && pipenv_major.is_none() && rewrite.files.contains_key("Pipfile.lock") {
        rewrite.warnings.push(socket_patch_core::patch::redirect::RewriteWarning {
            code: "redirect_pipenv_installer_unknown".into(),
            detail: format!(
                "Pipenv was not found on PATH, so the Pipfile.lock references use the modern `file` form (Pipenv 2018 and later). A project installed with Pipenv 7–11 needs `path` references instead: put that pipenv on PATH or set {}=<major> and re-run `scan --mode hosted`.",
                socket_patch_core::utils::pipenv::MAJOR_OVERRIDE_ENV
            ),
        });
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
    // Human mode only: this run touched nothing pnpm-related (no lock
    // spliced, trust already configured), so the full guidance, printed by
    // the run that made the change, shrinks to a one-line reminder.
    let mut pnpm_rerun_only = false;
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
                    .is_some_and(|name| matches!(name, "pnpm-lock.yaml" | "shrinkwrap.yaml"))
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
        let spliced_pnpm_locks = pnpm_lock_texts.len();
        if let Some(text) = heal_root {
            pnpm_lock_texts.push(text);
        }
        // A dry-run vendored→hosted takeover of a purl vendored into the
        // root pnpm lock: the wet run reverts that wiring and splices the
        // hosted URL into it, so the trust config is previewed against the
        // root lock (the vendored text carries the same lockfileVersion).
        let takeover_pnpm_urls: Vec<&str> = dry_run_takeover_urls
            .iter()
            .filter(|(_, locks)| locks.iter().any(|l| l == "pnpm-lock.yaml"))
            .map(|(url, _)| url.as_str())
            .collect();
        let takeover_root: Option<&String> = if takeover_pnpm_urls.is_empty()
            || heal_root.is_some()
            || rewrite.files.contains_key("pnpm-lock.yaml")
        {
            None
        } else {
            files.get("pnpm-lock.yaml")
        };
        if let Some(text) = takeover_root {
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
                // Dry-run takeover purls land in the root lock on the wet run.
                .chain(takeover_pnpm_urls.iter().filter_map(|url| url_host(url)))
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
            let root_lock_v9 = heal_root
                .or(takeover_root)
                .and_then(|text| pnpm_lock_version_major(text))
                .is_some_and(|major| major >= 9)
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
            let all_locks_legacy = pnpm_lock_texts.iter().all(|text| {
                pnpm_lock_version_major(text).is_some_and(|major| major < 9)
                    || text
                        .lines()
                        .any(|line| line.starts_with("shrinkwrapVersion:"))
            });
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
                        TrustPlan::AlreadyTrue => {
                            pnpm_rerun_only = spliced_pnpm_locks == 0;
                            format!(
                                "{}, and {PNPM_WORKSPACE_REL} already carries `trustLockfile: \
                                 true` — keep it committed alongside the lock; installs need \
                                 no extra flags. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
                                pnpm_trust_policy_preamble(&server),
                            )
                        }
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
            // The `--store` spelling only matters to pnpm 1–4, so it is
            // named only when a touched lock may be that old.
            let store_note = if pnpm_lock_texts
                .iter()
                .any(|text| pnpm_lock_may_need_store_flag(text))
            {
                " (pnpm 1–4 spell the option `--store`)"
            } else {
                ""
            };
            pnpm_warnings.push(serde_json::json!({
                "code": "redirect_pnpm_trust_lockfile",
                "detail": format!(
                    "{}. After a lock-only change, existing node_modules or a warm pnpm store \
                     can still contain upstream files. For a reliable reinstall, use a clean \
                     node_modules tree and an empty store with \
                     `pnpm install --frozen-lockfile --store-dir <new-empty-directory>`\
                     {store_note}. Do not rely on `--force`: some versions re-resolve the \
                     upstream artifact. Run `socket-patch vex` after installation to verify \
                     the patched files.",
                    detail.trim_end_matches('.')
                ),
            }));
        }
    }
    // npm >= 12 ships `allow-remote=none`: it refuses (EALLOWREMOTE) every
    // tarball whose `resolved` origin is not the configured registry — which
    // is exactly what a hosted redirect writes. Verified against real
    // installs (npm 12.0.0 / 12.1.0): a fresh `npm ci` of the redirected lock
    // fails before fetching anything, while npm <= 11 (11.x ships
    // `allow-remote=all`; <= 10 has no such setting) installs it unchanged,
    // and `allow-remote=all` in the project `.npmrc` makes npm 12 install
    // the patched bytes with the sha512 pins still enforced. `root` is not
    // enough in general: it only admits DIRECT dependencies of the project.
    //
    // ZERO-TOUCH DEFAULT (the npm twin of the pnpm trustLockfile auto-config
    // above): whenever a root npm lock ends this run carrying a granted
    // hosted artifact URL (spliced now, or already redirected by an earlier
    // run — so a missed config heals on re-run), the run ensures
    // `allow-remote=all` in the project `.npmrc` — created when absent
    // (`action: "created"`), one line appended otherwise (`"added"`), every
    // other byte preserved — and records it in the ledger
    // (`redirect_npmrc_allow_remote`) so rollback / remove / the vendored
    // takeover remove exactly that once no package-lock entry needs it. An
    // explicit user `allow-remote=<other>` is RESPECTED (never flipped), an
    // unreadable / symlinked `.npmrc` is left alone, and
    // `--no-npm-allow-remote-config` opts out entirely; every variant still
    // WARNS (`redirect_npm_allow_remote`) with the whole-tree tradeoff.
    // Vendored mode is unaffected: its `file:.socket/vendor/…` specs are npm
    // `file` specs, gated by `allow-file` (default `all`), not
    // `allow-remote`.
    let mut npm_warnings: Vec<serde_json::Value> = Vec::new();
    let mut npmrc_config_write: Option<(String, socket_patch_core::patch::redirect::FileEdit)> =
        None;
    {
        let npm_hosts: Vec<&str> = {
            let mut hosts: Vec<&str> = overrides
                .iter()
                .filter(|o| o.ecosystem == "npm")
                .filter(|o| {
                    NPM_LOCKS.iter().any(|lock| {
                        rewrite
                            .files
                            .get(*lock)
                            .or_else(|| files.get(*lock))
                            .is_some_and(|text| {
                                socket_patch_core::patch::redirect::artifact_url_present(
                                    text,
                                    &o.artifact_url,
                                )
                            })
                    })
                })
                .filter_map(|o| url_host(&o.artifact_url))
                // A dry-run vendored→hosted takeover: the wet run reverts
                // the vendored wiring in a root npm lock and splices the
                // hosted URL there, so preview the `.npmrc` write too.
                .chain(
                    dry_run_takeover_urls
                        .iter()
                        .filter(|(_, locks)| locks.iter().any(|l| NPM_LOCKS.contains(&l.as_str())))
                        .filter_map(|(url, _)| url_host(url)),
                )
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            hosts
        };
        if !npm_hosts.is_empty() {
            use socket_patch_core::patch::redirect::npmrc::{
                plan_npmrc_allow_remote_with, resolve_outer_allow_remote, NpmConfigEnv, NpmrcPlan,
                NPMRC_ALLOW_REMOTE_EDIT_KIND, NPMRC_REL,
            };
            let edit = |action: &str| socket_patch_core::patch::redirect::FileEdit {
                path: NPMRC_REL.into(),
                kind: NPMRC_ALLOW_REMOTE_EDIT_KIND.into(),
                action: action.into(),
                key: Some("allow-remote".into()),
                original: None,
                new: Some(serde_json::json!("all")),
            };
            let npmrc = read_npmrc_for_allow_remote(&common.cwd.join(NPMRC_REL));
            // The npm config layers OUTSIDE the project file, located the
            // way npm does: an env `npm_config_allow_remote` beats the
            // project file, and an explicit user / global / builtin value is
            // a machine / org policy a committed project line would silently
            // override — both are respected like a project value.
            let outer = resolve_outer_allow_remote(&NpmConfigEnv::from_process(), |path| {
                socket_patch_core::utils::fs::read_regular_to_string_sync(path).ok()
            });
            let detail = match npmrc {
                // Opt-out still reports an explicit / already-set value
                // truthfully; only the WRITE is suppressed.
                Ok(existing) => match plan_npmrc_allow_remote_with(existing.as_deref(), &outer) {
                    NpmrcPlan::AlreadyAll => npm_allow_remote_already_detail(&npm_hosts),
                    NpmrcPlan::UserSet(value) => {
                        npm_allow_remote_user_set_detail(&npm_hosts, &value)
                    }
                    NpmrcPlan::EnvSet { var, value } => {
                        npm_allow_remote_env_set_detail(&npm_hosts, &var, &value)
                    }
                    NpmrcPlan::OuterSet { layer, path, value } => {
                        npm_allow_remote_outer_set_detail(&npm_hosts, layer, &path, &value)
                    }
                    NpmrcPlan::Unsupported(why) => {
                        npm_allow_remote_unreadable_detail(&npm_hosts, &why)
                    }
                    _ if common.no_npm_allow_remote_config => {
                        npm_allow_remote_manual_detail(&npm_hosts)
                    }
                    NpmrcPlan::Create(text) => {
                        npmrc_config_write = Some((text, edit("created")));
                        npm_allow_remote_configured_detail(&npm_hosts, true, common.dry_run)
                    }
                    NpmrcPlan::Append(text) => {
                        npmrc_config_write = Some((text, edit("added")));
                        npm_allow_remote_configured_detail(&npm_hosts, false, common.dry_run)
                    }
                },
                Err(why) => npm_allow_remote_unreadable_detail(&npm_hosts, &why),
            };
            npm_warnings.push(serde_json::json!({
                "code": "redirect_npm_allow_remote",
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
    if let Some((text, edit)) = npmrc_config_write {
        rewrite.files.insert(
            socket_patch_core::patch::redirect::npmrc::NPMRC_REL.to_string(),
            text,
        );
        // Appended after the lock edits for the same reason: a whole-ledger
        // replay unwinds the setting before the lock originals it served.
        rewrite.edits.push(edit);
    }
    let rewritten: Vec<String> = rewrite
        .files
        .keys()
        .chain(rewrite.binary_files.keys())
        .cloned()
        .collect();

    // A dep counts as REDIRECTED only if its hosted-artifact URL (or its
    // per-dependency registry index URL) actually landed in the project's
    // files — either written by this run or already present from an earlier
    // one. A granted reference whose rewriter found nothing to edit (e.g. no
    // lockfile) must NOT be recorded or attested: nothing pins the patch.
    // A `pdm.lock` that is NOT the PyPI install driver (a `uv.lock` or
    // `poetry.lock` sits beside it) is never rewritten this run, yet it can
    // still carry a Socket artifact URL from an earlier run when pdm drove.
    // That stale text pins nothing now, so it must not feed the substring
    // confirmation probe below — otherwise an untouched uv/poetry project whose
    // real lock was never redirected would report a bogus `redirected: 1` and
    // persist a ledger record. When pdm DOES drive, pypi confirmation keys off
    // `confirmed_pdm_uuids` and never consults this probe, so dropping the file
    // here is always safe; `pdm.lock` only ever carries pypi URLs.
    let pdm_inactive =
        files.contains_key("pdm.lock") && !socket_patch_core::patch::redirect::pdm_drives(&files);
    let final_texts: Vec<&String> = files
        .iter()
        .filter(|(name, _)| !(pdm_inactive && name.as_str() == "pdm.lock"))
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
        .filter(|c| {
            let purl = c.purl.as_str();
            let uuid = c.dep.patch_uuid.as_str();
            if binary_bun && purl.starts_with("pkg:npm/") {
                return rewrite.confirmed_bun_binary_uuids.contains(uuid);
            }
            if rewrite.refused_pipenv_uuids.contains(uuid) {
                return false;
            }
            // pdm is transactional like cargo: a refused uuid is never
            // confirmed, and when `pdm.lock` is the PyPI install driver
            // (no `uv.lock` / `poetry.lock`) a pypi dep is confirmed ONLY
            // by the pdm rewriter's own report — the URL landing in a
            // sibling `requirements.txt` the project does not install from
            // pins nothing. When uv/poetry drive, their own lock proof
            // below still confirms them. This check precedes the hatch
            // gate: a PDM project may declare `hatchling` as its build
            // backend, which registers every pypi uuid as hatch-owned while
            // the lock's presence keeps hatch from confirming any of them.
            if rewrite.refused_pdm_uuids.contains(uuid) {
                return false;
            }
            if purl.starts_with("pkg:pypi/")
                && socket_patch_core::patch::redirect::pdm_drives(&files)
            {
                return rewrite.confirmed_pdm_uuids.contains(uuid);
            }
            if rewrite.python_lock_uuids.contains(uuid) {
                return rewrite.confirmed_python_lock_uuids.contains(uuid)
                    && !rewrite.refused_python_lock_uuids.contains(uuid);
            }
            if rewrite.hatch_uuids.contains(uuid) {
                return rewrite.confirmed_hatch_uuids.contains(uuid);
            }
            // A Pipfile.lock rewrite confirms its own uuids (the sibling
            // requirements.txt rewriter may have had nothing to do).
            if purl.starts_with("pkg:pypi/") {
                return rewrite.confirmed_pipenv_uuids.contains(uuid)
                    || rewrite.confirmed_requirements_uuids.contains(uuid);
            }
            if rewrite.refused_pnpm_uuids.contains(uuid) {
                return false;
            }
            // Cargo is transactional: the rewriter reports exactly which
            // patch uuids FULLY landed (manifest pin + lock + registry
            // block). Substring presence must never confirm a cargo dep —
            // the `[registries.…]` config block contains the index URL while
            // pinning nothing, so a config-block-only rewrite would be
            // attested with zero enforcement in any build.
            if purl.starts_with("pkg:cargo/") {
                return rewrite.confirmed_cargo_uuids.contains(uuid);
            }
            // Golang likewise: the goproxy `indexUrl` is the bare
            // patch-server origin (present in any other hosted lock), and
            // the socket module's go.sum lines outlive a removed replace.
            if purl.starts_with("pkg:golang/") {
                return rewrite.confirmed_golang_uuids.contains(uuid);
            }
            // The override's own targets: artifact URL; per-dependency
            // registry index URL; fail-closed maven's globally-unique
            // `-socket.<hex8>` suffixed version (never the `.pom` URL).
            let artifact_url = c.dep.artifact_url.as_str();
            let registry = c.dep.registry_override.as_ref();
            let index_url = registry.map(|o| o.index_url.as_str());
            let suffixed_version =
                registry.and_then(|o| o.identifiers.maven_suffixed_version.as_deref());
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
                    || index_url.is_some_and(|iu| text.contains(iu))
                    || suffixed_version.is_some_and(|sv| text.contains(sv))
            })
        })
        .map(|c| (c.purl.clone(), c.dep.patch_uuid.clone()))
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

    // SYMLINK GUARD — fail-closed, whole rewrite, before the ledger and before
    // any write (hosted rewrites are transactional). The writer below stages
    // next to the path and renames over it, which REPLACES a symbolic link
    // with a detached regular copy: the link target goes stale (uv itself
    // writes THROUGH a linked uv.lock/pylock/pyproject), and `--revert`
    // restores bytes but never the link (git shows a 120000→100644
    // typechange). Since Python lock discovery follows links, a shared
    // symlinked lock reaches this point as an ordinary rewrite target; the
    // revert side (replay.rs) already refuses linked files, so the write
    // side must too. Applies to every ecosystem's files (a symlinked
    // package-lock.json has the same defect) and to dry runs, so a dry run
    // predicts the refusal instead of a rewrite that will never happen.
    if let Some(linked) = socket_patch_core::utils::fs::first_symlink(
        &common.cwd,
        rewrite
            .files
            .keys()
            .chain(rewrite.binary_files.keys())
            .map(String::as_str),
    )
    .await
    {
        return refuse_symlinked_file(common, scan_result.take(), linked);
    }

    if !common.dry_run {
        let total = confirmed.len();
        for (i, (purl, uuid)) in confirmed.iter().enumerate() {
            status.set(format!("Fetching patch records... ({}/{total})", i + 1));
            match api_client.fetch_patch(uuid).await {
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
                             it will be missing from VEX until `socket-patch scan --mode \
                             hosted` is re-run"
                        ),
                    }));
                }
            }
        }
        status.finish();
    }

    // Whether this run persisted the redirect ledger (human next steps).
    let mut ledger_written = false;
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
        if !rewrite.edits.is_empty() || !records.is_empty() {
            // Ledgers written before the mode-string rename carry
            // `"mode": "redirect"`; normalize on rewrite so the on-disk
            // ledger converges on the documented "hosted" name (the
            // loader accepts either — mode is an opaque string to it).
            ledger.mode = "hosted".to_string();
            // REBASE instead of append for fragment kinds whose file the
            // package manager itself rewrites in place: when the ledger already
            // holds edits for the same (path, kind, key) and the file no longer
            // carried their `new` fragments before this run (Poetry 1.1/1.2
            // `poetry lock --no-update` keeps the Socket source but re-lays the
            // unit and drops the inserted `files` line), appending this run's
            // edits — recorded against the RELOCKED text — would build a chain
            // whose older links match nothing: rollback and remove then refuse
            // forever, and the refusal's own remedy ("re-run scan") is what
            // lengthened the chain. Keeping the oldest `original` (the pristine
            // fragment) and adopting the fresh `new` keeps the chain a single
            // invertible link: replay swaps the fragment this run wrote back to
            // the fragment the very first run found.
            let mut rebased: Vec<usize> = Vec::new();
            for edit in rewrite
                .edits
                .iter()
                .filter(|e| REBASE_KINDS.contains(&e.kind.as_str()))
            {
                let siblings: Vec<usize> = ledger
                    .edits
                    .iter()
                    .enumerate()
                    .filter(|(_, old)| {
                        old.path == edit.path && old.kind == edit.kind && old.key == edit.key
                    })
                    .map(|(i, _)| i)
                    .collect();
                let before = files.get(&edit.path).map(String::as_str).unwrap_or("");
                let drifted = !siblings.is_empty()
                    && siblings.iter().all(|&i| {
                        ledger.edits[i]
                            .new
                            .as_ref()
                            .and_then(serde_json::Value::as_str)
                            .is_none_or(|new| !before.contains(new))
                    });
                if !drifted {
                    continue;
                }
                // Positional pairing: the rewriter emits a key's fragments in a
                // fixed order (package unit, then the legacy integrity entry).
                let nth = rewrite
                    .edits
                    .iter()
                    .filter(|e| e.path == edit.path && e.kind == edit.kind && e.key == edit.key)
                    .position(|e| std::ptr::eq(e, edit))
                    .unwrap_or(0);
                if let Some(&target) = siblings.get(nth) {
                    if !rebased.contains(&target) {
                        // `pdm lock` fully un-patches the lock (registry source
                        // restored) and may reflow line endings (CRLF → LF), so
                        // the fresh run's `original` IS the correct
                        // relocked-registry rollback target and the stale
                        // recorded one would restore a mismatched fragment.
                        // Poetry's relock instead KEEPS the Socket source (it
                        // only drops the inserted `files` line), so its oldest
                        // `original` — the true pre-patch fragment — must
                        // survive; only its `new` is refreshed.
                        if edit.kind == "redirect_pdm_lock_package" {
                            ledger.edits[target].original = edit.original.clone();
                        }
                        ledger.edits[target].new = edit.new.clone();
                        ledger.edits[target].action = edit.action.clone();
                        rebased.push(target);
                    }
                }
            }
            // Dedup against the ledger as this run found it, never within
            // this run: one run legitimately records identical edits (a
            // Cargo.toml declaring the crate with the same line in two
            // sections), and each one reverts one occurrence — collapsing
            // them made `remove` leave the second pin (and its registry
            // block) in place while reporting success.
            let recorded = ledger.edits.len();
            for edit in &rewrite.edits {
                let is_rebased = REBASE_KINDS.contains(&edit.kind.as_str())
                    && rebased.iter().any(|&t| {
                        let old = &ledger.edits[t];
                        old.path == edit.path
                            && old.kind == edit.kind
                            && old.key == edit.key
                            && old.new == edit.new
                    });
                if !is_rebased && !ledger.edits[..recorded].contains(edit) {
                    ledger.edits.push(edit.clone());
                }
            }
            ledger.records.extend(records);
            // The ledger is the only revert path and the VEX record store —
            // a swallowed write failure would let the lockfile writes below
            // proceed with no revert data persisted while reporting success.
            let saved =
                socket_patch_core::patch::redirect::save_redirect_state(&common.cwd, &ledger).await;
            ledger_written = saved.is_ok();
            if let Err(e) = saved {
                let message = format!("failed to write .socket/vendor/redirect-state.json: {e}");
                eprintln!("{}", format_error_line(&message));
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        }
        for (rel, content) in rewrite
            .files
            .iter()
            .map(|(p, s)| (p, s.as_bytes()))
            .chain(rewrite.binary_files.iter().map(|(p, b)| (p, b.as_slice())))
        {
            let path = common.cwd.join(rel);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // Atomic stage+rename, mode-preserving (the vendored backend's
            // writer): a bare `fs::write` truncates first, so a crash
            // mid-write could leave a torn lockfile behind.
            if let Err(e) =
                socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(&path, content)
                    .await
            {
                let message = format!("failed to write {rel}: {e}");
                eprintln!("{}", format_error_line(&message));
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
    let gem_stale: StaleInstallOutcome = if common.dry_run {
        StaleInstallOutcome::default()
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
            &ledger.records,
            &gem_artifact_shas,
        )
        .await
    };
    let python_stale = if common.dry_run {
        StaleInstallOutcome::default()
    } else {
        python::stale_install_warnings(
            common,
            &confirmed,
            &rewrite.confirmed_pipenv_uuids,
            &ledger.records,
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
    // Classified over this run's in-memory ledgers — the redirect ledger as
    // merged and persisted above, the vendored ledger as the takeover left
    // it — so a non-dry-run reflects this run without re-reading either file.
    let mut takeover_warnings: Vec<serde_json::Value> = Vec::new();
    let superseded = super::classify_overlap_takeover_with(
        common,
        &common.cwd,
        Some(&ledger),
        vendor_state.as_ref().ok(),
    )
    .await
    .redirect;
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
        prune_warnings.push(prune_ignored_warning());
    }

    // Emit an OpenVEX attestation when `--vex` was requested. The redirected
    // bytes are fetched from the hosted patch server at install time, so the
    // PURLs CONFIRMED REDIRECTED BY THIS RUN are attested from the ledger
    // records WITHOUT hash verification (`assume_applied` — the integrity
    // pins written into the lockfile are the evidence), while any OTHER
    // manifest patches (previously applied / vendored — and any stale ledger
    // records this run did not confirm) still verify normally. A post-install
    // `socket-patch vex` hash-verifies the redirected patches against the
    // installed tree (it reads the records back from the redirect ledger and
    // re-proves their lockfile wiring — see `commands::vex_sources`), or,
    // with no install yet, attests from the pinned hosted wiring it finds in
    // the lockfile. Requested-but-failed VEX (including "nothing to attest")
    // flips the exit code, matching `scan --vex`.
    let mut vex_statements: Option<usize> = None;
    // VEX run-level advisories: `note_warning` keeps them off stderr under
    // --json, so the envelope's `vex.warnings` is their only channel there.
    let mut vex_warnings: Vec<crate::json_envelope::RunWarning> = Vec::new();
    let mut vex_error: Option<crate::commands::vex::VexGenError> = None;
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
            .filter(|purl| {
                !gem_stale.stale_purls.contains(purl) && !python_stale.stale_purls.contains(purl)
            })
            .collect();
        // A healthy copy in another interpreter must not override a stale
        // Python tree found by the probe, including with --vex-no-verify.
        params.known_stale = python_stale.stale_purls.iter().cloned().collect();
        let manifest_path = common.resolved_manifest_path();
        match generate_vex_from_manifest_path(common, &params, &manifest_path).await {
            Ok(summary) => {
                vex_statements = Some(summary.statements);
                vex_warnings = summary.warnings;
            }
            Err(e) => {
                vex_code = 1;
                vex_warnings = e.embedded_warnings();
                vex_error = Some(e);
            }
        }
    }

    // One merged warning list, in one order, for both channels: the
    // rewriter's own warnings first (e.g. `no package-lock.json`), then the
    // record, package-manager, stale-install, takeover and prune warnings.
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
    warnings.extend(rush_warnings.iter().cloned());
    warnings.extend(pnpm_warnings.iter().cloned());
    warnings.extend(npm_warnings.iter().cloned());
    warnings.extend(gem_stale.warnings.iter().cloned());
    warnings.extend(python_stale.warnings.iter().cloned());
    warnings.extend(takeover_pre_warnings.iter().cloned());
    warnings.extend(takeover_warnings.iter().cloned());
    warnings.extend(prune_warnings.iter().cloned());

    if common.json {
        // Nest the redirect result under `redirect` inside the classic scan
        // object (built by `run`, threaded in via `scan_result`), mirroring
        // vendored mode's nested `vendor` block. This keeps the hosted `--json`
        // envelope schema-consistent with the zero-discovery and non-hosted
        // scan envelopes — same top-level scan keys (scannedPackages,
        // totalPatches, canAccessPaidPatches) plus the `packages` enumeration —
        // instead of the bare `{status, redirect}` it used to emit.
        let redirect = redirect_json_block(
            confirmed.len(),
            rewritten,
            skipped,
            warnings,
            common.dry_run,
        );
        let mut result = build_redirect_json_envelope(scan_result.take(), redirect);
        if let Some(statements) = vex_statements {
            result["vex"] = serde_json::json!({
                "path": vex.vex.as_ref().expect("vex_statements is Some only when --vex was given").display().to_string(),
                "statements": statements,
                "format": "openvex-0.2.0",
                "verified": false,
            });
            // Same skip-if-empty `warnings` key as the agent arm's VEX block.
            if !vex_warnings.is_empty() {
                result["vex"]["warnings"] = serde_json::to_value(&vex_warnings)
                    .expect("RunWarning is a plain string struct: serialization cannot fail");
            }
        } else if let Some(e) = &vex_error {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({ "code": e.code, "message": e.message });
            super::append_vex_error_warnings(&mut result, &vex_warnings);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("serializing an in-memory JSON value cannot fail")
        );
    } else {
        if !common.silent {
            // Wrap long warnings only on a terminal: logs and pipes keep one
            // line per sentence so CI can grep them.
            let width =
                std::io::IsTerminal::is_terminal(&std::io::stderr()).then(crate::ui::stderr_width);
            for purl in &takeover_migrated {
                eprintln!("{}", format_takeover_line(purl, common.dry_run));
            }
            // The files a takeover's revert touched (or, on --dry-run,
            // would touch) count alongside the rewriters' own: a dry-run
            // takeover is withheld from the rewriters, and a wet revert can
            // touch a wiring file the hosted rewriter never rewrites. The
            // same union in both modes keeps preview and wet counts equal.
            let mut human_files = rewritten.clone();
            human_files.extend(takeover_files.iter().cloned());
            human_files.sort();
            human_files.dedup();
            // The one stdout line: scripts read it, so it stays on stdout;
            // everything below is on stderr and names its package itself.
            println!(
                "{}",
                format_redirect_summary(confirmed.len(), human_files.len(), common.dry_run)
            );
            let human_warnings: Vec<(&str, &str)> = warnings
                .iter()
                .map(|w| {
                    (
                        w["code"].as_str().unwrap_or_default(),
                        w["detail"].as_str().unwrap_or_default(),
                    )
                })
                // The prune notice already printed up front (in `run`);
                // successful takeovers printed above as progress lines.
                .filter(|(code, _)| {
                    *code != super::REDIRECT_PRUNE_IGNORED && !TAKEOVER_INFO_CODES.contains(code)
                })
                .collect();
            // Human output prints the bare strings — `Value`'s `Display`
            // would JSON-quote them.
            let skipped_pairs: Vec<(String, String)> = skipped
                .iter()
                .map(|s| {
                    (
                        s["purl"].as_str().unwrap_or_default().to_string(),
                        s["reason"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            // Granted, but nothing in the project pins it (no lock entry,
            // unreadable lock, ...): listed so it never vanishes silently.
            // (A skipped uuid — e.g. unavailable wheel metadata — is already
            // listed with its reason.)
            let unconfirmed: Vec<String> = candidates
                .iter()
                .filter(|c| {
                    !confirmed
                        .iter()
                        .any(|(cp, cu)| *cp == c.purl && *cu == c.dep.patch_uuid)
                })
                .filter(|c| {
                    !skipped
                        .iter()
                        .any(|s| s["uuid"].as_str() == Some(c.dep.patch_uuid.as_str()))
                })
                .map(|c| c.purl.clone())
                .collect();
            for line in format_unredirected(
                &skipped_pairs,
                &unconfirmed,
                confirmed.is_empty(),
                // Only the lockfile rewriters' own warnings explain a
                // missing lock entry; unrelated guidance (pnpm trust, VEX,
                // stale installs) is not what the hint points at.
                rewrite.warnings.len(),
            ) {
                eprintln!("{line}");
            }
            for (code, detail) in &human_warnings {
                let detail = if *code == "redirect_pnpm_trust_lockfile" && pnpm_rerun_only {
                    pnpm_trust_rerun_reminder()
                } else {
                    detail
                };
                eprintln!("{}", format_warning(code, detail, width));
            }
            if let Some(statements) = vex_statements {
                eprintln!(
                    "Wrote OpenVEX document with {} to {} (redirected patches are attested \
                     from the ledger, not hash-verified — their bytes are fetched at install \
                     time; run `socket-patch vex` after installing to verify against the \
                     installed tree).",
                    crate::ui::plural(statements, "statement", "statements"),
                    vex.vex
                        .as_ref()
                        .expect("vex_statements is Some only when --vex was given")
                        .display(),
                );
            } else if vex.vex.is_some() && common.dry_run {
                eprintln!(
                    "{}",
                    crate::commands::vex::format_vex_dry_run_skip("redirected")
                );
            }
            if !common.dry_run {
                for line in
                    format_next_steps(&human_files, ledger_written, !takeover_migrated.is_empty())
                {
                    println!("{line}");
                }
            }
        }
        // Errors print even under --silent ("errors only", never
        // "nothing"): exit 1 with no message would be undiagnosable.
        if let Some(e) = &vex_error {
            e.print_embedded(common);
        }
    }
    vex_code
}

// ── Human-output formatting ────────────────────────────────────────────────
//
// Pure `String` builders for everything the hosted flow prints in human
// mode, so the exact text is unit-testable (see the tests module). JSON
// output never goes through these: its `detail`/`reason` strings are the
// stable, machine-facing spellings.

/// Warning codes that report a SUCCESSFUL vendored→hosted migration. They
/// stay in the JSON `warnings[]` (additive contract), but a human run
/// prints them as plain progress lines ([`format_takeover_line`]), not as
/// warnings.
const TAKEOVER_INFO_CODES: &[&str] = &[
    "redirect_takeover_reverted_vendored",
    "redirect_would_revert_vendored",
];

/// Lowercase tool names that must keep their spelling at the start of a
/// sentence (`pnpm >=11 rejects…` must not become `Pnpm`).
const LOWERCASE_TOOLS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "cargo", "pip", "pipenv", "uv", "poetry", "pdm", "hatch", "go",
    "gem", "bundler", "bundle", "composer", "mvn", "gradle", "dotnet", "deno", "rush",
];

/// Capitalize the first letter of a message for an `Error:`/`Warning:`
/// line, leaving it alone when the first word is an identifier rather than
/// an English word: a file name (`pnpm-lock.yaml`), a purl, a flag, a path,
/// or a lowercase tool name.
fn sentence_case(msg: &str) -> String {
    let first_word = msg.split_whitespace().next().unwrap_or("");
    let is_word = !first_word.is_empty()
        && first_word
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == ',' || c == ';')
        && !LOWERCASE_TOOLS.contains(&first_word.trim_end_matches([',', ';']));
    if !is_word {
        return msg.to_string();
    }
    let mut chars = msg.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// `Error: <Message>` for a hosted-flow failure.
fn format_error_line(msg: &str) -> String {
    format!("Error: {}", sentence_case(msg))
}

/// Split `text` into wrap tokens at whitespace, except that a
/// backtick-delimited code span (`` `pnpm install --trust-lockfile` ``)
/// stays one token so a command the user copies is never broken across
/// lines. An unclosed span falls back to plain whitespace splitting.
fn wrap_tokens(text: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut span: Vec<&str> = Vec::new();
    for word in text.split_whitespace() {
        span.push(word);
        let open = span.iter().map(|w| w.matches('`').count()).sum::<usize>() % 2 == 1;
        if !open {
            tokens.push(span.join(" "));
            span.clear();
        }
    }
    tokens.extend(span.into_iter().map(str::to_string));
    tokens
}

/// Greedy word wrap to `width` columns (characters, not bytes). The first
/// line starts with `first_prefix`, later lines with `indent`. A word
/// longer than the line (a URL) gets a line of its own, never split; a
/// backtick code span counts as one word (see [`wrap_tokens`]).
fn wrap_words(text: &str, width: usize, first_prefix: &str, indent: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = first_prefix.to_string();
    let mut line_len = first_prefix.chars().count();
    let mut empty = true;
    for word in wrap_tokens(text) {
        let word = word.as_str();
        let wlen = word.chars().count();
        if !empty && line_len + 1 + wlen > width {
            lines.push(std::mem::replace(&mut line, indent.to_string()));
            line_len = indent.chars().count();
            empty = true;
        }
        if !empty {
            line.push(' ');
            line_len += 1;
        }
        line.push_str(word);
        line_len += wlen;
        empty = false;
    }
    lines.push(line);
    lines
}

/// Split a long guidance paragraph into its sentences, at every period
/// followed by a space (host names and versions such as `patch.socket.dev`
/// or `5.4` never contain one). Each sentence keeps its own period; the
/// last one is returned as written.
fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text.trim();
    while let Some(i) = rest.find(". ") {
        out.push(rest[..=i].to_string());
        rest = rest[i + 2..].trim_start();
    }
    if !rest.is_empty() {
        out.push(rest.to_string());
    }
    out
}

/// One human warning: `Warning (<code>): <detail>`. The pnpm trustLockfile
/// guidance is a paragraph of separate instructions, so it renders as a
/// headline plus one `  - ` bullet per sentence. With `width` (stderr is a
/// terminal) every line is word-wrapped; without it (a pipe or a CI log)
/// each sentence stays on one line so the text remains greppable.
fn format_warning(code: &str, detail: &str, width: Option<usize>) -> String {
    let prefix = format!("Warning ({code}): ");
    let detail = sentence_case(detail.trim());
    let (headline, bullets) = if code == "redirect_pnpm_trust_lockfile" {
        let mut sentences = split_sentences(&detail).into_iter();
        let head = sentences.next().unwrap_or_default();
        (head, sentences.collect::<Vec<_>>())
    } else {
        (detail, Vec::new())
    };
    let mut lines: Vec<String> = Vec::new();
    match width {
        Some(w) => {
            lines.extend(wrap_words(&headline, w, &prefix, "  "));
            for b in &bullets {
                lines.extend(wrap_words(b, w, "  - ", "    "));
            }
        }
        None => {
            lines.push(format!("{prefix}{headline}"));
            lines.extend(bullets.iter().map(|b| format!("  - {b}")));
        }
    }
    lines.join("\n")
}

/// The one-line re-run reminder that replaces the full pnpm trustLockfile
/// guidance in human mode when this run changed nothing pnpm-related (the
/// lock was redirected and trust configured by an earlier run, whose
/// output carried the full text; `--json` still carries it every time).
fn pnpm_trust_rerun_reminder() -> &'static str {
    "pnpm-lock.yaml is already redirected and pnpm-workspace.yaml already sets \
     `trustLockfile: true`; keep both committed, and never rebuild the lockfile \
     (`pnpm clean --lockfile`), which discards the redirect"
}

/// The stdout summary line.
///
/// - wet: `Redirected 1 package; rewrote 1 file.`
/// - dry run: `Would redirect 1 package and rewrite 1 file (--dry-run: nothing was changed).`
/// - every redirected package was already in place (nothing to rewrite):
///   `1 package is already redirected; nothing to rewrite.`
fn format_redirect_summary(redirected: usize, files: usize, dry_run: bool) -> String {
    use crate::ui::plural;
    if redirected > 0 && files == 0 {
        return format!(
            "{} already redirected; nothing to rewrite.",
            plural(redirected, "package is", "packages are")
        );
    }
    let pkgs = plural(redirected, "package", "packages");
    let files = plural(files, "file", "files");
    if dry_run {
        format!("Would redirect {pkgs} and rewrite {files} (--dry-run: nothing was changed).")
    } else {
        format!("Redirected {pkgs}; rewrote {files}.")
    }
}

/// Readable text for a `skipped[].reason` code (the JSON keeps the code).
/// Unknown server statuses fall through verbatim.
fn describe_skip_reason(reason: &str) -> String {
    match reason {
        "not_found" => "the hosted patch server has no artifact for this patch".into(),
        "forbidden" => "not entitled to this patch (paid plan or no org access)".into(),
        "pending" | "pending_build" => {
            "the hosted artifact is still being built; re-run later".into()
        }
        "build_failed" => "the hosted artifact failed to build".into(),
        "withdrawn" => "the patch was withdrawn".into(),
        "bad_purl" => "the server returned an unparseable package URL".into(),
        "no_url" => "the server returned no artifact URL".into(),
        "vendored_revert_failed" => {
            "its vendored state could not be reverted (see the warning)".into()
        }
        "python_metadata_unavailable" => "the hosted wheel's metadata could not be fetched".into(),
        "redirect_bun_lock_unsupported" | "redirect_bun_lockb_invalid" => {
            "the Bun lockfile blocks the vendored-to-hosted migration (see the warning)".into()
        }
        other => format!("server status `{other}`"),
    }
}

/// The per-package "not redirected" lines, `skipped` (with a reason code)
/// first, then `unconfirmed` (granted, but nothing in the project's files
/// pins it). When nothing at all was redirected they sit under a
/// `No patches could be redirected:` headline; otherwise each line stands
/// alone (it prints on stderr, apart from the stdout summary).
fn format_unredirected(
    skipped: &[(String, String)],
    unconfirmed: &[String],
    nothing_redirected: bool,
    lock_warnings: usize,
) -> Vec<String> {
    if skipped.is_empty() && unconfirmed.is_empty() {
        return Vec::new();
    }
    let see = match lock_warnings {
        0 => "",
        1 => " (see the warning below)",
        _ => " (see the warnings below)",
    };
    // Under the headline every line is a package that was not redirected,
    // so it needs no "Skipped"/"Not redirected" lead of its own.
    let (skip_lead, unpinned_lead) = if nothing_redirected {
        ("  ", "  ")
    } else {
        ("Skipped ", "Not redirected ")
    };
    let mut lines = Vec::new();
    if nothing_redirected {
        lines.push("No patches could be redirected:".to_string());
    }
    for (purl, reason) in skipped {
        lines.push(format!(
            "{skip_lead}{purl}: {}",
            describe_skip_reason(reason)
        ));
    }
    for purl in unconfirmed {
        lines.push(format!(
            "{unpinned_lead}{purl}: no lockfile entry pinning it could be redirected{see}"
        ));
    }
    lines
}

/// The human line for a successful (or, on `--dry-run`, planned)
/// vendored→hosted migration.
fn format_takeover_line(purl: &str, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Would migrate {purl} from vendored to hosted (its vendored wiring, ledger entry, \
             and committed artifact would be reverted first)."
        )
    } else {
        format!(
            "Migrated {purl} from vendored to hosted (reverted its vendored wiring, ledger \
             entry, and committed artifact)."
        )
    }
}

/// `a`, `a and b`, `a, b, and c`; past `max` names, `a, b, and 3 more`.
fn join_names(names: &[String], max: usize) -> String {
    let shown: Vec<&str> = names.iter().take(max).map(String::as_str).collect();
    let more = names.len().saturating_sub(max);
    let mut parts: Vec<String> = shown.iter().map(|s| s.to_string()).collect();
    if more > 0 {
        parts.push(format!("{more} more"));
    }
    match parts.len() {
        0 => String::new(),
        1 => parts.remove(0),
        2 => format!("{} and {}", parts[0], parts[1]),
        n => format!("{}, and {}", parts[..n - 1].join(", "), parts[n - 1]),
    }
}

/// Next steps after a wet run that rewrote files (stdout, after the
/// summary — the same place vendored mode prints its own): commit the
/// ledger and the rewritten files, reinstall so the installed tree picks
/// up the patched artifacts, then verify with `vex`. After a
/// vendored→hosted takeover (`vendored_removed`) the commit also has to
/// carry the deleted vendored ledger entries and artifacts, so the whole
/// `.socket/vendor/` directory is named instead of the redirect ledger.
fn format_next_steps(
    files: &[String],
    ledger_written: bool,
    vendored_removed: bool,
) -> Vec<String> {
    if files.is_empty() && !vendored_removed {
        return Vec::new();
    }
    let mut commit: Vec<String> = Vec::new();
    if vendored_removed {
        commit.push(if ledger_written {
            ".socket/vendor/ (the redirect ledger, plus the removed vendored ledger entries and \
             artifacts)"
                .to_string()
        } else {
            ".socket/vendor/ (the removed vendored ledger entries and artifacts)".to_string()
        });
    } else if ledger_written {
        commit.push(".socket/vendor/redirect-state.json".to_string());
    }
    commit.extend(files.iter().cloned());
    let npm = files
        .iter()
        .any(|f| f == "package-lock.json" || f == "npm-shrinkwrap.json");
    let hint = if npm { " (e.g. `npm ci`)" } else { "" };
    vec![
        format!("Commit {} to keep the redirect.", join_names(&commit, 6)),
        format!(
            "Reinstall from the updated lockfile{hint} so the installed packages pick up the \
             patched artifacts, then run `socket-patch vex` to verify them."
        ),
    ]
}

/// Transient-frame boxed constructor for [`run_redirect_selected`] — the
/// future embeds the whole hosted engine, and callers outside scan (`get
/// --mode hosted`) must not materialize it in their own poll frame (Windows
/// 1 MiB main-thread stack; same rationale as scan's `boxed_*` family).
pub(crate) fn boxed_run_redirect_selected<'a>(
    common: &'a crate::args::GlobalArgs,
    vex: &'a crate::commands::vex::VexEmbedArgs,
    prune_requested: bool,
    api_client: &'a socket_patch_core::api::client::ApiClient,
    selected: &'a [(String, String)],
    scan_result: Option<serde_json::Value>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_redirect_selected(
        common,
        vex,
        prune_requested,
        api_client,
        selected,
        scan_result,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        build_redirect_json_envelope, gem_stale_cache_warning, gem_stale_install_warning,
        gem_stale_install_warnings, installed_stale_positive_evidence,
        npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
        npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
        npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
        npm_allow_remote_user_set_detail, plan_workspace_trust, pnpm_heal_root,
        pnpm_lock_carries_hosted_redirect, pnpm_lock_version_major, pnpm_trust_configured_detail,
        pnpm_trust_legacy_detail, pnpm_trust_manual_guidance,
        pnpm_trust_workspace_unreadable_detail, prune_ignored_warning, read_npmrc_for_allow_remote,
        read_workspace_for_trust, redirect_json_block, TrustPlan, REDIRECT_CANDIDATE_FILES,
    };
    use super::{
        describe_skip_reason, format_error_line, format_next_steps, format_redirect_summary,
        format_takeover_line, format_unredirected, format_warning, join_names,
        pnpm_lock_may_need_store_flag, pnpm_trust_rerun_reminder, sentence_case, split_sentences,
        wrap_tokens, wrap_words, TAKEOVER_INFO_CODES,
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
            // The summary line already says it is a dry run; a marker
            // inside the noun phrase ("a new (--dry-run) pnpm-workspace")
            // read as garbled.
            assert!(!dry.contains("--dry-run"), "{dry}");
            let want = if created {
                "so `trustLockfile: true` would be written to a new pnpm-workspace.yaml — commit"
            } else {
                "so `trustLockfile: true` would be merged into the existing pnpm-workspace.yaml — commit"
            };
            assert!(dry.contains(want), "{dry}");
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
        assert!(legacy.contains("pnpm 1–8"), "{legacy}");
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
        // Built through the ONE spelling of the block (the production
        // site and `run`'s zero-discovery arm use the same helper), so the
        // key set asserted below is the tested single source.
        let redirect = redirect_json_block(
            1,
            vec!["package-lock.json".to_string()],
            Vec::new(),
            vec![prune_ignored_warning()],
            false,
        );
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
    /// no artifact shas) — tests override the knobs they exercise.
    /// `records` is the merged map production hands over (this run's
    /// fetched records plus the ledger's persisted ones).
    async fn probe(
        cwd: &std::path::Path,
        confirmed: &[(String, String)],
        records: &std::collections::BTreeMap<String, PatchRecord>,
    ) -> super::StaleInstallOutcome {
        gem_stale_install_warnings(
            cwd,
            false,
            None,
            confirmed,
            records,
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
    async fn installed_stale_positive_evidence_requires_readable_mismatched_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let record = gem_record();

        // Pristine upstream bytes → evidence.
        let upstream = tmp.path().join("upstream");
        std::fs::create_dir_all(upstream.join("lib")).unwrap();
        std::fs::write(upstream.join("lib").join("stale_unit.rb"), GEM_UPSTREAM).unwrap();
        assert!(installed_stale_positive_evidence(&upstream, &record).await);

        // Tampered bytes (neither hash) → evidence.
        let tampered = tmp.path().join("tampered");
        std::fs::create_dir_all(tampered.join("lib")).unwrap();
        std::fs::write(tampered.join("lib").join("stale_unit.rb"), b"other").unwrap();
        assert!(installed_stale_positive_evidence(&tampered, &record).await);

        // Patched bytes → no evidence.
        let patched = tmp.path().join("patched");
        std::fs::create_dir_all(patched.join("lib")).unwrap();
        std::fs::write(patched.join("lib").join("stale_unit.rb"), GEM_PATCHED).unwrap();
        assert!(!installed_stale_positive_evidence(&patched, &record).await);

        // Missing file → no evidence (never a guess).
        let hollow = tmp.path().join("hollow");
        std::fs::create_dir_all(hollow.join("lib")).unwrap();
        assert!(!installed_stale_positive_evidence(&hollow, &record).await);

        // A DIRECTORY at the file path (the unreadable-NotFound class) →
        // no evidence.
        let blocked = tmp.path().join("blocked");
        std::fs::create_dir_all(blocked.join("lib").join("stale_unit.rb")).unwrap();
        assert!(!installed_stale_positive_evidence(&blocked, &record).await);

        // Absent new-file (empty beforeHash routes to Ready with NO
        // current_hash) → no evidence.
        let mut new_file = gem_record();
        new_file
            .files
            .get_mut("lib/stale_unit.rb")
            .expect("fixture file entry")
            .before_hash = String::new();
        assert!(!installed_stale_positive_evidence(&hollow, &new_file).await);
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

    /// RE-FIRE guarantee: when this run's record fetch failed (no fresh
    /// records), the merged map the caller hands over still carries the
    /// redirect ledger's PERSISTED record under whatever purl key the
    /// ledger used — and the probe's uuid lookup judges from it, so a
    /// transient /patches/view failure cannot silently retire the warning
    /// while the stale materialization is still there.
    #[tokio::test]
    async fn gem_stale_probe_judges_from_persisted_ledger_records() {
        let stale = tempfile::tempdir().unwrap();
        materialize_gem(stale.path(), GEM_UPSTREAM);
        // Persisted under the API's qualified spelling, not the confirmed
        // purl: only the uuid links them.
        let mut ledger_only = std::collections::BTreeMap::new();
        ledger_only.insert(format!("{GEM_PURL}?platform=ruby"), gem_record());
        let out = probe(stale.path(), &one_confirmed(), &ledger_only).await;
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
            &shas,
        )
        .await;
        assert!(out.warnings.is_empty());
    }

    /// Committed `vendor/cache` fold, UNKNOWN-sha arm (`_ => false`): when
    /// the run carries NO artifact sha for the gem (empty shas map — e.g. a
    /// reference served without a gem checksum), a committed archive beside
    /// a stale install must STILL be folded into the delete list. Removal is
    /// safe either way (`bundle install` refetches), so "unknown" must never
    /// downgrade to "proven patched" and leave the archive to silently
    /// reinstate the stale bytes.
    #[tokio::test]
    async fn gem_stale_probe_folds_committed_cache_with_unknown_artifact_sha() {
        let tmp = tempfile::tempdir().unwrap();
        materialize_gem(tmp.path(), GEM_UPSTREAM);
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, b"upstream archive bytes").unwrap();

        // `probe()` passes an EMPTY gem_artifact_shas map: the
        // (None, Some(_)) pair must take the fold-anyway arm.
        let out = probe(tmp.path(), &one_confirmed(), &one_record()).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "one stale install, one warning (cache folded, not standalone): {:?}",
            out.warnings
        );
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&committed.display().to_string()),
            "the committed archive must join the delete list even with no \
             known artifact sha: {detail}"
        );
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()])
        );
        // Read-only contract: the archive itself is never deleted.
        assert!(committed.is_file(), "the probe prescribes, never deletes");
    }

    /// Standalone cache pass 3, UNREADABLE-archive arm: a committed archive
    /// whose bytes cannot be read (chmod 000) yields NO positive evidence,
    /// so the probe must stay silent instead of guessing staleness from the
    /// differing expected sha — the never-warn-without-positive-evidence
    /// contract, archive flavor.
    #[cfg(unix)]
    #[tokio::test]
    async fn gem_stale_probe_never_judges_unreadable_committed_archive() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // NO installed gem dir (fresh-checkout shape) so pass 3 is the only
        // judgment path.
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, b"upstream archive bytes").unwrap();
        std::fs::set_permissions(&committed, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root ignores mode bits: detect it while the chmod is in force so
        // the assertion below matches what the probe could actually read.
        let readable_despite_chmod = std::fs::File::open(&committed).is_ok();

        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64), // differs from the archive bytes' sha
        );
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        std::fs::set_permissions(&committed, std::fs::Permissions::from_mode(0o644)).unwrap();

        if readable_despite_chmod {
            // Running as root: the archive WAS readable and its sha differs,
            // so the ordinary stale-cache warning is the correct outcome.
            assert_eq!(out.warnings.len(), 1, "root fallback: readable + stale");
        } else {
            assert!(
                out.warnings.is_empty(),
                "an unreadable archive is never staleness evidence: {:?}",
                out.warnings
            );
            assert!(out.stale_purls.is_empty());
        }
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
        // (binary candidates are read separately).
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
    // ── Human-output formatting ────────────────────────────────────────────

    #[test]
    fn redirect_summary_singular_plural_and_dry_run() {
        assert_eq!(
            format_redirect_summary(1, 1, false),
            "Redirected 1 package; rewrote 1 file."
        );
        assert_eq!(
            format_redirect_summary(2, 3, false),
            "Redirected 2 packages; rewrote 3 files."
        );
        assert_eq!(
            format_redirect_summary(0, 0, false),
            "Redirected 0 packages; rewrote 0 files."
        );
        assert_eq!(
            format_redirect_summary(1, 1, true),
            "Would redirect 1 package and rewrite 1 file (--dry-run: nothing was changed)."
        );
        assert_eq!(
            format_redirect_summary(0, 0, true),
            "Would redirect 0 packages and rewrite 0 files (--dry-run: nothing was changed)."
        );
        assert_eq!(
            format_redirect_summary(2, 5, true),
            "Would redirect 2 packages and rewrite 5 files (--dry-run: nothing was changed)."
        );
    }

    #[test]
    fn redirect_summary_already_redirected_is_not_redirected_n() {
        // Confirmed but nothing to write: an idempotent re-run, never
        // "Redirected 1 package(s); rewrote 0 file(s)".
        for dry in [false, true] {
            assert_eq!(
                format_redirect_summary(1, 0, dry),
                "1 package is already redirected; nothing to rewrite."
            );
            assert_eq!(
                format_redirect_summary(3, 0, dry),
                "3 packages are already redirected; nothing to rewrite."
            );
        }
    }

    #[test]
    fn skip_reasons_are_readable_and_unknown_codes_pass_through() {
        assert_eq!(
            describe_skip_reason("forbidden"),
            "not entitled to this patch (paid plan or no org access)"
        );
        assert_eq!(
            describe_skip_reason("pending"),
            "the hosted artifact is still being built; re-run later"
        );
        assert_eq!(
            describe_skip_reason("not_found"),
            "the hosted patch server has no artifact for this patch"
        );
        assert_eq!(
            describe_skip_reason("vendored_revert_failed"),
            "its vendored state could not be reverted (see the warning)"
        );
        assert_eq!(
            describe_skip_reason("redirect_bun_lockb_invalid"),
            describe_skip_reason("redirect_bun_lock_unsupported")
        );
        assert_eq!(describe_skip_reason("mystery"), "server status `mystery`");
        for code in [
            "not_found",
            "forbidden",
            "pending",
            "pending_build",
            "build_failed",
            "withdrawn",
            "bad_purl",
            "no_url",
            "python_metadata_unavailable",
        ] {
            let text = describe_skip_reason(code);
            assert!(!text.contains('_'), "{code} → {text}");
        }
    }

    #[test]
    fn unredirected_lines_empty_partial_and_nothing_redirected() {
        assert!(format_unredirected(&[], &[], true, 1).is_empty());
        let skipped = vec![(
            "pkg:npm/lodash@4.17.20".to_string(),
            "forbidden".to_string(),
        )];
        let unconfirmed = vec!["pkg:npm/minimist@1.2.5".to_string()];
        assert_eq!(
            format_unredirected(&skipped, &unconfirmed, false, 1),
            vec![
                "Skipped pkg:npm/lodash@4.17.20: not entitled to this patch (paid plan or no \
                 org access)"
                    .to_string(),
                "Not redirected pkg:npm/minimist@1.2.5: no lockfile entry pinning it could be \
                 redirected (see the warning below)"
                    .to_string(),
            ]
        );
        assert_eq!(
            format_unredirected(&[], &unconfirmed, false, 2),
            vec![
                "Not redirected pkg:npm/minimist@1.2.5: no lockfile entry pinning it could be \
                 redirected (see the warnings below)"
                    .to_string(),
            ]
        );
        assert_eq!(
            format_unredirected(&[], &unconfirmed, true, 0),
            vec![
                "No patches could be redirected:".to_string(),
                "  pkg:npm/minimist@1.2.5: no lockfile entry pinning it could be redirected"
                    .to_string(),
            ]
        );
        assert_eq!(
            format_unredirected(&skipped, &[], true, 0),
            vec![
                "No patches could be redirected:".to_string(),
                "  pkg:npm/lodash@4.17.20: not entitled to this patch (paid plan or no org \
                 access)"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn takeover_lines_wet_and_dry() {
        assert_eq!(
            format_takeover_line("pkg:npm/lodash@4.17.20", false),
            "Migrated pkg:npm/lodash@4.17.20 from vendored to hosted (reverted its vendored \
             wiring, ledger entry, and committed artifact)."
        );
        assert_eq!(
            format_takeover_line("pkg:npm/lodash@4.17.20", true),
            "Would migrate pkg:npm/lodash@4.17.20 from vendored to hosted (its vendored \
             wiring, ledger entry, and committed artifact would be reverted first)."
        );
        assert!(TAKEOVER_INFO_CODES.contains(&"redirect_takeover_reverted_vendored"));
        assert!(TAKEOVER_INFO_CODES.contains(&"redirect_would_revert_vendored"));
        assert!(!TAKEOVER_INFO_CODES.contains(&"redirect_vendored_revert_failed"));
    }

    #[test]
    fn sentence_case_skips_identifiers_and_tool_names() {
        assert_eq!(
            sentence_case("failed to write x: y"),
            "Failed to write x: y"
        );
        assert_eq!(
            sentence_case("the redirect ledger ./a is malformed"),
            "The redirect ledger ./a is malformed"
        );
        assert_eq!(sentence_case("pnpm >=11 rejects"), "pnpm >=11 rejects");
        assert_eq!(
            sentence_case("pnpm-lock.yaml was repointed"),
            "pnpm-lock.yaml was repointed"
        );
        assert_eq!(
            sentence_case("pkg:npm/x@1 redirected"),
            "pkg:npm/x@1 redirected"
        );
        assert_eq!(sentence_case("`vendor` refused"), "`vendor` refused");
        assert_eq!(sentence_case("Already upper"), "Already upper");
        assert_eq!(sentence_case(""), "");
        assert_eq!(sentence_case("é accent"), "é accent");
        assert_eq!(
            format_error_line("failed to resolve patch references: boom"),
            "Error: Failed to resolve patch references: boom"
        );
    }

    #[test]
    fn wrap_words_respects_width_prefix_and_long_words() {
        assert_eq!(
            wrap_words("alpha beta gamma delta", 16, "W: ", "  "),
            vec!["W: alpha beta", "  gamma delta"]
        );
        // A word wider than the line sits alone, unsplit.
        let url = "https://patch.socket.dev/very/long/path/that/does/not/fit";
        assert_eq!(
            wrap_words(&format!("see {url} now"), 20, "", "  "),
            vec!["see".to_string(), format!("  {url}"), "  now".to_string()]
        );
        assert_eq!(wrap_words("", 10, "W: ", "  "), vec!["W: "]);
        // Counts characters, not bytes.
        let lines = wrap_words("ééé ééé ééé", 8, "", "");
        assert_eq!(lines, vec!["ééé ééé", "ééé"]);
        for line in wrap_words(&"word ".repeat(50), 30, "Warning (x): ", "  ") {
            assert!(line.chars().count() <= 30, "{line}");
        }
    }

    #[test]
    fn wrap_words_keeps_code_spans_whole() {
        // The span crosses the wrap column: it moves to the next line whole.
        assert_eq!(
            wrap_words(
                "never rebuild it (`pnpm clean --lockfile`), ever",
                30,
                "",
                "  "
            ),
            vec!["never rebuild it", "  (`pnpm clean --lockfile`),", "  ever"]
        );
        // A span wider than the line gets a line of its own, unsplit.
        assert_eq!(
            wrap_words(
                "use `pnpm install --frozen-lockfile --store-dir <dir>` now",
                20,
                "",
                "  "
            ),
            vec![
                "use",
                "  `pnpm install --frozen-lockfile --store-dir <dir>`",
                "  now"
            ]
        );
        // Two spans in one word, and a word with a closed span, split normally.
        assert_eq!(
            wrap_tokens("a `b` c `d e`f g"),
            vec!["a", "`b`", "c", "`d e`f", "g"]
        );
        // An unclosed span never swallows the rest of the text.
        assert_eq!(wrap_tokens("a `b c d"), vec!["a", "`b", "c", "d"]);
    }

    #[test]
    fn split_sentences_keeps_hosts_and_versions_whole() {
        assert_eq!(
            split_sentences("Repointed at patch.socket.dev. Keep lock 5.4 committed. done"),
            vec![
                "Repointed at patch.socket.dev.",
                "Keep lock 5.4 committed.",
                "done"
            ]
        );
        assert_eq!(split_sentences("one"), vec!["one"]);
        assert!(split_sentences("  ").is_empty());
    }

    #[test]
    fn warning_line_one_line_in_pipes_and_wrapped_on_terminals() {
        assert_eq!(
            format_warning(
                "redirect_npm_no_lockfile",
                "no package-lock.json present",
                None
            ),
            "Warning (redirect_npm_no_lockfile): No package-lock.json present"
        );
        let long = "word ".repeat(40);
        let wrapped = format_warning("c", &long, Some(40));
        assert!(wrapped.lines().count() > 1, "{wrapped}");
        assert!(
            wrapped.lines().all(|l| l.chars().count() <= 40),
            "{wrapped}"
        );
        assert!(wrapped.starts_with("Warning (c): Word word"), "{wrapped}");
        assert!(
            wrapped.lines().skip(1).all(|l| l.starts_with("  ")),
            "{wrapped}"
        );
    }

    #[test]
    fn pnpm_warning_renders_headline_plus_bullets() {
        let detail = "pnpm-lock.yaml was repointed at the server; so it goes. Note: a tradeoff. \
                      Do NOT rebuild the lockfile. Run `socket-patch vex` after installation.";
        assert_eq!(
            format_warning("redirect_pnpm_trust_lockfile", detail, None),
            "Warning (redirect_pnpm_trust_lockfile): pnpm-lock.yaml was repointed at the \
             server; so it goes.\n  - Note: a tradeoff.\n  - Do NOT rebuild the lockfile.\n  \
             - Run `socket-patch vex` after installation."
        );
        let wrapped = format_warning("redirect_pnpm_trust_lockfile", detail, Some(60));
        for line in wrapped.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
        assert_eq!(
            wrapped,
            "Warning (redirect_pnpm_trust_lockfile): pnpm-lock.yaml was\n  \
             repointed at the server; so it goes.\n  - Note: a tradeoff.\n  - Do NOT \
             rebuild the lockfile.\n  - Run `socket-patch vex` after installation."
        );
        // Continuation lines of a long bullet are indented under its text.
        let bullet = "Head. Do NOT follow the advice to rebuild the lockfile, which discards it.";
        assert_eq!(
            format_warning("redirect_pnpm_trust_lockfile", bullet, Some(40)),
            "Warning (redirect_pnpm_trust_lockfile): Head.\n  - Do NOT follow the advice to \
             rebuild\n    the lockfile, which discards it."
        );
    }

    #[test]
    fn pnpm_rerun_reminder_keeps_the_rebuild_caution() {
        let r = pnpm_trust_rerun_reminder();
        assert!(r.contains("trustLockfile: true"), "{r}");
        assert!(r.contains("pnpm clean --lockfile"), "{r}");
        assert!(r.chars().count() < 240, "a reminder, not the wall: {r}");
    }

    #[test]
    fn store_flag_note_only_for_pnpm_one_to_four_locks() {
        assert!(pnpm_lock_may_need_store_flag("shrinkwrapVersion: 3\n"));
        assert!(pnpm_lock_may_need_store_flag("lockfileVersion: 5.1\n"));
        assert!(pnpm_lock_may_need_store_flag("lockfileVersion: '5.2'\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: 5.3\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: 5.4\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: '6.0'\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: '9.0'\n"));
        assert!(!pnpm_lock_may_need_store_flag("packages: {}\n"));
    }

    #[test]
    fn join_names_lists_and_caps() {
        let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(join_names(&n(&[]), 6), "");
        assert_eq!(join_names(&n(&["a"]), 6), "a");
        assert_eq!(join_names(&n(&["a", "b"]), 6), "a and b");
        assert_eq!(join_names(&n(&["a", "b", "c"]), 6), "a, b, and c");
        assert_eq!(join_names(&n(&["a", "b", "c", "d"]), 2), "a, b, and 2 more");
    }

    #[test]
    fn next_steps_name_the_ledger_files_and_reinstall() {
        assert!(format_next_steps(&[], true, false).is_empty());
        assert_eq!(
            format_next_steps(&["package-lock.json".to_string()], true, false),
            vec![
                "Commit .socket/vendor/redirect-state.json and package-lock.json to keep the \
                 redirect."
                    .to_string(),
                "Reinstall from the updated lockfile (e.g. `npm ci`) so the installed packages \
                 pick up the patched artifacts, then run `socket-patch vex` to verify them."
                    .to_string(),
            ]
        );
        let steps = format_next_steps(
            &[
                "pnpm-lock.yaml".to_string(),
                "pnpm-workspace.yaml".to_string(),
            ],
            false,
            false,
        );
        assert_eq!(
            steps[0],
            "Commit pnpm-lock.yaml and pnpm-workspace.yaml to keep the redirect."
        );
        assert!(!steps[1].contains("npm ci"), "{}", steps[1]);
    }

    #[test]
    fn next_steps_after_a_takeover_name_the_removed_vendored_state() {
        assert_eq!(
            format_next_steps(&["package-lock.json".to_string()], true, true)[0],
            "Commit .socket/vendor/ (the redirect ledger, plus the removed vendored ledger \
             entries and artifacts) and package-lock.json to keep the redirect."
        );
        assert_eq!(
            format_next_steps(&["pnpm-lock.yaml".to_string()], false, true)[0],
            "Commit .socket/vendor/ (the removed vendored ledger entries and artifacts) and \
             pnpm-lock.yaml to keep the redirect."
        );
    }

    /// REGRESSION (npm 12): every hosted npm redirect variant tells the user
    /// that npm >= 12 refuses the redirected lock (EALLOWREMOTE) without
    /// `allow-remote=all`, and carries the whole-tree tradeoff disclosure —
    /// the auto-configured, already-set, explicit-other, opted-out and
    /// unreadable variants alike.
    #[test]
    fn npm_allow_remote_warning_variants_carry_the_load_bearing_sentences() {
        let hosts = ["patch.socket.dev"];
        let variants = [
            npm_allow_remote_configured_detail(&hosts, true, false),
            npm_allow_remote_configured_detail(&hosts, false, false),
            npm_allow_remote_configured_detail(&hosts, true, true),
            npm_allow_remote_configured_detail(&hosts, false, true),
            npm_allow_remote_already_detail(&hosts),
            npm_allow_remote_user_set_detail(&hosts, "root"),
            npm_allow_remote_manual_detail(&hosts),
            npm_allow_remote_unreadable_detail(&hosts, "could not be read (denied)"),
            npm_allow_remote_env_set_detail(&hosts, "npm_config_allow_remote", "none"),
            npm_allow_remote_outer_set_detail(
                &hosts,
                "user",
                std::path::Path::new("/home/u/.npmrc"),
                "none",
            ),
        ];
        for d in &variants {
            for needle in [
                "patch.socket.dev",
                "npm >=12",
                "EALLOWREMOTE",
                "lets npm install ANY url-resolved",
                "sha512 integrity pins are still enforced",
                "npm <=11 installs work unchanged",
            ] {
                assert!(d.contains(needle), "{needle:?} missing: {d}");
            }
        }
        let [created, appended, dry_created, dry_appended, already, user_set, manual, unreadable, env_set, outer_set] =
            &variants;
        assert!(
            env_set.contains("npm_config_allow_remote=none")
                && env_set.contains("overrides every .npmrc")
                && env_set.contains("would not take effect")
                && env_set.contains("left untouched"),
            "{env_set}"
        );
        assert!(
            outer_set.contains("The user npm config (/home/u/.npmrc)")
                && outer_set.contains("explicitly sets `allow-remote=none`")
                && outer_set.contains("does not commit a project .npmrc that overrides it"),
            "{outer_set}"
        );
        assert!(
            created.contains("was written to a new project .npmrc"),
            "{created}"
        );
        assert!(
            appended.contains("was appended to the existing project .npmrc"),
            "{appended}"
        );
        // The summary line already says it is a dry run (the pnpm
        // trustLockfile twin's rule): no marker inside the noun phrase.
        assert!(
            dry_created.contains("would be written to a new project .npmrc")
                && !dry_created.contains("(--dry-run)"),
            "{dry_created}"
        );
        assert!(
            dry_appended.contains("would be appended to the existing project .npmrc")
                && !dry_appended.contains("(--dry-run)"),
            "{dry_appended}"
        );
        for d in [created, appended, dry_created, dry_appended] {
            assert!(
                d.contains("--no-npm-allow-remote-config"),
                "opt-out named: {d}"
            );
            assert!(d.contains("SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG"), "{d}");
        }
        assert!(
            already.contains("already sets `allow-remote=all`"),
            "{already}"
        );
        assert!(
            user_set.contains("explicitly sets `allow-remote=root`"),
            "{user_set}"
        );
        assert!(
            user_set.contains("respected and left untouched"),
            "{user_set}"
        );
        assert!(
            user_set.contains("only admits direct dependencies"),
            "{user_set}"
        );
        for d in [user_set, manual, unreadable, env_set, outer_set] {
            assert!(
                d.contains("npm ci --allow-remote=all"),
                "manual remedy: {d}"
            );
        }
        assert!(
            unreadable.contains("could not be read (denied)"),
            "{unreadable}"
        );
    }

    /// The `.npmrc` read classifier: absent → plan a Create; readable →
    /// plan against the text; a symlink or unreadable file → hands off
    /// (never planned — a Create would clobber the user's config, and the
    /// atomic writer would replace a link).
    #[test]
    fn read_npmrc_for_allow_remote_classifies_absent_readable_and_unsafe() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".npmrc");
        assert_eq!(read_npmrc_for_allow_remote(&path), Ok(None));
        std::fs::write(&path, "fund=false\n").unwrap();
        assert_eq!(
            read_npmrc_for_allow_remote(&path),
            Ok(Some("fund=false\n".into()))
        );
        std::fs::write(&path, [0xff_u8, 0xfe]).unwrap();
        assert!(read_npmrc_for_allow_remote(&path)
            .unwrap_err()
            .contains("could not be read"));
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            std::fs::write(tmp.path().join("real"), "fund=false\n").unwrap();
            std::os::unix::fs::symlink(tmp.path().join("real"), &path).unwrap();
            assert!(read_npmrc_for_allow_remote(&path)
                .unwrap_err()
                .contains("symbolic link"));
        }
    }
}
