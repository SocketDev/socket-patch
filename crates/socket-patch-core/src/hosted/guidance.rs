//! The install-policy guidance of the hosted flow: the pnpm `trustLockfile`
//! and npm `allow-remote` auto-config planners and every warning text they
//! emit, shared verbatim by the disk and in-memory engines.

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
pub fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!host.is_empty()).then_some(host)
}

/// Repo-relative path of the pnpm workspace manifest the trustLockfile
/// auto-config edits (the same file the vendor backend's override surface
/// uses).
pub const PNPM_WORKSPACE_REL: &str = "pnpm-workspace.yaml";

/// `FileEdit.kind` recorded when the hosted flow ensures `trustLockfile:
/// true` in pnpm-workspace.yaml. `action: "created"` — the workspace file
/// itself was created (a revert deletes it); `action: "added"` — the single
/// `trustLockfile: true` line was appended to an existing file (a revert
/// removes exactly that line). Additive ledger vocabulary: older ledgers
/// without it load unchanged (kind is an opaque string to the loader).
pub const REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND: &str = "redirect_pnpm_workspace_trust";

/// The honest-tradeoff + don't-rebuild tail shared by every trustLockfile
/// warning variant. The tradeoff sentence is a security disclosure, not
/// prose garnish: `trustLockfile: true` disables pnpm's lockfile
/// re-verification for the WHOLE lock, so it must be stated wherever the
/// setting is written or recommended.
pub const PNPM_TRUST_TRADEOFF_AND_CAUTION: &str =
    "Note: trustLockfile makes pnpm skip its lockfile re-verification \
     (minimumReleaseAge / trustPolicy re-checks) for ALL lockfile entries, \
     not just the patched ones — the per-entry sha512 integrity pins are \
     still enforced. Do NOT follow pnpm's advice to rebuild the lockfile \
     (`pnpm clean --lockfile`): that silently discards the hosted patches and \
     reinstalls the vulnerable upstream artifact. pnpm <=10 ignores the \
     setting and installs work unchanged";

/// The policy preamble shared by every trustLockfile warning variant:
/// what was repointed, and how pnpm >=11 fails without trust.
pub fn pnpm_trust_policy_preamble(server: &str) -> String {
    format!(
        "pnpm-lock.yaml was repointed at {server}; pnpm >=11 rejects the \
         rewritten lock (pnpm 11: ERR_PNPM_TARBALL_URL_MISMATCH, pnpm 12: \
         ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION)"
    )
}

/// The pre-auto-config guidance, kept verbatim for the runs where the
/// auto-config does not apply (legacy 5.x/6.0 locks, Rush nested locks,
/// `--no-trust-lockfile-config`): both verified recoveries, spelled exactly.
pub fn pnpm_trust_manual_guidance(server: &str) -> String {
    format!(
        "{}. Install with `pnpm install --trust-lockfile`, or commit \
         `trustLockfile: true` in pnpm-workspace.yaml so every install \
         accepts the patched artifacts. Do NOT follow pnpm's advice to \
         rebuild the lockfile (`pnpm clean --lockfile`): that silently \
         discards the hosted patches and reinstalls the vulnerable upstream \
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
pub fn pnpm_trust_legacy_detail(server: &str) -> String {
    format!(
        "The pnpm lockfile was repointed at {server}. This is a legacy \
         lock read by pnpm 1–8, which have no \
         lockfile trust policy: no trust step exists or is needed. Do NOT regenerate the lockfile \
         (deleting it, or re-resolving on a newer pnpm): that silently \
         discards the hosted patches and reinstalls the vulnerable upstream \
         artifact. If the project later moves to pnpm >=9, re-run \
         `socket-patch scan --mode hosted` so the regenerated lock is \
         switched to hosted (and trust-configured) again"
    )
}

/// The unreadable-workspace fallback: pnpm-workspace.yaml EXISTS but could
/// not be read (permissions, invalid UTF-8, I/O error). Planning a Create
/// here would OVERWRITE the user's file with the root-only scaffold —
/// destroying their `packages:` globs — so the auto-config stands down and
/// the warning names the file, the error, and both manual recoveries.
pub fn pnpm_trust_workspace_unreadable_detail(server: &str, err: &std::io::Error) -> String {
    format!(
        "{}. {PNPM_WORKSPACE_REL} exists but could not be read ({err}); it \
         was left untouched — auto-configuring trust would risk overwriting \
         it. Fix the file, then install with `pnpm install --trust-lockfile` \
         or add `trustLockfile: true` to it yourself so every install \
         accepts the patched artifacts. Do NOT follow pnpm's advice to \
         rebuild the lockfile (`pnpm clean --lockfile`): that silently \
         discards the hosted patches and reinstalls the vulnerable upstream \
         artifact. pnpm <=10 installs work unchanged",
        pnpm_trust_policy_preamble(server),
    )
}

/// The pnpm-workspace.yaml read, classified for the trust auto-config:
/// `Ok(Some(text))` — read fine; `Ok(None)` — ABSENT (`ErrorKind::NotFound`,
/// the only state where planning a Create is safe); `Err(e)` — present but
/// unreadable, so the caller must fall back to warning-only guidance
/// (planning a Create would overwrite the user's `packages:` globs).
///
/// FIFO-safe (`read_regular_to_string_sync`: non-blocking open + fstat): a
/// FIFO planted at the path classifies as unreadable (`InvalidInput`) instead
/// of wedging the run in `open(2)`.
pub fn read_workspace_for_trust(path: &std::path::Path) -> std::io::Result<Option<String>> {
    match crate::utils::fs::read_regular_to_string_sync(path) {
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
/// run, or a crash between the lock write and the workspace write).
pub fn pnpm_lock_carries_hosted_redirect(
    lock_text: &str,
    overrides: &[crate::patch::redirect::DepOverride],
) -> bool {
    let groups: Vec<Vec<String>> = overrides
        .iter()
        .filter(|o| o.ecosystem == "npm")
        .map(|o| npm_lock_url_needles(&o.artifact_url))
        .collect();
    crate::patch::redirect::presence::groups_present(&[lock_text], &groups)
        .into_iter()
        .any(|present| present)
}

/// The spellings of an npm artifact URL a pnpm lock may carry — raw or
/// `\/`-escaped ([`artifact_url_spellings`](crate::patch::redirect::artifact_url_spellings),
/// the `artifact_url_present` pair) plus the percent-encoded form — searched
/// in one multi-needle pass ([`groups_present`](crate::patch::redirect::presence::groups_present)).
pub fn npm_lock_url_needles(artifact_url: &str) -> Vec<String> {
    let mut needles: Vec<String> =
        crate::patch::redirect::artifact_url_spellings(artifact_url).into();
    needles.push(crate::utils::uri::encode_uri_component(artifact_url));
    needles
}

/// The HEAL-ON-RERUN gate: when this run spliced no root pnpm-lock.yaml
/// (`root_spliced` false) but the on-disk root lock is v9 and already
/// carries a granted hosted artifact URL, return its text so the trust
/// block engages anyway. Legacy (<9) and unparseable-version locks stay
/// `None` (fail closed: never write config for a lock era we can't read),
/// as does a root lock this run DID splice (the splice path covers it).
pub fn pnpm_heal_root<'a>(
    root_spliced: bool,
    disk_root: Option<&'a String>,
    overrides: &[crate::patch::redirect::DepOverride],
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
pub fn pnpm_trust_configured_detail(server: &str, created: bool, dry_run: bool) -> String {
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

// The pnpm lock-version sniffs live with the format's model.
pub use crate::formats::pnpm::{
    lock_version_major as pnpm_lock_version_major,
    may_need_store_flag as pnpm_lock_may_need_store_flag,
};

/// The planned pnpm-workspace.yaml `trustLockfile: true` edit.
pub enum TrustPlan {
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
pub fn plan_workspace_trust(existing: Option<&str>) -> TrustPlan {
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
pub const NPM_LOCKS: [&str; 2] = ["npm-shrinkwrap.json", "package-lock.json"];

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
pub fn npm_allow_remote_configured_detail(hosts: &[&str], created: bool, dry_run: bool) -> String {
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
pub fn npm_allow_remote_already_detail(hosts: &[&str]) -> String {
    format!(
        "{}, and the project .npmrc already sets `allow-remote=all` — keep it committed \
         alongside the lock; `npm ci` needs no extra flags. {NPM_ALLOW_REMOTE_TRADEOFF}",
        npm_allow_remote_preamble(hosts),
    )
}

/// The user explicitly set another value: respected, never flipped (the
/// pnpm `trustLockfile: false` precedent) — the warning names the manual
/// recoveries instead.
pub fn npm_allow_remote_user_set_detail(hosts: &[&str], value: &str) -> String {
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
pub fn npm_allow_remote_env_set_detail(hosts: &[&str], var: &str, value: &str) -> String {
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
pub fn npm_allow_remote_outer_set_detail(
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
pub fn npm_allow_remote_manual_detail(hosts: &[&str]) -> String {
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
pub fn npm_allow_remote_unreadable_detail(hosts: &[&str], why: &str) -> String {
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
pub fn read_npmrc_for_allow_remote(path: &std::path::Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not be inspected ({e})")),
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err("is a symbolic link (socket-patch never writes through one)".into())
        }
        Ok(_) => {}
    }
    crate::utils::fs::read_regular_to_string_sync(path)
        .map(Some)
        .map_err(|e| format!("could not be read ({e})"))
}
