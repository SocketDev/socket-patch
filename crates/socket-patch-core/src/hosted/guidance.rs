//! The install-policy guidance of the hosted flow: the pnpm `trustLockfile`
//! and npm `allow-remote` auto-config planners and every warning text they
//! emit, shared verbatim by the disk and in-memory engines.

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

/// The Rush variant (#713): every touched pnpm lock is a Rush common or
/// subspace lock. rush runs pnpm in common/temp with a pnpm-workspace.yaml
/// it generates itself, and pnpm-config.json has no `trustLockfile` key, so
/// neither the repo-root workspace key nor `pnpm install --trust-lockfile`
/// reaches the install — the only knob rush forwards is pnpm's
/// `pnpm_config_trust_lockfile` env var. pnpm 11 additionally re-resolves a
/// trusted hosted entry back to the registry under the
/// `--no-prefer-frozen-lockfile` flag `rush install` passes by default
/// (exit 0, upstream bytes), which the `usePnpmFrozenLockfileForRushInstall`
/// experiment turns off. Verified with rush 5.180.0 on pnpm 11.0.0, 11.28.3
/// and 12.8.1. The tail replaces the generic `--store-dir` reinstall: rush
/// keeps its own store and node_modules under common/temp.
pub fn pnpm_trust_rush_detail(server: &str) -> String {
    format!(
        "The Rush pnpm lockfile was repointed at {server}. pnpm >=11 does not \
         install it under rush's default flow: it either fails \
         (ERR_PNPM_TARBALL_URL_MISMATCH / \
         ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION) or — pnpm 11 — SILENTLY \
         re-resolves the patched entries back to the vulnerable upstream \
         artifact while still exiting 0. rush runs pnpm in common/temp with a \
         pnpm-workspace.yaml it generates itself, so a repo-root \
         `trustLockfile` setting or `--trust-lockfile` flag never reaches it; \
         nothing was written. On pnpm 12, install with \
         `pnpm_config_trust_lockfile=true rush install` (set the variable in \
         CI too). On pnpm 11, also set \
         `\"usePnpmFrozenLockfileForRushInstall\": true` in \
         common/config/rush/experiments.json so `rush install` stops passing \
         `--no-prefer-frozen-lockfile`. pnpm <=10 installs work unchanged. \
         Note: trusting the lockfile makes pnpm skip its lockfile \
         re-verification (minimumReleaseAge / trustPolicy re-checks) for ALL \
         lockfile entries, not just the patched ones — the per-entry sha512 \
         integrity pins are still enforced. Do NOT rebuild the lockfile \
         (`rush update --full`, or deleting it): that silently discards the \
         hosted patches. After a lock-only change, rush's store and \
         node_modules under common/temp can still hold upstream files; run \
         `rush purge` before `rush install` for a reliable reinstall, then \
         run `socket-patch vex` to verify the patched files"
    )
}

/// Appended to the generic trust warning when a run spliced a Rush lock
/// ALONGSIDE a non-Rush pnpm lock, so the Rush half is not left with
/// remedies that never reach rush's install.
pub const PNPM_TRUST_RUSH_MIXED_NOTE: &str =
    "For the Rush lockfiles this run also repointed, none of the above \
     reaches rush's install: use `pnpm_config_trust_lockfile=true rush \
     install` (pnpm 11 also needs `\"usePnpmFrozenLockfileForRushInstall\": \
     true` in common/config/rush/experiments.json) and run `rush purge` \
     first for a clean reinstall";

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

/// The unspliceable-workspace fallback: pnpm-workspace.yaml is valid YAML
/// that a line append would corrupt (a flow-style root, several
/// documents), so the auto-config stands down and the warning names the
/// reason and both manual recoveries.
pub fn pnpm_trust_workspace_unsupported_detail(server: &str, why: &str) -> String {
    format!(
        "{}. {PNPM_WORKSPACE_REL} {why}, which the trust edit cannot extend \
         without corrupting it; it was left untouched. Install with \
         `pnpm install --trust-lockfile`, or add `trustLockfile: true` to it \
         yourself so every install accepts the patched artifacts. Do NOT \
         follow pnpm's advice to rebuild the lockfile (`pnpm clean \
         --lockfile`): that silently discards the hosted patches and \
         reinstalls the vulnerable upstream artifact. pnpm <=10 installs \
         work unchanged",
        pnpm_trust_policy_preamble(server),
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

/// The HEAL-ON-RERUN gate: when this run spliced no governing pnpm lock
/// (`root_spliced` false; the root pnpm-lock.yaml, or a member's own lock
/// under `sharedWorkspaceLockfile: false`) but the on-disk lock is v9 and
/// already carries a granted hosted artifact URL, return its text so the
/// trust block engages anyway. Legacy (<9) and unparseable-version locks stay
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
    // A created file makes the project a root-only workspace, where pnpm
    // 9.0–10.4 refuse `pnpm add` without `-w` (#734); a project pinned to
    // those releases never gets one, so the note names the pin as the way
    // out for an unpinned project with no install record.
    let root_only = if created {
        let then = if dry_run {
            "before the real run".to_string()
        } else {
            format!("then delete {PNPM_WORKSPACE_REL} and re-run")
        };
        format!(
            " On pnpm 9.0–10.4 a root-only workspace needs `pnpm add -w <pkg>` \
             to add dependencies; to avoid the file there, pin that pnpm in \
             package.json `packageManager` (any other pnpm pin — `engines.pnpm`, \
             `devEngines.packageManager`, node_modules/.modules.yaml — must name \
             9.0–10.4 too), {then}."
        )
    } else {
        String::new()
    };
    format!(
        "{}, so {how} {PNPM_WORKSPACE_REL} — commit it alongside the lock; \
         installs need no extra flags.{root_only} {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// The single-package variant on pnpm 9.0–10.4 (#734): the project has no
/// pnpm-workspace.yaml and every pin it carries (`pins`, as prose) is a
/// pnpm that never reads `trustLockfile` but would treat a created file as
/// a root-only workspace and refuse `pnpm add` (ERR_PNPM_ADDING_TO_ROOT),
/// so nothing was written. Names the pnpm >= 11 recovery.
pub fn pnpm_trust_not_needed_detail(server: &str, pins: &str, dry_run: bool) -> String {
    let was = if dry_run { "would be" } else { "was" };
    format!(
        "{}. The project's pnpm ({pins}) does not read `trustLockfile`, so no \
         {PNPM_WORKSPACE_REL} {was} created: on pnpm 9.0–10.4 one would make the \
         project a root-only workspace where `pnpm add <pkg>` fails with \
         ERR_PNPM_ADDING_TO_ROOT. After upgrading to pnpm >=11, re-run \
         `socket-patch scan --mode hosted` to create it, or install with \
         `pnpm install --trust-lockfile`. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

// The pnpm lock-version sniffs live with the format's model.
pub use crate::formats::pnpm::{
    is_shrinkwrap_lock as pnpm_is_shrinkwrap_lock, lock_version_major as pnpm_lock_version_major,
    may_need_store_flag as pnpm_lock_may_need_store_flag,
    root_only_workspace_breaks_add as pnpm_root_only_workspace_breaks_add,
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
    /// The file is valid YAML a line splice cannot extend (a flow-style
    /// root, an indented root, several documents): nothing is written and
    /// the reason is surfaced, since appending would corrupt it.
    Unsupported(String),
}

/// Decide how to ensure `trustLockfile: true` in pnpm-workspace.yaml.
/// Line splices only (never a YAML library), mirroring the vendor backend's
/// workspace surgery: untouched lines stay byte-identical, so a revert can
/// remove exactly what was added.
pub fn plan_workspace_trust(existing: Option<&str>) -> TrustPlan {
    use crate::formats::pnpm::workspace::{block_insert_point, top_level_key};
    let Some(text) = existing else {
        return TrustPlan::Create("packages:\n  - '.'\ntrustLockfile: true\n".to_string());
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    // Where the key would go — refused when the document is not a single
    // block mapping, so the scan for an existing key below is meaningful.
    let anchor = match block_insert_point(&lines) {
        Ok(anchor) => anchor,
        Err(why) => return TrustPlan::Unsupported(why),
    };
    // Top-level key only (every spelling pnpm reads: quoted, `key :`, a
    // trailing comment): an indented `trustLockfile:` under some other
    // mapping is not the setting pnpm reads.
    for line in &lines {
        if let Some((key, value)) = top_level_key(line) {
            if key != "trustLockfile" {
                continue;
            }
            let value = value.trim_matches(|c| c == '\'' || c == '"');
            if value == "true" {
                return TrustPlan::AlreadyTrue;
            }
            return TrustPlan::UserSet(value.to_string());
        }
    }
    // After the document's last non-empty line (no blank separator; before a
    // `...` end marker): a revert removes exactly one line and the file's
    // trailing bytes stay put.
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

/// Warning code for a hosted npm pin that npm's
/// `replace-registry-host` setting rewrites to the configured registry
/// (#812).
pub const NPM_REPLACE_REGISTRY_HOST_CODE: &str = "redirect_npm_replace_registry_host";

/// npm (>= 8) `replace-registry-host` rewrites the hosted pins' origin to
/// the configured registry, so every install fetches `<registry>/patch/…`
/// and fails E404 (closed: never unpatched bytes). Nothing is written to
/// override it — like an explicit `allow-remote`, the setting is the
/// user's — so the warning names where it is set and both remedies.
pub fn npm_replace_registry_host_detail(
    hosts: &[&str],
    value: &str,
    source: &crate::patch::redirect::npmrc::SettingSource,
) -> String {
    use crate::patch::redirect::npmrc::SettingSource;
    let (where_, fix) = match source {
        SettingSource::Env(var) => (
            format!("the environment variable {var} sets"),
            format!(
                "unset {var} (npm's environment layer overrides every .npmrc) or set it to \
                 `npmjs`"
            ),
        ),
        SettingSource::Project => (
            "the project .npmrc sets".to_string(),
            "change it to `replace-registry-host=npmjs` (npm's default) or remove it".to_string(),
        ),
        SettingSource::File { layer, path } => (
            format!("the {layer} npm config ({}) sets", path.display()),
            format!(
                "set `replace-registry-host=npmjs` (npm's default) in the project .npmrc (it \
                 outranks the {layer} config) or change the {layer} config"
            ),
        ),
    };
    format!(
        "the npm lockfile now resolves patched dependencies from the hosted patch server ({}), \
         but {where_} `replace-registry-host={value}`, which makes npm >=8 rewrite those \
         `resolved` URLs to the configured registry: every `npm ci` / `npm install` then \
         fails E404 (a warm npm cache can hide this locally; a fresh checkout or CI runner \
         fails). To install the hosted patches, {fix}; or switch this project to vendored \
         patches (`socket-patch scan --mode vendored`), whose `file:` resolutions npm never \
         rewrites",
        hosts.join(", "),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #734: a created root-only scaffold's detail keeps the `pnpm add -w`
    /// caveat and names the `packageManager` pin that avoids the file on
    /// pnpm 9.0–10.4; a merge into an existing file says neither.
    #[test]
    fn trust_scaffold_detail_names_the_add_caveat_and_the_pin_remedy() {
        for dry_run in [false, true] {
            let detail = pnpm_trust_configured_detail("patch.test", true, dry_run);
            assert!(detail.contains("`pnpm add -w <pkg>`"), "{detail}");
            assert!(
                detail.contains(
                    "to avoid the file there, pin that pnpm in package.json `packageManager`"
                ),
                "{detail}"
            );
            assert!(
                detail.contains("any other pnpm pin — `engines.pnpm`"),
                "{detail}"
            );
            assert_eq!(
                detail.contains(&format!("delete {PNPM_WORKSPACE_REL} and re-run")),
                !dry_run,
                "{detail}"
            );
            // No `@` (no `pnpm@x.y.z` example): the trust warning's
            // no-userinfo-leak check rejects any.
            assert!(!detail.contains('@'), "{detail}");
        }
        let merged = pnpm_trust_configured_detail("patch.test", false, false);
        assert!(!merged.contains("pnpm add -w"), "{merged}");
        assert!(!merged.contains("packageManager"), "{merged}");
    }

    /// #904 (hosted): a BOM-prefixed `trustLockfile:` first line is the
    /// user's explicit setting — kept, never shadowed by an appended
    /// duplicate key — and a BOM file that needs the key keeps its BOM.
    #[test]
    fn workspace_trust_plan_reads_a_bom_first_key() {
        match plan_workspace_trust(Some("\u{feff}trustLockfile: false\npackages:\n  - .\n")) {
            TrustPlan::UserSet(value) => assert_eq!(value, "false"),
            _ => panic!("expected UserSet(false)"),
        }
        assert!(matches!(
            plan_workspace_trust(Some("\u{feff}trustLockfile: true\npackages:\n  - .\n")),
            TrustPlan::AlreadyTrue
        ));
        match plan_workspace_trust(Some("\u{feff}packages:\n  - .\n")) {
            TrustPlan::Append(text) => {
                assert_eq!(text, "\u{feff}packages:\n  - .\ntrustLockfile: true\n")
            }
            _ => panic!("expected Append"),
        }
    }
}
