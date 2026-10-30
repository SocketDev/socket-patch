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
    let undo = format!("delete {PNPM_WORKSPACE_REL}");
    trust_configured_detail(server, how, created.then_some(undo.as_str()), dry_run)
}

/// The auto-config variant for an existing pnpm-workspace.yaml with no keys
/// ([`TrustPlan::Scaffold`]): the trust key went in with the root-only
/// `packages` field, which makes the project a root-only workspace just as
/// a created file does.
pub fn pnpm_trust_scaffolded_detail(server: &str, dry_run: bool) -> String {
    let how = if dry_run {
        "`trustLockfile: true` (with the root-only `packages: ['.']` that pnpm \
         8–10.4 require once the file holds a key) would be merged into the existing"
    } else {
        "`trustLockfile: true` (with the root-only `packages: ['.']` that pnpm \
         8–10.4 require once the file holds a key) was merged into the existing"
    };
    let undo =
        format!("remove the added `packages` and `trustLockfile` lines from {PNPM_WORKSPACE_REL}");
    trust_configured_detail(server, how, Some(&undo), dry_run)
}

/// `undo` (set when the edit made the project a root-only workspace) names
/// how to take the edit back.
fn trust_configured_detail(server: &str, how: &str, undo: Option<&str>, dry_run: bool) -> String {
    // A created file makes the project a root-only workspace, where pnpm
    // 9.0–10.4 refuse `pnpm add` without `-w` (#734); a project pinned to
    // those releases never gets one, so the note names the pin as the way
    // out for an unpinned project with no install record.
    let root_only = if let Some(undo) = undo {
        let then = if dry_run {
            "before the real run".to_string()
        } else {
            format!("then {undo} and re-run")
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

/// The keyless-workspace variant (#1096): pnpm-workspace.yaml holds no keys
/// and the lock lists workspace members, which only pnpm <= 10.4 install
/// from such a file (as every nested package). Those releases never read
/// `trustLockfile` and refuse a workspace file holding a key without
/// `packages`, while a root-only `packages` would drop the members, so
/// nothing is written.
pub fn pnpm_trust_keyless_members_detail(server: &str, dry_run: bool) -> String {
    let was = if dry_run { "would be" } else { "was" };
    format!(
        "{}. {PNPM_WORKSPACE_REL} has no keys and pnpm-lock.yaml lists workspace \
         members, which only pnpm <=10.4 installs from such a file; that pnpm does \
         not read `trustLockfile` and refuses a workspace file holding keys but no \
         `packages`, so nothing {was} written. After upgrading to pnpm >=11, list the \
         members under `packages:` in {PNPM_WORKSPACE_REL} and re-run \
         `socket-patch scan --mode hosted`, or install with \
         `pnpm install --trust-lockfile`. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
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
    /// Workspace file exists but holds no key at all (empty, comments only,
    /// bare document markers — "no workspace" to pnpm): the root-only
    /// `packages` scaffold goes in with the trust key, since pnpm 8.x–10.4
    /// refuse a workspace file holding a key but no `packages` (#1096).
    /// Every user byte is preserved, so rollback can take both back out
    /// ([`TRUST_SCAFFOLD_LINES`]).
    Scaffold(String),
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

/// The lines the trust auto-config writes into a file with no keys (and,
/// newline-terminated, the whole file it creates): the root-only `packages`
/// scaffold and the trust key.
pub const TRUST_SCAFFOLD_LINES: [&str; 3] = [
    crate::formats::pnpm::workspace::PACKAGES_SCAFFOLD[0],
    crate::formats::pnpm::workspace::PACKAGES_SCAFFOLD[1],
    "trustLockfile: true",
];

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
    if crate::formats::pnpm::workspace::is_keyless(text) {
        // Several (empty) documents: a splice would land in the last one,
        // while pnpm reads the first.
        let anchor = match block_insert_point(&lines) {
            Ok(anchor) => anchor,
            Err(why) => return TrustPlan::Unsupported(why),
        };
        lines.splice(anchor..anchor, TRUST_SCAFFOLD_LINES.map(str::to_string));
        return TrustPlan::Scaffold(lines.join("\n"));
    }
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
    setting: &crate::patch::redirect::npmrc::EffectiveSetting,
) -> String {
    use crate::patch::redirect::npmrc::SettingSource;
    // Name the spelling the user can find (`${RRH}`), and what npm makes
    // of it.
    let value = if setting.raw.trim() == setting.value {
        format!("`replace-registry-host={}`", setting.value)
    } else {
        format!(
            "`replace-registry-host={}` (npm expands it to `{}`)",
            setting.raw.trim(),
            setting.value
        )
    };
    let (where_, fix) = match &setting.source {
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
         but {where_} {value}, which makes npm >=8 rewrite those \
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
    use crate::patch::redirect::DepOverride;

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

    /// #1096: an existing file with no keys at all (empty, comments only,
    /// bare document markers) gains the root-only `packages` scaffold with
    /// the trust key — pnpm 8.x–10.4 refuse a workspace file holding a key
    /// but no `packages` — inside the document, every user byte intact.
    #[test]
    fn plan_workspace_trust_scaffolds_packages_in_a_keyless_file() {
        const ADDED: &str = "packages:\n  - '.'\ntrustLockfile: true\n";
        for (user, want) in [
            ("", ADDED.to_string()),
            ("\n", format!("{ADDED}\n")),
            ("# settings\n", format!("# settings\n{ADDED}")),
            ("---\n", format!("---\n{ADDED}")),
            ("%YAML 1.2\n---\n", format!("%YAML 1.2\n---\n{ADDED}")),
            ("---\n...\n", format!("---\n{ADDED}...\n")),
        ] {
            match plan_workspace_trust(Some(user)) {
                TrustPlan::Scaffold(text) => assert_eq!(text, want, "{user:?}"),
                _ => panic!("a keyless file must plan a Scaffold: {user:?}"),
            }
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

    /// #402: every key spelling pnpm reads as `trustLockfile` is the
    /// setting — an explicit value is respected, never duplicated.
    #[test]
    fn plan_workspace_trust_reads_quoted_and_spaced_keys() {
        for spelled in [
            "packages:\n  - '.'\n\"trustLockfile\": false\n",
            "packages:\n  - '.'\ntrustLockfile : false\n",
            "packages:\n  - '.'\n'trustLockfile':   false   # opt out\n",
        ] {
            match plan_workspace_trust(Some(spelled)) {
                TrustPlan::UserSet(value) => assert_eq!(value, "false", "{spelled:?}"),
                _ => panic!("an explicit false must be respected for {spelled:?}"),
            }
        }
        for spelled in [
            "'trustLockfile': true\npackages:\n  - '.'\n",
            "\"trustLockfile\" : \"true\"\n",
            "trustLockfile: true # set by hand\n",
        ] {
            assert!(
                matches!(plan_workspace_trust(Some(spelled)), TrustPlan::AlreadyTrue),
                "already-true must be a no-op for {spelled:?}"
            );
        }
    }

    /// #400: the key goes inside the document — before a `...` marker —
    /// and shapes a line append would corrupt are never appended to.
    #[test]
    fn plan_workspace_trust_respects_the_document_shape() {
        match plan_workspace_trust(Some("packages:\n  - '.'\n...\n")) {
            TrustPlan::Append(text) => {
                assert_eq!(text, "packages:\n  - '.'\ntrustLockfile: true\n...\n")
            }
            _ => panic!("a `...`-terminated block mapping must plan an Append"),
        }
        // The refusal reason reaches the warning with both manual recoveries.
        let TrustPlan::Unsupported(why) = plan_workspace_trust(Some("{packages: [.]}\n")) else {
            panic!("a flow-style document must be refused");
        };
        let detail =
            pnpm_trust_workspace_unsupported_detail("the hosted patch server (patch.test)", &why);
        assert!(detail.contains("flow-style"), "{detail}");
        assert!(detail.contains("left untouched"), "{detail}");
        assert!(detail.contains("--trust-lockfile"), "{detail}");
        assert!(detail.contains("trustLockfile: true"), "{detail}");
        assert!(detail.contains("pnpm clean --lockfile"), "{detail}");
        for text in [
            "{packages: [.]}\n",
            "--- {packages: [.]}\n",
            "packages:\n  - '.'\n---\ncatalog: {}\n",
            "packages:\n  - '.'\n...\n---\ncatalog: {}\n",
        ] {
            assert!(
                !matches!(
                    plan_workspace_trust(Some(text)),
                    TrustPlan::Append(_) | TrustPlan::Create(_)
                ),
                "{text:?} must not be appended to"
            );
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

    /// The legacy-lock (5.x/6.0 — pnpm 7/8) guidance must NEVER mention
    /// `--trust-lockfile` (pnpm 7/8 reject the flag as an unknown option) nor
    /// the `trustLockfile` setting (pnpm 7/8 ignore it); it must say installs
    /// work unchanged with no trust step, keep the don't-regenerate caution,
    /// and leak no URL authority.
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

    /// A PRESENT-but-unreadable pnpm-workspace.yaml must classify as `Err` —
    /// never as `Ok(None)`, which plans a Create that overwrites the user's
    /// file (destroying their `packages:` globs). Absent stays `Ok(None)`
    /// (the only Create-safe state); readable stays `Ok(Some)`.
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
            registry_override: None,
            integrity: Default::default(),
        }
    }

    /// Heal-on-rerun probe: a root lock ALREADY
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

        // The exact splice shape an earlier run wrote.
        let redirected = format!(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );
        assert!(pnpm_lock_carries_hosted_redirect(&redirected, &overrides));

        // The percent-encoded spelling counts too (same predicate set as the
        // confirmation probe).
        let encoded = crate::utils::uri::encode_uri_component(url);
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

    /// Heal-on-rerun gate (`pnpm_heal_root`): a re-scan that spliced NOTHING
    /// over a pre-redirected root v9 lock with a MISSING pnpm-workspace.yaml
    /// must engage the trust block (heal → plan Create), while a legacy
    /// pre-redirected lock, an unparseable-version lock, a pristine lock,
    /// and a root lock this run DID splice all stay out of the heal path.
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
        // planning it feeds produces the Create.
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

    /// Every hosted npm redirect variant tells the user
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
