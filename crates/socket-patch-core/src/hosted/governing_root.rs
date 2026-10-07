//! The governing-root pre-check of the hosted flow: a run whose `--cwd` is
//! a workspace member reads the member's directory only, while the package
//! manager installs from a lock in an ancestor directory. Hosted mode then
//! either pins nothing and reports success (pnpm, #590; npm, yarn and Bun
//! `package.json` workspaces, #884; vlt `vlt.json` workspaces, #942) or
//! rewrites the member as a lockless project and breaks the workspace
//! (cargo, #417).
//!
//! [`refusal`] spots these layouts before any takeover or write, so the run
//! fails closed and names the directory to run from. It also refuses a
//! pnpm member that does have its own lock when the `trustLockfile: true`
//! hosted pins need lives in the workspace root's `pnpm-workspace.yaml`,
//! the only one pnpm reads (#880). Vendored mode refuses
//! the same layouts (`vendor_lockfile_missing`,
//! `cargo_manifest_not_workspace_root`); the cargo check is the vendored
//! one, shared.
//!
//! Unlike the rest of [`super::engine`], this looks outside the project
//! directory (its ancestors), so it only runs over the disk; an in-memory
//! project is the host's whole file set and has no ancestors.

use std::path::{Path, PathBuf};

use crate::constants::npm_family::{NPM_LOCKS, VLT_LOCK};
use crate::patch::redirect::npmrc::npmrc_top_level_value;
use crate::utils::fs::{read_regular_to_string, read_regular_to_string_sync};
use crate::utils::pnpm_workspace::governing_workspace_file;
use crate::vendor::cargo::NOT_WORKSPACE_ROOT;
use crate::vendor::cargo_manifest;
use crate::vendor::lock_inventory::ProjectView;

use super::engine::{Candidate, Refusal};
use super::guidance::{
    plan_workspace_trust, pnpm_lock_version_major, read_workspace_for_trust, TrustPlan,
};

/// Refusal code for a pnpm project whose `pnpm-lock.yaml` lives in another
/// directory: the nearest ancestor `pnpm-workspace.yaml` (a workspace
/// member) or a configured `lockfile-dir`.
pub const PNPM_LOCKFILE_ELSEWHERE: &str = "redirect_pnpm_lockfile_elsewhere";

/// Refusal code for an npm, yarn, Bun or vlt workspace member: an ancestor
/// `package.json` (or, for vlt, `vlt.json`) lists the project directory in
/// its `workspaces`, and the workspace's lock lives at that root.
pub const WORKSPACE_LOCKFILE_ELSEWHERE: &str = "redirect_workspace_lockfile_elsewhere";

/// Refusal code for a pnpm workspace member with its own lock whose
/// settings (`trustLockfile`) live in an ancestor `pnpm-workspace.yaml`
/// that does not trust the lock yet.
pub const PNPM_SETTINGS_ELSEWHERE: &str = "redirect_pnpm_settings_elsewhere";

const PNPM_LOCK: &str = "pnpm-lock.yaml";
const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";
const VLT_JSON: &str = "vlt.json";

/// npm-family locks that, present in the project directory, make it its
/// own lock root: the existing rewriters handle it.
const OWN_LOCKS: [&str; 5] = [
    PNPM_LOCK,
    "shrinkwrap.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];

const HOSTED_CARGO_ROOT_HINT: &str =
    "hosted mode pins the crate in the workspace's Cargo.lock and in every member \
     manifest, which only a run from the workspace root can reach; run socket-patch \
     from the workspace root (the directory holding its Cargo.toml and Cargo.lock); \
     nothing was written";

/// `Some` when the project directory is governed by a lock in another
/// directory that hosted mode would not read, or (with the trust
/// auto-config on) by pnpm settings in another directory that hosted mode
/// would not write (see the module doc).
pub async fn refusal(
    view: &ProjectView<'_>,
    candidates: &[Candidate],
    trust_lockfile_config: bool,
) -> Option<Refusal> {
    let root: &Path = match view {
        ProjectView::Disk(root) => root,
        ProjectView::Snapshot(snap) => snap.root,
        ProjectView::Memory(_) => return None,
    };
    if candidates.iter().any(|c| c.dep.ecosystem == "cargo") {
        if let Some(refusal) = cargo_member_refusal(root).await {
            return Some(refusal);
        }
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        let workspace = if has_own_npm_family_lock(root) {
            None
        } else {
            nearer_root(
                package_json_workspace_refusal(root).await,
                vlt_workspace_refusal(root).await,
            )
        };
        if let Some(lock) = pnpm_lock_elsewhere(root).await {
            let dir = lock.parent().unwrap_or(&lock);
            // A `package.json` workspace root nested inside the pnpm lock's
            // directory is nearer the member and owns its lock (Bugbot on
            // #901); otherwise pnpm's workspace or `lockfile-dir` governs.
            if let Some((ws_root, refusal)) = workspace {
                let pnpm_dir = tokio::fs::canonicalize(dir)
                    .await
                    .unwrap_or_else(|_| dir.to_path_buf());
                if ws_root != pnpm_dir && ws_root.starts_with(&pnpm_dir) {
                    return Some(refusal);
                }
            }
            return Some(Refusal {
                code: PNPM_LOCKFILE_ELSEWHERE.to_string(),
                message: format!(
                    "{} has no lockfile of its own: pnpm installs it from {}, which a \
                     hosted run here cannot see; run socket-patch from {} (the directory \
                     holding pnpm-lock.yaml); nothing was written",
                    root.display(),
                    lock.display(),
                    dir.display()
                ),
            });
        }
        if let Some((_, refusal)) = workspace {
            return Some(refusal);
        }
        if trust_lockfile_config {
            if let Some(refusal) = pnpm_settings_elsewhere(root) {
                return Some(refusal);
            }
        }
    }
    None
}

/// A pnpm v9 project lock (the one the trust auto-config serves) in a
/// workspace member whose settings come from an ancestor
/// `pnpm-workspace.yaml` that neither trusts the lock nor explicitly opts
/// out. The auto-config used to create a nested file pnpm ignores (#880);
/// socket-patch writes only inside the project, so the user adds the key
/// to the root file. An explicit `trustLockfile: <non-true>` is respected,
/// as in a single project.
fn pnpm_settings_elsewhere(root: &Path) -> Option<Refusal> {
    let lock = read_regular_to_string_sync(&root.join(PNPM_LOCK)).ok()?;
    if pnpm_lock_version_major(&lock).is_none_or(|major| major < 9) {
        return None;
    }
    let file = governing_workspace_file(root)?;
    if let Ok(Some(text)) = read_workspace_for_trust(&file) {
        if matches!(
            plan_workspace_trust(Some(&text)),
            TrustPlan::AlreadyTrue | TrustPlan::UserSet(_)
        ) {
            return None;
        }
    }
    Some(Refusal {
        code: PNPM_SETTINGS_ELSEWHERE.to_string(),
        message: format!(
            "{} is a project of the pnpm workspace whose settings live in {}: pnpm \
             reads `trustLockfile` only from that file, so pnpm >= 11 rejects the hosted \
             pins in this project's pnpm-lock.yaml (ERR_PNPM_TARBALL_URL_MISMATCH) until \
             it trusts the lock, and a pnpm-workspace.yaml created here would be ignored; \
             add `trustLockfile: true` to {} (pnpm <= 10 ignores it) and re-run, or pass \
             --no-trust-lockfile-config to pin without it; nothing was written",
            root.display(),
            file.display(),
            file.display()
        ),
    })
}

/// The vendored workspace-root check over `<root>/Cargo.toml`; an absent or
/// unreadable manifest is left to the rewriter.
async fn cargo_member_refusal(root: &Path) -> Option<Refusal> {
    let text = read_regular_to_string(&root.join(cargo_manifest::CARGO_TOML))
        .await
        .ok()?;
    let doc = cargo_manifest::parse_manifest(&text).ok()?;
    let detail =
        crate::vendor::cargo::workspace_root_refusal(root, &doc, HOSTED_CARGO_ROOT_HINT).await?;
    Some(Refusal {
        code: NOT_WORKSPACE_ROOT.to_string(),
        message: detail,
    })
}

/// The `pnpm-lock.yaml` pnpm reads for a project directory that holds no
/// npm-family lock of its own, when it lives elsewhere and exists:
///
/// The nearest `pnpm-workspace.yaml` supplies `lockfileDir`, ahead of the
/// project's `.npmrc` and then the workspace root's `.npmrc`. A configured
/// relative directory is resolved from the invocation cwd, as pnpm does;
/// without an override, the workspace's lock lives at its root.
async fn pnpm_lock_elsewhere(root: &Path) -> Option<PathBuf> {
    if has_own_npm_family_lock(root) {
        return None;
    }
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());

    let mut workspace = None;
    for ancestor in canonical.ancestors() {
        let path = ancestor.join(PNPM_WORKSPACE);
        if let Ok(yaml) = read_regular_to_string(&path).await {
            workspace = Some((ancestor.to_path_buf(), yaml));
            break;
        }
        if ancestor == canonical && path.exists() {
            // An unreadable local workspace file still bounds the project.
            break;
        }
    }

    // Native pnpm 10: workspace YAML beats both npmrc files; the member's
    // npmrc beats the workspace root's. A member inherits root npmrc settings
    // even when its own directory has no pnpm-workspace.yaml.
    let mut configured = workspace
        .as_ref()
        .and_then(|(_, yaml)| workspace_lockfile_dir(yaml));
    if configured.is_none() {
        configured = npmrc_lockfile_dir(&canonical).await;
    }
    if configured.is_none() {
        if let Some((workspace_root, _)) = &workspace {
            if workspace_root != &canonical {
                configured = npmrc_lockfile_dir(workspace_root).await;
            }
        }
    }
    if let Some(dir) = configured {
        // Even an inherited relative override is based on the invocation
        // directory, not on the directory containing the setting.
        return lock_elsewhere(&canonical, &canonical, &dir).await;
    }
    if let Some((workspace_root, _)) = workspace {
        return lock_elsewhere(&canonical, &workspace_root, ".").await;
    }
    None
}

/// Whether the project directory is its own npm-family lock root: it holds
/// a lock the rewriters read, or is a Rush repo (Rush keeps its locks under
/// common/config, read by the rewriter).
fn has_own_npm_family_lock(root: &Path) -> bool {
    OWN_LOCKS
        .iter()
        .chain(NPM_LOCKS.iter())
        .chain(std::iter::once(&VLT_LOCK))
        .any(|name| root.join(name).exists())
        || root.join("rush.json").exists()
}

/// Locks of the package managers that read `package.json` `workspaces`
/// (npm, yarn, Bun). pnpm reads only `pnpm-workspace.yaml` and vlt only
/// `vlt.json`, so their locks at a `workspaces` root govern no member
/// through that field; the pnpm check owns pnpm workspaces.
const WORKSPACE_ROOT_LOCKS: [&str; 5] = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];

/// #884: the project directory is a member of an npm, yarn (classic or
/// berry) or Bun workspace, whose root `package.json` lists it under
/// `workspaces` and whose lock lives at that root. Each of those package
/// managers installs the member from the root lock, so a hosted run here
/// would find the member's copy, pin nothing and report success.
///
/// The nearest ancestor whose `workspaces` patterns match the member is
/// its workspace root, as npm and yarn resolve it. A matching root with no
/// lock may itself be a member of an outer workspace (yarn berry's nested
/// worktrees), so the walk goes on with that root as the member and
/// refuses at the first root that holds an npm, yarn or Bun lock; a chain
/// that ends without one (never installed), or at a Rush root, refuses
/// nothing. Returns the
/// governing root with the refusal, so [`refusal`] can weigh it against
/// the pnpm check (the nearer root wins; a tie goes to pnpm's message).
async fn package_json_workspace_refusal(root: &Path) -> Option<(PathBuf, Refusal)> {
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());
    let mut member: &Path = &canonical;
    for ancestor in canonical.ancestors().skip(1) {
        let Ok(text) = read_regular_to_string(&ancestor.join("package.json")).await else {
            continue;
        };
        let Some(patterns) = workspace_patterns(&text) else {
            continue;
        };
        let Ok(rel) = member.strip_prefix(ancestor) else {
            continue;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if !workspaces_include(&patterns, &rel) {
            continue;
        }
        let locks: Vec<&str> = WORKSPACE_ROOT_LOCKS
            .iter()
            .copied()
            .filter(|name| ancestor.join(name).is_file())
            .collect();
        if locks.is_empty() {
            // Rush keeps its locks under common/config: the rewriters own
            // a run from the Rush root.
            if ancestor.join("rush.json").exists() {
                return None;
            }
            member = ancestor;
            continue;
        }
        let refusal = Refusal {
            code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
            message: format!(
                "{} is a workspace member with no lockfile of its own: the workspace \
                 root {} lists it under \"workspaces\" and installs it from {}, which a \
                 hosted run here cannot see; run socket-patch from {} (the workspace \
                 root); nothing was written",
                root.display(),
                ancestor.display(),
                locks
                    .iter()
                    .map(|name| ancestor.join(name).display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                ancestor.display()
            ),
        };
        return Some((ancestor.to_path_buf(), refusal));
    }
    None
}

/// #942: the project directory is a member of a vlt workspace, whose
/// root `vlt.json` lists it under `workspaces` and holds `vlt-lock.json`.
/// vlt reads workspaces only from `vlt.json` and keeps one lock at that
/// root, so a hosted run here would find the member's copy, pin nothing
/// and report success. The nearest ancestor `vlt.json` whose patterns
/// match is the root; one without a lock (never installed) refuses
/// nothing.
async fn vlt_workspace_refusal(root: &Path) -> Option<(PathBuf, Refusal)> {
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());
    for ancestor in canonical.ancestors().skip(1) {
        let Ok(text) = read_regular_to_string(&ancestor.join(VLT_JSON)).await else {
            continue;
        };
        let Some(patterns) = vlt_workspace_patterns(&text) else {
            continue;
        };
        let Ok(rel) = canonical.strip_prefix(ancestor) else {
            continue;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if !workspaces_include(&patterns, &rel) {
            continue;
        }
        let lock = ancestor.join(VLT_LOCK);
        if !lock.is_file() {
            return None;
        }
        let refusal = Refusal {
            code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
            message: format!(
                "{} is a workspace member with no lockfile of its own: the workspace \
                 root {} lists it under \"workspaces\" in {} and installs it from {}, \
                 which a hosted run here cannot see; run socket-patch from {} (the \
                 workspace root); nothing was written",
                root.display(),
                ancestor.display(),
                ancestor.join(VLT_JSON).display(),
                lock.display(),
                ancestor.display()
            ),
        };
        return Some((ancestor.to_path_buf(), refusal));
    }
    None
}

/// The refusal of the nearer (deeper) of two governing roots.
fn nearer_root(
    a: Option<(PathBuf, Refusal)>,
    b: Option<(PathBuf, Refusal)>,
) -> Option<(PathBuf, Refusal)> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.0.starts_with(&a.0) && b.0 != a.0 {
            b
        } else {
            a
        }),
        (a, b) => a.or(b),
    }
}

/// The `workspaces` patterns of a `vlt.json`: a string, an array, or an
/// object of named groups whose values are a string or an array. `None`
/// when the field is absent or the file does not parse.
fn vlt_workspace_patterns(vlt_json: &str) -> Option<Vec<String>> {
    fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(list) => {
                out.extend(list.iter().filter_map(|v| v.as_str()).map(str::to_string))
            }
            _ => {}
        }
    }
    let text = vlt_json.strip_prefix('\u{feff}').unwrap_or(vlt_json);
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let field = doc.get("workspaces")?;
    let mut out = Vec::new();
    match field {
        serde_json::Value::Object(groups) => groups.values().for_each(|v| strings(v, &mut out)),
        other => strings(other, &mut out),
    }
    Some(out)
}

/// The `workspaces` patterns of a `package.json`: the array form (npm,
/// yarn, Bun) or the object form's `packages` array (yarn classic's
/// `nohoist` shape, Bun's catalogs shape). `None` when the field is absent
/// or the manifest does not parse.
fn workspace_patterns(package_json: &str) -> Option<Vec<String>> {
    let text = package_json
        .strip_prefix('\u{feff}')
        .unwrap_or(package_json);
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let field = doc.get("workspaces")?;
    let list = match field {
        serde_json::Value::Array(list) => list,
        serde_json::Value::Object(map) => map.get("packages")?.as_array()?,
        _ => return None,
    };
    Some(
        list.iter()
            .filter_map(|v| v.as_str())
            .map(str::to_string)
            .collect(),
    )
}

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) matches a `workspaces` pattern and no later
/// `!`-negated one. A pattern is a `/`-separated glob in the grammar npm
/// (minimatch), yarn and Bun share: brace sets (`{a,b}`, nested, and
/// `{1..3}` / `{a..c}` sequences) expand first, then `*`, `?` and
/// character classes (`[abc]`, `[a-c]`, `[!a]`, `[^a]`) match within one
/// component and `**` matches any number of components (#1071).
fn workspaces_include(patterns: &[String], rel: &[String]) -> bool {
    if rel.is_empty() {
        return false;
    }
    let rel: Vec<Vec<char>> = rel.iter().map(|c| c.chars().collect()).collect();
    let mut included = false;
    for pattern in patterns {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        let matched = expand_braces(pattern.trim()).iter().any(|alternative| {
            let segments: Vec<Vec<char>> = alternative
                .split(['/', '\\'])
                .filter(|s| !s.is_empty() && *s != ".")
                .map(|s| s.chars().collect())
                .collect();
            !segments.is_empty() && path_glob_matches(&segments, &rel)
        });
        if matched {
            included = !negated;
        }
    }
    included
}

/// Cap on the alternatives one pattern expands to, so a pathological
/// sequence (`{1..1000000}`) cannot stall the run.
const MAX_BRACE_EXPANSIONS: usize = 4096;

/// The brace expansion of a glob, as minimatch's `brace-expansion` does it:
/// the first `{...}` group holding a top-level `,` or a `x..y[..step]`
/// sequence is replaced by each alternative, recursively. A group with
/// neither, and an unbalanced `{`, stay literal.
fn expand_braces(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_braces_into(pattern, &mut out);
    out
}

fn expand_braces_into(pattern: &str, out: &mut Vec<String>) {
    if out.len() >= MAX_BRACE_EXPANSIONS {
        return;
    }
    for (open, _) in pattern.match_indices('{') {
        let Some(close) = matching_brace(pattern, open) else {
            continue;
        };
        let body = &pattern[open + 1..close];
        let alternatives = split_top_level_commas(body);
        let alternatives = if alternatives.len() > 1 {
            alternatives
        } else if let Some(sequence) = brace_sequence(body) {
            sequence
        } else {
            continue;
        };
        let (prefix, suffix) = (&pattern[..open], &pattern[close + 1..]);
        for alternative in alternatives {
            expand_braces_into(&format!("{prefix}{alternative}{suffix}"), out);
            if out.len() >= MAX_BRACE_EXPANSIONS {
                return;
            }
        }
        return;
    }
    out.push(pattern.to_string());
}

/// The byte index of the `}` closing the `{` at `open`.
fn matching_brace(pattern: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in pattern[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in body.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(body[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(body[start..].to_string());
    parts
}

/// A `{x..y}` or `{x..y..step}` sequence body: integers (zero-padded when
/// either end is) or single characters.
fn brace_sequence(body: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = body.split("..").collect();
    let (from, to, step) = match parts.as_slice() {
        [from, to] => (*from, *to, None),
        [from, to, step] => (*from, *to, Some(*step)),
        _ => return None,
    };
    let step = match step {
        Some(step) => step.parse::<i64>().ok()?.unsigned_abs().max(1),
        None => 1,
    };
    let (start, end, width, as_char) =
        if let (Ok(a), Ok(b)) = (from.parse::<i64>(), to.parse::<i64>()) {
            let padded = |s: &str| {
                s.trim_start_matches('-').len() > 1 && s.trim_start_matches('-').starts_with('0')
            };
            let width = if padded(from) || padded(to) {
                from.len().max(to.len())
            } else {
                0
            };
            (a, b, width, false)
        } else {
            let (mut a, mut b) = (from.chars(), to.chars());
            let (Some(a), None, Some(b), None) = (a.next(), a.next(), b.next(), b.next()) else {
                return None;
            };
            (a as i64, b as i64, 0, true)
        };
    let mut out = Vec::new();
    let mut n = start;
    loop {
        out.push(if as_char {
            char::from_u32(u32::try_from(n).ok()?)?.to_string()
        } else {
            format!("{n:0width$}")
        });
        if n == end || out.len() >= MAX_BRACE_EXPANSIONS {
            break;
        }
        let next = if start <= end {
            n.checked_add(step as i64)?
        } else {
            n.checked_sub(step as i64)?
        };
        if (start <= end && next > end) || (start > end && next < end) {
            break;
        }
        n = next;
    }
    Some(out)
}

fn path_glob_matches(pattern: &[Vec<char>], path: &[Vec<char>]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((first, rest)) if first.as_slice() == ['*', '*'] => {
            (0..=path.len()).any(|skip| path_glob_matches(rest, &path[skip..]))
        }
        Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
            segment_glob_matches(first, head) && path_glob_matches(rest, tail)
        }),
    }
}

fn segment_glob_matches(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|skip| segment_glob_matches(rest, &name[skip..])),
        Some(('?', rest)) => !name.is_empty() && segment_glob_matches(rest, &name[1..]),
        Some(('[', rest)) => match char_class(rest) {
            Some((class, after)) => name
                .split_first()
                .is_some_and(|(c, tail)| class.matches(*c) && segment_glob_matches(after, tail)),
            None => name.first() == Some(&'[') && segment_glob_matches(rest, &name[1..]),
        },
        Some((c, rest)) => name.first() == Some(c) && segment_glob_matches(rest, &name[1..]),
    }
}

/// A parsed `[...]` character class.
struct CharClass {
    negated: bool,
    ranges: Vec<(char, char)>,
}

impl CharClass {
    fn matches(&self, c: char) -> bool {
        self.ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) != self.negated
    }
}

/// The class after a `[`, and the pattern after its closing `]`. A `!` or
/// `^` first negates it; a `]` right after that is a member. `None` when
/// the class never closes (the `[` is then literal).
fn char_class(pattern: &[char]) -> Option<(CharClass, &[char])> {
    let (negated, mut i) = match pattern.first() {
        Some('!' | '^') => (true, 1),
        _ => (false, 0),
    };
    let mut ranges = Vec::new();
    let first = i;
    while i < pattern.len() {
        let c = pattern[i];
        if c == ']' && i > first {
            return Some((CharClass { negated, ranges }, &pattern[i + 1..]));
        }
        if pattern.get(i + 1) == Some(&'-') && pattern.get(i + 2).is_some_and(|&h| h != ']') {
            ranges.push((c, pattern[i + 2]));
            i += 3;
        } else {
            ranges.push((c, c));
            i += 1;
        }
    }
    None
}

async fn npmrc_lockfile_dir(root: &Path) -> Option<String> {
    let npmrc = read_regular_to_string(&root.join(".npmrc")).await.ok()?;
    npmrc_top_level_value(&npmrc, "lockfile-dir")
}

/// `<base>/<dir>/pnpm-lock.yaml` when it exists and `<base>/<dir>` is not
/// the project directory itself.
async fn lock_elsewhere(project: &Path, base: &Path, dir: &str) -> Option<PathBuf> {
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    let dir = base.join(dir);
    let lock = dir.join(PNPM_LOCK);
    let same_dir = tokio::fs::canonicalize(&dir)
        .await
        .is_ok_and(|d| d == project);
    (!same_dir && lock.is_file()).then_some(lock)
}

/// The top-level `lockfileDir:` scalar of a `pnpm-workspace.yaml`, read
/// through the workspace splices' own key grammar
/// ([`top_level_key`](crate::formats::pnpm::workspace::top_level_key):
/// every key spelling, a trailing comment, a leading UTF-8 BOM). The last
/// assignment wins, as in the `.npmrc` reader.
fn workspace_lockfile_dir(yaml: &str) -> Option<String> {
    yaml.lines()
        .filter_map(crate::formats::pnpm::workspace::top_level_key)
        .rfind(|(key, _)| key == "lockfileDir")
        .map(|(_, value)| unquote_scalar(value).to_string())
        .filter(|value| !value.is_empty())
}

/// A YAML scalar value without its surrounding quotes.
fn unquote_scalar(value: &str) -> &str {
    match value.as_bytes() {
        [q @ (b'"' | b'\''), .., last] if last == q => &value[1..value.len() - 1],
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(ecosystem: &str) -> Candidate {
        Candidate {
            purl: format!("pkg:{ecosystem}/x@1.0.0"),
            dep: serde_json::from_value(serde_json::json!({
                "ecosystem": ecosystem,
                "name": "x",
                "version": "1.0.0",
                "token": "t",
                "patchUuid": "11111111-1111-4111-8111-111111111111",
                "artifactUrl": "https://patch.socket.dev/x.tgz",
                "integrity": {},
            }))
            .unwrap(),
        }
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    async fn code(dir: &Path, ecosystem: &str) -> Option<String> {
        refusal(&ProjectView::Disk(dir), &[candidate(ecosystem)], true)
            .await
            .map(|r| r.code)
    }

    /// #590: a pnpm workspace member has no lock; the root's lock governs it.
    #[tokio::test]
    async fn pnpm_workspace_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\n",
        );
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(tmp.path(), "packages/a/package.json", "{}");
        let member = tmp.path().join("packages/a");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
        // The root itself is fine, and so is a non-npm run from the member.
        assert_eq!(code(tmp.path(), "npm").await, None);
        assert_eq!(code(&member, "pypi").await, None);
    }

    /// A member with its own lock (`sharedWorkspaceLockfile: false`) is its
    /// own lock root; a workspace whose root has no lock refuses nothing.
    #[tokio::test]
    async fn pnpm_member_with_own_lock_or_lockless_root_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\ntrustLockfile: true\n",
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        let member = tmp.path().join("packages/a");
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        assert_eq!(code(&member, "npm").await, None);
    }

    /// #880: a member with its own v9 lock is pinned through that lock, but
    /// pnpm reads `trustLockfile` only from the root `pnpm-workspace.yaml`.
    /// Until that file trusts the lock (or opts out), the hosted run refuses
    /// rather than nest a settings file pnpm ignores.
    #[tokio::test]
    async fn pnpm_member_with_own_lock_needs_the_root_to_trust_it() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - packages/*\nsharedWorkspaceLockfile: false\n";
        write(tmp.path(), "pnpm-workspace.yaml", ws);
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        let member = tmp.path().join("packages/a");
        let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .unwrap();
        assert_eq!(refused.code, PNPM_SETTINGS_ELSEWHERE);
        assert!(
            refused.message.contains("trustLockfile: true")
                && refused.message.contains("pnpm-workspace.yaml")
                && refused.message.contains("nothing was written"),
            "{}",
            refused.message
        );
        // `--no-trust-lockfile-config` plans no trust write: nothing to refuse.
        let opted_out = refusal(&ProjectView::Disk(&member), &[candidate("npm")], false).await;
        assert!(opted_out.is_none());
        // A non-npm run, and a pre-v9 lock (no trust policy), are untouched.
        assert_eq!(code(&member, "pypi").await, None);
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '6.0'\n",
        );
        assert_eq!(code(&member, "npm").await, None);
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        // The root trusting the lock, or explicitly opting out, settles it.
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            &format!("{ws}trustLockfile: true\n"),
        );
        assert_eq!(code(&member, "npm").await, None);
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            &format!("{ws}trustLockfile: false\n"),
        );
        assert_eq!(code(&member, "npm").await, None);
        // A member with its own settings file is its own workspace there.
        write(tmp.path(), "pnpm-workspace.yaml", ws);
        write(
            tmp.path(),
            "packages/a/pnpm-workspace.yaml",
            "packages:\n  - .\n",
        );
        assert_eq!(code(&member, "npm").await, None);
    }

    /// #590 `lockfile-dir=..` variant, from `.npmrc` or `pnpm-workspace.yaml`.
    #[tokio::test]
    async fn pnpm_lockfile_dir_elsewhere_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(tmp.path(), "proj/package.json", "{}");
        write(tmp.path(), "proj/.npmrc", "lockfile-dir=..\n");
        let proj = tmp.path().join("proj");
        assert_eq!(
            code(&proj, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );

        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(tmp.path(), "proj/package.json", "{}");
        write(
            tmp.path(),
            "proj/pnpm-workspace.yaml",
            "lockfileDir: '..'  # shared\n",
        );
        let proj = tmp.path().join("proj");
        assert_eq!(
            code(&proj, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );

        // `lockfile-dir=.` names the project itself.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", "{}");
        write(tmp.path(), ".npmrc", "lockfile-dir=.\n");
        assert_eq!(code(tmp.path(), "npm").await, None);
    }

    /// An inherited relative `lockfileDir` is resolved from the member cwd,
    /// verified with native pnpm, rather than from the workspace root.
    #[tokio::test]
    async fn pnpm_member_of_workspace_with_relocated_lock_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "ws/packages/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        write(
            tmp.path(),
            "ws/pnpm-workspace.yaml",
            "packages:\n  - packages/*\nlockfileDir: ..\n",
        );
        write(tmp.path(), "ws/packages/a/package.json", "{}");
        let member = tmp.path().join("ws/packages/a");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
    }

    #[tokio::test]
    async fn pnpm_config_precedence_matches_native_workspace_install() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let member = root.join("packages/a");
        write(&root, "packages/a/package.json", "{}");
        write(&root, PNPM_LOCK, "lockfileVersion: '9.0'\n");
        for dir in ["yaml-locks", "root-rc-locks", "member-rc-locks"] {
            write(
                tmp.path(),
                &format!("{dir}/{PNPM_LOCK}"),
                "lockfileVersion: '9.0'\n",
            );
        }
        let yaml_lock = tmp.path().join("yaml-locks");
        let root_rc_lock = tmp.path().join("root-rc-locks");
        let member_rc_lock = tmp.path().join("member-rc-locks");
        write(
            &root,
            PNPM_WORKSPACE,
            &format!(
                "packages:\n  - packages/*\nlockfileDir: '{}'\n",
                yaml_lock.display()
            ),
        );
        write(
            &root,
            ".npmrc",
            &format!("lockfile-dir={}\n", root_rc_lock.display()),
        );
        write(
            &member,
            ".npmrc",
            &format!("lockfile-dir={}\n", member_rc_lock.display()),
        );
        for expected in [&yaml_lock, &member_rc_lock, &root_rc_lock, &root] {
            let found = pnpm_lock_elsewhere(&member).await.expect("governing lock");
            assert_eq!(
                std::fs::canonicalize(found).unwrap(),
                std::fs::canonicalize(expected.join(PNPM_LOCK)).unwrap()
            );
            if expected == &yaml_lock {
                write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
            } else if expected == &member_rc_lock {
                std::fs::remove_file(member.join(".npmrc")).unwrap();
            } else if expected == &root_rc_lock {
                std::fs::remove_file(root.join(".npmrc")).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn pnpm_member_own_workspace_bounds_ancestor_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        write(tmp.path(), PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/pnpm-workspace.yaml",
            "packages: []\n",
        );
        assert_eq!(code(&tmp.path().join("packages/a"), "npm").await, None);
    }

    /// #884: a member of an npm / yarn classic / yarn berry / Bun workspace
    /// has no lock of its own; the root `package.json` lists it under
    /// `workspaces` and the root lock governs it.
    #[tokio::test]
    async fn package_json_workspace_member_is_refused_for_every_root_lock() {
        for lock in [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
            );
            write(tmp.path(), lock, "");
            write(tmp.path(), "packages/a/package.json", "{}");
            let member = tmp.path().join("packages/a");
            let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
                .await
                .unwrap_or_else(|| panic!("{lock}: member must be refused"));
            assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE, "{lock}");
            assert!(
                refusal.message.contains(lock) && refusal.message.contains("nothing was written"),
                "{lock}: {}",
                refusal.message
            );
            // The root is fine, and so is a non-npm run from the member.
            assert_eq!(code(tmp.path(), "npm").await, None, "{lock}");
            assert_eq!(code(&member, "pypi").await, None, "{lock}");
        }
    }

    /// #884, yarn classic `nohoist` and Bun's object form: `workspaces` is
    /// an object whose `packages` lists the members.
    #[tokio::test]
    async fn package_json_object_workspaces_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":{"packages":["packages/*"],"nohoist":["**/left-pad"]}}"#,
        );
        write(tmp.path(), "yarn.lock", "");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("packages/a"), "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
    }

    /// A member with its own lock is its own lock root; a directory the
    /// root's `workspaces` does not list, a lockless workspace root and a
    /// root without `workspaces` refuse nothing.
    #[tokio::test]
    async fn package_json_workspace_non_members_are_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*","!packages/excluded"]}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        let member = tmp.path().join("packages/a");
        // Lockless root.
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "yarn.lock", "");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
        // Unlisted and negated directories.
        write(tmp.path(), "tools/x/package.json", "{}");
        assert_eq!(code(&tmp.path().join("tools/x"), "npm").await, None);
        write(tmp.path(), "packages/excluded/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("packages/excluded"), "npm").await,
            None
        );
        // A member with its own lock.
        write(tmp.path(), "packages/a/package-lock.json", "{}");
        assert_eq!(code(&member, "npm").await, None);

        // No `workspaces` at all: a nested standalone project.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"name":"root"}"#);
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "sub/package.json", "{}");
        assert_eq!(code(&tmp.path().join("sub"), "npm").await, None);
    }

    /// The nearest ancestor that lists the member is its root, past an
    /// intermediate `package.json` that does not.
    #[tokio::test]
    async fn package_json_workspace_root_is_the_nearest_listing_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/**"]}"#,
        );
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "apps/package.json", r#"{"name":"not-a-root"}"#);
        write(tmp.path(), "apps/web/site/package.json", "{}");
        let refusal = refusal(
            &ProjectView::Disk(&tmp.path().join("apps/web/site")),
            &[candidate("npm")],
            true,
        )
        .await
        .expect("deep member refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", root.display())),
            "{}",
            refusal.message
        );
    }

    /// Bugbot on #901: a lockless workspace root that is itself a member
    /// of an outer workspace (yarn berry nested worktrees) hands the walk
    /// to the outer root, whose lock governs both.
    #[tokio::test]
    async fn nested_lockless_workspace_defers_to_the_outer_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), "yarn.lock", "");
        write(
            tmp.path(),
            "packages/inner/package.json",
            r#"{"private":true,"workspaces":["pkgs/*"]}"#,
        );
        write(tmp.path(), "packages/inner/pkgs/a/package.json", "{}");
        let member = tmp.path().join("packages/inner/pkgs/a");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("nested member refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", root.display())),
            "{}",
            refusal.message
        );
        // The outer root must list the inner root, not just any path.
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/*"]}"#,
        );
        assert_eq!(code(&member, "npm").await, None);
    }

    /// Bugbot on #901: a pnpm workspace nested in an outer yarn workspace
    /// is the member's lock root; the pnpm check names it, not the outer
    /// yarn root.
    #[tokio::test]
    async fn nested_pnpm_root_stops_the_package_json_walk() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), "yarn.lock", "");
        write(
            tmp.path(),
            "packages/inner/package.json",
            r#"{"private":true,"workspaces":["pkgs/*"]}"#,
        );
        write(
            tmp.path(),
            "packages/inner/pnpm-workspace.yaml",
            "packages:\n  - pkgs/*\n",
        );
        write(
            tmp.path(),
            "packages/inner/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        write(tmp.path(), "packages/inner/pkgs/a/package.json", "{}");
        let member = tmp.path().join("packages/inner/pkgs/a");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );

        // Bugbot on #901: a stray pnpm lock at the inner root with no
        // `pnpm-workspace.yaml` governs nothing (pnpm ignores
        // `package.json` workspaces), so the outer yarn root is named.
        std::fs::remove_file(tmp.path().join("packages/inner/pnpm-workspace.yaml")).unwrap();
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("outer yarn root refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let outer = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", outer.display()))
                && refusal.message.contains("yarn.lock"),
            "{}",
            refusal.message
        );
    }

    /// Bugbot on #901: a yarn workspace nested inside a pnpm workspace is
    /// nearer the member and owns its lock, so it is the root named.
    #[tokio::test]
    async fn nearer_package_json_root_beats_an_outer_pnpm_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), PNPM_WORKSPACE, "packages:\n  - tools/*\n");
        write(tmp.path(), PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "apps/package.json",
            r#"{"private":true,"workspaces":["web"]}"#,
        );
        write(tmp.path(), "apps/yarn.lock", "");
        write(tmp.path(), "apps/web/package.json", "{}");
        let member = tmp.path().join("apps/web");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("member refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let apps = std::fs::canonicalize(tmp.path().join("apps")).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", apps.display())),
            "{}",
            refusal.message
        );
        // Same directory: pnpm's own message wins the tie.
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["tools/*"]}"#,
        );
        write(tmp.path(), "tools/t/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("tools/t"), "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
    }

    /// Bugbot on #901: a stray `pnpm-lock.yaml` at a nested `workspaces`
    /// root does not beat the outer pnpm workspace pnpm installs from.
    #[tokio::test]
    async fn stray_inner_pnpm_lock_does_not_beat_the_outer_pnpm_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), PNPM_WORKSPACE, "packages:\n  - apps/**\n");
        write(tmp.path(), PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "apps/package.json",
            r#"{"private":true,"workspaces":["web"]}"#,
        );
        write(
            tmp.path(),
            "apps/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        write(tmp.path(), "apps/web/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("apps/web"), "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
    }

    #[test]
    fn workspaces_patterns_match_like_npm_and_yarn() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a")
        ));
        assert!(!workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["./packages/*/"]),
            &rel("packages/a")
        ));
        assert!(workspaces_include(
            &pats(&["packages/**"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["**/pkg-*"]),
            &rel("x/y/pkg-one")
        ));
        assert!(workspaces_include(&pats(&["app"]), &rel("app")));
        assert!(!workspaces_include(&pats(&["app"]), &rel("apps")));
        assert!(workspaces_include(&pats(&["app?"]), &rel("apps")));
        assert!(!workspaces_include(
            &pats(&["packages/*", "!packages/b"]),
            &rel("packages/b")
        ));
        assert!(!workspaces_include(&pats(&["*"]), &[]));
    }

    /// #1071: npm (minimatch), yarn and Bun expand brace sets and match
    /// character classes in `workspaces`.
    #[test]
    fn workspaces_patterns_expand_braces_and_match_classes() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let yes = |p: &str, r: &str| assert!(workspaces_include(&pats(&[p]), &rel(r)), "{p} ~ {r}");
        let no =
            |p: &str, r: &str| assert!(!workspaces_include(&pats(&[p]), &rel(r)), "{p} !~ {r}");
        // Brace sets, nested, spanning separators, and sequences.
        yes("packages/{a,b}", "packages/a");
        yes("packages/{a,b}", "packages/b");
        no("packages/{a,b}", "packages/c");
        yes("{apps,packages}/*", "apps/web");
        yes("packages/{a,{b,c}x}", "packages/cx");
        no("packages/{a,{b,c}x}", "packages/c");
        yes("{packages/a,tools/*}", "tools/t");
        yes("packages/pkg-{1..3}", "packages/pkg-2");
        no("packages/pkg-{1..3}", "packages/pkg-4");
        yes("packages/{a..c}", "packages/b");
        yes("packages/v{01..10}", "packages/v07");
        yes("packages/{,x}a", "packages/a");
        // A brace group with no comma or range is literal, as in minimatch.
        yes("packages/{a}", "packages/{a}");
        no("packages/{a}", "packages/a");
        yes("packages/{a,b", "packages/{a,b");
        // Character classes: sets, ranges, negation, a literal `]` first.
        yes("packages/[a-c]", "packages/b");
        no("packages/[a-c]", "packages/d");
        yes("packages/[ab]x", "packages/bx");
        yes("packages/[!b]", "packages/a");
        no("packages/[!b]", "packages/b");
        yes("packages/[^b]", "packages/c");
        yes("packages/[]a]", "packages/]");
        yes("packages/[a-c]*", "packages/core");
        // An unclosed class is a literal `[`.
        yes("packages/[a", "packages/[a");
        no("packages/[a", "packages/a");
        // Non-ASCII names match one character per `?` and class.
        yes("packages/?", "packages/é");
        yes("packages/[é]", "packages/é");
        // Negation applies to the expanded alternatives too.
        assert!(!workspaces_include(
            &pats(&["packages/*", "!packages/{b,c}"]),
            &rel("packages/b")
        ));
    }

    /// #942: vlt's `workspaces` in `vlt.json` is a string, an array or an
    /// object of named groups, each a string or an array.
    #[test]
    fn vlt_workspace_patterns_read_every_shape() {
        assert_eq!(
            vlt_workspace_patterns(r#"{"workspaces":"packages/*"}"#),
            Some(vec!["packages/*".to_string()])
        );
        assert_eq!(
            vlt_workspace_patterns("\u{feff}{\"workspaces\":[\"a/*\",\"b\"]}"),
            Some(vec!["a/*".to_string(), "b".to_string()])
        );
        assert_eq!(
            vlt_workspace_patterns(r#"{"workspaces":{"apps":"apps/*","libs":["libs/*","x"]}}"#),
            Some(vec![
                "apps/*".to_string(),
                "libs/*".to_string(),
                "x".to_string()
            ])
        );
        assert_eq!(vlt_workspace_patterns(r#"{"registries":{}}"#), None);
        assert_eq!(vlt_workspace_patterns("not json"), None);
    }

    /// #942: a vlt workspace member has no lock; the root's `vlt-lock.json`
    /// governs it. The root, a directory the root does not list and a
    /// never-installed root refuse nothing.
    #[tokio::test]
    async fn vlt_workspace_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(
            tmp.path(),
            "vlt.json",
            r#"{"workspaces":{"apps":"apps/*","libs":["packages/{a,b}"]}}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(tmp.path(), "packages/c/package.json", "{}");
        write(tmp.path(), "apps/web/package.json", "{}");
        let member = tmp.path().join("packages/a");
        // Never installed: no lock anywhere, nothing to refuse.
        assert_eq!(code(&member, "npm").await, None);

        write(tmp.path(), VLT_LOCK, "{}");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("a vlt workspace member must be refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        assert!(
            refusal.message.contains(VLT_LOCK)
                && refusal.message.contains("vlt.json")
                && refusal.message.contains("nothing was written"),
            "{}",
            refusal.message
        );
        assert_eq!(
            code(&tmp.path().join("apps/web"), "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
        assert_eq!(code(&tmp.path().join("packages/c"), "npm").await, None);
        assert_eq!(code(tmp.path(), "npm").await, None);
        assert_eq!(code(&member, "pypi").await, None);

        // A member with its own lock is its own root.
        write(tmp.path(), "packages/a/vlt-lock.json", "{}");
        assert_eq!(code(&member, "npm").await, None);
    }

    /// A `vlt-lock.json` at a `package.json` `workspaces` root governs no
    /// member through that field (vlt reads only `vlt.json`), and a
    /// `package-lock.json` at a `vlt.json` root governs none through
    /// `vlt.json` (npm reads only `package.json`).
    #[tokio::test]
    async fn vlt_and_package_json_workspaces_need_their_own_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), VLT_LOCK, "{}");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(code(&tmp.path().join("packages/a"), "npm").await, None);

        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(tmp.path(), "vlt.json", r#"{"workspaces":"packages/*"}"#);
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(code(&tmp.path().join("packages/a"), "npm").await, None);
    }

    /// The nearer of a `vlt.json` root and a `package.json` root governs.
    #[tokio::test]
    async fn nearer_of_vlt_and_package_json_roots_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/**"]}"#,
        );
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "apps/vlt.json", r#"{"workspaces":["web"]}"#);
        write(tmp.path(), "apps/package.json", "{}");
        write(tmp.path(), "apps/vlt-lock.json", "{}");
        write(tmp.path(), "apps/web/package.json", "{}");
        let refusal = refusal(
            &ProjectView::Disk(&tmp.path().join("apps/web")),
            &[candidate("npm")],
            true,
        )
        .await
        .expect("refused");
        assert!(refusal.message.contains(VLT_LOCK), "{}", refusal.message);
    }

    #[test]
    fn workspace_patterns_reads_both_field_shapes() {
        assert_eq!(
            workspace_patterns(r#"{"workspaces":["a/*","b"]}"#),
            Some(vec!["a/*".to_string(), "b".to_string()])
        );
        assert_eq!(
            workspace_patterns("\u{feff}{\"workspaces\":{\"packages\":[\"a/*\"]}}"),
            Some(vec!["a/*".to_string()])
        );
        assert_eq!(workspace_patterns(r#"{"name":"x"}"#), None);
        assert_eq!(workspace_patterns("not json"), None);
    }

    /// #417: a cargo workspace member is refused with the vendored code; the
    /// root and a standalone crate are not.
    #[tokio::test]
    async fn cargo_workspace_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"direct\"]\n",
        );
        write(
            tmp.path(),
            "direct/Cargo.toml",
            "[package]\nname = \"direct\"\nversion = \"0.1.0\"\n",
        );
        let member = tmp.path().join("direct");
        assert_eq!(
            code(&member, "cargo").await.as_deref(),
            Some(NOT_WORKSPACE_ROOT)
        );
        assert_eq!(code(tmp.path(), "cargo").await, None);
        assert_eq!(code(&member, "npm").await, None);

        let standalone = tempfile::tempdir().unwrap();
        write(
            standalone.path(),
            "Cargo.toml",
            "[package]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(code(standalone.path(), "cargo").await, None);
    }

    #[test]
    fn workspace_lockfile_dir_reads_the_top_level_key() {
        assert_eq!(
            workspace_lockfile_dir("lockfileDir: ..\n").as_deref(),
            Some("..")
        );
        assert_eq!(
            workspace_lockfile_dir("packages: []\nlockfileDir: \"../x\"\n").as_deref(),
            Some("../x")
        );
        assert_eq!(
            workspace_lockfile_dir("\"lockfileDir\": \"..\"\n").as_deref(),
            Some("..")
        );
        assert_eq!(
            workspace_lockfile_dir("'lockfileDir': ../x\n").as_deref(),
            Some("../x")
        );
        assert_eq!(workspace_lockfile_dir("  lockfileDir: ..\n"), None);
        assert_eq!(workspace_lockfile_dir("lockfileDirX: ..\n"), None);
        // Bugbot on #598: a BOM-prefixed file, and the last assignment.
        assert_eq!(
            workspace_lockfile_dir("\u{feff}lockfileDir: ../x\n").as_deref(),
            Some("../x")
        );
        assert_eq!(
            workspace_lockfile_dir("lockfileDir: ../a\nlockfileDir: ../b\n").as_deref(),
            Some("../b")
        );
        // #905: read through the shared `top_level_key` grammar, so every
        // spelling the workspace splices accept is read here too.
        assert_eq!(
            workspace_lockfile_dir("lockfileDir : ../x # shared lock\n").as_deref(),
            Some("../x")
        );
        assert_eq!(workspace_lockfile_dir("lockfileDir: \"\"\n"), None);
        assert_eq!(workspace_lockfile_dir("# lockfileDir: ..\n"), None);
    }
}
