//! Conservative line grammar for bun's text lockfile (`bun.lock`).
//!
//! `bun.lock` is JSONC (trailing commas), so the surgery the vendor and
//! redirect backends perform is line-oriented — bun emits each `packages`
//! entry on a single line — under a conservative grammar that fails CLOSED on
//! anything unexpected; the file is never fed to a JSON parser.
//!
//! This module owns the pure parsing/scanning primitives shared by those
//! backends. The vendor- and redirect-specific classification of a parsed
//! entry lives with each backend.

/// The text-lockfile versions the surgery has byte-exact fixtures for.
///
/// Bun 1.1.39–1.1.45 emits 0 with the same package tuple grammar.
/// bun 1.3.x emits 1 (spike pinned 1.3.14). bun 1.4.0 bumped the default to
/// 2 (oven-sh/bun PR #31539): the bump gates stricter PARSE checks —
/// integrity hashes required for off-registry npm tarballs, unsafe git
/// `.bun-tag` values rejected — behind an UNCHANGED emitted grammar (a
/// 1.3.14 and a 1.4.0 lock of the same fixture are byte-identical except
/// this integer; verified empirically). Our URL/local 3-tuples always carry
/// a sha512, so they satisfy the v2 off-registry-integrity rule by
/// construction.
///
/// Bun 1.4.0 and later write 3 instead of 2 when the root `package.json`
/// has a nested override (`"overrides": {"rc": {"minimist": "1.2.2"}}`) or
/// a yarn-style path resolution (`"resolutions": {"rc/minimist": "1.2.2"}`).
/// The only difference is in the lock's head, where `overrides` then holds
/// nested objects; the `packages` section this module splices is the same
/// grammar (measured on 1.4.0, 1.4.2, 1.4.3 and 1.4.4: a hosted or local
/// tuple written into a version-3 lock installs frozen and stays put). Bun
/// 1.3 cannot read a version-3 lock, as it cannot read a version-2 one, so
/// every rule keyed on "version 2 or later means Bun 1.4 or later" holds
/// for 3 as well.
const SUPPORTED_LOCK_VERSIONS: [u64; 4] = [0, 1, 2, 3];

/// The `patchedDependencies` keys a Bun project declares: the root
/// `package.json`'s object, which `bun patch --commit` writes and every
/// install reads, plus the copy Bun mirrors at the top of a text `bun.lock`
/// (`  "patchedDependencies": {` … `  },`, one `"key": "path"` line each).
/// Either source alone is enough: a key missing from one is still a patch
/// Bun applies. The manifest is read as Bun reads it, a leading BOM,
/// comments and trailing commas allowed ([`strip_jsonc`]); one Bun cannot parse either, and a lock
/// section out of Bun's emitted shape, contribute only what they spell
/// plainly.
pub(crate) fn patched_dependency_keys(manifest: Option<&str>, lock: Option<&str>) -> Vec<String> {
    let mut keys: Vec<String> = manifest
        .and_then(parse_manifest)
        .and_then(|value| match value.get("patchedDependencies") {
            Some(serde_json::Value::Object(map)) => Some(map.keys().cloned().collect()),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(lock) = lock {
        let mut lines = lock
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .skip_while(|l| *l != "  \"patchedDependencies\": {")
            .skip(1);
        while let Some((4, key, _, _)) = lines.next().and_then(parse_string_pair_line) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

pub(crate) use crate::formats::package_json::strip_jsonc;

/// A root `package.json` parsed as Bun reads it: a leading BOM, comments
/// and trailing commas allowed. `None` when Bun could not parse it either.
fn parse_manifest(text: &str) -> Option<serde_json::Value> {
    crate::formats::package_json::parse(text)
}

/// Bun's built-in default-trusted package names, the union of every release
/// up to 1.4.2 (`src/install/default-trusted-dependencies.txt` upstream).
const DEFAULT_TRUSTED: &str = include_str!("bun_default_trusted.txt");

/// Whether Bun runs `name`'s lifecycle scripts only through its built-in
/// default trust, which a hosted or vendored rewire takes away (#371).
///
/// Bun trusts a package when the project's `trustedDependencies` lists it,
/// or, when the project declares no `trustedDependencies` at all, when its
/// name is on Bun's default list. From Bun 1.3.5 on that default applies
/// only to packages resolved from the npm registry, so a package on a hosted
/// URL or a local tarball loses it: `bun install` skips its `install` /
/// `postinstall` script without failing, and a native addon is left
/// unbuilt. An explicit list (in the root manifest, or the copy Bun mirrors
/// at the top of a text `bun.lock`) already decides trust by name alone,
/// so the rewire changes nothing there.
pub(crate) fn loses_default_trust(manifest: Option<&str>, lock: Option<&str>, name: &str) -> bool {
    // The list lookup is cheap and almost always false, so it runs first:
    // the hosted rewriter calls this per wired dep, and the manifest parse
    // plus whole-lock scan must not land in its per-dep loop (#578).
    static TRUSTED: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    if !TRUSTED
        .get_or_init(|| DEFAULT_TRUSTED.lines().collect())
        .contains(name)
    {
        return false;
    }
    let declared = manifest.and_then(parse_manifest).is_some_and(|value| {
        value
            .get("trustedDependencies")
            .is_some_and(|v| v.is_array())
    }) || lock.is_some_and(|lock| {
        lock.split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .any(|l| l.starts_with("  \"trustedDependencies\": ["))
    });
    !declared
}

/// The user-facing warning for a rewired package that loses Bun's default
/// trust ([`loses_default_trust`]), shared by the hosted and vendored paths.
/// `target` names what the package now resolves to.
pub(crate) fn default_trust_detail(name: &str, version: &str, target: &str) -> String {
    format!(
        "{name}@{version} is on Bun's default trusted list, which Bun 1.3.5 and later apply \
         only to packages installed from the npm registry; now that it resolves to {target}, \
         `bun install` skips its install scripts without failing (`bun pm untrusted` lists \
         it), which can leave native bindings unbuilt. Add \"{name}\" to \
         \"trustedDependencies\" in package.json and run `bun install`. Declaring \
         trustedDependencies replaces Bun's default list, so also list any other \
         default-trusted dependency whose scripts you rely on"
    )
}

/// The user-facing reason a default-trusted package ([`loses_default_trust`])
/// is left on the registry, unpatched, instead of being rewired to `target`,
/// shared by the hosted and vendored paths.
///
/// Bun reads `trustedDependencies` from `package.json` alone: a copy written
/// only into `bun.lock` leaves the install script blocked on a frozen
/// install and is deleted by a plain one (measured on Bun 1.3.14 and
/// 1.4.4), so a lockfile edit cannot keep the script running.
pub(crate) fn default_trust_skip_detail(name: &str, version: &str, target: &str) -> String {
    format!(
        "{name}@{version} is on Bun's default trusted list, which Bun 1.3.5 and later apply \
         only to packages installed from the npm registry; resolving it to {target} would \
         make `bun install` skip its install scripts without failing, which can leave native \
         bindings unbuilt, so it was left on the registry and stays UNPATCHED. To patch it, \
         add \"{name}\" to \"trustedDependencies\" in package.json (declaring \
         trustedDependencies replaces Bun's default list, so also list any other \
         default-trusted dependency whose scripts you rely on), run `bun install`, and run \
         socket-patch again. `--mode agent` patches the installed copy without changing how \
         it resolves"
    )
}

/// The `patchedDependencies` key that makes Bun apply a project-authored
/// patch to `name@version`, if any, which a run that rewires the package
/// to `target` (a hosted URL or vendored tarball path) would orphan. Bun
/// keys the patch on the package's resolution: the registry
/// `name@version`, or, for a `bun patch` made after a hosted or vendored
/// rewire, the tarball it resolves to (Bun 1.4, #1019). A bare `name` is
/// matched too so that a key spelled without a version never slips past
/// the gate.
///
/// Bun applies such a patch only while the lock resolves the package to
/// that resolution. Rewiring it elsewhere makes Bun drop the user's patch
/// on every install, silently (#367), so both modes leave such a package
/// alone and say why. A key for `target` itself is no conflict: the run
/// leaves the package where the patch applies. Any other tarball key
/// counts, even one the lock no longer resolves to: a takeover checks
/// after reverting the wiring the key names, so the lock cannot tell a
/// stale key from a live one, and the refusal's remedy (remove the entry)
/// clears a stale one.
pub(crate) fn patched_dependency_key<'k>(
    keys: &'k [String],
    name: &str,
    version: &str,
    target: &str,
) -> Option<&'k str> {
    let spec = format!("{name}@{version}");
    keys.iter()
        .map(String::as_str)
        .find(|key| *key == spec || *key == name)
        .or_else(|| {
            keys.iter().map(String::as_str).find(|key| {
                tarball_resolution(key, name, version)
                    .is_some_and(|resolution| resolution != target)
            })
        })
}

/// The resolution `key` names when it is `name@<url or path>` of
/// `name@version`'s own tarball, the key a `bun patch` made after a hosted
/// or vendored rewire writes (Bun 1.4, #1019), such as
/// `left-pad@.socket/vendor/npm/<uuid>/left-pad-1.3.0.tgz`: a hosted URL
/// and a vendored path both end in npm's tarball name.
fn tarball_resolution<'k>(key: &'k str, name: &str, version: &str) -> Option<&'k str> {
    let (key_name, resolution) = split_name_spec(key)?;
    let leaf = name.rsplit('/').next().unwrap_or(name);
    (key_name == name && resolution.ends_with(&format!("/{leaf}-{version}.tgz")))
        .then_some(resolution)
}

/// Of `keys`, the ones naming a non-registry resolution that `specs` (the
/// lock's `name@resolution` entry specs) still holds: the patches Bun
/// applies to a hosted or vendored tarball right now (#1019). An unwind
/// that takes one of these out of the lock drops that patch.
pub(crate) fn live_resolution_keys<'s>(
    keys: &[String],
    specs: impl IntoIterator<Item = &'s str>,
) -> std::collections::BTreeSet<String> {
    let specs: std::collections::HashSet<&str> = specs.into_iter().collect();
    keys.iter()
        .filter(|key| {
            split_name_spec(key).is_some_and(|(_, resolution)| resolution.contains('/'))
                && specs.contains(key.as_str())
        })
        .cloned()
        .collect()
}

/// The user-facing warning detail for a project-authored Bun patch keyed by
/// a tarball the package no longer resolves to after an unwind (#1019).
pub(crate) fn dropped_patch_detail(key: &str) -> String {
    let name = split_name_spec(key).map_or(key, |(name, _)| name);
    format!(
        "package.json `patchedDependencies` has `{key}`, a patch the project applies with \
         `bun patch` only while {name} resolves to that tarball; now that the lock resolves it \
         elsewhere, `bun install` stops applying that patch without failing. Re-create it with \
         `bun patch {name}` and `bun patch --commit`, or remove the entry"
    )
}

/// The user-facing reason a package with a project-authored Bun patch is
/// left on its current resolution, shared by the hosted and vendored
/// paths so the two modes never drift apart.
pub(crate) fn patched_dependency_detail(key: &str, name: &str, version: &str) -> String {
    let applies_to = match split_name_spec(key) {
        Some((_, resolution)) if resolution != version => {
            format!("while {name}@{version} resolves to {resolution}")
        }
        _ => format!("to the registry {name}@{version}"),
    };
    format!(
        "package.json `patchedDependencies` has `{key}`, a patch the project applies with \
         `bun patch`; Bun applies it only {applies_to}, so rewiring the \
         package would silently drop that patch from every install. It is left unchanged and \
         stays without the Socket patch: fold the Socket fix into your own patch, or remove \
         the `patchedDependencies` entry (`bun patch --commit` again without it) and re-run"
    )
}

/// One parsed single-line packages entry.
pub(crate) struct BunEntry {
    pub(crate) line_idx: usize,
    /// Leading whitespace, re-emitted verbatim.
    pub(crate) indent: String,
    /// Decoded map key (`left-pad`, `haspad/left-pad`).
    pub(crate) key: String,
    /// The key token exactly as spelled (incl. quotes), re-emitted verbatim.
    pub(crate) key_raw: String,
    /// Verbatim top-level tuple elements (trimmed).
    pub(crate) elems: Vec<String>,
    pub(crate) trailing_comma: bool,
    /// Bun never installs this entry from its own spec: it is unpacked from
    /// a bundling ancestor's tarball ([`is_bundled_entry`]). Set by
    /// [`parse_packages_section`], which sees the whole lock; an entry
    /// parsed on its own ([`parse_entry_line`]) is `false`.
    pub(crate) in_bundled_copy: bool,
}

/// `name@spec` split at the FIRST `@` past the leading character: a name's
/// only `@` is a scope marker at index 0, while the spec itself may contain
/// `@` (a vendored path keeps the scope dir in its leaf —
/// `@scope/pkg@.socket/vendor/npm/<uuid>/@scope/pkg-1.0.0.tgz`), so the
/// last `@` is not a safe split point.
pub(crate) fn split_name_spec(s: &str) -> Option<(&str, &str)> {
    let at = s
        .char_indices()
        .find_map(|(i, c)| (c == '@' && i > 0).then_some(i))?;
    Some((&s[..at], &s[at + 1..]))
}

/// The version a user tarball dependency of `name` installs (#497). Bun
/// records a remote-URL or `file:` tarball dependency as `name@<url|path>`
/// (text) or as a tarball resolution (binary) with no version of its own,
/// and installs it from that spec, never from the registry, so no rewire
/// of a registry `name@version` reaches it. The version is read from the
/// artifact leaf, `<bare>-<version>.tgz` (or `.tar.gz`) with a semver
/// `<version>` (`<bare>` = the name without its `@scope/`): the leaf every
/// registry tarball and `npm pack` output carries. A leaf naming no version
/// yields `None`, and so does our own vendored path.
pub(crate) fn user_tarball_version<'t>(name: &str, target: &'t str) -> Option<&'t str> {
    // The leaf checks are cheap and reject a registry spec (`name@1.2.3`)
    // at once; the vendor-path parse runs only for a tarball leaf (#578).
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let leaf = path.rsplit(['/', '\\']).next()?;
    let bare = name.rsplit('/').next().unwrap_or(name);
    let version = leaf.strip_prefix(bare)?.strip_prefix('-')?;
    let version = version
        .strip_suffix(".tgz")
        .or_else(|| version.strip_suffix(".tar.gz"))?;
    if crate::vendor::path::parse_vendor_path(target).is_some() {
        return None;
    }
    semver::Version::parse(version).is_ok().then_some(version)
}

/// [`user_tarball_version`] for a text `packages` entry: true when the
/// entry's spec is `name@<tarball>` and the tarball's leaf names `version`.
pub(crate) fn is_user_tarball_entry(entry: &BunEntry, name: &str, version: &str) -> bool {
    entry
        .elems
        .first()
        .and_then(|raw| decode_json_string(raw))
        .is_some_and(|spec| is_user_tarball_spec(&spec, name, version))
}

/// [`is_user_tarball_entry`] on an already-decoded `name@<target>` spec,
/// for hot loops that decoded it once already. The name is matched by a
/// prefix strip, so an entry of another package costs one compare.
#[inline]
pub(crate) fn is_user_tarball_spec(spec: &str, name: &str, version: &str) -> bool {
    // Length and separator first: the hosted rewriter asks this of every
    // lock entry per patch, nearly all of another package (#578).
    if spec.as_bytes().get(name.len()) != Some(&b'@') {
        return false;
    }
    spec.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('@'))
        .is_some_and(|target| user_tarball_version(name, target) == Some(version))
}

/// `"lockfileVersion": <n>` head check — only the fixture-pinned text
/// lockfile versions are spliced (fail-closed on anything newer/older).
///
/// The `Err` text is the user-facing refusal detail for BOTH the vendored
/// and the hosted (`redirect_bun_lock_unsupported`) paths, so the two modes
/// never drift apart. Each arm's remedy is the one that can actually work:
/// every accepted version is 0 to 3 and the parser yields a `u64`, so an
/// unsupported `Some(v)` is a lock newer than this release knows — written
/// by a Bun newer than any we test — and "re-lock with a newer Bun" would
/// just reproduce it; updating socket-patch (or re-locking with an older
/// Bun) is the fix. Only a head with no integer at all is a lock that a
/// current Bun re-lock repairs.
pub(crate) fn check_lock_version(text: &str) -> Result<(), String> {
    match lock_version(text) {
        Some(v) if SUPPORTED_LOCK_VERSIONS.contains(&v) => Ok(()),
        Some(v) => Err(format!(
            "bun.lock has lockfileVersion {v}, newer than this socket-patch release supports \
             (0 to 3) — update socket-patch, or re-lock with a Bun release that writes \
             lockfileVersion 0–3"
        )),
        None => Err(
            "bun.lock has no integer lockfileVersion in its head; only 0 to 3 are \
             supported — re-lock with Bun ≥ 1.2 (`bun install`)"
                .to_string(),
        ),
    }
}

pub(crate) fn lock_version(text: &str) -> Option<u64> {
    text.lines()
        .take(5)
        .find_map(|line| line.trim().strip_prefix("\"lockfileVersion\":"))
        .and_then(|rest| rest.trim().trim_end_matches(',').parse().ok())
}

pub(crate) fn has_workspace_packages(entries: &[BunEntry]) -> bool {
    entries.iter().any(|entry| {
        entry
            .elems
            .first()
            .and_then(|raw| decode_json_string(raw))
            .is_some_and(|spec| {
                split_name_spec(&spec).is_some_and(|(_, version)| version.starts_with("workspace:"))
            })
    })
}

#[cfg(test)]
thread_local! {
    /// Entry metas this thread JSON-parsed to look for `"bundled": true`
    /// ([`declares_bundled`] past its substring fast path). Parsing a lock
    /// pays one per entry that spells `bundled`, and no rewrite loop over
    /// N deps × M entries may add any (#578, #580).
    pub(crate) static BUNDLED_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// True when Bun installs `entry` from a bundling ancestor's tarball and
/// never reads the entry's spec (#469): no rewire of it reaches the
/// installed bytes, so the rewriters skip it and lockfile discovery never
/// takes it as a ref. That is an entry whose `{meta}` carries
/// `"bundled": true` (a name in the parent's `bundleDependencies`), and
/// every entry reached only through such entries: Bun also writes the
/// bundled copies' own dependencies into the lock, as unflagged
/// `parent/child` entries with registry specs, but it never fetches them —
/// they too come out of the parent's tarball, at whatever version the
/// parent packed. See [`mark_bundled_copies`].
pub(crate) fn is_bundled_entry(entry: &BunEntry) -> bool {
    entry.in_bundled_copy
}

/// True when `entry`'s own `{meta}` object carries `"bundled": true`. The
/// meta is the first object element (index 2 of a registry 4-tuple, 1 of a
/// tarball tuple). A meta that does not parse as JSON but mentions
/// `"bundled"` counts as bundled: fail closed, never rewire or attest it.
pub(crate) fn declares_bundled(entry: &BunEntry) -> bool {
    let Some(meta) = entry_meta(entry) else {
        return false;
    };
    // Fast path (#580): a meta that never spells `bundled` cannot carry the
    // key. A backslash could hide it behind a JSON escape, so only a meta
    // with neither skips the parse.
    if !meta.contains("bundled") && !meta.contains('\\') {
        return false;
    }
    #[cfg(test)]
    BUNDLED_CHECKS.with(|checks| checks.set(checks.get() + 1));
    match serde_json::from_str::<serde_json::Value>(meta) {
        Ok(value) => value.get("bundled").and_then(serde_json::Value::as_bool) == Some(true),
        Err(_) => meta.contains("\"bundled\""),
    }
}

/// The `{meta}` object of a tuple, verbatim.
fn entry_meta(entry: &BunEntry) -> Option<&str> {
    entry
        .elems
        .iter()
        .skip(1)
        .map(String::as_str)
        .find(|e| e.starts_with('{'))
}

/// The package names of a packages key, outermost first: `a/b` is `b`
/// nested under `a`, and a scoped name keeps its own slash
/// (`@scope/a/@scope/b`).
fn key_segments(key: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut rest = key;
    while !rest.is_empty() {
        let mut end = rest.find('/').unwrap_or(rest.len());
        if rest.starts_with('@') && end < rest.len() {
            end = rest[end + 1..]
                .find('/')
                .map_or(rest.len(), |next| end + 1 + next);
        }
        segments.push(&rest[..end]);
        rest = rest[end..].strip_prefix('/').unwrap_or("");
    }
    segments
}

/// Set [`BunEntry::in_bundled_copy`] on every entry Bun unpacks from a
/// bundling ancestor's tarball.
///
/// Bun flags only the names a package lists in `bundleDependencies`
/// (`"bundled": true`). The dependencies of those copies get ordinary
/// looking entries under the same parent, which Bun writes but never
/// installs: a project that depends on `npm` has hundreds. So an unflagged
/// entry counts too when it is nested, some entry depends on it, and every
/// entry that depends on it is itself a bundled copy. A dependency name is
/// resolved the way Bun's text lock does it, to the nearest key walking up
/// from the dependent (`a/b` needs `c`: `a/b/c`, then `a/c`, then `c`).
/// Top-level entries and a workspace member's own nested entries are never
/// inferred: the project's manifests can depend on those, and their
/// dependency lists are not in the packages section. Measured against what
/// Bun 1.4.4 downloads into an empty cache for `npm@6.14.18`,
/// `npm@10.9.0`, `fsevents@1.2.9` and a 1,069-entry lock holding
/// `semantic-release`: the entries left unmarked are exactly the packages
/// Bun fetched.
///
/// A lock with no flagged entry costs one substring search per entry. A
/// meta that is not JSON leaves only the flagged entries marked: without
/// every dependency list, nothing can be inferred.
fn mark_bundled_copies(entries: &mut [BunEntry]) {
    let flagged: Vec<bool> = entries.iter().map(declares_bundled).collect();
    if !flagged.contains(&true) {
        return;
    }
    for (entry, flag) in entries.iter_mut().zip(&flagged) {
        entry.in_bundled_copy = *flag;
    }
    let Some(inferred) = inferred_bundled_copies(entries, &flagged) else {
        return;
    };
    for (entry, inferred) in entries.iter_mut().zip(inferred) {
        entry.in_bundled_copy |= inferred;
    }
}

/// The unflagged entries [`mark_bundled_copies`] infers, or `None` when a
/// meta cannot be read.
fn inferred_bundled_copies(entries: &[BunEntry], flagged: &[bool]) -> Option<Vec<bool>> {
    use std::collections::HashMap;

    let mut index: HashMap<&str, usize> = HashMap::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        index.entry(entry.key.as_str()).or_insert(i);
    }
    let segments: Vec<Vec<&str>> = entries.iter().map(|e| key_segments(&e.key)).collect();

    // What each entry depends on, and what depends on each entry.
    let mut dependencies: Vec<Vec<usize>> = vec![Vec::new(); entries.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); entries.len()];
    let mut candidate_key = String::new();
    for (i, entry) in entries.iter().enumerate() {
        let Some(meta) = entry_meta(entry) else {
            continue;
        };
        if meta == "{}" {
            continue;
        }
        let meta: serde_json::Value = serde_json::from_str(meta).ok()?;
        for group in ["dependencies", "optionalDependencies", "peerDependencies"] {
            let Some(names) = meta.get(group).and_then(serde_json::Value::as_object) else {
                continue;
            };
            for name in names.keys() {
                let resolved = (0..=segments[i].len()).rev().find_map(|depth| {
                    candidate_key.clear();
                    for segment in &segments[i][..depth] {
                        candidate_key.push_str(segment);
                        candidate_key.push('/');
                    }
                    candidate_key.push_str(name);
                    index.get(candidate_key.as_str()).copied()
                });
                if let Some(target) = resolved {
                    if target != i && !dependencies[i].contains(&target) {
                        dependencies[i].push(target);
                        dependents[target].push(i);
                    }
                }
            }
        }
    }

    let is_workspace = |i: usize| {
        entries[i]
            .elems
            .first()
            .and_then(|raw| decode_json_string(raw))
            .is_some_and(|spec| {
                split_name_spec(&spec).is_some_and(|(_, version)| version.starts_with("workspace:"))
            })
    };
    // Nested, and not directly under a workspace member.
    let inferable = |i: usize| {
        let Some((_, parents)) = segments[i].split_last() else {
            return false;
        };
        !parents.is_empty()
            && index
                .get(parents.join("/").as_str())
                .is_none_or(|&parent| !is_workspace(parent))
    };

    // Everything a flagged entry reaches is a candidate ...
    let mut inferred = vec![false; entries.len()];
    let mut reached = flagged.to_vec();
    let mut stack: Vec<usize> = (0..entries.len()).filter(|&i| flagged[i]).collect();
    while let Some(i) = stack.pop() {
        for &target in &dependencies[i] {
            if !reached[target] {
                reached[target] = true;
                stack.push(target);
            }
        }
    }
    for i in 0..entries.len() {
        inferred[i] = reached[i] && !flagged[i] && inferable(i) && !dependents[i].is_empty();
    }
    // ... until something Bun does install depends on it. Dropping one
    // candidate can expose the candidates it depends on, so they are
    // looked at again.
    let mut queue: Vec<usize> = (0..entries.len()).filter(|&i| inferred[i]).collect();
    while let Some(i) = queue.pop() {
        if inferred[i]
            && dependents[i]
                .iter()
                .any(|&dependent| !flagged[dependent] && !inferred[dependent])
        {
            inferred[i] = false;
            queue.extend(dependencies[i].iter().copied().filter(|&d| inferred[d]));
        }
    }
    // An entry stored under a bundled copy lives inside that copy's
    // directory, which Bun does not populate.
    for i in 0..entries.len() {
        if flagged[i] || inferred[i] || segments[i].len() < 2 {
            continue;
        }
        let under_bundled_copy = (1..segments[i].len()).any(|depth| {
            index
                .get(segments[i][..depth].join("/").as_str())
                .is_some_and(|&ancestor| flagged[ancestor] || inferred[ancestor])
        });
        inferred[i] = under_bundled_copy;
    }
    Some(inferred)
}

/// `(header_idx, close_idx)` of the lock's own `"packages": {` section.
pub(crate) fn packages_bounds(lines: &[String]) -> Option<(usize, usize)> {
    let start = top_level_packages_header(lines)?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| matches!(l.trim_end(), "  }" | "  },"))
        .map(|(i, _)| i)?;
    Some((start, end))
}

/// The line holding the lock's top-level `"packages"` key, in bun's emitted
/// spelling: the first such line that is a key of the root object and not
/// inside a comment. The lock is JSONC, so the same text can also sit in a
/// `/* … */` block or under some other key, where Bun does not read it as
/// the package list; taking that line would attest (or rewire) entries
/// Bun never installs. Bun itself takes the first of two top-level keys.
/// Only the lock's head is walked: the scan stops at the header.
fn top_level_packages_header(lines: &[String]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_block_comment = false;
    for (idx, line) in lines.iter().enumerate() {
        if depth == 1 && !in_block_comment && line.trim_end() == "  \"packages\": {" {
            return Some(idx);
        }
        let bytes = line.as_bytes();
        // A JSON string cannot span lines.
        let mut in_string = false;
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if in_block_comment {
                if byte == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    in_block_comment = false;
                    i += 1;
                }
            } else if in_string {
                match byte {
                    b'\\' => i += 1,
                    b'"' => in_string = false,
                    _ => {}
                }
            } else {
                match byte {
                    b'"' => in_string = true,
                    b'/' if bytes.get(i + 1) == Some(&b'/') => break,
                    b'/' if bytes.get(i + 1) == Some(&b'*') => {
                        in_block_comment = true;
                        i += 1;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            i += 1;
        }
    }
    None
}

/// Strictly parse every entry line of the packages section. Any line that
/// is neither blank nor a single-line `"key": [tuple]` entry fails CLOSED.
pub(crate) fn parse_packages_section(lines: &[String]) -> Result<Vec<BunEntry>, String> {
    let Some((start, end)) = packages_bounds(lines) else {
        // Only a lock with NO `"packages"` object at all is an empty lock.
        // Everything else fails CLOSED: an unterminated canonical section is
        // malformed, and a header spelled ANY other way than bun's byte-exact
        // emitted shape (tab/4-space re-indent, `"packages" : {`) must refuse
        // rather than read as "no entries" — treating it as empty would make
        // the caller silently skip a lock bun itself parses fine.
        return if top_level_packages_header(lines).is_some() {
            Err("unterminated \"packages\" section".to_string())
        } else if lines.iter().any(|l| l.trim_end() == "  \"packages\": {") {
            // Spelled as bun spells it, but not a key of the root object
            // (inside a comment, or under another key): not the package
            // list Bun reads, and no reason to read the lock as empty.
            Err(
                "the only \"packages\" section is inside a comment or under another key"
                    .to_string(),
            )
        } else if lines.iter().any(|l| {
            l.trim_start()
                .strip_prefix("\"packages\"")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|rest| rest.trim_start().starts_with('{'))
        }) {
            Err("\"packages\" section header is not in bun's emitted shape".to_string())
        } else {
            Ok(Vec::new())
        };
    };
    let mut entries = Vec::new();
    for (idx, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let mut entry = parse_entry_line(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
        entry.line_idx = idx;
        entries.push(entry);
    }
    mark_bundled_copies(&mut entries);
    Ok(entries)
}

/// Parse one `    "key": ["…", …],` line (the only shape bun emits for
/// packages entries). Returns `Err` on anything that deviates.
pub(crate) fn parse_entry_line(line: &str) -> Result<BunEntry, String> {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, s) = line.split_at(indent_len);
    // Key token: a JSON string.
    let key_end = scan_json_string(s)?;
    let key_raw = &s[..key_end];
    let key = decode_json_string(key_raw).ok_or("invalid JSON string key")?;
    // `: [` separator.
    let after = s[key_end..]
        .strip_prefix(':')
        .ok_or("expected `:` after the entry key")?
        .trim_start();
    if !after.starts_with('[') {
        return Err("entry value is not a single-line array".to_string());
    }
    // The tuple, with depth/string tracking up to its matching `]`.
    let close = scan_balanced_array(after)?;
    let interior = &after[1..close - 1];
    let tail = after[close..].trim();
    let trailing_comma = match tail {
        "" => false,
        "," => true,
        other => return Err(format!("unexpected trailing content `{other}`")),
    };
    let elems = split_top_level(interior)?;
    if elems.is_empty() {
        return Err("empty tuple".to_string());
    }
    Ok(BunEntry {
        line_idx: 0, // set by the caller
        indent: indent.to_string(),
        key,
        key_raw: key_raw.to_string(),
        elems,
        trailing_comma,
        in_bundled_copy: false, // set by `parse_packages_section`
    })
}

/// Byte index one past the closing quote of the JSON string at the start of
/// `s` (escape-aware).
fn scan_json_string(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected a quoted key".to_string());
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err("unterminated string".to_string())
}

/// Byte index one past the `]` matching the `[` at the start of `s`
/// (string- and nesting-aware; closer type must match its opener).
fn scan_balanced_array(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&s[i..])? - 1,
            b'[' => stack.push(b']'),
            b'{' => stack.push(b'}'),
            b']' | b'}' => {
                if stack.pop() != Some(bytes[i]) {
                    return Err("mismatched brackets".to_string());
                }
                if stack.is_empty() {
                    return Ok(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("unterminated array".to_string())
}

/// Split the tuple interior at top-level commas into verbatim trimmed
/// element substrings.
fn split_top_level(interior: &str) -> Result<Vec<String>, String> {
    let bytes = interior.as_bytes();
    let mut elems = Vec::new();
    let mut stack: Vec<u8> = Vec::new();
    let mut elem_start = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&interior[i..])? - 1,
            b'[' => stack.push(b']'),
            b'{' => stack.push(b'}'),
            b']' | b'}' => {
                if stack.pop() != Some(bytes[i]) {
                    return Err("unbalanced brackets".to_string());
                }
            }
            b',' if stack.is_empty() => {
                elems.push(interior[elem_start..i].trim().to_string());
                elem_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = interior[elem_start..].trim();
    if !last.is_empty() {
        elems.push(last.to_string());
    }
    if elems.iter().any(String::is_empty) {
        return Err("empty tuple element".to_string());
    }
    Ok(elems)
}

/// Decode a verbatim JSON string token; `None` if it is not one.
pub(crate) fn decode_json_string(token: &str) -> Option<String> {
    if !token.starts_with('"') {
        return None;
    }
    serde_json::from_str::<String>(token).ok()
}

/// The dependency groups a `workspaces` member lists, in both the lock and
/// its `package.json`.
const WORKSPACE_DEP_GROUPS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// One `"key": "value"` line, decoded: `(indent, key, value, trailing_comma)`.
fn parse_string_pair_line(line: &str) -> Option<(usize, String, String, bool)> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let indent = line.len() - line.trim_start().len();
    let s = &line[indent..];
    let key_end = scan_json_string(s).ok()?;
    let key = decode_json_string(&s[..key_end])?;
    let rest = s[key_end..].strip_prefix(": ")?;
    let value_end = scan_json_string(rest).ok()?;
    let value = decode_json_string(&rest[..value_end])?;
    let trailing_comma = match &rest[value_end..] {
        "" => false,
        "," => true,
        _ => return None,
    };
    Some((indent, key, value, trailing_comma))
}

/// A `"key": {` line at exactly `indent` spaces: the decoded key.
fn object_open_key(line: &str, indent: usize) -> Option<String> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let s = line.strip_prefix(&" ".repeat(indent))?;
    let key_end = scan_json_string(s).ok()?;
    if &s[key_end..] != ": {" {
        return None;
    }
    decode_json_string(&s[..key_end])
}

/// A `}` / `},` line at exactly `indent` spaces.
fn is_object_close(line: &str, indent: usize) -> bool {
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.strip_prefix(&" ".repeat(indent))
        .is_some_and(|rest| matches!(rest, "}" | "},"))
}

/// One dependency line of a `workspaces` member.
struct WorkspaceDepLine {
    line_idx: usize,
    /// The member's lock key (`""` is the root).
    workspace: String,
    group: String,
    name: String,
    literal: String,
}

/// The `workspaces` section in bun's emitted shape.
struct WorkspacesSection {
    /// Each member's `(key, name)`, in lock order.
    members: Vec<(String, Option<String>)>,
    deps: Vec<WorkspaceDepLine>,
}

/// Parse the `workspaces` section. `None` when there is no section or it
/// deviates from bun's emitted shape anywhere (fail closed).
fn parse_workspaces_section(lines: &[String]) -> Option<WorkspacesSection> {
    let start = lines
        .iter()
        .position(|l| l.strip_suffix('\r').unwrap_or(l) == "  \"workspaces\": {")?;
    let mut members = Vec::new();
    let mut deps = Vec::new();
    let mut idx = start + 1;
    loop {
        let line = lines.get(idx)?;
        if is_object_close(line, 2) {
            return Some(WorkspacesSection { members, deps });
        }
        let workspace = object_open_key(line, 4)?;
        let mut name = None;
        idx += 1;
        loop {
            let line = lines.get(idx)?;
            if is_object_close(line, 4) {
                break;
            }
            if let Some(group) = object_open_key(line, 6) {
                // Only the dependency groups hold `name: literal` pairs;
                // any other object member is skipped up to its close.
                let is_dep_group = WORKSPACE_DEP_GROUPS.contains(&group.as_str());
                idx += 1;
                loop {
                    let line = lines.get(idx)?;
                    if is_object_close(line, 6) {
                        break;
                    }
                    if is_dep_group {
                        let (indent, dep, literal, _) = parse_string_pair_line(line)?;
                        if indent != 8 {
                            return None;
                        }
                        deps.push(WorkspaceDepLine {
                            line_idx: idx,
                            workspace: workspace.clone(),
                            group: group.clone(),
                            name: dep,
                            literal,
                        });
                    }
                    idx += 1;
                }
            } else if let Some((6, key, value, _)) = parse_string_pair_line(line) {
                if key == "name" {
                    name = Some(value);
                }
            } else if line
                .strip_prefix("      \"")
                .is_none_or(|rest| rest.starts_with(' '))
            {
                // Not a member field at the member's own indent.
                return None;
            }
            idx += 1;
        }
        members.push((workspace, name));
        idx += 1;
    }
}

/// The member directories a `bun.lock` lists under `workspaces` (`""` is
/// the project root), in lock order. Empty when the section is absent or
/// not in bun's emitted shape.
pub(crate) fn workspace_member_dirs(lines: &[String]) -> Vec<String> {
    listed_workspace_dirs(lines).unwrap_or_default()
}

/// [`workspace_member_dirs`], but `None` when the section is absent or not
/// in bun's emitted shape, so a caller can tell "lists no such member"
/// from "could not read the list".
pub(crate) fn listed_workspace_dirs(lines: &[String]) -> Option<Vec<String>> {
    parse_workspaces_section(lines)
        .map(|section| section.members.into_iter().map(|(dir, _)| dir).collect())
}

/// Whether a `workspaces` key is a plain relative directory (`""` is the
/// root): no `..`, no absolute or drive-prefixed path, no backslash. Only
/// such a member's `package.json` is ever read.
pub(crate) fn is_plain_member_dir(dir: &str) -> bool {
    !dir.contains(['\\', ':'])
        && std::path::Path::new(dir)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// One workspace dependency literal [`heal_workspace_literals`] rewrote.
pub(crate) struct WorkspaceLiteralHeal {
    /// `<member>:<group>:<dependency>`, e.g. `packages/m1:dependencies:m2`.
    pub(crate) key: String,
    pub(crate) original: String,
    pub(crate) new: String,
}

/// Put back the `workspace:` literal a member's `package.json` declares
/// wherever the lock spells that inter-workspace dependency as the
/// target member's path instead.
///
/// A hosted or vendored `bun.lockb` stores the resolved member path as the
/// dependency literal (`normalize_workspace_behaviors`, which older binary
/// readers need). Bun 1.4 carries that path into `bun.lock` when it
/// migrates the lock to text, and its text reader then compares it with
/// the manifest's `workspace:*`, re-resolves the member and drops every
/// hosted or vendored tuple (#803): frozen installs fail and an unfrozen
/// one installs the unpatched registry bytes. Bun writes the manifest's
/// literal itself, so this restores exactly its own output.
///
/// Only a line whose literal is the path of a member with the dependency's
/// own name, and whose declaring manifest (read by `manifest`, keyed by
/// member dir, `""` for the root) spells it `workspace:…`, is touched.
/// Anything else, including a lock not in bun's emitted shape, is left
/// alone. A version-0 lock is never touched either: Bun 1.1 writes the
/// bare path there itself.
pub(crate) fn heal_workspace_literals(
    lines: &mut [String],
    mut manifest: impl FnMut(&str) -> Option<String>,
) -> Vec<WorkspaceLiteralHeal> {
    let head = lines.iter().take(5).cloned().collect::<Vec<_>>().join("\n");
    if lock_version(&head).is_none_or(|v| v < 1) {
        return Vec::new();
    }
    let Some(WorkspacesSection { members, deps }) = parse_workspaces_section(lines) else {
        return Vec::new();
    };
    let mut manifests = std::collections::HashMap::<String, Option<serde_json::Value>>::new();
    let mut heals = Vec::new();
    for dep in deps {
        let points_at_member = members.iter().any(|(dir, name)| {
            !dir.is_empty() && *dir == dep.literal && name.as_deref() == Some(dep.name.as_str())
        });
        if !points_at_member || !is_plain_member_dir(&dep.workspace) {
            continue;
        }
        let declared = manifests
            .entry(dep.workspace.clone())
            .or_insert_with(|| {
                manifest(&dep.workspace).and_then(|text| serde_json::from_str(&text).ok())
            })
            .as_ref()
            .and_then(|json| json.get(&dep.group))
            .and_then(|group| group.get(&dep.name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let Some(declared) = declared.filter(|d| d.starts_with("workspace:")) else {
            continue;
        };
        let original = lines[dep.line_idx].clone();
        // Only the value token changes: the key, the comma and a CRLF
        // lock's `\r` are re-emitted verbatim.
        let encoded =
            serde_json::to_string(&dep.literal).expect("a String serializes to JSON infallibly");
        let Some(at) = original.rfind(&format!(": {encoded}")) else {
            continue;
        };
        let start = at + 2;
        let new = format!(
            "{}{}{}",
            &original[..start],
            serde_json::to_string(&declared).expect("a String serializes to JSON infallibly"),
            &original[start + encoded.len()..],
        );
        lines[dep.line_idx] = new.clone();
        heals.push(WorkspaceLiteralHeal {
            key: format!("{}:{}:{}", dep.workspace, dep.group, dep.name),
            original,
            new,
        });
    }
    heals
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #497: a user tarball's version is its `<bare>-<semver>.tgz` leaf,
    /// for remote URLs and local paths alike; a registry version, a leaf
    /// naming no version or another package, and our own vendored path are
    /// not user tarballs.
    #[test]
    fn user_tarball_version_reads_the_leaf() {
        for (name, target, want) in [
            (
                "is-number",
                "https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz",
                Some("6.0.0"),
            ),
            ("is-number", "./is-number-6.0.0.tgz", Some("6.0.0")),
            ("is-number", "file:./is-number-6.0.0.tgz", Some("6.0.0")),
            ("is-number", "vendor\\is-number-6.0.0.tar.gz", Some("6.0.0")),
            (
                "@s/p",
                "https://h.test/@s/p/-/p-1.0.0-2.tgz?t=1",
                Some("1.0.0-2"),
            ),
            ("is-number", "6.0.0", None),
            ("is-number", "./is-number.tgz", None),
            ("is-number", "./is-number-latest.tgz", None),
            ("is-number", "./is-odd-6.0.0.tgz", None),
            ("is-number", "github:jonschlinkert/is-number#6.0.0", None),
            (
                "is-number",
                ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/is-number-6.0.0.tgz",
                None,
            ),
        ] {
            assert_eq!(user_tarball_version(name, target), want, "{name} {target}");
        }
    }

    #[test]
    fn is_user_tarball_spec_checks_the_name_first() {
        assert!(is_user_tarball_spec(
            "left-pad@./left-pad-1.3.0.tgz",
            "left-pad",
            "1.3.0"
        ));
        assert!(is_user_tarball_spec(
            "@s/p@file:./p-1.0.0.tgz",
            "@s/p",
            "1.0.0"
        ));
        assert!(!is_user_tarball_spec(
            "left-pad@./left-pad-1.2.0.tgz",
            "left-pad",
            "1.3.0"
        ));
        assert!(!is_user_tarball_spec("left-pad@1.3.0", "left-pad", "1.3.0"));
        assert!(!is_user_tarball_spec(
            "left-pad-x@./left-pad-1.3.0.tgz",
            "left-pad",
            "1.3.0"
        ));
        assert!(!is_user_tarball_spec(
            "is-odd@./left-pad-1.3.0.tgz",
            "left-pad",
            "1.3.0"
        ));
    }

    /// #1019: Bun 1.4 keys a `bun patch` made after a rewire by the
    /// package's resolution, the hosted URL or the vendored tarball path.
    /// Only a resolution to this package's own tarball matches.
    #[test]
    fn patched_dependency_key_matches_rewired_resolutions() {
        let keys: Vec<String> = [
            "plainpkg@https://patch.socket.dev/patch/npm/plainpkg/1.0.0/tok/u1/plainpkg-1.0.0.tgz",
            "@s/p@.socket/vendor/npm/u1/@s/p-2.0.0.tgz",
            "@s/q@https://patch.socket.dev/patch/npm/@s/q/3.0.0/tok/u1/q-3.0.0.tgz",
        ]
        .map(String::from)
        .into();
        assert_eq!(
            patched_dependency_key(&keys, "plainpkg", "1.0.0", ""),
            Some(keys[0].as_str())
        );
        assert_eq!(
            patched_dependency_key(&keys, "@s/p", "2.0.0", ""),
            Some(keys[1].as_str())
        );
        assert_eq!(
            patched_dependency_key(&keys, "@s/q", "3.0.0", ""),
            Some(keys[2].as_str())
        );
        // Another version's tarball, or another package's, is no match.
        assert_eq!(patched_dependency_key(&keys, "plainpkg", "1.0.1", ""), None);
        assert_eq!(patched_dependency_key(&keys, "p", "2.0.0", ""), None);
        assert_eq!(patched_dependency_key(&keys, "@s/p", "2.0.0-0", ""), None);
        // A run that keeps the package on the keyed resolution drops
        // nothing.
        let target = "https://patch.socket.dev/patch/npm/plainpkg/1.0.0/tok/u1/plainpkg-1.0.0.tgz";
        assert_eq!(
            patched_dependency_key(&keys, "plainpkg", "1.0.0", target),
            None
        );
        // Only tarball keys the lock still holds are live.
        let mut with_registry = keys.clone();
        with_registry.push("left-pad@1.3.0".into());
        let live = live_resolution_keys(&with_registry, [keys[1].as_str(), "left-pad@1.3.0"]);
        assert_eq!(live.into_iter().collect::<Vec<_>>(), vec![keys[1].clone()]);
        // The refusal names the resolution Bun applies the patch to.
        let detail = patched_dependency_detail(&keys[1], "@s/p", "2.0.0");
        assert!(
            detail.contains("resolves to .socket/vendor/npm/u1/@s/p-2.0.0.tgz"),
            "{detail}"
        );
        let registry = patched_dependency_detail("@s/p@2.0.0", "@s/p", "2.0.0");
        assert!(
            registry.contains("only to the registry @s/p@2.0.0,"),
            "{registry}"
        );
    }

    /// #367: the keys come from the manifest and from the lock's mirror,
    /// and match the exact `name@version` (scoped too) or a bare name.
    #[test]
    fn patched_dependency_keys_read_manifest_and_lock() {
        let manifest = r#"{"name":"app","patchedDependencies":{"left-pad@1.3.0":"patches/left-pad@1.3.0.patch"}}"#;
        let lock = "{\r\n  \"lockfileVersion\": 1,\r\n  \"patchedDependencies\": {\r\n    \"@s/p@2.0.0\": \"patches/@s%2Fp@2.0.0.patch\",\r\n    \"left-pad@1.3.0\": \"patches/left-pad@1.3.0.patch\",\r\n  },\r\n  \"packages\": {\r\n    \"x@1.0.0\": \"not a key\",\r\n  }\r\n}\r\n";
        let keys = patched_dependency_keys(Some(manifest), Some(lock));
        assert_eq!(keys, vec!["left-pad@1.3.0", "@s/p@2.0.0"]);
        assert_eq!(
            patched_dependency_key(&keys, "left-pad", "1.3.0", ""),
            Some("left-pad@1.3.0")
        );
        assert_eq!(
            patched_dependency_key(&keys, "@s/p", "2.0.0", ""),
            Some("@s/p@2.0.0")
        );
        assert_eq!(patched_dependency_key(&keys, "left-pad", "1.3.1", ""), None);
        assert_eq!(patched_dependency_key(&keys, "x", "1.0.0", ""), None);
        let bare = vec!["left-pad".to_string()];
        assert_eq!(
            patched_dependency_key(&bare, "left-pad", "1.3.0", ""),
            Some("left-pad")
        );
        assert!(patched_dependency_keys(Some("not json"), None).is_empty());
        // Bun reads a JSONC manifest: comments and trailing commas, with
        // the same characters inside strings left alone.
        let jsonc = "{\n  // a comment, \"x\": 1\n  \"name\": \"a//b /* c */\",\n  /* block\n  */\n  \"patchedDependencies\": {\n    \"left-pad@1.3.0\": \"patches/x,}.patch\",\n  },\n}\n";
        assert_eq!(
            patched_dependency_keys(Some(jsonc), None),
            vec!["left-pad@1.3.0"]
        );
        // A Windows-saved manifest leads with a UTF-8 BOM, which Bun skips.
        assert_eq!(
            patched_dependency_keys(Some(&format!("\u{feff}{jsonc}")), None),
            vec!["left-pad@1.3.0"]
        );
        let stripped: serde_json::Value = serde_json::from_str(&strip_jsonc(jsonc)).unwrap();
        assert_eq!(stripped["name"], "a//b /* c */");
        assert_eq!(
            stripped["patchedDependencies"]["left-pad@1.3.0"],
            "patches/x,}.patch"
        );
        assert!(patched_dependency_keys(Some(r#"{"patchedDependencies":[]}"#), None).is_empty());
        assert!(patched_dependency_keys(None, None).is_empty());
    }

    /// The `bundled` meta flag, in the shapes real Bun 1.3.14 writes, the
    /// rewritten tarball tuple, and a meta that is not plain JSON.
    #[test]
    fn bundled_meta_flag_is_detected() {
        let bundled = |line: &str| declares_bundled(&parse_entry_line(line).unwrap());
        assert!(bundled(
            r#"    "@bh/bund/is-number": ["is-number@7.0.0", "", { "bundled": true }, "sha512-X=="],"#
        ));
        assert!(bundled(
            r#"    "p/is-number": ["is-number@https://p.test/is-number-7.0.0.tgz", { "bundled": true }, "sha512-X=="],"#
        ));
        assert!(bundled(
            r#"    "p/q": ["q@1.0.0", "", { "bundled": true, }, "sha512-X=="],"#
        ));
        assert!(!bundled(r#"    "q": ["q@1.0.0", "", {}, "sha512-X=="],"#));
        assert!(!bundled(
            r#"    "q": ["q@1.0.0", "", { "dependencies": { "bundled": "1.0.0" } }, "sha512-X=="],"#
        ));
        assert!(!bundled(
            r#"    "q": ["q@1.0.0", "", { "bundled": false }, "sha512-X=="],"#
        ));
    }

    /// The package list is the root object's `"packages"` key. The same
    /// text inside a comment, or under another key, is not what Bun reads:
    /// a decoy placed ahead of the real section (holding a Socket-wired
    /// entry while the real one stays on the registry) must not be the
    /// section that is parsed, attested or rewired.
    #[test]
    fn only_the_root_objects_packages_key_is_the_package_list() {
        let real = "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-REAL==\"],";
        let decoy = "    \"left-pad\": [\"left-pad@https://patch.socket.dev/x/left-pad-1.3.0.tgz\", {}, \"sha512-DECOY==\"],";
        let lock = |head: &[&str]| -> Vec<String> {
            let mut lines = vec!["{", "  \"lockfileVersion\": 2,"];
            lines.extend_from_slice(head);
            lines.extend_from_slice(&["  \"packages\": {", real, "  }", "}", ""]);
            lines.into_iter().map(str::to_string).collect()
        };
        let specs = |lines: &[String]| -> Vec<String> {
            parse_packages_section(lines)
                .unwrap()
                .iter()
                .map(|e| decode_json_string(&e.elems[0]).unwrap())
                .collect()
        };
        for head in [
            // A block comment holding a whole decoy section.
            &["  /*", "  \"packages\": {", decoy, "  }", "  */"][..],
            // The same on one opening line, and closed mid-line.
            &["  /* x", "  \"packages\": {", decoy, "  } */"][..],
            // Under another top-level key, indented like a top-level key.
            &[
                "  \"x-decoy\": {",
                "  \"packages\": {",
                decoy,
                "  }",
                "  },",
            ][..],
            // Comment markers inside a string are content.
            &["  \"note\": \"/* not a comment\","][..],
            &["  \"url\": \"https://example.test/a\","][..],
            // A line comment mentioning a brace.
            &["  // {{{"][..],
            // The plain head.
            &[][..],
        ] {
            let lines = lock(head);
            assert_eq!(specs(&lines), ["left-pad@1.3.0"], "{head:?}");
        }
        // Two top-level keys: the first, as Bun reads it.
        let twice: Vec<String> = [
            "{",
            "  \"lockfileVersion\": 2,",
            "  \"packages\": {",
            real,
            "  },",
            "  \"packages\": {",
            decoy,
            "  }",
            "}",
        ]
        .iter()
        .map(|l| l.to_string())
        .collect();
        assert_eq!(specs(&twice), ["left-pad@1.3.0"]);
        // No real section at all: refused, not read as an empty lock.
        let only_decoy: Vec<String> = ["{", "  /*", "  \"packages\": {", decoy, "  }", "  */", "}"]
            .iter()
            .map(|l| l.to_string())
            .collect();
        let err = parse_packages_section(&only_decoy)
            .err()
            .expect("a lock whose only section is a decoy is refused");
        assert!(
            err.contains("inside a comment or under another key"),
            "{err}"
        );
    }

    /// A lock section with the given entry lines, parsed whole.
    fn section(entry_lines: &[&str]) -> Vec<BunEntry> {
        let mut lines = vec!["{".to_string(), "  \"packages\": {".to_string()];
        lines.extend(entry_lines.iter().map(|l| format!("    {l},")));
        lines.extend(["  }".to_string(), "}".to_string()]);
        parse_packages_section(&lines).unwrap()
    }

    fn bundled_copies(entries: &[BunEntry]) -> Vec<&str> {
        entries
            .iter()
            .filter(|e| is_bundled_entry(e))
            .map(|e| e.key.as_str())
            .collect()
    }

    #[test]
    fn key_segments_keep_scoped_names_whole() {
        assert_eq!(key_segments("a"), ["a"]);
        assert_eq!(key_segments("a/b/c"), ["a", "b", "c"]);
        assert_eq!(key_segments("@s/a"), ["@s/a"]);
        assert_eq!(key_segments("@s/a/@t/b/c"), ["@s/a", "@t/b", "c"]);
        assert_eq!(key_segments("a/@t/b"), ["a", "@t/b"]);
        assert!(key_segments("").is_empty());
    }

    /// Bun flags only the names in a parent's `bundleDependencies`; the
    /// copies' own dependencies are written as ordinary nested entries it
    /// never installs. An entry is in a bundled copy when it is flagged, or
    /// nested and depended on only by bundled copies (cycles included), or
    /// stored under one. A nested entry the parent itself or any other
    /// installed entry needs, and every top-level entry, stays installable.
    #[test]
    fn dependencies_of_bundled_copies_are_bundled_copies() {
        let entries = section(&[
            r#""app-dep": ["app-dep@1.0.0", "", { "dependencies": { "shared": "^1.0.0" } }, "sha512-A=="]"#,
            r#""bundler": ["bundler@1.0.0", "", { "dependencies": { "inner": "^1.0.0", "plain": "^2.0.0" } }, "sha512-A=="]"#,
            r#""bundler/both": ["both@1.0.0", "", { "dependencies": { "leaf": "^1.0.0" } }, "sha512-A=="]"#,
            r#""bundler/both/leaf": ["leaf@1.0.0", "", {}, "sha512-A=="]"#,
            r#""bundler/cyc": ["cyc@1.0.0", "", { "dependencies": { "deep": "^1.0.0" } }, "sha512-A=="]"#,
            r#""bundler/deep": ["deep@1.0.0", "", { "dependencies": { "cyc": "^1.0.0" } }, "sha512-A=="]"#,
            r#""bundler/inner": ["inner@1.0.0", "", { "dependencies": { "both": "^1.0.0", "deep": "^1.0.0", "shared": "^2.0.0", "top-only": "^1.0.0" }, "bundled": true }, "sha512-A=="]"#,
            r#""bundler/inner/own": ["own@1.0.0", "", {}, "sha512-A=="]"#,
            r#""bundler/plain": ["plain@2.0.0", "", { "dependencies": { "both": "^1.0.0" } }, "sha512-A=="]"#,
            r#""bundler/shared": ["shared@2.0.0", "", { "optionalDependencies": { "@s/opt": "^1.0.0" } }, "sha512-A=="]"#,
            r#""bundler/@s/opt": ["@s/opt@1.0.0", "", {}, "sha512-A=="]"#,
            r#""plain": ["plain@1.0.0", "", {}, "sha512-A=="]"#,
            r#""shared": ["shared@1.0.0", "", {}, "sha512-A=="]"#,
            r#""top-only": ["top-only@1.0.0", "", {}, "sha512-A=="]"#,
            r#""ws": ["ws@workspace:packages/ws"]"#,
            r#""ws/tool": ["tool@1.0.0", "", {}, "sha512-A=="]"#,
        ]);
        assert_eq!(
            bundled_copies(&entries),
            [
                "bundler/cyc",
                "bundler/deep",
                "bundler/inner",
                "bundler/inner/own",
                "bundler/shared",
                "bundler/@s/opt",
            ],
            "`bundler/plain` is the parent's own nested dependency, `bundler/both` is \
             also needed by it, `bundler/both/leaf` follows `both`, and `top-only` is \
             top-level, where the project's manifests may depend on it"
        );
    }

    /// Real Bun 1.4.4 lock of a project depending on `fsevents@1.2.9`,
    /// whose tarball bundles `node-pre-gyp` and its whole dependency tree.
    /// Bun flags `fsevents/node-pre-gyp` alone, writes 72 more entries for
    /// that tree, and installs none of the 73: an empty cache ends up
    /// holding `fsevents` and `nan` only (the tree's on-disk versions are
    /// the tarball's — `minimist` 0.0.8 where the lock says 1.2.8).
    #[test]
    fn real_capture_marks_the_whole_bundled_tree() {
        let lock = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/bun-lock-bundled/transitive/bun.lock"),
        )
        .unwrap();
        let lines: Vec<String> = lock.lines().map(str::to_string).collect();
        let entries = parse_packages_section(&lines).unwrap();
        assert_eq!(entries.len(), 75);
        let flagged: Vec<&str> = entries
            .iter()
            .filter(|e| declares_bundled(e))
            .map(|e| e.key.as_str())
            .collect();
        assert_eq!(flagged, ["fsevents/node-pre-gyp"]);
        let installed: Vec<&str> = entries
            .iter()
            .filter(|e| !is_bundled_entry(e))
            .map(|e| e.key.as_str())
            .collect();
        assert_eq!(installed, ["fsevents", "nan"]);
        let minimist = entries
            .iter()
            .find(|e| e.key == "fsevents/minimist")
            .unwrap();
        assert!(is_bundled_entry(minimist) && !declares_bundled(minimist));
    }

    /// Without a flagged entry nothing is inferred and no meta is parsed;
    /// with a meta that is not JSON only the flagged entries count.
    #[test]
    fn bundled_copies_need_a_flag_and_readable_metas() {
        let plain = section(&[
            r#""a": ["a@1.0.0", "", { "dependencies": { "b": "^1.0.0" } }, "sha512-A=="]"#,
            r#""a/b": ["b@1.0.0", "", {}, "sha512-A=="]"#,
        ]);
        BUNDLED_CHECKS.with(|checks| checks.set(0));
        let again = section(&[
            r#""a": ["a@1.0.0", "", { "dependencies": { "b": "^1.0.0" } }, "sha512-A=="]"#,
            r#""a/b": ["b@1.0.0", "", {}, "sha512-A=="]"#,
        ]);
        assert_eq!(BUNDLED_CHECKS.with(std::cell::Cell::get), 0);
        assert!(bundled_copies(&plain).is_empty() && bundled_copies(&again).is_empty());

        let unreadable = section(&[
            r#""a": ["a@1.0.0", "", { "dependencies": { "b": "^1.0.0" } }, "sha512-A=="]"#,
            r#""a/b": ["b@1.0.0", "", { "dependencies": { "c": "^1.0.0" }, "bundled": true }, "sha512-A=="]"#,
            r#""a/c": ["c@1.0.0", "", { "dependencies": { "d": , } }, "sha512-A=="]"#,
        ]);
        assert_eq!(bundled_copies(&unreadable), ["a/b"]);
    }

    /// The substring fast path (#580) never changes the answer: a meta that
    /// never spells `bundled` is not bundled, a malformed meta that does
    /// still fails closed, and a JSON-escaped key still takes the parse.
    #[test]
    fn bundled_fast_path_matches_the_full_parse() {
        let bundled = |line: &str| declares_bundled(&parse_entry_line(line).unwrap());
        assert!(!bundled(
            r#"    "q": ["q@1.0.0", "", { "dependencies": { "a": "1" } }, "sha512-X=="],"#
        ));
        assert!(!bundled(
            r#"    "q": ["q@1.0.0", "", { "x": , }, "sha512-X=="],"#
        ));
        assert!(bundled(
            r#"    "q": ["q@1.0.0", "", { "bundled": true, "x": , }, "sha512-X=="],"#
        ));
        assert!(bundled(
            r#"    "q": ["q@1.0.0", "", { "bundl\u0065d": true }, "sha512-X=="],"#
        ));
    }

    #[test]
    fn line_grammar_parses_the_fixture_shapes() {
        // Registry 4-tuple with deps and trailing comma.
        let e = parse_entry_line(
            r#"    "haspad/left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI=="],"#,
        )
        .unwrap();
        assert_eq!(e.key, "haspad/left-pad");
        assert_eq!(e.key_raw, "\"haspad/left-pad\"");
        assert_eq!(e.indent, "    ");
        assert!(e.trailing_comma);
        assert_eq!(
            e.elems,
            vec!["\"left-pad@1.3.0\"", "\"\"", "{}", "\"sha512-XI==\""]
        );

        // Local 3-tuple with a deps object containing commas + brackets.
        let e = parse_entry_line(
            r#"    "haspad": ["haspad@./h.tgz", { "dependencies": { "a": "^1", "b": "[2]" } }, "sha512-C=="]"#,
        )
        .unwrap();
        assert_eq!(e.elems.len(), 3);
        assert_eq!(
            e.elems[1],
            r#"{ "dependencies": { "a": "^1", "b": "[2]" } }"#
        );
        assert!(!e.trailing_comma);

        // split at the FIRST @ past index 0 (a scoped name's @ is at index 0;
        // the spec may contain more @s).
        assert_eq!(
            split_name_spec("@scope/pkg@1.0.0"),
            Some(("@scope/pkg", "1.0.0"))
        );
        assert_eq!(
            split_name_spec("left-pad@.socket/x.tgz"),
            Some(("left-pad", ".socket/x.tgz"))
        );
        assert_eq!(
            split_name_spec("@scope/pkg"),
            None,
            "a scope @ alone is not a version sep"
        );
        assert_eq!(
            split_name_spec("@scope/pkg@.socket/vendor/npm/u/@scope/pkg-1.0.0.tgz"),
            Some(("@scope/pkg", ".socket/vendor/npm/u/@scope/pkg-1.0.0.tgz")),
            "an @ inside the spec (scoped vendored leaf) must not shift the split"
        );

        // Fail-closed grammar.
        assert!(
            parse_entry_line("    \"k\": [\"a\", ").is_err(),
            "unterminated"
        );
        assert!(
            parse_entry_line(r#"    "k": ["a"},"#).is_err(),
            "array closed by `}}` must not parse"
        );
        assert!(
            parse_entry_line(r#"    "k": ["a", {"x": 1]],"#).is_err(),
            "object closed by `]` must not parse"
        );
        assert!(
            parse_entry_line(r#"    "k": ["a", [1}]"#).is_err(),
            "nested array closed by `}}` must not parse"
        );
        assert!(parse_entry_line("    k: [\"a\"]").is_err(), "unquoted key");
        assert!(parse_entry_line("    \"k\": \"not an array\"").is_err());
        assert!(
            parse_entry_line("    \"k\": [\"a\"], junk").is_err(),
            "trailing junk"
        );
    }

    /// The fail-closed refusals bun never emits (empty tuple, empty element,
    /// a line whose only quote is the opener) plus the escape-aware paths of
    /// the scanners: an escaped quote in the KEY, a backslash escape inside
    /// an ELEMENT string (verbatim round-trip), and decode_json_string's
    /// None arm — load-bearing for the callers that classify tuple shapes by
    /// `decode_json_string(&elems[1]).is_some()` where elems[1] is a `{...}`
    /// deps object.
    #[test]
    fn grammar_edge_cases_fail_closed_and_escapes_parse() {
        // BunEntry has no Debug impl (deliberately — never touched here), so
        // extract the error side without `unwrap_err`.
        let err_of = |line: &str| parse_entry_line(line).err().expect("expected an error");

        // Empty tuple: bun never emits `[]` — the guard must refuse it.
        assert_eq!(err_of(r#"    "k": [],"#), "empty tuple");

        // Empty tuple elements from a hand-mangled lock (double / leading
        // comma) fail closed rather than parse as fewer elements.
        assert_eq!(err_of(r#"    "k": ["a", , "b"],"#), "empty tuple element");
        assert_eq!(err_of(r#"    "k": [, "a"]"#), "empty tuple element");

        // A truncated line whose only quote is the opening one: the string
        // scanner itself must report the unterminated STRING (the existing
        // `["a", ` fixture only ever hits the unterminated-ARRAY arm).
        assert_eq!(err_of("    \"key"), "unterminated string");
        // A lone backslash at end-of-line: the escape skip steps past the
        // end and must fall through to the same error, not panic.
        assert_eq!(err_of("    \"k\\"), "unterminated string");

        // Escaped quote in the key: decoded key vs verbatim key_raw.
        let e = parse_entry_line(r#"    "k\"x": ["a@1.0.0", "", {}, "sha512-Y=="],"#).unwrap();
        assert_eq!(e.key, "k\"x", "key decodes the escape");
        assert_eq!(e.key_raw, r#""k\"x""#, "key_raw keeps the escape verbatim");
        assert_eq!(e.elems.len(), 4);

        // Backslash escape inside an ELEMENT string round-trips verbatim
        // (elements are re-emitted, never decoded).
        let e = parse_entry_line(r#"    "k": ["a\\b@1.0.0", "", {}, "sha512-Y=="]"#).unwrap();
        assert_eq!(e.elems[0], r#""a\\b@1.0.0""#);

        // decode_json_string: None for any non-string token — the negative
        // side of the registry-4-tuple classifiers — Some for a real string.
        assert_eq!(decode_json_string("{}"), None);
        assert_eq!(decode_json_string("123"), None);
        assert_eq!(decode_json_string(""), None);
        assert_eq!(decode_json_string(r#""a\"b""#), Some("a\"b".to_string()));

        // A stray closer at top level inside a tuple interior is unbalanced.
        assert_eq!(
            split_top_level(r#""a"]"#).unwrap_err(),
            "unbalanced brackets"
        );
    }

    /// A nested ARRAY element (commas and all) must survive the top-level
    /// split as ONE verbatim element — the fixtures only ever nest objects.
    #[test]
    fn nested_array_element_splits_at_top_level() {
        let e = parse_entry_line(r#"    "k": ["a@1.0.0", ["x", "y"], "z"],"#).unwrap();
        assert_eq!(
            e.elems,
            vec![r#""a@1.0.0""#, r#"["x", "y"]"#, r#""z""#],
            "the nested array's comma must not split it"
        );
        assert!(e.trailing_comma);

        // A comma inside a string inside the nested array doesn't split
        // either level.
        let e = parse_entry_line(r#"    "k": [["a,b"], "c"]"#).unwrap();
        assert_eq!(e.elems, vec![r#"["a,b"]"#, r#""c""#]);
        assert!(!e.trailing_comma);
    }

    fn to_lines(text: &str) -> Vec<String> {
        text.split('\n').map(str::to_string).collect()
    }

    /// A `"packages"` header spelled any way other than bun's byte-exact
    /// emitted shape must parse as an ERROR (fail closed), never as an empty
    /// lock — "empty" would make the rewriters silently skip locks bun itself
    /// parses fine.
    #[test]
    fn noncanonical_packages_header_is_an_error_not_empty() {
        let entry = r#""left-pad": ["left-pad@1.3.0", "", {}, "sha512-X=="],"#;
        for lock in [
            format!("{{\n  \"lockfileVersion\": 1,\n\t\"packages\": {{\n    {entry}\n\t}}\n}}\n"),
            format!(
                "{{\n  \"lockfileVersion\": 1,\n    \"packages\": {{\n    {entry}\n    }}\n}}\n"
            ),
            format!("{{\n  \"lockfileVersion\": 1,\n  \"packages\" : {{\n    {entry}\n  }}\n}}\n"),
        ] {
            assert!(
                parse_packages_section(&to_lines(&lock)).is_err(),
                "must fail closed, not read as empty: {lock}"
            );
        }

        // Truly absent packages section: an empty lock, no error.
        let empty = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n  }\n}\n";
        assert!(parse_packages_section(&to_lines(empty)).unwrap().is_empty());

        // A dependency literally named "packages" in another section must not
        // trip the fail-closed header detection (its value is a string, not
        // an object opener).
        let dep_named_packages = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \
                                  \"\": {\n      \"dependencies\": {\n        \
                                  \"packages\": \"^1.0.0\",\n      },\n    },\n  }\n}\n";
        assert!(parse_packages_section(&to_lines(dep_named_packages))
            .unwrap()
            .is_empty());

        // The canonical-but-unterminated case still errors.
        let unterminated = "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n";
        assert!(parse_packages_section(&to_lines(unterminated)).is_err());
    }

    /// bun 1.3 emits `"lockfileVersion": 1`; bun 1.4 emits 2 over the SAME
    /// grammar (the bump gates stricter parse checks, not new entry shapes —
    /// same-fixture locks are byte-identical except the integer), and 3 when
    /// the manifest has a nested override or a path resolution (the head's
    /// `overrides` then nests; the `packages` grammar is unchanged). All
    /// must pass; anything else — or a missing/non-integer head — fails
    /// closed.
    #[test]
    fn lock_version_gate_accepts_0_to_3_only() {
        for v in [0u64, 1, 2, 3] {
            assert!(
                check_lock_version(&format!("{{\n  \"lockfileVersion\": {v},\n}}\n")).is_ok(),
                "lockfileVersion {v} must be accepted"
            );
        }
        // Every unsupported integer is ≥ 4, i.e. written by a Bun NEWER than
        // this release tests: the remedy must be "update socket-patch" (or
        // downgrade the writer) — never "re-lock with a newer Bun", which
        // would reproduce the same head.
        for v in [4u64, 99] {
            let err =
                check_lock_version(&format!("{{\n  \"lockfileVersion\": {v},\n}}\n")).unwrap_err();
            assert!(
                err.contains(&format!(
                    "lockfileVersion {v}, newer than this socket-patch release"
                )) && err.contains("(0 to 3)")
                    && err.contains("update socket-patch")
                    && err.contains("re-lock with a Bun release that writes lockfileVersion 0–3"),
                "the refusal must name the found version and a remedy that can work: {err}"
            );
            assert!(
                !err.contains(">= 1.4"),
                "a future-version refusal must not tell the user to re-lock with the Bun that \
                 wrote it: {err}"
            );
        }
        // Missing / non-integer / string-typed heads fail closed too — and
        // THIS is the arm where a plain re-lock with a current Bun is the fix.
        for head in [
            "{\n  \"packages\": {\n  }\n}\n",
            "{\n  \"lockfileVersion\": \"1\",\n}\n",
            "{\n  \"lockfileVersion\": one,\n}\n",
        ] {
            let err = check_lock_version(head).unwrap_err();
            assert!(
                err.contains("no integer lockfileVersion")
                    && err.contains("only 0 to 3 are supported")
                    && err.contains("re-lock with Bun ≥ 1.2 (`bun install`)"),
                "a head without an integer version must point at a Bun re-lock: {err}"
            );
        }
    }

    /// The lock Bun 1.4.2 writes when it migrates a hosted workspace
    /// `bun.lockb` to text (#803): the inter-workspace literals are the
    /// member paths the binary normalization interned.
    const MIGRATED_WORKSPACE_LOCK: &str = r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "w",
      "dependencies": {
        "m1": "packages/m1",
      },
    },
    "packages/m1": {
      "name": "m1",
      "version": "1.0.0",
      "dependencies": {
        "is-number": "7.0.0",
        "m2": "packages/m2",
      },
      "devDependencies": {
        "gh": "packages/m2",
      },
    },
    "packages/m2": {
      "name": "m2",
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "is-number": ["is-number@https://patches.example/tok/is-number-7.0.0.tgz", {}, "sha512-AAAA"],

    "m1": ["m1@workspace:packages/m1"],

    "m2": ["m2@workspace:packages/m2"],
  }
}
"#;

    fn migrated_manifests(dir: &str) -> Option<String> {
        Some(
            match dir {
                "" => r#"{"name":"w","workspaces":["packages/*"],"dependencies":{"m1":"workspace:*"}}"#,
                "packages/m1" => {
                    r#"{"name":"m1","dependencies":{"is-number":"7.0.0","m2":"workspace:^"},"devDependencies":{"gh":"packages/m2"}}"#
                }
                "packages/m2" => r#"{"name":"m2","dependencies":{"left-pad":"1.3.0"}}"#,
                _ => return None,
            }
            .to_string(),
        )
    }

    #[test]
    fn workspace_path_literals_heal_back_to_the_manifest_literal() {
        let mut lines = to_lines(MIGRATED_WORKSPACE_LOCK);
        assert_eq!(
            workspace_member_dirs(&lines),
            ["", "packages/m1", "packages/m2"]
        );
        let heals = heal_workspace_literals(&mut lines, migrated_manifests);
        let keys: Vec<&str> = heals.iter().map(|h| h.key.as_str()).collect();
        assert_eq!(keys, [":dependencies:m1", "packages/m1:dependencies:m2"]);
        let healed = lines.join("\n");
        // Exactly what Bun writes for the manifests: `workspace:*` and
        // `workspace:^` restored, everything else byte-identical.
        let expected = MIGRATED_WORKSPACE_LOCK
            .replace(r#""m1": "packages/m1","#, r#""m1": "workspace:*","#)
            .replace(r#""m2": "packages/m2","#, r#""m2": "workspace:^","#);
        assert_eq!(healed, expected);
        assert_eq!(heals[0].original, r#"        "m1": "packages/m1","#);
        assert_eq!(heals[0].new, r#"        "m1": "workspace:*","#);
        // Converged: a second pass finds nothing.
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
    }

    #[test]
    fn workspace_literal_heal_keeps_crlf_and_fails_closed() {
        // CRLF: the `\r` stays on the healed line.
        let mut lines = to_lines(&MIGRATED_WORKSPACE_LOCK.replace('\n', "\r\n"));
        let heals = heal_workspace_literals(&mut lines, migrated_manifests);
        assert_eq!(heals.len(), 2);
        assert_eq!(heals[0].new, "        \"m1\": \"workspace:*\",\r");
        // No readable manifest, or a manifest that does not spell the
        // dependency `workspace:`: the literal is left alone.
        let mut lines = to_lines(MIGRATED_WORKSPACE_LOCK);
        assert!(heal_workspace_literals(&mut lines, |_| None).is_empty());
        assert!(heal_workspace_literals(&mut lines, |_| Some("{".into())).is_empty());
        assert_eq!(lines.join("\n"), MIGRATED_WORKSPACE_LOCK);
        // A section not in bun's emitted shape is never touched.
        let reindented =
            MIGRATED_WORKSPACE_LOCK.replace("    \"packages/m1\": {", "   \"packages/m1\": {");
        let mut lines = to_lines(&reindented);
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
        assert!(workspace_member_dirs(&lines).is_empty());
        assert_eq!(lines.join("\n"), reindented);
        // A version-0 lock spells the literal as a path itself.
        let v0 = MIGRATED_WORKSPACE_LOCK
            .replace("\"lockfileVersion\": 2,", "\"lockfileVersion\": 0,")
            .replace("  \"configVersion\": 1,\n", "");
        let mut lines = to_lines(&v0);
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
        // A member dir that leaves the project is never read.
        assert!(is_plain_member_dir("") && is_plain_member_dir("packages/m1"));
        for dir in [
            "../m1",
            "/abs/m1",
            "C:/m1",
            "packages/../../m1",
            "packages\\m1",
            "./m1",
        ] {
            assert!(!is_plain_member_dir(dir), "{dir}");
        }
        // No `workspaces` section at all.
        let mut lines = to_lines("{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n  }\n}\n");
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
    }
}
