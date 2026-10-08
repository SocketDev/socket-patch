//! `pnpm-lock.yaml` in every generation (pnpm <= 2's `shrinkwrap.yaml`,
//! lockfile 5.x block resolutions, 5.4 / 6.0 / 9.0 flow resolutions) and
//! Rush's nested pnpm locks: the ONE model of the format.
//!
//! [`PnpmLock`] parses a lock text once and answers every question the
//! modes ask of it:
//!
//! * [`PnpmLock::entries`] — the registry inventory (`scan` / `get`
//!   lockfile supplements, `vendor`'s pristine fetch);
//! * [`PnpmLock::resolves`] — whether the lock resolves a `name@version`
//!   at all (`get`'s installed-version narrowing under pnpm PnP);
//! * [`PnpmLock::wired_refs`] — every entry whose resolution names a
//!   tarball, the raw material lockfile discovery (`vex::discover::npm`)
//!   classifies as hosted / vendored refs, and [`PnpmLock::wired_integrity`]
//!   repair's trust anchor for a vendored artifact;
//! * [`PnpmLock::vendored_in_use`] — whether a vendored artifact is still
//!   consumed (both vendored backends' revert guards and ledger liveness);
//! * [`plan_hosted`] — the hosted planner (the redirect rewriter's pnpm
//!   leg: resolution splices over the whole lock set);
//! * the vendored planners (`vendor::pnpm_lock` for lockfileVersion 9.0,
//!   `vendor::pnpm_lock_legacy` for 5.4 / 6.0) splice with [`lines`] and
//!   route on [`sniff_lock_grammar`];
//!
//! Everything here is pure (text in, answers out); the callers own the
//! reads.

pub(crate) mod grammar;
pub(crate) mod hosted;
pub(crate) mod lines;
pub(crate) mod workspace;

pub(crate) use grammar::{
    entry_bundled, entry_field, is_pnpm_lock_text, Bundled, Entry, Resolution,
};
pub(crate) use hosted::plan_hosted;

use std::collections::HashSet;

use crate::constants::npm_family::PNPM_LOCK;
use crate::formats::text::strip_bom;
use crate::utils::digest::is_sri_pin;
use crate::vendor::lock_inventory::{http_url, LockIntegrity, LockfileEntry};
use crate::vendor::path::parse_vendor_path;

// ── entry model ──

/// One `packages:` entry of a pnpm lock, read with the entry grammar
/// ([`grammar::entries`] / [`grammar::resolution`]: two-space keys, a flat
/// flow or block `resolution:` map, CRLF included).
pub(crate) struct PnpmPackage<'a> {
    /// The packages key, trimmed and unquoted.
    pub(crate) key: &'a str,
    pub(crate) entry: Entry<'a>,
    /// The entry's `resolution:` map; `None` when it has none or the
    /// grammar refuses it (duplicate keys, nested values, aliases).
    pub(crate) resolution: Option<Resolution<'a>>,
}

impl<'a> PnpmPackage<'a> {
    /// The unquoted tokens of the entry's raw `resolution:` text
    /// ([`grammar::resolution_raw_lines`] split on whitespace and flow
    /// punctuation) — what a reader inspects when the grammar refused the
    /// map (`resolution` is `None`) and it must still tell a Socket-shaped
    /// value from anything else.
    pub(crate) fn resolution_tokens(&self) -> Vec<&'a str> {
        grammar::resolution_raw_lines(&self.entry)
            .into_iter()
            .flat_map(|text| {
                text.split(|c: char| c.is_whitespace() || matches!(c, ',' | '{' | '}' | '[' | ']'))
            })
            .map(|token| grammar::unquote(token.trim()))
            .filter(|token| !token.is_empty())
            .collect()
    }
}

/// Every `packages:` entry of a pnpm lock text, in lock order — the ONE
/// entry walk the inventory, lockfile discovery and repair share. Every
/// entry is returned (registry, rekeyed vendored, hosted, directory, git);
/// each consumer applies its own key and resolution rules.
pub(crate) fn pnpm_packages(text: &str) -> Vec<PnpmPackage<'_>> {
    grammar::entries(text)
        .into_iter()
        .map(|entry| PnpmPackage {
            key: grammar::unquote(entry.key.trim()),
            resolution: grammar::resolution(&entry),
            entry,
        })
        .collect()
}

/// The `(integrity, tarball)` of one recorded `packages:` block — a
/// vendored planner's wiring fragment (its key line and body, as
/// recorded), each unquoted; `None` unless the fragment is exactly one
/// entry with a flat resolution.
pub(crate) fn fragment_resolution(block: &[String]) -> Option<(Option<String>, Option<String>)> {
    let text = format!("packages:\n{}\n", block.join("\n"));
    let packages = pnpm_packages(&text);
    let [package] = packages.as_slice() else {
        return None;
    };
    let resolution = package.resolution.as_ref()?;
    Some((
        resolution.integrity().map(str::to_string),
        resolution.tarball().map(str::to_string),
    ))
}

/// How a pnpm packages key names its package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PnpmKey<'a> {
    /// A registry key in any lock generation ([`pnpm_registry_key`]).
    Registry { name: &'a str, version: &'a str },
    /// v9's rekeyed vendored entry `name@file:<rel>` (`vendor::pnpm_lock`);
    /// `path` is the raw `file:<rel>` spec, peer suffix stripped.
    V9File { name: &'a str, path: &'a str },
    /// v5.4 / v6.0's rekeyed vendored entry, the bare `file:<rel>` key
    /// (`vendor::pnpm_lock_legacy`); the name is on the entry's `name:`
    /// line.
    LegacyFile { path: &'a str },
    /// Anything else (url, git, `link:`, v5 non-default-registry keys).
    Other,
}

/// Classify a packages key, in this order: a legacy `file:` key, a v9
/// `name@file:` key (the `@` after a scope's leading one), a registry key,
/// else [`PnpmKey::Other`]. The `file:` paths are returned raw — the CALLER
/// anchors them (lockfile discovery with its root-anchored `vendor_ref`,
/// the writers with `parse_vendor_path`).
pub(crate) fn classify_pnpm_key(key: &str) -> PnpmKey<'_> {
    let base = strip_pnpm_peer_suffix(key);
    if base.starts_with("file:") {
        PnpmKey::LegacyFile { path: base }
    } else if let Some(at) = base.get(1..).and_then(|rest| rest.find("@file:")) {
        PnpmKey::V9File {
            name: &base[..at + 1],
            path: &base[at + 2..],
        }
    } else {
        match pnpm_registry_key(base) {
            Some((name, version)) => PnpmKey::Registry { name, version },
            None => PnpmKey::Other,
        }
    }
}

/// The uuid of the `.socket/vendor/npm/<uuid>/` artifact a rekeyed
/// vendored key (v9 `name@file:<rel>` or legacy bare `file:<rel>`, in a
/// `packages:` or `snapshots:` section) resolves to.
pub(crate) fn vendored_npm_uuid(key: &str) -> Option<String> {
    let path = match classify_pnpm_key(key) {
        PnpmKey::V9File { path, .. } | PnpmKey::LegacyFile { path } => path,
        PnpmKey::Registry { .. } | PnpmKey::Other => return None,
    };
    parse_vendor_path(path)
        .filter(|parts| parts.eco == "npm")
        .map(|parts| parts.uuid)
}

/// A pnpm packages key without its v6+ peer suffix (`(peer@1.0.0)…`).
pub(crate) fn strip_pnpm_peer_suffix(key: &str) -> &str {
    key.find('(').map_or(key, |p| key[..p].trim_end())
}

/// `(name, version)` of a REGISTRY-form pnpm packages key, in every lock
/// generation's grammar — v9 `name@version`, v6 (pnpm 8) the same behind a
/// leading `/`, v5.4 (pnpm 7) and shrinkwrap `/name/version`; names may be
/// scoped in all of them. Peer suffixes are stripped: v6/v9 append
/// `(peer@1.2.3)…` after the version, v5 appends `_peer@x` / `_<hash>` to
/// the version itself. `None` for anything that is not a plain registry
/// version (digit-first): `file:` / `link:` / url / git keys and v5
/// non-default-registry keys. The ONE key rule every reader shares, so all
/// of them read a key as the same package.
pub(crate) fn pnpm_registry_key(key: &str) -> Option<(&str, &str)> {
    let base = strip_pnpm_peer_suffix(key);
    let (base, legacy) = match base.strip_prefix('/') {
        Some(stripped) => (stripped, true),
        None => (base, false),
    };
    let (name, version) = split_pnpm_key(base, legacy)?;
    let version = version.split('_').next().unwrap_or(version);
    version
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit())
        .then_some((name, version))
}

/// Split a peer-paren-stripped, slash-stripped pnpm packages key into
/// `(name, version)`; `None` is skipped by the caller, never guessed.
/// `legacy` marks a key that carried the v5/v6 leading `/` — only those may
/// use the v5 `name/version` grammar. What tells v5 `/@scope/name/1.2.3`
/// apart from v6 `/@scope/name@1.2.3` is the segment after the last `/`:
/// a v5 version (its `_peer`/`_hash` suffix dropped) starts with a digit
/// and never contains `@`, while a v6 scoped key's trailing segment is
/// `name@version`. v5 non-default-registry keys (`example.com/name/1.2.3`)
/// carry no leading `/` and fall through to the `@` split, where they are
/// dropped fail-closed downstream.
fn split_pnpm_key(base: &str, legacy: bool) -> Option<(&str, &str)> {
    if legacy {
        if let Some((name, rest)) = base.rsplit_once('/') {
            let version = rest.split('_').next().unwrap_or(rest);
            if !name.is_empty()
                && version.chars().next().is_some_and(|c| c.is_ascii_digit())
                && !version.contains('@')
            {
                return Some((name, version));
            }
        }
    }
    let at = base.rfind('@').filter(|&p| p > 0)?;
    Some((&base[..at], &base[at + 1..]))
}

// ── lock version ──

/// Which vendorable pnpm lock grammar a `pnpm-lock.yaml` head declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpmLockGrammar {
    /// `lockfileVersion: '9.0'` — the `vendor::pnpm_lock` backend.
    V9,
    /// `lockfileVersion: 5.4` (pnpm 7, bare float spelling).
    V54,
    /// `lockfileVersion: '6.0'` (pnpm 8).
    V60,
}

impl PnpmLockGrammar {
    /// Human name for diagnostics (`pnpm 7 (lockfileVersion 5.4)`).
    pub fn describe(self) -> &'static str {
        match self {
            PnpmLockGrammar::V9 => "pnpm >= 9 (lockfileVersion 9.0)",
            PnpmLockGrammar::V54 => "pnpm 7 (lockfileVersion 5.4)",
            PnpmLockGrammar::V60 => "pnpm 8 (lockfileVersion 6.0)",
        }
    }
}

/// The `lockfileVersion:` a lock head (its first five lines) declares,
/// unquoted. A leading BOM is encoding, not key text (#903).
fn head_lock_version(text: &str) -> Option<String> {
    strip_bom(text)
        .lines()
        .take(5)
        .find_map(|line| line.strip_prefix("lockfileVersion:"))
        .map(|rest| rest.trim().trim_matches(['\'', '"']).to_string())
}

/// The full vendor allowlist sniff (5.4 / 6.0 / 9.0) the flavor router
/// uses; anything else refuses with a version-aware remedy: pre-allowlist
/// versions (pnpm <= 6's 5.x line) are fixed by upgrading pnpm, but a
/// FUTURE version means the user's pnpm already outgrew this build —
/// looping them back to "re-lock with pnpm >= 9" would hand them the lock
/// they have.
pub fn sniff_lock_grammar(text: &str) -> Result<PnpmLockGrammar, String> {
    match head_lock_version(text).as_deref() {
        Some("9.0") => Ok(PnpmLockGrammar::V9),
        Some("5.4") => Ok(PnpmLockGrammar::V54),
        Some("6.0") => Ok(PnpmLockGrammar::V60),
        Some(v) => {
            let major = v.split('.').next().and_then(|m| m.parse::<u32>().ok());
            Err(match major {
                Some(m) if m < 9 => format!(
                    "{PNPM_LOCK} has lockfileVersion {v}; supported versions are 5.4 \
                     (pnpm 7), 6.0 (pnpm 8), and 9.0 (pnpm >= 9) — re-lock with pnpm >= 9"
                ),
                _ => format!(
                    "{PNPM_LOCK} has lockfileVersion {v}; this socket-patch build supports \
                     lockfileVersions 5.4, 6.0, and 9.0 — re-lock with a pnpm release that \
                     emits one of them, or update socket-patch"
                ),
            })
        }
        None => Err(format!(
            "{PNPM_LOCK} has no lockfileVersion in its head; supported versions are 5.4, \
             6.0, and 9.0 — re-lock with pnpm >= 9"
        )),
    }
}

/// The `(major, minor)` of every `lockfileVersion:` line of a lock (the
/// first one decides), unquoted; a missing minor reads as 0. A leading BOM
/// is encoding, not key text (#903).
fn lock_versions(text: &str) -> impl Iterator<Item = (Option<u32>, u32)> + '_ {
    strip_bom(text).lines().filter_map(|line| {
        let rest = line.strip_prefix("lockfileVersion:")?;
        let value = rest.trim().trim_matches(|c| c == '\'' || c == '"');
        let mut parts = value.split('.');
        let major = parts.next().and_then(|m| m.parse::<u32>().ok());
        let minor = parts
            .next()
            .and_then(|m| m.parse::<u32>().ok())
            .unwrap_or(0);
        Some((major, minor))
    })
}

/// `lockfileVersion` major of a pnpm lock. pnpm 9-12 emit
/// `lockfileVersion: '9.0'` (single doc, first line); pnpm 8 emits `'6.0'`,
/// pnpm 7 an unquoted `5.4`. `None` when no parseable version line exists —
/// the hosted trust-config gate treats that as "not trust-policy era" and
/// stays hands-off (fail closed: never write config for a lock it can't
/// read).
pub fn lock_version_major(text: &str) -> Option<u32> {
    lock_versions(text).find_map(|(major, _)| major)
}

/// Whether a pnpm lock may belong to pnpm 1–4, which spell the store flag
/// `--store` (pnpm 1–3 can silently ignore `--store-dir`; early pnpm 4
/// rejects it): a `shrinkwrapVersion` lock (pnpm 1–2) or lockfileVersion
/// 5.0–5.2 (pnpm 3–5). Later locks never get the `--store` note.
pub fn may_need_store_flag(text: &str) -> bool {
    is_shrinkwrap_lock(text)
        || lock_versions(text).any(|(major, minor)| major == Some(5) && minor <= 2)
}

/// Whether a pnpm lock is a pnpm 1–2 `shrinkwrapVersion:` lock (a leading
/// BOM skipped).
pub fn is_shrinkwrap_lock(text: &str) -> bool {
    strip_bom(text)
        .lines()
        .any(|line| line.starts_with("shrinkwrapVersion:"))
}

/// The lockfileVersion the v9 vendored planner splices.
const V9_LOCK_VERSION: &str = "9.0";

/// `lockfileVersion: '9.0'` head check (accept pnpm's single quotes plus
/// double-quoted/bare spellings) — the v9 vendored planner's own guard.
/// The flavor router sniffs with [`sniff_lock_grammar`] instead, whose
/// allowlist also routes the legacy 5.4/6.0 grammars to their planner;
/// this check only fires if a non-9.0 lock reaches the v9 planner directly.
pub(crate) fn check_v9_lock_version(text: &str) -> Result<(), String> {
    match head_lock_version(text) {
        Some(v) if v == V9_LOCK_VERSION => Ok(()),
        Some(v) => {
            // The remedy must point the right way: 5.x (pnpm 7) / 6.x
            // (pnpm 8) locks predate the v9 grammar and upgrading pnpm
            // re-locks them, but a HIGHER version means the user's pnpm
            // already outgrew this build — telling them "re-lock with
            // pnpm >= 9" would loop them back to the lock they have.
            let major = v.split('.').next().and_then(|m| m.parse::<u32>().ok());
            Err(match major {
                Some(m) if m < 9 => format!(
                    "{PNPM_LOCK} has lockfileVersion {v}; only {V9_LOCK_VERSION} is \
                     supported — re-lock with pnpm >= 9"
                ),
                _ => format!(
                    "{PNPM_LOCK} has lockfileVersion {v}; this socket-patch build supports \
                     lockfileVersion {V9_LOCK_VERSION} — re-lock with a pnpm release \
                     that emits it, or update socket-patch"
                ),
            })
        }
        None => Err(format!(
            "{PNPM_LOCK} has no lockfileVersion in its head; only \
             {V9_LOCK_VERSION} is supported — re-lock with pnpm >= 9"
        )),
    }
}

// ── the model ──

/// One pnpm lock, parsed once (see the module docs).
pub struct PnpmLock<'t> {
    text: &'t str,
    packages: Vec<PnpmPackage<'t>>,
    /// [`vendored_npm_uuids`] of the text.
    vendored: HashSet<String>,
}

/// One `packages:` entry whose resolution names a tarball — a candidate
/// hosted or vendored ref ([`PnpmLock::wired_refs`]).
pub(crate) struct PnpmTarballRef<'p> {
    pub(crate) tarball: &'p str,
    /// The resolution's `integrity`, unfiltered (a caller that needs an SRI
    /// pin checks it with `is_sri_pin`).
    pub(crate) integrity: Option<&'p str>,
}

impl<'t> PnpmLock<'t> {
    /// Parse a lock text (any content: a non-pnpm text has no entries).
    pub fn parse(text: &'t str) -> Self {
        PnpmLock {
            text,
            packages: pnpm_packages(text),
            vendored: vendored_npm_uuids(text),
        }
    }

    pub fn text(&self) -> &'t str {
        self.text
    }

    /// Whether the text is a pnpm lock at all ([`is_pnpm_lock_text`]).
    pub fn is_pnpm_lock(&self) -> bool {
        is_pnpm_lock_text(self.text)
    }

    /// Every `packages:` entry, in lock order.
    pub(crate) fn packages(&self) -> &[PnpmPackage<'t>] {
        &self.packages
    }

    fn has_packages_section(&self) -> bool {
        self.text
            .lines()
            .any(|l| l.trim_end_matches('\r') == "packages:")
    }

    /// The registry inventory: one entry per plain-registry packages key
    /// (every key generation, [`pnpm_registry_key`]), flow and block
    /// resolutions, CRLF included. A resolution the grammar refuses leaves
    /// the entry listed without a verifier; our own vendored tarballs are
    /// not registry dependencies and are dropped. `None` when the lock has
    /// no `packages:` section.
    pub fn entries(&self) -> Option<Vec<LockfileEntry>> {
        if !self.has_packages_section() {
            return None;
        }
        let mut out = Vec::new();
        for package in &self.packages {
            // Only plain registry versions: `file:`/`link:`/`https:`/git
            // specs are not registry-resolvable.
            let Some((name, version)) = pnpm_registry_key(package.key) else {
                continue;
            };
            let resolution = package.resolution.as_ref();
            let integrity = resolution
                .and_then(|r| r.integrity())
                .map(|i| LockIntegrity::Sri(i.to_string()))
                .unwrap_or(LockIntegrity::None);
            let tarball = resolution.and_then(|r| r.tarball());
            if tarball.is_some_and(|t| parse_vendor_path(t).is_some()) {
                continue;
            }
            out.push(LockfileEntry::npm(
                name,
                version,
                tarball.and_then(http_url),
                integrity,
            ));
        }
        Some(out)
    }

    /// Whether some packages key resolves exactly `name@version` (any peer
    /// suffix, any key generation).
    pub fn resolves(&self, name: &str, version: &str) -> bool {
        self.packages
            .iter()
            .any(|p| pnpm_registry_key(p.key) == Some((name, version)))
    }

    /// Every packages entry whose flat resolution names a `tarball:`, in
    /// lock order.
    pub(crate) fn wired_refs(&self) -> impl Iterator<Item = PnpmTarballRef<'_>> {
        self.packages.iter().filter_map(|package| {
            let resolution = package.resolution.as_ref()?;
            Some(PnpmTarballRef {
                tarball: resolution.tarball()?,
                integrity: resolution.integrity(),
            })
        })
    }

    /// The SRI pin the lock records for the vendored artifact at
    /// `artifact_rel` (forward-slashed, no `./`): the `integrity` of the
    /// first entry whose tarball is `file:<rel>` and carries an SRI pin.
    pub fn wired_integrity(&self, artifact_rel: &str) -> Option<String> {
        self.wired_refs()
            .filter(|r| {
                let path = r.tarball.strip_prefix("file:").unwrap_or(r.tarball);
                path.trim_start_matches("./") == artifact_rel
            })
            .find_map(|r| r.integrity.filter(|sri| is_sri_pin(sri)))
            .map(str::to_string)
    }

    /// Is the vendored npm artifact of patch `uuid` still consumed by this
    /// lock? `true` when a `packages:` / `snapshots:` block is keyed by it
    /// ([`vendored_npm_uuid`] — v9's `name@file:` and legacy's bare `file:`
    /// keys alike); `false` when the lock carries none (the `overrides:`
    /// declaration alone never counts: pnpm keeps it mirrored from
    /// package.json even when nothing matches it). CRLF locks read like LF
    /// ones.
    pub fn vendored_in_use(&self, uuid: &str) -> bool {
        self.vendored.contains(uuid)
    }
}

/// The uuid of every `packages:` / `snapshots:` block key that resolves
/// into `.socket/vendor/npm/<uuid>/` — the block-key grammar the vendored
/// planners splice with ([`lines::parse_key_line`] at two-space indent),
/// read in one walk with each line's `\r` dropped, so a CRLF lock (a
/// Windows autocrlf checkout) answers like its LF twin.
pub(crate) fn vendored_npm_uuids(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut in_section = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !line.is_empty() && !line.starts_with(' ') {
            in_section = line == "packages:" || line == "snapshots:";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(uuid) =
            lines::parse_key_line(line, 2).and_then(|(key, _, _)| vendored_npm_uuid(key))
        {
            out.insert(uuid);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn resolves_reads_every_key_generation_boundary_anchored() {
        let lock = |keys: &str| format!("lockfileVersion: '9.0'\n\npackages:\n\n{keys}");
        let yes = [
            (
                "  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n",
                "left-pad",
                "1.3.0",
            ),
            (
                "  /left-pad@1.3.0:\n    resolution: {}\n",
                "left-pad",
                "1.3.0",
            ),
            (
                "  /left-pad/1.3.0:\n    resolution: {}\n",
                "left-pad",
                "1.3.0",
            ),
            (
                "  'left-pad@1.3.0(react@18.0.0)':\n    dev: false\n",
                "left-pad",
                "1.3.0",
            ),
            (
                "  /left-pad/1.3.0_react@18.0.0:\n    dev: false\n",
                "left-pad",
                "1.3.0",
            ),
            (
                "  '@scope/name@1.0.0':\n    dev: false\n",
                "@scope/name",
                "1.0.0",
            ),
            (
                "  /@scope/name@1.0.0:\n    dev: false\n",
                "@scope/name",
                "1.0.0",
            ),
            (
                "  /@scope/name/1.0.0:\n    dev: false\n",
                "@scope/name",
                "1.0.0",
            ),
        ];
        for (keys, name, version) in yes {
            assert!(
                PnpmLock::parse(&lock(keys)).resolves(name, version),
                "{keys}"
            );
        }
        let no = [
            ("  left-pad@1.3.0-beta.1:\n    dev: false\n", "left-pad", "1.3.0"),
            ("  left-pad@1.3.0:\n    dev: false\n", "pad", "1.3.0"),
            ("  /left-pad/1.3.0:\n    dev: false\n", "pad", "1.3.0"),
            ("  '@scope/name@1.0.0':\n    dev: false\n", "name", "1.0.0"),
            ("  /@scope/name@1.0.0:\n    dev: false\n", "name", "1.0.0"),
            ("  left-pad@1.3.1:\n    dev: false\n", "left-pad", "1.3.0"),
            (
                &format!("  left-pad@file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz:\n    version: 1.3.0\n"),
                "left-pad",
                "1.3.0",
            ),
        ];
        for (keys, name, version) in no {
            assert!(
                !PnpmLock::parse(&lock(keys)).resolves(name, version),
                "{keys}"
            );
        }
        // Keys outside `packages:` (importers, overrides) resolve nothing.
        let importers = "lockfileVersion: '9.0'\n\nimporters:\n\n  left-pad@1.3.0:\n    x: y\n";
        assert!(!PnpmLock::parse(importers).resolves("left-pad", "1.3.0"));
    }

    #[test]
    fn vendored_in_use_reads_v9_and_legacy_keys_and_crlf() {
        let v9 = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  a@file:.socket/vendor/npm/{UUID}/a-1.0.0.tgz:\n    resolution: {{integrity: sha512-x, tarball: file:.socket/vendor/npm/{UUID}/a-1.0.0.tgz}}\n    version: 1.0.0\n"
        );
        let legacy = format!(
            "lockfileVersion: 5.4\n\npackages:\n\n  file:.socket/vendor/npm/{UUID}/a-1.0.0.tgz:\n    resolution: {{integrity: sha512-x, tarball: file:.socket/vendor/npm/{UUID}/a-1.0.0.tgz}}\n    name: a\n    version: 1.0.0\n"
        );
        let snapshot = format!(
            "lockfileVersion: '9.0'\n\nsnapshots:\n\n  a@file:.socket/vendor/npm/{UUID}/a-1.0.0.tgz: {{}}\n"
        );
        for text in [&v9, &legacy, &snapshot] {
            assert!(PnpmLock::parse(text).vendored_in_use(UUID), "{text}");
            let other = "22222222-2222-4222-8222-222222222222";
            assert!(!PnpmLock::parse(text).vendored_in_use(other));
            let crlf = text.replace('\n', "\r\n");
            assert!(
                PnpmLock::parse(&crlf).vendored_in_use(UUID),
                "CRLF reads like LF"
            );
        }
        // An overrides declaration alone is not usage.
        let overrides = format!(
            "lockfileVersion: '9.0'\n\noverrides:\n  a@1.0.0: file:.socket/vendor/npm/{UUID}/a-1.0.0.tgz\n"
        );
        assert!(!PnpmLock::parse(&overrides).vendored_in_use(UUID));
    }

    #[test]
    fn wired_integrity_reads_the_vendored_entry_pin_only() {
        let sri = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        let rel = format!(".socket/vendor/npm/{UUID}/a-1.0.0.tgz");
        for text in [
            format!("lockfileVersion: '9.0'\n\npackages:\n\n  a@file:{rel}:\n    resolution: {{integrity: {sri}, tarball: file:{rel}}}\n    version: 1.0.0\n"),
            format!("lockfileVersion: 5.4\r\n\r\npackages:\r\n\r\n  file:{rel}:\r\n    resolution: {{integrity: {sri}, tarball: file:{rel}}}\r\n    name: a\r\n"),
        ] {
            assert_eq!(PnpmLock::parse(&text).wired_integrity(&rel).as_deref(), Some(sri));
        }
        // A neighbouring registry entry's pin never leaks into the answer.
        let neighbour = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  a@file:{rel}:\n    version: 1.0.0\n\n  b@1.0.0:\n    resolution: {{integrity: {sri}}}\n"
        );
        assert_eq!(PnpmLock::parse(&neighbour).wired_integrity(&rel), None);
    }

    /// #903 / #905: a leading UTF-8 BOM is encoding, not content — pnpm
    /// reads a BOM lock like its plain twin, so every sniff here must too.
    /// Before the fix the BOM twin read as "not a pnpm lock", unversioned
    /// and unsupported while its entries still parsed.
    #[test]
    fn bom_lock_reads_like_its_plain_twin() {
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n";
        let v6 = "lockfileVersion: '6.0'\n\ndependencies:\n  left-pad:\n    specifier: 1.3.0\n    version: 1.3.0\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n";
        let v54 = "lockfileVersion: 5.4\n\nspecifiers:\n  left-pad: 1.3.0\n\ndependencies:\n  left-pad: 1.3.0\n\npackages:\n\n  /left-pad/1.3.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n";
        let v52 = "lockfileVersion: 5.2\n\npackages:\n\n  /left-pad/1.3.0:\n    resolution: {integrity: sha512-x}\n";
        let shrinkwrap = "shrinkwrapVersion: 3\nshrinkwrapMinorVersion: 7\n\npackages:\n\n  /left-pad/1.3.0:\n    resolution: {integrity: sha512-x}\n";
        for plain in [v9, v6, v54, v52, shrinkwrap] {
            let bom = format!("\u{feff}{plain}");
            assert!(PnpmLock::parse(plain).is_pnpm_lock(), "{plain}");
            assert!(PnpmLock::parse(&bom).is_pnpm_lock(), "BOM twin of {plain}");
            assert!(is_pnpm_lock_text(&bom), "{plain}");
            assert_eq!(
                sniff_lock_grammar(&bom),
                sniff_lock_grammar(plain),
                "{plain}"
            );
            assert_eq!(
                lock_version_major(&bom),
                lock_version_major(plain),
                "{plain}"
            );
            assert_eq!(
                may_need_store_flag(&bom),
                may_need_store_flag(plain),
                "{plain}"
            );
            assert_eq!(
                check_v9_lock_version(&bom),
                check_v9_lock_version(plain),
                "{plain}"
            );
            let keys = |text: &str| {
                PnpmLock::parse(text).entries().map(|e| {
                    e.into_iter()
                        .map(|e| (e.name, e.version))
                        .collect::<Vec<_>>()
                })
            };
            assert_eq!(keys(&bom), keys(plain), "{plain}");
        }
        assert_eq!(
            sniff_lock_grammar(&format!("\u{feff}{v9}")),
            Ok(PnpmLockGrammar::V9)
        );
        assert_eq!(lock_version_major(&format!("\u{feff}{v9}")), Some(9));
        assert!(may_need_store_flag(&format!("\u{feff}{v52}")));
        assert!(may_need_store_flag(&format!("\u{feff}{shrinkwrap}")));
        assert!(grammar::unsupported_early_shrinkwrap(
            "\u{feff}shrinkwrapVersion: 3\n"
        ));
        // Exactly one BOM is encoding; a second one is content, as for pnpm.
        assert!(!is_pnpm_lock_text(
            "\u{feff}\u{feff}lockfileVersion: '9.0'\n"
        ));
    }
}
