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
pub(crate) mod modules_yaml;
mod version;
pub(crate) mod workspace;

pub use version::{matches_file_id_build_keys, root_only_workspace_breaks_add};

pub use grammar::PnpmDocument;
pub(crate) use grammar::{
    entry_bundled, entry_field, is_pnpm_lock_text, Bundled, Entry, Resolution,
};
pub(crate) use hosted::plan_hosted;

use std::collections::HashSet;
use std::sync::OnceLock;

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
    /// The lock document the entry is in ([`grammar::documents`]): the
    /// project lock or pnpm 11+'s env lockfile, each its own install tree.
    pub(crate) document: PnpmDocument,
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

/// Every `packages:` entry of a pnpm lock text, in lock order, each tagged
/// with its document — the ONE entry walk every reader shares (through
/// [`PnpmLock::packages`]). Every entry is returned (registry, rekeyed
/// vendored, hosted, directory, git); each consumer applies its own key
/// and resolution rules.
fn pnpm_packages(text: &str, resolve: Resolve) -> Vec<PnpmPackage<'_>> {
    let documents = grammar::documents(text);
    grammar::entries(text)
        .into_iter()
        .map(|entry| {
            // Tag by the KEY line: an entry with an empty body (its key the
            // last line of a document) has its body offset on the next
            // document's `---` line, or at the end of the text.
            let key_at = entry.key.as_ptr() as usize - text.as_ptr() as usize;
            PnpmPackage {
                key: grammar::unquote(entry.key.trim()),
                resolution: match resolve {
                    Resolve::Yes => grammar::resolution(&entry),
                    Resolve::No => None,
                },
                document: documents
                    .iter()
                    .find(|(span, _)| span.contains(&key_at))
                    .map_or(PnpmDocument::Project, |(_, kind)| *kind),
                entry,
            }
        })
        .collect()
}

/// Whether [`pnpm_packages`] parses each entry's `resolution:` map.
#[derive(Clone, Copy)]
enum Resolve {
    Yes,
    /// Keys and bodies only: the store crawler's hot path
    /// ([`InstalledPackages::from_lock_text`]) never reads a resolution.
    No,
}

/// The `(integrity, tarball)` of one recorded `packages:` block — a
/// vendored planner's wiring fragment (its key line and body, as
/// recorded), each unquoted; `None` unless the fragment is exactly one
/// entry with a flat resolution.
pub(crate) fn fragment_resolution(block: &[String]) -> Option<(Option<String>, Option<String>)> {
    let text = format!("packages:\n{}\n", block.join("\n"));
    let packages = pnpm_packages(&text, Resolve::Yes);
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
/// `lockfileVersion: '9.0'` (first line; pnpm >= 11 with config
/// dependencies or a `packageManager` pin writes two documents, each with
/// its own version line after a `---`); pnpm 8 emits `'6.0'`, pnpm 7 an
/// unquoted `5.4`. `None` when no parseable version line exists —
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
///
/// Every document is read. pnpm 11+ writes its env lockfile
/// (`configDependencies`, `packageManagerDependencies`) as a first
/// document; its entries are installed too (into pnpm's config store, not
/// `node_modules`), so they are part of the lock, tagged
/// [`PnpmDocument::Env`]: a reader that keeps install trees apart
/// (lockfile discovery's contests) reads the env document as a tree of its
/// own ([`PnpmPackage::document`]).
pub struct PnpmLock<'t> {
    text: &'t str,
    /// Every document's entries, with offsets into `text`.
    packages: Vec<PnpmPackage<'t>>,
    /// [`vendored_npm_uuids`] of the whole lock, computed on first use (the
    /// store crawler never asks).
    vendored: OnceLock<HashSet<String>>,
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
            packages: pnpm_packages(text, Resolve::Yes),
            vendored: OnceLock::new(),
        }
    }

    /// [`PnpmLock::parse`] without the resolution maps (every
    /// [`PnpmPackage::resolution`] is `None`), for a reader of keys and
    /// entry fields only.
    fn parse_keys(text: &'t str) -> Self {
        PnpmLock {
            text,
            packages: pnpm_packages(text, Resolve::No),
            vendored: OnceLock::new(),
        }
    }

    pub fn text(&self) -> &'t str {
        self.text
    }

    /// Whether the text is a pnpm lock at all ([`is_pnpm_lock_text`]).
    pub fn is_pnpm_lock(&self) -> bool {
        is_pnpm_lock_text(self.text)
    }

    /// Every `packages:` entry of every document, in lock order, each
    /// tagged with its [`PnpmDocument`].
    pub(crate) fn packages(&self) -> &[PnpmPackage<'t>] {
        &self.packages
    }

    /// The entries of one document kind, in lock order.
    pub(crate) fn packages_of(
        &self,
        document: PnpmDocument,
    ) -> impl Iterator<Item = &PnpmPackage<'t>> {
        self.packages.iter().filter(move |p| p.document == document)
    }

    /// The document kinds the lock has entries in, project first.
    pub(crate) fn documents(&self) -> Vec<PnpmDocument> {
        let mut kinds: Vec<PnpmDocument> = self.packages.iter().map(|p| p.document).collect();
        kinds.sort();
        kinds.dedup();
        kinds
    }

    fn has_packages_section(&self) -> bool {
        self.text
            .lines()
            .any(|l| l.trim_end_matches('\r') == "packages:")
    }

    /// The registry inventory: one entry per plain-registry packages key
    /// (every key generation, [`pnpm_registry_key`]) of every document,
    /// flow and block resolutions, CRLF included. A resolution the grammar
    /// refuses leaves the entry listed without a verifier; our own vendored
    /// tarballs are not registry dependencies and are dropped. `None` when
    /// the lock has no `packages:` section.
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
            if tarball
                .is_some_and(|t| crate::vendor::path::recognize_vendor_path_anywhere(t).is_some())
            {
                continue;
            }
            let mut entry =
                LockfileEntry::npm(name, version, tarball.and_then(http_url), integrity);
            entry.pnpm_env = package.document == PnpmDocument::Env;
            out.push(entry);
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
        self.vendored
            .get_or_init(|| vendored_npm_uuids(self.text))
            .contains(uuid)
    }
}

/// The packages a pnpm "current lockfile" — the `lock.yaml` pnpm writes in
/// its virtual store (`node_modules/.pnpm/lock.yaml`) after every install —
/// says are installed, by `(name, version)`. pnpm 7–12 keep a removed or
/// upgraded-away package's store entry on disk for a while (#1197); the
/// current lockfile is the record of which entries the install still uses.
#[derive(Debug, Default)]
pub(crate) struct InstalledPackages {
    versions: HashSet<(String, String)>,
    /// Names of entries whose version the lock does not state: every
    /// version of these counts as installed.
    any_version: HashSet<String>,
}

impl InstalledPackages {
    /// Read a current lockfile in any lock generation (v5.4 `/name/1.0.0`,
    /// v6 `/name@1.0.0`, v9 `name@1.0.0` keys; a non-registry entry by its
    /// `name:` / `version:` fields, the last of each winning, or a v9 key's
    /// name), through [`PnpmLock`]'s entry walk. `None` when the text is not
    /// a pnpm lock, or holds an entry whose package cannot be named — the
    /// caller must then keep every store entry.
    ///
    /// Every document counts. pnpm writes the current lockfile as the
    /// project lock alone (the env lockfile lives only in `pnpm-lock.yaml`,
    /// and config dependencies install into `node_modules/.pnpm-config`, not
    /// the virtual store), so a second document is not expected here; if
    /// one appears, its entries keep their store entries too, the side that
    /// never hides an installed package.
    pub(crate) fn from_lock_text(text: &str) -> Option<Self> {
        if !grammar::is_pnpm_lock_text(text) {
            return None;
        }
        // Keys and `name:` / `version:` lines only: the scan reads this on
        // every run, for every package of the install.
        let lock = PnpmLock::parse_keys(text);
        let mut out = Self::default();
        for package in lock.packages() {
            let (mut name, mut version) = (None, None);
            for line in package.entry.body.split('\n') {
                let line = line.strip_suffix('\r').unwrap_or(line);
                if let Some((field, _, value)) = lines::parse_key_line(line, 4) {
                    let value = Some(grammar::unquote(value.trim())).filter(|v| !v.is_empty());
                    match field {
                        "name" => name = value,
                        "version" => version = value,
                        _ => {}
                    }
                }
            }
            out.insert_entry(package.key, name, version)?;
        }
        // A lock listing no package at all says nothing about the store.
        (!lock.packages().is_empty()).then_some(out)
    }

    /// Record one `packages:` entry; `None` when its package cannot be
    /// named.
    fn insert_entry(
        &mut self,
        key: &str,
        field_name: Option<&str>,
        field_version: Option<&str>,
    ) -> Option<()> {
        let (name, version) = match classify_pnpm_key(key) {
            PnpmKey::Registry { name, version } => (Some(name), Some(version)),
            PnpmKey::V9File { name, .. } => (Some(name), field_version),
            PnpmKey::LegacyFile { .. } => (field_name, field_version),
            // A v9 url / git key still leads with `name@`; a legacy one
            // names its package only in the `name:` field.
            PnpmKey::Other => {
                let base = strip_pnpm_peer_suffix(key);
                let v9_name = (!base.starts_with('/'))
                    .then(|| base.get(1..).and_then(|rest| rest.find('@')))
                    .flatten()
                    .map(|at| &base[..at + 1]);
                (field_name.or(v9_name), field_version)
            }
        };
        let name = name?;
        match version {
            Some(version) => {
                self.versions
                    .insert((name.to_string(), version.to_string()));
            }
            None => {
                self.any_version.insert(name.to_string());
            }
        }
        Some(())
    }

    /// Whether the lock installs `name@version`.
    pub(crate) fn contains(&self, name: &str, version: &str) -> bool {
        self.any_version.contains(name)
            || self
                .versions
                .contains(&(name.to_string(), version.to_string()))
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

    /// #1197: the current lockfile's packages, by name and version, in the
    /// shapes real pnpm 7.33.7 / 8.15.9 / 10–12 write after an upgrade
    /// (`left-pad` 1.3.0 → 1.2.0), plus non-registry entries.
    #[test]
    fn installed_packages_read_every_lock_generation() {
        for (head, keys) in [
            ("5.4", ["/@sindresorhus/is/4.6.0", "/left-pad/1.2.0"]),
            ("6.0", ["/@sindresorhus/is@4.6.0", "/left-pad@1.2.0"]),
            (
                "9.0",
                ["'@sindresorhus/is@4.6.0'", "left-pad@1.2.0(peer@1.0.0)"],
            ),
        ] {
            let text = format!(
                "lockfileVersion: '{head}'\n\npackages:\n\n  {}:\n    resolution: {{integrity: \
                 sha512-a}}\n\n  {}:\n    resolution: {{integrity: sha512-b}}\n",
                keys[0], keys[1]
            );
            let installed = InstalledPackages::from_lock_text(&text).unwrap();
            assert!(installed.contains("@sindresorhus/is", "4.6.0"), "{text}");
            assert!(installed.contains("left-pad", "1.2.0"), "{text}");
            assert!(!installed.contains("left-pad", "1.3.0"), "{text}");
        }
        let text = "lockfileVersion: '9.0'\n\npackages:\n\n  \
                    lp@file:lp.tgz:\n    resolution: {integrity: sha512-a, tarball: file:lp.tgz}\n    \
                    version: 1.0.0\n\n  git-dep@https://codeload.github.com/u/r/tar.gz/abc:\n    \
                    resolution: {tarball: https://codeload.github.com/u/r/tar.gz/abc}\n";
        let installed = InstalledPackages::from_lock_text(text).unwrap();
        assert!(installed.contains("lp", "1.0.0") && !installed.contains("lp", "0.9.0"));
        assert!(
            installed.contains("git-dep", "0.0.1"),
            "no version: any version"
        );
        // A package the lock cannot name, or no lock at all: unknown.
        let unnamed = "lockfileVersion: 5.4\n\npackages:\n\n  \
                       registry.example.com/x/1.0.0:\n    resolution: {integrity: sha512-a}\n";
        assert!(InstalledPackages::from_lock_text(unnamed).is_none());
        assert!(InstalledPackages::from_lock_text("not: a lock\n").is_none());
        // A lock listing no package says nothing about the store.
        assert!(InstalledPackages::from_lock_text("lockfileVersion: 9\n").is_none());
    }

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

    /// pnpm 11+'s env document is part of the lock (owner decision,
    /// lock-model divergence N4; this reverses #1949's skip): pnpm installs
    /// its config dependencies, and the hosted planner and the v9 vendored
    /// in-use check already read it. `entries()`, `resolves()`, the
    /// vendored uuids and `InstalledPackages` all read both documents and
    /// agree with each other; every entry is tagged with its document, so
    /// discovery keeps the env document a tree of its own.
    #[test]
    fn env_document_is_read_as_its_own_tree() {
        let env = format!(
            "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      cfg-dep:\n        specifier: 2.0.0\n        version: 2.0.0\n\npackages:\n\n  cfg-dep@2.0.0:\n    resolution: {{integrity: sha512-c}}\n\n  b@file:.socket/vendor/npm/{UUID}/b-1.0.0.tgz:\n    resolution: {{integrity: sha512-x, tarball: file:.socket/vendor/npm/{UUID}/b-1.0.0.tgz}}\n    version: 1.0.0\n\n"
        );
        let project = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n";
        for text in [
            format!("{env}{project}"),
            format!("\u{feff}{env}{project}"),
            format!("{env}{project}").replace('\n', "\r\n"),
        ] {
            let lock = PnpmLock::parse(&text);
            let names: Vec<_> = lock
                .entries()
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.version))
                .collect();
            assert_eq!(
                names,
                [
                    ("cfg-dep".to_string(), "2.0.0".to_string()),
                    ("left-pad".to_string(), "1.3.0".to_string())
                ],
                "{text:?}"
            );
            assert!(lock.resolves("left-pad", "1.3.0"));
            assert!(lock.resolves("cfg-dep", "2.0.0"));
            assert!(lock.vendored_in_use(UUID));
            let tagged: Vec<_> = lock
                .packages()
                .iter()
                .map(|p| (p.key, p.document))
                .collect();
            assert_eq!(
                tagged,
                [
                    ("cfg-dep@2.0.0", PnpmDocument::Env),
                    (
                        format!("b@file:.socket/vendor/npm/{UUID}/b-1.0.0.tgz").as_str(),
                        PnpmDocument::Env
                    ),
                    ("left-pad@1.3.0", PnpmDocument::Project),
                ],
                "{text:?}"
            );
            assert_eq!(lock.documents(), [PnpmDocument::Project, PnpmDocument::Env]);
            let installed = InstalledPackages::from_lock_text(&text).unwrap();
            assert!(installed.contains("left-pad", "1.3.0"));
            assert!(installed.contains("cfg-dep", "2.0.0"));
            assert!(installed.contains("b", "1.0.0"));
        }
        // One document: the project, whatever its importers say.
        let lone = env.trim_start_matches("---\n");
        assert!(PnpmLock::parse(lone)
            .packages()
            .iter()
            .all(|p| p.document == PnpmDocument::Project));
        // Offsets still index the whole text.
        let text = format!("{env}{project}");
        let lock = PnpmLock::parse(&text);
        let entry = &lock.packages()[0].entry;
        assert_eq!(
            &text[entry.offset..entry.offset + entry.body.len()],
            entry.body
        );
    }

    /// N4: before, the readers took the text after the LAST `---` as the
    /// project, so a lock with an extra document chose its own "project"
    /// and hid the rest; now every document is read. The env document is
    /// the FIRST one, when its importers say so, as pnpm and the vendored
    /// planners' `split_project_document` read it: an env-shaped LATER
    /// document is a project one, so it cannot opt out of the project
    /// tree's contests (code-review finding 2).
    #[test]
    fn documents_are_identified_by_position_and_content() {
        let env = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      cfg-dep:\n        specifier: 2.0.0\n        version: 2.0.0\n\npackages:\n\n  cfg-dep@2.0.0:\n    resolution: {integrity: sha512-c}\n";
        let project = |dep: &str| {
            format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      {dep}:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  {dep}@1.0.0:\n    resolution: {{integrity: sha512-x}}\n"
            )
        };
        let kinds = |text: &str| -> Vec<(String, PnpmDocument)> {
            PnpmLock::parse(text)
                .packages()
                .iter()
                .map(|p| (p.key.to_string(), p.document))
                .collect()
        };
        let own = |pairs: &[(&str, PnpmDocument)]| -> Vec<(String, PnpmDocument)> {
            pairs.iter().map(|(k, d)| (k.to_string(), *d)).collect()
        };
        use PnpmDocument::{Env, Project};
        // An env-shaped document after the project is a project one.
        let swapped = format!("---\n{}---\n{env}", project("a"));
        assert_eq!(
            kinds(&swapped),
            own(&[("a@1.0.0", Project), ("cfg-dep@2.0.0", Project)])
        );
        assert!(!PnpmLock::parse(&swapped).documents().contains(&Env));
        // A first document that is not the env document is a project one,
        // and its entries are no longer skipped.
        let two = format!("---\n{}---\n{}", project("a"), project("b"));
        assert_eq!(
            kinds(&two),
            own(&[("a@1.0.0", Project), ("b@1.0.0", Project)])
        );
        // A third document is read too, CRLF and a BOM included.
        let three = format!("---\n{env}---\n{}---\n{}", project("a"), project("b"));
        for text in [
            three.clone(),
            three.replace('\n', "\r\n"),
            format!("\u{feff}{three}"),
        ] {
            assert_eq!(
                kinds(&text),
                own(&[
                    ("cfg-dep@2.0.0", Env),
                    ("a@1.0.0", Project),
                    ("b@1.0.0", Project)
                ]),
                "{text:?}"
            );
        }
    }

    /// An entry is tagged by its KEY line (code-review finding 5): a key
    /// whose body is empty — the last line of the env document, right
    /// before `---` — has its body offset on the separator, in no document.
    #[test]
    fn an_entry_with_an_empty_body_keeps_its_document() {
        let env = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      cfg-dep:\n        specifier: 2.0.0\n        version: 2.0.0\n\npackages:\n\n  cfg-dep@2.0.0:\n";
        let project = "---\nlockfileVersion: '9.0'\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n\n  b@1.0.0:";
        let text = format!("{env}{project}");
        for text in [text.clone(), text.replace('\n', "\r\n")] {
            let tagged: Vec<_> = PnpmLock::parse(&text)
                .packages()
                .iter()
                .map(|p| (p.key, p.document))
                .collect();
            assert_eq!(
                tagged,
                [
                    ("cfg-dep@2.0.0", PnpmDocument::Env),
                    ("a@1.0.0", PnpmDocument::Project),
                    ("b@1.0.0", PnpmDocument::Project),
                ],
                "{text:?}"
            );
        }
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

    /// Lock-head version sniff against real pnpm 7/8/9-12 heads: quoted `'9.0'` and `'6.0'`,
    /// unquoted `5.4`; a headless/garbled lock yields `None` (hands-off).
    #[test]
    fn lock_version_major_sniffs_real_lock_heads() {
        assert_eq!(
            lock_version_major("lockfileVersion: '9.0'\n\nsettings:\n"),
            Some(9),
            "pnpm 9-12 emit a quoted '9.0'"
        );
        assert_eq!(
            lock_version_major("lockfileVersion: '6.0'\n\nsettings:\n"),
            Some(6),
            "pnpm 8 emits a quoted '6.0'"
        );
        assert_eq!(
            lock_version_major("lockfileVersion: 5.4\n\nspecifiers:\n"),
            Some(5),
            "pnpm 7 emits an unquoted 5.4"
        );
        // Not necessarily the first line (a comment/BOM-damaged head).
        assert_eq!(
            lock_version_major("# managed\nlockfileVersion: \"9.0\"\n"),
            Some(9)
        );
        assert_eq!(
            lock_version_major("importers:\n  .:\n"),
            None,
            "no version line → None, callers stay hands-off"
        );
        assert_eq!(
            lock_version_major("lockfileVersion: banana\n"),
            None,
            "unparseable version → None, never a guess"
        );
    }

    #[test]
    fn may_need_store_flag_only_for_pnpm_one_to_four_locks() {
        assert!(may_need_store_flag("shrinkwrapVersion: 3\n"));
        assert!(may_need_store_flag("lockfileVersion: 5.1\n"));
        assert!(may_need_store_flag("lockfileVersion: '5.2'\n"));
        assert!(!may_need_store_flag("lockfileVersion: 5.3\n"));
        assert!(!may_need_store_flag("lockfileVersion: 5.4\n"));
        assert!(!may_need_store_flag("lockfileVersion: '6.0'\n"));
        assert!(!may_need_store_flag("lockfileVersion: '9.0'\n"));
        assert!(!may_need_store_flag("packages: {}\n"));
    }
}

/// ARCHITECTURE GUARD: outside `formats/pnpm`, pnpm lock entries are READ
/// through [`PnpmLock`] (one walk, every document tagged), never through
/// the grammar's raw entry walk or a hand-rolled `packages:` line walk.
/// Writers that splice by byte range or line position keep their own
/// walk; each such use is allowlisted below with a label and a count, so
/// a new reader in the same file still fails.
#[cfg(test)]
mod architecture_tests {
    use std::path::{Path, PathBuf};

    /// `(root-relative file, uses, why)`.
    const WRITERS: &[(&str, usize, &str)] = &[
        (
            "patch/redirect/upstream/npm.rs",
            2,
            "hosted unwind (`restore_pnpm_locks`): splices each pin's \
             resolution byte range back to the registry spelling",
        ),
        (
            "vendor/pnpm_lock.rs",
            3,
            "v9 vendored planner: preflight and splices over line blocks \
             (`lock_has_target_package`, `edit_packages`, `LockIndex`)",
        ),
        (
            "vendor/pnpm_lock_legacy.rs",
            6,
            "5.4 / 6.0 vendored planner: preflight, splices and revert over \
             line blocks",
        ),
    ];

    /// Whether one production line reads pnpm entries outside the model.
    fn raw_walk(line: &str) -> bool {
        let code = line.trim_start();
        if code.starts_with("//") {
            return false;
        }
        [
            "grammar::entries(",
            "pnpm::entries(",
            "pnpm_grammar::entries(",
            "pnpm_packages(",
            "== \"packages:\"",
        ]
        .iter()
        .any(|needle| code.contains(needle))
            || (code.contains("\"packages\")")
                && (code.contains("bounds(") || code.contains("SectionIndex::build(")))
    }

    /// The lines of `text` outside `#[cfg(test)]` / `#[cfg(all(test, …))]`
    /// items: an out-of-line `mod name;` declaration drops that line only,
    /// an inline item (`mod tests { … }`, a helper `fn`) drops through its
    /// closing brace, so production code after either is still scanned.
    fn production(text: &str) -> Vec<&str> {
        let lines: Vec<&str> = text.split('\n').collect();
        let deltas = brace_deltas(text);
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let attr = lines[i].trim_start();
            if !(attr.starts_with("#[cfg(test)]") || attr.starts_with("#[cfg(all(test")) {
                out.push(lines[i]);
                i += 1;
                continue;
            }
            // Skip the gated item's other attributes, then the item.
            i += 1;
            while i < lines.len() && lines[i].trim_start().starts_with("#[") {
                i += 1;
            }
            let mut depth = 0i64;
            let mut opened = false;
            while i < lines.len() {
                let (open, close) = deltas[i];
                let line = lines[i];
                i += 1;
                depth += open - close;
                opened |= open > 0;
                if (!opened && line.trim_end().ends_with(';')) || (opened && depth <= 0) {
                    break;
                }
            }
        }
        out
    }

    /// Per line of `text` (split on `\n`), the `{` and `}` in code: outside
    /// comments and string, raw string and char literals, which may span
    /// lines.
    fn brace_deltas(text: &str) -> Vec<(i64, i64)> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = vec![(0i64, 0i64)];
        let mut i = 0;
        let ident = |c: char| c.is_alphanumeric() || c == '_';
        // Advance past `n` chars, opening a new line entry at each `\n`.
        let step = |out: &mut Vec<(i64, i64)>, i: &mut usize, n: usize| {
            for _ in 0..n {
                if chars.get(*i) == Some(&'\n') {
                    out.push((0, 0));
                }
                *i += 1;
            }
        };
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if c == '/' && next == Some('/') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            } else if c == '/' && next == Some('*') {
                let mut depth = 0;
                while i < chars.len() {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        step(&mut out, &mut i, 2);
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        step(&mut out, &mut i, 2);
                        if depth == 0 {
                            break;
                        }
                    } else {
                        step(&mut out, &mut i, 1);
                    }
                }
            } else if c == 'r'
                && matches!(next, Some('"' | '#'))
                && (i == 0 || !ident(chars[i - 1]) || chars[i - 1] == 'b')
            {
                let hashes = chars[i + 1..].iter().take_while(|&&h| h == '#').count();
                if chars.get(i + 1 + hashes) != Some(&'"') {
                    step(&mut out, &mut i, 1);
                    continue;
                }
                step(&mut out, &mut i, 2 + hashes);
                while i < chars.len() {
                    let closes = chars[i] == '"'
                        && chars[i + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|&&h| h == '#')
                            .count()
                            == hashes;
                    if closes {
                        step(&mut out, &mut i, 1 + hashes);
                        break;
                    }
                    step(&mut out, &mut i, 1);
                }
            } else if c == '"' {
                step(&mut out, &mut i, 1);
                while i < chars.len() && chars[i] != '"' {
                    let n = if chars[i] == '\\' { 2 } else { 1 };
                    step(&mut out, &mut i, n);
                }
                step(&mut out, &mut i, 1);
            } else if c == '\'' && next == Some('\\') {
                // An escaped char literal (`'\''`, `'\u{7b}'`).
                step(&mut out, &mut i, 2);
                while i < chars.len() && chars[i] != '\'' {
                    step(&mut out, &mut i, 1);
                }
                step(&mut out, &mut i, 1);
            } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
                step(&mut out, &mut i, 3);
            } else {
                let last = out.last_mut().expect("one entry per line");
                match c {
                    '{' => last.0 += 1,
                    '}' => last.1 += 1,
                    _ => {}
                }
                step(&mut out, &mut i, 1);
            }
        }
        out
    }

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn pnpm_entries_are_read_through_the_model() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rs_files(&src, &mut files);
        let mut found: Vec<(String, usize)> = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with("formats/pnpm/") || rel.ends_with("tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            let uses = production(&text)
                .into_iter()
                .filter(|l| raw_walk(l))
                .count();
            if uses > 0 {
                found.push((rel, uses));
            }
        }
        found.sort();
        let mut allowed: Vec<(String, usize)> = WRITERS
            .iter()
            .map(|(rel, uses, _)| (rel.to_string(), *uses))
            .collect();
        allowed.sort();
        assert_eq!(
            found, allowed,
            "pnpm lock entries read outside formats/pnpm: read them through \
             PnpmLock::packages (a reader), or allowlist a writer that needs \
             byte or line positions in WRITERS with its reason"
        );
    }

    #[test]
    fn raw_walk_needles() {
        assert!(raw_walk("    for entry in pnpm::entries(&text) {"));
        assert!(raw_walk("        in_packages = line == \"packages:\";"));
        assert!(raw_walk(
            "    let (s, e) = section_bounds(lines, \"packages\").unwrap();"
        ));
        assert!(!raw_walk("    // pnpm::entries(&text)"));
        assert!(!raw_walk("    lock.get(\"packages\")"));
        assert!(!raw_walk("    for p in PnpmLock::parse(t).packages() {"));
    }

    /// Code-review finding 1: an out-of-line test module declared near the
    /// top of a file (`crawlers/npm_crawler.rs`, `patch/redirect/mod.rs`,
    /// `vendor/mod.rs` do) used to end the scan there, so a raw walk deep
    /// in the file went unseen. Only the gated items are dropped now.
    #[test]
    fn production_drops_only_test_gated_items() {
        let src = "use a;\n#[cfg(test)]\nmod oracle;\n#[cfg(all(test, unix))]\n#[path = \"x.rs\"]\nmod x_tests;\n\
                   #[cfg(test)]\nfn helper() {\n    let s = \"}\";\n    let c = '{';\n    if true { pnpm::entries(t); }\n}\n\
                   fn reader<'a>(t: &'a str) {\n    for e in pnpm::entries(t) {}\n}\n\
                   #[cfg(test)]\nmod tests {\n    fn t() { pnpm::entries(\"{\"); }\n    \
                   const S: &str = \"a {\n{ b\";\n    const R: &str = r#\"{\"{\n\"#;\n    /* { */\n}\n\
                   fn after() { let x = line == \"packages:\"; }\n";
        let kept = production(src);
        assert_eq!(kept.iter().filter(|l| raw_walk(l)).count(), 2, "{kept:#?}");
        assert!(kept.iter().all(|l| !l.contains("mod oracle")));
        assert!(kept.iter().any(|l| l.contains("fn after()")));
        assert!(kept.iter().all(|l| !l.contains("fn helper")));
        // The real files that declare test modules early keep their late
        // production code.
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for (rel, late) in [
            ("crawlers/npm_crawler.rs", "fn is_safe_npm_component("),
            ("patch/redirect/mod.rs", "fn rewrite_golang_target("),
            ("vendor/mod.rs", "pub async fn vendored_purl_keys("),
        ] {
            let text = std::fs::read_to_string(src.join(rel))
                .unwrap()
                .replace("\r\n", "\n");
            assert!(
                production(&text).iter().any(|l| l.starts_with(late)),
                "{rel}: production code before its test module was not scanned"
            );
        }
    }
}
