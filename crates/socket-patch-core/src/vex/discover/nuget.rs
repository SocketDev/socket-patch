//! NuGet — the root `nuget.config` (source wiring) plus `packages.lock.json`
//! (version + content pin).
//!
//! `packages.lock.json` records NO source url, so the patch identity lives
//! only in `nuget.config`, and it takes BOTH halves of the config to tie a
//! uuid to a package:
//!
//! * the source DEFINITION `<packageSources><add key="socket-patch-<uuid>"
//!   value="…"/>` says where the patch is served from, and
//! * the `<packageSourceMapping><packageSource key="socket-patch-<uuid>">
//!   <package pattern="<PkgId>"/>` MAPPING is the pin: mapping is exclusive
//!   and longest-prefix, so the exact-id pattern forces `<PkgId>` from our
//!   source while the `*` catch-all the writers fan out keeps everything
//!   else where it was. A definition without its mapping routes nothing
//!   (rule 10), so it is diagnosed [`DIAG_REF_UNATTRIBUTABLE`], never a ref.
//!
//! Both writers use the same key grammar (`socket-patch-<uuid>`, no
//! `-vendor-` infix, unlike maven) and exactly ONE exact-id pattern per
//! Socket source, so any other pattern set (none, several, a wildcard) is
//! unattributable. The source VALUE decides the mode:
//!
//! | writer | `value` | mode | version from | pin |
//! |---|---|---|---|---|
//! | `patch::redirect::rewrite_nuget` (`scan --mode hosted`) | `https://patch.socket.dev/patch-registry/nuget/<token>/<uuid>/index.json` ([`DiscoverCtx::hosted_uuid`], must equal the key's uuid) | Hosted | every `packages.lock.json` entry for the id (`dependencies.<tfm>.<id>.resolved`, id case-insensitive) | its `contentHash` |
//! | `vendor::nuget_feed` (`vendor`, `scan --mode vendored`) | `.socket/vendor/nuget/<uuid>` ([`vendor_uuid_dir`], must be the nuget dir of the key's uuid) | Vendored | the feed's single `<idLower>.<version>.nupkg` (the patched version), else every locked `resolved` as above | `contentHash` when locked |
//!
//! The vendored artifact is `.socket/vendor/nuget/<uuid>/<idLower>.
//! <versionNorm>.nupkg` ([`nupkg_leaf`], the writer's own stable leaf:
//! lowercased id, version through the SAME `normalize_nuget_version`) — the exact
//! `VendorArtifact::path` the ledger records, which the CLI's liveness check
//! compares verbatim. The feed dir is listed for the patched version (one
//! nupkg for the mapped id; its name is split at the KNOWN id, not guessed
//! from the first digit-leading segment); with no lock (NuGet only writes
//! one under `RestorePackagesWithLockFile`) it must hold exactly one.
//!
//! `contentHash` is base64 sha512 of the nupkg bytes — the hosted rewriter
//! derives it by stripping `sha512-` from the patch's SRI — so it is carried
//! as [`LockIntegrity::Sri`] `sha512-<contentHash>`, and only when every lock
//! entry of that version agrees (divergent hashes fail restore: diagnosed,
//! no ref). Versions are keyed through `normalize_nuget_version` of the
//! trimmed `resolved`, as the writers match lock entries (`1.0` and `1.0.0`
//! are one version).
//!
//! The mapping routes EVERY version of the id to a source that serves only
//! the patched one, so both writers refuse a lock that also locks the id at
//! another version (`*_nuget_lock_other_version`). Here such a source's refs
//! stay refs (the wiring is still there to roll back) but are marked
//! [`UnattestedKind::NugetLockOtherVersion`], never attested: see
//! [`other_versions`] for how the patched version is known.
//!
//! **`integrity_required = true`** for hosted refs: `rewrite_nuget` refuses a
//! dep without a sha512 (`redirect_nuget_missing_sha512`) and always writes
//! `contentHash` on every lock entry it re-pins, so a pin-less entry was not
//! Socket-written. A hosted source with no lock at all (or a lock with no
//! entry for the id) names no version and is unattributable: there is no
//! purl to attest, and the csproj `Version` is a minimum, not a pin. With no
//! lock at all, an EXCLUSIVE exact-id mapping (no other source maps the same
//! id) is still live wiring for a redirect-ledger record of that id — the
//! Socket source serves only the patched version — and is recorded as an
//! [`UnlockedPin`] (see [`emit_hosted`]).
//!
//! What NuGet reads, and nothing else: the first of `nuget.config`,
//! `NuGet.config`, `NuGet.Config` present at the root (NuGet's own per-
//! directory order; a case-insensitive filesystem makes all three the same
//! file), through [`parse_config`] (only the routing elements; a file it
//! refuses is [`DIAG_LOCKFILE_UNPARSEABLE`]); a source listed in
//! `<disabledPackageSources>` with `value="true"` wires nothing (diagnosed).
//!
//! The lock is every lock the root config governs: the root
//! `packages.lock.json` plus, on disk, each lock a project under the root
//! restores into (member projects, `packages.<Project>.lock.json`, a literal
//! `NuGetLockFilePath`; [`crate::formats::nuget::lock::governed_locks`], the
//! discovery both writers pin through).
//!
//! Non-goals (documented, not guessed): parent-directory / user-level
//! configs; `<clear />` inheritance semantics (neither writer emits one); a
//! non-Socket source that ALSO maps the exact id (the lock's `contentHash`
//! is what makes such a restore fail).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{
    parse_json, simple_purl, socket_patch_name_uuid, vendor_ref, vendor_uuid_dir, DiscoverCtx,
    Discovery, PatchedRef, UnattestedKind, UnlockedPin, WiringMode, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_LOCKFILE_UNREADABLE, DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::formats::nuget::lock::nuget_lock_entries;
use crate::formats::nuget::{parse_config, NugetConfig};
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::nuget_config::{same_file, CONFIG_NAMES};
use crate::vendor::nuget_feed::{is_plain_nuget_token, normalize_nuget_version, nupkg_leaf};
use crate::vendor::path::VENDOR_DIR;

/// The lock NuGet writes beside the project (default name).
const PACKAGES_LOCK: &str = "packages.lock.json";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let mut config_rel = None;
    for name in CONFIG_NAMES {
        if ctx.exists(name).await {
            config_rel = Some(name);
            break;
        }
    }
    let Some(cfg_rel) = config_rel else {
        return;
    };
    // NuGet reads only the first spelling present; Socket sources left in a
    // later one wire nothing and are recognized as such (rule 11). On a
    // case-insensitive filesystem the "others" are the file read below
    // itself — skipped, so it is not reported under three names.
    for name in CONFIG_NAMES.iter().filter(|name| **name != cfg_rel) {
        // In memory every spelling is its own entry.
        let same = match ctx.disk_root_reading([*name, cfg_rel]) {
            Some(root) => same_file(&root.join(name), &root.join(cfg_rel)).await,
            None => false,
        };
        if !same {
            ctx.recognize_ignored(name).await;
        }
    }
    let Some(text) = ctx.read_text(cfg_rel, out).await else {
        return;
    };
    let Some(cfg) = parse_config(&text) else {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            cfg_rel,
            format!("{cfg_rel} is not well-formed XML; no NuGet sources were read from it"),
        );
        return;
    };
    let sources = socket_sources(&cfg, cfg_rel, out);
    if sources.is_empty() {
        // No Socket wiring: the lock (which carries no urls) is irrelevant,
        // and a malformed one is not this reader's business.
        return;
    }
    let ids: BTreeSet<String> = sources.iter().map(|s| s.id.to_ascii_lowercase()).collect();
    let lock = load_lock(ctx, &ids, out).await;
    for src in &sources {
        // Another source mapping the same exact id ties with ours (NuGet may
        // restore it from either); without a lock's contentHash to reject
        // the wrong bytes, only an exclusive mapping routes the package.
        let exclusive = !cfg.mappings.iter().any(|(key, patterns)| {
            *key != src.key && patterns.iter().any(|p| p.eq_ignore_ascii_case(&src.id))
        });
        emit(ctx, cfg_rel, src, &lock, exclusive, out).await;
    }
}

// ── Socket sources ───────────────────────────────────────────────────────

/// A Socket patch source that a mapping ties to exactly one package id.
struct SocketSource {
    key: String,
    uuid: String,
    value: String,
    id: String,
}

/// Every well-formed `socket-patch-<uuid>` source with its single mapped id;
/// everything Socket-shaped that falls short is diagnosed.
fn socket_sources(cfg: &NugetConfig, cfg_rel: &str, out: &mut Discovery) -> Vec<SocketSource> {
    // key → distinct values, in first-definition order.
    let mut defined: Vec<(&str, Vec<&str>)> = Vec::new();
    for (key, value) in &cfg.sources {
        if socket_patch_name_uuid(key, false).is_none() {
            continue;
        }
        match defined.iter_mut().find(|(k, _)| *k == key.as_str()) {
            Some((_, values)) if !values.contains(&value.as_str()) => values.push(value.as_str()),
            Some(_) => {}
            None => defined.push((key.as_str(), vec![value.as_str()])),
        }
    }
    let mut reported_undefined = BTreeSet::new();
    for (key, _) in &cfg.mappings {
        if socket_patch_name_uuid(key, false).is_some()
            && !defined.iter().any(|(k, _)| *k == key.as_str())
            && reported_undefined.insert(key.as_str())
        {
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!(
                    "{cfg_rel}: <packageSourceMapping> routes packages to {key}, which no \
                     <packageSources> entry defines; NuGet cannot restore from it"
                ),
            );
        }
    }

    let mut found = Vec::new();
    for (key, values) in defined {
        let uuid = socket_patch_name_uuid(key, false).expect("filtered to socket-patch keys above");
        if values.len() > 1 {
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!("{cfg_rel}: Socket patch source {key} is defined with several values {values:?}"),
            );
            continue;
        }
        if cfg.disabled.contains(key) {
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!(
                    "{cfg_rel}: Socket patch source {key} is disabled in \
                     <disabledPackageSources>; it serves no package"
                ),
            );
            continue;
        }
        let mut patterns: Vec<&str> = Vec::new();
        for (_, pats) in cfg.mappings.iter().filter(|(k, _)| k == key) {
            for p in pats {
                if !patterns.iter().any(|q| q.eq_ignore_ascii_case(p)) {
                    patterns.push(p);
                }
            }
        }
        let id = match patterns.as_slice() {
            [] => {
                out.diag(
                    DIAG_REF_UNATTRIBUTABLE,
                    cfg_rel,
                    format!(
                        "{cfg_rel}: Socket patch source {key} is defined but no \
                         <packageSourceMapping> entry routes a package to it"
                    ),
                );
                continue;
            }
            [one] if !one.contains('*') => *one,
            many => {
                out.diag(
                    DIAG_REF_UNATTRIBUTABLE,
                    cfg_rel,
                    format!(
                        "{cfg_rel}: Socket patch source {key} is mapped to {many:?}; a Socket \
                         patch source serves exactly one package id"
                    ),
                );
                continue;
            }
        };
        if !is_nuget_id(id) {
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!("{cfg_rel}: Socket patch source {key} maps the unusable package id {id:?}"),
            );
            continue;
        }
        found.push(SocketSource {
            key: key.to_string(),
            uuid,
            value: values[0].trim().to_string(),
            id: id.to_string(),
        });
    }
    found
}

/// A NuGet package id: the writers' [`is_plain_nuget_token`] charset minus
/// `+` (which only versions use), not starting with a dot, with at least one
/// alphanumeric — safe as a purl name, a filename prefix and a path segment.
fn is_nuget_id(id: &str) -> bool {
    is_plain_nuget_token(id)
        && !id.contains('+')
        && !id.starts_with('.')
        && id.contains(|c: char| c.is_ascii_alphanumeric())
}

// ── packages.lock.json ───────────────────────────────────────────────────

/// What the governed locks say about one `(id, version)`, the version
/// keyed through [`normalize_nuget_version`] (of the trimmed `resolved`) as
/// the writers match it (`locked_at`, `other_versions`): `1.0` and `1.0.0`
/// are one package.
#[derive(Debug, Default)]
struct Pins {
    /// Every trimmed `resolved` spelling of this version, first seen first
    /// (never empty). The first is the purl's version: purls compare NuGet
    /// versions through the same normalization.
    spellings: Vec<String>,
    /// The governed locks that lock this version.
    files: BTreeSet<String>,
    /// Distinct non-empty `contentHash` values across target frameworks.
    hashes: BTreeSet<String>,
    /// Some entry of this version carries no `contentHash`.
    unpinned: bool,
}

/// What the governed locks say about one Socket-mapped id.
#[derive(Debug, Default)]
struct IdLocks {
    /// Normalized version → pins.
    versions: BTreeMap<String, Pins>,
    /// Locks with an entry for the id whose `resolved` is empty (diagnosed).
    /// No version to attest, but the writers count it as another version
    /// (it does not normalize to the patched one), so it withholds the
    /// statement like one.
    empty: BTreeSet<String>,
}

enum Lock {
    Absent,
    /// Present but unreadable / unparseable (already diagnosed).
    Unusable,
    /// Lowercased Socket-mapped id → what the locks say about it.
    Parsed(BTreeMap<String, IdLocks>),
}

/// Every lock the root config governs: the root `packages.lock.json`, and on
/// disk each lock a project under the root restores into (#353, #514; the
/// writers pin all of them). Their entries are merged: one version's
/// `contentHash` must agree across them, as within one lock. Only the
/// Socket-mapped `ids` (lowercased) are indexed.
async fn load_lock(ctx: &DiscoverCtx<'_>, ids: &BTreeSet<String>, out: &mut Discovery) -> Lock {
    let mut rels = vec![PACKAGES_LOCK.to_string()];
    // On disk only (the in-memory engine refuses NuGet). Walked through the
    // view, never its raw root: a re-scan's read cache keeps recording.
    if !matches!(
        ctx.view,
        crate::vendor::lock_inventory::ProjectView::Memory(_)
    ) {
        // The writers refuse a tree whose locks they cannot all find; a
        // reader that fell back to the root lock alone would take a pinned
        // member lock for no lock at all, so it is unusable here too.
        match crate::vendor::nuget_config::governed_locks_in(&ctx.view).await {
            Ok(governed) => {
                if let Some((project, detail)) = governed.unresolved.first() {
                    out.diag(
                        DIAG_LOCKFILE_UNREADABLE,
                        project,
                        format!("{project}: {detail}; its NuGet lock cannot be located"),
                    );
                    return Lock::Unusable;
                }
                for rel in governed.locks {
                    if !rels.contains(&rel) {
                        rels.push(rel);
                    }
                }
            }
            Err(why) => {
                out.diag(
                    DIAG_LOCKFILE_UNREADABLE,
                    PACKAGES_LOCK,
                    format!("cannot list the project's NuGet locks: {why}"),
                );
                return Lock::Unusable;
            }
        }
    }
    let mut index: BTreeMap<String, IdLocks> = BTreeMap::new();
    let mut any = false;
    for rel in &rels {
        if !ctx.exists(rel).await {
            continue;
        }
        any = true;
        let Some(bytes) = ctx.read_bytes(rel, out).await else {
            return Lock::Unusable;
        };
        let doc: Value = match parse_json(rel, &bytes) {
            Ok(Value::Object(doc)) => Value::Object(doc),
            Ok(_) => {
                out.diag(
                    DIAG_LOCKFILE_UNPARSEABLE,
                    rel,
                    format!("{rel} is not a JSON object"),
                );
                return Lock::Unusable;
            }
            Err(detail) => {
                out.diag(DIAG_LOCKFILE_UNPARSEABLE, rel, detail);
                return Lock::Unusable;
            }
        };
        for entry in nuget_lock_entries(&doc) {
            let id = entry.id.to_ascii_lowercase();
            if !ids.contains(&id) {
                continue;
            }
            let id_locks = index.entry(id).or_default();
            let resolved = entry.resolved.trim();
            if resolved.is_empty() {
                if id_locks.empty.insert(rel.clone()) {
                    out.diag(
                        DIAG_REF_INVALID,
                        rel,
                        format!(
                            "{rel}: {} is locked with an empty resolved version",
                            entry.id
                        ),
                    );
                }
                continue;
            }
            let pins = id_locks
                .versions
                .entry(normalize_nuget_version(resolved))
                .or_default();
            if !pins.spellings.iter().any(|s| s == resolved) {
                pins.spellings.push(resolved.to_string());
            }
            if !pins.files.contains(rel) {
                pins.files.insert(rel.clone());
            }
            match entry.content_hash {
                Some(hash) if !hash.trim().is_empty() => {
                    pins.hashes.insert(hash.trim().to_string());
                }
                _ => pins.unpinned = true,
            }
        }
    }
    if !any {
        return Lock::Absent;
    }
    Lock::Parsed(index)
}

/// One locked version of a Socket source's id.
struct Row {
    /// Normalized ([`normalize_nuget_version`]).
    norm: String,
    /// The purl's version (the first spelling).
    spelling: String,
    integrity: Option<LockIntegrity>,
}

/// The locked versions of `src`'s id, sorted by NuGet precedence. A version
/// whose entries disagree on `contentHash` is diagnosed and dropped (NuGet
/// fails that restore).
fn lock_rows(locks: &IdLocks, src: &SocketSource, cfg_rel: &str, out: &mut Discovery) -> Vec<Row> {
    let mut rows = Vec::new();
    for (norm, pins) in sorted_versions(locks) {
        if pins.hashes.len() > 1 {
            let files: Vec<&str> = pins.files.iter().map(String::as_str).collect();
            out.diag(
                DIAG_REF_INVALID,
                files[0],
                format!(
                    "{}: {} {} (routed to Socket patch {} by {cfg_rel}) is locked with \
                     conflicting contentHash values",
                    files.join(", "),
                    src.id,
                    pins.spellings.join(" / "),
                    src.uuid
                ),
            );
            continue;
        }
        let integrity = match (pins.hashes.iter().next(), pins.unpinned) {
            (Some(hash), false) => Some(LockIntegrity::Sri(format!("sha512-{hash}"))),
            _ => None,
        };
        rows.push(Row {
            norm: norm.clone(),
            spelling: pins.spellings[0].clone(),
            integrity,
        });
    }
    rows
}

/// `locks`' versions in NuGet precedence order (`13.0.9` before `13.0.10`,
/// a pre-release before its release), not string order.
fn sorted_versions(locks: &IdLocks) -> Vec<(&String, &Pins)> {
    let mut versions: Vec<(&String, &Pins)> = locks.versions.iter().collect();
    versions.sort_by(|(a, _), (b, _)| precedence(a).cmp(&precedence(b)).then(a.cmp(b)));
    versions
}

/// A normalized NuGet version's sort key: numeric segments, then a release
/// above its pre-releases, then the pre-release label. Orders listings only.
fn precedence(norm: &str) -> (Vec<u64>, bool, &str) {
    let (core, pre) = match norm.split_once('-') {
        Some((core, pre)) => (core, pre),
        None => (norm, ""),
    };
    let segments = core
        .split('.')
        .map(|s| s.parse().unwrap_or(u64::MAX))
        .collect();
    (segments, pre.is_empty(), pre)
}

/// `(file, detail)` of an [`other_versions`] finding.
type OtherVersion = (String, String);

/// The writers' other-version rule (`formats::nuget::lock::other_versions`)
/// for a ref of `version` (normalized): the exact-id mapping routes EVERY
/// version of the id to a Socket source that serves only the patched one,
/// so a lock entry at any other version cannot restore, and both writers
/// refuse such a lock (`redirect_nuget_lock_other_version`,
/// `vendor_nuget_lock_other_version`). `serves` names that source.
/// `(file, detail)`, the file a lock holding the first other version (in
/// NuGet precedence), or `None` when every entry is at `version`.
///
/// The writers know the patched version from the patch. Of the files, only
/// the vendored feed names it; a hosted url names only the uuid, so a
/// hosted ref is checked against its own version: of two locked versions,
/// one is unpatched, whichever that is, and both refs are withheld. A
/// single locked version that is not the patched one is the VEX plan's to
/// catch: the patch record names another package version.
fn other_versions(
    locks: &IdLocks,
    version: &str,
    src: &SocketSource,
    serves: &str,
    cfg_rel: &str,
) -> Option<OtherVersion> {
    let mut listed = Vec::new();
    let mut file = None;
    for (norm, pins) in sorted_versions(locks) {
        if norm != version {
            let files: Vec<&str> = pins.files.iter().map(String::as_str).collect();
            file.get_or_insert_with(|| files[0].to_string());
            listed.push(format!("{} ({})", pins.spellings[0], files.join(", ")));
        }
    }
    if !locks.empty.is_empty() {
        let files: Vec<&str> = locks.empty.iter().map(String::as_str).collect();
        file.get_or_insert_with(|| files[0].to_string());
        listed.push(format!("an empty version ({})", files.join(", ")));
    }
    let file = file?;
    let also = if locks.versions.contains_key(version) {
        "also lock"
    } else {
        "lock"
    };
    Some((
        file,
        format!(
            "the NuGet locks {also} {} at {}, while {cfg_rel} routes every version of it to \
             {serves}, so those target frameworks cannot restore",
            src.id,
            listed.join(", ")
        ),
    ))
}

/// Push `r`, marked [`UnattestedKind::NugetLockOtherVersion`] when the
/// locks also hold another version ([`other_versions`]): still a ref, so
/// rollback, remove and the ledgers' liveness gates see the wiring (which
/// a re-run cannot clear either), but never attested.
fn push_ref(out: &mut Discovery, r: PatchedRef, other: Option<OtherVersion>) {
    if let Some((file, detail)) = other {
        out.unattested(
            &r.purl,
            &r.uuid,
            &file,
            detail,
            UnattestedKind::NugetLockOtherVersion,
        );
    }
    out.push(r);
}

// ── refs ─────────────────────────────────────────────────────────────────

async fn emit(
    ctx: &DiscoverCtx<'_>,
    cfg_rel: &str,
    src: &SocketSource,
    lock: &Lock,
    exclusive: bool,
    out: &mut Discovery,
) {
    let SocketSource {
        key,
        uuid,
        value,
        id,
    } = src;
    if let Some((eco, dir_uuid)) = vendor_uuid_dir(value) {
        if eco != "nuget" || dir_uuid != *uuid {
            // The value is this project's vendor tree, so the key names a
            // Socket patch too — rejected (discover rule 11).
            ctx.recognize_paired_name(cfg_rel, uuid, WiringMode::Vendored);
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!(
                    "{cfg_rel}: Socket patch source {key} points at {value:?}, not this patch's \
                     {VENDOR_DIR}/nuget/{uuid} feed"
                ),
            );
            return;
        }
        emit_vendored(ctx, cfg_rel, src, lock, out).await;
        return;
    }
    match ctx.hosted_uuid(value) {
        Some(url_uuid) if url_uuid == *uuid => emit_hosted(cfg_rel, src, lock, exclusive, out),
        Some(url_uuid) => {
            // The value is on the Socket host, so the key's uuid is a Socket
            // identity too, and this pairing is rejected (rule 11) — else
            // the mapping's `key` text would revive a ledger record for it.
            ctx.recognize_paired_name(cfg_rel, uuid, WiringMode::Hosted);
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!(
                    "{cfg_rel}: Socket patch source {key} serves {value}, which names patch \
                     {url_uuid}, not {uuid}"
                ),
            )
        }
        None => out.diag(
            DIAG_REF_INVALID,
            cfg_rel,
            format!(
                "{cfg_rel}: Socket patch source {key} (package {id}) points at {value:?}, which \
                 is neither a Socket patch server url nor this project's \
                 {VENDOR_DIR}/nuget/{uuid} feed"
            ),
        ),
    }
}

/// Hosted refs for `src`: one per `packages.lock.json` version of its id.
/// With NO lock at all (NuGet writes one only under
/// `RestorePackagesWithLockFile`, so this is `rewrite_nuget`'s ordinary
/// output for most projects) the exclusive exact-id mapping still routes
/// every restore of the id to the Socket source, which serves only the
/// patched version: that is recorded as an [`UnlockedPin`] — live wiring
/// for a redirect-ledger record of the id ([`Discovery::hosted_claim`]) —
/// though still no ref (no version to attest on its own).
fn emit_hosted(
    cfg_rel: &str,
    src: &SocketSource,
    lock: &Lock,
    exclusive: bool,
    out: &mut Discovery,
) {
    let locks = match lock {
        Lock::Unusable => return,
        Lock::Absent => {
            if exclusive {
                out.unlocked_pin(UnlockedPin {
                    ecosystem: "nuget".to_string(),
                    name: src.id.clone(),
                    uuid: src.uuid.clone(),
                    file: cfg_rel.into(),
                    version_reqs: Vec::new(),
                    index_url: Some(src.value.clone()),
                });
            }
            None
        }
        Lock::Parsed(index) => index
            .get(&src.id.to_ascii_lowercase())
            .filter(|locks| !locks.versions.is_empty()),
    };
    let Some(locks) = locks else {
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            cfg_rel,
            format!(
                "{cfg_rel}: Socket patch source {} routes {} to patch {}, but no {PACKAGES_LOCK} \
                 entry pins which version it resolves",
                src.key, src.id, src.uuid
            ),
        );
        return;
    };
    let serves = format!(
        "Socket patch source {}, which serves only the patched version",
        src.key
    );
    for row in lock_rows(locks, src, cfg_rel, out) {
        let Some(purl) = simple_purl("nuget", &src.id, &row.spelling) else {
            out.diag(
                DIAG_REF_INVALID,
                PACKAGES_LOCK,
                format!(
                    "{PACKAGES_LOCK}: {} resolves to the unusable version {:?}",
                    src.id, row.spelling
                ),
            );
            continue;
        };
        let other = other_versions(locks, &row.norm, src, &serves, cfg_rel);
        push_ref(
            out,
            PatchedRef::hosted(
                purl,
                src.uuid.clone(),
                cfg_rel,
                Some(&src.value),
                row.integrity,
                true,
            ),
            other,
        );
    }
}

/// Vendored refs for `src`. The feed names the patched version: the writer
/// vendors exactly one `<idLower>.<versionNorm>.nupkg` per patch, so with a
/// single nupkg for the id the ref is that version alone — pinned by the
/// lock's entries at it, if any — and a lock entry at any other version is
/// reported through [`other_versions`], never as a ref of its own (no
/// artifact serves it). Without one, the lock's versions are the refs.
async fn emit_vendored(
    ctx: &DiscoverCtx<'_>,
    cfg_rel: &str,
    src: &SocketSource,
    lock: &Lock,
    out: &mut Discovery,
) {
    let id_lower = src.id.to_ascii_lowercase();
    let locks = match lock {
        Lock::Parsed(index) => index.get(&id_lower),
        Lock::Absent | Lock::Unusable => None,
    };
    let serves = format!("the vendored feed {VENDOR_DIR}/nuget/{}", src.uuid);
    // (purl version, artifact leaf, integrity, other versions)
    let mut rows: Vec<(String, String, Option<LockIntegrity>, Option<OtherVersion>)> = Vec::new();
    let leaves = feed_leaves(ctx, &src.uuid, &id_lower).await;
    if let [(leaf, version)] = leaves.as_slice() {
        let norm = normalize_nuget_version(version);
        match locks {
            Some(locks) => {
                let serves = format!("{serves}, which serves only {version}");
                let other = other_versions(locks, &norm, src, &serves, cfg_rel);
                let locked = lock_rows(locks, src, cfg_rel, out)
                    .into_iter()
                    .find(|row| row.norm == norm);
                match locked {
                    Some(row) => {
                        let leaf = nupkg_leaf(&id_lower, &row.spelling);
                        rows.push((row.spelling, leaf, row.integrity, other));
                    }
                    // Locked at conflicting hashes: diagnosed, no ref.
                    None if locks.versions.contains_key(&norm) => {}
                    // Not locked at the patched version: the feed's own
                    // artifact, unpinned — still the writer's wiring.
                    None => rows.push((version.clone(), leaf.clone(), None, other)),
                }
            }
            None => rows.push((version.clone(), leaf.clone(), None, None)),
        }
    } else if let Some(locks) = locks.filter(|locks| !locks.versions.is_empty()) {
        // No single feed nupkg to name the patched version: every locked
        // version is a ref, checked against its own version as hosted.
        let serves = format!("{serves}, which serves only the patched version");
        for row in lock_rows(locks, src, cfg_rel, out) {
            let other = other_versions(locks, &row.norm, src, &serves, cfg_rel);
            let leaf = nupkg_leaf(&id_lower, &row.spelling);
            rows.push((row.spelling, leaf, row.integrity, other));
        }
    } else {
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            cfg_rel,
            format!(
                "{cfg_rel}: Socket patch source {} routes {} to the vendored feed \
                 {VENDOR_DIR}/nuget/{}, which holds {} {} for it and no \
                 {PACKAGES_LOCK} entry says which version is restored",
                src.key,
                src.id,
                src.uuid,
                leaves.len(),
                if leaves.len() == 1 { "nupkg" } else { "nupkgs" },
            ),
        );
        return;
    }
    for (version, leaf, integrity, other) in rows {
        let artifact = format!("{VENDOR_DIR}/nuget/{}/{leaf}", src.uuid);
        let (Some(purl), Some(vref)) = (
            simple_purl("nuget", &src.id, &version),
            vendor_ref(&artifact),
        ) else {
            out.diag(
                DIAG_REF_INVALID,
                cfg_rel,
                format!(
                    "{cfg_rel}: {} {version:?} (Socket patch source {}) does not name a usable \
                     vendored artifact",
                    src.id, src.key
                ),
            );
            continue;
        };
        push_ref(
            out,
            PatchedRef::vendored(purl, &vref, cfg_rel, integrity),
            other,
        );
    }
}

/// `(leaf, version)` of every regular `<id>.<version>.nupkg` in the vendored
/// feed dir (id compared case-insensitively, version digit-leading and in
/// NuGet's version charset), sorted.
async fn feed_leaves(ctx: &DiscoverCtx<'_>, uuid: &str, id_lower: &str) -> Vec<(String, String)> {
    // `uuid` passed the canonical grammar (socket_patch_name_uuid), so the
    // join cannot escape `.socket/vendor/nuget/`.
    // The vendored feed is a dir of packages: only a disk has one.
    let Some(root) = ctx.disk_root() else {
        return Vec::new();
    };
    let dir = root.join(VENDOR_DIR).join("nuget").join(uuid);
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
        return Vec::new();
    };
    let prefix = format!("{id_lower}.");
    let mut leaves = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.file_type().await.is_ok_and(|t| t.is_file()) {
            continue;
        }
        let Some(stem) = name.strip_suffix(".nupkg") else {
            continue;
        };
        // `get`, not indexing: a multi-byte name must not split a char.
        if stem.len() <= prefix.len()
            || !stem
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(&prefix))
        {
            continue;
        }
        let version = &stem[prefix.len()..];
        let version_ok = version.starts_with(|c: char| c.is_ascii_digit())
            && version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
        if version_ok {
            leaves.push((name.clone(), version.to_string()));
        }
    }
    leaves.sort();
    leaves
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    /// Base64 sha512-shaped content hash (the lock's `contentHash`).
    const HASH: &str = "UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==";

    /// The hosted index url `rewrite_nuget` writes.
    fn index_url(uuid: &str) -> String {
        format!("https://patch.socket.dev/patch-registry/nuget/{TOKEN}/{uuid}/index.json")
    }

    /// A config with `sources` (`(key, value)`) and `mappings`
    /// (`(key, pattern)`), in the writers' layout.
    fn config(sources: &[(&str, &str)], mappings: &[(&str, &str)]) -> String {
        let mut s = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n",
        );
        for (k, v) in sources {
            s.push_str(&format!("    <add key=\"{k}\" value=\"{v}\" />\n"));
        }
        s.push_str("  </packageSources>\n  <packageSourceMapping>\n");
        for (k, p) in mappings {
            s.push_str(&format!(
                "    <packageSource key=\"{k}\">\n      <package pattern=\"{p}\" />\n    </packageSource>\n"
            ));
        }
        s.push_str("  </packageSourceMapping>\n</configuration>\n");
        s
    }

    fn lock(entries: &[(&str, &str, &str, Option<&str>)]) -> String {
        // (tfm, id, resolved, contentHash)
        let mut deps = serde_json::Map::new();
        for (tfm, id, resolved, hash) in entries {
            let fw = deps
                .entry(tfm.to_string())
                .or_insert_with(|| serde_json::json!({}));
            let mut e = serde_json::json!({
                "type": "Direct",
                "requested": format!("[{resolved}, )"),
                "resolved": resolved,
            });
            if let Some(h) = hash {
                e["contentHash"] = serde_json::json!(h);
            }
            fw.as_object_mut().unwrap().insert(id.to_string(), e);
        }
        serde_json::json!({ "version": 1, "dependencies": deps }).to_string()
    }

    fn socket_key(uuid: &str) -> String {
        format!("socket-patch-{uuid}")
    }

    fn feed(uuid: &str) -> String {
        format!(".socket/vendor/nuget/{uuid}")
    }

    const ORG: (&str, &str) = ("nuget.org", "https://api.nuget.org/v3/index.json");

    /// Every committed `rewrite_nuget` golden output (fresh mapping, an
    /// existing corp feed fanned out, empty and self-closing
    /// `<packageSources>`): the patch uuid, never the uuid-shaped-free token
    /// level, with the re-pinned contentHash.
    #[tokio::test]
    async fn golden_hosted_fixtures_yield_the_patch_uuid() {
        for case in [
            "basic",
            "no-preexisting-mapping",
            "empty-sources",
            "empty-sources-selfclosing",
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/nuget/packages-lock/{case}/expected"));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[(
                    "pkg:nuget/newtonsoft.json@13.0.3",
                    "66666666-6666-6666-6666-666666666666",
                    WiringMode::Hosted,
                )],
            );
            let r = &out.refs[0];
            assert_eq!(r.source_file, std::path::PathBuf::from("nuget.config"));
            assert!(r.integrity_required, "{case}");
            assert!(r.lockfile_basis_ok(), "{case}: the lock pins contentHash");
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sri(
                    "sha512-PATCHEDcontenthashbase64PATCHEDcontenthashbase64PATCHEDcontenthashbase64PATCHEDcontenthashbase64PATCHEDcontenthashAA==".into()
                )),
                "{case}"
            );
            assert!(r.url.as_deref().unwrap().ends_with("/index.json"));
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// The INPUT side of the same fixtures (pre-redirect) wires nothing and
    /// says nothing: a registry-only project.
    #[tokio::test]
    async fn registry_only_configs_produce_nothing() {
        for case in ["basic", "no-preexisting-mapping", "empty-sources"] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/nuget/packages-lock/{case}/input"));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
        // A corp feed mapped by id — not Socket.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[ORG, ("corp", "https://nuget.corp.example/v3/index.json")],
                &[("nuget.org", "*"), ("corp", "Contoso.Widgets")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Contoso.Widgets", "1.0.0", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The orchestrator runs this extractor.
    #[tokio::test]
    async fn orchestrator_discovers_the_golden_fixture() {
        let p = Project::new();
        p.copy_fixture("redirect/nuget/packages-lock/basic/expected");
        let out = p.discover().await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3",
                "66666666-6666-6666-6666-666666666666",
                WiringMode::Hosted,
            )],
        );
    }

    /// `vendor::nuget_feed`'s from-scratch config (nuget.org seeded first,
    /// our source second) with a lock: version + pin from the lock, the
    /// artifact is the writer's `<idLower>.<versionNorm>.nupkg` leaf.
    #[tokio::test]
    async fn vendored_fresh_config_with_lock() {
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[ORG, (&socket_key(UUID_A), &feed(UUID_A))],
                &[("nuget.org", "*"), (&socket_key(UUID_A), "Newtonsoft.Json")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
                ("net8.0", "newtonsoft.json", "13.0.3", Some(HASH)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3",
                UUID_A,
                WiringMode::Vendored,
            )],
        );
        let r = &out.refs[0];
        assert_eq!(
            r.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/nuget/{UUID_A}/newtonsoft.json.13.0.3.nupkg").as_str())
        );
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::Sri(format!("sha512-{HASH}")))
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The leaf uses the writer's version normalization (4th zero segment
    /// dropped, lowercased pre-release) while the purl keeps the lock's
    /// resolved spelling.
    #[tokio::test]
    async fn vendored_leaf_uses_the_writers_version_normalization() {
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[ORG, (&socket_key(UUID_A), &feed(UUID_A))],
                &[("nuget.org", "*"), (&socket_key(UUID_A), "Contoso.Widgets")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Contoso.Widgets", "2.1.0.0-RC1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/contoso.widgets@2.1.0.0-rc1",
                UUID_A,
                WiringMode::Vendored,
            )],
        );
        assert_eq!(
            out.refs[0].artifact_rel.as_deref(),
            Some(format!(".socket/vendor/nuget/{UUID_A}/contoso.widgets.2.1.0-rc1.nupkg").as_str())
        );
    }

    /// No lock (NuGet writes one only on opt-in): the version comes from the
    /// feed's single nupkg for the id, split at the KNOWN id — an id with a
    /// digit-leading segment (`Foo.2D`) would fool a first-digit split.
    #[tokio::test]
    async fn vendored_without_lock_reads_the_feed_leaf() {
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[ORG, (&socket_key(UUID_A), &feed(UUID_A))],
                &[("nuget.org", "*"), (&socket_key(UUID_A), "Foo.2D")],
            ),
        );
        p.write(
            &format!(".socket/vendor/nuget/{UUID_A}/foo.2d.1.0.0.nupkg"),
            b"PK",
        );
        p.write(
            &format!(".socket/vendor/nuget/{UUID_A}/socket-patch.vendor.json"),
            b"{}",
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:nuget/foo.2d@1.0.0", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(
            out.refs[0].artifact_rel.as_deref(),
            Some(format!(".socket/vendor/nuget/{UUID_A}/foo.2d.1.0.0.nupkg").as_str())
        );
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// No lock and an empty or ambiguous feed: which version is restored is
    /// unknowable — unattributable, no ref. A lock that is present but
    /// lacks the id falls back to the feed the same way.
    #[tokio::test]
    async fn vendored_feed_without_a_single_nupkg_is_unattributable() {
        let cfg = config(
            &[ORG, (&socket_key(UUID_A), &feed(UUID_A))],
            &[("nuget.org", "*"), (&socket_key(UUID_A), "Newtonsoft.Json")],
        );
        let p = Project::new();
        p.write("nuget.config", &cfg);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);

        let p = Project::new();
        p.write("nuget.config", &cfg);
        for v in ["13.0.1", "13.0.3"] {
            p.write(
                &format!(".socket/vendor/nuget/{UUID_A}/newtonsoft.json.{v}.nupkg"),
                b"PK",
            );
        }
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);

        // A lock for another project's packages: fall back to the feed.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Serilog", "3.0.0", Some(HASH))]),
        );
        p.write(
            &format!(".socket/vendor/nuget/{UUID_A}/newtonsoft.json.13.0.3.nupkg"),
            b"PK",
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3",
                UUID_A,
                WiringMode::Vendored,
            )],
        );
    }

    /// Both writers into one existing config (a project mapping + the
    /// catch-all already present): a hosted and a vendored patch side by
    /// side, each attributed to its own id.
    #[tokio::test]
    async fn hosted_and_vendored_sources_in_one_config() {
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[
                    (&socket_key(UUID_A), &index_url(UUID_A)),
                    ORG,
                    (&socket_key(UUID_B), &feed(UUID_B)),
                ],
                &[
                    (&socket_key(UUID_A), "Newtonsoft.Json"),
                    ("nuget.org", "*"),
                    (&socket_key(UUID_B), "Serilog"),
                ],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[
                ("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH)),
                ("net8.0", "Serilog", "3.0.0", Some("U0VSSUxPRw==")),
                ("net8.0", "Other", "1.0.0", Some("T1RIRVI=")),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (
                    "pkg:nuget/newtonsoft.json@13.0.1",
                    UUID_A,
                    WiringMode::Hosted,
                ),
                ("pkg:nuget/serilog@3.0.0", UUID_B, WiringMode::Vendored),
            ],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// NuGet's other config spellings are read (the first present wins).
    #[tokio::test]
    async fn alternate_config_spellings_are_read() {
        for name in ["NuGet.config", "NuGet.Config"] {
            let p = Project::new();
            p.write(
                name,
                config(
                    &[(&socket_key(UUID_A), &index_url(UUID_A))],
                    &[(&socket_key(UUID_A), "Newtonsoft.Json")],
                ),
            );
            p.write(
                "packages.lock.json",
                lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
            );
            let out = run(&p).await;
            assert_refs(
                &out,
                &[(
                    "pkg:nuget/newtonsoft.json@13.0.1",
                    UUID_A,
                    WiringMode::Hosted,
                )],
            );
        }
    }

    /// Hand-edit tolerance: single quotes, whitespace around `=`, attribute
    /// order, entities, comments, a BOM and a namespace-free DOCTYPE.
    #[tokio::test]
    async fn hand_edited_xml_spellings_are_tolerated() {
        let url = index_url(UUID_A).replace('/', "&#x2F;");
        let key = socket_key(UUID_A);
        let text = format!(
            "\u{feff}<?xml version='1.0'?>\n<!DOCTYPE configuration>\n<configuration >\n\
             <!-- <packageSources><add key=\"{k2}\" value=\"{u2}\"/></packageSources> -->\n\
             <packageSources >\n  <add value = '{url}'  key = '{key}'/>\n</packageSources>\n\
             <packageSourceMapping>\n  <packageSource key='{key}' >\n    \
             <package pattern = 'Newtonsoft.Json' ></package>\n  </packageSource>\n\
             </packageSourceMapping>\n</configuration >\n",
            k2 = socket_key(UUID_B),
            u2 = index_url(UUID_B),
        );
        let p = Project::new();
        p.write("nuget.config", text);
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.1",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A commented-out wiring is invisible to NuGet and to us.
    #[tokio::test]
    async fn commented_out_wiring_is_ignored() {
        let live = config(&[ORG], &[("nuget.org", "*")]);
        let dead = config(
            &[(&socket_key(UUID_A), &index_url(UUID_A))],
            &[(&socket_key(UUID_A), "Newtonsoft.Json")],
        )
        .replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n", "");
        let p = Project::new();
        p.write(
            "nuget.config",
            live.replace(
                "</configuration>",
                &format!("<!--\n{dead}-->\n</configuration>"),
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        // Silently skipped, yet RECOGNIZED: the commented-out wiring still
        // names the patch, and must not keep a ledger record alive.
        assert_eq!(
            out.hosted_claim("pkg:nuget/newtonsoft.json@13.0.1", UUID_A),
            Some(false)
        );
    }

    /// A uuid in a non-Socket host's url is not a ref; a placeholder token
    /// path has no canonical uuid at all. Both are Socket-KEYED, so both
    /// are diagnosed.
    #[tokio::test]
    async fn foreign_host_and_placeholder_urls_are_rejected() {
        for url in [
            format!("https://evil.example/patch-registry/nuget/{TOKEN}/{UUID_A}/index.json"),
            "https://patch.socket.dev/patch-registry/nuget/tok/uuid/index.json".to_string(),
            format!("http://patch.socket.dev/patch-registry/nuget/{TOKEN}/{UUID_A}/index.json"),
            format!(
                "https://user@patch.socket.dev/patch-registry/nuget/{TOKEN}/{UUID_A}/index.json"
            ),
        ] {
            let p = Project::new();
            p.write(
                "nuget.config",
                config(
                    &[(&socket_key(UUID_A), &url), ORG],
                    &[(&socket_key(UUID_A), "Newtonsoft.Json"), ("nuget.org", "*")],
                ),
            );
            p.write(
                "packages.lock.json",
                lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{url}");
        }
    }

    /// The grant token level can itself be uuid-shaped: the LAST uuid
    /// segment is the patch, and it must agree with the key.
    #[tokio::test]
    async fn uuid_shaped_grant_token_is_not_the_patch() {
        // Key names the real patch (after the token): a ref for it.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[(&socket_key(UUID_A), &index_url(UUID_A))],
                &[(&socket_key(UUID_A), "Newtonsoft.Json")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.1",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
        // Key names the TOKEN: key and url disagree — no ref.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[(&socket_key(TOKEN), &index_url(UUID_A))],
                &[(&socket_key(TOKEN), "Newtonsoft.Json")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        let purl = "pkg:nuget/newtonsoft.json@13.0.1";
        assert_eq!(out.hosted_claim(purl, UUID_A), Some(false));

        // A key naming a patch the (Socket-host) url does not: the pairing is
        // rejected, and because it is host-verified the KEY's uuid is
        // recognized as well — the mapping's key text cannot revive a ledger
        // record for it (rule 11). A bare name alone would not count.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[(&socket_key(UUID_B), &index_url(UUID_A))],
                &[(&socket_key(UUID_B), "Newtonsoft.Json")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(out.hosted_claim(purl, UUID_B), Some(false));
        assert_eq!(
            out.recognized_files(UUID_B, WiringMode::Hosted),
            vec![std::path::Path::new("nuget.config")]
        );
    }

    /// `--patch-server-url` origins count as hosted.
    #[tokio::test]
    async fn configured_patch_server_origin_is_hosted() {
        let url = format!("http://127.0.0.1:4545/patch-registry/nuget/{TOKEN}/{UUID_A}/index.json");
        let p = Project::new().with_origin("http://127.0.0.1:4545");
        p.write(
            "nuget.config",
            config(
                &[(&socket_key(UUID_A), &url)],
                &[(&socket_key(UUID_A), "Newtonsoft.Json")],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.1",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
    }

    /// Rule 10: a definition without its mapping pins nothing; a mapping
    /// without its definition cannot restore; a disabled source serves
    /// nothing. None is a ref.
    #[tokio::test]
    async fn definitions_mappings_and_disabled_sources_alone_are_not_refs() {
        let lockfile = lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]);
        // Definition only (the mapping was reverted).
        let p = Project::new();
        p.write(
            "nuget.config",
            config(&[(&socket_key(UUID_A), &index_url(UUID_A)), ORG], &[]),
        );
        p.write("packages.lock.json", &lockfile);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        // No <packageSourceMapping> element at all.
        let p = Project::new();
        p.write(
            "nuget.config",
            format!(
                "<configuration><packageSources><add key=\"{}\" value=\"{}\"/></packageSources></configuration>",
                socket_key(UUID_A),
                index_url(UUID_A)
            ),
        );
        p.write("packages.lock.json", &lockfile);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        // Mapping only.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(&[ORG], &[(&socket_key(UUID_A), "Newtonsoft.Json")]),
        );
        p.write("packages.lock.json", &lockfile);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        // Disabled.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[(&socket_key(UUID_A), &index_url(UUID_A))],
                &[(&socket_key(UUID_A), "Newtonsoft.Json")],
            )
            .replace(
                "</configuration>",
                &format!(
                    "  <disabledPackageSources>\n    <add key=\"{}\" value=\"True\" />\n  \
                     </disabledPackageSources>\n</configuration>",
                    socket_key(UUID_A)
                ),
            ),
        );
        p.write("packages.lock.json", &lockfile);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// `<add>` elements outside `configuration/packageSources` define no
    /// source (other sections reuse the element name).
    #[tokio::test]
    async fn add_elements_in_other_sections_define_nothing() {
        let key = socket_key(UUID_A);
        let text = format!(
            "<configuration>\n  <config>\n    <add key=\"{key}\" value=\"{url}\" />\n  </config>\n  \
             <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
             </packageSources>\n</configuration>\n",
            url = index_url(UUID_A)
        );
        let p = Project::new();
        p.write("nuget.config", text);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A Socket source serves ONE id: a wildcard or several patterns are
    /// unattributable.
    #[tokio::test]
    async fn wildcard_or_multiple_patterns_are_unattributable() {
        for patterns in [
            vec!["Newtonsoft.*"],
            vec!["*"],
            vec!["Newtonsoft.Json", "Serilog"],
        ] {
            let key = socket_key(UUID_A);
            let mappings: Vec<(&str, &str)> = patterns.iter().map(|p| (key.as_str(), *p)).collect();
            let p = Project::new();
            p.write(
                "nuget.config",
                config(&[(&key, &index_url(UUID_A))], &mappings),
            );
            p.write(
                "packages.lock.json",
                lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_REF_UNATTRIBUTABLE],
                "{patterns:?}"
            );
        }
    }

    /// Hosted refs need a version: no lock, or a lock without the id, is
    /// unattributable (a lockless exclusive mapping only keeps a ledger
    /// record live). A pin-less entry is a ref that cannot use the
    /// lockfile basis; divergent hashes for one version are invalid.
    #[tokio::test]
    async fn hosted_version_and_pin_come_from_the_lock() {
        let cfg = config(
            &[(&socket_key(UUID_A), &index_url(UUID_A))],
            &[(&socket_key(UUID_A), "Newtonsoft.Json")],
        );
        let p = Project::new();
        p.write("nuget.config", &cfg);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        // No ref (no version to attest), but with NO lock at all this is
        // `rewrite_nuget`'s ordinary output for a project without
        // RestorePackagesWithLockFile: the exclusive exact-id mapping routes
        // every restore of the id to the Socket source, so a redirect-ledger
        // record for that id (any spelling) is live — and one for another
        // package or patch is not.
        assert_eq!(
            out.hosted_claim("pkg:nuget/Newtonsoft.Json@13.0.1", UUID_A),
            Some(true)
        );
        assert_eq!(
            out.hosted_claim("pkg:nuget/serilog@3.0.0", UUID_A),
            Some(false)
        );
        // A second source mapping the same exact id ties with ours: without a
        // lock's contentHash NuGet may restore it from either, so dead.
        let tied = config(
            &[
                (&socket_key(UUID_A), &index_url(UUID_A)),
                ("nuget.org", "https://api.nuget.org/v3/index.json"),
            ],
            &[
                (&socket_key(UUID_A), "Newtonsoft.Json"),
                ("nuget.org", "newtonsoft.json"),
            ],
        );
        let p = Project::new();
        p.write("nuget.config", &tied);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(
            out.hosted_claim("pkg:nuget/newtonsoft.json@13.0.1", UUID_A),
            Some(false)
        );

        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Serilog", "3.0.0", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        assert_eq!(
            out.hosted_claim("pkg:nuget/newtonsoft.json@13.0.1", UUID_A),
            Some(false)
        );

        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", None)]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.1",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(!out.refs[0].lockfile_basis_ok());

        // One TFM pinned, another not: not a Socket-written pin.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.1", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", "13.0.1", None),
            ]),
        );
        let out = run(&p).await;
        assert!(!out.refs[0].lockfile_basis_ok());

        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.1", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", "13.0.1", Some("T1RIRVI=")),
            ]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// #353 / #514: with no root lock, the version and pin come from the
    /// member-project (or named) lock the root config governs.
    #[tokio::test]
    async fn hosted_version_and_pin_come_from_a_member_lock() {
        let cfg = config(
            &[(&socket_key(UUID_A), &index_url(UUID_A))],
            &[(&socket_key(UUID_A), "Newtonsoft.Json")],
        );
        for (project, lock_rel) in [
            ("src/App/App.csproj", "src/App/packages.lock.json"),
            ("app.csproj", "packages.app.lock.json"),
        ] {
            let p = Project::new();
            p.write("nuget.config", &cfg);
            p.write(project, "<Project />");
            p.write(
                lock_rel,
                lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
            );
            let out = run(&p).await;
            assert_refs(
                &out,
                &[(
                    "pkg:nuget/newtonsoft.json@13.0.1",
                    UUID_A,
                    WiringMode::Hosted,
                )],
            );
            assert!(out.refs[0].lockfile_basis_ok(), "{lock_rel}");
        }
        // A project whose lock cannot be located: no ref is read off a
        // partial lock set (the writers refuse such a tree too).
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "app.csproj",
            "<Project><PropertyGroup><NuGetLockFilePath>$(X).json</NuGetLockFilePath></PropertyGroup></Project>",
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(
            diag_codes(&out).contains(&DIAG_LOCKFILE_UNREADABLE),
            "{:?}",
            diag_codes(&out)
        );
    }

    /// Two Socket sources mapping the same id are both emitted — precedence
    /// is the CLI's `wiring_conflict` gate, not the extractor's.
    #[tokio::test]
    async fn two_sources_for_one_id_are_both_reported() {
        let p = Project::new();
        p.write(
            "nuget.config",
            config(
                &[
                    (&socket_key(UUID_A), &index_url(UUID_A)),
                    (&socket_key(UUID_B), &index_url(UUID_B)),
                ],
                &[
                    (&socket_key(UUID_A), "Newtonsoft.Json"),
                    (&socket_key(UUID_B), "Newtonsoft.Json"),
                ],
            ),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (
                    "pkg:nuget/newtonsoft.json@13.0.1",
                    UUID_A,
                    WiringMode::Hosted,
                ),
                (
                    "pkg:nuget/newtonsoft.json@13.0.1",
                    UUID_B,
                    WiringMode::Hosted,
                ),
            ],
        );
    }

    /// Malformed files are diagnosed, never a panic, never a ref.
    #[tokio::test]
    async fn malformed_files_are_diagnosed() {
        let key = socket_key(UUID_A);
        for text in [
            format!("<configuration><packageSources><add key=\"{key}\" value=\"x\""),
            "<configuration><packageSources></configuration>".to_string(),
            "<configuration><!-- never closed".to_string(),
            format!(
                "<configuration><packageSources><add key={key} /></packageSources></configuration>"
            ),
            "<configuration><a><b></a></b></configuration>".to_string(),
            "<".repeat(10_000),
            "<a>".repeat(100),
        ] {
            let p = Project::new();
            p.write("nuget.config", &text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_LOCKFILE_UNPARSEABLE],
                "{text:.80}"
            );
        }
        // A malformed lock beside real wiring.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(&[(&key, &index_url(UUID_A))], &[(&key, "Newtonsoft.Json")]),
        );
        p.write("packages.lock.json", "{ not json");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);
        // ...but beside a registry-only config it is not our business.
        let p = Project::new();
        p.write("nuget.config", config(&[ORG], &[]));
        p.write("packages.lock.json", "[1, 2");
        let out = run(&p).await;
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Tokenizer and lock shapes no other test reaches: a CDATA section, a
    /// `false` disabled entry, a keyless `<packageSource>`, a non-object
    /// framework and a project reference beside real wiring; then the three
    /// open-tag refusals.
    #[tokio::test]
    async fn tokenizer_and_lock_edge_shapes() {
        let key = socket_key(UUID_A);
        let text = config(&[(&key, &index_url(UUID_A))], &[(&key, "Newtonsoft.Json")])
            .replace(
                "<packageSources>",
                "<![CDATA[ <add key=\"x\" value=\"y\" /> ]]><packageSources>",
            )
            .replace(
                "</configuration>",
                &format!(
                    "<disabledPackageSources><add key=\"{key}\" value=\"false\" />\
                     </disabledPackageSources><packageSourceMapping><packageSource>\
                     <package pattern=\"x\" /></packageSource></packageSourceMapping>\
                     </configuration>"
                ),
            );
        let lockfile = serde_json::json!({
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": { "resolved": "13.0.3", "contentHash": HASH },
                    "App.Core": { "type": "Project" }
                },
                "net9.0": 5
            }
        })
        .to_string();
        let p = Project::new();
        p.write("nuget.config", &text);
        p.write("packages.lock.json", &lockfile);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        for text in [
            "<configuration>< foo/></configuration>",
            "<configuration =\"x\"></configuration>",
            "<configuration a=\"<\"></configuration>",
        ] {
            let p = Project::new();
            p.write("nuget.config", text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{text}");
        }
    }

    /// Path traversal / wrong-dir feeds and unusable ids are rejected.
    #[tokio::test]
    async fn traversal_and_mismatched_feeds_are_rejected() {
        let key = socket_key(UUID_A);
        let lockfile = lock(&[("net8.0", "Newtonsoft.Json", "13.0.3", Some(HASH))]);
        for value in [
            format!("../.socket/vendor/nuget/{UUID_A}"),
            format!("/abs/.socket/vendor/nuget/{UUID_A}"),
            format!(".socket/vendor/nuget/{UUID_A}/../../../etc"),
            format!(".socket/vendor/nuget/{UUID_B}"),
            format!(".socket/vendor/npm/{UUID_A}"),
            "C:\\feeds\\corp".to_string(),
        ] {
            let p = Project::new();
            p.write(
                "nuget.config",
                config(&[(&key, &value)], &[(&key, "Newtonsoft.Json")]),
            );
            p.write("packages.lock.json", &lockfile);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{value}");
        }
        for id in ["../evil", "a/b", "..", "Newtonsoft.Json&amp;x"] {
            let p = Project::new();
            p.write(
                "nuget.config",
                config(&[(&key, &feed(UUID_A))], &[(&key, id)]),
            );
            p.write("packages.lock.json", &lockfile);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{id}");
        }
        // A lock-resolved version that is not a safe segment.
        let p = Project::new();
        p.write(
            "nuget.config",
            config(&[(&key, &feed(UUID_A))], &[(&key, "Newtonsoft.Json")]),
        );
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "../../x", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// The kinds of the [`Unattested`] marks, per canonical purl.
    fn unattested(out: &Discovery) -> Vec<(String, UnattestedKind)> {
        out.unattested
            .iter()
            .map(|u| (u.purl.clone(), u.kind))
            .collect()
    }

    /// Both writers refuse a lock that locks the mapped id at a version
    /// other than the patched one (`*_nuget_lock_other_version`): the
    /// mapping routes every version to a source serving only the patched
    /// one, so that target framework cannot restore. A hosted url names no
    /// version, so each ref is checked against its own: of two locked
    /// versions (across target frameworks or governed locks) one is
    /// unpatched, and every ref stays (the ledger's liveness, rollback and
    /// remove still see the wiring) but is never attested.
    #[tokio::test]
    async fn hosted_id_locked_at_two_versions_is_unattested() {
        let cfg = config(
            &[(&socket_key(UUID_A), &index_url(UUID_A))],
            &[(&socket_key(UUID_A), "Newtonsoft.Json")],
        );
        let expected = [
            (
                "pkg:nuget/newtonsoft.json@13.0.1",
                UUID_A,
                WiringMode::Hosted,
            ),
            (
                "pkg:nuget/newtonsoft.json@13.0.3",
                UUID_A,
                WiringMode::Hosted,
            ),
        ];
        let marks = vec![
            (
                "pkg:nuget/newtonsoft.json@13.0.1".to_string(),
                UnattestedKind::NugetLockOtherVersion,
            ),
            (
                "pkg:nuget/newtonsoft.json@13.0.3".to_string(),
                UnattestedKind::NugetLockOtherVersion,
            ),
        ];

        // Two target frameworks of one lock.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.1", Some("T1RIRVI=")),
                ("net8.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(&out, &expected);
        assert_eq!(unattested(&out), marks);
        // Each mark names the OTHER version, not its own.
        assert!(
            out.unattested[0]
                .detail
                .contains("also lock Newtonsoft.Json at 13.0.3 (packages.lock.json)"),
            "{}",
            out.unattested[0].detail
        );
        assert!(
            out.unattested[1]
                .detail
                .contains("at 13.0.1 (packages.lock.json)"),
            "{}",
            out.unattested[1].detail
        );
        // Still live wiring for the ledger record of either version.
        assert_eq!(
            out.hosted_claim("pkg:nuget/newtonsoft.json@13.0.3", UUID_A),
            Some(true)
        );

        // The root lock and a member project's lock: each mark names the
        // lock holding the other version.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.3", Some(HASH))]),
        );
        p.write("src/App/App.csproj", "<Project />");
        p.write(
            "src/App/packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some("T1RIRVI="))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &expected);
        assert_eq!(unattested(&out), marks);
        assert_eq!(
            out.unattested[0].file,
            std::path::PathBuf::from("packages.lock.json")
        );
        assert_eq!(
            out.unattested[1].file,
            std::path::PathBuf::from("src/App/packages.lock.json")
        );

        // Other versions are listed in NuGet precedence (13.0.9 before
        // 13.0.10), and the file is the first one's lock.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", "13.0.10", Some("T1RIRVI=")),
            ]),
        );
        p.write("src/App/App.csproj", "<Project />");
        p.write(
            "src/App/packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.9", Some("TklORQ=="))]),
        );
        let out = run(&p).await;
        let mark = out
            .unattested
            .iter()
            .find(|u| u.purl == "pkg:nuget/newtonsoft.json@13.0.3")
            .expect("13.0.3 is unattested");
        assert_eq!(
            mark.file,
            std::path::PathBuf::from("src/App/packages.lock.json")
        );
        assert!(
            mark.detail
                .contains("at 13.0.9 (src/App/packages.lock.json), 13.0.10 (packages.lock.json)"),
            "{}",
            mark.detail
        );

        // One version (the writers' own output) is attested as before.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(&out, &expected[1..]);
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);
    }

    /// The vendored feed names the patched version (its single
    /// `<idLower>.<versionNorm>.nupkg`): the ref is that version alone, and
    /// a lock entry at any other version, beside the patched one or
    /// instead of it, withholds it (the writer's refusal) without becoming
    /// a ref of its own (no artifact serves it).
    #[tokio::test]
    async fn vendored_id_locked_at_another_version_is_unattested() {
        let cfg = config(
            &[ORG, (&socket_key(UUID_A), &feed(UUID_A))],
            &[("nuget.org", "*"), (&socket_key(UUID_A), "Newtonsoft.Json")],
        );
        let nupkg = format!(".socket/vendor/nuget/{UUID_A}/newtonsoft.json.13.0.3.nupkg");
        let patched = [(
            "pkg:nuget/newtonsoft.json@13.0.3",
            UUID_A,
            WiringMode::Vendored,
        )];
        let mark = vec![(
            "pkg:nuget/newtonsoft.json@13.0.3".to_string(),
            UnattestedKind::NugetLockOtherVersion,
        )];

        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(&nupkg, b"PK");
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.1", Some("T1RIRVI=")),
                ("net8.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(&out, &patched);
        assert_eq!(
            out.refs[0].locked_integrity,
            Some(LockIntegrity::Sri(format!("sha512-{HASH}")))
        );
        assert_eq!(unattested(&out), mark);
        assert!(
            out.unattested[0].detail.contains(
                "also lock Newtonsoft.Json at 13.0.1 (packages.lock.json), while nuget.config \
                 routes every version of it to the vendored feed"
            ) && out.unattested[0].detail.contains("serves only 13.0.3"),
            "{}",
            out.unattested[0].detail
        );
        // The ledger's own artifact is still wired (rollback / remove).
        assert_eq!(
            out.vendored_claim("pkg:nuget/newtonsoft.json@13.0.3", UUID_A, &nupkg),
            Some(true)
        );

        // The lock names only another version than the feed serves: the
        // feed's artifact stays the (unpinned, unattested) ref, so the
        // ledger's claim on it stays live.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(&nupkg, b"PK");
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.1", Some("T1RIRVI="))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &patched);
        assert_eq!(out.refs[0].artifact_rel.as_deref(), Some(nupkg.as_str()));
        assert_eq!(out.refs[0].locked_integrity, None);
        assert_eq!(unattested(&out), mark);
        assert!(
            out.unattested[0]
                .detail
                .starts_with("the NuGet locks lock Newtonsoft.Json at 13.0.1"),
            "{}",
            out.unattested[0].detail
        );
        assert_eq!(
            out.vendored_claim("pkg:nuget/newtonsoft.json@13.0.3", UUID_A, &nupkg),
            Some(true)
        );

        // The patched version, in a spelling that normalizes to the feed's.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(&nupkg, b"PK");
        p.write(
            "packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.3.0", Some(HASH))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3.0",
                UUID_A,
                WiringMode::Vendored,
            )],
        );
        assert_eq!(out.refs[0].artifact_rel.as_deref(), Some(nupkg.as_str()));
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);
    }

    /// Versions are keyed through `normalize_nuget_version` of the trimmed
    /// `resolved`, as the writers match them: `13.0.3`, ` 13.0.3` and
    /// `13.0.3.0` in several target frameworks are ONE package, so one ref
    /// whose pin is checked across all, never several refs with
    /// independent pins.
    #[tokio::test]
    async fn non_normalized_version_spellings_are_one_version() {
        let cfg = config(
            &[(&socket_key(UUID_A), &index_url(UUID_A))],
            &[(&socket_key(UUID_A), "Newtonsoft.Json")],
        );
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
                ("net7.0", "Newtonsoft.Json", " 13.0.3 ", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", "13.0.3.0", Some(HASH)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
        assert!(out.refs[0].lockfile_basis_ok());
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        // The two spellings pinned to different bytes: one package with
        // conflicting contentHash values, which NuGet fails to restore. The
        // diagnostic names the locks and the spellings.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH))]),
        );
        p.write("src/App/App.csproj", "<Project />");
        p.write(
            "src/App/packages.lock.json",
            lock(&[("net8.0", "Newtonsoft.Json", "13.0.3.0", Some("T1RIRVI="))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        let detail = &out.diagnostics[0].detail;
        assert!(
            detail.starts_with("packages.lock.json, src/App/packages.lock.json: ")
                && detail.contains("13.0.3 / 13.0.3.0"),
            "{detail}"
        );

        // One spelling pinned, the other not: not a Socket-written pin.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", "13.0.03", None),
            ]),
        );
        let out = run(&p).await;
        assert_eq!(out.refs.len(), 1, "{:#?}", out.refs);
        assert!(!out.refs[0].lockfile_basis_ok());

        // An empty `resolved` is no version to attest (diagnosed), but the
        // writers count it as another version: the ref is withheld.
        let p = Project::new();
        p.write("nuget.config", &cfg);
        p.write(
            "packages.lock.json",
            lock(&[
                ("net6.0", "Newtonsoft.Json", "13.0.3", Some(HASH)),
                ("net8.0", "Newtonsoft.Json", " ", Some(HASH)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:nuget/newtonsoft.json@13.0.3",
                UUID_A,
                WiringMode::Hosted,
            )],
        );
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert_eq!(
            unattested(&out),
            vec![(
                "pkg:nuget/newtonsoft.json@13.0.3".to_string(),
                UnattestedKind::NugetLockOtherVersion,
            )]
        );
    }
}
