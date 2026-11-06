//! Cargo — `Cargo.lock`, `Cargo.toml`, and the project cargo config
//! (`.cargo/config`, which cargo reads IN PREFERENCE to `.cargo/config.toml`
//! when both exist, else `.cargo/config.toml`).
//!
//! ## Hosted (`scan --mode hosted`, `patch::redirect::rewrite_cargo`)
//!
//! The rewriter edits three files together or not at all (it skips a dep
//! entirely when any of them cannot be edited):
//!
//! * `Cargo.toml`: EVERY declaration of the crate (rename-aware, every
//!   dependency table incl. `[target.*]` and `[workspace.dependencies]`)
//!   gains `registry = "socket-patch-<uuid>"` — inline
//!   `{ version = "…", registry = "…" }` or a `registry = "…"` line in the
//!   `[dependencies.<key>]` table form;
//! * `Cargo.lock`: the crate's `[[package]]` gets
//!   `source = "sparse+<index>"` and `checksum = "<sha256 hex of the patched
//!   .crate>"`, where `<index>` is
//!   `https://patch.socket.dev/patch-registry/cargo/<token>/<uuid>/index/`;
//! * the cargo config: the registry DEFINITION
//!   `[registries.socket-patch-<uuid>] index = "sparse+<index>"`.
//!
//! A ref comes from the `Cargo.lock` entry — the resolved identity (exact
//! version, content pin): the source must name a Socket patch server
//! ([`DiscoverCtx::hosted_uuid`]; `sparse+` / `registry+` kinds only), and
//! the uuid is the index's last canonical-uuid segment (the grant token
//! before it may be uuid-shaped). The rewriter always writes the checksum
//! (it skips a dep with no / malformed cksum), so `integrity_required` is
//! set; the checksum becomes [`LockIntegrity::Sha256Hex`]. A v1 lock
//! (cargo < 1.41) files it in `[metadata]` as `"checksum <name> <version>
//! (<source>)"` instead — read as the same pin.
//!
//! The manifests decide whether cargo still USES that entry (rule 10): cargo
//! re-resolves a locked package whose source no longer matches the
//! manifest's declaration. The manifests are the root `Cargo.toml` and every
//! workspace member's (`<dir>/Cargo.toml`, enumerated as the hosted rewriter
//! enumerates the manifests it pins:
//! [`crate::utils::cargo_workspace::member_manifests_in`], minus `.socket/`
//! and `target/`), whose declarations count alike. So for the lock entry's
//! crate:
//!
//! * not declared in any of them (a transitive-only crate; no / unparseable
//!   root manifest) → ref;
//! * some declaration names `socket-patch-<uuid>` (the same uuid) → ref;
//!   the other declarations whose requirement may select the locked
//!   version then decide whether it is attested. One routed to ANOTHER
//!   Socket patch (that the lock does not resolve the crate from) adds a
//!   `Cargo.toml` ref for it — the conflict pair below. One cargo builds
//!   its own copy for — crates.io or another registry not redirected by a
//!   Socket `[patch.<source>]` entry, a `registry-index`, a path or git
//!   (even beside a `socket-patch-<uuid>` registry, which those override:
//!   the hosted rewriter's own pinned check) — marks the ref
//!   [`super::UnattestedKind::CargoUnpinnedDeclaration`], naming its file
//!   and whether a re-scan can pin it: cargo resolves each source on its
//!   own, so that copy is unpatched and may be this very version. The
//!   hosted rewriter pins every declaration, so this is a partial revert or
//!   a hand edit. A `[workspace.dependencies]` template counts only when a
//!   manifest inherits it. When the lock already holds a same-version copy
//!   from another source, the twin rule (`unpatched_twins`, #679) withholds
//!   the ref instead;
//! * declarations pin only OTHER `socket-patch-<V>` registries → the lock
//!   ref AND a `Cargo.toml` ref for `<V>` at the locked version (no pin):
//!   the files disagree and the CLI gates the package as `wiring_conflict`;
//! * declared, but no declaration pins a Socket registry (the pin was
//!   reverted, or moved to a user registry) → no ref, [`DIAG_REF_INVALID`]:
//!   cargo resolves the declared source, never the stale lock entry.
//!
//! `[patch.<source>]` entries carrying `registry = "socket-patch-<uuid>"`
//! (a hand-wired variant cargo honors) count as declarations too. The
//! project config's `[registries.socket-patch-<uuid>]` definition, when
//! present, must index the same patch (project config overrides
//! `$CARGO_HOME`, so a disagreeing definition is what cargo resolves
//! against → [`DIAG_REF_INVALID`], no ref); a missing definition proves
//! nothing (it may live in `$CARGO_HOME/config.toml`). A definition is never
//! a ref by itself, nor is a `Cargo.toml` pin with no Socket-sourced lock
//! entry (no exact version, or a lock that routes the crate elsewhere) →
//! [`DIAG_REF_UNATTRIBUTABLE`].
//!
//! ## Vendored (`vendor`, `vendor::cargo` + `vendor::cargo_manifest`)
//!
//! `Cargo.lock` is the PRIMARY identity signal: the detached entry loses
//! `source` + `checksum` and its version is the copy's TAGGED version
//! `<version>+socket.<uuid>` (`vendor::cargo_lock::detach_lock_entry`,
//! `vendor::cargo_tag`) — what cargo locks for the tagged copy it builds.
//! The purl version is the tag stripped (`pkg:cargo/<name>@<version>`), and
//! the tag's uuid must be the uuid of the wiring's copy path: a sourceless
//! entry tagged for ANOTHER uuid means the copy cargo builds is not the one
//! this wiring names (a config override elsewhere, or a stale `[patch]`) →
//! no ref ([`DIAG_REF_INVALID`]). A tagged entry that no visible wiring
//! names (the `[patch]` lives in a config discovery does not read, or was
//! removed) is [`DIAG_REF_UNATTRIBUTABLE`]. The entry tagged for the path
//! uuid decides whenever one exists (a same-version untagged sibling — the
//! user's own path fork, which cargo locks beside the tagged copy — does
//! not matter); failing that, a tagged sibling for another uuid rejects it.
//! An UNTAGGED sourceless entry alone is a copy vendored before tagged
//! versions and counts only while the copy's own `Cargo.toml` is untagged
//! too: cargo locks a tagged copy at its tagged version, so beside a tagged
//! copy an untagged entry is some OTHER crate cargo built (a `[patch]`
//! override in a config discovery does not read, a path dependency) → no
//! ref ([`DIAG_REF_INVALID`]). A copy whose `Cargo.toml` is tagged for
//! another uuid than its path is no ref either. The wiring is a
//! `[patch.crates-io]` path entry
//! `<key> = { path = ".socket/vendor/cargo/<uuid>/<name>-<version>" }` —
//! PRIMARILY in the root `Cargo.toml` (what v5+ `vendor` writes; `<key>` is
//! the Socket-owned `<name>-socket-<uuid8>` with `package = "<name>"`),
//! and for projects vendored by an older release in the effective project
//! config (pre-v5 wiring; cargo honors both). Matching is KEY-AGNOSTIC:
//! the entry's crate is `package = "…"` when renamed, else the key, and any
//! `[patch.<source>]` table counts (inline, sub-table, or
//! `[patch] crates-io = { … }` forms). The path must be root-anchored
//! ([`vendor_ref`]: a `../` or absolute spelling consumes some OTHER
//! checkout's copy), the leaf a single `<name>-<version>` directory for the
//! entry's crate. The lock is the liveness truth source (the prune GC's
//! in-use verdict, `Discovery::vendor_entry_in_use`, reads it from these
//! refs): when a `Cargo.lock` parses, it
//! must hold a SOURCELESS `[[package]]` for that name + version — an entry
//! with a registry source (re-resolved, or a hosted takeover) or none at
//! all means the copy is not what builds, and so does a
//! `[[patch.unused]]` entry for that name + version (cargo's own record of
//! a `[patch]` left out of the graph — e.g. by the user's path dependency,
//! whose lock entry is sourceless too), so no ref ([`DIAG_REF_INVALID`]).
//! No lock (first build pending) or an unparseable one (cargo refuses to
//! build) keeps the ref. A manifest entry
//! cargo ignores is no ref ([`DIAG_REF_INVALID`]) either: cargo lets a
//! project-config `[patch]` item with the same key replace it (unless that
//! item wires the same path — the half-migrated shape, attested through the
//! config), and a `[patch."<crates.io URL>"]` table in the manifest
//! replaces `[patch.crates-io]` wholesale — both leave the lock looking
//! exactly like live Socket wiring.
//! A `[patch.<source>]` entry replaces the crate only in declarations from
//! `<source>`, so a ref whose build may also compile a copy of the version
//! the wiring does not reach — a live declaration (root or member) from
//! another registry, a `registry-index` or git that may select the version
//! and that no `[patch]` table pointing at this copy redirects, or a
//! same-version lock entry from any source — stays a ref but is marked
//! [`super::UnattestedKind::CargoPatchBypassed`] ([`patch_bypassed`]); the
//! members are read for this whenever a `[patch]` wires a Socket copy.
//! A `.socket/cargo-patches/` path (the retired redirect backend) carries no
//! uuid and is not a ref. Socket-shaped entries in a `.cargo/config.toml`
//! that cargo ignores (because `.cargo/config` exists) are diagnosed, never
//! read.

use std::collections::BTreeMap;

use toml_edit::{DocumentMut, Item, TableLike};

use super::{
    names_vendor_dir, simple_purl, socket_patch_name_uuid, toml_or_diag, vendor_ref, DiscoverCtx,
    Discovery, PatchedRef, TomlDiag, UnattestedKind, UnlockedPin, VendorRef, DIAG_REF_INVALID,
    DIAG_REF_UNATTRIBUTABLE,
};
use crate::formats::cargo::{is_registry_source, CargoLock, CopyClaim, LockedPackage};
use crate::patch::redirect::generation::{hosted_pin_name, PIN_NAME_PREFIX};
use crate::patch::redirect::{cargo_req_selects, CargoReqMatch};
use crate::utils::digest::is_hex64_lower;
use crate::vendor::cargo_config::{
    effective_config_rel_in, patch_entries, registry_definitions, CargoPatchEntry, CONFIG_LEGACY,
    CONFIG_TOML,
};
use crate::vendor::cargo_manifest::{crates_io_url_alias_tables, is_crates_io_source};
use crate::vendor::cargo_tag;
use crate::vendor::lock_inventory::LockIntegrity;

const CARGO_LOCK: &str = "Cargo.lock";
const CARGO_TOML: &str = "Cargo.toml";

/// Manifest dependency-table names (cargo still accepts the deprecated
/// underscore spellings).
const DEP_TABLES: [&str; 5] = [
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
    "dev_dependencies",
    "build_dependencies",
];

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let lock = load_lock(ctx, out).await;
    let root = read_toml(ctx, CARGO_TOML, out).await;
    let config = read_config(ctx, out).await;
    // The root manifest, then every workspace member's — the manifests the
    // hosted rewriter pins a crate in (each that declares it).
    let mut manifests: Vec<(String, DocumentMut)> = Vec::new();
    if let Some(doc) = root {
        let root_pins = manifest_has_socket_pin(&doc);
        // A vendored copy wired in the root or the config is weighed against
        // every member's declarations ([`patch_bypassed`]).
        let vendored = std::iter::once(&doc)
            .chain(config.iter().map(|(_, c)| c))
            .any(|d| !socket_copies(d).is_empty());
        manifests.push((CARGO_TOML.to_string(), doc));
        manifests.extend(read_members(ctx, &lock, root_pins, vendored, out).await);
    }
    let manifest: Option<&DocumentMut> = manifests.first().map(|(_, doc)| doc);

    // Crate name → each declaration of it in the root or a member manifest
    // (its file, `registry` value — `None` = declared with no registry key —
    // and version requirement). Absent map = no usable root manifest.
    let decls = manifest.map(|doc| {
        let mut decls = manifest_declarations(&manifests);
        // `[patch]` is read from the root manifest only: cargo ignores (and
        // warns about) a member's.
        for patch in patch_entries(doc) {
            if let Some(reg) = patch.registry {
                let name = patch.name.to_string();
                decls
                    .entry(name)
                    .or_default()
                    .push(Decl::patch(CARGO_TOML, patch.source, reg));
            }
        }
        decls
    });
    // The config's `[patch]` registry pins are also declarations cargo
    // honors (only matters for crates the manifests also declare).
    let decls = decls.map(|mut decls| {
        if let Some((file, doc)) = &config {
            for patch in patch_entries(doc) {
                if let (Some(reg), Some(existing)) = (patch.registry, decls.get_mut(patch.name)) {
                    existing.push(Decl::patch(file, patch.source, reg));
                }
            }
        }
        decls
    });
    let definitions: BTreeMap<String, String> = config
        .as_ref()
        .map(|(_, doc)| registry_definitions(doc).into_iter().collect())
        .unwrap_or_default();

    hosted_from_lock(ctx, &lock, decls.as_ref(), &definitions, out);
    unpatched_twins(ctx, &lock, out);
    if let Some(decls) = &decls {
        unresolved_manifest_pins(ctx, &lock, decls, &definitions, out);
    }
    let wired: Vec<(String, VendorRef)> = manifest
        .into_iter()
        .chain(config.iter().map(|(_, doc)| doc))
        .flat_map(socket_copies)
        .collect();
    let bypass = Bypass {
        lock: &lock,
        decls: decls.as_ref(),
        wired: &wired,
    };
    if let Some(doc) = manifest {
        // Cargo drops a manifest crates.io `[patch]` item that the project
        // config redefines under the same key (any version), and a
        // `[patch."<crates.io URL>"]` table replaces `[patch.crates-io]`
        // wholesale — a Socket entry there is dead wiring, never attested.
        let config_keys: Vec<(&str, String, Option<String>)> = config
            .iter()
            .flat_map(|(file, doc)| {
                patch_entries(doc)
                    .into_iter()
                    .filter(|e| is_crates_io_source(e.source))
                    .map(move |e| (*file, e.key.to_string(), e.path.map(same_path_key)))
            })
            .collect();
        let aliases = crates_io_url_alias_tables(doc);
        let shadowed = |entry: &CargoPatchEntry<'_>| -> Option<String> {
            if !is_crates_io_source(entry.source) {
                return None;
            }
            if let (true, Some(alias)) = (entry.source == "crates-io", aliases.first()) {
                return Some(format!(
                    "the `[patch.\"{alias}\"]` table replaces `[patch.crates-io]` in cargo"
                ));
            }
            // The same key wiring the same copy (a half-migrated project)
            // is not a shadow: the config's own ref carries it.
            let own = entry.path.map(same_path_key);
            config_keys
                .iter()
                .find(|(_, key, path)| key == entry.key && *path != own)
                .map(|(file, key, _)| {
                    format!("{file} redefines `[patch]` key `{key}`, which replaces it in cargo")
                })
        };
        vendored_from_patches(ctx, CARGO_TOML, doc, &lock, &shadowed, &bypass, out).await;
    }
    if let Some((file, doc)) = &config {
        vendored_from_patches(ctx, file, doc, &lock, &|_| None, &bypass, out).await;
    }
    let copies: Vec<VendorRef> = wired.into_iter().map(|(_, v)| v).collect();
    unattributed_tags(&lock, &copies, out);
}

/// Every Socket copy a file's `[patch]` tables point at, with the
/// `[patch.<source>]` table pointing at it.
fn socket_copies(doc: &DocumentMut) -> Vec<(String, VendorRef)> {
    patch_entries(doc)
        .into_iter()
        .filter_map(|e| Some((e.source.to_string(), e.path.and_then(vendor_ref)?)))
        .filter(|(_, v)| v.eco == "cargo")
        .collect()
}

/// Diagnose Socket-tagged sourceless lock entries that no visible
/// `[patch]` wiring names (`.socket/vendor/cargo/<uuid>/<name>-<version>`):
/// the lock records a vendored copy the files discovery reads cannot
/// attribute, so it is not attested.
fn unattributed_tags(lock: &Lock, wired: &[VendorRef], out: &mut Discovery) {
    for pkg in lock.packages() {
        if pkg.source.is_some() {
            continue;
        }
        let Some((version, uuid)) = cargo_tag::split_tag(&pkg.version) else {
            continue;
        };
        let leaf = format!("{}-{version}", pkg.name);
        if wired.iter().any(|v| v.uuid == uuid && v.leaf == leaf) {
            continue;
        }
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            CARGO_LOCK,
            format!(
                "{CARGO_LOCK}: {} {} is a Socket-vendored copy (patch {uuid}), but no \
                 [patch] entry in {CARGO_TOML} or the project cargo config points at \
                 .socket/vendor/cargo/{uuid}/{leaf}; not counted",
                pkg.name, pkg.version
            ),
        );
    }
}

// ── reads ────────────────────────────────────────────────────────────────

/// The state of the root `Cargo.lock`, read through the format's model
/// ([`CargoLock`]).
#[derive(Debug)]
enum Lock {
    /// No lock (or unreadable — diagnosed by the read).
    Absent,
    /// Present but not TOML (diagnosed).
    Unparseable,
    Parsed(CargoLock),
}

impl Lock {
    fn packages(&self) -> &[LockedPackage] {
        match self {
            Lock::Parsed(lock) => lock.packages(),
            Lock::Absent | Lock::Unparseable => &[],
        }
    }
}

async fn load_lock(ctx: &DiscoverCtx<'_>, out: &mut Discovery) -> Lock {
    let Some(text) = ctx.read_text(CARGO_LOCK, out).await else {
        return Lock::Absent;
    };
    let Some(doc) = parse_toml(CARGO_LOCK, &text, out) else {
        return Lock::Unparseable;
    };
    // v1–v4 all list packages as `[[package]]` (a v1 lock's `[metadata]`
    // checksums read as the same pin the inline v2+ `checksum` is — the
    // hosted rewriter writes it there for a v1 lock); `[[patch.unused]]` is
    // never a package — it is the "not wired" shape, kept apart.
    Lock::Parsed(CargoLock::from_doc(&doc))
}

/// Guarded read + parse of a TOML file (`None`: missing, unreadable, or
/// unparseable — the latter two diagnosed).
async fn read_toml(ctx: &DiscoverCtx<'_>, file: &str, out: &mut Discovery) -> Option<DocumentMut> {
    let text = ctx.read_text(file, out).await?;
    parse_toml(file, &text, out)
}

/// Every workspace member manifest (`<dir>/Cargo.toml`) of the root one,
/// parsed — the set the hosted rewriter pins in
/// ([`crate::utils::cargo_workspace::member_manifests_in`], keeping the
/// keys it accepts: never under `.socket/` — a vendored copy is Socket's,
/// not a declaration — or a build `target/`). Unparseable ones are skipped
/// (diagnosed).
///
/// Members only ever decide about Socket wiring, so the walk is skipped
/// when there is none they could decide about: a parsed lock with no
/// Socket-sourced package, or an unparseable one (no ref either way). With
/// no lock, a member matters only when some manifest carries a
/// `socket-patch-` pin (a lockless pin, [`UnlockedPin`]); the walk has the
/// texts, so the parse is skipped otherwise. `vendored` (the root manifest
/// or the config wires a Socket copy through `[patch]`, whose lock entries
/// are sourceless) always reads them, whatever the lock: a member's
/// declaration from a source the `[patch]` does not redirect bypasses the
/// copy ([`patch_bypassed`]).
async fn read_members(
    ctx: &DiscoverCtx<'_>,
    lock: &Lock,
    root_pins: bool,
    vendored: bool,
    out: &mut Discovery,
) -> Vec<(String, DocumentMut)> {
    let lockless = match lock {
        _ if vendored => false,
        Lock::Parsed(_) if has_socket_sourced(ctx, lock) => false,
        Lock::Parsed(_) | Lock::Unparseable => return Vec::new(),
        Lock::Absent => true,
    };
    let texts: Vec<(String, String)> =
        crate::utils::cargo_workspace::member_manifest_texts_in(&ctx.view)
            .await
            .into_iter()
            .filter(|(rel, _)| crate::patch::redirect::is_cargo_member_manifest_key(rel))
            .collect();
    if lockless && !root_pins && !texts.iter().any(|(_, t)| t.contains(PIN_NAME_PREFIX)) {
        return Vec::new();
    }
    let mut members = Vec::new();
    for (rel, text) in texts {
        ctx.adopt_read(&rel, &text);
        if let Some(doc) = parse_toml(&rel, &text, out) {
            members.push((rel, doc));
        }
    }
    members
}

/// Whether some dependency declaration of `doc` names a `socket-patch-`
/// registry.
fn manifest_has_socket_pin(doc: &DocumentMut) -> bool {
    dependency_entries(doc).iter().any(|d| {
        d.registry
            .as_deref()
            .is_some_and(|r| r.trim().starts_with(PIN_NAME_PREFIX))
    })
}

/// Whether the lock resolves some package from a Socket patch server.
fn has_socket_sourced(ctx: &DiscoverCtx<'_>, lock: &Lock) -> bool {
    lock.packages().iter().any(|p| {
        p.source
            .as_deref()
            .is_some_and(|s| source_uuid(ctx, s).is_some())
    })
}

fn parse_toml(file: &str, text: &str, out: &mut Discovery) -> Option<DocumentMut> {
    toml_or_diag(file, text, TomlDiag::TrimEnd, out).map(toml_edit::Document::into_mut)
}

/// The config file cargo actually reads ([`effective_config_rel_in`]), parsed,
/// with its root-relative name. When `.cargo/config` exists cargo ignores
/// `.cargo/config.toml` entirely (and warns); Socket-shaped wiring left in
/// the ignored file is diagnosed so a "why is my patch not attested" has an
/// answer.
async fn read_config(
    ctx: &DiscoverCtx<'_>,
    out: &mut Discovery,
) -> Option<(&'static str, DocumentMut)> {
    if effective_config_rel_in(ctx.view).await == CONFIG_TOML {
        return read_toml(ctx, CONFIG_TOML, out)
            .await
            .map(|doc| (CONFIG_TOML, doc));
    }
    // Reading the ignored file only to explain it: its parse errors are not
    // cargo's problem, so it is parsed quietly.
    let mut scratch = Discovery::default();
    if let Some(ignored) = read_toml(ctx, CONFIG_TOML, &mut scratch).await {
        let socket_shaped = patch_entries(&ignored)
            .iter()
            .any(|p| p.path.is_some_and(names_vendor_dir))
            || !registry_definitions(&ignored).is_empty();
        if socket_shaped {
            out.diag(
                DIAG_REF_INVALID,
                CONFIG_TOML,
                format!(
                    "{CONFIG_TOML}: its Socket patch wiring is ignored — cargo reads \
                     {CONFIG_LEGACY} instead when both exist"
                ),
            );
        }
    }
    read_toml(ctx, CONFIG_LEGACY, out)
        .await
        .map(|doc| (CONFIG_LEGACY, doc))
}

// ── manifest / config shapes ─────────────────────────────────────────────

/// Where cargo takes one declaration of a crate from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeclSource {
    /// A `[patch.<table>]` entry's `registry` pin: it declares no
    /// dependency, but redirects the declarations cargo resolves from
    /// `<table>` ([`Decl::patched_by`]).
    Patch(String),
    /// A registry dependency: its `registry`, else crates.io.
    Registry,
    /// `registry-index = "<url>"`.
    RegistryIndex(String),
    /// `path = "…"` (cargo builds it locally, whatever `registry` says).
    Path,
    /// `git = "…"`.
    Git,
}

/// One declaration of a crate: the root-relative file holding it, its
/// `registry` value (`None` = no registry key), its version requirement
/// and where cargo takes it from.
#[derive(Debug, Clone)]
struct Decl {
    file: String,
    registry: Option<String>,
    /// The `version` requirement (`None` for a `[patch]` registry pin, or
    /// a declaration without one).
    version: Option<String>,
    source: DeclSource,
    /// `false` for a `[workspace.dependencies]` template no manifest
    /// inherits (`workspace = true`): cargo resolves it for nobody.
    live: bool,
}

impl Decl {
    /// A `[patch.<table>]` entry's registry pin.
    fn patch(file: &str, table: &str, registry: &str) -> Self {
        Decl {
            file: file.to_string(),
            registry: Some(registry.to_string()),
            version: None,
            source: DeclSource::Patch(table.to_string()),
            live: true,
        }
    }

    /// The Socket patch uuid a well-formed `socket-patch-<uuid>` registry
    /// names.
    fn socket_uuid(&self) -> Option<String> {
        socket_patch_name_uuid(self.registry.as_deref()?, false)
    }

    /// Whether the registry is `socket-patch-…`-shaped (well-formed or not).
    fn socket_shaped(&self) -> bool {
        self.registry
            .as_deref()
            .is_some_and(|r| r.trim().starts_with(PIN_NAME_PREFIX))
    }

    /// The Socket patch this declaration itself pins the crate to: a
    /// `socket-patch-<uuid>` registry on a registry dependency or a
    /// `[patch]` entry. Beside `path`, `git` or `registry-index` the
    /// registry key does not decide where cargo takes the crate from (the
    /// hosted rewriter's own pinned check), so that is no pin.
    fn pin(&self) -> Option<String> {
        match self.source {
            DeclSource::Registry | DeclSource::Patch(_) => self.socket_uuid(),
            _ => None,
        }
    }

    /// Whether the `[patch.<table>]` table redirects this declaration:
    /// a registry dependency of that registry (`crates-io`, or a crates.io
    /// URL alias, for one with no `registry`).
    fn patched_by(&self, table: &str) -> bool {
        self.source == DeclSource::Registry
            && match self.registry.as_deref() {
                None => is_crates_io_source(table),
                Some(reg) => reg.trim() == table,
            }
    }

    /// Where cargo takes this dependency from, for messages.
    fn origin(&self) -> String {
        match (&self.source, self.registry.as_deref()) {
            (DeclSource::Git, _) => "a git repository".to_string(),
            (DeclSource::Path, _) => "a local path".to_string(),
            (DeclSource::RegistryIndex(url), _) => format!("the registry index {url}"),
            (_, Some(reg)) => format!("registry `{reg}`"),
            (_, None) => "crates.io".to_string(),
        }
    }
}

/// Crate name → its declarations ([`Decl`]).
type Decls = BTreeMap<String, Vec<Decl>>;

/// Every dependency declaration in `manifests` (root first, then members),
/// keyed by the crate it names (`package = "…"` when renamed, else the
/// key). `workspace = true` inheritors are not declarations of their own —
/// the root's `[workspace.dependencies]` template they inherit is, and it
/// is live only when some manifest inherits its key.
fn manifest_declarations(manifests: &[(String, DocumentMut)]) -> Decls {
    let entries: Vec<(&str, DepEntry)> = manifests
        .iter()
        .flat_map(|(file, doc)| {
            dependency_entries(doc)
                .into_iter()
                .map(move |d| (file.as_str(), d))
        })
        .collect();
    let inherited: Vec<&str> = entries
        .iter()
        .filter(|(_, d)| d.inherits)
        .map(|(_, d)| d.key.as_str())
        .collect();
    let mut decls = Decls::new();
    for (file, dep) in entries.iter().filter(|(_, d)| !d.inherits) {
        let decl = Decl {
            file: file.to_string(),
            registry: dep.registry.clone(),
            version: dep.version.clone(),
            source: dep.source.clone(),
            live: !dep.template || inherited.contains(&dep.key.as_str()),
        };
        decls.entry(dep.name.clone()).or_default().push(decl);
    }
    decls
}

/// The distinct present values, in first-seen order.
fn distinct(values: impl IntoIterator<Item = Option<String>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values.into_iter().flatten() {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// The distinct files among `decls`, in order, joined for a message.
fn decl_files<'a>(decls: impl IntoIterator<Item = &'a Decl>) -> String {
    let mut files: Vec<&str> = Vec::new();
    for d in decls {
        if !files.contains(&d.file.as_str()) {
            files.push(&d.file);
        }
    }
    files.join(", ")
}

/// One manifest dependency entry (see [`manifest_declarations`]).
struct DepEntry {
    /// The table key.
    key: String,
    /// The crate: `package = "…"` when renamed, else the key.
    name: String,
    registry: Option<String>,
    /// The `version` requirement (a bare string entry is one).
    version: Option<String>,
    source: DeclSource,
    /// A `[workspace.dependencies]` template.
    template: bool,
    /// A `workspace = true` inheritor (of the template keyed `key`).
    inherits: bool,
}

fn dependency_entries(doc: &DocumentMut) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut tables: Vec<(&dyn TableLike, bool)> = Vec::new();
    let root = doc.as_table();
    for kind in DEP_TABLES {
        tables.extend(
            root.get(kind)
                .and_then(Item::as_table_like)
                .map(|t| (t, false)),
        );
    }
    if let Some(ws) = root.get("workspace").and_then(Item::as_table_like) {
        tables.extend(
            ws.get("dependencies")
                .and_then(Item::as_table_like)
                .map(|t| (t, true)),
        );
    }
    if let Some(targets) = root.get("target").and_then(Item::as_table_like) {
        for (_, target) in targets.iter() {
            let Some(target) = target.as_table_like() else {
                continue;
            };
            for kind in DEP_TABLES {
                tables.extend(
                    target
                        .get(kind)
                        .and_then(Item::as_table_like)
                        .map(|t| (t, false)),
                );
            }
        }
    }
    for (table, template) in tables {
        for (key, item) in table.iter() {
            let dep = if let Some(version) = item.as_str() {
                DepEntry {
                    key: key.to_string(),
                    name: key.to_string(),
                    registry: None,
                    version: Some(version.to_string()),
                    source: DeclSource::Registry,
                    template,
                    inherits: false,
                }
            } else if let Some(entry) = item.as_table_like() {
                let field = |k: &str| entry.get(k).and_then(Item::as_str).map(str::to_string);
                let source = if entry.contains_key("git") {
                    DeclSource::Git
                } else if entry.contains_key("path") {
                    DeclSource::Path
                } else if let Some(url) = field("registry-index") {
                    DeclSource::RegistryIndex(url)
                } else {
                    DeclSource::Registry
                };
                DepEntry {
                    key: key.to_string(),
                    name: field("package").unwrap_or_else(|| key.to_string()),
                    registry: field("registry"),
                    version: field("version"),
                    source,
                    template,
                    inherits: !template
                        && entry.get("workspace").and_then(Item::as_bool) == Some(true),
                }
            } else {
                continue;
            };
            deps.push(dep);
        }
    }
    deps
}

// ── hosted ───────────────────────────────────────────────────────────────

/// The patch uuid a Cargo.lock `source` routes to, when it is a registry
/// source on a Socket patch server.
fn source_uuid(ctx: &DiscoverCtx<'_>, source: &str) -> Option<String> {
    if !is_registry_source(source) {
        return None; // git / path / local-registry sources are never ours
    }
    ctx.hosted_uuid(source.trim())
}

fn hosted_from_lock(
    ctx: &DiscoverCtx<'_>,
    lock: &Lock,
    decls: Option<&Decls>,
    definitions: &BTreeMap<String, String>,
    out: &mut Discovery,
) {
    for pkg in lock.packages() {
        let Some(source) = pkg.source.as_deref() else {
            continue;
        };
        let Some(uuid) = source_uuid(ctx, source) else {
            continue;
        };
        let Some(purl) = simple_purl("cargo", &pkg.name, &pkg.version) else {
            out.diag(
                DIAG_REF_INVALID,
                CARGO_LOCK,
                format!(
                    "{CARGO_LOCK}: Socket-sourced package {:?}@{:?} has unsafe coordinates",
                    pkg.name, pkg.version
                ),
            );
            continue;
        };
        let reg = hosted_pin_name(&uuid);
        if let Some(index) = definitions.get(&reg) {
            if source_uuid(ctx, index).as_deref() != Some(uuid.as_str()) {
                out.diag(
                    DIAG_REF_INVALID,
                    CARGO_LOCK,
                    format!(
                        "{CARGO_LOCK}: {purl} resolves from Socket patch {uuid}, but the \
                         cargo config defines registry {reg} with a different index \
                         ({index}); not counted"
                    ),
                );
                continue;
            }
        }
        let locked_integrity = pkg
            .checksum
            .as_deref()
            .filter(|c| is_hex64_lower(c))
            .map(|c| LockIntegrity::Sha256Hex(c.to_string()));
        let lock_ref = PatchedRef::hosted(
            purl.clone(),
            uuid.clone(),
            CARGO_LOCK,
            Some(source),
            locked_integrity,
            true,
        );
        let Some(regs) = decls.and_then(|d| d.get(&pkg.name)) else {
            // Declared by no manifest (a transitive-only crate), or no
            // usable root manifest: the lock is the only word.
            out.push(lock_ref);
            continue;
        };
        // Some declaration names this patch's registry (even one a `path`,
        // `git` or `registry-index` overrides): Socket's wiring is present,
        // so the lock ref stands, and the other declarations decide whether
        // it is attested ([`beside_the_pin`]).
        if regs
            .iter()
            .any(|d| d.registry.as_deref() == Some(reg.as_str()))
        {
            out.push(lock_ref);
            beside_the_pin(ctx, lock, pkg, &purl, &uuid, regs, out);
            continue;
        }
        let others: Vec<(&str, String)> = regs
            .iter()
            .filter_map(|d| Some((d.file.as_str(), d.pin()?)))
            .collect();
        if others.is_empty() {
            let files = decl_files(regs);
            let verb = if files.contains(", ") {
                "declare"
            } else {
                "declares"
            };
            out.diag(
                DIAG_REF_INVALID,
                CARGO_LOCK,
                format!(
                    "{CARGO_LOCK}: {purl} resolves from Socket patch {uuid}, but {files} \
                     {verb} {} without registry = \"{reg}\" — cargo re-resolves it from the \
                     declared source; not counted",
                    pkg.name
                ),
            );
            continue;
        }
        // A manifest routes the crate to a DIFFERENT Socket patch than the
        // lock pins: emit both wirings and let the CLI's conflict gate refuse
        // to pick one.
        out.push(lock_ref);
        for (file, other) in others {
            out.push(PatchedRef::hosted(
                purl.clone(),
                other,
                file,
                None,
                None,
                true,
            ));
        }
    }
}

/// What one declaration of a crate means for its Socket-locked
/// `name@version` ([`route`]).
enum Route {
    /// Routes it to this Socket patch: its own `socket-patch-<uuid>`
    /// registry, or a `[patch]` entry's that redirects it.
    Pin(String),
    /// Cargo builds its own, unpatched copy for it, which may be this
    /// version: [`CargoReqMatch::Ours`] when only this locked version
    /// matches its requirement, [`CargoReqMatch::Ambiguous`] when another
    /// locked one does too.
    Unpinned(CargoReqMatch),
    /// Says nothing about this version: its requirement excludes it, it is
    /// a `[patch]` entry (a redirection, counted through the declarations
    /// it redirects), a template nobody inherits, or a malformed
    /// `socket-patch-*` name (diagnosed by [`unresolved_manifest_pins`]).
    Elsewhere,
}

/// Classify `d` for the locked `version` of its crate, `others` being the
/// other versions the lock holds of it and `patch_pins` the `[patch.<table>]`
/// Socket registry pins (table, uuid) cargo honors.
fn route(d: &Decl, patch_pins: &[(&str, String)], version: &str, others: &[String]) -> Route {
    if matches!(d.source, DeclSource::Patch(_)) || !d.live {
        return Route::Elsewhere;
    }
    let selects = cargo_req_selects(d.version.as_deref(), version, others);
    if selects == CargoReqMatch::NotOurs {
        return Route::Elsewhere;
    }
    if let Some(uuid) = d.pin() {
        return Route::Pin(uuid);
    }
    if d.source == DeclSource::Registry && d.socket_shaped() {
        return Route::Elsewhere;
    }
    match patch_pins.iter().find(|(table, _)| d.patched_by(table)) {
        Some((_, uuid)) => Route::Pin(uuid.clone()),
        None => Route::Unpinned(selects),
    }
}

/// The other declarations beside a lock entry pinned to Socket patch
/// `uuid` ([`route`] for each):
///
/// * one routed to ANOTHER Socket patch that may select this version is a
///   conflict: its wiring is emitted beside the lock ref, so the CLI's
///   conflict gate refuses to pick one;
/// * one cargo builds its own copy for (crates.io, another registry or
///   registry index, a path, git — including a `socket-patch-<uuid>`
///   registry a `path` / `git` / `registry-index` overrides) marks the ref
///   [`UnattestedKind::CargoUnpinnedDeclaration`]: cargo resolves each
///   source on its own, so that copy is unpatched and may be this very
///   version. The hosted rewriter pins every declaration, so this is a
///   partial revert or a hand edit. The ref stays (rollback, remove and
///   the ledgers still see the pin); the detail names the declarations and
///   whether a re-scan can pin them.
///
/// When the lock already holds a same-version copy from another source,
/// [`unpatched_twins`] withholds the ref and names that entry (#679), so
/// nothing is added here.
fn beside_the_pin(
    ctx: &DiscoverCtx<'_>,
    lock: &Lock,
    pkg: &LockedPackage,
    purl: &str,
    uuid: &str,
    regs: &[Decl],
    out: &mut Discovery,
) {
    let same_name = || lock.packages().iter().filter(|p| p.name == pkg.name);
    let twin = same_name().any(|p| {
        p.version == pkg.version
            && p.source
                .as_deref()
                .is_some_and(|s| source_uuid(ctx, s).is_none())
    });
    if twin {
        return;
    }
    let others = distinct(
        same_name()
            .filter(|p| p.version != pkg.version)
            .map(|p| Some(p.version.clone())),
    );
    let patch_pins: Vec<(&str, String)> = regs
        .iter()
        .filter_map(|d| match &d.source {
            DeclSource::Patch(table) => Some((table.as_str(), d.socket_uuid()?)),
            _ => None,
        })
        .collect();
    let mut unpinned: Vec<(&Decl, CargoReqMatch)> = Vec::new();
    for d in regs {
        match route(d, &patch_pins, &pkg.version, &others) {
            // A patch the lock resolves the crate from at all is its own
            // ref (that registry serves only its own version, a separate,
            // patched package): no conflict.
            Route::Pin(other)
                if other != uuid
                    && !same_name().any(|p| {
                        p.source
                            .as_deref()
                            .and_then(|s| source_uuid(ctx, s))
                            .is_some_and(|u| u == other)
                    }) =>
            {
                out.push(PatchedRef::hosted(
                    purl.to_string(),
                    other,
                    &d.file,
                    None,
                    None,
                    true,
                ));
            }
            Route::Unpinned(selects) => unpinned.push((d, selects)),
            Route::Pin(_) | Route::Elsewhere => {}
        }
    }
    let Some((first, _)) = unpinned.first() else {
        return;
    };
    let declared = unpinned
        .iter()
        .map(|(d, _)| {
            let req = d
                .version
                .as_deref()
                .map_or_else(|| "with no version".to_string(), |v| format!("{v:?}"));
            format!("{} declares {} {req} from {}", d.file, pkg.name, d.origin())
        })
        .collect::<Vec<_>>()
        .join(", and ");
    // What a re-scan can do: the hosted rewriter pins a crates.io
    // declaration whose requirement selects only the patched version among
    // the locked ones, and refuses every other kind.
    let refused: Vec<String> = unpinned
        .iter()
        .filter_map(|(d, selects)| {
            let why = match (&d.source, d.registry.as_deref(), selects) {
                (DeclSource::Registry, None, CargoReqMatch::Ours) => return None,
                (DeclSource::Registry, None, _) => {
                    let also: Vec<&str> = others
                        .iter()
                        .filter(|v| {
                            cargo_req_selects(d.version.as_deref(), v, &[])
                                != CargoReqMatch::NotOurs
                        })
                        .map(String::as_str)
                        .collect();
                    format!(
                        "its requirement also matches {} {} locked beside it",
                        pkg.name,
                        also.join(", ")
                    )
                }
                (DeclSource::Registry | DeclSource::RegistryIndex(_), ..) => {
                    "it names another registry".to_string()
                }
                _ => "it builds a path or git source".to_string(),
            };
            Some(format!("{}'s declaration ({why})", d.file))
        })
        .collect();
    let remedy = if refused.is_empty() {
        "re-run `socket-patch scan` to pin it too".to_string()
    } else {
        format!(
            "`socket-patch scan` cannot pin {}, so change that declaration or roll the \
             patch back",
            refused.join(", or ")
        )
    };
    out.unattested(
        purl,
        uuid,
        &first.file,
        format!(
            "{declared}, not registry \"{}\": cargo resolves that declaration as a \
             separate package, so the crate declaring it builds an unpatched {} that the \
             requirement allows to be {}; {remedy}",
            hosted_pin_name(uuid),
            pkg.name,
            pkg.version
        ),
        UnattestedKind::CargoUnpinnedDeclaration,
    );
}

/// Record every lock block that resolves a Socket-hosted crate's
/// `name@version` from another source ([`Discovery::unpatched_copy`]).
/// Cargo never unifies packages of different sources, so a dependency that
/// locks its own crates.io (or git) copy beside the hosted pin, typically
/// one added after the scan (#679), compiles that copy unpatched. The hosted
/// ref is then withheld from attestation, though rollback / remove still
/// unwind it. A re-scan cannot rewire the other copy (the rewriter refuses
/// a crate a transitive dependent resolves from crates.io,
/// `redirect_cargo_transitive_dependents`), so it is a shadow, not a
/// rewirable ref.
fn unpatched_twins(ctx: &DiscoverCtx<'_>, lock: &Lock, out: &mut Discovery) {
    let packages = lock.packages();
    let hosted: Vec<&LockedPackage> = packages
        .iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| source_uuid(ctx, s).is_some())
        })
        .collect();
    if hosted.is_empty() {
        return;
    }
    for pkg in packages {
        let Some(source) = pkg.source.as_deref() else {
            // A sourceless block is a workspace member, a path dependency or
            // a vendored copy (tagged, so another version): not this crate.
            continue;
        };
        if source_uuid(ctx, source).is_some()
            || !hosted
                .iter()
                .any(|h| h.name == pkg.name && h.version == pkg.version)
        {
            continue;
        }
        out.unpatched_copy(
            CARGO_LOCK,
            simple_purl("cargo", &pkg.name, &pkg.version),
            &format!("{} {} ({source})", pkg.name, pkg.version),
            &format!(
                "resolves the same crate version from another source, which cargo builds \
                 beside the Socket copy for the dependents that lock it (`cargo tree -i \
                 {}@{}` lists them)",
                pkg.name, pkg.version
            ),
        );
    }
}

/// Diagnose `Cargo.toml` Socket-registry pins no lock entry turns into a ref
/// (no exact version to attest), and malformed `socket-patch-*` names. One
/// diagnostic per crate and patch, naming every manifest that pins it.
///
/// With NO `Cargo.lock` at all (a library that gitignores it; `rewrite_cargo`
/// supports that state — `LockCommit::Absent` — and writes only the pin and
/// the registry definition) a pin is still live wiring for the crate: no
/// declaration routes it to another Socket registry, the project config
/// defines that registry on the Socket host for the same `U`, and that
/// registry serves only the patched version. It is recorded as ONE
/// [`UnlockedPin`] per crate and patch, carrying the pinning declarations'
/// version requirements (from the root and every member) and, as
/// `excluded_reqs`, those of the declarations without a pin: the rewriter
/// leaves a declaration alone only when its requirement excludes the
/// patched version, so a redirect-ledger record stays live
/// ([`Discovery::hosted_claim`]) when its exact version satisfies every
/// pinned requirement and no unpinned one. An unpinned declaration with no
/// version requirement (git, path) may resolve any version: no pin. It is
/// still not a ref (no version to attest on its own).
fn unresolved_manifest_pins(
    ctx: &DiscoverCtx<'_>,
    lock: &Lock,
    decls: &Decls,
    definitions: &BTreeMap<String, String>,
    out: &mut Discovery,
) {
    for (name, regs) in decls {
        let mut malformed: Vec<(&str, &str)> = Vec::new();
        let mut uuids: Vec<String> = Vec::new();
        for decl in regs.iter().filter(|d| d.socket_shaped()) {
            let reg = decl.registry.as_deref().unwrap_or_default();
            match decl.socket_uuid() {
                Some(uuid) if !uuids.contains(&uuid) => uuids.push(uuid),
                Some(_) => {}
                None if !malformed.contains(&(decl.file.as_str(), reg)) => {
                    malformed.push((decl.file.as_str(), reg));
                }
                None => {}
            }
        }
        for (file, reg) in malformed {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {name} is pinned to registry {reg:?}, which is not a \
                     socket-patch-<uuid> name"
                ),
            );
        }
        if uuids.is_empty() {
            continue;
        }
        let socket_sourced = lock.packages().iter().any(|p| {
            p.name == *name
                && p.source
                    .as_deref()
                    .and_then(|s| source_uuid(ctx, s))
                    .is_some()
        });
        if socket_sourced {
            continue; // a ref (or the conflict pair) came from the lock
        }
        for uuid in &uuids {
            let pinning: Vec<&Decl> = regs
                .iter()
                .filter(|d| d.socket_uuid().as_deref() == Some(uuid.as_str()))
                .collect();
            let reg = pinning[0].registry.as_deref().unwrap_or_default();
            let file = pinning[0].file.as_str();
            let why = match lock {
                Lock::Unparseable => continue, // already diagnosed
                Lock::Absent => {
                    // Another Socket registry (or a malformed one) for the
                    // same crate is a conflict, never a pin.
                    let only_this_patch = regs
                        .iter()
                        .filter(|d| d.socket_shaped())
                        .all(|d| d.socket_uuid().as_deref() == Some(uuid.as_str()));
                    let defined_here = definitions
                        .get(reg)
                        .and_then(|index| source_uuid(ctx, index))
                        .is_some_and(|u| u == *uuid);
                    let version_reqs = distinct(pinning.iter().map(|d| d.version.clone()));
                    // `None` when some unpinned declaration carries no
                    // requirement (git, path): it may resolve any version.
                    let excluded_reqs: Option<Vec<String>> = regs
                        .iter()
                        .filter(|d| !d.socket_shaped())
                        .map(|d| d.version.clone())
                        .collect();
                    if let (true, true, false, Some(excluded_reqs)) = (
                        only_this_patch,
                        defined_here,
                        version_reqs.is_empty(),
                        excluded_reqs,
                    ) {
                        let excluded_reqs = distinct(excluded_reqs.into_iter().map(Some));
                        out.unlocked_pin(UnlockedPin {
                            ecosystem: "cargo".to_string(),
                            name: name.clone(),
                            uuid: uuid.clone(),
                            file: file.into(),
                            version_reqs,
                            excluded_reqs,
                            index_url: definitions.get(reg).cloned(),
                        });
                    }
                    format!("there is no {CARGO_LOCK} to fix its version")
                }
                Lock::Parsed { .. } => format!(
                    "{CARGO_LOCK} does not resolve it from a Socket patch server (a stale \
                     lock, or a patch server outside the allowlist — see \
                     --patch-server-url)"
                ),
            };
            let files = decl_files(pinning.iter().copied());
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                file,
                format!("{files}: {name} is pinned to Socket patch {uuid}, but {why}"),
            );
        }
    }
}

// ── vendored ─────────────────────────────────────────────────────────────

/// A `[patch]` path spelled for comparison (separators, `./` segments and
/// a trailing slash ignored).
fn same_path_key(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// The Socket version tag of a wired copy's own `Cargo.toml`.
enum CopyTag {
    /// No copy manifest on disk (the copy is missing: verification says so).
    Absent,
    /// Untagged: a copy vendored before tagged versions.
    Untagged,
    Tagged(String),
    /// Present but unreadable: treated as tagged (fail-closed — an untagged
    /// lock entry then never counts).
    Unreadable,
}

/// Read the tag of the copy at root-relative `artifact_rel` (the only
/// identity its manifest can mention is the uuid its `[patch]` path already
/// names).
async fn copy_tag(ctx: &DiscoverCtx<'_>, artifact_rel: &str, out: &mut Discovery) -> CopyTag {
    let rel = format!("{artifact_rel}/{CARGO_TOML}");
    if !ctx.exists(&rel).await {
        return CopyTag::Absent;
    }
    match ctx.read_text(&rel, out).await {
        Some(text) => match cargo_tag::manifest_tag_uuid(&text) {
            Some(uuid) => CopyTag::Tagged(uuid),
            None => CopyTag::Untagged,
        },
        None => CopyTag::Unreadable,
    }
}

/// What a vendored copy is weighed against for copies its `[patch]` wiring
/// does not redirect ([`patch_bypassed`]).
struct Bypass<'a> {
    lock: &'a Lock,
    /// Every declaration in the root and member manifests (`None`: no
    /// usable root manifest).
    decls: Option<&'a Decls>,
    /// Every Socket copy the manifest and config `[patch]` tables point at,
    /// with the `[patch.<source>]` table pointing at it.
    wired: &'a [(String, VendorRef)],
}

/// Mark the vendored ref `purl` (the copy `vref` of `name`@`version`)
/// [`UnattestedKind::CargoPatchBypassed`] when the build may also compile
/// a copy of that version its wiring does not reach. A `[patch.<source>]`
/// entry replaces the crate only in declarations from `<source>` (v5
/// `vendor` writes `[patch.crates-io]`), so either of these builds
/// unpatched bytes:
///
/// * a live dependency declaration (the root's or a workspace member's)
///   from another registry, a `registry-index` or git, whose requirement
///   may select `version`, unless it is a registry dependency that a
///   `[patch]` table pointing at this copy redirects ([`Decl::patched_by`]):
///   cargo resolves it as a separate package, maybe at this very version;
/// * a `Cargo.lock` entry of `name` at exactly `version` with a source
///   (any registry or git; a Socket patch server's is hosted wiring, a ref
///   of its own): that copy is already locked beside the vendored one.
///
/// A path declaration (the user's own fork) is left alone, as the lock's
/// copy claim leaves its sourceless entry alone; a `socket-patch-*`
/// registry dependency is hosted wiring, weighed there. The ref stays
/// (rollback, remove and the ledgers still see the wiring), but nothing
/// attests it.
fn patch_bypassed(
    ctx: &DiscoverCtx<'_>,
    bypass: &Bypass<'_>,
    vref: &VendorRef,
    name: &str,
    version: &str,
    purl: &str,
    out: &mut Discovery,
) {
    let redirected = |d: &Decl| {
        bypass
            .wired
            .iter()
            .any(|(table, v)| v.uuid == vref.uuid && v.leaf == vref.leaf && d.patched_by(table))
    };
    let declared: Vec<&Decl> = bypass
        .decls
        .and_then(|d| d.get(name))
        .into_iter()
        .flatten()
        .filter(|d| d.live)
        .filter(|d| match &d.source {
            DeclSource::Registry => !d.socket_shaped() && !redirected(d),
            DeclSource::RegistryIndex(_) | DeclSource::Git => true,
            DeclSource::Path | DeclSource::Patch(_) => false,
        })
        .filter(|d| cargo_req_selects(d.version.as_deref(), version, &[]) != CargoReqMatch::NotOurs)
        .collect();
    let locked = bypass
        .lock
        .packages()
        .iter()
        .filter(|p| p.name == name && p.version == version)
        .find_map(|p| {
            p.source
                .as_deref()
                .filter(|s| source_uuid(ctx, s).is_none())
        });
    let redirects = format!(
        "which no [patch] entry pointing at {} redirects",
        vref.artifact_rel
    );
    let (file, detail) = match (declared.first(), locked) {
        (Some(first), _) => {
            let evidence = locked.map_or_else(String::new, |source| {
                format!("; {CARGO_LOCK} also locks {name} {version} from {source}")
            });
            let declared = declared
                .iter()
                .map(|d| {
                    let req = d
                        .version
                        .as_deref()
                        .map_or_else(|| "with no version".to_string(), |v| format!("{v:?}"));
                    format!("{} declares {name} {req} from {}", d.file, d.origin())
                })
                .collect::<Vec<_>>()
                .join(", and ");
            (
                first.file.as_str(),
                format!(
                    "{declared}, {redirects}: cargo resolves that declaration as a separate \
                     package, so the crate declaring it builds an unpatched {name} that the \
                     requirement allows to be {version}{evidence}"
                ),
            )
        }
        (None, Some(source)) => (
            CARGO_LOCK,
            format!(
                "{CARGO_LOCK} also locks {name} {version} from {source}, {redirects}: cargo \
                 builds that copy unpatched beside the vendored one"
            ),
        ),
        (None, None) => return,
    };
    out.unattested(
        purl,
        &vref.uuid,
        file,
        detail,
        UnattestedKind::CargoPatchBypassed,
    );
}

/// Vendored refs from one file's `[patch]` tables. `shadowed` names why
/// cargo ignores an entry (a higher-precedence item replaces it), if so.
async fn vendored_from_patches(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    doc: &DocumentMut,
    lock: &Lock,
    shadowed: &(dyn Fn(&CargoPatchEntry<'_>) -> Option<String> + Sync),
    bypass: &Bypass<'_>,
    out: &mut Discovery,
) {
    for entry in patch_entries(doc) {
        let Some(path) = entry.path else {
            continue; // a git / registry patch
        };
        if !names_vendor_dir(path) {
            continue; // a user path, or the uuid-less `.socket/cargo-patches/`
        }
        let name = entry.name;
        if let Some(why) = shadowed(&entry) {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: [patch] entry `{}` for {name} points at {path:?}, but {why}; \
                     not counted",
                    entry.key
                ),
            );
            continue;
        }
        let Some(vref) = vendor_ref(path).filter(|v| v.eco == "cargo") else {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: [patch] path {path:?} for {name} is not this project's \
                     .socket/vendor/cargo/<uuid>/<name>-<version> copy"
                ),
            );
            continue;
        };
        // One `<name>-<version>` directory, named for THIS entry's crate.
        let version = if vref.leaf.contains('/') {
            None
        } else {
            vref.leaf.strip_prefix(&format!("{name}-"))
        };
        let Some((version, purl)) =
            version.and_then(|v| simple_purl("cargo", name, v).map(|purl| (v, purl)))
        else {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: [patch] path {path:?} does not name a {name}-<version> copy \
                     for {name}"
                ),
            );
            continue;
        };
        let tag = copy_tag(ctx, &vref.artifact_rel, out).await;
        if let CopyTag::Tagged(t) = &tag {
            if *t != vref.uuid {
                // Cargo builds this copy as `<version>+socket.<t>`: not the
                // patch its path names.
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: [patch] entry for {name} points at {}, but that copy's \
                         {CARGO_TOML} is tagged for patch {t}; not counted",
                        vref.artifact_rel
                    ),
                );
                continue;
            }
        }
        let copy_tagged = matches!(tag, CopyTag::Tagged(_) | CopyTag::Unreadable);
        if let Lock::Parsed(lock) = lock {
            let claim = lock.vendored_in_use(name, version, &vref.uuid, copy_tagged);
            let relock_pending =
                matches!(claim, CopyClaim::OtherTag(_) | CopyClaim::UntaggedOverride);
            let why = match claim {
                CopyClaim::Consumed => None,
                CopyClaim::OtherTag(other) => Some(format!(
                    "{CARGO_LOCK} builds the copy tagged for patch {other} ({name} {})",
                    cargo_tag::tag_version(version, other)
                )),
                CopyClaim::UntaggedOverride => Some(format!(
                    "{CARGO_LOCK} builds an untagged {name} {version}, not the copy (which \
                     cargo would lock as {}): another [patch] or path dependency overrides it",
                    cargo_tag::tag_version(version, &vref.uuid)
                )),
                CopyClaim::NotConsumed => Some(format!(
                    "{CARGO_LOCK} does not build {name}@{version} from it (an unused patch, \
                     or the lock resolves it from a registry)"
                )),
            };
            if let Some(why) = why {
                // The manifest still routes the crate to this copy and the
                // lock entry is detached: only the lock's generation lags,
                // and the next unlocked build consumes the copy.
                if relock_pending {
                    out.withheld.push(super::Recognized {
                        uuid: vref.uuid.clone(),
                        mode: super::WiringMode::Vendored,
                        file: std::path::PathBuf::from(file),
                    });
                }
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: [patch] entry for {name} points at {}, but {why}; not counted",
                        vref.artifact_rel
                    ),
                );
                continue;
            }
        }
        patch_bypassed(ctx, bypass, &vref, name, version, &purl, out);
        out.push(PatchedRef::vendored(purl, &vref, file, None));
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    /// The uuid (and uuid-shaped grant token) the committed redirect
    /// fixtures use.
    const FIXTURE_UUID: &str = "55555555-5555-5555-5555-555555555555";
    const FIXTURE_OLD_UUID: &str = "00000000-0000-0000-0000-000000000000";
    const CKSUM: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn index(uuid: &str) -> String {
        format!("sparse+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{uuid}/index/")
    }

    fn lock(pkgs: &[(&str, &str, Option<&str>, Option<&str>)]) -> String {
        let mut s = String::from(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\nversion = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        );
        for (name, version, source, checksum) in pkgs {
            s.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
            ));
            if let Some(src) = source {
                s.push_str(&format!("source = \"{src}\"\n"));
            }
            if let Some(c) = checksum {
                s.push_str(&format!("checksum = \"{c}\"\n"));
            }
        }
        s
    }

    fn manifest(deps: &str) -> String {
        format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n{deps}\n")
    }

    fn pinned(name: &str, version: &str, uuid: &str) -> String {
        format!("{name} = {{ version = \"{version}\", registry = \"socket-patch-{uuid}\" }}")
    }

    fn registry_block(uuid: &str) -> String {
        format!(
            "[registries.socket-patch-{uuid}]\nindex = \"{}\"\n",
            index(uuid)
        )
    }

    fn vendor_path(uuid: &str, leaf: &str) -> String {
        format!(".socket/vendor/cargo/{uuid}/{leaf}")
    }

    fn patch_config(entries: &[(&str, &str)]) -> String {
        let mut s = String::from("[patch.crates-io]\n");
        for (name, path) in entries {
            s.push_str(&format!("{name} = {{ path = \"{path}\" }}\n"));
        }
        s
    }

    fn hosted(purl: &str, uuid: &str) -> (String, String, WiringMode) {
        (purl.to_string(), uuid.to_string(), WiringMode::Hosted)
    }

    // ── hosted: committed rewriter goldens ───────────────────────────

    #[tokio::test]
    async fn golden_hosted_fixtures_yield_the_patch_uuid_not_the_token() {
        for case in [
            "basic",
            "two-sections",
            "table-form",
            "renamed",
            "supersede",
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/cargo/cargo/{case}/expected"));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.190", FIXTURE_UUID, WiringMode::Hosted)],
            );
            assert!(out.diagnostics.is_empty(), "{case}: {:#?}", out.diagnostics);
            let r = &out.refs[0];
            assert_eq!(
                r.source_file,
                std::path::PathBuf::from("Cargo.lock"),
                "{case}"
            );
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sha256Hex(CKSUM.into())),
                "{case}"
            );
            assert!(r.integrity_required && r.lockfile_basis_ok(), "{case}");
            assert!(r
                .url
                .as_deref()
                .is_some_and(|u| u.starts_with("sparse+https://")));
        }
    }

    /// The `rerun` / `commented-config` goldens have no `expected/` tree
    /// (nothing changes); their `input/` is already the redirected shape.
    #[tokio::test]
    async fn golden_rerun_input_is_already_a_ref() {
        for case in ["rerun", "commented-config"] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/cargo/cargo/{case}/input"));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.190", FIXTURE_UUID, WiringMode::Hosted)],
            );
        }
    }

    /// The pre-rewrite inputs are ordinary crates.io projects: nothing.
    #[tokio::test]
    async fn golden_inputs_are_registry_only() {
        for case in ["basic", "two-sections", "table-form", "renamed"] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/cargo/cargo/{case}/input"));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(out.diagnostics.is_empty(), "{case}: {:#?}", out.diagnostics);
        }
    }

    /// The supersede golden's INPUT: pinned (manifest + lock + config) to
    /// the older patch — that older uuid is the ref.
    #[tokio::test]
    async fn golden_supersede_input_yields_the_old_patch() {
        let p = Project::new();
        p.copy_fixture("redirect/cargo/cargo/supersede/input");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:cargo/serde@1.0.190",
                FIXTURE_OLD_UUID,
                WiringMode::Hosted,
            )],
        );
    }

    // ── hosted: shapes ───────────────────────────────────────────────

    /// #679: a dependency added after the hosted pin resolves its own
    /// crates.io copy of the same cfg-if 1.0.4 (cargo cannot unify the two
    /// sources), so the build compiles the unpatched copy too. The ref is
    /// withheld from attestation, diagnosed, and kept as `shadowed` so
    /// rollback / remove still unwind the pin.
    #[tokio::test]
    async fn crates_io_twin_of_the_hosted_crate_withholds_the_ref() {
        for other in [
            CRATES_IO.to_string(),
            "git+https://github.com/rust-lang/cfg-if?rev=1#abc".to_string(),
        ] {
            let p = Project::new();
            p.write("Cargo.toml", manifest(&pinned("cfg-if", "1.0.4", UUID_A)));
            p.write(
                "Cargo.lock",
                lock(&[
                    ("cfg-if", "1.0.4", Some(&other), Some(CKSUM)),
                    ("cfg-if", "1.0.4", Some(&index(UUID_A)), Some(CKSUM)),
                    ("crc32fast", "1.5.0", Some(CRATES_IO), Some(CKSUM)),
                ]),
            );
            p.write(".cargo/config.toml", registry_block(UUID_A));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                out.shadowed
                    .iter()
                    .map(|r| (r.purl.as_str(), r.uuid.as_str()))
                    .collect::<Vec<_>>(),
                [("pkg:cargo/cfg-if@1.0.4", UUID_A)],
                "{other}"
            );
            assert!(
                out.diagnostics
                    .iter()
                    .any(|d| d.code == DIAG_REF_UNATTRIBUTABLE
                        && d.detail.contains("cfg-if")
                        && d.detail.contains("UNPATCHED")),
                "{other}: {:#?}",
                out.diagnostics
            );
        }
        // Another VERSION from crates.io is a different package: no effect.
        let p = Project::new();
        p.write("Cargo.toml", manifest(&pinned("cfg-if", "1.0.4", UUID_A)));
        p.write(
            "Cargo.lock",
            lock(&[
                ("cfg-if", "0.1.10", Some(CRATES_IO), Some(CKSUM)),
                ("cfg-if", "1.0.4", Some(&index(UUID_A)), Some(CKSUM)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.shadowed.is_empty());
    }

    #[tokio::test]
    async fn workspace_and_target_tables_carry_the_pin() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "[workspace]\nmembers = [\"m\"]\n\n[workspace.dependencies]\n{}\n\n\
                 [target.'cfg(unix)'.dependencies]\n{}\n\n[dependencies]\n\
                 serde.workspace = true\nlibc = {{ workspace = true }}\n",
                pinned("serde", "1", UUID_A),
                pinned("libc", "0.2", UUID_B),
            ),
        );
        p.write(
            "Cargo.lock",
            lock(&[
                ("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM)),
                ("libc", "0.2.9", Some(&index(UUID_B)), Some(CKSUM)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted),
                ("pkg:cargo/libc@0.2.9", UUID_B, WiringMode::Hosted),
            ],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// A crate the root manifest never declares (a workspace member's dep
    /// the root lock describes, or no manifest at all): the lock decides.
    #[tokio::test]
    async fn undeclared_or_manifestless_lock_entry_is_a_ref() {
        for with_manifest in [true, false] {
            let p = Project::new();
            if with_manifest {
                p.write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
            }
            p.write(
                "Cargo.lock",
                lock(&[("smallvec", "1.6.0", Some(&index(UUID_A)), Some(CKSUM))]),
            );
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/smallvec@1.6.0", UUID_A, WiringMode::Hosted)],
            );
        }
    }

    /// `--patch-server-url` origins count; without them the same lock is
    /// not a ref, and the manifest pin is diagnosed as unresolved.
    #[tokio::test]
    async fn configured_origin_is_accepted_and_otherwise_diagnosed() {
        let src =
            format!("sparse+http://127.0.0.1:4545/patch-registry/cargo/{TOKEN}/{UUID_A}/index/");
        let write = |p: &Project| {
            p.write("Cargo.toml", manifest(&pinned("serde", "1", UUID_A)));
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&src), Some(CKSUM))]),
            );
            p.write(
                ".cargo/config.toml",
                format!("[registries.socket-patch-{UUID_A}]\nindex = \"{src}\"\n"),
            );
        };
        let p = Project::new().with_origin("http://127.0.0.1:4545");
        write(&p);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);

        let p = Project::new();
        write(&p);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        // The boundary of rule 11: a patch server OUTSIDE the allowlist and
        // a host-independent `socket-patch-<uuid>` name recognize nothing,
        // so a ledger record for it is left to the ledger's own evidence
        // (staging / test servers without `--patch-server-url`).
        assert_eq!(out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A), None);
    }

    /// A pin-less (hand-edited) Socket-sourced entry is still a wiring ref,
    /// but it cannot use the not-installed lockfile basis.
    #[tokio::test]
    async fn missing_or_malformed_checksum_blocks_the_lockfile_basis() {
        for checksum in [None, Some("DEADBEEF"), Some("")] {
            let p = Project::new();
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&index(UUID_A)), checksum)]),
            );
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
            );
            assert_eq!(out.refs[0].locked_integrity, None);
            assert!(!out.refs[0].lockfile_basis_ok(), "{checksum:?}");
        }
    }

    /// A v1 lock (cargo < 1.41) keeps the pin in `[metadata]`, keyed by
    /// the source — the shape the hosted rewriter writes for a v1 lock. It
    /// is the lockfile basis exactly like v2+'s inline checksum; a
    /// `[metadata]` checksum filed under ANOTHER source (the crates.io
    /// original) pins nothing. REGRESSION: the `[metadata]` table was not
    /// read, so a not-installed v1 hosted checkout could never attest.
    #[tokio::test]
    async fn v1_metadata_checksum_is_the_lockfile_pin() {
        let v1 = |key_source: &str| {
            let src = index(UUID_A);
            format!(
                "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
                 \"serde 1.0.1 ({src})\",\n]\n\n[[package]]\nname = \"serde\"\n\
                 version = \"1.0.1\"\nsource = \"{src}\"\n\n[metadata]\n\
                 \"checksum serde 1.0.1 ({key_source})\" = \"{CKSUM}\"\n"
            )
        };
        let p = Project::new();
        p.write("Cargo.lock", v1(&index(UUID_A)));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        assert_eq!(
            out.refs[0].locked_integrity,
            Some(LockIntegrity::Sha256Hex(CKSUM.to_string()))
        );
        assert!(out.refs[0].lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        let p = Project::new();
        p.write("Cargo.lock", v1(CRATES_IO));
        let out = run(&p).await;
        assert_eq!(out.refs.len(), 1, "{:?}", out.refs);
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(!out.refs[0].lockfile_basis_ok());
    }

    // ── hosted: negatives ────────────────────────────────────────────

    #[tokio::test]
    async fn non_socket_hosts_and_non_registry_sources_are_not_refs() {
        let p = Project::new();
        p.write(
            "Cargo.lock",
            lock(&[
                // A uuid-shaped path segment on someone else's registry.
                (
                    "a",
                    "1.0.0",
                    Some(&format!("sparse+https://evil.example/cargo/{UUID_A}/index/")),
                    Some(CKSUM),
                ),
                // Look-alike host.
                (
                    "b",
                    "1.0.0",
                    Some(&format!("sparse+https://patch.socket.dev.evil.example/{UUID_A}/index/")),
                    Some(CKSUM),
                ),
                // Plain http to the real host.
                (
                    "c",
                    "1.0.0",
                    Some(&format!("sparse+http://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID_A}/index/")),
                    Some(CKSUM),
                ),
                // Userinfo.
                (
                    "d",
                    "1.0.0",
                    Some(&format!("sparse+https://u:p@patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID_A}/index/")),
                    Some(CKSUM),
                ),
                // A git source on the patch host is not something we write.
                (
                    "e",
                    "1.0.0",
                    Some(&format!("git+https://patch.socket.dev/x/{UUID_A}#abc")),
                    None,
                ),
                // Placeholder / non-canonical uuid.
                (
                    "f",
                    "1.0.0",
                    Some("sparse+https://patch.socket.dev/patch-registry/cargo/TOKEN/UUID/index/"),
                    Some(CKSUM),
                ),
                ("g", "1.0.0", Some(CRATES_IO), Some(CKSUM)),
                ("h", "1.0.0", Some("sparse+https://index.crates.io/"), Some(CKSUM)),
                // Workspace member / path dep.
                ("i", "1.0.0", None, None),
            ]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// The grant token level before the patch uuid is uuid-shaped: the LAST
    /// canonical segment (the patch) is the ref, never the token.
    #[tokio::test]
    async fn uuid_shaped_grant_token_is_not_the_patch_uuid() {
        let p = Project::new();
        p.write(
            "Cargo.lock",
            lock(&[(
                "serde",
                "1.0.1",
                Some(&format!(
                    "sparse+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID_A}/index/"
                )),
                Some(CKSUM),
            )]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
    }

    /// The pin was reverted in Cargo.toml (or moved to a user registry) but
    /// the lock still names the patch: cargo re-resolves, so no ref.
    #[tokio::test]
    async fn reverted_manifest_pin_drops_the_stale_lock_entry() {
        for decl in [
            "serde = \"1.0.1\"".to_string(),
            "serde = { version = \"1\", registry = \"my-corp\" }".to_string(),
            "[dependencies.serde]\nversion = \"1\"".to_string(),
        ] {
            let p = Project::new();
            p.write("Cargo.toml", manifest(&decl));
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
            );
            p.write(".cargo/config.toml", registry_block(UUID_A));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{decl}");
            assert!(out.diagnostics[0].detail.contains("Cargo.lock"));
            // The stale lock entry's patch is RECOGNIZED: a redirect ledger
            // record for it is dead, not resurrected from Cargo.lock's text.
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A),
                Some(false),
                "{decl}"
            );
        }
    }

    /// Manifest and lock name DIFFERENT patches: both wirings are emitted
    /// so the CLI gates the package as a conflict.
    #[tokio::test]
    async fn manifest_and_lock_disagreeing_on_the_patch_emit_both() {
        let p = Project::new();
        p.write("Cargo.toml", manifest(&pinned("serde", "1", UUID_B)));
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted),
                ("pkg:cargo/serde@1.0.1", UUID_B, WiringMode::Hosted),
            ],
        );
        let toml_ref = out.refs.iter().find(|r| r.uuid == UUID_B).unwrap();
        assert_eq!(toml_ref.source_file, std::path::PathBuf::from("Cargo.toml"));
        assert!(!toml_ref.lockfile_basis_ok());
    }

    /// A project-config definition of the pinned registry that indexes a
    /// different patch (or a non-Socket host) is what cargo resolves
    /// against: the lock entry is stale.
    #[tokio::test]
    async fn disagreeing_registry_definition_drops_the_ref() {
        for idx in [
            index(UUID_B),
            "sparse+https://evil.example/index/".to_string(),
        ] {
            let p = Project::new();
            p.write("Cargo.toml", manifest(&pinned("serde", "1", UUID_A)));
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
            );
            p.write(
                ".cargo/config.toml",
                format!("[registries.socket-patch-{UUID_A}]\nindex = \"{idx}\"\n"),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        }
    }

    /// A workspace root that declares nothing itself, with one member.
    fn workspace_with_member(p: &Project, member_deps: &str) {
        p.write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
        p.write(
            "crates/a/Cargo.toml",
            format!(
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\n{member_deps}\n"
            ),
        );
    }

    /// REGRESSION (C2): the hosted rewriter pins the crate in every member
    /// manifest that declares it, so a member's declaration decides like the
    /// root's. A member reverted to crates.io (the root declares nothing)
    /// makes cargo re-resolve from crates.io: no ref, diagnosed against the
    /// member, and the stale lock entry's patch is recognized (a ledger
    /// record for it is dead).
    #[tokio::test]
    async fn reverted_member_manifest_pin_drops_the_stale_lock_entry() {
        for decl in [
            "serde = \"1.0.1\"".to_string(),
            "serde = { version = \"1\", registry = \"my-corp\" }".to_string(),
        ] {
            let p = Project::new();
            workspace_with_member(&p, &decl);
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
            );
            p.write(".cargo/config.toml", registry_block(UUID_A));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{decl}");
            assert!(
                out.diagnostics[0].detail.contains("crates/a/Cargo.toml"),
                "{:#?}",
                out.diagnostics
            );
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A),
                Some(false),
                "{decl}"
            );
        }
    }

    /// The member's own pin keeps the lock entry a ref; a member pin for
    /// ANOTHER patch emits the conflict pair, attributed to the member.
    #[tokio::test]
    async fn member_manifest_pins_count_like_the_roots() {
        let p = Project::new();
        workspace_with_member(&p, &pinned("serde", "1", UUID_A));
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);

        let p = Project::new();
        workspace_with_member(&p, &pinned("serde", "1", UUID_B));
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted),
                ("pkg:cargo/serde@1.0.1", UUID_B, WiringMode::Hosted),
            ],
        );
        let toml_ref = out.refs.iter().find(|r| r.uuid == UUID_B).unwrap();
        assert_eq!(
            toml_ref.source_file,
            std::path::PathBuf::from("crates/a/Cargo.toml")
        );
    }

    /// The root's pin still decides when a member declares the crate under
    /// another version requirement the pin does not reach (the rewriter
    /// leaves such a declaration alone): some declaration pins the patch.
    #[tokio::test]
    async fn a_root_pin_with_an_unpinned_member_declaration_is_a_ref() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "[workspace]\nmembers = [\"crates/*\"]\n\n[package]\nname = \"app\"\n\
                 version = \"0.1.0\"\n\n[dependencies]\n{}\n",
                pinned("serde", "1", UUID_A)
            ),
        );
        p.write(
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"0.9\"\n",
        );
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
    }

    /// A workspace whose root and member `crates/a` declare serde with the
    /// given dependency lines, locked to Socket patch A at 1.0.1 (plus
    /// `extra` lock entries).
    fn mixed_workspace(root_dep: &str, member_dep: &str, extra: &[(&str, &str)]) -> Project {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "[workspace]\nmembers = [\"crates/*\"]\n\n[package]\nname = \"app\"\n\
                 version = \"0.1.0\"\n\n[dependencies]\n{root_dep}\n"
            ),
        );
        p.write(
            "crates/a/Cargo.toml",
            format!(
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\n{member_dep}\n"
            ),
        );
        let socket = index(UUID_A);
        let mut pkgs = vec![("serde", "1.0.1", Some(socket.as_str()), Some(CKSUM))];
        pkgs.extend(
            extra
                .iter()
                .map(|(v, s)| ("serde", *v, Some(*s), Some(CKSUM))),
        );
        p.write("Cargo.lock", lock(&pkgs));
        p.write(".cargo/config.toml", registry_block(UUID_A));
        p
    }

    /// The one unattested mark of `out`, asserted to be the hosted serde
    /// ref's [`UnattestedKind::CargoUnpinnedDeclaration`] naming `file`.
    fn unpinned_mark<'a>(out: &'a Discovery, file: &str) -> &'a Unattested {
        assert_eq!(out.unattested.len(), 1, "{:#?}", out.unattested);
        let u = &out.unattested[0];
        assert_eq!(u.kind, UnattestedKind::CargoUnpinnedDeclaration);
        assert_eq!(
            (u.purl.as_str(), u.uuid.as_str()),
            ("pkg:cargo/serde@1.0.1", UUID_A)
        );
        assert_eq!(u.file, std::path::PathBuf::from(file));
        u
    }

    /// REGRESSION: the root pins serde to Socket, but a member declares it
    /// from crates.io at a requirement the patched 1.0.1 satisfies. Cargo
    /// resolves that declaration as a separate crates.io package, so the
    /// member builds unpatched bytes: the ref stays (rollback / remove find
    /// it, the ledger claim lives) but is not attested, naming the member.
    #[tokio::test]
    async fn a_root_pin_beside_an_unpinned_member_is_unattested() {
        for member in [
            "serde = \"1\"",
            "serde = \"=1.0.1\"",
            "serde = { version = \"1\", registry = \"my-corp\" }",
            "serde = { git = \"https://github.com/serde-rs/serde\" }",
            "legacy = { package = \"serde\", version = \"1.0\" }",
        ] {
            let p = mixed_workspace(&pinned("serde", "1", UUID_A), member, &[]);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
            );
            assert!(
                out.diagnostics.is_empty(),
                "{member}: {:#?}",
                out.diagnostics
            );
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A),
                Some(true),
                "{member}"
            );
            let u = unpinned_mark(&out, "crates/a/Cargo.toml");
            assert!(
                u.detail.contains("crates/a/Cargo.toml declares serde")
                    && u.detail
                        .contains(&format!("not registry \"socket-patch-{UUID_A}\""))
                    && !u.detail.contains("already locks"),
                "{member}: {}",
                u.detail
            );
        }
        let p = mixed_workspace(&pinned("serde", "1", UUID_A), "serde = \"1\"", &[]);
        let u = &run(&p).await.unattested[0];
        assert!(
            u.detail.contains("serde \"1\" from crates.io"),
            "{}",
            u.detail
        );
    }

    /// The mirror image: a member pins serde, the root declares it from
    /// crates.io. The root's declaration builds unpatched bytes.
    #[tokio::test]
    async fn a_member_pin_beside_an_unpinned_root_is_unattested() {
        let p = mixed_workspace("serde = \"1.0\"", &pinned("serde", "1", UUID_A), &[]);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        let u = unpinned_mark(&out, "Cargo.toml");
        assert!(
            u.detail
                .contains("Cargo.toml declares serde \"1.0\" from crates.io"),
            "{}",
            u.detail
        );
    }

    /// What the hosted rewriter writes — every declaration pinned — is
    /// attested; so is a pin beside an unpinned declaration that the
    /// patched version cannot satisfy (cargo resolves it to another
    /// version, never this one).
    #[tokio::test]
    async fn every_declaration_pinned_is_attested() {
        for (root, member) in [
            (pinned("serde", "1", UUID_A), pinned("serde", "1.0", UUID_A)),
            (pinned("serde", "1", UUID_A), "serde = \"0.9\"".to_string()),
            (
                pinned("serde", "1", UUID_A),
                "serde = \">=1.0.2\"".to_string(),
            ),
            // A `[patch]` registry entry redirects declarations; it declares
            // no dependency of its own.
            (
                format!(
                    "{}\n\n[patch.crates-io]\nserde = {{ version = \"1\", registry = \"my-corp\" }}",
                    pinned("serde", "1", UUID_A)
                ),
                pinned("serde", "1", UUID_A),
            ),
        ] {
            let p = mixed_workspace(&root, &member, &[]);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
            );
            assert!(out.unattested.is_empty(), "{member}: {:#?}", out.unattested);
            assert!(
                out.diagnostics.is_empty(),
                "{member}: {:#?}",
                out.diagnostics
            );
        }
    }

    /// The lock already holds the member's crates.io copy at the patched
    /// version beside the Socket entry: the crates.io-twin rule (#679)
    /// withholds the ref (shadowed, its diagnostic naming that lock entry)
    /// and no unattested mark is added for a ref that no longer stands.
    #[tokio::test]
    async fn a_locked_same_version_twin_is_left_to_the_twin_rule() {
        let p = mixed_workspace(
            &pinned("serde", "1", UUID_A),
            "serde = \"1\"",
            &[("1.0.1", CRATES_IO)],
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(out.shadowed.len(), 1, "{:#?}", out.shadowed);
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.code == DIAG_REF_UNATTRIBUTABLE
                    && d.detail.contains(&format!("serde 1.0.1 ({CRATES_IO})"))),
            "{:#?}",
            out.diagnostics
        );
    }

    /// The remedy follows what a re-scan can do: the hosted rewriter pins a
    /// crates.io declaration whose requirement selects only the patched
    /// version, but refuses one that also matches another locked version
    /// (`redirect_cargo_toml_dep_unrewritable`), one from another registry
    /// or `registry-index`, and a path / git one.
    #[tokio::test]
    async fn the_remedy_says_whether_a_rescan_can_pin_it() {
        let p = mixed_workspace(&pinned("serde", "=1.0.1", UUID_A), "serde = \"1\"", &[]);
        let u = run(&p).await.unattested.remove(0);
        assert!(
            u.detail.contains("re-run `socket-patch scan`"),
            "{}",
            u.detail
        );

        // `"1"` also matches the crates.io 1.0.200 locked beside it.
        let p = mixed_workspace(
            &pinned("serde", "=1.0.1", UUID_A),
            "serde = \"1\"",
            &[("1.0.200", CRATES_IO)],
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        let u = unpinned_mark(&out, "crates/a/Cargo.toml");
        assert!(
            u.detail.contains("also matches serde 1.0.200")
                && u.detail.contains("roll the patch back")
                && !u.detail.contains("re-run `socket-patch scan`"),
            "{}",
            u.detail
        );

        for (member, from) in [
            (
                "serde = { version = \"1\", registry = \"my-corp\" }",
                "from registry `my-corp`",
            ),
            (
                "serde = { version = \"1\", registry-index = \"https://corp.example/index\" }",
                "from the registry index https://corp.example/index",
            ),
            ("serde = { path = \"../serde\" }", "from a local path"),
        ] {
            let p = mixed_workspace(&pinned("serde", "1", UUID_A), member, &[]);
            let out = run(&p).await;
            let u = unpinned_mark(&out, "crates/a/Cargo.toml");
            assert!(
                u.detail.contains(from)
                    && u.detail.contains("roll the patch back")
                    && !u.detail.contains("re-run `socket-patch scan`"),
                "{member}: {}",
                u.detail
            );
        }
    }

    /// A declaration that names the Socket registry but also a `path`,
    /// `git` or `registry-index` source is not a pin (the hosted rewriter's
    /// own check): cargo builds that source. Beside a real pin it withholds
    /// the statement; alone it still keeps the ref (Socket's wiring is
    /// present) but never attests it.
    #[tokio::test]
    async fn a_socket_registry_beside_another_source_is_not_a_pin() {
        let reg = format!("registry = \"socket-patch-{UUID_A}\"");
        for extra in [
            "path = \"../serde\"",
            "git = \"https://github.com/serde-rs/serde\"",
            "registry-index = \"https://corp.example/index\"",
        ] {
            let member = format!("serde = {{ version = \"1\", {reg}, {extra} }}");
            let p = mixed_workspace(&pinned("serde", "1", UUID_A), &member, &[]);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
            );
            unpinned_mark(&out, "crates/a/Cargo.toml");

            let p = Project::new();
            p.write("Cargo.toml", manifest(&member));
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
            );
            p.write(".cargo/config.toml", registry_block(UUID_A));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
            );
            unpinned_mark(&out, "Cargo.toml");
        }
    }

    /// A `[workspace.dependencies]` entry is a template: cargo resolves it
    /// only for a manifest that inherits it (`workspace = true`). An
    /// unpinned template nobody inherits builds nothing; an inherited one
    /// does.
    #[tokio::test]
    async fn an_unpinned_workspace_template_counts_only_when_inherited() {
        for (member_dep, inherited) in [
            ("other = \"1\"", false),
            ("serde = { workspace = true }", true),
        ] {
            let p = Project::new();
            p.write(
                "Cargo.toml",
                format!(
                    "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\n\
                     serde = \"1\"\n\n[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                     [dependencies]\n{}\n",
                    pinned("serde", "1", UUID_A)
                ),
            );
            p.write(
                "crates/a/Cargo.toml",
                format!(
                    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                     {member_dep}\n"
                ),
            );
            p.write(
                "Cargo.lock",
                lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
            );
            p.write(".cargo/config.toml", registry_block(UUID_A));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
            );
            if inherited {
                unpinned_mark(&out, "Cargo.toml");
            } else {
                assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
            }
        }
    }

    /// The root pins the lock's patch A, a member pins ANOTHER patch B for
    /// the same version: the files disagree, so both wirings are emitted
    /// and the CLI's conflict gate refuses to pick one. A member pin whose
    /// requirement excludes the locked version is about another version.
    #[tokio::test]
    async fn a_member_pinned_to_another_patch_is_a_conflict_pair() {
        let p = mixed_workspace(
            &pinned("serde", "1", UUID_A),
            &pinned("serde", "1", UUID_B),
            &[],
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted),
                ("pkg:cargo/serde@1.0.1", UUID_B, WiringMode::Hosted),
            ],
        );
        let b = out.refs.iter().find(|r| r.uuid == UUID_B).unwrap();
        assert_eq!(
            b.source_file,
            std::path::PathBuf::from("crates/a/Cargo.toml")
        );
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);

        let p = mixed_workspace(
            &pinned("serde", "1", UUID_A),
            &pinned("serde", "0.9", UUID_B),
            &[],
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );

        // The lock resolves the member's B pin too, at another version: B's
        // registry serves only that version, a separate patched package
        // with its own ref, not a conflict over 1.0.1.
        let b_index = index(UUID_B);
        let p = mixed_workspace(
            &pinned("serde", "1", UUID_A),
            &pinned("serde", "1", UUID_B),
            &[("1.0.5", b_index.as_str())],
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted),
                ("pkg:cargo/serde@1.0.5", UUID_B, WiringMode::Hosted),
            ],
        );
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
    }

    /// A manifest under `.socket/` (a path dependency into Socket's own
    /// tree, as a vendored copy is) is not a declaration the hosted
    /// rewriter pins, so it never decides: the lock stays the only word.
    #[tokio::test]
    async fn manifests_under_dot_socket_are_not_declarations() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            manifest("local = { path = \".socket/local\" }"),
        );
        p.write(
            ".socket/local/Cargo.toml",
            "[package]\nname = \"local\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
        );
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
    }

    /// With no lock, a member's pin is an unlocked pin carrying the member's
    /// requirement, attributed to the member manifest.
    #[tokio::test]
    async fn lockless_member_pin_is_an_unlocked_pin() {
        let p = Project::new();
        workspace_with_member(&p, &pinned("serde", "1", UUID_A));
        p.write(".cargo/config.toml", registry_block(UUID_A));
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(out.unlocked_pins.len(), 1, "{:#?}", out.unlocked_pins);
        let pin = &out.unlocked_pins[0];
        assert_eq!(pin.file, std::path::PathBuf::from("crates/a/Cargo.toml"));
        assert_eq!(pin.version_reqs, vec!["1".to_string()]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        assert_eq!(
            out.diagnostics[0].file,
            std::path::PathBuf::from("crates/a/Cargo.toml")
        );
    }

    /// A workspace whose root pins `serde` and declares `crates/*` members.
    fn pinned_root_workspace(p: &Project) {
        p.write(
            "Cargo.toml",
            format!(
                "[workspace]\nmembers = [\"crates/*\"]\n\n[package]\nname = \"app\"\n\
                 version = \"0.1.0\"\n\n[dependencies]\n{}\n",
                pinned("serde", "1", UUID_A)
            ),
        );
    }

    fn member(p: &Project, dir: &str, deps: &str) {
        p.write(
            &format!("crates/{dir}/Cargo.toml"),
            format!("[package]\nname = \"{dir}\"\nversion = \"0.1.0\"\n\n[dependencies]\n{deps}\n"),
        );
    }

    /// REVIEW (lockless members): a member's unpinned declaration at a
    /// version the pin does not reach (`serde = "0.9"` beside the root's
    /// pinned `serde = "1"`, which the rewriter leaves alone) keeps the
    /// lockless pin; it only excludes the versions it accepts. One that
    /// accepts the record's version, or that has no requirement at all (a
    /// git dependency), leaves the record unrouted.
    #[tokio::test]
    async fn lockless_pin_survives_a_member_declaring_another_version() {
        let record = "pkg:cargo/serde@1.0.1";
        for (member_decl, live) in [
            ("serde = \"0.9\"", true),
            ("serde = \"1.0\"", false),
            ("serde = { git = \"https://example.com/serde\" }", false),
        ] {
            let p = Project::new();
            pinned_root_workspace(&p);
            member(&p, "a", member_decl);
            p.write(".cargo/config.toml", registry_block(UUID_A));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                out.hosted_claim(record, UUID_A),
                Some(live),
                "{member_decl}: {:#?}",
                out.unlocked_pins
            );
        }
        let p = Project::new();
        pinned_root_workspace(&p);
        member(&p, "a", "serde = \"0.9\"");
        p.write(".cargo/config.toml", registry_block(UUID_A));
        let out = run(&p).await;
        assert_eq!(out.unlocked_pins.len(), 1);
        assert_eq!(out.unlocked_pins[0].excluded_reqs, vec!["0.9".to_string()]);
        assert_eq!(
            out.hosted_claim("pkg:cargo/serde@0.9.5", UUID_A),
            Some(false),
            "the member resolves 0.9 from crates.io"
        );
    }

    /// REVIEW (one pin per crate and patch): the root and two members pin the
    /// same patch — one lockless pin carrying every requirement, one
    /// diagnostic listing each manifest once.
    #[tokio::test]
    async fn one_lockless_pin_and_diagnostic_per_crate_and_patch() {
        let p = Project::new();
        pinned_root_workspace(&p);
        member(&p, "a", &pinned("serde", "1.0", UUID_A));
        member(
            &p,
            "b",
            &format!(
                "{}\n\n[dev-dependencies]\n{}",
                pinned("serde", "1", UUID_A),
                pinned("serde", "1", UUID_A)
            ),
        );
        p.write(".cargo/config.toml", registry_block(UUID_A));
        let out = run(&p).await;
        assert_eq!(out.unlocked_pins.len(), 1, "{:#?}", out.unlocked_pins);
        let pin = &out.unlocked_pins[0];
        assert_eq!(pin.file, std::path::PathBuf::from("Cargo.toml"));
        assert_eq!(pin.version_reqs, vec!["1".to_string(), "1.0".to_string()]);
        assert!(pin.excluded_reqs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        assert!(
            out.diagnostics[0]
                .detail
                .starts_with("Cargo.toml, crates/a/Cargo.toml, crates/b/Cargo.toml: serde"),
            "{}",
            out.diagnostics[0].detail
        );
    }

    /// REVIEW (perf): members only matter to Socket wiring, so a project
    /// with a lock that resolves nothing from a Socket patch server — or no
    /// lock and no `socket-patch-` pin anywhere — reads no member manifest
    /// as discovery's own (none in [`Discovery::read`], which the full run
    /// collects).
    #[tokio::test]
    async fn members_are_read_only_when_socket_wiring_could_need_them() {
        let member_read = |out: &Discovery| {
            out.read
                .iter()
                .any(|r| r.file == std::path::Path::new("crates/a/Cargo.toml"))
        };
        // A plain lock: no walk.
        let p = Project::new();
        workspace_with_member(&p, "serde = \"1\"");
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(CRATES_IO), Some(CKSUM))]),
        );
        assert!(!member_read(&p.discover().await));
        // No lock, no pin anywhere: walked, not adopted.
        let p = Project::new();
        workspace_with_member(&p, "serde = \"1\"");
        assert!(!member_read(&p.discover().await));
        // A Socket-sourced lock entry: read.
        let p = Project::new();
        workspace_with_member(&p, "serde = \"1\"");
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        assert!(member_read(&p.discover().await));
        // No lock, a member pin: read.
        let p = Project::new();
        workspace_with_member(&p, &pinned("serde", "1", UUID_A));
        assert!(member_read(&p.discover().await));
    }

    /// A rotated grant token in the definition is the same patch.
    #[tokio::test]
    async fn rotated_token_in_the_definition_still_agrees() {
        let p = Project::new();
        p.write("Cargo.toml", manifest(&pinned("serde", "1", UUID_A)));
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        p.write(
            ".cargo/config.toml",
            format!(
                "[registries.socket-patch-{UUID_A}]\nindex = \"sparse+https://patch.socket.dev/patch-registry/cargo/other-token/{UUID_A}/index/\"\n"
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
    }

    /// Definitions alone never make a ref; a pin with no Socket-sourced lock
    /// entry is diagnosed, not guessed at.
    #[tokio::test]
    async fn definitions_and_unresolved_pins_are_not_refs() {
        // Definition only, crates.io lock.
        let p = Project::new();
        p.write(".cargo/config.toml", registry_block(UUID_A));
        p.write("Cargo.toml", manifest("serde = \"1\""));
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(CRATES_IO), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        // The leftover definition names the patch on the Socket host: it is
        // recognized, so a ledger claim for it is dead (rule 11).
        assert_eq!(
            out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A),
            Some(false)
        );

        // Pin, but no lock at all / a lock resolving crates.io.
        for with_lock in [false, true] {
            let p = Project::new();
            p.write(".cargo/config.toml", registry_block(UUID_A));
            p.write("Cargo.toml", manifest(&pinned("serde", "1", UUID_A)));
            if with_lock {
                p.write(
                    "Cargo.lock",
                    lock(&[("serde", "1.0.1", Some(CRATES_IO), Some(CKSUM))]),
                );
            }
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_REF_UNATTRIBUTABLE],
                "{with_lock}"
            );
            // With NO lock the pin is `rewrite_cargo`'s own `LockCommit::Absent`
            // output (a library that gitignores Cargo.lock): live wiring for a
            // ledger record whose version satisfies the requirement. A lock
            // resolving crates.io positively says otherwise.
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A),
                Some(!with_lock),
                "{with_lock}"
            );
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@2.0.0", UUID_A),
                Some(false),
                "{with_lock}: outside the manifest requirement"
            );
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_B),
                None,
                "{with_lock}: another patch is not mentioned at all"
            );
        }

        // Lockless, but not every declaration routes to the patch registry
        // (a plain crates.io declaration too), or the registry is defined for
        // another patch: dead.
        for (deps, config) in [
            (
                format!(
                    "{}\n[dev-dependencies]\nserde = \"1\"",
                    pinned("serde", "1", UUID_A)
                ),
                registry_block(UUID_A),
            ),
            (
                pinned("serde", "1", UUID_A),
                registry_block(UUID_B).replace(
                    &format!("socket-patch-{UUID_B}"),
                    &format!("socket-patch-{UUID_A}"),
                ) + &registry_block(UUID_A).replace(&format!("socket-patch-{UUID_A}]"), "unused]"),
            ),
        ] {
            let p = Project::new();
            p.write(".cargo/config.toml", &config);
            p.write("Cargo.toml", manifest(&deps));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                out.hosted_claim("pkg:cargo/serde@1.0.1", UUID_A),
                Some(false),
                "{deps}\n{config}"
            );
        }

        // A malformed socket-patch-* registry name.
        let p = Project::new();
        p.write(
            "Cargo.toml",
            manifest("serde = { version = \"1\", registry = \"socket-patch-UUID\" }"),
        );
        let out = run(&p).await;
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// `[patch.crates-io] x = { registry = "socket-patch-<U>" }` (hand-wired)
    /// is a declaration cargo honors.
    #[tokio::test]
    async fn patch_table_registry_pin_counts_as_the_declaration() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\n{}\n",
                manifest("serde = \"1\""),
                pinned("serde", "1", UUID_A)
            ),
        );
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        // The crates.io declaration is what the entry redirects: not unpinned.
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);

        // A declaration from ANOTHER registry is not redirected by
        // `[patch.crates-io]`: cargo builds my-corp's serde for it.
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\n{}\n",
                manifest("serde = \"1\"\nalt = { package = \"serde\", version = \"1\", registry = \"my-corp\" }"),
                pinned("serde", "1", UUID_A)
            ),
        );
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_eq!(out.unattested.len(), 1, "{:#?}", out.unattested);
        assert!(
            out.unattested[0].detail.contains("from registry `my-corp`"),
            "{:#?}",
            out.unattested
        );
    }

    /// A registry pin in the effective config's `[patch]` counts as a
    /// declaration for a crate the manifest declares without one.
    #[tokio::test]
    async fn config_patch_registry_pin_counts_for_a_declared_crate() {
        let p = Project::new();
        p.write("Cargo.toml", manifest("serde = \"1\""));
        p.write(
            ".cargo/config.toml",
            format!("[patch.crates-io]\n{}\n", pinned("serde", "1", UUID_A)),
        );
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.1", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.1", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
    }

    #[tokio::test]
    async fn unsafe_lock_coordinates_are_diagnosed() {
        let p = Project::new();
        p.write(
            "Cargo.lock",
            lock(&[
                ("../evil", "1.0.0", Some(&index(UUID_A)), Some(CKSUM)),
                ("serde", "../1.0.0", Some(&index(UUID_A)), Some(CKSUM)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID, DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn malformed_files_are_diagnosed_not_fatal() {
        let p = Project::new();
        p.write("Cargo.lock", "[[package]\nname = ");
        p.write("Cargo.toml", "[dependencies\nserde = ");
        p.write(".cargo/config.toml", "= = =");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(
            diag_codes(&out),
            vec![
                DIAG_LOCKFILE_UNPARSEABLE,
                DIAG_LOCKFILE_UNPARSEABLE,
                DIAG_LOCKFILE_UNPARSEABLE
            ]
        );
        let mut files: Vec<_> = out.diagnostics.iter().map(|d| d.file.clone()).collect();
        files.sort();
        assert_eq!(
            files,
            [".cargo/config.toml", "Cargo.lock", "Cargo.toml"]
                .map(std::path::PathBuf::from)
                .to_vec()
        );

        // Well-formed TOML of the wrong shape: silently nothing.
        let p = Project::new();
        p.write("Cargo.lock", "package = 3\n");
        p.write("Cargo.toml", "dependencies = \"x\"\npatch = 1\n");
        p.write(
            ".cargo/config.toml",
            "patch = { crates-io = 5 }\nregistries = []\n",
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    // ── vendored ─────────────────────────────────────────────────────

    /// The pre-v5 shape `vendor`'s cargo backend wrote (still honored): a
    /// project-config `[patch]` entry plus an untagged detached (sourceless)
    /// lock entry.
    #[tokio::test]
    async fn vendored_patch_entry_with_detached_lock_entry() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let p = Project::new();
        p.write(".cargo/config.toml", patch_config(&[("cfg-if", &rel)]));
        p.write("Cargo.toml", manifest("cfg-if = \"1\""));
        p.write("Cargo.lock", lock(&[("cfg-if", "1.0.4", None, None)]));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        let r = &out.refs[0];
        assert_eq!(
            r.source_file,
            std::path::PathBuf::from(".cargo/config.toml")
        );
        assert_eq!(r.artifact_rel.as_deref(), Some(rel.as_str()));
    }

    /// Every spelling of the config entry (inline table, sub-table,
    /// `[patch] crates-io = {…}`, `./` and backslash paths, trailing slash,
    /// a renamed `package =`, a pre-release version) and no lock at all.
    #[tokio::test]
    async fn vendored_spellings_and_lockless_projects() {
        let configs = [
            patch_config(&[("serde", &vendor_path(UUID_A, "serde-1.0.0-rc.1"))]),
            format!(
                "[patch.crates-io.serde]\npath = \"./{}/\"\n",
                vendor_path(UUID_A, "serde-1.0.0-rc.1")
            ),
            format!(
                "[patch]\ncrates-io = {{ serde = {{ path = '{}' }} }}\n",
                vendor_path(UUID_A, "serde-1.0.0-rc.1").replace('/', "\\")
            ),
            format!(
                "[patch.crates-io]\nalias = {{ package = \"serde\", path = \"{}\" }}\n",
                vendor_path(UUID_A, "serde-1.0.0-rc.1")
            ),
        ];
        for config in configs {
            let p = Project::new();
            p.write(".cargo/config.toml", &config);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/serde@1.0.0-rc.1", UUID_A, WiringMode::Vendored)],
            );
            assert!(
                out.diagnostics.is_empty(),
                "{config}: {:#?}",
                out.diagnostics
            );
        }
    }

    /// Cargo reads `.cargo/config` instead of `config.toml` when both
    /// exist: only the legacy file's wiring counts, the ignored file's is
    /// diagnosed.
    #[tokio::test]
    async fn legacy_config_wins_and_the_ignored_file_is_diagnosed() {
        let p = Project::new();
        p.write(
            ".cargo/config",
            patch_config(&[("serde", &vendor_path(UUID_A, "serde-1.0.0"))]),
        );
        p.write(
            ".cargo/config.toml",
            patch_config(&[("libc", &vendor_path(UUID_B, "libc-0.2.0"))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.0", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(
            out.refs[0].source_file,
            std::path::PathBuf::from(".cargo/config")
        );
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert_eq!(
            out.diagnostics[0].file,
            std::path::PathBuf::from(".cargo/config.toml")
        );
    }

    /// An ignored `config.toml` holding only a Socket registry definition
    /// (no vendored `[patch]`) is still Socket-shaped, so it is diagnosed.
    #[tokio::test]
    async fn ignored_config_toml_with_only_a_registry_definition_is_diagnosed() {
        let p = Project::new();
        p.write(".cargo/config", "[build]\njobs = 1\n");
        p.write(".cargo/config.toml", registry_block(UUID_A));
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert_eq!(
            out.diagnostics[0].file,
            std::path::PathBuf::from(".cargo/config.toml")
        );
    }

    /// A `[patch]` in the root manifest itself (hand-wired) is honored by
    /// cargo too.
    #[tokio::test]
    async fn manifest_patch_table_is_read() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\nserde = {{ path = \"{}\" }}\n",
                manifest("serde = \"1\""),
                vendor_path(UUID_A, "serde-1.0.0")
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.0", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(
            out.refs[0].source_file,
            std::path::PathBuf::from("Cargo.toml")
        );
    }

    /// The v5 `vendor` output: the root manifest's `[patch.crates-io]`,
    /// including a SECOND vendored version of the same crate under the
    /// Socket-owned `<name>-socket-<uuid8>` key with `package =` — both
    /// attest, key-agnostically, with no project config at all.
    #[tokio::test]
    async fn v5_manifest_wiring_with_two_versions_attests_both() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\n\
                 cfg-if-socket-0a1b2c3d = {{ package = \"cfg-if\", path = \"{}\" }}\n",
                manifest("cfg-if = \"1\"\nold = { package = \"cfg-if\", version = \"0.1\" }"),
                vendor_path(UUID_A, "cfg-if-1.0.4"),
                vendor_path(UUID_B, "cfg-if-0.1.10"),
            ),
        );
        p.write(
            "Cargo.lock",
            lock(&[
                ("cfg-if", "0.1.10", None, None),
                ("cfg-if", "1.0.4", None, None),
            ]),
        );
        let out = run(&p).await;
        let mut want = vec![
            ("pkg:cargo/cfg-if@0.1.10", UUID_B, WiringMode::Vendored),
            ("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored),
        ];
        want.sort();
        assert_refs(&out, &want);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        assert!(out
            .refs
            .iter()
            .all(|r| r.source_file == std::path::Path::new("Cargo.toml")));
    }

    /// Half-migrated (the legacy config entry could not be removed): the
    /// manifest and the pre-v5 config wire the SAME copy — one package,
    /// one patch, no conflict.
    #[tokio::test]
    async fn half_migrated_manifest_and_legacy_config_agree() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        for key in ["cfg-if-socket-aaaaaaaa", "cfg-if"] {
            let p = Project::new();
            p.write(
                "Cargo.toml",
                format!(
                    "{}\n[patch.crates-io]\n{key} = {{ package = \"cfg-if\", path = \"{rel}\" }}\n",
                    manifest("cfg-if = \"1\"")
                ),
            );
            p.write(".cargo/config.toml", patch_config(&[("cfg-if", &rel)]));
            p.write("Cargo.lock", lock(&[("cfg-if", "1.0.4", None, None)]));
            let out = p.discover().await;
            let triples = ref_triples(&out);
            assert!(
                triples
                    .iter()
                    .all(|t| t.0 == "pkg:cargo/cfg-if@1.0.4" && t.1 == UUID_A),
                "{triples:?}"
            );
            assert!(!triples.is_empty());
            assert!(out.diagnostics.is_empty(), "{key}: {:#?}", out.diagnostics);
        }
    }

    /// Cargo lets a config `[patch]` item replace the manifest item with the
    /// same key: a Socket manifest entry whose key a user config entry
    /// redefines is dead wiring (the user's path builds, and the lock looks
    /// identical), so it is never attested.
    #[tokio::test]
    async fn manifest_entry_shadowed_by_a_same_key_config_entry_is_not_a_ref() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\ncfg-if-socket-aaaaaaaa = {{ package = \"cfg-if\", path = \"{rel}\" }}\n",
                manifest("cfg-if = \"1\"")
            ),
        );
        p.write(
            ".cargo/config.toml",
            "[patch.crates-io]\ncfg-if-socket-aaaaaaaa = { package = \"cfg-if\", path = \"../cfg-if\" }\n",
        );
        p.write("Cargo.lock", lock(&[("cfg-if", "1.0.4", None, None)]));
        let out = p.discover().await;
        assert!(ref_triples(&out).is_empty(), "{:?}", ref_triples(&out));
        assert!(
            out.diagnostics.iter().any(|d| d
                .detail
                .contains("redefines `[patch]` key `cfg-if-socket-aaaaaaaa`")),
            "{:#?}",
            out.diagnostics
        );
    }

    /// A `[patch."<crates.io URL>"]` table replaces `[patch.crates-io]`
    /// wholesale in cargo: the Socket entry under `crates-io` is dead.
    #[tokio::test]
    async fn manifest_entry_under_a_url_replaced_crates_io_table_is_not_a_ref() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\ncfg-if-socket-aaaaaaaa = {{ package = \"cfg-if\", path = \"{rel}\" }}\n\n\
                 [patch.\"https://github.com/rust-lang/crates.io-index\"]\nitoa = {{ path = \"../itoa\" }}\n",
                manifest("cfg-if = \"1\"")
            ),
        );
        p.write("Cargo.lock", lock(&[("cfg-if", "1.0.4", None, None)]));
        let out = p.discover().await;
        assert!(ref_triples(&out).is_empty(), "{:?}", ref_triples(&out));
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.detail.contains("replaces `[patch.crates-io]`")),
            "{:#?}",
            out.diagnostics
        );
    }

    /// A Socket-shaped key whose `package` names ANOTHER crate than the
    /// copy leaf is not a reference (the leaf must be `<package>-<ver>`).
    #[tokio::test]
    async fn v5_socket_key_with_a_mismatched_package_is_not_a_ref() {
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\ncfg-if-socket-7c8d9e0f = {{ package = \"libc\", path = \"{}\" }}\n",
                manifest("cfg-if = \"1\""),
                vendor_path(UUID_A, "cfg-if-1.0.4"),
            ),
        );
        p.write("Cargo.lock", lock(&[("cfg-if", "1.0.4", None, None)]));
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// The lock is the liveness truth source: a registry-sourced entry
    /// (re-resolved / hosted takeover) or a missing one (`[[patch.unused]]`)
    /// means the copy is not built.
    #[tokio::test]
    async fn vendored_entry_the_lock_does_not_build_is_not_a_ref() {
        let rel = vendor_path(UUID_A, "serde-1.0.0");
        let unused = format!(
            "{}\n[[patch.unused]]\nname = \"serde\"\nversion = \"1.0.0\"\n",
            lock(&[("serde", "0.9.0", Some(CRATES_IO), Some(CKSUM))])
        );
        // REGRESSION: the user's own path dependency on the crate is ALSO
        // sourceless — cargo builds it and records the vendored `[patch]`
        // as unused (the exact lock real cargo 1.97 writes for
        // `serde = { path = "my-serde" }` beside the stale `[patch]`).
        // Before, the sourceless entry alone made this a ref, and `vex`
        // attested `(vendored)` for a copy the build never compiles.
        let shadowed_by_path_dep = format!(
            "{}\n[[patch.unused]]\nname = \"serde\"\nversion = \"1.0.0\"\n",
            lock(&[("serde", "1.0.0", None, None)])
        );
        for lock_text in [
            lock(&[("serde", "1.0.0", Some(CRATES_IO), Some(CKSUM))]),
            unused,
            lock(&[("serde", "1.0.1", None, None)]),
            shadowed_by_path_dep,
        ] {
            let p = Project::new();
            p.write(".cargo/config.toml", patch_config(&[("serde", &rel)]));
            p.write("Cargo.lock", &lock_text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{lock_text}");
            // The unbuilt copy's patch is RECOGNIZED: a vendor ledger entry
            // for it is dead, not kept alive by the config naming the dir.
            assert_eq!(
                out.vendored_claim("pkg:cargo/serde@1.0.0", UUID_A, &rel),
                Some(false),
                "{lock_text}"
            );
        }
    }

    /// Hosted takeover of a vendored crate: the lock's Socket source is the
    /// ref; the stale `[patch]` entry is diagnosed.
    #[tokio::test]
    async fn hosted_takeover_leaves_only_the_hosted_ref() {
        let p = Project::new();
        p.write(
            ".cargo/config.toml",
            format!(
                "{}\n{}",
                patch_config(&[("serde", &vendor_path(UUID_B, "serde-1.0.0"))]),
                registry_block(UUID_A)
            ),
        );
        p.write("Cargo.toml", manifest(&pinned("serde", "1", UUID_A)));
        p.write(
            "Cargo.lock",
            lock(&[("serde", "1.0.0", Some(&index(UUID_A)), Some(CKSUM))]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/serde@1.0.0", UUID_A, WiringMode::Hosted)],
        );
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn vendored_path_traversal_and_mismatches_are_rejected() {
        let a = UUID_A;
        for path in [
            format!("../.socket/vendor/cargo/{a}/serde-1.0.0"),
            format!("/abs/.socket/vendor/cargo/{a}/serde-1.0.0"),
            format!("sub/.socket/vendor/cargo/{a}/serde-1.0.0"),
            format!(".socket/vendor/cargo/{a}/../../../etc"),
            format!(".socket/vendor/cargo/{a}/serde-1.0.0/../../x"),
            ".socket/vendor/cargo/not-a-uuid/serde-1.0.0".to_string(),
            format!(".socket/vendor/cargo/{}/serde-1.0.0", a.to_uppercase()),
            // Wrong ecosystem dir.
            format!(".socket/vendor/npm/{a}/serde-1.0.0.tgz"),
            // Leaf names a different crate / nested leaf / no version.
            format!(".socket/vendor/cargo/{a}/evil-1.0.0"),
            format!(".socket/vendor/cargo/{a}/serde-1.0.0/src"),
            format!(".socket/vendor/cargo/{a}/serde"),
            format!(".socket/vendor/cargo/{a}/serde-"),
            format!(".socket/vendor/cargo/{a}"),
        ] {
            let p = Project::new();
            p.write(".cargo/config.toml", patch_config(&[("serde", &path)]));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{path}");
        }
    }

    /// User paths, git patches and the uuid-less legacy redirect copies are
    /// silently not ours.
    #[tokio::test]
    async fn non_socket_patch_entries_are_ignored() {
        let p = Project::new();
        p.write(
            ".cargo/config.toml",
            "[patch.crates-io]\n\
             a = { path = \"../forks/a\" }\n\
             b = { git = \"https://github.com/x/b\" }\n\
             c = { path = \".socket/cargo-patches/c-1.0.0\" }\n\
             d = \"1.0\"\n",
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// Hosted and vendored wiring for different crates in one project, via
    /// the full orchestrator.
    #[tokio::test]
    async fn hosted_and_vendored_together_through_discover() {
        let p = Project::new();
        p.write(
            ".cargo/config.toml",
            format!(
                "{}\n{}",
                patch_config(&[("cfg-if", &vendor_path(UUID_B, "cfg-if-1.0.4"))]),
                registry_block(UUID_A)
            ),
        );
        p.write(
            "Cargo.toml",
            manifest(&format!("{}\ncfg-if = \"1\"", pinned("serde", "1", UUID_A))),
        );
        p.write(
            "Cargo.lock",
            lock(&[
                ("cfg-if", "1.0.4", None, None),
                ("serde", "1.0.190", Some(&index(UUID_A)), Some(CKSUM)),
                ("libc", "0.2.0", Some(CRATES_IO), Some(CKSUM)),
            ]),
        );
        let out = p.discover().await;
        assert_eq!(
            ref_triples(&out),
            {
                let mut v = vec![
                    hosted("pkg:cargo/serde@1.0.190", UUID_A),
                    (
                        "pkg:cargo/cfg-if@1.0.4".to_string(),
                        UUID_B.to_string(),
                        WiringMode::Vendored,
                    ),
                ];
                v.sort();
                v
            },
            "{:#?}",
            out.diagnostics
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    // ── tagged vendored versions ─────────────────────────────────────

    fn socket_manifest(rel: &str) -> String {
        format!(
            "{}\n[patch.crates-io]\ncfg-if-socket-aaaaaaaa = {{ package = \"cfg-if\", path = \"{rel}\" }}\n",
            manifest("cfg-if = \"1\"")
        )
    }

    /// The v5 shape: the lock's detached entry carries the copy's tagged
    /// version. The purl is the tag stripped; a pre-release and a version
    /// with its own build metadata read the same way.
    #[tokio::test]
    async fn tagged_lock_version_is_the_identity() {
        for version in ["1.0.4", "1.0.0-rc.1", "2.0.1+zstd.1.5.2"] {
            let rel = vendor_path(UUID_A, &format!("cfg-if-{version}"));
            let tagged = crate::vendor::cargo_tag::tag_version(version, UUID_A);
            let p = Project::new();
            p.write("Cargo.toml", socket_manifest(&rel));
            p.write("Cargo.lock", lock(&[("cfg-if", &tagged, None, None)]));
            let out = run(&p).await;
            let purl = format!("pkg:cargo/cfg-if@{version}");
            assert_refs(&out, &[(purl.as_str(), UUID_A, WiringMode::Vendored)]);
            assert!(
                out.diagnostics.is_empty(),
                "{version}: {:#?}",
                out.diagnostics
            );
        }
    }

    /// A detached entry tagged for ANOTHER uuid: cargo builds a different
    /// copy than the wiring names — no ref, and the ledger entry for the
    /// named copy is dead.
    #[tokio::test]
    async fn lock_tag_for_another_uuid_is_dead_wiring() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let p = Project::new();
        p.write("Cargo.toml", socket_manifest(&rel));
        p.write(
            "Cargo.lock",
            lock(&[("cfg-if", &format!("1.0.4+socket.{UUID_B}"), None, None)]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE],
            "{:#?}",
            out.diagnostics
        );
        assert!(out.diagnostics.iter().any(|d| d.detail.contains(UUID_B)));
        assert_eq!(
            out.vendored_claim("pkg:cargo/cfg-if@1.0.4", UUID_A, &rel),
            Some(false)
        );
    }

    /// A tagged lock entry no visible wiring points at is diagnosed, never
    /// attested from the lock alone.
    #[tokio::test]
    async fn tagged_lock_entry_without_wiring_is_unattributable() {
        let p = Project::new();
        p.write("Cargo.toml", manifest("cfg-if = \"1\""));
        p.write(
            "Cargo.lock",
            lock(&[("cfg-if", &format!("1.0.4+socket.{UUID_A}"), None, None)]),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
    }

    /// The copy's own `Cargo.toml` tag decides an UNTAGGED sourceless lock
    /// entry: it is the pre-tag vendored shape only beside an untagged (or
    /// missing — verification reports that) copy; beside a tagged or
    /// unreadable copy it is some other crate cargo built. A copy tagged for
    /// another uuid than its path is dead wiring whatever the lock says.
    #[tokio::test]
    async fn copy_manifest_tag_decides_an_untagged_lock_entry() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let copy_toml = format!("{rel}/Cargo.toml");
        let at = |v: &str| format!("[package]\nname = \"cfg-if\"\nversion = \"{v}\"\n");
        let tag = |u: &str| crate::vendor::cargo_tag::tag_version("1.0.4", u);
        let purl = "pkg:cargo/cfg-if@1.0.4";
        let untagged_lock = lock(&[("cfg-if", "1.0.4", None, None)]);
        let tagged_lock = lock(&[("cfg-if", &tag(UUID_A), None, None)]);

        for (what, copy, lock_text, attests) in [
            ("no copy manifest", None, &untagged_lock, true),
            ("untagged copy", Some(at("1.0.4")), &untagged_lock, true),
            (
                "tagged copy, untagged lock",
                Some(at(&tag(UUID_A))),
                &untagged_lock,
                false,
            ),
            (
                "tagged copy, tagged lock",
                Some(at(&tag(UUID_A))),
                &tagged_lock,
                true,
            ),
            (
                "copy tagged for another uuid",
                Some(at(&tag(UUID_B))),
                &tagged_lock,
                false,
            ),
            (
                "copy tagged for another uuid, untagged lock",
                Some(at(&tag(UUID_B))),
                &untagged_lock,
                false,
            ),
        ] {
            let p = Project::new();
            p.write("Cargo.toml", socket_manifest(&rel));
            p.write("Cargo.lock", lock_text);
            if let Some(copy) = copy {
                p.write(&copy_toml, copy);
            }
            let out = run(&p).await;
            if attests {
                assert_refs(&out, &[(purl, UUID_A, WiringMode::Vendored)]);
                assert!(out.diagnostics.is_empty(), "{what}: {:#?}", out.diagnostics);
            } else {
                assert_refs(&out, &[]);
                assert!(
                    diag_codes(&out).contains(&DIAG_REF_INVALID),
                    "{what}: {:#?}",
                    out.diagnostics
                );
            }
        }

        // Unreadable (a directory where the manifest should be): fail
        // closed — the untagged entry never counts.
        let p = Project::new();
        p.write("Cargo.toml", socket_manifest(&rel));
        p.write("Cargo.lock", &untagged_lock);
        std::fs::create_dir_all(p.root().join(&copy_toml)).unwrap();
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(
            diag_codes(&out).contains(&DIAG_REF_INVALID),
            "{:#?}",
            out.diagnostics
        );
    }

    /// A user's same-version path fork locked beside the tagged copy (real
    /// cargo 1.97 sorts the untagged entry first) does not hide the copy;
    /// beside another uuid's tagged entry the wiring is still dead.
    #[tokio::test]
    async fn a_same_version_fork_beside_the_tagged_copy_is_ignored() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let tag = |u: &str| crate::vendor::cargo_tag::tag_version("1.0.4", u);
        for (tagged_for, attests) in [(UUID_A, true), (UUID_B, false)] {
            let p = Project::new();
            p.write("Cargo.toml", socket_manifest(&rel));
            p.write(
                &format!("{rel}/Cargo.toml"),
                format!(
                    "[package]\nname = \"cfg-if\"\nversion = \"{}\"\n",
                    tag(UUID_A)
                ),
            );
            p.write(
                "Cargo.lock",
                lock(&[
                    ("cfg-if", "1.0.4", None, None),
                    ("cfg-if", &tag(tagged_for), None, None),
                ]),
            );
            let out = run(&p).await;
            if attests {
                assert_refs(
                    &out,
                    &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
                );
            } else {
                assert_refs(&out, &[]);
                assert!(
                    diag_codes(&out).contains(&DIAG_REF_INVALID),
                    "{:#?}",
                    out.diagnostics
                );
            }
        }
    }

    // ── vendored: copies the [patch] does not redirect ───────────────

    const MY_CORP: &str = "registry+https://my-corp.example/index";

    /// A v5-vendored workspace: the root wires cfg-if 1.0.4 to the tagged
    /// copy for patch A through `[patch.crates-io]` (plus `root_extra`
    /// appended to the root manifest) and declares it from crates.io; the
    /// member `crates/a` declares it with `member_dep`. The lock holds the
    /// tagged copy plus `extra` entries `(version, source)`.
    fn vendored_workspace(member_dep: &str, root_extra: &str, extra: &[(&str, &str)]) -> Project {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let p = Project::new();
        p.write(
            "Cargo.toml",
            format!(
                "[workspace]\nmembers = [\"crates/*\"]\n\n{}\n[patch.crates-io]\n\
                 cfg-if-socket-aaaaaaaa = {{ package = \"cfg-if\", path = \"{rel}\" }}\n\
                 {root_extra}\n",
                manifest("cfg-if = \"1\"")
            ),
        );
        p.write(
            "crates/a/Cargo.toml",
            format!(
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\n{member_dep}\n"
            ),
        );
        let tagged = crate::vendor::cargo_tag::tag_version("1.0.4", UUID_A);
        let mut pkgs = vec![("cfg-if", tagged.as_str(), None, None)];
        pkgs.extend(
            extra
                .iter()
                .map(|(v, s)| ("cfg-if", *v, Some(*s), Some(CKSUM))),
        );
        p.write("Cargo.lock", lock(&pkgs));
        p
    }

    /// The one unattested mark of `out`, asserted to be the vendored
    /// cfg-if ref's [`UnattestedKind::CargoPatchBypassed`] naming `file`.
    fn bypassed_mark<'a>(out: &'a Discovery, file: &str) -> &'a Unattested {
        assert_eq!(out.unattested.len(), 1, "{:#?}", out.unattested);
        let u = &out.unattested[0];
        assert_eq!(u.kind, UnattestedKind::CargoPatchBypassed);
        assert_eq!(
            (u.purl.as_str(), u.uuid.as_str()),
            ("pkg:cargo/cfg-if@1.0.4", UUID_A)
        );
        assert_eq!(u.file, std::path::PathBuf::from(file));
        u
    }

    /// REGRESSION: `[patch.crates-io]` redirects only crates.io
    /// declarations. A member that declares cfg-if from another registry or
    /// from git, at a requirement the patched 1.0.4 satisfies, resolves its
    /// own unpatched copy, which may be that very version. The vendored ref
    /// stays (rollback / remove find it, the ledger claim lives) but is not
    /// attested, naming the member.
    #[tokio::test]
    async fn a_member_from_another_source_bypasses_the_vendored_copy() {
        for (member, origin) in [
            (
                "cfg-if = { version = \"1\", registry = \"my-corp\" }",
                "from registry `my-corp`",
            ),
            (
                "fork = { package = \"cfg-if\", version = \"=1.0.4\", registry = \"my-corp\" }",
                "from registry `my-corp`",
            ),
            (
                "cfg-if = { git = \"https://example.com/cfg-if\" }",
                "from a git repository",
            ),
            (
                "cfg-if = { version = \"1\", registry-index = \"sparse+https://my-corp.example/index/\" }",
                "from the registry index sparse+https://my-corp.example/index/",
            ),
        ] {
            let p = vendored_workspace(member, "", &[]);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
            );
            assert!(
                out.diagnostics.is_empty(),
                "{member}: {:#?}",
                out.diagnostics
            );
            assert_eq!(
                out.vendored_claim(
                    "pkg:cargo/cfg-if@1.0.4",
                    UUID_A,
                    &vendor_path(UUID_A, "cfg-if-1.0.4")
                ),
                Some(true),
                "{member}"
            );
            let u = bypassed_mark(&out, "crates/a/Cargo.toml");
            assert!(
                u.detail.contains("crates/a/Cargo.toml declares cfg-if")
                    && u.detail.contains(origin)
                    && !u.detail.contains("also locks"),
                "{member}: {}",
                u.detail
            );
        }
    }

    /// The lock already holds a same-version cfg-if from another source
    /// (another registry, git, even crates.io) beside the vendored copy:
    /// cargo builds that copy unpatched whoever declares it, so the mark
    /// names the lock entry. A copy at another version is no such evidence.
    #[tokio::test]
    async fn a_same_version_lock_entry_from_any_source_bypasses_the_vendored_copy() {
        for source in [MY_CORP, "git+https://example.com/cfg-if#abc123", CRATES_IO] {
            let p = vendored_workspace("cfg-if = \"1\"", "", &[("1.0.4", source)]);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
            );
            let u = bypassed_mark(&out, "Cargo.lock");
            assert!(
                u.detail
                    .contains(&format!("Cargo.lock also locks cfg-if 1.0.4 from {source}")),
                "{source}: {}",
                u.detail
            );
        }
        let p = vendored_workspace("cfg-if = \"1\"", "", &[("0.1.10", MY_CORP)]);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
        );
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
    }

    /// What the `[patch]` wiring redirects stays attested: a member
    /// declaring cfg-if from crates.io, under any spelling, and a
    /// declaration from elsewhere whose requirement excludes the patched
    /// version, or a registry dependency whose `[patch.<registry>]` table
    /// also points at the same copy; and a `[workspace.dependencies]`
    /// template from another registry that no manifest inherits. A user's
    /// own path fork is the documented exception (see
    /// `a_same_version_fork_beside_the_tagged_copy_is_ignored`).
    #[tokio::test]
    async fn declarations_the_patch_redirects_keep_the_vendored_copy_attested() {
        let rel = vendor_path(UUID_A, "cfg-if-1.0.4");
        let covered = format!("\n[patch.my-corp]\ncfg-if = {{ path = \"{rel}\" }}\n");
        let template = "\n[workspace.dependencies]\n\
             cfg-if = { version = \"1\", registry = \"my-corp\" }\n";
        for (member, root_extra) in [
            ("cfg-if = \"1\"", ""),
            ("cfg-if = \"=1.0.4\"", ""),
            ("cfg-if = { version = \"1\", registry = \"crates-io\" }", ""),
            ("alias = { package = \"cfg-if\", version = \"1.0\" }", ""),
            ("cfg-if = { version = \"0.1\", registry = \"my-corp\" }", ""),
            (
                "cfg-if = { version = \"1\", registry = \"my-corp\" }",
                covered.as_str(),
            ),
            ("cfg-if = { path = \"../fork\" }", ""),
            ("cfg-if = \"1\"", template),
        ] {
            let p = vendored_workspace(member, root_extra, &[]);
            let out = run(&p).await;
            assert!(
                out.refs.iter().any(|r| r.purl == "pkg:cargo/cfg-if@1.0.4"
                    && r.uuid == UUID_A
                    && r.mode == WiringMode::Vendored),
                "{member}: {:#?}",
                out.refs
            );
            assert!(out.unattested.is_empty(), "{member}: {:#?}", out.unattested);
        }
    }

    /// The pre-v5 wiring in the project config redirects only crates.io
    /// too: a member's git declaration bypasses it the same way.
    #[tokio::test]
    async fn a_member_from_git_bypasses_the_config_wired_copy() {
        let p = Project::new();
        p.write(
            ".cargo/config.toml",
            patch_config(&[("cfg-if", &vendor_path(UUID_A, "cfg-if-1.0.4"))]),
        );
        workspace_with_member(&p, "cfg-if = { git = \"https://example.com/cfg-if\" }");
        p.write("Cargo.lock", lock(&[("cfg-if", "1.0.4", None, None)]));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
        );
        bypassed_mark(&out, "crates/a/Cargo.toml");
    }

    /// REGRESSION (member gate): a vendored project's lock has no
    /// Socket-sourced package (the copy's entry is sourceless), and a
    /// lockless one has no `socket-patch-` pin, so the member walk must
    /// not hinge on either: the members are read whenever a `[patch]`
    /// wires a Socket copy, lock or no lock.
    #[tokio::test]
    async fn members_are_read_for_a_vendored_copy_without_a_socket_lock_entry() {
        for with_lock in [true, false] {
            let p = vendored_workspace(
                "cfg-if = { version = \"1\", registry = \"my-corp\" }",
                "",
                &[],
            );
            if !with_lock {
                std::fs::remove_file(p.root().join("Cargo.lock")).unwrap();
            }
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:cargo/cfg-if@1.0.4", UUID_A, WiringMode::Vendored)],
            );
            bypassed_mark(&out, "crates/a/Cargo.toml");
        }
    }
}
