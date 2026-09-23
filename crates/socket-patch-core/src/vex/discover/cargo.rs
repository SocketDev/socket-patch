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
//! `Cargo.toml` decides whether cargo still USES that entry (rule 10): cargo
//! re-resolves a locked package whose source no longer matches the
//! manifest's declaration. So for the lock entry's crate:
//!
//! * not declared in the root `Cargo.toml` at all (a workspace member's dep
//!   the root lock describes; no / unparseable manifest) → ref;
//! * some declaration pins `socket-patch-<uuid>` (the same uuid) → ref;
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
//! ## Vendored (`vendor`, `vendor::cargo` + `vendor::cargo_config`)
//!
//! NOT visible in `Cargo.lock` beyond the entry losing `source` + `checksum`
//! (`vendor::cargo_lock::detach_lock_entry`). The identity is the config's
//! `[patch.crates-io] <name> = { path = ".socket/vendor/cargo/<uuid>/<name>-<version>" }`
//! (inline, sub-table, or `[patch] crates-io = { … }` forms). Read from the
//! effective config and, for hand-edit tolerance, the root `Cargo.toml`'s
//! own `[patch.*]` tables (cargo honors both); any `[patch.<source>]` table
//! counts. The path must be root-anchored ([`vendor_ref`]: a `../` or
//! absolute spelling consumes some OTHER checkout's copy), the leaf a single
//! `<name>-<version>` directory for the entry's crate (`package = "…"` when
//! renamed, else the key). Same liveness truth source as
//! `vendor::cargo::vendored_entry_in_use`: when a `Cargo.lock` parses, it
//! must hold a SOURCELESS `[[package]]` for that name + version — an entry
//! with a registry source (re-resolved, or a hosted takeover) or none at
//! all means the copy is not what builds, and so does a
//! `[[patch.unused]]` entry for that name + version (cargo's own record of
//! a `[patch]` left out of the graph — e.g. by the user's path dependency,
//! whose lock entry is sourceless too), so no ref ([`DIAG_REF_INVALID`]).
//! No lock (first build pending) or an unparseable one (cargo refuses to
//! build) keeps the ref, like `vendored_entry_in_use`.
//! A `.socket/cargo-patches/` path (the retired redirect backend) carries no
//! uuid and is not a ref. Socket-shaped entries in a `.cargo/config.toml`
//! that cargo ignores (because `.cargo/config` exists) are diagnosed, never
//! read.

use std::collections::BTreeMap;

use toml_edit::{DocumentMut, Item, TableLike};

use super::{
    names_vendor_dir, simple_purl, socket_patch_name_uuid, toml_or_diag, vendor_ref, DiscoverCtx,
    Discovery, PatchedRef, TomlDiag, UnlockedPin, DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::utils::digest::is_hex64_lower;
use crate::vendor::cargo_config::{
    effective_config_rel, patch_entries, registry_definitions, CONFIG_LEGACY, CONFIG_TOML,
    SOCKET_REGISTRY_PREFIX,
};
use crate::vendor::cargo_lock::{
    locked_packages, unused_patches, vendored_copy_consumed, LockedPackage,
};
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
    let manifest = read_toml(ctx, CARGO_TOML, out).await;
    let config = read_config(ctx, out).await;

    // Crate name → the `registry` value of each root-manifest declaration
    // (`None` = declared with no registry key). Absent map = no usable
    // manifest.
    let decls = manifest.as_ref().map(|doc| {
        let mut decls = manifest_declarations(doc);
        for patch in patch_entries(doc) {
            if let Some(reg) = patch.registry {
                let name = patch.name.to_string();
                decls.entry(name).or_default().push(Some(reg.to_string()));
            }
        }
        decls
    });
    // The config's `[patch]` registry pins are also declarations cargo
    // honors (only matters for crates the manifest also declares).
    let decls = decls.map(|mut decls| {
        if let Some((_, doc)) = &config {
            for patch in patch_entries(doc) {
                if let (Some(reg), Some(existing)) = (patch.registry, decls.get_mut(patch.name)) {
                    existing.push(Some(reg.to_string()));
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
    if let (Some(decls), Some(doc)) = (&decls, &manifest) {
        unresolved_manifest_pins(ctx, &lock, decls, doc, &definitions, out);
    }
    if let Some((file, doc)) = &config {
        vendored_from_patches(file, doc, &lock, out);
    }
    if let Some(doc) = &manifest {
        vendored_from_patches(CARGO_TOML, doc, &lock, out);
    }
}

// ── reads ────────────────────────────────────────────────────────────────

/// The state of the root `Cargo.lock`, read through the vendor backend's
/// own lock model ([`locked_packages`] / [`unused_patches`]).
#[derive(Debug)]
enum Lock {
    /// No lock (or unreadable — diagnosed by the read).
    Absent,
    /// Present but not TOML (diagnosed).
    Unparseable,
    Parsed {
        pkgs: Vec<LockedPackage>,
        /// `(name, version)` of every `[[patch.unused]]` entry: a `[patch]`
        /// cargo resolved and then did NOT use in the crate graph.
        unused: Vec<(String, String)>,
    },
}

impl Lock {
    fn packages(&self) -> &[LockedPackage] {
        match self {
            Lock::Parsed { pkgs, .. } => pkgs,
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
    Lock::Parsed {
        pkgs: locked_packages(&doc),
        unused: unused_patches(&doc),
    }
}

/// Guarded read + parse of a TOML file (`None`: missing, unreadable, or
/// unparseable — the latter two diagnosed).
async fn read_toml(ctx: &DiscoverCtx<'_>, file: &str, out: &mut Discovery) -> Option<DocumentMut> {
    let text = ctx.read_text(file, out).await?;
    parse_toml(file, &text, out)
}

fn parse_toml(file: &str, text: &str, out: &mut Discovery) -> Option<DocumentMut> {
    toml_or_diag(file, text, TomlDiag::TrimEnd, out)
}

/// The config file cargo actually reads ([`effective_config_rel`]), parsed,
/// with its root-relative name. When `.cargo/config` exists cargo ignores
/// `.cargo/config.toml` entirely (and warns); Socket-shaped wiring left in
/// the ignored file is diagnosed so a "why is my patch not attested" has an
/// answer.
async fn read_config(
    ctx: &DiscoverCtx<'_>,
    out: &mut Discovery,
) -> Option<(&'static str, DocumentMut)> {
    if effective_config_rel(ctx.root).await == CONFIG_TOML {
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

/// Every dependency declaration in a manifest, keyed by the crate it names
/// (`package = "…"` when renamed, else the key): the `registry` value of
/// each (`None` = no registry key). `workspace = true` inheritors are
/// skipped — the `[workspace.dependencies]` entry they inherit is itself
/// collected.
fn manifest_declarations(doc: &DocumentMut) -> BTreeMap<String, Vec<Option<String>>> {
    let mut decls: BTreeMap<String, Vec<Option<String>>> = BTreeMap::new();
    for dep in dependency_entries(doc) {
        decls.entry(dep.name).or_default().push(dep.registry);
    }
    decls
}

/// One manifest dependency declaration (see [`manifest_declarations`]).
struct DepEntry {
    name: String,
    registry: Option<String>,
    /// The `version` requirement (a bare string entry is one).
    version: Option<String>,
}

fn dependency_entries(doc: &DocumentMut) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut tables: Vec<&dyn TableLike> = Vec::new();
    let root = doc.as_table();
    for kind in DEP_TABLES {
        tables.extend(root.get(kind).and_then(Item::as_table_like));
    }
    if let Some(ws) = root.get("workspace").and_then(Item::as_table_like) {
        tables.extend(ws.get("dependencies").and_then(Item::as_table_like));
    }
    if let Some(targets) = root.get("target").and_then(Item::as_table_like) {
        for (_, target) in targets.iter() {
            let Some(target) = target.as_table_like() else {
                continue;
            };
            for kind in DEP_TABLES {
                tables.extend(target.get(kind).and_then(Item::as_table_like));
            }
        }
    }
    for table in tables {
        for (key, item) in table.iter() {
            let dep = if let Some(version) = item.as_str() {
                DepEntry {
                    name: key.to_string(),
                    registry: None,
                    version: Some(version.to_string()),
                }
            } else if let Some(entry) = item.as_table_like() {
                if entry.get("workspace").and_then(Item::as_bool) == Some(true) {
                    continue;
                }
                let field = |k: &str| entry.get(k).and_then(Item::as_str).map(str::to_string);
                DepEntry {
                    name: field("package").unwrap_or_else(|| key.to_string()),
                    registry: field("registry"),
                    version: field("version"),
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
    let s = source.trim();
    if !(s.starts_with("sparse+") || s.starts_with("registry+")) {
        return None; // git / path / local-registry sources are never ours
    }
    ctx.hosted_uuid(s)
}

fn hosted_from_lock(
    ctx: &DiscoverCtx<'_>,
    lock: &Lock,
    decls: Option<&BTreeMap<String, Vec<Option<String>>>>,
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
        let reg = format!("{SOCKET_REGISTRY_PREFIX}{uuid}");
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
            // Not declared by the root manifest (a member's dependency the
            // root lock describes), or no usable manifest: the lock is the
            // only word.
            out.push(lock_ref);
            continue;
        };
        if regs.iter().any(|r| r.as_deref() == Some(reg.as_str())) {
            out.push(lock_ref);
            continue;
        }
        let others: Vec<String> = regs
            .iter()
            .flatten()
            .filter_map(|r| socket_patch_name_uuid(r, false))
            .collect();
        if others.is_empty() {
            out.diag(
                DIAG_REF_INVALID,
                CARGO_LOCK,
                format!(
                    "{CARGO_LOCK}: {purl} resolves from Socket patch {uuid}, but {CARGO_TOML} \
                     declares {} without registry = \"{reg}\" — cargo re-resolves it from the \
                     declared source; not counted",
                    pkg.name
                ),
            );
            continue;
        }
        // The manifest routes the crate to a DIFFERENT Socket patch than the
        // lock pins: emit both wirings and let the CLI's conflict gate refuse
        // to pick one.
        out.push(lock_ref);
        for other in others {
            out.push(PatchedRef::hosted(
                purl.clone(),
                other,
                CARGO_TOML,
                None,
                None,
                true,
            ));
        }
    }
}

/// Diagnose `Cargo.toml` Socket-registry pins no lock entry turns into a ref
/// (no exact version to attest), and malformed `socket-patch-*` names.
///
/// With NO `Cargo.lock` at all (a library that gitignores it; `rewrite_cargo`
/// supports that state — `LockCommit::Absent` — and writes only the pin and
/// the registry definition) a pin is still live wiring for the crate: every
/// declaration of it routes to `socket-patch-<U>`, the project config defines
/// that registry on the Socket host for the same `U`, and that registry
/// serves only the patched version. It is recorded as an [`UnlockedPin`]
/// carrying the manifest's version requirements, so a redirect-ledger record
/// whose exact version satisfies them stays live
/// ([`Discovery::hosted_claim`]); it is still not a ref (no version to
/// attest on its own).
fn unresolved_manifest_pins(
    ctx: &DiscoverCtx<'_>,
    lock: &Lock,
    decls: &BTreeMap<String, Vec<Option<String>>>,
    manifest: &DocumentMut,
    definitions: &BTreeMap<String, String>,
    out: &mut Discovery,
) {
    let deps = dependency_entries(manifest);
    for (name, regs) in decls {
        for reg in regs.iter().flatten() {
            if !reg.trim().starts_with(SOCKET_REGISTRY_PREFIX) {
                continue;
            }
            let Some(uuid) = socket_patch_name_uuid(reg, false) else {
                out.diag(
                    DIAG_REF_INVALID,
                    CARGO_TOML,
                    format!(
                        "{CARGO_TOML}: {name} is pinned to registry {reg:?}, which is not a \
                         socket-patch-<uuid> name"
                    ),
                );
                continue;
            };
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
            let why = match lock {
                Lock::Unparseable => continue, // already diagnosed
                Lock::Absent => {
                    let only_this_registry = regs.iter().all(|r| r.as_deref() == Some(reg));
                    let defined_here = definitions
                        .get(reg.as_str())
                        .and_then(|index| source_uuid(ctx, index))
                        .is_some_and(|u| u == uuid);
                    let version_reqs: Vec<String> = deps
                        .iter()
                        .filter(|d| d.name == *name && d.registry.as_deref() == Some(reg))
                        .filter_map(|d| d.version.clone())
                        .collect();
                    if only_this_registry && defined_here && !version_reqs.is_empty() {
                        out.unlocked_pin(UnlockedPin {
                            ecosystem: "cargo".to_string(),
                            name: name.clone(),
                            uuid: uuid.clone(),
                            file: CARGO_TOML.into(),
                            version_reqs,
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
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                CARGO_TOML,
                format!("{CARGO_TOML}: {name} is pinned to Socket patch {uuid}, but {why}"),
            );
        }
    }
}

// ── vendored ─────────────────────────────────────────────────────────────

fn vendored_from_patches(file: &str, doc: &DocumentMut, lock: &Lock, out: &mut Discovery) {
    for entry in patch_entries(doc) {
        let Some(path) = entry.path else {
            continue; // a git / registry patch
        };
        if !names_vendor_dir(path) {
            continue; // a user path, or the uuid-less `.socket/cargo-patches/`
        }
        let name = entry.name;
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
        if let Lock::Parsed { pkgs, unused } = lock {
            if !vendored_copy_consumed(pkgs, unused, name, version) {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: [patch] entry for {name} points at {}, but {CARGO_LOCK} \
                         does not build {name}@{version} from it (an unused patch, or the \
                         lock resolves it from a registry); not counted",
                        vref.artifact_rel
                    ),
                );
                continue;
            }
        }
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

    /// The exact shape `vendor`'s cargo backend writes: the config entry
    /// plus a detached (sourceless) lock entry.
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
}
