//! npm-family lockfiles: `package-lock.json` / `npm-shrinkwrap.json` (the
//! reference extractor) and pnpm (`pnpm-lock.yaml` in every lockfile
//! generation, pnpm <= 2's `shrinkwrap.yaml`, Rush's pnpm locks — see
//! [`extract_pnpm`]).
//!
//! ## package-lock.json / npm-shrinkwrap.json
//!
//! BOTH locks are read when both exist: the hosted rewriter
//! (`patch::redirect::rewrite_npm_lock`) rewrites every present npm lock (npm
//! 12 reifies from `package-lock.json` beside a committed shrinkwrap), so
//! either may carry the wiring. Each lock's entries come from the lock
//! inventory's own walk ([`npm_lock_nodes`]), one of two entry trees:
//!
//! * `packages` (lockfileVersion 2/3): keys containing `node_modules/`; the
//!   package is the entry's `name` field when present (npm writes it for
//!   aliases — the key is then the ALIAS) else the key's trailing path, and
//!   the version is the entry's `version`. `""` (the root) and bare keys
//!   (workspace members — source dirs) are skipped, as are `link: true` and
//!   `inBundle: true` entries: npm installs those from elsewhere, so a
//!   Socket URL written there wires nothing (the rewriters refuse them too).
//! * `dependencies` (lockfileVersion 1 ONLY): keyed by name, recursive
//!   through nested `dependencies`; `bundled: true` skipped for the same
//!   reason as `inBundle`. A v2 lock's `dependencies` is a legacy mirror
//!   that npm 7+ never reads when `packages` exists, so it is ignored there
//!   — a stale mirror entry must not outvote the `packages` entry npm
//!   installs.
//!
//! An entry is a ref when its `resolved` is
//!
//! * a Socket-HOSTED url ([`DiscoverCtx::hosted_uuid`]) → [`WiringMode::Hosted`].
//!   The hosted rewriter ALWAYS writes the patched tarball's `integrity`
//!   (`sha512-…` SRI; it refuses deps without one), so `integrity_required`
//!   is set and a pin-less hosted entry cannot use the lockfile basis;
//! * a root-anchored `file:.socket/vendor/npm/<uuid>/<leaf>.tgz`
//!   ([`vendor_ref`]) → [`WiringMode::Vendored`]. The vendored backend
//!   (`vendor::npm_lock`) names the tarball `[@scope/]<name>-<version>.tgz`
//!   after the entry it rewires, so a leaf naming a DIFFERENT package than
//!   the entry is not Socket-written and is diagnosed, not trusted.

use std::collections::BTreeSet;

use serde_json::Value;

use super::{
    npm_purl, npm_vendored_tarball_names, parse_json, vendor_ref, DiscoverCtx, Discovery,
    LocateOpts, Located, PatchedRef, VendorRef, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID,
    DIAG_REF_UNATTRIBUTABLE,
};
use crate::constants::npm_family::{NPM_LOCKS, PNPM_LOCK, PNPM_SHRINKWRAP_LEGACY};
use crate::patch::redirect::pnpm::{entry_field, is_pnpm_lock_text};
use crate::utils::digest::is_sri_pin;
use crate::vendor::lock_inventory::pnpm::{
    classify_pnpm_key, pnpm_packages, rush_lock_rels, PnpmKey, PnpmPackage,
};
use crate::vendor::lock_inventory::{
    npm_lock_nodes, pnpm_registry_key, LockIntegrity, NpmLockNode,
};

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let mut locks: Vec<NpmLockRefs> = Vec::new();
    for lock in NPM_LOCKS {
        if let Some(read) = extract_package_lock(ctx, lock, out).await {
            locks.push(read);
        }
    }
    push_uncontested(locks, out);
    extract_pnpm(ctx, out).await;
}

/// What one parsed npm lock wires, plus the packages it resolves ELSEWHERE
/// (an entry whose `resolved` is not a Socket reference).
struct NpmLockRefs {
    file: &'static str,
    refs: Vec<PatchedRef>,
    unwired: BTreeSet<String>,
}

/// Push every ref no OTHER npm lock contests. npm <= 11 installs from
/// npm-shrinkwrap.json when both exist; npm 12 auto-creates a
/// package-lock.json beside it and installs from THAT (verified against real
/// npm 12.0.0 / 12.1.0). A package one lock wires to a Socket patch while the
/// other resolves it only elsewhere (the registry) is therefore installed
/// patched by some npm majors and unpatched by others — not decidable from
/// the files, so it is diagnosed and not attested (the same call as the v2
/// legacy mirror: a lock section some npm reads must not attest bytes
/// another npm installs). The lock that does not mention the package at all
/// contests nothing. Two locks wiring DIFFERENT patches are both emitted
/// (the CLI's `wiring_conflict` gate).
fn push_uncontested(locks: Vec<NpmLockRefs>, out: &mut Discovery) {
    let wired: Vec<BTreeSet<String>> = locks
        .iter()
        .map(|l| l.refs.iter().map(|r| r.purl.clone()).collect())
        .collect();
    for (i, lock) in locks.iter().enumerate() {
        for r in &lock.refs {
            let contested_by = locks.iter().enumerate().find(|(j, other)| {
                *j != i && other.unwired.contains(&r.purl) && !wired[*j].contains(&r.purl)
            });
            if let Some((_, other)) = contested_by {
                out.diag(
                    DIAG_REF_UNATTRIBUTABLE,
                    lock.file,
                    format!(
                        "{}: {} is wired to Socket patch {} but {} resolves it elsewhere — \
                         npm <= 11 installs from {}, npm >= 12 from {}, so whether the \
                         patched bytes install depends on the npm version; rewire both \
                         locks (re-run `socket-patch vendor` / `scan --mode hosted`) to \
                         attest it",
                        lock.file, r.purl, r.uuid, other.file, NPM_LOCKS[0], NPM_LOCKS[1],
                    ),
                );
            } else {
                out.push(r.clone());
            }
        }
    }
}

/// One npm lock (`file` is root-relative): both entry trees, see the module
/// docs. `None` when the lock is absent, unreadable or unparseable (already
/// diagnosed).
async fn extract_package_lock(
    ctx: &DiscoverCtx<'_>,
    file: &'static str,
    out: &mut Discovery,
) -> Option<NpmLockRefs> {
    let bytes = ctx.read_bytes(file, out).await?;
    let mut read = NpmLockRefs {
        file,
        refs: Vec::new(),
        unwired: BTreeSet::new(),
    };
    let doc: Value = match parse_json(file, &bytes) {
        Ok(doc) => doc,
        Err(detail) => {
            out.diag(DIAG_LOCKFILE_UNPARSEABLE, file, detail);
            return None;
        }
    };
    // npm >= 7 reads ONLY `packages` whenever it exists; v2's `dependencies`
    // is a legacy mirror for npm 6 that nothing installs from. A mirror
    // left carrying a Socket url after `packages` was reverted to the
    // registry must not become a ref (with no install it would attest from
    // the lockfile basis) — the shared walk reads the mirror only for a v1
    // lock.
    for node in npm_lock_nodes(&doc) {
        entry_ref(ctx, file, &node, &mut read, out);
    }
    Some(read)
}

/// Classify one lock entry: a ref (into `read.refs`), a package resolved
/// elsewhere (into `read.unwired`), or nothing.
fn entry_ref(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    node: &NpmLockNode<'_>,
    read: &mut NpmLockRefs,
    out: &mut Discovery,
) {
    let name = node.name;
    let resolved = node.resolved;
    let Located {
        vendored,
        hosted,
        decorated_leaf,
    } = resolved.map_or_else(Located::default, |r| {
        ctx.locate(r, LocateOpts::LITERAL_CHECKED)
    });
    if let (Some(r), true) = (resolved, decorated_leaf) {
        // A `#` / `::` in the vendored leaf: npm installs the file that
        // literal string names, not the committed artifact before the `#`.
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: {name} is wired to {r:?}, which is not a literal \
                 .socket/vendor/npm/<uuid>/<tarball> path; it is ignored"
            ),
        );
        return;
    }
    let hosted_uuid = if vendored.is_none() { hosted } else { None };
    let (Some(resolved), true) = (resolved, vendored.is_some() || hosted_uuid.is_some()) else {
        // A registry / git / tarball dependency: not ours. Remembered so a
        // sibling lock's Socket wiring for the same package is contested
        // (the npm pair here, any other lock by the orchestrator).
        if let Some(purl) = node.version.and_then(|v| npm_purl(name, v)) {
            out.resolved_elsewhere(file, Some(purl.clone()));
            read.unwired.insert(purl);
        }
        return;
    };
    let Some(version) = node.version else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: Socket-wired entry for {name:?} has no version"),
        );
        return;
    };
    let Some(purl) = npm_purl(name, version) else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: Socket-wired entry {name:?}@{version:?} has unsafe coordinates"),
        );
        return;
    };
    let integrity = node
        .sri_pin()
        .map(|sri| LockIntegrity::Sri(sri.to_string()));

    if let Some(vref) = vendored {
        if !npm_vendored_tarball_names(&vref, &purl) {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {purl} is wired to {resolved:?}, which is not that package's \
                     vendored npm tarball"
                ),
            );
            return;
        }
        read.refs
            .push(PatchedRef::vendored(purl, &vref, file, integrity));
    } else if let Some(uuid) = hosted_uuid {
        read.refs.push(PatchedRef::hosted(
            purl,
            uuid,
            file,
            Some(resolved),
            integrity,
            true,
        ));
    }
}

// ── pnpm ─────────────────────────────────────────────────────────────────

/// pnpm locks: which files, and which of their entries are refs.
///
/// ## Files
///
/// * `pnpm-lock.yaml` at the root.
/// * `shrinkwrap.yaml` (pnpm 1 / 2) ONLY when there is no `pnpm-lock.yaml`:
///   pnpm >= 3 never reads it (it migrates it to `pnpm-lock.yaml` once), and
///   pnpm <= 2 never writes `pnpm-lock.yaml`, so a pair means one of them is
///   migration debris — the same call `lock_inventory` makes (it reads
///   shrinkwrap.yaml only on `vendor_lockfile_missing`). The hosted rewriter
///   edits both when both exist, so the live one is covered either way; a
///   stale shrinkwrap left carrying a Socket url must not attest from the
///   lockfile basis after `pnpm-lock.yaml` was reverted.
/// * Rush (`rush.json` present): `common/config/rush/pnpm-lock.yaml` and every
///   `common/config/subspaces/<name>/pnpm-lock.yaml` — the only non-root
///   locks in scope, exactly the set `scan --mode hosted` collects and
///   rewrites (`commands/scan/hosted.rs`). Read whether or not a root lock
///   exists, like the rewriter (no precedence between files — rule 10).
///   Vendoring refuses Rush (`npm_flavor`), so these only carry hosted refs.
///
/// ## Entries
///
/// Only `packages:` entries are read — the section pnpm resolves and fetches
/// from; `importers:` / root `dependencies:` / `snapshots:` only REFER to
/// packages keys, and `overrides:` (lock, package.json `pnpm.overrides`,
/// `pnpm-workspace.yaml`) is configuration that routes nothing once no
/// dependency in the graph matches it (rule 10: pins, not definitions). The
/// entries come from the entry model the lock inventory shares
/// ([`pnpm_packages`]), which reads the hosted rewriter's own block grammar
/// (two-space keys, a flat flow or block `resolution:` map), so every shape
/// it writes is read back identically, CRLF included; keys are classified
/// by [`classify_pnpm_key`]. An entry is a ref when its `resolution`
/// `tarball:` is
///
/// * a Socket-HOSTED url ([`DiscoverCtx::hosted_uuid`]) →
///   [`WiringMode::Hosted`]. The hosted rewriter (`rewrite_pnpm_lock`) keeps
///   the registry KEY and replaces only the resolution with `{integrity:
///   sha512-…, tarball: <url>}` (or the block-map spelling in pnpm <= 5
///   locks), so name@version come from the key in each generation's grammar
///   ([`pnpm_registry_key`]): v9 `name@ver`, v6 `/name@ver`, v5.x / shrinkwrap
///   `/name/ver`, scoped names, quoted keys, and peer suffixes `(…)` (v6+)
///   / `_…` (v5) stripped. It refuses deps with no sha512, so it ALWAYS
///   writes the pin → `integrity_required`.
/// * a root-anchored `file:.socket/vendor/npm/<uuid>/<leaf>.tgz`
///   ([`vendor_ref`]) → [`WiringMode::Vendored`]. The vendor backends rekey
///   the entry: v9 (`vendor::pnpm_lock`) `name@file:<rel-tgz>` + a
///   `version:` line; v5.4 / v6.0 (`vendor::pnpm_lock_legacy`) the bare
///   `file:<rel-tgz>` key + `name:` / `version:` lines — both with
///   `resolution: {integrity, tarball: file:<rel-tgz>}`. The packages key
///   and tarball are always lockfile-root-relative (only pnpm <= 8's
///   importer SPECIFIER is absolute, and specifiers are not read), so no
///   absolute path is ever accepted. The key's path must name the same
///   artifact as the tarball, and the leaf (`[@scope/]<name>-<version>.tgz`)
///   the same package as the entry — anything else is diagnosed. A
///   registry-form key whose tarball was hand-pointed at a vendored
///   tarball is also a ref (pnpm fetches `file:` tarballs locally), under
///   the same leaf check.
///
/// A resolution the grammar refuses (duplicate keys, nested values,
/// aliases) is a [`DIAG_REF_INVALID`] when it carries a Socket reference;
/// a file with neither `lockfileVersion:` nor `shrinkwrapVersion:` is not a
/// pnpm lock ([`DIAG_LOCKFILE_UNPARSEABLE`]).
async fn extract_pnpm(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let root_lock = ctx.exists(PNPM_LOCK).await;
    if root_lock {
        extract_pnpm_lock(ctx, PNPM_LOCK, out).await;
        // pnpm never reads the debris shrinkwrap: the patches it still names
        // are recognized as NOT wired (module docs, rule 11), so a ledger
        // record its stale Socket url alone keeps "mentioned" is dead.
        ctx.recognize_ignored(PNPM_SHRINKWRAP_LEGACY).await;
    } else {
        extract_pnpm_lock(ctx, PNPM_SHRINKWRAP_LEGACY, out).await;
    }
    if ctx.exists("rush.json").await {
        // The common lock, then each subspace's, sorted for deterministic
        // diagnostics (stat / list only — the reads below stay on the ctx).
        for rel in rush_lock_rels(ctx.root).await {
            extract_pnpm_lock(ctx, &rel, out).await;
        }
    }
}

/// One pnpm lock at root-relative `file` (see [`extract_pnpm`]).
async fn extract_pnpm_lock(ctx: &DiscoverCtx<'_>, file: &str, out: &mut Discovery) {
    let Some(text) = ctx.read_text(file, out).await else {
        return;
    };
    if !is_pnpm_lock_text(&text) {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            file,
            format!("{file} is not a pnpm lockfile (no lockfileVersion / shrinkwrapVersion)"),
        );
        return;
    }
    for package in pnpm_packages(&text) {
        pnpm_entry_ref(ctx, file, &package, out);
    }
}

/// Classify one `packages:` entry and push its ref, if any.
fn pnpm_entry_ref(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    package: &PnpmPackage<'_>,
    out: &mut Discovery,
) {
    let key = package.key;
    let Some(resolution) = &package.resolution else {
        if resolution_is_socket_shaped(ctx, package) {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: packages entry {key:?} references a Socket patch through a \
                     resolution that is not a flat pnpm resolution map; it is ignored"
                ),
            );
        }
        return;
    };
    let Some(tarball) = resolution.tarball() else {
        // A plain registry entry (integrity only) or a directory/git dep.
        out.resolved_elsewhere(file, pnpm_registry_key_purl(key));
        return;
    };
    let integrity = resolution
        .integrity()
        .filter(|sri| is_sri_pin(sri))
        .map(|sri| LockIntegrity::Sri(sri.to_string()));
    let located = ctx.locate(tarball, LocateOpts::LITERAL_CHECKED);
    if let Some(vref) = located.vendored {
        pnpm_vendored_ref(file, package, tarball, &vref, integrity, out);
    } else if located.decorated_leaf {
        // pnpm fetches the literal file (`#` / `::` included).
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: packages entry {key:?} (tarball {tarball:?}) is not a literal \
                 .socket/vendor/npm/<uuid>/<tarball> path; it is ignored"
            ),
        );
    } else if let Some(uuid) = located.hosted {
        let Some(purl) = pnpm_registry_key_purl(key) else {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: packages entry {key:?} resolves from the Socket patch server but \
                     its key is not a registry name@version"
                ),
            );
            return;
        };
        out.push(PatchedRef::hosted(
            purl,
            uuid,
            file,
            Some(tarball),
            integrity,
            true,
        ));
    } else {
        // A registry-keyed entry fetching some other tarball.
        out.resolved_elsewhere(file, pnpm_registry_key_purl(key));
    }
}

/// A vendored packages entry (see [`extract_pnpm`] for the key shapes).
fn pnpm_vendored_ref(
    file: &str,
    package: &PnpmPackage<'_>,
    tarball: &str,
    vref: &VendorRef,
    integrity: Option<LockIntegrity>,
    out: &mut Discovery,
) {
    let key = package.key;
    let invalid = |out: &mut Discovery, why: &str| {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: packages entry {key:?} (tarball {tarball:?}) {why}; it is ignored"),
        );
    };
    // (name, the key's own `file:` path if the key was rekeyed).
    let (name, key_path) = match classify_pnpm_key(key) {
        // Legacy (v5.4 / v6.0): bare `file:<rel-tgz>` key + `name:` line.
        PnpmKey::LegacyFile { path } => (entry_field(&package.entry, "name"), Some(path)),
        // v9: `name@file:<rel-tgz>`.
        PnpmKey::V9File { name, path } => (Some(name), Some(path)),
        // Registry-form key with a hand-pointed `file:` tarball.
        PnpmKey::Registry { name, version } => {
            return finish_vendored(file, name, version, vref, integrity, invalid, out)
        }
        PnpmKey::Other => return invalid(out, "has no registry name@version key"),
    };
    if let Some(path) = key_path {
        if vendor_ref(path).map(|k| k.artifact_rel) != Some(vref.artifact_rel.clone()) {
            return invalid(out, "is keyed by a different path than its tarball");
        }
    }
    let Some(name) = name else {
        return invalid(out, "has no (single) `name:` line");
    };
    let Some(version) = entry_field(&package.entry, "version") else {
        return invalid(out, "has no (single) `version:` line");
    };
    finish_vendored(file, name, version, vref, integrity, invalid, out)
}

fn finish_vendored(
    file: &str,
    name: &str,
    version: &str,
    vref: &VendorRef,
    integrity: Option<LockIntegrity>,
    invalid: impl Fn(&mut Discovery, &str),
    out: &mut Discovery,
) {
    let Some(purl) = npm_purl(name, version) else {
        return invalid(out, "has unsafe name/version coordinates");
    };
    if !npm_vendored_tarball_names(vref, &purl) {
        return invalid(
            out,
            &format!("names {purl} but its tarball is not that package's vendored npm tarball"),
        );
    }
    out.push(PatchedRef::vendored(purl, vref, file, integrity));
}

/// [`pnpm_registry_key`] (the lock inventory's key grammar) as a validated
/// npm purl.
fn pnpm_registry_key_purl(key: &str) -> Option<String> {
    let (name, version) = pnpm_registry_key(key)?;
    npm_purl(name, version)
}

/// Whether an entry's (unparseable) `resolution:` value carries a Socket
/// hosted url or a root-anchored vendored path
/// ([`PnpmPackage::resolution_tokens`]) — the entry is then worth a
/// diagnostic rather than a silent skip.
fn resolution_is_socket_shaped(ctx: &DiscoverCtx<'_>, package: &PnpmPackage<'_>) -> bool {
    package
        .resolution_tokens()
        .into_iter()
        .any(|tok| vendor_ref(tok).is_some() || ctx.hosted_uuid(tok).is_some())
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    fn lock_with_packages(packages: serde_json::Value) -> String {
        serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": packages,
        })
        .to_string()
    }

    const SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";

    /// The committed golden fixture (written by the TS backend — exactly what
    /// a depscan PR leaves behind: no `.socket/` at all).
    #[tokio::test]
    async fn golden_hosted_fixture_yields_the_patch_uuid_not_the_token() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/package-lock-v3/basic/expected");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:npm/left-pad@1.3.0",
                "22222222-2222-2222-2222-222222222222",
                WiringMode::Hosted,
            )],
        );
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from("package-lock.json"));
        assert!(r.integrity_required);
        assert!(
            r.lockfile_basis_ok(),
            "the golden lock pins the patched sha512"
        );
        assert!(r
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://patch.socket.dev/"));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn hosted_and_vendored_entries_in_one_lock() {
        let hosted = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let vendored = format!("file:.socket/vendor/npm/{UUID_B}/@scope/pkg-2.0.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": { "version": "1.3.0", "resolved": hosted, "integrity": SRI },
                "node_modules/@scope/pkg": { "version": "2.0.0", "resolved": vendored, "integrity": SRI },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": SRI
                },
            })),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted),
                ("pkg:npm/@scope/pkg@2.0.0", UUID_B, WiringMode::Vendored),
            ],
        );
        let v = out
            .refs
            .iter()
            .find(|r| r.mode == WiringMode::Vendored)
            .unwrap();
        assert_eq!(
            v.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/npm/{UUID_B}/@scope/pkg-2.0.0.tgz").as_str())
        );
        assert_eq!(
            v.locked_integrity,
            Some(LockIntegrity::Sri(SRI.to_string()))
        );
    }

    /// Nested instances and the alias `name` field: the package is the
    /// entry's `name`, not the alias key; nested `node_modules/` keys count.
    #[tokio::test]
    async fn alias_and_nested_instances_resolve_to_the_real_package() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                "node_modules/pad-alias": { "name": "left-pad", "version": "1.3.0", "resolved": url, "integrity": SRI },
                "node_modules/a/node_modules/left-pad": { "version": "1.3.0", "resolved": url, "integrity": SRI },
            })),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// Both npm locks are read (npm 12 installs from package-lock.json beside a
    /// committed shrinkwrap); a v2 lock's legacy `dependencies` mirror is
    /// not (its agreeing twin adds nothing).
    #[tokio::test]
    async fn both_locks_are_read_and_the_agreeing_mirror_adds_nothing() {
        let a = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let b = format!("file:.socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz");
        let p = Project::new();
        p.write(
            "npm-shrinkwrap.json",
            lock_with_packages(serde_json::json!({
                "node_modules/left-pad": { "version": "1.3.0", "resolved": a, "integrity": SRI },
            })),
        );
        p.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 2,
                "packages": {
                    "node_modules/minimist": { "version": "1.2.5", "resolved": b, "integrity": SRI },
                },
                "dependencies": {
                    "minimist": { "version": "1.2.5", "resolved": b, "integrity": SRI },
                    "outer": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/outer/-/outer-1.0.0.tgz",
                        "dependencies": {
                            "minimist": { "version": "1.2.5", "resolved": b, "integrity": SRI }
                        }
                    }
                }
            })
            .to_string(),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted),
                ("pkg:npm/minimist@1.2.5", UUID_B, WiringMode::Vendored),
            ],
        );
        assert_eq!(
            out.refs.len(),
            2,
            "the v2 mirror and its nested legacy copy add nothing: {:#?}",
            out.refs
        );
    }

    /// REGRESSION (npm 12): npm 12 installs from package-lock.json beside a
    /// committed npm-shrinkwrap.json (npm <= 11 from the shrinkwrap). A
    /// package one lock wires to a Socket patch while the other resolves it
    /// from the registry installs unpatched under one of those majors, so it
    /// must NOT become a ref (with no install it would attest from the
    /// lockfile basis) — in either direction, hosted or vendored. The patch
    /// uuid stays recognized, so a ledger claim for it is dead too.
    #[tokio::test]
    async fn a_package_the_sibling_npm_lock_resolves_elsewhere_is_contested() {
        let hosted = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let vendored = format!("file:.socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz");
        let registry = |n: &str, v: &str| format!("https://registry.npmjs.org/{n}/-/{n}-{v}.tgz");
        let p = Project::new();
        // Shrinkwrap wires left-pad (hosted); package-lock has it registry.
        // package-lock wires minimist (vendored); shrinkwrap has it registry.
        p.write(
            "npm-shrinkwrap.json",
            lock_with_packages(serde_json::json!({
                "node_modules/left-pad": { "version": "1.3.0", "resolved": hosted, "integrity": SRI },
                "node_modules/minimist": { "version": "1.2.5", "resolved": registry("minimist", "1.2.5"), "integrity": SRI },
            })),
        );
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                "node_modules/left-pad": { "version": "1.3.0", "resolved": registry("left-pad", "1.3.0"), "integrity": SRI },
                "node_modules/minimist": { "version": "1.2.5", "resolved": vendored, "integrity": SRI },
            })),
        );
        let out = run(&p).await;
        assert!(
            out.refs.is_empty(),
            "contested refs emitted: {:#?}",
            out.refs
        );
        let contested: Vec<&Diag> = out
            .diagnostics
            .iter()
            .filter(|d| d.code == DIAG_REF_UNATTRIBUTABLE)
            .collect();
        assert_eq!(contested.len(), 2, "{:#?}", out.diagnostics);
        assert!(contested
            .iter()
            .any(|d| d.file == std::path::Path::new("npm-shrinkwrap.json")
                && d.detail.contains("pkg:npm/left-pad@1.3.0")
                && d.detail.contains("npm >= 12")));
        assert!(contested
            .iter()
            .any(|d| d.file == std::path::Path::new("package-lock.json")
                && d.detail.contains("pkg:npm/minimist@1.2.5")));
        for (label, uuid) in [("UUID_A", UUID_A), ("UUID_B", UUID_B)] {
            assert!(
                out.recognized.iter().any(|r| r.uuid == uuid),
                "{label} must stay recognized (authoritative, dead): {:#?}",
                out.recognized
            );
        }
    }

    /// The agreeing dual-lock state (both locks wired identically — what the
    /// hosted rewriter and the vendor backend now write) is a ref from each
    /// lock; a lock that does not mention the package contests nothing.
    #[tokio::test]
    async fn agreeing_dual_npm_locks_both_wire_the_patch() {
        let hosted = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let wired = lock_with_packages(serde_json::json!({
            "node_modules/left-pad": { "version": "1.3.0", "resolved": hosted, "integrity": SRI },
        }));
        let p = Project::new();
        p.write("npm-shrinkwrap.json", &wired);
        p.write("package-lock.json", &wired);
        let out = run(&p).await;
        assert_eq!(out.refs.len(), 2, "{:#?}", out.refs);
        assert!(out
            .refs
            .iter()
            .all(|r| r.purl == "pkg:npm/left-pad@1.3.0" && r.uuid == UUID_A));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// REGRESSION: a v2 lock whose `packages` entry was reverted to the
    /// registry while its stale legacy `dependencies` mirror still carries
    /// the Socket url wires NOTHING — npm >= 7 installs from `packages`, so
    /// the mirror ref would have attested an unpatched registry tarball from
    /// the lockfile basis. Same for a vendored mirror entry.
    #[tokio::test]
    async fn stale_legacy_mirror_is_ignored_when_packages_exists() {
        let hosted = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let vendored = format!("file:.socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 2,
                "packages": {
                    "": { "name": "app", "version": "1.0.0" },
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity": "sha512-ORIG"
                    },
                    "node_modules/minimist": {
                        "version": "1.2.5",
                        "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
                        "integrity": "sha512-ORIG"
                    },
                },
                "dependencies": {
                    "left-pad": { "version": "1.3.0", "resolved": hosted, "integrity": SRI },
                    "minimist": { "version": "1.2.5", "resolved": vendored, "integrity": SRI },
                }
            })
            .to_string(),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        // Skipped silently, but RECOGNIZED: a ledger record for either
        // mirror patch is dead, never revived from the mirror's text by the
        // CLI's ledger fallback (rule 11).
        assert_eq!(
            out.hosted_claim("pkg:npm/left-pad@1.3.0", UUID_A),
            Some(false)
        );
        assert_eq!(
            out.vendored_claim(
                "pkg:npm/minimist@1.2.5",
                UUID_B,
                &format!(".socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz"),
            ),
            Some(false)
        );
    }

    /// v1 locks (no `packages`) are read through the legacy tree.
    #[tokio::test]
    async fn lockfile_v1_dependencies_tree() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 1,
                "dependencies": { "left-pad": { "version": "1.3.0", "resolved": url, "integrity": SRI } }
            })
            .to_string(),
        );
        assert_refs(
            &run(&p).await,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// link / inBundle / bundled entries install from somewhere else, so a
    /// Socket URL written there wires nothing.
    #[tokio::test]
    async fn link_and_bundled_entries_wire_nothing() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 2,
                "packages": {
                    "node_modules/left-pad": { "version": "1.3.0", "resolved": url, "link": true },
                    "node_modules/p/node_modules/left-pad": { "version": "1.3.0", "resolved": url, "inBundle": true },
                },
            })
            .to_string(),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        // v1's `bundled: true` (the legacy tree is read only without `packages`).
        let v1 = Project::new();
        v1.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 1,
                "dependencies": {
                    "left-pad": { "version": "1.3.0", "resolved": url, "bundled": true }
                }
            })
            .to_string(),
        );
        let out = run(&v1).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
    }

    /// Negative shapes: a uuid on a foreign host, a placeholder token, the
    /// root and workspace-member keys, and an escaping vendored path.
    #[tokio::test]
    async fn non_socket_and_unsafe_references_are_not_refs() {
        let foreign = format!("https://evil.example/patch/npm/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz");
        let placeholder = "https://patch.socket.dev/patch/npm/tok/uuid/left-pad-1.3.0.tgz";
        let good = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                "": { "name": "app", "version": "1.0.0", "resolved": good },
                "packages/member": { "name": "member", "version": "1.0.0", "resolved": good },
                "node_modules/a": { "version": "1.0.0", "resolved": foreign, "integrity": SRI },
                "node_modules/b": { "version": "1.0.0", "resolved": placeholder, "integrity": SRI },
                "node_modules/c": {
                    "version": "1.0.0",
                    "resolved": format!("file:../.socket/vendor/npm/{UUID_B}/c-1.0.0.tgz"),
                    "integrity": SRI
                },
            })),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(
            out.diagnostics.is_empty(),
            "plain non-Socket entries are silent: {:?}",
            out.diagnostics
        );
    }

    /// A Socket-shaped entry that fails validation is DIAGNOSED (the user
    /// should know a wired patch is being ignored), never attested.
    #[tokio::test]
    async fn invalid_socket_entries_are_diagnosed() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                // No version.
                "node_modules/left-pad": { "resolved": url },
                // Unsafe name smuggled through the alias `name` field.
                "node_modules/x": { "name": "../../etc", "version": "1.0.0", "resolved": url },
                // Vendored leaf names another package than the entry.
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": format!("file:.socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz")
                },
            })),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 3],
            "{:#?}",
            out.diagnostics
        );
    }

    /// npm and pnpm read a `file:` spec as a LITERAL path:
    /// `…/foo-1.0.0.tgz#evil.tgz` is a file of that name (npm-package-arg
    /// keeps the `#…` in the fetch spec; verified with npm 11 and pnpm 11),
    /// not the committed `foo-1.0.0.tgz` beside it. Cutting the `#…` would
    /// verify the good tarball while the build installs the other one, so
    /// the entry is diagnosed and wires nothing — and the uuid it mentions is
    /// still recognized, so a vendor-ledger claim for it is dead (rule 11).
    #[tokio::test]
    async fn a_decorated_vendored_leaf_names_another_file_and_is_not_a_ref() {
        let good = format!(".socket/vendor/npm/{UUID_B}/foo-1.0.0.tgz");
        for spec in [
            format!("file:{good}#evil.tgz"),
            format!("file:{good}::locator=x"),
        ] {
            let npm = Project::new();
            npm.write(
                "package-lock.json",
                lock_with_packages(serde_json::json!({
                    "node_modules/foo": {
                        "version": "1.0.0",
                        "resolved": spec,
                        "integrity": SRI,
                    },
                })),
            );
            let pnpm = Project::new();
            pnpm.write(
                "pnpm-lock.yaml",
                format!(
                    "lockfileVersion: '9.0'\n\npackages:\n\n  foo@{spec}:\n    resolution: \
                     {{integrity: {SRI}, tarball: {spec}}}\n    version: 1.0.0\n"
                ),
            );
            for p in [&npm, &pnpm] {
                let out = run(p).await;
                assert!(out.refs.is_empty(), "{spec}: {:#?}", out.refs);
                assert_eq!(
                    diag_codes(&out),
                    vec![DIAG_REF_INVALID],
                    "{spec}: {:#?}",
                    out.diagnostics
                );
                assert_eq!(
                    out.vendored_claim("pkg:npm/foo@1.0.0", UUID_B, &good),
                    Some(false),
                    "{spec}"
                );
            }
        }
    }

    /// A hosted entry that lost its pin (hand-edited): still a ref — its
    /// installed tree can verify it — but not lockfile-attestable.
    #[tokio::test]
    async fn pinless_hosted_entry_cannot_use_the_lockfile_basis() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                "node_modules/left-pad": { "version": "1.3.0", "resolved": url },
            })),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        assert!(!out.refs[0].lockfile_basis_ok());
    }

    /// `--patch-server-url` deployments (staging, local test servers) count.
    #[tokio::test]
    async fn configured_patch_server_origin_is_accepted() {
        let url = format!("http://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz");
        let lock = lock_with_packages(serde_json::json!({
            "node_modules/left-pad": { "version": "1.3.0", "resolved": url, "integrity": SRI },
        }));
        let without = Project::new();
        without.write("package-lock.json", &lock);
        assert!(run(&without).await.refs.is_empty());
        let with = Project::new().with_origin("http://127.0.0.1:4545");
        with.write("package-lock.json", &lock);
        assert_refs(
            &run(&with).await,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
    }

    #[tokio::test]
    async fn malformed_lock_is_diagnosed_not_fatal() {
        let p = Project::new();
        p.write("package-lock.json", "{ not json");
        let out = run(&p).await;
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);
    }

    /// A FIFO squatting the lock name fails fast (guarded read) instead of
    /// wedging discovery forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_is_unreadable_not_a_hang() {
        let p = Project::new();
        let path = p.root().join("package-lock.json");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    // ── pnpm ─────────────────────────────────────────────────────────────

    use crate::patch::redirect::{rewrite_registry_redirect, DepOverride, Integrity};

    /// The patched tarball's sha512 the hosted rewriter pins.
    const PNPM_SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789abcdefABCDEF==";

    /// A hosted override for `name@1.3.0` under `uuid` — the exact input
    /// `scan --mode hosted` hands the rewriter.
    fn pnpm_override(name: &str, uuid: &str, origin: Option<&str>) -> DepOverride {
        let (namespace, bare) = name
            .rsplit_once('/')
            .map_or((None, name), |(ns, n)| (Some(ns.to_string()), n));
        let leaf = format!("{bare}-1.3.0.tgz");
        let url = match origin {
            Some(o) => format!("{o}/patch/npm/{name}/1.3.0/{TOKEN}/{uuid}/{leaf}"),
            None => hosted_url("npm", name, "1.3.0", uuid, &leaf),
        };
        DepOverride {
            ecosystem: "npm".into(),
            name: bare.into(),
            namespace,
            version: "1.3.0".into(),
            token: TOKEN.into(),
            patch_uuid: uuid.into(),
            artifact_url: url,
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha512: Some(PNPM_SRI.into()),
                ..Default::default()
            },
        }
    }

    /// Run the REAL hosted rewriter over `lock` (at root-relative `path`) and
    /// return the rewritten text — so the tests read back exactly what our
    /// own tool writes, never a hand-imitation of it.
    fn hosted_rewrite(path: &str, lock: &str, deps: &[DepOverride]) -> String {
        let files = std::collections::BTreeMap::from([(path.to_string(), lock.to_string())]);
        let r = rewrite_registry_redirect(&files, deps);
        assert!(r.warnings.is_empty(), "{path}: {:?}", r.warnings);
        r.files
            .get(path)
            .unwrap_or_else(|| panic!("{path}: rewriter changed nothing"))
            .clone()
    }

    fn assert_hosted_pin(out: &Discovery, source: &str) {
        for r in &out.refs {
            assert_eq!(r.source_file, std::path::PathBuf::from(source));
            assert!(r.integrity_required, "{r:?}");
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sri(PNPM_SRI.into())),
                "{r:?}"
            );
            assert!(r.lockfile_basis_ok(), "{r:?}");
        }
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// The committed golden (TS backend output — what a depscan PR leaves).
    #[tokio::test]
    async fn pnpm_golden_hosted_fixture() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/pnpm/basic/expected");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:npm/left-pad@1.3.0",
                "22222222-2222-2222-2222-222222222222",
                WiringMode::Hosted,
            )],
        );
        assert!(out.refs[0]
            .url
            .as_deref()
            .is_some_and(|u| u.starts_with("https://patch.socket.dev/")));
        assert!(out.refs[0].lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        // The pre-rewrite input is a plain registry lock: nothing, silently.
        let input = Project::new();
        input.copy_fixture("redirect/npm/pnpm/basic/input");
        let out = run(&input).await;
        assert!(
            out.refs.is_empty() && out.diagnostics.is_empty(),
            "{out:#?}"
        );
    }

    /// Real locks captured from EVERY pinned pnpm major (1.43.1 shrinkwrap
    /// through 12.x lockfileVersion 9 — block and flow resolutions, `/n/v`,
    /// `/n@v` and `n@v` keys), rewritten by the real hosted rewriter, LF and
    /// CRLF: each yields exactly the patch uuid (not the uuid-shaped grant
    /// token before it) with the rewriter's sha512 pin.
    #[tokio::test]
    async fn pnpm_hosted_every_real_major_lf_and_crlf() {
        let root = fixture_path("pnpm-hosted");
        let mut cases = 0;
        for dir in std::fs::read_dir(&root).expect("fixture dir") {
            let dir = dir.expect("dir entry").path();
            for file in std::fs::read_dir(&dir).expect("major dir") {
                let path = file.expect("lock").path();
                let name = path.file_name().unwrap().to_str().unwrap().to_string();
                let captured = std::fs::read_to_string(&path).expect("read lock");
                for lock in [captured.clone(), captured.replace('\n', "\r\n")] {
                    let before = Project::new();
                    before.write(&name, &lock);
                    let out = run(&before).await;
                    assert!(
                        out.refs.is_empty() && out.diagnostics.is_empty(),
                        "{}: registry lock: {out:#?}",
                        dir.display()
                    );
                    let rewritten =
                        hosted_rewrite(&name, &lock, &[pnpm_override("left-pad", UUID_A, None)]);
                    let p = Project::new();
                    p.write(&name, &rewritten);
                    let out = run(&p).await;
                    assert_refs(
                        &out,
                        &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
                    );
                    assert_hosted_pin(&out, &name);
                }
                cases += 1;
            }
        }
        assert_eq!(cases, 12, "every pinned pnpm major needs a captured lock");
    }

    /// Scoped names, quoted keys and both peer-suffix grammars (v5 `_peer`,
    /// v6+ nested `(peer(child))`) — the key shapes the rewriter repoints —
    /// resolve to the bare `@scope/name@version`; bystander versions and the
    /// unscoped same-named package stay silent.
    #[tokio::test]
    async fn pnpm_hosted_scoped_peer_and_quoted_keys() {
        for key in [
            "/@scope/left-pad/1.3.0_peer@2.0.0",
            "/@scope/left-pad@1.3.0(peer@2.0.0(child@3.0.0))",
            "@scope/left-pad@1.3.0",
        ] {
            for quote in ["", "'", "\""] {
                if key.starts_with('@') && quote.is_empty() {
                    continue;
                }
                let lock = format!(
                    "lockfileVersion: '6.0'\npackages:\n  {quote}{key}{quote}:\n    resolution: \
                     {{integrity: sha512-UPSTREAM==}}\n    dependencies:\n      child: 3.0.0\n  \
                     /left-pad@1.3.0:\n    resolution: {{integrity: sha512-BYSTANDER==}}\n  \
                     /@scope/left-pad@1.3.0-beta.1:\n    resolution: {{integrity: sha512-B==}}\n"
                );
                let rewritten = hosted_rewrite(
                    "pnpm-lock.yaml",
                    &lock,
                    &[pnpm_override("@scope/left-pad", UUID_A, None)],
                );
                let p = Project::new();
                p.write("pnpm-lock.yaml", &rewritten);
                let out = run(&p).await;
                assert_refs(
                    &out,
                    &[("pkg:npm/@scope/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
                );
                assert_hosted_pin(&out, "pnpm-lock.yaml");
            }
        }
    }

    /// Rush: the common lock and every subspace lock are read when
    /// `rush.json` exists (whatever the root has), and never without it.
    #[tokio::test]
    async fn pnpm_rush_common_and_subspace_locks() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/pnpm/nested-rush-lock/expected");
        assert!(run(&p).await.refs.is_empty(), "no rush.json: not read");
        p.write("rush.json", "{}");
        let sub = hosted_rewrite(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\npackages:\n\n  ms@1.3.0:\n    resolution: {integrity: sha512-UP==}\n",
            &[pnpm_override("ms", UUID_B, None)],
        );
        p.write("common/config/subspaces/frontend/pnpm-lock.yaml", &sub);
        // A subspace-named FILE (not a dir) is ignored.
        p.write("common/config/subspaces/stray", "x");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (
                    "pkg:npm/left-pad@1.3.0",
                    "22222222-2222-2222-2222-222222222222",
                    WiringMode::Hosted,
                ),
                ("pkg:npm/ms@1.3.0", UUID_B, WiringMode::Hosted),
            ],
        );
        let files: Vec<_> = out.refs.iter().map(|r| r.source_file.clone()).collect();
        assert!(files.contains(&"common/config/rush/pnpm-lock.yaml".into()));
        assert!(files.contains(&"common/config/subspaces/frontend/pnpm-lock.yaml".into()));
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// `shrinkwrap.yaml` (pnpm <= 2) is read only when there is no
    /// `pnpm-lock.yaml`: beside one it is migration debris, and a stale
    /// Socket url left in it must not attest a reverted project.
    #[tokio::test]
    async fn pnpm_shrinkwrap_only_without_pnpm_lock() {
        let captured =
            std::fs::read_to_string(fixture_path("pnpm-hosted/2.25.7/shrinkwrap.yaml")).unwrap();
        let wired = hosted_rewrite(
            "shrinkwrap.yaml",
            &captured,
            &[pnpm_override("left-pad", UUID_A, None)],
        );
        let alone = Project::new();
        alone.write("shrinkwrap.yaml", &wired);
        assert_refs(
            &run(&alone).await,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        let with_lock = Project::new();
        with_lock.write("shrinkwrap.yaml", &wired);
        with_lock.copy_fixture("pnpm-hosted/9.15.9");
        let out = run(&with_lock).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        // The debris shrinkwrap is swept even though it is not read as a
        // lock: its patch is RECOGNIZED, so a ledger claim for it is dead.
        assert_eq!(
            out.hosted_claim("pkg:npm/left-pad@1.3.0", UUID_A),
            Some(false)
        );
        assert_eq!(
            out.recognized_files(UUID_A, WiringMode::Hosted),
            vec![std::path::Path::new("shrinkwrap.yaml")]
        );
    }

    /// `--patch-server-url` deployments count; the same URL without the
    /// configured origin does not.
    #[tokio::test]
    async fn pnpm_configured_patch_server_origin() {
        let origin = "http://127.0.0.1:4545";
        let captured =
            std::fs::read_to_string(fixture_path("pnpm-hosted/10.33.0/pnpm-lock.yaml")).unwrap();
        let lock = hosted_rewrite(
            "pnpm-lock.yaml",
            &captured,
            &[pnpm_override("left-pad", UUID_A, Some(origin))],
        );
        let without = Project::new();
        without.write("pnpm-lock.yaml", &lock);
        assert!(run(&without).await.refs.is_empty());
        let with = Project::new().with_origin(origin);
        with.write("pnpm-lock.yaml", &lock);
        assert_refs(
            &run(&with).await,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// A hosted resolution that lost its pin (hand-edited): still a ref
    /// (an installed tree can verify it) but not lockfile-attestable.
    #[tokio::test]
    async fn pnpm_pinless_hosted_entry_cannot_use_the_lockfile_basis() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "pnpm-lock.yaml",
            format!("lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {{tarball: {url}}}\n"),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        assert!(!out.refs[0].lockfile_basis_ok());
    }

    // Vendored goldens — copied VERBATIM from the vendor backends' own
    // byte-exact fixtures (captured real pnpm output): `vendor::pnpm_lock`
    // P1_AFTER_LOCK / P7_AFTER_LOCK (pnpm 9/10, lockfileVersion 9.0) and
    // `vendor::pnpm_lock_legacy` T7_AFTER_LOCK (pnpm 7, 5.4), T8_AFTER_LOCK
    // (pnpm 8, 6.0), X7_AFTER_LOCK (transitive-only 5.4).
    const V_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const V_LEGACY_UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
    const V_SRI: &str = "sha512-VR8nCbFxvOcFX5Rxku2psjaj0+xzKdzFkcuqZJSHf597bMVomG100t6+cJkMBFRLhyVdSVwufbCwVzlCzZkUwg==";
    const V_LEGACY_SRI: &str = "sha512-pceaN98Av+E8ugNGKlqbfzvbJWVAdWx3RKI7kc7jPThP6QHZg7c2xbZhCqV8N42Jf9hKWdLW4ZNDnFHQinZ0Hw==";
    const P1_AFTER_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

importers:

  .:
    dependencies:
      consumer:
        specifier: file:./consumer
        version: file:consumer
      left-pad:
        specifier: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz
        version: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz
      left-pad-old:
        specifier: npm:left-pad@1.2.0
        version: left-pad@1.2.0

packages:

  consumer@file:consumer:
    resolution: {directory: consumer, type: directory}

  left-pad@1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-VR8nCbFxvOcFX5Rxku2psjaj0+xzKdzFkcuqZJSHf597bMVomG100t6+cJkMBFRLhyVdSVwufbCwVzlCzZkUwg==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz}
    version: 1.3.0

snapshots:

  consumer@file:consumer:
    dependencies:
      left-pad: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

  left-pad@1.2.0: {}

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz: {}
";
    const P7_AFTER_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

importers:

  .: {}

  packages/app:
    dependencies:
      left-pad:
        specifier: file:../../.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz
        version: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

packages:

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-VR8nCbFxvOcFX5Rxku2psjaj0+xzKdzFkcuqZJSHf597bMVomG100t6+cJkMBFRLhyVdSVwufbCwVzlCzZkUwg==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz}
    version: 1.3.0

snapshots:

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz: {}
";
    const T7_AFTER_LOCK: &str = "lockfileVersion: 5.4

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

specifiers:
  consumer: file:./consumer
  left-pad: file:__PROJECT_ROOT__/.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
  left-pad-old: npm:left-pad@1.2.0

dependencies:
  consumer: file:consumer
  left-pad: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
  left-pad-old: /left-pad/1.2.0

packages:

  /left-pad/1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()
    dev: false

  file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-pceaN98Av+E8ugNGKlqbfzvbJWVAdWx3RKI7kc7jPThP6QHZg7c2xbZhCqV8N42Jf9hKWdLW4ZNDnFHQinZ0Hw==, tarball: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz}
    name: left-pad
    version: 1.3.0
    dev: false

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    version: 1.0.0
    dependencies:
      left-pad: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
    dev: false
";
    const T8_AFTER_LOCK: &str = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

dependencies:
  consumer:
    specifier: file:./consumer
    version: file:consumer
  left-pad:
    specifier: file:__PROJECT_ROOT__/.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
    version: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
  left-pad-old:
    specifier: npm:left-pad@1.2.0
    version: /left-pad@1.2.0

packages:

  /left-pad@1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()
    dev: false

  file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-pceaN98Av+E8ugNGKlqbfzvbJWVAdWx3RKI7kc7jPThP6QHZg7c2xbZhCqV8N42Jf9hKWdLW4ZNDnFHQinZ0Hw==, tarball: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz}
    name: left-pad
    version: 1.3.0
    dev: false

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    dependencies:
      left-pad: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
    dev: false
";
    const X7_AFTER_LOCK: &str = "lockfileVersion: 5.4

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

specifiers:
  consumer: file:./consumer

dependencies:
  consumer: file:consumer

packages:

  file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-pceaN98Av+E8ugNGKlqbfzvbJWVAdWx3RKI7kc7jPThP6QHZg7c2xbZhCqV8N42Jf9hKWdLW4ZNDnFHQinZ0Hw==, tarball: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz}
    name: left-pad
    version: 1.3.0
    dev: false

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    version: 1.0.0
    dependencies:
      left-pad: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz
    dev: false
";

    /// Every vendored golden (v9 single + workspace, v5.4 direct +
    /// transitive-only, v6.0), LF and CRLF (a Windows autocrlf checkout),
    /// yields exactly the vendored left-pad with its artifact path and the
    /// recomputed tarball pin; the directory dep, the registry 1.2.0 alias
    /// and the lock `overrides:` add nothing, and pnpm <= 8's ABSOLUTE
    /// importer specifier is never read.
    #[tokio::test]
    async fn pnpm_vendored_goldens_every_grammar() {
        for (label, lock, uuid, sri) in [
            ("v9", P1_AFTER_LOCK, V_UUID, V_SRI),
            ("v9-workspace", P7_AFTER_LOCK, V_UUID, V_SRI),
            ("v5.4", T7_AFTER_LOCK, V_LEGACY_UUID, V_LEGACY_SRI),
            ("v6.0", T8_AFTER_LOCK, V_LEGACY_UUID, V_LEGACY_SRI),
            (
                "v5.4-transitive",
                X7_AFTER_LOCK,
                V_LEGACY_UUID,
                V_LEGACY_SRI,
            ),
        ] {
            for crlf in [false, true] {
                let p = Project::new();
                let mut text = lock.replace("__PROJECT_ROOT__", &p.root().to_string_lossy());
                if crlf {
                    text = text.replace('\n', "\r\n");
                }
                p.write("pnpm-lock.yaml", &text);
                let out = run(&p).await;
                assert_refs(
                    &out,
                    &[("pkg:npm/left-pad@1.3.0", uuid, WiringMode::Vendored)],
                );
                let r = &out.refs[0];
                assert_eq!(
                    r.artifact_rel.as_deref(),
                    Some(format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz").as_str()),
                    "{label}"
                );
                assert_eq!(
                    r.locked_integrity,
                    Some(LockIntegrity::Sri(sri.into())),
                    "{label}"
                );
                assert!(
                    out.diagnostics.is_empty(),
                    "{label}: {:#?}",
                    out.diagnostics
                );
            }
        }
    }

    /// Scoped vendored entries in both rekeyed grammars (v9 quotes the
    /// `@`-leading key), next to a hosted one in the same lock.
    #[tokio::test]
    async fn pnpm_scoped_vendored_and_hosted_in_one_lock() {
        let rel = format!(".socket/vendor/npm/{UUID_B}/@scope/pkg-2.0.0.tgz");
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let v9 = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  '@scope/pkg@file:{rel}':\n    resolution: \
             {{integrity: {SRI}, tarball: file:{rel}}}\n    version: 2.0.0\n\n  left-pad@1.3.0:\n    \
             resolution: {{integrity: {SRI}, tarball: {url}}}\n"
        );
        let legacy = format!(
            "lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: \
             {{integrity: {SRI}, tarball: {url}}}\n    dev: false\n\n  file:{rel}:\n    \
             resolution: {{integrity: {SRI}, tarball: file:{rel}}}\n    name: '@scope/pkg'\n    \
             version: 2.0.0\n    dev: false\n"
        );
        for lock in [v9, legacy] {
            let p = Project::new();
            p.write("pnpm-lock.yaml", &lock);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[
                    ("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted),
                    ("pkg:npm/@scope/pkg@2.0.0", UUID_B, WiringMode::Vendored),
                ],
            );
            assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        }
    }

    /// Negative shapes, all silent: a uuid on a foreign host, a placeholder
    /// token, a vendored path escaping the root (`../`, absolute) or
    /// traversing out of its uuid dir, a directory dep, git/url keys, and
    /// the Socket strings in sections pnpm does not fetch from (importers,
    /// snapshots, overrides).
    #[tokio::test]
    async fn pnpm_non_socket_and_unsafe_references_are_not_refs() {
        let foreign = format!("https://evil.example/patch/npm/{TOKEN}/{UUID_A}/a-1.0.0.tgz");
        let placeholder = "https://patch.socket.dev/patch/npm/tok/uuid/b-1.0.0.tgz";
        let up = format!("file:../.socket/vendor/npm/{UUID_B}/c-1.0.0.tgz");
        let abs = format!("file:/abs/project/.socket/vendor/npm/{UUID_B}/d-1.0.0.tgz");
        let trav = format!("file:.socket/vendor/npm/{UUID_B}/../../../e-1.0.0.tgz");
        let good = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let lock = format!(
            "lockfileVersion: '9.0'\n\noverrides:\n  left-pad@1.3.0: {good}\n\nimporters:\n\n  .:\n    \
             dependencies:\n      left-pad:\n        specifier: {good}\n        version: {good}\n\n\
             packages:\n\n  a@1.0.0:\n    resolution: {{integrity: {SRI}, tarball: {foreign}}}\n\n  \
             b@1.0.0:\n    resolution: {{integrity: {SRI}, tarball: {placeholder}}}\n\n  \
             c@file:{}:\n    resolution: {{integrity: {SRI}, tarball: {up}}}\n    version: 1.0.0\n\n  \
             {abs}:\n    resolution: {{integrity: {SRI}, tarball: {abs}}}\n    name: d\n    version: 1.0.0\n\n  \
             e@1.0.0:\n    resolution: {{integrity: {SRI}, tarball: {trav}}}\n\n  \
             consumer@file:consumer:\n    resolution: {{directory: consumer, type: directory}}\n\n  \
             lodash@4.17.21:\n    resolution: {{integrity: {SRI}}}\n\n  \
             x@https://codeload.github.com/x/x/tar.gz/abc:\n    resolution: {{tarball: https://codeload.github.com/x/x/tar.gz/abc}}\n    version: 1.0.0\n\n\
             snapshots:\n\n  left-pad@1.3.0:\n    resolution: {{integrity: {SRI}, tarball: {good}}}\n",
            &up[5..],
        );
        let p = Project::new();
        p.write("pnpm-lock.yaml", &lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// Socket-shaped entries that fail validation are DIAGNOSED, never
    /// attested: a leaf naming another package, a key path that is not the
    /// tarball, a legacy entry without `name:`, ambiguous `version:` lines,
    /// a traversal name, a Socket url under a non-registry key, and a
    /// resolution the grammar refuses (duplicate tarball).
    #[tokio::test]
    async fn pnpm_invalid_socket_entries_are_diagnosed() {
        let v = |leaf: &str| format!(".socket/vendor/npm/{UUID_B}/{leaf}");
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let entries = [
            // Leaf names minimist, key names lodash (v9 + legacy).
            format!(
                "  lodash@file:{0}:\n    resolution: {{integrity: {SRI}, tarball: file:{0}}}\n    version: 4.17.21\n",
                v("minimist-1.2.5.tgz")
            ),
            format!(
                "  file:{0}:\n    resolution: {{integrity: {SRI}, tarball: file:{0}}}\n    name: lodash\n    version: 4.17.21\n",
                v("minimist-1.2.5.tgz")
            ),
            // Key path differs from the fetched tarball.
            format!(
                "  ms@file:{}:\n    resolution: {{integrity: {SRI}, tarball: file:{}}}\n    version: 2.1.3\n",
                v("ms-2.1.2.tgz"),
                v("ms-2.1.3.tgz")
            ),
            // Legacy rekeyed entry with no `name:`.
            format!(
                "  file:{0}:\n    resolution: {{integrity: {SRI}, tarball: file:{0}}}\n    version: 1.0.0\n",
                v("qs-1.0.0.tgz")
            ),
            // Two `version:` lines.
            format!(
                "  debug@file:{0}:\n    resolution: {{integrity: {SRI}, tarball: file:{0}}}\n    version: 1.0.0\n    version: 2.0.0\n",
                v("debug-1.0.0.tgz")
            ),
            // Traversal name in a v5 key.
            format!("  /../../etc/1.0.0:\n    resolution: {{integrity: {SRI}, tarball: {url}}}\n"),
            // Socket url behind a url-spec key.
            format!("  left-pad@https://x.example/l.tgz:\n    resolution: {{integrity: {SRI}, tarball: {url}}}\n"),
            // Duplicate tarball: the grammar refuses the whole resolution.
            format!(
                "  chalk@1.0.0:\n    resolution: {{integrity: {SRI}, tarball: {url}, tarball: {url}}}\n"
            ),
        ];
        let lock = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n{}",
            entries.join("\n")
        );
        let p = Project::new();
        p.write("pnpm-lock.yaml", &lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; entries.len()],
            "{:#?}",
            out.diagnostics
        );
        assert!(out
            .diagnostics
            .iter()
            .all(|d| d.detail.starts_with("pnpm-lock.yaml")));
    }

    /// A file that is not a pnpm lock is diagnosed (and yields nothing even
    /// if Socket-looking lines are present); an unreadable one is too; a
    /// FIFO fails fast.
    #[tokio::test]
    async fn pnpm_malformed_and_unreadable_locks_are_diagnosed_not_fatal() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "pnpm-lock.yaml",
            format!("{{ not: yaml\npackages:\n  left-pad@1.3.0:\n    resolution: {{integrity: {SRI}, tarball: {url}}}\n"),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);

        let bin = Project::new();
        bin.write("pnpm-lock.yaml", [0xffu8, 0xfe, 0x00, 0x80]);
        let out = run(&bin).await;
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pnpm_fifo_lock_is_unreadable_not_a_hang() {
        let p = Project::new();
        let path = p.root().join("pnpm-lock.yaml");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    /// The full orchestrator sees pnpm refs too (npm and pnpm locks side by
    /// side are both read — no precedence between files).
    #[tokio::test]
    async fn pnpm_and_npm_locks_are_both_discovered() {
        let p = Project::new();
        p.write("pnpm-lock.yaml", P1_AFTER_LOCK);
        let url = hosted_url("npm", "ms", "2.1.3", UUID_A, "ms-2.1.3.tgz");
        p.write(
            "package-lock.json",
            lock_with_packages(serde_json::json!({
                "node_modules/ms": { "version": "2.1.3", "resolved": url, "integrity": SRI },
            })),
        );
        assert_refs(
            &p.discover().await,
            &[
                ("pkg:npm/left-pad@1.3.0", V_UUID, WiringMode::Vendored),
                ("pkg:npm/ms@2.1.3", UUID_A, WiringMode::Hosted),
            ],
        );
    }

    // ── edge shapes no other test reaches ────────────────────────────────

    /// A REGISTRY-form packages key whose tarball was hand-pointed at a
    /// vendored tarball is a vendored ref under the leaf check, in the v9
    /// and v5 key grammars; a key no grammar reads as a package (a v5
    /// non-default-registry key) is diagnosed, as is a legacy rekeyed entry
    /// with unsafe coordinates.
    #[tokio::test]
    async fn pnpm_registry_keyed_vendored_tarballs_and_unusable_keys() {
        let v = |leaf: &str| format!(".socket/vendor/npm/{UUID_B}/{leaf}");
        for (label, key) in [("v9", "left-pad@1.3.0"), ("v5", "/left-pad/1.3.0")] {
            let lock = format!(
                "lockfileVersion: '9.0'\n\npackages:\n\n  {key}:\n    resolution: {{integrity: \
                 {SRI}, tarball: file:{}}}\n",
                v("left-pad-1.3.0.tgz")
            );
            let p = Project::new();
            p.write("pnpm-lock.yaml", &lock);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:npm/left-pad@1.3.0", UUID_B, WiringMode::Vendored)],
            );
            assert!(
                out.diagnostics.is_empty(),
                "{label}: {:#?}",
                out.diagnostics
            );
        }
        let lock = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  example.com/foo/1.0.0:\n    resolution: \
             {{integrity: {SRI}, tarball: file:{0}}}\n\n  file:{1}:\n    resolution: {{integrity: \
             {SRI}, tarball: file:{1}}}\n    name: ..\n    version: 1.0.0\n",
            v("foo-1.0.0.tgz"),
            v("x-1.0.0.tgz"),
        );
        let p = Project::new();
        p.write("pnpm-lock.yaml", &lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 2],
            "{:#?}",
            out.diagnostics
        );
    }

    /// A legacy rekeyed entry's `name:` / `version:` are the ENTRY-level
    /// (four-space) lines: a deeper `name:` inside a nested map is not one.
    #[tokio::test]
    async fn pnpm_legacy_entry_fields_ignore_nested_maps() {
        let rel = format!(".socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz");
        let lock = format!(
            "lockfileVersion: '6.0'\n\npackages:\n\n  file:{rel}:\n    resolution: {{integrity: \
             {SRI}, tarball: file:{rel}}}\n    name: left-pad\n    version: 1.3.0\n    \
             dependencies:\n      name: other\n    dev: false\n"
        );
        let p = Project::new();
        p.write("pnpm-lock.yaml", &lock);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_B, WiringMode::Vendored)],
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }

    /// A BLOCK `resolution:` map the grammar refuses: a Socket url on one of
    /// its continuation lines is diagnosed; one with no Socket reference is
    /// skipped silently like any unreadable registry entry.
    #[tokio::test]
    async fn pnpm_refused_block_resolutions() {
        let url = hosted_url("npm", "chalk", "1.0.0", UUID_A, "chalk-1.0.0.tgz");
        let lock = format!(
            "lockfileVersion: '5.4'\n\npackages:\n\n  /chalk/1.0.0:\n    resolution:\n      \
             tarball: {url}\n      tarball: {url}\n    dev: false\n\n  /debug/1.0.0:\n    \
             resolution:\n      integrity: sha512-A\n      integrity: sha512-B\n    dev: false\n"
        );
        let p = Project::new();
        p.write("pnpm-lock.yaml", &lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID],
            "{:#?}",
            out.diagnostics
        );
    }

    /// Rush without subspaces reads the common lock alone; a subspace dir
    /// whose name is not a safe path segment is never read.
    #[tokio::test]
    async fn pnpm_rush_without_subspaces_and_unsafe_subspace_names() {
        let common = hosted_rewrite(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\npackages:\n\n  ms@1.3.0:\n    resolution: {integrity: sha512-UP==}\n",
            &[pnpm_override("ms", UUID_A, None)],
        );
        let p = Project::new();
        p.write("rush.json", "{}");
        p.write("common/config/rush/pnpm-lock.yaml", &common);
        let out = run(&p).await;
        assert_refs(&out, &[("pkg:npm/ms@1.3.0", UUID_A, WiringMode::Hosted)]);

        // `:` is not a legal Windows path character: Unix only.
        if cfg!(unix) {
            let sub = hosted_rewrite(
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\n\npackages:\n\n  qs@1.3.0:\n    resolution: {integrity: sha512-UP==}\n",
                &[pnpm_override("qs", UUID_B, None)],
            );
            p.write("common/config/subspaces/a:b/pnpm-lock.yaml", &sub);
            let out = run(&p).await;
            assert_refs(&out, &[("pkg:npm/ms@1.3.0", UUID_A, WiringMode::Hosted)]);
        }
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }
}
