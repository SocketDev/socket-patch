//! Lockfile discovery of Socket-patched dependency references — the input
//! side of manifest-less VEX.
//!
//! `scan --mode hosted` rewrites a project's lockfiles so a patched
//! dependency resolves from Socket's patch server; `vendor` / `scan --mode
//! vendored` rewire them onto committed `.socket/vendor/<eco>/<uuid>/…`
//! artifacts. Either way the patch uuid is recoverable from the wired string
//! itself, which is what lets `socket-patch vex` attest a project with NO
//! `.socket/manifest.json` — and possibly no `.socket/vendor` ledgers either
//! (a depscan-opened PR, a clone of a repo that never committed them).
//!
//! [`discover_patched_refs`] reads every supported lockfile / package-manager
//! config at the project ROOT and returns one [`PatchedRef`] per wired
//! `(package, patch)` pair, plus [`Diag`]nostics for files or references it
//! could not use. It is read-only, never touches the network, and never
//! panics on malformed input: every file here is committed, tamper-able data,
//! so each value is validated fail-closed (canonical uuid grammar, path-safe
//! coordinates, root-anchored vendor paths, a Socket host allowlist for
//! hosted URLs) before it becomes a ref.
//!
//! A ref is an attestation INPUT, never an attestation by itself: the CLI
//! (`commands/vex.rs`) still needs a patch record whose uuid AND purl match
//! the ref (manifest, ledgers, or the patch API), and hash evidence — the
//! committed vendored artifact, or the installed tree when one is present.
//! The refs also serve as the WIRING-LIVENESS proof for ledger entries: a
//! vendor/redirect ledger record only attests while some lockfile still
//! references it.
//!
//! Discovery and the lock inventory (`vendor::lock_inventory`: scan's
//! lockfile supplement, the vendored fetch inventory) read each format
//! through ONE shared reader that yields EVERY entry, Socket-owned ones
//! included: the npm-family entry models in `lock_inventory`
//! (`npm_lock_nodes`, `pnpm::pnpm_packages`, `yarn::classic_entries` /
//! `berry_entries`, `BunLockb::parse_packages`) and, for the other formats,
//! the readers the writers own (`cargo_lock` / `cargo_config`, `go_mod_edit`
//! / `go_sum_edit`, `gemfile_lock`, `composer_lock_packages`, the
//! `utils::python_lock` / `poetry_lock` / `requirements` / `hatch` readers,
//! `maven_pom`, `nuget_config` / `nuget_feed`). The inventory's registry
//! views drop the Socket-owned entries (they feed registry discovery and
//! fetches); the extractors here classify and validate exactly those. File
//! selection and I/O stay with each consumer: discovery reads every present
//! file through its recognizing ctx (rules 1, 2, 11), the inventory keeps its
//! precedence chains and silent guarded reads.
//!
//! # Extractor contract
//!
//! One submodule per package-manager group — [`npm`] (package-lock /
//! npm-shrinkwrap, pnpm modern + legacy), [`yarn`] (classic + berry),
//! [`bun`] (`bun.lock` text + `bun.lockb`), [`cargo`], [`golang`],
//! [`pypi_locks`] (uv.lock, poetry.lock, pdm.lock, pylock.toml),
//! [`pypi_other`] (Pipfile.lock, requirements*.txt, hatch), [`gem`],
//! [`composer`], [`maven`], [`nuget`], [`deno`]. Each exports exactly
//!
//! ```ignore
//! pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery)
//! ```
//!
//! and is called once, in a fixed order, by [`discover_patched_refs_with`].
//! The rules below let the extractors be written independently:
//!
//! 1. **Root-only, every file.** Read only the files named in the extractor's
//!    own docs, relative to [`DiscoverCtx::root`] (the same scope as
//!    `lock_inventory`; nested workspace lockfiles are a documented non-goal
//!    except where a root lock already describes them). Read EVERY supported
//!    file that is present — never an either/or precedence chain like the
//!    inventory's pypi chain: the hosted rewriter edits every candidate file
//!    it finds, so a lock another lock "shadows" may still wire a patch.
//! 2. **Guarded reads only**: [`DiscoverCtx::read_text`] /
//!    [`DiscoverCtx::read_bytes`] (FIFO-safe; a missing file is a silent
//!    `None`, an unreadable one records [`DIAG_LOCKFILE_UNREADABLE`]).
//! 3. **Fail-soft.** A malformed FILE records [`DIAG_LOCKFILE_UNPARSEABLE`]
//!    and yields nothing from that file; a recognizably Socket-shaped entry
//!    that fails validation records [`DIAG_REF_INVALID`] (or
//!    [`DIAG_REF_UNATTRIBUTABLE`] when a Socket uuid cannot be tied to one
//!    artifact); an ordinary registry entry is skipped silently. Never
//!    panic, never `unwrap` on file data, bound every recursion.
//! 4. **Hosted identity** comes ONLY from [`DiscoverCtx::hosted_uuid`] (the
//!    Socket host allowlist + last-canonical-uuid-segment rule of
//!    [`crate::patch::redirect::hosted_patch_uuid`]) — except identities
//!    that are not URLs: Go's `patch.socket.dev/gopatch/<uuid>` module path
//!    ([`crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX`]) and the
//!    `socket-patch-<uuid>` registry / repository / source names
//!    ([`socket_patch_name_uuid`]).
//! 5. **Vendored identity** comes ONLY from [`vendor_ref`] (a root-anchored
//!    `.socket/vendor/<eco>/<uuid>/<leaf>` string, leaf taken literally),
//!    [`vendor_ref_decorated`] (only where the format defines `#` / `::`
//!    decorations: yarn classic, berry, url-form pip / Hatch references) or
//!    [`vendor_uuid_dir`] (strings that end at the uuid dir —
//!    maven repository urls, nuget feed paths). A lock location that may be
//!    either kind goes through [`DiscoverCtx::locate`], which computes the
//!    vendored path, the hosted uuid (rule 4) and the decorated-leaf check
//!    once; each extractor keeps its own decision order over the result.
//! 6. **Purls** are built with the validating builders ([`npm_purl`],
//!    [`pypi_purl`], [`simple_purl`], [`golang_purl`], [`composer_purl`],
//!    [`maven_purl`]) and name the package the entry REPLACES — the lock
//!    entry's own coordinates, never the artifact's. [`Discovery::push`]
//!    canonicalizes them ([`canonical_base_purl`]: no qualifiers, pypi PEP
//!    503 names).
//! 7. **Emit** through [`Discovery::push`] with [`PatchedRef::hosted`] /
//!    [`PatchedRef::vendored`]; push re-validates (an invalid ref becomes a
//!    diagnostic) and dedupes. `source_file` is the root-relative name of the
//!    file the reference was read from.
//! 8. **Integrity.** Set `locked_integrity` whenever the lock pins the
//!    artifact bytes. For hosted refs set `integrity_required` iff that
//!    format's hosted rewriter ALWAYS writes a pin: a pin-less entry is then
//!    not Socket-written and must not use the not-installed lockfile basis
//!    (see [`PatchedRef::lockfile_basis_ok`]). Document the per-format
//!    choice in the extractor. Vendored refs ignore it (the artifact is
//!    hashed).
//! 9. **Tests** live in the extractor's own file and use the `testing`
//!    module below (`Project` tempdir builder with fixture copy,
//!    `hosted_url`, `assert_refs`, the `UUID_*` / `TOKEN` constants). Use the
//!    committed redirect fixtures (`tests/fixtures/redirect/<eco>/<flavor>/
//!    <case>/expected/`) for hosted shapes and the real-package-manager
//!    fixtures (`tests/fixtures/{pnpm-hosted,poetry,pdm-native,pipenv,
//!    bun-lockb}/…`) where they exist; include negative cases (non-Socket
//!    host carrying a uuid, placeholder tokens, uuid-shaped grant token,
//!    path traversal in a vendored leaf). `Project::run` asserts that every
//!    emitted ref's uuid was recognized (rule 11).
//! 10. **Pins, not definitions; what the package manager READS.** Emit a
//!     ref only where the file routes THIS package's resolution (a lock
//!     entry, a `Cargo.toml` `registry = "socket-patch-<U>"`, a nuget
//!     `<packageSource>` mapping, a pom `-socket.<hex8>` dependency version)
//!     — never from a registry / index / source DEFINITION alone
//!     (`.cargo/config.toml` `[registries]`, nuget `<add key>`, pom
//!     `<repository>`, uv index tables, `.npmrc`), which survives a reverted
//!     pin (the ledger fallback [`hosted_wiring_in_files`] applies the same
//!     rule). Skip sections the package manager ignores (npm's v2
//!     `dependencies` mirror when `packages` exists). Do NOT resolve
//!     precedence between files: emit what every file wires — the CLI gates
//!     a package wired to several uuids as `wiring_conflict`, and the
//!     orchestrator drops a ref another lock CONTESTS by resolving the same
//!     package elsewhere (extractors report those entries through
//!     [`Discovery::resolved_elsewhere`]; see `contest_across_locks`). Once an
//!     extractor recognizes a uuid, discovery is AUTHORITATIVE for it (a
//!     ledger record for that uuid is live only if a ref wires the same
//!     purl), so a ref with the wrong purl unwires a correct ledger.
//! 11. **Recognition is automatic, and authority follows it.** Every file
//!     read through [`DiscoverCtx::read_text`] / [`DiscoverCtx::read_bytes`]
//!     is swept for the Socket patch identities it MENTIONS — root-anchored
//!     or not `.socket/vendor/<eco>/<uuid>` paths, Socket-host patch URLs
//!     (plain, `\/`-escaped, wholly percent-encoded, `sparse+`-prefixed; every
//!     canonical-uuid segment), `patch.socket.dev/gopatch/<uuid>` module
//!     paths — into [`Discovery::recognized`], whether or not the extractor
//!     accepts them. A ledger claim for a recognized uuid is decided by the
//!     refs ALONE ([`Discovery::hosted_claim`] / [`Discovery::vendored_claim`]):
//!     an entry an extractor rejects with a diagnostic (an orphaned berry
//!     entry, an inert Go replace, a reverted cargo pin, a uv lock its
//!     pyproject does not confirm, a shadowed maven pin, an unattributable
//!     nuget source) or skips because the package manager does not read it
//!     (npm's v2 mirror, `inBundle` / `link` entries, commented-out lines,
//!     an unparseable lock) can never be resurrected as live wiring from the
//!     same raw text by the CLI's fallbacks ([`hosted_wiring_in_files`],
//!     [`vendored_wiring_live`]), which only ever see uuids no read file
//!     mentions (formats nothing reads, patch servers outside the host
//!     allowlist). So extractors get this for free — they cannot forget it —
//!     as long as they read content ONLY through the ctx helpers (an
//!     architecture test in this module enforces it) and sweep a file the
//!     package manager IGNORES in favor of a sibling with
//!     [`DiscoverCtx::recognize_ignored`] (its stale identities are dead
//!     too). `socket-patch-<uuid>` registry / repository / source NAMES are
//!     host-independent — a staging registry reuses the grammar — so they
//!     are never swept: they count through an emitted ref, or through
//!     [`DiscoverCtx::recognize_paired_name`] when the extractor rejects a
//!     name whose own element (a maven `<repository>`, a nuget `<add>`) is
//!     on the Socket host but names another patch.
//! 12. **npm-family extractors iterate the entry models only.** The npm,
//!     pnpm, yarn and bun extractors walk the `lock_inventory` entry models,
//!     never the grammar primitives those wrap (`scan_blocks`, the pnpm
//!     grammar's `entries` / `resolution`, `bun_lock_text`'s section reader,
//!     `BunLockb::parse`) nor a parser of their own (a JSON read of
//!     `bun.lock`), so discovery and the inventory see one entry walk per
//!     format (an architecture test in this module enforces it).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::crawlers::Ecosystem;
use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment};
use crate::utils::purl::{normalize_purl, strip_purl_qualifiers};
use crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX;
use crate::vendor::lock_inventory::{
    inventory_project_every_lock, lookup, LockIntegrity, LockfileEntry, SourceKind,
};
use crate::vendor::path::{ecosystem_dir_for_purl, leaf_to_purl, ECOSYSTEM_DIRS, VENDOR_DIR};
use crate::vendor::state::VendorEntry;

pub(crate) mod bun;
pub(crate) mod cargo;
pub(crate) mod composer;
pub(crate) mod deno;
pub(crate) mod gem;
pub(crate) mod golang;
pub(crate) mod maven;
pub(crate) mod npm;
pub(crate) mod nuget;
pub(crate) mod pypi_locks;
pub(crate) mod pypi_other;
pub(crate) mod yarn;

// ── diagnostics ──────────────────────────────────────────────────────────

/// A supported lockfile/config exists but could not be read (permissions, a
/// FIFO/device squatting the name, non-UTF-8 text).
pub const DIAG_LOCKFILE_UNREADABLE: &str = "lockfile_unreadable";
/// A supported lockfile/config was read but is not valid for its format;
/// nothing is discovered from it.
pub const DIAG_LOCKFILE_UNPARSEABLE: &str = "lockfile_unparseable";
/// A Socket-shaped reference (hosted URL on the patch server, a
/// `.socket/vendor/` path) failed validation — unsafe coordinates, a
/// non-canonical uuid, an artifact leaf that names a different package, a
/// vendor path that escapes the project root.
pub const DIAG_REF_INVALID: &str = "patched_ref_invalid";
/// A Socket patch uuid is present but cannot be tied to exactly one
/// artifact (a maven `socket-patch-<uuid>` repository with no suffixed
/// dependency version, a nuget source with no package mapping).
pub const DIAG_REF_UNATTRIBUTABLE: &str = "patched_ref_unattributable";

/// One non-fatal discovery finding. The CLI surfaces each as a run warning
/// (`code` is the stable routing tag, `file` the root-relative source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub code: &'static str,
    pub file: PathBuf,
    pub detail: String,
}

// ── refs ─────────────────────────────────────────────────────────────────

/// How a discovered dependency is wired to its Socket patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WiringMode {
    /// The lock resolves the dependency from Socket's patch server
    /// (`scan --mode hosted`). The bytes are remote until install.
    Hosted,
    /// The lock/config consumes a committed `.socket/vendor/<eco>/<uuid>/…`
    /// artifact (`vendor`, `scan --mode vendored`).
    Vendored,
}

/// One `(package, patch)` pair a project file wires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedRef {
    /// Canonical base purl of the dependency the patch REPLACES (no
    /// qualifiers; pypi names PEP 503-canonical — see
    /// [`canonical_base_purl`]).
    pub purl: String,
    /// The patch uuid (canonical grammar, enforced by [`Discovery::push`]).
    pub uuid: String,
    pub mode: WiringMode,
    /// Root-relative file the reference was read from.
    pub source_file: PathBuf,
    /// [`WiringMode::Vendored`] only: the root-relative artifact path
    /// (`.socket/vendor/<eco>/<uuid>/<leaf>`, the `VendorArtifact::path`
    /// shape) the wiring consumes. `None` for hosted refs.
    pub artifact_rel: Option<String>,
    /// The content pin the lock records for the wired artifact, if any.
    /// Never `Some(LockIntegrity::None)` (push normalizes it to `None`).
    pub locked_integrity: Option<LockIntegrity>,
    /// Hosted only: this format's hosted rewriter ALWAYS writes an
    /// integrity pin, so a missing `locked_integrity` means the entry was
    /// not Socket-written (hand-edited / degraded) and must not be attested
    /// from the lockfile alone.
    pub integrity_required: bool,
    /// Hosted only: the Socket URL (artifact, registry index, or source url)
    /// the reference was recovered from, for diagnostics.
    pub url: Option<String>,
}

impl PatchedRef {
    /// A hosted ref. `uuid` must come from [`DiscoverCtx::hosted_uuid`] (or a
    /// non-URL identity checked with [`is_canonical_uuid`] / [`socket_patch_name_uuid`]).
    pub fn hosted(
        purl: String,
        uuid: String,
        source_file: &str,
        url: Option<&str>,
        locked_integrity: Option<LockIntegrity>,
        integrity_required: bool,
    ) -> Self {
        PatchedRef {
            purl,
            uuid,
            mode: WiringMode::Hosted,
            source_file: PathBuf::from(source_file),
            artifact_rel: None,
            locked_integrity,
            integrity_required,
            url: url.map(str::to_string),
        }
    }

    /// A vendored ref for the artifact `vref` names.
    pub fn vendored(
        purl: String,
        vref: &VendorRef,
        source_file: &str,
        locked_integrity: Option<LockIntegrity>,
    ) -> Self {
        PatchedRef {
            purl,
            uuid: vref.uuid.clone(),
            mode: WiringMode::Vendored,
            source_file: PathBuf::from(source_file),
            artifact_rel: Some(vref.artifact_rel.clone()),
            locked_integrity,
            integrity_required: false,
            url: None,
        }
    }

    /// Whether this ref may be attested from the lockfile wiring ALONE when
    /// no installed tree exists yet (the not-installed hosted basis — the
    /// same evidence the in-run `scan --mode hosted --vex` uses: the Socket
    /// host allowlist fixes WHERE the bytes come from, and the lock's pin
    /// fixes WHICH bytes). Vendored refs never use it: their artifact is
    /// hashed instead.
    pub fn lockfile_basis_ok(&self) -> bool {
        self.mode == WiringMode::Hosted
            && (self.locked_integrity.is_some() || !self.integrity_required)
    }
}

/// A Socket patch identity that a file discovery READ mentions — whether or
/// not any extractor accepted it as a ref (rule 11 of the module docs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Recognized {
    pub uuid: String,
    /// [`WiringMode::Vendored`] for a `.socket/vendor/<eco>/<uuid>` path,
    /// [`WiringMode::Hosted`] for a Socket-host url or Go module path.
    pub mode: WiringMode,
    /// Root-relative file that mentions it.
    pub file: PathBuf,
}

/// A Socket pin that routes EVERY version of one package to a patch but
/// cannot name the version, because the project has no lock to fix it: a
/// cargo `Cargo.toml` `registry = "socket-patch-<U>"` pin, a nuget exclusive
/// exact-id `<packageSourceMapping>`. Both are the hosted rewriter's
/// ordinary output for a lockless project, and the patch registry they
/// route to serves only the patched version, so the pin is live wiring for
/// a ledger record that supplies the exact version — never a ref on its own
/// (there is no version to attest). See [`Discovery::hosted_claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedPin {
    /// The purl type (`cargo`, `nuget`).
    pub ecosystem: String,
    /// The package name as the pin spells it.
    pub name: String,
    pub uuid: String,
    /// Root-relative file carrying the pin.
    pub file: PathBuf,
    /// Version requirements the pinning declarations carry (cargo's
    /// `version = "…"`); a ledger version must satisfy every one. Empty =
    /// none to check (nuget: the csproj `Version` is only a minimum).
    pub version_reqs: Vec<String>,
}

impl UnlockedPin {
    /// Whether this pin routes `purl` (any spelling) to patch `uuid`.
    fn covers(&self, purl: &str, uuid: &str) -> bool {
        if self.uuid != uuid {
            return false;
        }
        let key = canonical_base_purl(purl);
        let Some(version) = key.rsplit_once('@').map(|(_, v)| v) else {
            return false;
        };
        let pinned =
            canonical_base_purl(&format!("pkg:{}/{}@{version}", self.ecosystem, self.name));
        pinned == key
            && self.version_reqs.iter().all(|req| {
                match (
                    semver::VersionReq::parse(req),
                    semver::Version::parse(version),
                ) {
                    (Ok(req), Ok(version)) => req.matches(&version),
                    _ => false,
                }
            })
    }
}

/// A lock entry that resolves a package from somewhere OTHER than a Socket
/// patch — a registry, a user's url, git, a local path: positive evidence
/// that installing from that lock yields the unpatched package (see
/// [`Discovery::resolved_elsewhere`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedElsewhere {
    /// Canonical base purl ([`canonical_base_purl`]).
    pub purl: String,
    /// Root-relative lock file.
    pub file: PathBuf,
}

/// Everything [`discover_patched_refs`] found.
#[derive(Debug, Clone, Default)]
pub struct Discovery {
    /// Sorted by `(source_file, purl, uuid, mode)`, exact duplicates removed.
    pub refs: Vec<PatchedRef>,
    pub diagnostics: Vec<Diag>,
    /// Every Socket patch identity the files discovery read mention, the
    /// refs' own included — sorted, deduped. A uuid in here is one discovery
    /// is AUTHORITATIVE for (rule 11): see [`Discovery::hosted_claim`].
    pub recognized: Vec<Recognized>,
    /// Lockless Socket pins ([`UnlockedPin`]) — liveness evidence for a
    /// ledger record, never refs.
    pub unlocked_pins: Vec<UnlockedPin>,
    /// npm-family and Python lock entries resolving a package from a
    /// non-Socket source — the evidence the cross-lock contest
    /// ([`discover_patched_refs_with`]) weighs against another lock's ref.
    pub elsewhere: Vec<ResolvedElsewhere>,
}

impl Discovery {
    /// Validate, canonicalize, and record `r`. An invalid ref is dropped and
    /// becomes a [`DIAG_REF_INVALID`] diagnostic instead — this is the last
    /// fail-closed gate between a committed file and an attestation input,
    /// so it re-checks what the extractors already should have:
    ///
    /// * the uuid is canonical;
    /// * the purl is `pkg:<known type>/<name>@<version>` (then canonicalized);
    /// * a vendored ref names a root-anchored artifact under its OWN uuid dir
    ///   and its purl's ecosystem dir.
    pub fn push(&mut self, mut r: PatchedRef) {
        let file = r.source_file.to_string_lossy().into_owned();
        if !is_canonical_uuid(&r.uuid) {
            self.diag(
                DIAG_REF_INVALID,
                &file,
                format!(
                    "{file}: {}: patch uuid {:?} is not a canonical uuid",
                    r.purl, r.uuid
                ),
            );
            return;
        }
        // Every identity an extractor builds a ref from is recognized — the
        // valid ref and the one rejected below alike (rule 11). This is also
        // how host-independent identities (a cargo `socket-patch-<uuid>`
        // manifest pin paired with a Socket-sourced lock entry) get
        // recognized: only through a ref.
        self.recognize(&r.uuid, r.mode, &file);
        let Some(purl) = validated_ref_purl(&r.purl) else {
            self.diag(
                DIAG_REF_INVALID,
                &file,
                format!("{file}: {:?} is not a usable package purl", r.purl),
            );
            return;
        };
        r.purl = purl;
        match r.mode {
            WiringMode::Vendored => {
                let artifact_ok = r
                    .artifact_rel
                    .as_deref()
                    .and_then(vendor_ref)
                    .is_some_and(|v| {
                        v.uuid == r.uuid
                            && Some(v.artifact_rel.as_str()) == r.artifact_rel.as_deref()
                            && ecosystem_dir_for_purl(&r.purl) == Some(v.eco.as_str())
                    });
                if !artifact_ok {
                    self.diag(
                        DIAG_REF_INVALID,
                        &file,
                        format!(
                            "{file}: {}: vendored artifact path {:?} is not this patch's \
                             .socket/vendor/<eco>/{}/ artifact",
                            r.purl, r.artifact_rel, r.uuid
                        ),
                    );
                    return;
                }
                r.integrity_required = false;
                r.url = None;
            }
            WiringMode::Hosted => r.artifact_rel = None,
        }
        if matches!(r.locked_integrity, Some(LockIntegrity::None)) {
            r.locked_integrity = None;
        }
        if !self.refs.contains(&r) {
            self.refs.push(r);
        }
    }

    /// Record a diagnostic for root-relative `file`. `detail` is shown to
    /// the user verbatim (as a run warning), so it must name the file itself.
    pub fn diag(&mut self, code: &'static str, file: &str, detail: impl Into<String>) {
        let diag = Diag {
            code,
            file: PathBuf::from(file),
            detail: detail.into(),
        };
        if !self.diagnostics.contains(&diag) {
            self.diagnostics.push(diag);
        }
    }

    /// Whether some file wires `purl` (any spelling — compared via
    /// [`canonical_base_purl`]) to patch `uuid` in `mode`.
    pub fn wires(&self, purl: &str, uuid: &str, mode: WiringMode) -> bool {
        let key = canonical_base_purl(purl);
        self.refs
            .iter()
            .any(|r| r.uuid == uuid && r.mode == mode && r.purl == key)
    }

    /// Whether some file discovery read mentions patch `uuid` as a `mode`
    /// identity (rule 11) — accepted as a ref or not.
    pub fn recognizes(&self, uuid: &str, mode: WiringMode) -> bool {
        self.recognized
            .iter()
            .any(|r| r.uuid == uuid && r.mode == mode)
    }

    /// The root-relative files that mention patch `uuid` as a `mode`
    /// identity, sorted.
    pub fn recognized_files(&self, uuid: &str, mode: WiringMode) -> Vec<&Path> {
        let mut files: Vec<&Path> = self
            .recognized
            .iter()
            .filter(|r| r.uuid == uuid && r.mode == mode)
            .map(|r| r.file.as_path())
            .collect();
        files.dedup();
        files
    }

    /// Record that root-relative lock `file` resolves `purl` (a validated
    /// builder's output; `None` is ignored) from a non-Socket source — its
    /// entry is neither a Socket-hosted url nor a vendored artifact, nor a
    /// Socket-shaped string an extractor rejected. Extractors of the
    /// package managers that keep several lockfiles side by side (npm,
    /// pnpm, yarn, bun; uv, pylock, poetry, pdm, Pipfile, requirements)
    /// call it for every such entry with exact coordinates.
    pub(crate) fn resolved_elsewhere(&mut self, file: &str, purl: Option<String>) {
        let Some(purl) = purl else { return };
        let entry = ResolvedElsewhere {
            purl: canonical_base_purl(&purl),
            file: PathBuf::from(file),
        };
        if !self.elsewhere.contains(&entry) {
            self.elsewhere.push(entry);
        }
    }

    /// Drop every ref that ANOTHER lock contests: a lock that resolves the
    /// same package at the same version from a non-Socket source
    /// ([`Discovery::resolved_elsewhere`]) while wiring it to no patch
    /// itself. Which lock the build installs from depends on the package
    /// manager that runs (`yarn install` beside `npm ci`, `uv sync` beside
    /// `pip install -r requirements.txt`, npm 12 beside npm 11 for the npm
    /// pair), so a Socket wiring in one lock and the unpatched package in
    /// another is not decidable from the files: the ref is diagnosed
    /// ([`DIAG_REF_UNATTRIBUTABLE`], naming both files) and not emitted.
    /// Its uuid stays recognized, so a ledger claim for it is dead too (rule
    /// 11). This generalizes the npm extractor's shrinkwrap/package-lock
    /// rule to every pair of locks. PEP 723 script locks (`*.py.lock`)
    /// neither contest nor are contested: each is scoped to its own script's
    /// install.
    fn contest_across_locks(&mut self) {
        let wiring: BTreeSet<(String, PathBuf)> = self
            .refs
            .iter()
            .map(|r| (r.purl.clone(), r.source_file.clone()))
            .collect();
        let mut contested = Vec::new();
        let refs = std::mem::take(&mut self.refs);
        for r in refs {
            let other = (!is_script_lock(&r.source_file))
                .then(|| {
                    self.elsewhere.iter().find(|e| {
                        e.purl == r.purl
                            && e.file != r.source_file
                            && !wiring.contains(&(e.purl.clone(), e.file.clone()))
                    })
                })
                .flatten();
            match other {
                Some(e) => contested.push((r, e.file.clone())),
                None => self.refs.push(r),
            }
        }
        for (r, other) in contested {
            let file = r.source_file.to_string_lossy().into_owned();
            self.diag(
                DIAG_REF_UNATTRIBUTABLE,
                &file,
                format!(
                    "{file}: {} is wired to Socket patch {}, but {} resolves the same version \
                     from elsewhere (not a Socket patch) — which lock the build installs from \
                     depends on the package manager that runs, so the patch is not attested; \
                     rewire both locks (re-run `socket-patch scan` / `vendor`) or delete the \
                     stale one",
                    r.purl,
                    r.uuid,
                    other.display()
                ),
            );
        }
    }

    /// Record a lockless Socket pin (see [`UnlockedPin`]).
    pub(crate) fn unlocked_pin(&mut self, pin: UnlockedPin) {
        if is_canonical_uuid(&pin.uuid) && !self.unlocked_pins.contains(&pin) {
            self.unlocked_pins.push(pin);
        }
    }

    /// Discovery's verdict on a HOSTED ledger claim "`purl` resolves from
    /// patch `uuid`" (the redirect ledger's liveness gate):
    ///
    /// * `Some(true)` — a ref wires exactly that, or a lockless pin
    ///   ([`UnlockedPin`]) routes every version of the package to `uuid` and
    ///   the ledger's exact version satisfies its requirements;
    /// * `Some(false)` — the uuid IS recognized in a file discovery read, but
    ///   no ref wires this package to it: the pin was reverted, points at
    ///   another package, or survives only in a shape an extractor rejected
    ///   or a section the package manager does not read. Final: the caller
    ///   must not re-derive liveness from the same raw text;
    /// * `None` — no file discovery read mentions the uuid (a format nothing
    ///   reads, a patch server outside the host allowlist): only then may the
    ///   ledger's own recorded evidence decide ([`hosted_wiring_in_files`]).
    pub fn hosted_claim(&self, purl: &str, uuid: &str) -> Option<bool> {
        self.recognizes(uuid, WiringMode::Hosted).then(|| {
            self.wires(purl, uuid, WiringMode::Hosted)
                || self.unlocked_pins.iter().any(|p| p.covers(purl, uuid))
        })
    }

    /// [`Discovery::hosted_claim`]'s VENDORED twin (the vendor ledger's
    /// liveness gate): `Some(true)` only when a ref wires `purl` to exactly
    /// the ledger's committed `artifact_rel` under `uuid`; `None` hands the
    /// decision to the ledger's recorded wiring ([`vendored_wiring_live`]).
    pub fn vendored_claim(&self, purl: &str, uuid: &str, artifact_rel: &str) -> Option<bool> {
        self.recognizes(uuid, WiringMode::Vendored).then(|| {
            let key = canonical_base_purl(purl);
            let artifact = artifact_rel.trim_start_matches("./");
            self.refs.iter().any(|r| {
                r.uuid == uuid
                    && r.mode == WiringMode::Vendored
                    && r.purl == key
                    && r.artifact_rel.as_deref() == Some(artifact)
            })
        })
    }

    fn recognize(&mut self, uuid: &str, mode: WiringMode, file: &str) {
        self.recognized.push(Recognized {
            uuid: uuid.to_string(),
            mode,
            file: PathBuf::from(file),
        });
    }

    fn finalize(&mut self) {
        self.elsewhere.sort();
        self.elsewhere.dedup();
        self.refs.sort_by(|a, b| {
            (&a.source_file, &a.purl, &a.uuid, a.mode).cmp(&(
                &b.source_file,
                &b.purl,
                &b.uuid,
                b.mode,
            ))
        });
        self.refs.dedup();
        self.diagnostics
            .sort_by(|a, b| (&a.file, a.code, &a.detail).cmp(&(&b.file, b.code, &b.detail)));
        self.recognized.sort();
        self.recognized.dedup();
    }
}

// ── orchestrator ─────────────────────────────────────────────────────────

/// Discovery knobs.
#[derive(Debug, Clone, Default)]
pub struct DiscoverOptions {
    /// Extra patch-server ORIGINS whose URLs count as hosted references in
    /// addition to `https://patch.socket.dev` — the operator's
    /// `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` deployment (staging,
    /// self-hosted, local test servers). Compared on scheme + host + port.
    pub patch_server_origins: Vec<String>,
}

/// [`discover_patched_refs_with`] with default options (only Socket's
/// public patch server counts as a hosted origin).
pub async fn discover_patched_refs(root: &Path) -> Discovery {
    discover_patched_refs_with(root, &DiscoverOptions::default()).await
}

/// Scan `root`'s lockfiles/configs for Socket-patched dependency references.
/// See the module docs for the contract; the extractor order below is fixed
/// only for deterministic diagnostics — refs are sorted afterwards.
pub async fn discover_patched_refs_with(root: &Path, opts: &DiscoverOptions) -> Discovery {
    let ctx = DiscoverCtx::with_origins(root, &opts.patch_server_origins);
    let mut out = Discovery::default();
    npm::extract(&ctx, &mut out).await;
    yarn::extract(&ctx, &mut out).await;
    bun::extract(&ctx, &mut out).await;
    cargo::extract(&ctx, &mut out).await;
    golang::extract(&ctx, &mut out).await;
    pypi_locks::extract(&ctx, &mut out).await;
    pypi_other::extract(&ctx, &mut out).await;
    gem::extract(&ctx, &mut out).await;
    composer::extract(&ctx, &mut out).await;
    maven::extract(&ctx, &mut out).await;
    nuget::extract(&ctx, &mut out).await;
    deno::extract(&ctx, &mut out).await;
    out.contest_across_locks();
    out.recognized.extend(ctx.take_recognized());
    out.finalize();
    out
}

/// A PEP 723 script lock (`<script>.py.lock`).
fn is_script_lock(file: &Path) -> bool {
    crate::utils::python_lock::is_script_lock_name(&file.to_string_lossy())
}

/// What every extractor receives: the project root plus the hosted-origin
/// allowlist, with the guarded-read and identity helpers bolted on.
pub(crate) struct DiscoverCtx<'a> {
    pub(crate) root: &'a Path,
    patch_server_origins: &'a [String],
    /// What the guarded reads have recognized so far (rule 11) — collected
    /// here, not in the extractor's `&mut Discovery`, so a read into a
    /// scratch `Discovery` (a file parsed only to explain it) still counts.
    /// A `Mutex` keeps the ctx `Sync` across the extractors' `.await`s.
    recognized: Mutex<BTreeSet<Recognized>>,
}

impl<'a> DiscoverCtx<'a> {
    pub(crate) fn with_origins(root: &'a Path, patch_server_origins: &'a [String]) -> Self {
        DiscoverCtx {
            root,
            patch_server_origins,
            recognized: Mutex::new(BTreeSet::new()),
        }
    }

    /// Record every Socket identity `text` (the content of root-relative
    /// `rel`) mentions — see [`socket_identities`].
    fn recognize_text(&self, rel: &str, text: &str) {
        let found = socket_identities(text, self.patch_server_origins);
        if found.is_empty() {
            return;
        }
        let mut seen = self
            .recognized
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (uuid, mode) in found {
            seen.insert(Recognized {
                uuid,
                mode,
                file: PathBuf::from(rel),
            });
        }
    }

    /// Recognize a HOST-INDEPENDENT `socket-patch-<uuid>` name that the
    /// extractor tied to a Socket-host url (or this project's vendor dir) in
    /// the SAME element, which names another patch — a maven `<repository>`
    /// whose `<id>` and `<url>` disagree, a nuget `<add>` whose `key` and
    /// `value` do. The sweep never counts bare names (a staging registry
    /// reuses the grammar), but once its element is host-verified the name
    /// is a Socket identity like any other, and the rejected pairing must
    /// not leave it to the raw-text fallback, which would find the name's
    /// uuid in pin position (rule 11).
    pub(crate) fn recognize_paired_name(&self, rel: &str, uuid: &str, mode: WiringMode) {
        if !is_canonical_uuid(uuid) {
            return;
        }
        self.recognized
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(Recognized {
                uuid: uuid.to_string(),
                mode,
                file: PathBuf::from(rel),
            });
    }

    /// Everything recognized so far, draining the collector.
    pub(crate) fn take_recognized(&self) -> Vec<Recognized> {
        let mut seen = self
            .recognized
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *seen).into_iter().collect()
    }

    /// Sweep a file the package manager IGNORES in favor of a sibling
    /// (`shrinkwrap.yaml` beside `pnpm-lock.yaml`, `bun.lockb` beside
    /// `bun.lock`, a second nuget config spelling) for the identities it
    /// mentions, without reading it as a lock: nothing in it is wiring, so a
    /// ledger claim it alone keeps textually "alive" must be dead (rule 11).
    /// Quiet — a missing or unreadable ignored file is not a finding.
    pub(crate) async fn recognize_ignored(&self, rel: &str) {
        if let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&self.root.join(rel)).await {
            self.recognize_text(rel, &String::from_utf8_lossy(&bytes));
        }
    }

    /// The patch uuid of a Socket-HOSTED url, or `None` for anything else
    /// (see [`crate::patch::redirect::hosted_patch_uuid`] for the accepted
    /// spellings and the host allowlist).
    pub(crate) fn hosted_uuid(&self, url: &str) -> Option<String> {
        crate::patch::redirect::hosted_patch_uuid(url, self.patch_server_origins)
    }

    /// Whether `rel` exists (lstat — a dangling symlink still "exists", the
    /// read then fails and diagnoses).
    pub(crate) async fn exists(&self, rel: &str) -> bool {
        tokio::fs::symlink_metadata(self.root.join(rel))
            .await
            .is_ok()
    }

    /// Guarded UTF-8 read of root-relative `rel`: `None` when missing
    /// (silent) or unreadable ([`DIAG_LOCKFILE_UNREADABLE`] recorded). The
    /// content is swept for the Socket identities it mentions BEFORE any
    /// parsing (rule 11) — so a file that then fails to parse, or an entry
    /// the extractor rejects or skips, is still recognized.
    pub(crate) async fn read_text(&self, rel: &str, out: &mut Discovery) -> Option<String> {
        match crate::utils::fs::read_regular_to_string(&self.root.join(rel)).await {
            Ok(text) => {
                self.recognize_text(rel, &text);
                Some(text)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                out.diag(
                    DIAG_LOCKFILE_UNREADABLE,
                    rel,
                    format!("cannot read {rel}: {e}"),
                );
                None
            }
        }
    }

    /// Bytes twin of [`DiscoverCtx::read_text`] (JSON and binary locks). A
    /// binary lock is swept through its lossy UTF-8 view: string pools store
    /// resolutions verbatim, and a stale string an older patch generation
    /// left in `bun.lockb`'s append-only pool names a DEAD patch, which is
    /// exactly what recognition should say about it.
    pub(crate) async fn read_bytes(&self, rel: &str, out: &mut Discovery) -> Option<Vec<u8>> {
        match crate::utils::fs::read_regular_to_bytes(&self.root.join(rel)).await {
            Ok(bytes) => {
                self.recognize_text(rel, &String::from_utf8_lossy(&bytes));
                Some(bytes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                out.diag(
                    DIAG_LOCKFILE_UNREADABLE,
                    rel,
                    format!("cannot read {rel}: {e}"),
                );
                None
            }
        }
    }
}

// ── identity helpers ─────────────────────────────────────────────────────

/// The uuid of a Socket-owned registry / repository / source NAME:
/// `socket-patch-<uuid>` (cargo `[registries.*]` + Cargo.toml `registry =`,
/// maven `<repository><id>`, nuget `<add key>`) or, with
/// `vendored = true`, `socket-patch-vendor-<uuid>` (maven's vendored repo
/// id). Exact grammar only — a suffix or a non-canonical uuid is not ours.
pub(crate) fn socket_patch_name_uuid(name: &str, vendored: bool) -> Option<String> {
    crate::patch::redirect::socket_patch_name_uuid_exact(name.trim(), vendored).map(str::to_string)
}

/// Every Socket patch identity `text` MENTIONS, by wiring mode — the sweep
/// behind rule 11, run over the content of every file discovery reads. It is
/// deliberately a superset of what any extractor accepts (it must recognize
/// exactly the shapes extractors reject), yet never counts a uuid on a host
/// outside the allowlist or a bare name:
///
/// * [`WiringMode::Vendored`]: `.socket/vendor/<eco>/<uuid>` ANYWHERE — a
///   `../` / absolute / other-checkout spelling or a traversal leaf
///   included (the ledger's raw-text fallback would match those too);
/// * [`WiringMode::Hosted`]: every canonical-uuid path segment of a url on
///   an accepted patch-server origin
///   ([`crate::patch::redirect::hosted_patch_url_uuids`]: plain,
///   `sparse+` / `registry+` prefixed, or a wholly percent-encoded berry
///   `__archiveUrl`), and every canonical-uuid segment of a
///   `patch.socket.dev/gopatch/…` Go module path.
///
/// The escapes the extractors' parsers decode (JSON / TOML `\uXXXX`, XML
/// character and named entities — nuget's hand-edit tolerance) are decoded
/// first, so the sweep sees every string an extractor sees; then JSON `\/`
/// escapes and (doubled) Windows backslashes are folded to `/`. Bounded
/// work per anchor, so a tampered multi-megabyte lock costs one linear pass
/// per anchor kind.
fn socket_identities(text: &str, origins: &[String]) -> BTreeSet<(String, WiringMode)> {
    let mut found = BTreeSet::new();
    let norm = decode_escapes(text)
        .replace("\\/", "/")
        .replace("\\\\", "/")
        .replace('\\', "/");
    let bytes = norm.as_bytes();

    let anchor = format!("{VENDOR_DIR}/");
    for (at, _) in norm.match_indices(anchor.as_str()) {
        let rest = &norm[at + anchor.len()..];
        for eco in ECOSYSTEM_DIRS {
            let uuid = rest
                .strip_prefix(eco)
                .and_then(|r| r.strip_prefix('/'))
                .and_then(|r| r.get(..36))
                .filter(|u| is_canonical_uuid(u));
            if let Some(uuid) = uuid {
                found.insert((uuid.to_string(), WiringMode::Vendored));
            }
        }
    }

    for (at, _) in norm.match_indices(HOSTED_GO_MODULE_PREFIX) {
        let start = at + HOSTED_GO_MODULE_PREFIX.len();
        let end = token_end(bytes, start, b"@");
        for segment in norm[start..end].split('/') {
            if is_canonical_uuid(segment) {
                found.insert((segment.to_string(), WiringMode::Hosted));
            }
        }
    }

    // Cheap pre-filter: only a token naming an accepted host can be ours.
    let mut hosts = vec![crate::patch::redirect::SOCKET_PATCH_SERVER_HOST.to_string()];
    hosts.extend(origins.iter().filter_map(|o| {
        reqwest::Url::parse(o.trim())
            .ok()?
            .host_str()
            .map(str::to_ascii_lowercase)
    }));
    let lower = norm.to_ascii_lowercase();
    for separator in ["://", "%3a%2f%2f"] {
        for (at, _) in lower.match_indices(separator) {
            let Some(start) = scheme_start(bytes, at) else {
                continue;
            };
            let end = token_end(bytes, at + separator.len(), b"");
            if !hosts.iter().any(|h| lower[start..end].contains(h.as_str())) {
                continue;
            }
            let uuids = crate::patch::redirect::hosted_patch_url_uuids(&norm[start..end], origins);
            for uuid in uuids.into_iter().flatten() {
                found.insert((uuid, WiringMode::Hosted));
            }
        }
    }
    found
}

/// Best-effort decode of `\uXXXX` / `\UXXXXXXXX` escapes and XML entities
/// (`&#x2F;`, `&#47;`, `&amp;`, …) for [`socket_identities`] — over-decoding
/// (an escaped backslash before `u`) only ever ADDS recognition, which can
/// only make a claim dead, never live.
fn decode_escapes(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("\\u") && !text.contains("\\U") && !text.contains('&') {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(['\\', '&']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        match decode_one_escape(tail) {
            Some((ch, used)) => {
                out.push(ch);
                rest = &tail[used..];
            }
            None => {
                // `\` and `&` are one byte each.
                out.push_str(&tail[..1]);
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

/// The char one escape at the start of `tail` stands for, and its length.
fn decode_one_escape(tail: &str) -> Option<(char, usize)> {
    let hex_char = |digits: &str| char::from_u32(u32::from_str_radix(digits, 16).ok()?);
    if let Some(rest) = tail.strip_prefix("\\u") {
        return Some((hex_char(rest.get(..4)?)?, 6));
    }
    if let Some(rest) = tail.strip_prefix("\\U") {
        return Some((hex_char(rest.get(..8)?)?, 10));
    }
    if let Some(rest) = tail.strip_prefix("&#") {
        let end = rest.get(..rest.len().min(10))?.find(';')?;
        let body = &rest[..end];
        let ch = match body.strip_prefix(['x', 'X']) {
            Some(hex) => hex_char(hex)?,
            None => char::from_u32(body.parse().ok()?)?,
        };
        return Some((ch, end + 3));
    }
    [
        ("&amp;", '&'),
        ("&quot;", '"'),
        ("&apos;", '\''),
        ("&lt;", '<'),
        ("&gt;", '>'),
    ]
    .into_iter()
    .find(|(name, _)| tail.starts_with(name))
    .map(|(name, ch)| (ch, name.len()))
}

/// Start of the url whose `://` (or `%3A%2F%2F`) is at byte `at`: the
/// LONGEST http(s) scheme spelling ending there (cargo's `sparse+` /
/// `registry+` kinds included) — only http(s) urls can be Socket-hosted, so
/// any other scheme is `None`. Matching a known spelling rather than
/// walking back over scheme characters keeps the string before it out of
/// the url: bun's `name@url` specs, berry's `=` bindings, and above all a
/// binary lock's string pool, whose strings abut with no delimiter.
fn scheme_start(bytes: &[u8], at: usize) -> Option<usize> {
    const SCHEMES: [&[u8]; 6] = [
        b"registry+https",
        b"registry+http",
        b"sparse+https",
        b"sparse+http",
        b"https",
        b"http",
    ];
    let head = &bytes[..at];
    SCHEMES
        .iter()
        .find(|scheme| {
            head.len() >= scheme.len()
                && head[head.len() - scheme.len()..].eq_ignore_ascii_case(scheme)
        })
        .map(|scheme| at - scheme.len())
}

/// End of the token starting at byte `from`: the first delimiter a lock or
/// config format puts after a url / path (whitespace, quotes, brackets, XML
/// tag starts, list and binding separators, any control byte), plus
/// `extra`. Delimiters are all ASCII, so the result is always a char
/// boundary.
fn token_end(bytes: &[u8], from: usize, extra: &[u8]) -> usize {
    let mut end = from;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_whitespace()
            || b.is_ascii_control()
            || b"\"'`<>,;()[]{}|&".contains(&b)
            || extra.contains(&b)
        {
            break;
        }
        end += 1;
    }
    end
}

/// A vendored artifact reference recovered from a wiring string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRef {
    /// Vendor ecosystem dir (`npm`, `cargo`, `pypi`, …).
    pub eco: String,
    pub uuid: String,
    /// The natural leaf, lock-format suffixes stripped ([`strip_leaf_suffix`]),
    /// forward-slashed, no trailing slash.
    pub leaf: String,
    /// `.socket/vendor/<eco>/<uuid>/<leaf>` — the root-relative artifact path.
    pub artifact_rel: String,
}

/// Recover a vendored artifact reference from a lockfile/config string that
/// points into THIS project's `.socket/vendor/`: `file:` / `./` / bare
/// spellings, backslashed Windows spellings, and `\/`-escaped JSON text.
///
/// Stricter than [`crate::vendor::parse_vendor_path`] (which finds the anchor
/// anywhere, for the orphan sweep): the anchor must START the path. A
/// `../.socket/vendor/…` or absolute spelling points the package manager at
/// an artifact OUTSIDE the project root, and verifying the root's same-named
/// artifact instead would attest bytes the build never consumes. Callers
/// whose format legitimately prefixes the project root (hatch
/// `{root:uri}/`, maven `file://${project.basedir}/`, pnpm-legacy absolute
/// importer paths) strip that exact prefix first.
///
/// The leaf must be a traversal-safe relative path, taken LITERALLY: npm,
/// pnpm, bun, composer, bundler, go, cargo, maven, nuget and every pypi
/// lock read the string as a file path, so a leaf carrying `#` or `::` is
/// rejected (`None`) rather than cut — `…/foo-1.0.0.tgz#evil.tgz` is a file
/// of that literal name, which npm installs while the cut leaf would verify
/// the good `foo-1.0.0.tgz` beside it. The formats whose grammar DEFINES
/// those decorations use [`vendor_ref_decorated`] instead.
pub fn vendor_ref(s: &str) -> Option<VendorRef> {
    vendor_ref_with(s, false)
}

/// [`vendor_ref`] for the formats that decorate a vendored path: yarn
/// classic `#<sha1>`, berry `#./…::hash=…` fragments and `::locator=…`
/// bindings, and url-form pip / Hatch references (`file:…#sha256=…`,
/// `{root:uri}/…#sha256=…`). The leaf keeps only its natural name — the
/// decorations ([`strip_leaf_suffix`]) are cut before the literal-path
/// checks.
pub fn vendor_ref_decorated(s: &str) -> Option<VendorRef> {
    vendor_ref_with(s, true)
}

fn vendor_ref_with(s: &str, decorated: bool) -> Option<VendorRef> {
    let rest = root_anchored_vendor_rest(s)?;
    let mut it = rest.splitn(3, '/');
    let eco = it.next()?;
    let uuid = it.next()?;
    let leaf_raw = it.next()?;
    if !ECOSYSTEM_DIRS.contains(&eco) || !is_canonical_uuid(uuid) {
        return None;
    }
    let leaf = if decorated {
        strip_leaf_suffix(leaf_raw)
    } else if leaf_raw.contains('#') || leaf_raw.contains("::") {
        return None;
    } else {
        leaf_raw
    };
    let leaf = leaf.trim_end_matches('/');
    if leaf.is_empty() || !is_safe_multi_segment(leaf) {
        return None;
    }
    Some(VendorRef {
        eco: eco.to_string(),
        uuid: uuid.to_string(),
        leaf: leaf.to_string(),
        artifact_rel: format!("{VENDOR_DIR}/{eco}/{uuid}/{leaf}"),
    })
}

/// `(eco, uuid)` for a root-anchored string that ends AT the uuid dir
/// (`.socket/vendor/nuget/<uuid>`, a maven repository url's path) — the
/// shapes [`vendor_ref`] rejects for having no leaf.
pub fn vendor_uuid_dir(s: &str) -> Option<(String, String)> {
    let rest = root_anchored_vendor_rest(s)?;
    let (eco, uuid) = rest.trim_end_matches('/').split_once('/')?;
    if !ECOSYSTEM_DIRS.contains(&eco) || !is_canonical_uuid(uuid) {
        return None;
    }
    Some((eco.to_string(), uuid.to_string()))
}

/// Whether `s` is a vendored artifact path [`vendor_ref`] rejects ONLY for
/// a `#` / `::` in its leaf (what [`vendor_ref_decorated`] would have cut):
/// to a literal-path format that names another file, which extractors
/// diagnose rather than skip silently.
pub(crate) fn is_decorated_vendor_path(s: &str) -> bool {
    vendor_ref(s).is_none() && vendor_ref_decorated(s).is_some()
}

/// Everything after a LEADING `.socket/vendor/` anchor (after `file:`, one
/// `./`, backslash and `\/` normalization), or `None`.
fn root_anchored_vendor_rest(s: &str) -> Option<String> {
    let norm = s.trim().replace("\\/", "/").replace('\\', "/");
    let norm = norm.strip_prefix("file:").unwrap_or(&norm);
    let norm = norm.strip_prefix("./").unwrap_or(norm);
    norm.strip_prefix(&format!("{VENDOR_DIR}/"))
        .map(str::to_string)
}

/// Cut the lock-format decorations off a vendored leaf: everything from the
/// first `#` (yarn classic `#<sha1>`, berry `#./<path>::hash=…`, pip/hatch
/// `#sha256=…`) or `::` (berry `::locator=…`).
pub fn strip_leaf_suffix(leaf: &str) -> &str {
    let cut = [leaf.find('#'), leaf.find("::")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(leaf.len());
    &leaf[..cut]
}

/// The canonical base purl a vendored leaf names (see
/// [`crate::vendor::path`]'s leaf table), suffixes stripped and pypi names
/// canonicalized. `None` when the leaf is not a recognizable artifact name.
pub fn vendored_leaf_purl(eco: &str, leaf: &str) -> Option<String> {
    leaf_to_purl(eco, strip_leaf_suffix(leaf).trim_end_matches('/'))
        .map(|purl| canonical_base_purl(&purl))
}

// ── shared extractor helpers ─────────────────────────────────────────────

/// How a lock format spells a vendored leaf: literally ([`vendor_ref`]) or
/// with `#` / `::` decorations after it ([`vendor_ref_decorated`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafGrammar {
    /// The string is a file path: a `#` / `::` belongs to the leaf.
    Literal,
    /// The format defines `#` / `::` decorations after the leaf (yarn
    /// classic / berry, url-form pip and Hatch references).
    Decorated,
}

/// What [`DiscoverCtx::locate`] computes for one wiring string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocateOpts {
    pub(crate) grammar: LeafGrammar,
    /// [`LeafGrammar::Literal`] only: also report a vendored path whose leaf
    /// carries a decoration ([`is_decorated_vendor_path`]) — the npm, pnpm
    /// and bun extractors diagnose it; composer and the pypi readers do not
    /// check it.
    pub(crate) decorated_check: bool,
}

impl LocateOpts {
    /// A literal path, decorated leaves reported (npm, pnpm, bun).
    pub(crate) const LITERAL_CHECKED: Self = LocateOpts {
        grammar: LeafGrammar::Literal,
        decorated_check: true,
    };
    /// A literal path, decorated leaves not checked (composer, pypi locks,
    /// bare pip / Hatch paths).
    pub(crate) const LITERAL: Self = LocateOpts {
        grammar: LeafGrammar::Literal,
        decorated_check: false,
    };
    /// A decorated spelling (yarn, url-form pip / Hatch references).
    pub(crate) const DECORATED: Self = LocateOpts {
        grammar: LeafGrammar::Decorated,
        decorated_check: false,
    };
}

/// Where one lockfile / config string points — every identity decision an
/// extractor takes from it, computed once. Each extractor keeps its own
/// decision ORDER over the fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Located {
    /// The root-anchored vendored artifact the string names, read with the
    /// requested [`LeafGrammar`].
    pub(crate) vendored: Option<VendorRef>,
    /// The patch uuid of a Socket-hosted url ([`DiscoverCtx::hosted_uuid`]),
    /// computed eagerly: it needs an http(s) url on an allowed origin while
    /// `vendored` needs the string to START at `.socket/vendor/`, so at most
    /// one of the two is ever set.
    pub(crate) hosted: Option<String>,
    /// [`is_decorated_vendor_path`] when [`LocateOpts::decorated_check`] is
    /// set (Literal grammar only), else `false`.
    pub(crate) decorated_leaf: bool,
}

impl DiscoverCtx<'_> {
    /// Classify `s` (see [`Located`]).
    pub(crate) fn locate(&self, s: &str, opts: LocateOpts) -> Located {
        let vendored = match opts.grammar {
            LeafGrammar::Literal => vendor_ref(s),
            LeafGrammar::Decorated => vendor_ref_decorated(s),
        };
        let decorated_leaf = opts.decorated_check
            && opts.grammar == LeafGrammar::Literal
            && is_decorated_vendor_path(s);
        Located {
            vendored,
            hosted: self.hosted_uuid(s),
            decorated_leaf,
        }
    }
}

/// The Socket wiring a lock location carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Wired {
    Hosted(String),
    Vendored(VendorRef),
}

impl Wired {
    pub(crate) fn uuid(&self) -> &str {
        match self {
            Wired::Hosted(uuid) => uuid,
            Wired::Vendored(vref) => &vref.uuid,
        }
    }

    /// The same patch artifact: the same hosted uuid, or the same vendored
    /// artifact path.
    pub(crate) fn same_artifact(&self, other: &Wired) -> bool {
        match (self, other) {
            (Wired::Hosted(a), Wired::Hosted(b)) => a == b,
            (Wired::Vendored(a), Wired::Vendored(b)) => a.artifact_rel == b.artifact_rel,
            _ => false,
        }
    }
}

/// Whether `s` points into SOME `.socket/vendor/` tree, any anchoring
/// (backslashes folded) — a Socket-shaped string whose rejection is worth a
/// diagnostic (cargo `[patch]` paths, gem remotes, composer path dists,
/// maven repository urls).
pub(crate) fn names_vendor_dir(s: &str) -> bool {
    s.replace('\\', "/").contains(&format!("{VENDOR_DIR}/"))
}

/// [`names_vendor_dir`] that also folds JSON / TOML `\/` escapes (the pypi
/// readers).
pub(crate) fn mentions_vendor_dir(s: &str) -> bool {
    s.replace("\\/", "/")
        .replace('\\', "/")
        .contains(&format!("{VENDOR_DIR}/"))
}

/// Whether `s` STARTS at this project's `.socket/vendor/` after the `file:`
/// / `./` spellings [`vendor_ref_decorated`] accepts (yarn's rule; `\/` is
/// not folded).
pub(crate) fn root_anchored_spelling(s: &str) -> bool {
    let norm = s.trim().replace('\\', "/");
    let norm = norm.strip_prefix("file:").unwrap_or(&norm);
    let norm = norm.strip_prefix("./").unwrap_or(norm);
    norm.starts_with(&format!("{VENDOR_DIR}/"))
}

/// Whether vendored artifact `vref` is the npm tarball the vendor backends
/// write for `purl` (`[@scope/]<name>-<version>.tgz` in the npm vendor dir)
/// — the leaf rule the npm, pnpm and yarn extractors share.
pub(crate) fn npm_vendored_tarball_names(vref: &VendorRef, purl: &str) -> bool {
    vref.eco == "npm" && vendored_leaf_purl("npm", &vref.leaf).as_deref() == Some(purl)
}

/// Parse a JSON document read from root-relative `file`; `Err` carries the
/// diagnostic detail `"<file> is not valid JSON: <error>"`. No BOM handling:
/// the callers that tolerate one strip it first.
pub(crate) fn parse_json(file: &str, bytes: &[u8]) -> Result<serde_json::Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("{file} is not valid JSON: {e}"))
}

/// How [`toml_or_diag`] spells the parse error in its diagnostic (the goldens
/// pin each extractor's `detail` byte for byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TomlDiag {
    /// The error trailing whitespace trimmed (cargo).
    TrimEnd,
    /// The error as displayed (pypi locks).
    Raw,
    /// The error's lines trimmed and joined by spaces (the other pypi
    /// readers, whose caller strips a leading BOM first).
    BomFlattened,
}

/// Parse `text` as TOML, recording [`DIAG_LOCKFILE_UNPARSEABLE`] for
/// root-relative `file` (in `style`) on failure.
pub(crate) fn toml_or_diag(
    file: &str,
    text: &str,
    style: TomlDiag,
    out: &mut Discovery,
) -> Option<toml_edit::DocumentMut> {
    match text.parse::<toml_edit::DocumentMut>() {
        Ok(doc) => Some(doc),
        Err(e) => {
            let reason = match style {
                TomlDiag::TrimEnd => e.to_string().trim_end().to_string(),
                TomlDiag::Raw => e.to_string(),
                TomlDiag::BomFlattened => {
                    let reason = e.to_string();
                    let reason = reason.lines().map(str::trim).collect::<Vec<_>>().join(" ");
                    reason.trim().to_string()
                }
            };
            out.diag(
                DIAG_LOCKFILE_UNPARSEABLE,
                file,
                format!("{file} is not valid TOML: {reason}"),
            );
            None
        }
    }
}

// ── purl helpers ─────────────────────────────────────────────────────────

/// The comparison key for "the same package" across purl spellings:
/// qualifiers and subpath stripped, components percent-decoded, the type
/// lowercased, and the name folded where the ecosystem's own resolution is
/// insensitive — pypi (PEP 503: case + `-`/`_`/`.` runs), composer and
/// nuget (case). Used to match discovered refs against manifest / ledger
/// keys and API purls; it is also the form [`PatchedRef::purl`] carries.
/// Never used to build filesystem paths.
pub fn canonical_base_purl(purl: &str) -> String {
    let base = normalize_purl(strip_purl_qualifiers(purl.trim())).into_owned();
    let Some(rest) = base.strip_prefix("pkg:") else {
        return base;
    };
    let Some((ty, tail)) = rest.split_once('/') else {
        return base;
    };
    let ty = ty.to_ascii_lowercase();
    match ty.as_str() {
        "pypi" => match tail.rsplit_once('@') {
            Some((name, version)) => {
                format!("pkg:pypi/{}@{version}", canonicalize_pypi_name(name))
            }
            None => format!("pkg:pypi/{}", canonicalize_pypi_name(tail)),
        },
        "composer" | "nuget" => format!("pkg:{ty}/{}", tail.to_lowercase()),
        _ => format!("pkg:{ty}/{tail}"),
    }
}

/// [`canonical_base_purl`] for a ref about to be pushed, plus shape checks:
/// a known ecosystem type and a non-empty name and version (the version
/// after the LAST `@`, containing no `/`).
fn validated_ref_purl(purl: &str) -> Option<String> {
    let canonical = canonical_base_purl(purl);
    Ecosystem::from_purl(&canonical)?;
    let rest = canonical.strip_prefix("pkg:")?;
    let (_, name_version) = rest.split_once('/')?;
    let (name, version) = name_version.rsplit_once('@')?;
    if name.is_empty() || version.is_empty() || version.contains('/') {
        return None;
    }
    Some(canonical)
}

/// The validating purl builders of rule 6 — [`crate::utils::purl`]'s, the
/// same ones the lock inventory's registry views build their purls with.
pub use crate::utils::purl::{
    composer_purl, golang_purl, maven_purl, npm_purl, pypi_purl, simple_purl,
};

// ── ledger wiring-liveness proofs (used by the CLI) ──────────────────────

impl Discovery {
    /// Whether any discovered reference wires `purl` (any spelling) in
    /// `mode`, whichever patch it names.
    pub fn wires_package(&self, purl: &str, mode: WiringMode) -> bool {
        let key = canonical_base_purl(purl);
        self.refs.iter().any(|r| r.mode == mode && r.purl == key)
    }

    /// Liveness of a VENDOR-ledger entry — the ONE rule every reader of the
    /// vendor ledger applies (`vex`'s liveness gate, `scan`'s cross-mode
    /// takeover classifier). Discovery is AUTHORITATIVE for every uuid a
    /// file it read mentions ([`Discovery::vendored_claim`], rule 11): the
    /// entry is live only if a ref wires this package to this artifact — a
    /// mention an extractor rejected (an orphaned berry entry, an unbuilt
    /// cargo `[patch]`, a uv lock its pyproject does not confirm, …) or a
    /// section the package manager never reads is DEAD, and re-deriving
    /// liveness from that same raw text is exactly the stale-ledger false
    /// attestation the gate closes. Only a uuid no read file mentions (a
    /// format nothing reads) falls back to the ledger's recorded wiring
    /// files still naming the uuid dir (or, with none recorded, the
    /// ecosystem's root locks — [`vendored_wiring_live`]).
    pub async fn vendor_entry_live(&self, root: &Path, entry: &VendorEntry) -> bool {
        if let Some(live) = self.vendored_claim(&entry.base_purl, &entry.uuid, &entry.artifact.path)
        {
            return live;
        }
        // `repair`'s reconstructed entries record no wiring files; the
        // helper then probes the ecosystem's root locks rather than
        // concluding "unwired" from a missing record.
        let files: Vec<&str> = entry.wiring.iter().map(|w| w.file.as_str()).collect();
        vendored_wiring_live(root, &files, &entry.ecosystem, &entry.uuid).await
    }

    /// Liveness of a REDIRECT-ledger record (`purl` resolves from patch
    /// `uuid`) — the ONE rule every reader of the redirect ledger applies
    /// (`vex`'s liveness gate, `scan`'s takeover classifier and its
    /// hosted-wiring-retained advisory). Discovery is authoritative for a
    /// uuid any file it read mentions ([`Discovery::hosted_claim`] — an
    /// inert Go replace, a reverted cargo pin, a shadowed maven pin, a nuget
    /// source whose lock no longer restores the id are all dead however much
    /// text survives; a lockless pin, [`UnlockedPin`], is live); otherwise —
    /// hosts outside the discovery allowlist, formats no extractor reads —
    /// the ledger's own evidence decides, in order:
    ///
    /// 0. (gem only) a ledger-recorded Gemfile / `gems.rb` whose live
    ///    `source "<patch registry>" do` block still declares the gem
    ///    ([`gem::gemfile_source_block_pins`]): live — bundler re-resolves
    ///    from it whatever the lock says;
    /// 1. a lock inventory entry for this purl whose resolved url carries
    ///    the uuid: live;
    /// 2. a lock inventory entry that resolves the purl from somewhere ELSE
    ///    (a registry url, a crates.io-checksummed Cargo.lock source): dead
    ///    — the lock positively says the build fetches the unpatched
    ///    package, whatever leftover text still names the uuid;
    /// 3. a ledger-recorded edit file (`recorded_files`) still PINNING the
    ///    uuid ([`hosted_wiring_in_files`] ignores registry / index / source
    ///    definitions such as `.cargo/config.toml` `[registries]`, which
    ///    route nothing once the dependency pin is reverted, and reads a
    ///    Gemfile / `gems.rb` with discovery's source-block grammar).
    ///
    /// `inventory` is the project's EVERY-instance lock inventory
    /// ([`inventory_project_every_lock`] — step 2 is negative evidence, so a
    /// collapsed view that dropped the hosted instance must not feed it),
    /// loaded on first need and shared across calls.
    pub async fn redirect_record_live(
        &self,
        root: &Path,
        purl: &str,
        uuid: &str,
        recorded_files: &[&str],
        inventory: &mut Option<Vec<LockfileEntry>>,
    ) -> bool {
        if let Some(live) = self.hosted_claim(purl, uuid) {
            return live;
        }
        // Bundler resolves from the Gemfile / `gems.rb`: when a `source
        // "<patch registry>" do` block there still pins the uuid but the
        // lock says rubygems.org, `bundle install` re-resolves the gem to the
        // patch registry (and a frozen install refuses the pair) — the
        // registry lock entry is not what the build consumes. That mixed
        // pair is the bundler < 2.6 hosted rewriter's NORMAL output (it
        // cannot pin a CHECKSUMS-less lock and leaves the lock for the next
        // unfrozen install), so step 2 must not kill it. Checked only for
        // gem purls and only in the ledger's recorded bundler manifests,
        // with discovery's Gemfile grammar (a live `source` block declaring
        // THIS gem — a commented-out block or another gem's is not wiring);
        // step 3 then leaves those manifests alone.
        let mut recorded: Vec<&str> = recorded_files.to_vec();
        if let Some(gem_name) = gem_purl_name(purl) {
            let is_manifest = |f: &&str| matches!(*f, "Gemfile" | "gems.rb");
            let manifests: Vec<&str> = recorded.iter().copied().filter(is_manifest).collect();
            recorded.retain(|f| !is_manifest(f));
            for rel in unique_safe_rel_files(&manifests) {
                let Ok(text) = crate::utils::fs::read_regular_to_string(&root.join(&rel)).await
                else {
                    continue;
                };
                if gem::gemfile_source_block_pins(&text, uuid, Some(&gem_name)) {
                    return true;
                }
            }
        }
        if inventory.is_none() {
            *inventory = Some(inventory_project_every_lock(root).await);
        }
        // Every lock's entry for the purl: the every-instance inventory keeps
        // each lock's own entry (the collapsed one keeps ONE per package, so a
        // registry entry from a script lock or a Rush subspace lock could
        // hide the project lock's hosted entry and veto it in step 2), and
        // `lookup` alone would stop at the first.
        let entries: Vec<&LockfileEntry> = inventory
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|e| lookup(std::slice::from_ref(*e), purl).is_some())
            .collect();
        if entries
            .iter()
            .any(|e| e.resolved.as_deref().is_some_and(|r| r.contains(uuid)))
        {
            return true;
        }
        if entries.iter().any(|e| resolves_elsewhere(e)) {
            return false;
        }
        hosted_wiring_in_files(root, &recorded, uuid).await
    }
}

/// The gem name of a `pkg:gem/<name>@<version>` purl (any qualifiers).
fn gem_purl_name(purl: &str) -> Option<String> {
    let base = canonical_base_purl(purl);
    let rest = base.strip_prefix("pkg:gem/")?;
    let (name, _) = rest.rsplit_once('@')?;
    (!name.is_empty()).then(|| name.to_string())
}

/// The state every ledger-liveness caller shares for ONE project state:
/// the root, its [`Discovery`], the redirect ledger's recorded edit files
/// (sorted, deduplicated) and the lock inventory, loaded at most once and
/// only when a verdict first needs it. Callers ask it for verdicts; the rules
/// themselves are [`Discovery::redirect_record_live`] and
/// [`Discovery::vendor_entry_live`].
///
/// One holder per call-site invocation, built from the ledger the caller
/// judges (scan's takeover path passes its in-memory post-takeover ledger),
/// and never kept across a lockfile write: its discovery and inventory
/// describe one project state.
pub struct LedgerLiveness<'a> {
    root: &'a Path,
    discovery: &'a Discovery,
    redirect_files: Vec<&'a str>,
    inventory: Option<Vec<LockfileEntry>>,
}

impl<'a> LedgerLiveness<'a> {
    pub fn new(
        root: &'a Path,
        discovery: &'a Discovery,
        redirect: Option<&'a crate::patch::redirect::RedirectState>,
    ) -> Self {
        let mut redirect_files: Vec<&str> = redirect
            .map(|r| r.edits.iter().map(|e| e.path.as_str()).collect())
            .unwrap_or_default();
        redirect_files.sort();
        redirect_files.dedup();
        Self {
            root,
            discovery,
            redirect_files,
            inventory: None,
        }
    }

    /// [`Discovery::redirect_record_live`] for this project state.
    pub async fn redirect_record(&mut self, purl: &str, uuid: &str) -> bool {
        self.discovery
            .redirect_record_live(
                self.root,
                purl,
                uuid,
                &self.redirect_files,
                &mut self.inventory,
            )
            .await
    }

    /// [`Discovery::vendor_entry_live`] for this project state.
    pub async fn vendor_entry(&self, entry: &VendorEntry) -> bool {
        self.discovery.vendor_entry_live(self.root, entry).await
    }
}

/// A lock inventory entry (already known NOT to carry the patch uuid in its
/// resolved url) that positively resolves from a non-patch source: an
/// explicit artifact url, or a crates.io Cargo.lock source (the registry
/// view's [`SourceKind::CratesIo`]; Socket sparse sources carry no url in
/// the inventory and so prove nothing either way). An entry with no url is
/// the conventional registry for most formats but is also how the inventory
/// records hosted pypi / cargo entries whose uuid it drops — ambiguous, so
/// it proves nothing.
fn resolves_elsewhere(entry: &LockfileEntry) -> bool {
    entry.resolved.is_some()
        || (entry.ecosystem == "cargo" && entry.source_kind == SourceKind::CratesIo)
}

/// Whether any of `files` — the root-relative wiring files a VENDOR ledger
/// entry recorded editing — still references the entry's
/// `.socket/vendor/<eco>/<uuid>` dir. This is the fallback liveness proof
/// for ledger entries whose uuid NO file discovery read mentions
/// ([`Discovery::vendored_claim`] is `None` — rule 11); for a recognized
/// uuid the refs decide, because this raw-text match cannot tell a wiring
/// from a rejected or ignored mention. A vendored artifact left behind
/// after the lockfile was reverted must not keep attesting.
///
/// `bun.lockb` is read through its binary resolution records, never as text
/// — its append-only string pool can retain paths from earlier patch
/// generations. Ledger paths are tamper-able: absolute / `..` / empty names
/// are skipped, reads are FIFO-guarded, unreadable files prove nothing.
pub async fn vendored_wiring_in_files(root: &Path, files: &[&str], eco: &str, uuid: &str) -> bool {
    let Some(marker) = crate::vendor::path::vendor_uuid_dir_rel(eco, uuid) else {
        return false;
    };
    let escaped = marker.replace('/', "\\/");
    for file in unique_safe_rel_files(files) {
        if file == "bun.lockb" || file.ends_with("/bun.lockb") {
            if bun_lockb_resolutions(root, &file)
                .await
                .iter()
                .any(|resolution| {
                    crate::vendor::parse_vendor_path(resolution)
                        .is_some_and(|p| p.eco == eco && p.uuid == uuid)
                })
            {
                return true;
            }
            continue;
        }
        if let Ok(text) = crate::utils::fs::read_regular_to_string(&root.join(&file)).await {
            if text.contains(&marker) || text.contains(&escaped) {
                return true;
            }
        }
    }
    false
}

/// Liveness of a vendor-ledger entry by its recorded wiring — the fallback
/// for ledger entries no discovered reference covers. The entry's own
/// `wiring` files are authoritative when any of them still exists: a
/// recorded lockfile that no longer names `.socket/vendor/<eco>/<uuid>` was
/// reverted, and the leftover artifact must not keep attesting. When the
/// entry recorded NO wiring file that exists — `repair`'s ledger
/// reconstruction writes `wiring: []` for every ecosystem but gem, and an
/// older ledger may name a lock since renamed — the entry's ecosystem's
/// root lockfiles / wiring configs ([`vendored_wiring_probe_files`]) are
/// probed instead: absence of a wiring RECORD is not evidence the wiring is
/// gone.
pub async fn vendored_wiring_live(root: &Path, recorded: &[&str], eco: &str, uuid: &str) -> bool {
    if vendored_wiring_in_files(root, recorded, eco, uuid).await {
        return true;
    }
    let any_recorded_exists = unique_safe_rel_files(recorded)
        .iter()
        .any(|f| root.join(f).is_file());
    if any_recorded_exists {
        return false;
    }
    let probe = vendored_wiring_probe_files(root, eco);
    let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
    vendored_wiring_in_files(root, &probe, eco, uuid).await
}

/// The root files a vendored `eco` artifact can be wired from — every
/// vendor backend's lockfile / wiring config for that ecosystem (npm: all
/// five npm-family locks; cargo: the `[patch.crates-io]` config; maven /
/// nuget: the repository / source that serves the vendored dir). Manifests
/// such as package.json are deliberately absent: the lock is what the
/// install consumes.
pub fn vendored_wiring_probe_files(root: &Path, eco: &str) -> Vec<String> {
    let fixed: Vec<&str> = match eco {
        "npm" => crate::constants::npm_family::names_with(|r| r.vendor_probe),
        "pypi" => vec![
            "uv.lock",
            "poetry.lock",
            "pdm.lock",
            "Pipfile.lock",
            "requirements.txt",
            "pyproject.toml",
            "hatch.toml",
        ],
        "cargo" => vec![".cargo/config.toml", ".cargo/config"],
        "golang" => vec!["go.mod"],
        "gem" => vec!["Gemfile.lock"],
        "composer" => vec!["composer.lock"],
        "maven" => vec!["pom.xml"],
        "nuget" => crate::vendor::nuget_config::CONFIG_NAMES.to_vec(),
        _ => Vec::new(),
    };
    let mut files: Vec<String> = fixed.into_iter().map(str::to_string).collect();
    if eco == "pypi" {
        // pylock.toml / pylock.<name>.toml / *.py.lock.
        files.extend(crate::utils::python_lock::python_lock_paths(root).unwrap_or_default());
    }
    files
}

/// Whether any of `files` — the root-relative lockfiles a REDIRECT ledger
/// recorded editing — still PINS patch `uuid`'s hosted resolution. Fallback
/// liveness proof for hosted ledger records whose uuid no file discovery
/// read mentions ([`Discovery::hosted_claim`] is `None` — a format nothing
/// reads, a host outside the discovery allowlist); same guards as
/// [`vendored_wiring_in_files`].
///
/// A bare "the uuid occurs in the file" check is not enough, because the
/// hosted rewriters write the uuid into two kinds of place:
///
/// * a PIN that routes this package's resolution to the patch (a lockfile
///   url, a `Cargo.toml` `registry = "socket-patch-<U>"`, a go.mod
///   `replace`, a `name @ <url>` requirement), and
/// * a DEFINITION that routes nothing by itself (`.cargo/config.toml`
///   `[registries.socket-patch-<U>]`, a nuget.config `<packageSources>`
///   `<add key>`, a pom.xml `<repository>`, a pyproject index table,
///   `settings.xml`, go.sum hashes).
///
/// A definition left behind after the pin was reverted (the package resolves
/// from the public registry again) must not keep the ledger alive — that is
/// the stale-ledger `--no-verify` false attestation this gate exists to
/// close. So, per [`hosted_file_role`]: definition-only files never prove
/// anything; pom.xml needs the `-socket.<hex8>` dependency-version pin as
/// well as the full uuid; nuget.config counts only a `<packageSource>`
/// MAPPING element; pyproject/hatch.toml count only a PEP 508 `name @ url`
/// line; and in every file a uuid occurrence inside a committed
/// `.socket/vendor/<eco>/` path is the VENDORED wiring and proves the wrong
/// mode.
pub async fn hosted_wiring_in_files(root: &Path, files: &[&str], uuid: &str) -> bool {
    if !is_canonical_uuid(uuid) {
        return false;
    }
    for file in unique_safe_rel_files(files) {
        let role = hosted_file_role(&file);
        if role == HostedFileRole::DefinitionOnly {
            continue;
        }
        if file == "bun.lockb" || file.ends_with("/bun.lockb") {
            if bun_lockb_resolutions(root, &file)
                .await
                .iter()
                .any(|resolution| {
                    resolution.contains(uuid)
                        && crate::vendor::parse_vendor_path(resolution).is_none()
                })
            {
                return true;
            }
            continue;
        }
        let Ok(text) = crate::utils::fs::read_regular_to_string(&root.join(&file)).await else {
            continue;
        };
        if role == HostedFileRole::GemManifest {
            if gem::gemfile_source_block_pins(&text, uuid, None) {
                return true;
            }
            continue;
        }
        if role == HostedFileRole::Pom && !text.contains(&format!("-socket.{}", &uuid[..8])) {
            // The full uuid only ever appears in the `<repository>`
            // definition; the dependency pin is the version suffix.
            continue;
        }
        let mut from = 0;
        while let Some(pos) = text[from..].find(uuid) {
            let idx = from + pos;
            if !preceded_by_vendor_dir(&text[..idx]) && role.occurrence_pins(&text, idx) {
                return true;
            }
            from = idx + uuid.len();
        }
    }
    false
}

/// How [`hosted_wiring_in_files`] reads one ledger-recorded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedFileRole {
    /// Registry / index / source definitions and integrity side files: they
    /// name the uuid but pin no package's resolution.
    DefinitionOnly,
    /// `pom.xml`: `<repository>` definition + `-socket.<hex8>` version pin.
    Pom,
    /// `nuget.config`: `<add key>` definition + `<packageSource>` mapping.
    NugetConfig,
    /// `pyproject.toml` / `hatch.toml`: index tables + direct references.
    PyProject,
    /// `Gemfile` / `gems.rb`: Ruby source, read with discovery's
    /// source-block grammar ([`gem::gemfile_source_block_pins`]) — comments
    /// and non-block text are not pins.
    GemManifest,
    /// Lockfiles and manifests whose uuid occurrences are pins.
    Pin,
}

impl HostedFileRole {
    /// Does the uuid occurrence at byte `idx` of `text` sit in a pin?
    fn occurrence_pins(self, text: &str, idx: usize) -> bool {
        match self {
            HostedFileRole::DefinitionOnly => false,
            HostedFileRole::Pom | HostedFileRole::Pin => true,
            // Judged whole-file in `hosted_wiring_in_files`.
            HostedFileRole::GemManifest => false,
            // The innermost open tag must be a mapping `<packageSource …>`
            // (not `<packageSources>`, not `<add …>`).
            HostedFileRole::NugetConfig => text[..idx].rfind('<').is_some_and(|lt| {
                let tag = &text[lt + 1..idx];
                tag.strip_prefix("packageSource")
                    .is_some_and(|rest| rest.starts_with(char::is_whitespace))
            }),
            HostedFileRole::PyProject => {
                let start = text[..idx].rfind('\n').map_or(0, |i| i + 1);
                text[start..idx].contains(" @ ")
            }
        }
    }
}

/// Classify a root-relative ledger path (see [`HostedFileRole`]).
fn hosted_file_role(rel: &str) -> HostedFileRole {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let lower = base.to_ascii_lowercase();
    let definition_only = rel == ".cargo/config.toml"
        || rel == ".cargo/config"
        || rel.starts_with(".mvn/")
        || matches!(
            lower.as_str(),
            ".npmrc"
                | ".yarnrc"
                | ".yarnrc.yml"
                | "pnpm-workspace.yaml"
                | "bunfig.toml"
                | "settings.xml"
                | "go.sum"
                | "go.work.sum"
        );
    // Deno has no hosted rewriter: no writer ever records `deno.lock` /
    // `deno.json(c)`, and a Socket url in them is the user's own import
    // (`remote` / `npm` tarball entries), never a pin routing a patch — so a
    // (forged or foreign) ledger naming them proves nothing, like a
    // definition.
    let never_wired = matches!(lower.as_str(), "deno.lock" | "deno.json" | "deno.jsonc");
    if definition_only || never_wired {
        HostedFileRole::DefinitionOnly
    } else if lower == "pom.xml" {
        HostedFileRole::Pom
    } else if lower == "nuget.config" {
        HostedFileRole::NugetConfig
    } else if lower == "pyproject.toml" || lower == "hatch.toml" {
        HostedFileRole::PyProject
    } else if matches!(base, "Gemfile" | "gems.rb") {
        HostedFileRole::GemManifest
    } else {
        HostedFileRole::Pin
    }
}

/// Does `head` (the text before a uuid occurrence) end with a
/// `.socket/vendor/<eco>/` level (or its `\/`-escaped spelling)?
fn preceded_by_vendor_dir(head: &str) -> bool {
    let tail_start = head
        .char_indices()
        .rev()
        .nth(47)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let tail = head[tail_start..].replace("\\/", "/").replace('\\', "/");
    ECOSYSTEM_DIRS
        .iter()
        .any(|eco| tail.ends_with(&format!("{VENDOR_DIR}/{eco}/")))
}

/// Resolution strings of a `bun.lockb`'s active package records (empty on
/// any read/parse failure — which proves nothing).
async fn bun_lockb_resolutions(root: &Path, rel: &str) -> Vec<String> {
    let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&root.join(rel)).await else {
        return Vec::new();
    };
    crate::vendor::bun_lockb::BunLockb::parse_packages(&bytes)
        .map(|packages| packages.into_iter().map(|p| p.resolution).collect())
        .unwrap_or_default()
}

/// De-duplicated, traversal-safe, root-relative file names from a ledger.
fn unique_safe_rel_files(files: &[&str]) -> Vec<String> {
    let set: BTreeSet<String> = files
        .iter()
        .map(|f| f.replace('\\', "/"))
        .filter(|f| {
            !f.is_empty()
                && !f.starts_with('/')
                && !f.contains(':')
                && !f.contains('\0')
                && f.split('/').all(|seg| !seg.is_empty() && seg != "..")
        })
        .collect();
    set.into_iter().collect()
}

// ── shared test helpers ──────────────────────────────────────────────────

/// Helpers every extractor's unit tests share (see rule 9 of the module
/// docs). Typical use:
///
/// ```ignore
/// use crate::vex::discover::testing::*;
/// use crate::vex::discover::*;
///
/// #[tokio::test]
/// async fn hosted_entry_is_discovered() {
///     let p = Project::new();
///     p.write("package-lock.json", lock_text);
///     // Just this extractor (the closure boxes its future):
///     let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
///     assert_refs(&out, &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)]);
/// }
/// ```
#[cfg(test)]
pub(crate) mod testing {
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;

    use super::{DiscoverCtx, Discovery, Recognized, WiringMode};

    /// Canonical patch uuids for fixtures.
    pub(crate) const UUID_A: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    pub(crate) const UUID_B: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    /// A uuid-SHAPED grant token: the last-uuid-segment rule must still pick
    /// the patch uuid after it.
    pub(crate) const TOKEN: &str = "11111111-2222-4333-8444-555555555555";

    /// Production artifact-URL shape on Socket's patch server
    /// (`…/patch/<eco>/<name>/<version>/<token>/<uuid>/<leaf>`).
    pub(crate) fn hosted_url(
        eco: &str,
        name: &str,
        version: &str,
        uuid: &str,
        leaf: &str,
    ) -> String {
        format!("https://patch.socket.dev/patch/{eco}/{name}/{version}/{TOKEN}/{uuid}/{leaf}")
    }

    /// Absolute path of a committed fixture under `crates/socket-patch-core/tests/fixtures/`.
    pub(crate) fn fixture_path(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel)
    }

    /// Boxed-future shape of an extractor, so tests can hand
    /// `super::extract` to [`Project::run`].
    pub(crate) type ExtractFn = for<'a> fn(
        &'a DiscoverCtx<'a>,
        &'a mut Discovery,
    ) -> Pin<Box<dyn Future<Output = ()> + 'a>>;

    /// A throwaway project root.
    pub(crate) struct Project {
        dir: tempfile::TempDir,
        origins: Vec<String>,
    }

    impl Project {
        pub(crate) fn new() -> Self {
            Project {
                dir: tempfile::tempdir().expect("create tempdir"),
                origins: Vec::new(),
            }
        }

        /// Also accept `origin` (e.g. `http://127.0.0.1:4545`) as a hosted
        /// patch-server origin, like `--patch-server-url`.
        pub(crate) fn with_origin(mut self, origin: &str) -> Self {
            self.origins.push(origin.to_string());
            self
        }

        pub(crate) fn root(&self) -> &Path {
            self.dir.path()
        }

        /// Write `content` at root-relative `rel`, creating parents.
        pub(crate) fn write(&self, rel: &str, content: impl AsRef<[u8]>) -> &Self {
            let path = self.root().join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create fixture parent");
            }
            std::fs::write(&path, content).expect("write fixture file");
            self
        }

        /// Copy every file under committed fixture dir `rel` (e.g.
        /// `redirect/npm/package-lock-v3/basic/expected`) into the root,
        /// preserving relative paths.
        pub(crate) fn copy_fixture(&self, rel: &str) -> &Self {
            let src = fixture_path(rel);
            let mut stack = vec![src.clone()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).expect("read fixture dir") {
                    let entry = entry.expect("fixture dir entry");
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        let rel_path = path.strip_prefix(&src).expect("fixture-relative path");
                        let dest = self.root().join(rel_path);
                        if let Some(parent) = dest.parent() {
                            std::fs::create_dir_all(parent).expect("create fixture parent");
                        }
                        std::fs::copy(&path, &dest).expect("copy fixture file");
                    }
                }
            }
            self
        }

        /// The context an extractor receives for this project.
        pub(crate) fn ctx(&self) -> DiscoverCtx<'_> {
            DiscoverCtx::with_origins(self.root(), &self.origins)
        }

        /// Run ONE extractor (`p.run(|c, o| Box::pin(super::extract(c, o)))`),
        /// collecting its reads' recognition like the orchestrator does.
        pub(crate) async fn run(&self, extract: ExtractFn) -> Discovery {
            let ctx = self.ctx();
            let mut out = Discovery::default();
            extract(&ctx, &mut out).await;
            let swept = ctx.take_recognized();
            assert_recognition_covers_refs(&out, &swept, "the ctx sweep", Some(self.root()));
            out.recognized.extend(swept);
            out.finalize();
            out
        }

        /// Run the full orchestrator.
        pub(crate) async fn discover(&self) -> Discovery {
            let out = super::discover_patched_refs_with(
                self.root(),
                &super::DiscoverOptions {
                    patch_server_origins: self.origins.clone(),
                },
            )
            .await;
            assert_recognition_covers_refs(&out, &out.recognized, "`recognized`", None);
            out
        }
    }

    /// Rule 11's invariant: every emitted ref's `(uuid, mode)` is among the
    /// identities `recognized` holds — for [`Project::run`], the ctx sweep
    /// of the files the extractor READ (plus the paired names it
    /// recognized), so an extractor that accepts an identity the sweep
    /// cannot see (a decoding the sweep lacks) fails here. The one
    /// exception is rule 4's host-independent `socket-patch-[vendor-]<uuid>`
    /// NAME, which is never swept and counts through the ref itself: with
    /// `root`, a ref whose source file spells that name is accepted.
    pub(crate) fn assert_recognition_covers_refs(
        out: &Discovery,
        recognized: &[Recognized],
        what: &str,
        root: Option<&Path>,
    ) {
        for r in &out.refs {
            let named = root.is_some_and(|root| {
                std::fs::read_to_string(root.join(&r.source_file)).is_ok_and(|text| {
                    text.contains(&format!("socket-patch-{}", r.uuid))
                        || text.contains(&format!("socket-patch-vendor-{}", r.uuid))
                })
            });
            assert!(
                named
                    || recognized
                        .iter()
                        .any(|rec| rec.uuid == r.uuid && rec.mode == r.mode),
                "ref {} ({:?}, from {}) is not recognized by {what}: {recognized:#?}",
                r.purl,
                r.mode,
                r.source_file.display()
            );
        }
    }

    /// `(purl, uuid, mode)` triples, sorted and deduped.
    pub(crate) fn ref_triples(out: &Discovery) -> Vec<(String, String, WiringMode)> {
        let mut triples: Vec<_> = out
            .refs
            .iter()
            .map(|r| (r.purl.clone(), r.uuid.clone(), r.mode))
            .collect();
        triples.sort();
        triples.dedup();
        triples
    }

    /// Assert the discovered `(purl, uuid, mode)` set equals `expected`
    /// (order-insensitive), printing refs + diagnostics on failure.
    pub(crate) fn assert_refs(out: &Discovery, expected: &[(&str, &str, WiringMode)]) {
        let mut want: Vec<(String, String, WiringMode)> = expected
            .iter()
            .map(|(p, u, m)| (p.to_string(), u.to_string(), *m))
            .collect();
        want.sort();
        want.dedup();
        assert_eq!(
            ref_triples(out),
            want,
            "refs: {:#?}\ndiagnostics: {:#?}",
            out.refs,
            out.diagnostics
        );
    }

    /// The diagnostic codes recorded, sorted.
    pub(crate) fn diag_codes(out: &Discovery) -> Vec<&'static str> {
        let mut codes: Vec<_> = out.diagnostics.iter().map(|d| d.code).collect();
        codes.sort();
        codes
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn vendor_ref_strips_lock_suffixes_and_requires_a_root_anchor() {
        let a = UUID_A;
        for spelled in [
            format!("file:.socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!("file:./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!("./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!(".socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!(".socket\\vendor\\npm\\{a}\\left-pad-1.3.0.tgz"),
            format!(".socket\\/vendor\\/npm\\/{a}\\/left-pad-1.3.0.tgz"),
            // yarn classic `#<sha1>`, berry fragment + locator, pip `#sha256=`.
            format!("file:./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz#0123abcd"),
            format!(
                "./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz#./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz::hash=abc123&locator=app%40workspace%3A."
            ),
            format!("./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz::locator=app%40workspace%3A."),
        ] {
            let decorated = spelled.contains('#') || spelled.contains("::");
            // The literal-path reader refuses a decorated leaf outright: to
            // npm / pnpm / bun / … it names a DIFFERENT file.
            assert_eq!(vendor_ref(&spelled).is_none(), decorated, "{spelled}");
            let v = vendor_ref_decorated(&spelled).unwrap_or_else(|| panic!("{spelled}"));
            assert_eq!(v.eco, "npm", "{spelled}");
            assert_eq!(v.uuid, a, "{spelled}");
            assert_eq!(v.leaf, "left-pad-1.3.0.tgz", "{spelled}");
            assert_eq!(
                v.artifact_rel,
                format!(".socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
                "{spelled}"
            );
        }
        // Dir-shaped leaves keep their nesting, trailing slash dropped.
        let v = vendor_ref(&format!(
            "./.socket/vendor/golang/{a}/github.com/foo/bar@v1.2.3/"
        ))
        .unwrap();
        assert_eq!(v.leaf, "github.com/foo/bar@v1.2.3");
    }

    #[test]
    fn vendor_ref_rejects_escapes_foreign_anchors_and_bad_uuids() {
        let a = UUID_A;
        for bad in [
            // The package manager would read OUTSIDE the project root.
            format!("../.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("file:../.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("/abs/project/.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("sub/.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            // Traversal inside the leaf.
            format!(".socket/vendor/npm/{a}/../../../etc/passwd"),
            format!(".socket/vendor/npm/{a}/a//b.tgz"),
            // No leaf / uuid-dir only / unknown eco / non-canonical uuid.
            format!(".socket/vendor/npm/{a}"),
            format!(".socket/vendor/npm/{a}/"),
            format!(".socket/vendor/jsr/{a}/x-1.0.0.tgz"),
            format!(".socket/vendor/npm/{}/x-1.0.0.tgz", a.to_ascii_uppercase()),
            ".socket/vendor/npm/not-a-uuid/x-1.0.0.tgz".to_string(),
            "https://registry.npmjs.org/x/-/x-1.0.0.tgz".to_string(),
        ] {
            assert_eq!(vendor_ref(&bad), None, "{bad}");
        }
    }

    #[test]
    fn vendor_uuid_dir_accepts_only_the_bare_uuid_dir() {
        let a = UUID_A;
        assert_eq!(
            vendor_uuid_dir(&format!(".socket/vendor/nuget/{a}")),
            Some(("nuget".to_string(), a.to_string()))
        );
        assert_eq!(
            vendor_uuid_dir(&format!("./.socket/vendor/maven/{a}/")),
            Some(("maven".to_string(), a.to_string()))
        );
        assert_eq!(
            vendor_uuid_dir(&format!(".socket/vendor/nuget/{a}/x.nupkg")),
            None
        );
        assert_eq!(
            vendor_uuid_dir(&format!("../.socket/vendor/nuget/{a}")),
            None
        );
        assert_eq!(vendor_uuid_dir(".socket/vendor/nuget/nope"), None);
    }

    #[test]
    fn vendored_leaf_purl_strips_and_canonicalizes() {
        assert_eq!(
            vendored_leaf_purl("npm", "@scope/pkg-1.2.3.tgz#deadbeef").as_deref(),
            Some("pkg:npm/@scope/pkg@1.2.3")
        );
        assert_eq!(
            vendored_leaf_purl(
                "pypi",
                "Python_Dateutil-2.8.2-py2.py3-none-any.whl#sha256=ab"
            )
            .as_deref(),
            Some("pkg:pypi/python-dateutil@2.8.2")
        );
        assert_eq!(
            vendored_leaf_purl("cargo", "serde-1.0.0/").as_deref(),
            Some("pkg:cargo/serde@1.0.0")
        );
        assert_eq!(vendored_leaf_purl("npm", "not-a-tarball"), None);
    }

    #[test]
    fn canonical_base_purl_folds_only_insensitive_ecosystems() {
        assert_eq!(
            canonical_base_purl("pkg:pypi/Python_Dateutil@2.8.2?artifact_id=py3-none-any-whl"),
            "pkg:pypi/python-dateutil@2.8.2"
        );
        assert_eq!(
            canonical_base_purl("pkg:npm/%40scope/Name@1.0.0"),
            "pkg:npm/@scope/Name@1.0.0",
            "npm is case-sensitive; only percent-decoding applies"
        );
        assert_eq!(
            canonical_base_purl("pkg:nuget/Newtonsoft.Json@13.0.1"),
            "pkg:nuget/newtonsoft.json@13.0.1"
        );
        assert_eq!(
            canonical_base_purl("pkg:composer/Monolog/Monolog@2.0.0"),
            "pkg:composer/monolog/monolog@2.0.0"
        );
        assert_eq!(
            canonical_base_purl("pkg:gem/nokogiri@1.16.5?platform=java"),
            "pkg:gem/nokogiri@1.16.5"
        );
        assert_eq!(
            canonical_base_purl("pkg:golang/github.com/Foo/bar@v1.0.0#sub/dir"),
            "pkg:golang/github.com/Foo/bar@v1.0.0"
        );
    }

    #[test]
    fn socket_patch_names_are_exact() {
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-{UUID_A}"), false).as_deref(),
            Some(UUID_A)
        );
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-vendor-{UUID_A}"), true).as_deref(),
            Some(UUID_A)
        );
        // The hosted grammar never matches the vendored id and vice versa.
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-vendor-{UUID_A}"), false),
            None
        );
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-{UUID_A}"), true),
            None
        );
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-{UUID_A}-x"), false),
            None
        );
        assert_eq!(socket_patch_name_uuid("socket-patch-nope", false), None);
    }

    #[test]
    fn push_validates_canonicalizes_and_dedupes() {
        let mut out = Discovery::default();
        let url = hosted_url(
            "pypi",
            "six",
            "1.16.0",
            UUID_A,
            "six-1.16.0-py3-none-any.whl",
        );
        let hosted = PatchedRef::hosted(
            "pkg:pypi/Six@1.16.0?artifact_id=x".to_string(),
            UUID_A.to_string(),
            "uv.lock",
            Some(&url),
            Some(LockIntegrity::None),
            true,
        );
        out.push(hosted.clone());
        out.push(hosted);
        assert_eq!(out.refs.len(), 1, "exact duplicates collapse");
        assert_eq!(out.refs[0].purl, "pkg:pypi/six@1.16.0");
        assert_eq!(
            out.refs[0].locked_integrity, None,
            "LockIntegrity::None normalizes"
        );
        assert!(!out.refs[0].lockfile_basis_ok(), "required pin missing");

        // Non-canonical uuid / unusable purl / vendored path under another
        // uuid or ecosystem: dropped with a diagnostic.
        out.push(PatchedRef::hosted(
            "pkg:npm/x@1.0.0".into(),
            "not-a-uuid".into(),
            "package-lock.json",
            None,
            None,
            false,
        ));
        out.push(PatchedRef::hosted(
            "pkg:npm/x".into(),
            UUID_A.into(),
            "package-lock.json",
            None,
            None,
            false,
        ));
        let vref = vendor_ref(&format!(".socket/vendor/npm/{UUID_B}/x-1.0.0.tgz")).unwrap();
        let mut wrong_uuid =
            PatchedRef::vendored("pkg:npm/x@1.0.0".into(), &vref, "package-lock.json", None);
        wrong_uuid.uuid = UUID_A.to_string();
        out.push(wrong_uuid);
        out.push(PatchedRef::vendored(
            "pkg:cargo/x@1.0.0".into(),
            &vref,
            "Cargo.lock",
            None,
        ));
        assert_eq!(out.refs.len(), 1);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID; 4]);

        // A valid vendored ref lands.
        out.push(PatchedRef::vendored(
            "pkg:npm/x@1.0.0".into(),
            &vref,
            "package-lock.json",
            None,
        ));
        assert!(out.wires("pkg:npm/x@1.0.0", UUID_B, WiringMode::Vendored));
        assert!(!out.wires("pkg:npm/x@1.0.0", UUID_B, WiringMode::Hosted));
        assert_eq!(out.refs.iter().filter(|r| r.uuid == UUID_B).count(), 1);
    }

    /// Discovery and the lock inventory share ONE SRI-pin rule
    /// (`utils::digest::is_sri_pin`): an integrity string in an algorithm no
    /// package manager verifies (`sha-x`, `shaXYZ-…`) is not a pin anywhere,
    /// so it can never open the pinned lockfile basis.
    #[tokio::test]
    async fn only_supported_sri_algorithms_are_lockfile_pins() {
        for (integrity, pinned) in [
            ("sha512-abc", true),
            ("sha1-abc sha512-def", true),
            ("sha-abc", false),
            ("shaXYZ-abc", false),
            ("sha512-", false),
        ] {
            let p = Project::new();
            let url = hosted_url("npm", "x", "1.0.0", UUID_A, "x-1.0.0.tgz");
            p.write(
                "package-lock.json",
                serde_json::json!({
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "app"},
                        "node_modules/x": {
                            "version": "1.0.0",
                            "resolved": url,
                            "integrity": integrity,
                        }
                    }
                })
                .to_string(),
            );
            let out = p.discover().await;
            assert_eq!(out.refs.len(), 1, "{integrity}: {:?}", out.diagnostics);
            assert_eq!(
                out.refs[0].locked_integrity.is_some(),
                pinned,
                "{integrity}"
            );
            assert_eq!(out.refs[0].lockfile_basis_ok(), pinned, "{integrity}");
            assert_eq!(
                crate::utils::digest::is_sri_pin(integrity),
                pinned,
                "{integrity}"
            );
        }
    }

    #[test]
    fn lockfile_basis_needs_a_pin_only_where_the_format_always_writes_one() {
        let pinned = PatchedRef::hosted(
            "pkg:npm/x@1.0.0".into(),
            UUID_A.into(),
            "package-lock.json",
            None,
            Some(LockIntegrity::Sri("sha512-abc".into())),
            true,
        );
        assert!(pinned.lockfile_basis_ok());
        let unpinned_format = PatchedRef {
            locked_integrity: None,
            integrity_required: false,
            ..pinned.clone()
        };
        assert!(unpinned_format.lockfile_basis_ok());
        let stripped_pin = PatchedRef {
            locked_integrity: None,
            ..pinned
        };
        assert!(!stripped_pin.lockfile_basis_ok());
    }

    /// REGRESSION: step 2's negative evidence reads EVERY lock's instance.
    /// `uv.lock` routes six to a hosted wheel on a patch host outside the
    /// discovery allowlist (no `hosted_claim`), and a PEP 723 script lock
    /// that sorts first resolves the same six from PyPI. The collapsed
    /// inventory keeps only the script lock's instance, which made the
    /// record look resolved-elsewhere (dead) although the project lock still
    /// installs the patch.
    #[tokio::test]
    async fn a_script_lock_registry_instance_does_not_veto_the_hosted_project_lock() {
        let p = Project::new();
        let url = format!(
            "https://patches.internal.example/patch/pypi/six/1.16.0/g/{UUID_A}/\
             six-1.16.0-py3-none-any.whl"
        );
        p.write(
            "pyproject.toml",
            format!(
                "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"six @ {url}\"]\n"
            ),
        );
        let wheel_sha = "b".repeat(64);
        p.write(
            "uv.lock",
            format!(
                "version = 1\nrequires-python = \">=3.9\"\n\n\
                 [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 source = {{ virtual = \".\" }}\ndependencies = [{{ name = \"six\" }}]\n\n\
                 [[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\
                 source = {{ url = \"{url}\" }}\n\
                 wheels = [{{ url = \"{url}\", hash = \"sha256:{wheel_sha}\" }}]\n"
            ),
        );
        p.write(
            "tool.py",
            "# /// script\n# dependencies = [\"six==1.16.0\"]\n# ///\n",
        );
        let registry_sha = "a".repeat(64);
        p.write(
            "tool.py.lock",
            format!(
                "version = 1\nrequires-python = \">=3.9\"\n\n\
                 [[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\
                 source = {{ registry = \"https://pypi.org/simple\" }}\n\
                 wheels = [{{ url = \"https://files.pythonhosted.org/packages/\
                 six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{registry_sha}\" }}]\n"
            ),
        );
        let root = p.root();
        let purl = "pkg:pypi/six@1.16.0";
        // The collapsed view hides the hosted instance …
        let collapsed = crate::vendor::lock_inventory::inventory_project(root).await;
        let six: Vec<_> = collapsed.iter().filter(|e| e.purl == purl).collect();
        assert_eq!(six.len(), 1);
        assert!(!six[0].resolved.as_deref().unwrap_or("").contains(UUID_A));
        // … the every-instance view keeps both.
        let every = inventory_project_every_lock(root).await;
        assert_eq!(every.iter().filter(|e| e.purl == purl).count(), 2);

        let discovery = discover_patched_refs(root).await;
        assert_eq!(
            discovery.hosted_claim(purl, UUID_A),
            None,
            "host not allowlisted"
        );
        let mut inventory = None;
        assert!(
            discovery
                .redirect_record_live(root, purl, UUID_A, &["uv.lock"], &mut inventory)
                .await,
            "uv.lock still installs the patch"
        );

        // Control: with the project lock itself resolving from PyPI, the
        // registry instance IS the evidence — dead.
        std::fs::remove_file(root.join("uv.lock")).unwrap();
        let mut inventory = None;
        assert!(
            !discovery
                .redirect_record_live(root, purl, UUID_A, &["uv.lock"], &mut inventory)
                .await
        );
    }

    /// REGRESSION: step 0 reads a recorded Gemfile with discovery's
    /// source-block grammar. The lock resolves rails from rubygems.org and
    /// the patch host is outside the allowlist (no `hosted_claim`); only a
    /// LIVE `source "<patch registry>" do` block declaring rails keeps the
    /// record alive — the uuid in a `#` comment, inside `=begin` … `=end`,
    /// or in a block for another gem used to (a raw substring scan).
    #[tokio::test]
    async fn gemfile_liveness_reads_live_source_blocks_only() {
        let index = format!("https://patches.example.com/patch-registry/gem/{TOKEN}/{UUID_A}/");
        let p = Project::new();
        p.write(
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n",
        );
        let root = p.root();
        let purl = "pkg:gem/rails@7.0.0";
        let discovery = discover_patched_refs(root).await;
        assert_eq!(discovery.hosted_claim(purl, UUID_A), None);
        for (gemfile, live) in [
            (String::new(), false),
            (
                format!("source \"https://rubygems.org\"\n# source \"{index}\" do\n#   gem \"rails\"\n# end\n"),
                false,
            ),
            (
                format!("source \"https://rubygems.org\"\n=begin\nsource \"{index}\" do\n  gem \"rails\"\nend\n=end\n"),
                false,
            ),
            (
                format!("source \"{index}\" do\n  gem \"tiny-dep\"\nend\ngem \"rails\"\n"),
                false,
            ),
            (
                format!("source \"https://rubygems.org\"\nsource \"{index}\" do\n  gem \"rails\", \"7.0.0\"\nend\n"),
                true,
            ),
        ] {
            p.write("Gemfile", &gemfile);
            let mut inventory = None;
            assert_eq!(
                discovery
                    .redirect_record_live(root, purl, UUID_A, &["Gemfile", "Gemfile.lock"], &mut inventory)
                    .await,
                live,
                "{gemfile}"
            );
            // The ledger text fallback reads a Gemfile with the same grammar.
            assert_eq!(
                hosted_wiring_in_files(root, &["Gemfile"], UUID_A).await,
                live || gemfile.contains("tiny-dep"),
                "{gemfile}"
            );
        }
    }

    #[tokio::test]
    async fn vendored_ledger_proof_reads_only_safe_recorded_files() {
        let p = Project::new();
        let marker = format!(".socket/vendor/npm/{UUID_A}/x-1.0.0.tgz");
        p.write(
            "package-lock.json",
            format!("{{\"resolved\":\"file:{marker}\"}}"),
        );
        p.write("composer.lock", marker.replace('/', "\\/"));
        let root = p.root();
        assert!(vendored_wiring_in_files(root, &["package-lock.json"], "npm", UUID_A).await);
        assert!(
            vendored_wiring_in_files(root, &["composer.lock"], "npm", UUID_A).await,
            "`\\/`-escaped spelling counts"
        );
        assert!(!vendored_wiring_in_files(root, &["package-lock.json"], "npm", UUID_B).await);
        assert!(!vendored_wiring_in_files(root, &["package-lock.json"], "cargo", UUID_A).await);
        assert!(!vendored_wiring_in_files(root, &["missing.lock"], "npm", UUID_A).await);
        // Tampered ledger paths are never followed.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("evil.lock"), &marker).unwrap();
        let escape = format!(
            "../{}/evil.lock",
            outside.path().file_name().unwrap().to_string_lossy()
        );
        assert!(!vendored_wiring_in_files(root, &[escape.as_str()], "npm", UUID_A).await);
        let absolute = outside
            .path()
            .join("evil.lock")
            .to_string_lossy()
            .into_owned();
        assert!(!vendored_wiring_in_files(root, &[absolute.as_str()], "npm", UUID_A).await);
    }

    #[tokio::test]
    async fn hosted_ledger_proof_ignores_vendored_path_occurrences() {
        let p = Project::new();
        let hosted = hosted_url("npm", "x", "1.0.0", UUID_A, "x-1.0.0.tgz");
        p.write(
            "package-lock.json",
            format!("{{\"resolved\":\"{hosted}\"}}"),
        );
        p.write(
            "yarn.lock",
            format!("resolved \"file:./.socket/vendor/npm/{UUID_B}/x-1.0.0.tgz#abc\"\n"),
        );
        let root = p.root();
        assert!(hosted_wiring_in_files(root, &["package-lock.json"], UUID_A).await);
        assert!(
            !hosted_wiring_in_files(root, &["yarn.lock"], UUID_B).await,
            "the vendored wiring embeds the uuid too — it proves the WRONG mode"
        );
        assert!(!hosted_wiring_in_files(root, &["package-lock.json"], UUID_B).await);
        assert!(!hosted_wiring_in_files(root, &["package-lock.json"], "not-a-uuid").await);
    }

    /// [`LedgerLiveness`]: the redirect ledger's edit files are sorted and
    /// deduplicated, verdicts are the [`Discovery`] rule's, and the lock
    /// inventory loads only when a verdict first needs it and then once per
    /// holder — a lock write after that is invisible to it, which is why a
    /// holder must never outlive the project state it was built for.
    #[tokio::test]
    async fn ledger_liveness_shares_one_lazily_loaded_inventory() {
        let p = Project::new();
        let hosted = hosted_url("npm", "x", "1.0.0", UUID_A, "x-1.0.0.tgz");
        p.write(
            "package-lock.json",
            format!(
                r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/x":{{"version":"1.0.0","resolved":"{hosted}"}}}}}}"#
            ),
        );
        let root = p.root();
        let mut redirect = crate::patch::redirect::RedirectState::new();
        for path in ["package-lock.json", ".npmrc", "package-lock.json"] {
            redirect.edits.push(crate::patch::redirect::FileEdit {
                path: path.to_string(),
                kind: "redirect_npm_lock".to_string(),
                action: "rewritten".to_string(),
                key: None,
                original: None,
                new: None,
            });
        }
        let discovery = Discovery::default();
        let purl = "pkg:npm/x@1.0.0";

        let mut liveness = LedgerLiveness::new(root, &discovery, Some(&redirect));
        assert_eq!(liveness.redirect_files, [".npmrc", "package-lock.json"]);
        assert!(liveness.inventory.is_none(), "nothing loads up front");

        let mut rule_inventory = None;
        let rule = discovery
            .redirect_record_live(
                root,
                purl,
                UUID_A,
                &[".npmrc", "package-lock.json"],
                &mut rule_inventory,
            )
            .await;
        assert!(rule, "the lock's resolved url carries the uuid");
        assert_eq!(liveness.redirect_record(purl, UUID_A).await, rule);
        assert!(liveness.inventory.is_some());
        assert_eq!(
            format!("{:?}", liveness.inventory),
            format!("{rule_inventory:?}")
        );

        std::fs::remove_file(root.join("package-lock.json")).unwrap();
        assert!(
            liveness.redirect_record(purl, UUID_A).await,
            "the holder keeps the inventory it loaded"
        );
        assert!(
            !LedgerLiveness::new(root, &discovery, Some(&redirect))
                .redirect_record(purl, UUID_A)
                .await,
            "a fresh holder reads the new project state"
        );
        assert!(LedgerLiveness::new(root, &discovery, None)
            .redirect_files
            .is_empty());
    }

    /// REGRESSION: a registry / index / source DEFINITION left behind after
    /// the dependency pin was reverted names the uuid but routes nothing, so
    /// it must not keep a hosted ledger record alive (the stale-ledger
    /// `--no-verify` false attestation). Pins still count.
    #[tokio::test]
    async fn hosted_ledger_proof_ignores_definition_only_occurrences() {
        let p = Project::new();
        let a = UUID_A;
        let hex8 = &a[..8];
        let index = format!("https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{a}/index/");
        // cargo: the leftover `[registries]` block alone.
        p.write(
            ".cargo/config.toml",
            format!("[registries.socket-patch-{a}]\nindex = \"sparse+{index}\"\n"),
        );
        p.write("Cargo.toml", "[dependencies]\nsmallvec = \"1.6.0\"\n");
        // go.sum hashes, .npmrc / settings.xml definitions.
        p.write(
            "go.sum",
            format!("patch.socket.dev/gopatch/{a} v1.0.0-socketpatch.1 h1:x=\n"),
        );
        p.write(
            ".npmrc",
            format!("registry=https://patch.socket.dev/{a}/\n"),
        );
        p.write("settings.xml", format!("<id>socket-patch-{a}</id>"));
        // maven: `<repository>` without the version-suffix pin.
        let repo = format!(
            "<repositories><repository><id>socket-patch-{a}</id>\
             <url>https://patch.socket.dev/patch-registry/maven/{TOKEN}/{a}/maven2</url>\
             </repository></repositories>"
        );
        p.write(
            "pom.xml",
            format!("<project><dependencies><dependency><version>1.0.0</version></dependency></dependencies>{repo}</project>"),
        );
        // nuget: the `<add key>` source definition without its mapping.
        p.write(
            "nuget.config",
            format!(
                "<configuration><packageSources><add key=\"socket-patch-{a}\" \
                 value=\"https://patch.socket.dev/{a}/index.json\" /></packageSources>\
                 <packageSourceMapping><packageSource key=\"nuget.org\">\
                 <package pattern=\"*\" /></packageSource></packageSourceMapping></configuration>"
            ),
        );
        // pyproject: a uv index table, no direct reference.
        p.write(
            "pyproject.toml",
            format!(
                "[project]\ndependencies = [\"six==1.16.0\"]\n\n[[tool.uv.index]]\n\
                 name = \"socket-patch-{a}\"\nurl = \"https://patch.socket.dev/{a}/simple\"\n"
            ),
        );
        let root = p.root();
        for file in [
            ".cargo/config.toml",
            "Cargo.toml",
            "go.sum",
            ".npmrc",
            "settings.xml",
            "pom.xml",
            "nuget.config",
            "pyproject.toml",
        ] {
            assert!(
                !hosted_wiring_in_files(root, &[file], a).await,
                "{file}: a definition-only occurrence must not prove hosted wiring"
            );
        }

        // The pins, same files.
        let q = Project::new();
        q.write(
            "Cargo.toml",
            format!("[dependencies]\nsmallvec = {{ version = \"1.6.0\", registry = \"socket-patch-{a}\" }}\n"),
        );
        q.write(
            "pom.xml",
            format!("<project><dependencies><dependency><version>1.0.0-socket.{hex8}</version></dependency></dependencies>{repo}</project>"),
        );
        q.write(
            "nuget.config",
            format!(
                "<configuration><packageSources><add key=\"socket-patch-{a}\" value=\"x\" />\
                 </packageSources><packageSourceMapping><packageSource key=\"socket-patch-{a}\">\
                 <package pattern=\"Newtonsoft.Json\" /></packageSource></packageSourceMapping>\
                 </configuration>"
            ),
        );
        q.write(
            "pyproject.toml",
            format!(
                "[project]\ndependencies = [\n  \"six @ https://patch.socket.dev/patch/pypi/six/1.16.0/{TOKEN}/{a}/six-1.16.0.whl\",\n]\n"
            ),
        );
        let root = q.root();
        for file in ["Cargo.toml", "pom.xml", "nuget.config", "pyproject.toml"] {
            assert!(
                hosted_wiring_in_files(root, &[file], a).await,
                "{file}: a pin proves hosted wiring"
            );
        }
    }

    /// REGRESSION: a redirect ledger naming `deno.lock` (which no hosted
    /// writer edits — Deno has no rewriter) must not stay alive on the
    /// user's own Socket-url import text there: the fallback used to treat
    /// every unknown file as a pin, so `vex --no-verify` attested the
    /// forged record. `deno.json(c)` likewise.
    #[tokio::test]
    async fn hosted_ledger_proof_never_trusts_deno_files() {
        let p = Project::new();
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        p.write(
            "deno.lock",
            format!(
                r#"{{"version":"4","npm":{{"left-pad@1.3.0":{{"integrity":"sha512-x","tarball":"{url}"}}}},"remote":{{"{url}":"abc"}}}}"#
            ),
        );
        p.write(
            "deno.json",
            format!(r#"{{"imports":{{"left-pad":"{url}"}}}}"#),
        );
        p.write(
            "deno.jsonc",
            format!("// x\n{{\"imports\":{{\"lp\":\"{url}\"}}}}"),
        );
        // The same text in a real hosted lockfile IS a pin (control).
        p.write("package-lock.json", format!(r#"{{"resolved":"{url}"}}"#));
        let root = p.root();
        for file in ["deno.lock", "deno.json", "deno.jsonc"] {
            assert!(
                !hosted_wiring_in_files(root, &[file], UUID_A).await,
                "{file}: no hosted writer edits it; a Socket url there pins nothing"
            );
        }
        assert!(hosted_wiring_in_files(root, &["package-lock.json"], UUID_A).await);
    }

    /// The root files the no-recorded-wiring fallback probes, per ecosystem
    /// (sorted: `unique_safe_rel_files` sorts them before reading, so order
    /// carries no meaning).
    #[test]
    fn vendored_wiring_probe_files_per_ecosystem() {
        let p = Project::new();
        let sorted = |eco: &str| {
            let mut files = vendored_wiring_probe_files(p.root(), eco);
            files.sort();
            files
        };
        let expect: [(&str, &[&str]); 9] = [
            (
                "npm",
                &[
                    "bun.lock",
                    "bun.lockb",
                    "npm-shrinkwrap.json",
                    "package-lock.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                ],
            ),
            (
                "pypi",
                &[
                    "Pipfile.lock",
                    "hatch.toml",
                    "pdm.lock",
                    "poetry.lock",
                    "pyproject.toml",
                    "requirements.txt",
                    "uv.lock",
                ],
            ),
            ("cargo", &[".cargo/config", ".cargo/config.toml"]),
            ("golang", &["go.mod"]),
            ("gem", &["Gemfile.lock"]),
            ("composer", &["composer.lock"]),
            ("maven", &["pom.xml"]),
            ("nuget", &["NuGet.Config", "NuGet.config", "nuget.config"]),
            ("deno", &[]),
        ];
        for (eco, files) in expect {
            assert_eq!(sorted(eco), files, "{eco}");
        }
        p.write("pylock.toml", "lock-version = \"1.0\"\n");
        assert!(sorted("pypi").contains(&"pylock.toml".to_string()));
    }

    /// An unparseable `bun.lockb` proves nothing either way, even when its
    /// bytes spell the uuid or the vendored dir.
    #[tokio::test]
    async fn unparseable_bun_lockb_proves_no_wiring() {
        let p = Project::new();
        p.write(
            "bun.lockb",
            format!("not a lockfile https://patch.socket.dev/x/{UUID_A}/x.tgz .socket/vendor/npm/{UUID_A}/x.tgz"),
        );
        let root = p.root();
        assert!(!hosted_wiring_in_files(root, &["bun.lockb"], UUID_A).await);
        assert!(!vendored_wiring_in_files(root, &["bun.lockb"], "npm", UUID_A).await);
    }

    /// REGRESSION: `repair`'s reconstructed ledger entries carry `wiring: []`
    /// (every ecosystem but gem). No recorded wiring file is not evidence the
    /// wiring is gone: the ecosystem's root locks are probed instead. A
    /// recorded file that still exists stays authoritative (reverted =>
    /// dead, even if another root lock mentions the dir).
    #[tokio::test]
    async fn vendored_liveness_probes_root_locks_when_no_wiring_is_recorded() {
        let p = Project::new();
        let dir = format!(".socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz");
        p.write(
            "pnpm-lock.yaml",
            format!(
                "lockfileVersion: '9.0'\npackages:\n  left-pad@file:{dir}:\n    version: 1.3.0\n"
            ),
        );
        let root = p.root();
        assert!(vendored_wiring_live(root, &[], "npm", UUID_A).await);
        assert!(
            vendored_wiring_live(root, &["yarn.lock"], "npm", UUID_A).await,
            "a recorded wiring file that no longer exists falls back to the probe"
        );
        assert!(!vendored_wiring_live(root, &[], "npm", UUID_B).await);
        assert!(
            !vendored_wiring_live(root, &[], "cargo", UUID_A).await,
            "the probe reads only the entry's own ecosystem's files for its own dir"
        );
        p.write(
            "package-lock.json",
            "{\"lockfileVersion\":3,\"packages\":{}}",
        );
        assert!(
            !vendored_wiring_live(root, &["package-lock.json"], "npm", UUID_A).await,
            "an existing recorded wiring file that was reverted is authoritative"
        );
        // cargo's wiring lives in the config, not Cargo.lock.
        let c = Project::new();
        c.write(
            ".cargo/config.toml",
            format!("[patch.crates-io]\nsmallvec = {{ path = \".socket/vendor/cargo/{UUID_A}/smallvec-1.6.0\" }}\n"),
        );
        assert!(vendored_wiring_live(c.root(), &[], "cargo", UUID_A).await);
    }

    /// Cross-package-manager union: one root carrying the committed hosted
    /// golden output of EVERY rewriter family at once (npm package-lock, pnpm,
    /// bun, yarn, cargo, go, uv, requirements, bundler, composer, maven,
    /// nuget) plus hand-written vendored wiring in files none of those
    /// fixtures own (`gems.locked` PATH section, a `Pipfile.lock` wheel)
    /// discovers exactly the UNION of what each file discovers alone — no
    /// extractor shadows, suppresses, or re-attributes another's refs, and
    /// no file's presence makes another file diagnose. This is the property
    /// the design's "read EVERY lockfile present" rule (module docs, rule 1)
    /// promises a polyglot repo.
    #[tokio::test]
    async fn polyglot_project_discovers_the_union_of_every_package_manager() {
        const HOSTED: [&str; 12] = [
            "redirect/npm/package-lock-v3/basic/expected",
            "redirect/npm/pnpm/basic/expected",
            "redirect/npm/bun/basic/expected",
            "redirect/npm/yarn-classic/basic/expected",
            "redirect/cargo/cargo/basic/expected",
            "redirect/golang/gomod/basic/expected",
            "redirect/pypi/uv/basic/expected",
            "redirect/pypi/requirements/basic/expected",
            "redirect/gem/bundler/basic/expected",
            "redirect/composer/composer-lock/basic/expected",
            "redirect/maven/pom/basic/expected",
            "redirect/nuget/packages-lock/basic/expected",
        ];
        let gem_rel = format!(".socket/vendor/gem/{UUID_A}/rack-3.2.6");
        let gems_locked = format!(
            "PATH\n  remote: {gem_rel}\n  specs:\n    rack (3.2.6)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.2.6)!\n\n\
             BUNDLED WITH\n   2.5.22\n"
        );
        let wheel = format!(".socket/vendor/pypi/{UUID_B}/six-1.16.0-py2.py3-none-any.whl");
        let pipfile_lock = serde_json::json!({
            "_meta": { "pipfile-spec": 6, "hash": { "sha256": "x" }, "requires": {}, "sources": [] },
            "default": {
                "six": { "file": format!("./{wheel}"), "hashes": [format!("sha256:{}", "a".repeat(64))] },
            },
            "develop": {},
        })
        .to_string();
        let vendored: [(&str, &str); 2] = [
            ("gems.locked", gems_locked.as_str()),
            ("Pipfile.lock", pipfile_lock.as_str()),
        ];

        // Each source alone: must be non-empty and diagnostic-free, so the
        // union below is a meaningful sum rather than a sum of nothings.
        let mut want: Vec<(String, String, WiringMode)> = Vec::new();
        let mut want_files: BTreeSet<(String, String)> = BTreeSet::new();
        let alone: Vec<Discovery> = {
            let mut outs = Vec::new();
            for fixture in HOSTED {
                let p = Project::new();
                p.copy_fixture(fixture);
                outs.push((fixture.to_string(), p.discover().await));
            }
            for (rel, content) in vendored {
                let p = Project::new();
                p.write(rel, content);
                outs.push((rel.to_string(), p.discover().await));
            }
            outs.into_iter()
                .map(|(what, out)| {
                    assert!(!out.refs.is_empty(), "{what} alone discovers nothing");
                    assert!(
                        out.diagnostics.is_empty(),
                        "{what} alone: {:?}",
                        out.diagnostics
                    );
                    out
                })
                .collect()
        };
        for out in &alone {
            want.extend(ref_triples(out));
            want_files.extend(
                out.refs
                    .iter()
                    .map(|r| (r.source_file.to_string_lossy().into_owned(), r.uuid.clone())),
            );
        }
        want.sort();
        want.dedup();

        // Everything in one root. No two sources share a file name (asserted
        // by the copy: a collision would silently overwrite and shrink the
        // union, so check the file set up front).
        let p = Project::new();
        let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
        for fixture in HOSTED {
            for entry in walk_files(&testing::fixture_path(fixture)) {
                assert!(
                    seen.insert(entry.clone()),
                    "{fixture}: {} collides",
                    entry.display()
                );
            }
            p.copy_fixture(fixture);
        }
        for (rel, content) in vendored {
            assert!(seen.insert(PathBuf::from(rel)), "{rel} collides");
            p.write(rel, content);
        }
        let out = p.discover().await;
        assert_eq!(
            ref_triples(&out),
            want,
            "diagnostics: {:#?}",
            out.diagnostics
        );
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        let got_files: BTreeSet<(String, String)> = out
            .refs
            .iter()
            .map(|r| (r.source_file.to_string_lossy().into_owned(), r.uuid.clone()))
            .collect();
        assert_eq!(got_files, want_files, "every ref keeps its own source file");

        // Every ecosystem with a hosted/vendored mode is represented, both
        // modes appear, and vendored refs keep their artifact path.
        let ecosystems: BTreeSet<&str> = out
            .refs
            .iter()
            .filter_map(|r| r.purl.strip_prefix("pkg:")?.split('/').next())
            .collect();
        assert_eq!(
            ecosystems,
            ["cargo", "composer", "gem", "golang", "maven", "npm", "nuget", "pypi"]
                .into_iter()
                .collect(),
        );
        for (purl, uuid, rel) in [
            ("pkg:gem/rack@3.2.6", UUID_A, gem_rel.as_str()),
            ("pkg:pypi/six@1.16.0", UUID_B, wheel.as_str()),
        ] {
            let r = out
                .refs
                .iter()
                .find(|r| r.purl == purl && r.uuid == uuid)
                .unwrap_or_else(|| panic!("{purl} missing: {:#?}", out.refs));
            assert_eq!(r.mode, WiringMode::Vendored);
            assert_eq!(r.artifact_rel.as_deref(), Some(rel));
        }
        assert!(out.refs.iter().any(|r| r.mode == WiringMode::Hosted));
    }

    /// Root-relative paths of every file under `dir` (fixture collision check).
    fn walk_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).expect("read fixture dir") {
                let path = entry.expect("fixture dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    files.push(
                        path.strip_prefix(dir)
                            .expect("fixture-relative")
                            .to_path_buf(),
                    );
                }
            }
        }
        files
    }

    /// Rule 11's sweep: every spelling the lock formats record a Socket
    /// identity in is recognized, in its mode — and nothing that is not
    /// Socket's (foreign hosts, host-independent names, http, userinfo,
    /// non-canonical uuids, unknown vendor ecosystems) is.
    #[test]
    fn socket_identities_recognize_every_spelling_and_nothing_else() {
        let a = UUID_A;
        let t = TOKEN;
        let hosted = |text: &str| {
            socket_identities(text, &[])
                .into_iter()
                .filter(|(_, m)| *m == WiringMode::Hosted)
                .map(|(u, _)| u)
                .collect::<Vec<_>>()
        };
        let vendored = |text: &str| {
            socket_identities(text, &[])
                .into_iter()
                .filter(|(_, m)| *m == WiringMode::Vendored)
                .map(|(u, _)| u)
                .collect::<Vec<_>>()
        };
        let url = hosted_url("npm", "left-pad", "1.3.0", a, "left-pad-1.3.0.tgz");
        let both = {
            let mut v = vec![t.to_string(), a.to_string()];
            v.sort();
            v
        };
        for text in [
            format!("\"resolved\": \"{url}\""),
            format!("  tarball: {url}}}"),
            format!("[\"left-pad@{url}\", {{}}, \"sha512-x\"]"),
            format!("six @ {url} --hash=sha256:{}", "a".repeat(64)),
            format!("\"url\": \"{}\"", url.replace('/', "\\/")),
            format!(
                "resolution: \"left-pad@npm:1.3.0::__archiveUrl={}\"",
                url.replace(':', "%3A").replace('/', "%2F")
            ),
            format!("value=\"{}\"", url.replace('/', "&#x2F;")),
            format!("\"resolved\": \"{}\"", url.replace('/', "\\u002F")),
            format!(
                "source = \"sparse+https://patch.socket.dev/patch-registry/cargo/{t}/{a}/index/\""
            ),
            format!("  remote: https://patch.socket.dev/patch-registry/gem/{t}/{a}/\n"),
        ] {
            assert_eq!(hosted(&text), both, "{text}");
            assert!(vendored(&text).is_empty(), "{text}");
        }
        // Go module paths: every canonical segment (a token before the uuid
        // is a shape we never write — recognized all the same).
        for text in [
            format!("replace m v1 => patch.socket.dev/gopatch/{a} v1.0.0-socketpatch.1"),
            format!("patch.socket.dev/gopatch/{a}/v2 v2.0.0-socketpatch.1 h1:x="),
            format!("patch.socket.dev/gopatch/{a}@v1.0.0"),
        ] {
            assert_eq!(hosted(&text), vec![a.to_string()], "{text}");
        }
        assert_eq!(
            hosted(&format!("patch.socket.dev/gopatch/{t}/{a} v1")),
            both
        );
        // Vendored: root-anchored or not, any separator spelling, a dir that
        // ends at the uuid, a traversal leaf.
        for text in [
            format!("\"resolved\": \"file:.socket/vendor/npm/{a}/x-1.0.0.tgz\""),
            format!("../other/.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("\".socket\\\\vendor\\\\npm\\\\{a}\\\\x-1.0.0.tgz\""),
            format!("\".socket\\/vendor\\/composer\\/{a}\\/m\\/m@1.0.0\""),
            format!("value=\".socket/vendor/nuget/{a}\" />"),
            format!("<url>file://${{project.basedir}}/.socket/vendor/maven/{a}</url>"),
            format!(".socket/vendor/npm/{a}/../../../etc/passwd"),
            format!("# ./.socket/vendor/pypi/{a}/six-1.16.0-py3-none-any.whl"),
        ] {
            assert_eq!(vendored(&text), vec![a.to_string()], "{text}");
            assert!(hosted(&text).is_empty(), "{text}");
        }
        // Not Socket's.
        for text in [
            format!("https://evil.example/patch/npm/x/1.0.0/{t}/{a}/x-1.0.0.tgz"),
            format!("https://patch.socket.dev.evil.example/{a}/x.tgz"),
            format!("http://patch.socket.dev/patch/npm/x/1.0.0/{t}/{a}/x.tgz"),
            format!("https://user:pw@patch.socket.dev/patch/npm/x/1.0.0/{t}/{a}/x.tgz"),
            format!("registry = \"socket-patch-{a}\""),
            format!("<id>socket-patch-vendor-{a}</id>"),
            format!(".socket/vendor/jsr/{a}/x.tgz"),
            format!(".socket/vendor/npm/{}/x.tgz", a.to_ascii_uppercase()),
            ".socket/vendor/npm/not-a-uuid/x.tgz".to_string(),
            "https://patch.socket.dev/patch/npm/x/1.0.0/tok/placeholder/x.tgz".to_string(),
        ] {
            assert!(socket_identities(&text, &[]).is_empty(), "{text}");
        }
        // A configured patch-server origin counts only when configured.
        let staging =
            format!("\"resolved\": \"http://127.0.0.1:4545/patch/npm/x/1/{t}/{a}/x.tgz\"");
        assert!(socket_identities(&staging, &[]).is_empty());
        assert_eq!(
            socket_identities(&staging, &["http://127.0.0.1:4545".to_string()])
                .into_iter()
                .map(|(u, _)| u)
                .collect::<Vec<_>>(),
            both
        );
    }

    /// The claim API: a recognized uuid is decided by the refs alone (live
    /// only for the package — and, vendored, the artifact — a ref wires),
    /// while an unrecognized one is left to the caller (`None`).
    #[test]
    fn ledger_claims_follow_the_refs_for_recognized_uuids_only() {
        let rel = format!(".socket/vendor/npm/{UUID_A}/x-1.0.0.tgz");
        let vref = vendor_ref(&rel).unwrap();
        let mut out = Discovery::default();
        out.push(PatchedRef::vendored(
            "pkg:npm/x@1.0.0".into(),
            &vref,
            "package-lock.json",
            None,
        ));
        out.recognize(UUID_B, WiringMode::Hosted, "go.mod");
        out.finalize();
        assert_eq!(
            out.vendored_claim("pkg:npm/x@1.0.0", UUID_A, &rel),
            Some(true)
        );
        assert_eq!(
            out.vendored_claim("pkg:npm/x@1.0.0", UUID_A, &format!("./{rel}")),
            Some(true),
            "a ledger's `./` spelling is the same artifact"
        );
        assert_eq!(
            out.vendored_claim("pkg:npm/y@1.0.0", UUID_A, &rel),
            Some(false)
        );
        assert_eq!(
            out.vendored_claim("pkg:npm/x@1.0.0", UUID_A, ".socket/vendor/npm/other.tgz"),
            Some(false)
        );
        // Mode-specific: the vendored ref says nothing about a hosted claim.
        assert_eq!(out.hosted_claim("pkg:npm/x@1.0.0", UUID_A), None);
        // Recognized with no ref at all (a rejected entry): dead.
        assert_eq!(out.hosted_claim("pkg:golang/m@v1.0.0", UUID_B), Some(false));
        assert_eq!(
            out.recognized_files(UUID_B, WiringMode::Hosted),
            vec![Path::new("go.mod")]
        );
        // Never mentioned: the caller's (ledger evidence) call.
        assert_eq!(out.hosted_claim("pkg:npm/x@1.0.0", TOKEN), None);
        assert_eq!(out.vendored_claim("pkg:npm/x@1.0.0", TOKEN, &rel), None);
    }

    /// Recognition through the ORCHESTRATOR, across package managers: each
    /// file below mentions a patch only in a shape its extractor rejects or
    /// skips (the stale ledger false-attestation shapes), so nothing is a
    /// ref — yet every patch is recognized, so a ledger claim for any of
    /// them is dead instead of being revived from the raw text.
    #[tokio::test]
    async fn rejected_and_skipped_wiring_is_recognized_across_package_managers() {
        let u = |n: u8| {
            format!("{n}{n}{n}{n}{n}{n}{n}{n}-1111-4111-8111-{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}")
        };
        let (npm_u, go_u, req_u, pip_u, comp_u) = (u(1), u(2), u(3), u(4), u(5));
        let p = Project::new();
        // npm: only the v2 `dependencies` mirror (which npm 7+ ignores)
        // names the patch.
        p.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 2,
                "packages": { "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                } },
                "dependencies": { "left-pad": {
                    "version": "1.3.0",
                    "resolved": hosted_url("npm", "left-pad", "1.3.0", &npm_u, "left-pad-1.3.0.tgz")
                } }
            })
            .to_string(),
        );
        // go: a hosted replace made inert by a `require` bump.
        p.write(
            "go.mod",
            format!(
                "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.5.0\n\n\
                 replace github.com/foo/bar v1.4.2 => patch.socket.dev/gopatch/{go_u} \
                 v1.4.2-socketpatch.1\n"
            ),
        );
        // requirements: a commented-out vendored line.
        p.write(
            "requirements.txt",
            format!(
                "# ./.socket/vendor/pypi/{req_u}/six-1.16.0-py3-none-any.whl\nrequests==2.31.0\n"
            ),
        );
        // Pipfile.lock: unparseable, so pipenv installs nothing from it.
        p.write(
            "Pipfile.lock",
            format!(
                "{{ \"default\": {{ \"six\": {{ \"file\": \"{}\" ",
                hosted_url(
                    "pypi",
                    "six",
                    "1.16.0",
                    &pip_u,
                    "six-1.16.0-py3-none-any.whl"
                )
            ),
        );
        // composer: a vendored path dist whose `reference` lost the uuid.
        p.write(
            "composer.lock",
            serde_json::json!({
                "packages": [{
                    "name": "psr/log",
                    "version": "3.0.2",
                    "dist": {
                        "type": "path",
                        "url": format!(".socket/vendor/composer/{comp_u}/psr/log@3.0.2"),
                        "reference": null
                    }
                }],
                "packages-dev": []
            })
            .to_string(),
        );
        let out = p.discover().await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        for (purl, uuid, mode, file) in [
            (
                "pkg:npm/left-pad@1.3.0",
                &npm_u,
                WiringMode::Hosted,
                "package-lock.json",
            ),
            (
                "pkg:golang/github.com/foo/bar@v1.4.2",
                &go_u,
                WiringMode::Hosted,
                "go.mod",
            ),
            (
                "pkg:pypi/six@1.16.0",
                &req_u,
                WiringMode::Vendored,
                "requirements.txt",
            ),
            (
                "pkg:pypi/six@1.16.0",
                &pip_u,
                WiringMode::Hosted,
                "Pipfile.lock",
            ),
            (
                "pkg:composer/psr/log@3.0.2",
                &comp_u,
                WiringMode::Vendored,
                "composer.lock",
            ),
        ] {
            let claim = match mode {
                WiringMode::Hosted => out.hosted_claim(purl, uuid),
                WiringMode::Vendored => out.vendored_claim(purl, uuid, "unused"),
            };
            assert_eq!(
                claim,
                Some(false),
                "{purl} ({mode:?}): {:#?}",
                out.recognized
            );
            assert_eq!(
                out.recognized_files(uuid, mode),
                vec![Path::new(file)],
                "{purl}"
            );
        }
    }

    /// ARCHITECTURE GUARD for rule 11: recognition happens inside the
    /// guarded reads, so an extractor that read file CONTENT any other way
    /// would silently opt its rejections out of it (the stale-ledger false
    /// attestation). Every extractor module's production code is scanned
    /// for content reads and for bypasses of the ctx identity helpers;
    /// metadata / directory probes are fine. New extractor files are
    /// covered automatically.
    #[test]
    fn extractors_read_content_only_through_the_recognizing_ctx_helpers() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vex/discover");
        let forbidden = [
            "tokio::fs::read(",
            "tokio::fs::read_to_string(",
            "std::fs::read(",
            "std::fs::read_to_string(",
            "fs::read_to_string(",
            "read_regular_to_string(",
            "read_regular_to_bytes(",
            "File::open(",
            "OpenOptions",
            "hosted_patch_uuid(",
            "hosted_patch_url_uuids(",
            // The file-reading entry points of the shared readers an
            // extractor imports (the lock inventory, the writers' config
            // readers): each reads content outside the recognizing ctx.
            // Bare `inventory_` also catches an imported inventory name.
            "inventory_project",
            "inventory_",
            "read_patch_entries(",
            "socket_registry_indexes(",
            "config_path(",
            "existing_config_path(",
            "read_replace_entries(",
            "read_required_versions(",
            "read_lock(",
            "wired_vendor_integrity(",
            "recover_lock_entry(",
        ];
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("read discover dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name == "mod.rs" {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read extractor source");
            let prod = src.split("#[cfg(test)]").next().unwrap_or_default();
            for needle in forbidden {
                assert!(
                    !prod.contains(needle),
                    "{name}: production code uses `{needle}` — read content only through \
                     DiscoverCtx::read_text / read_bytes / recognize_ignored and take hosted \
                     identities from DiscoverCtx::hosted_uuid (module docs, rules 2, 4, 11)"
                );
            }
            checked += 1;
        }
        assert!(checked >= 12, "only {checked} extractor files scanned");
    }

    /// ARCHITECTURE GUARD (rule 12): the npm-family extractors read their
    /// locks through the entry models the lock inventory shares
    /// (`classic_entries` / `berry_entries`, `pnpm_packages`,
    /// `bun_text_entries`, `BunLockb::parse_packages`), never through the
    /// grammar primitives those models wrap, nor a second parser of the
    /// same lock (a JSON read of `bun.lock`) — so discovery and the
    /// inventory see one entry walk per format.
    #[test]
    fn npm_family_extractors_iterate_entry_models_only() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vex/discover");
        let primitives = [
            "scan_blocks(",
            "pnpm_grammar::entries(",
            "pnpm_grammar::resolution(",
            "BunLockb::parse(",
            "parse_packages_section(",
            "parse_entry_line(",
            "packages_bounds(",
            // Locating pnpm resolution lines by hand (the grammar's key).
            "    resolution:",
        ];
        // Per-file: a second whole-document parser of a lock whose entry
        // model already exists.
        let per_file: &[(&str, &[&str])] = &[(
            "bun.rs",
            &[
                "serde_json::from_str(",
                "serde_json::from_slice(",
                "check_lock_version(",
            ],
        )];
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("read discover dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name == "mod.rs" {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read extractor source");
            let prod = src.split("#[cfg(test)]").next().unwrap_or_default();
            let extra = per_file
                .iter()
                .filter(|(file, _)| *file == name)
                .flat_map(|(_, banned)| banned.iter());
            let uses: Vec<&str> = primitives
                .iter()
                .chain(extra)
                .copied()
                .filter(|p| prod.contains(p))
                .collect();
            assert!(
                uses.is_empty(),
                "{name}: production code calls {uses:?} — iterate the shared entry models \
                 instead (module docs, rule 12)"
            );
            checked += 1;
        }
        assert!(checked >= 12, "only {checked} extractor files scanned");
    }

    /// REGRESSION (false attestation): one lock wires a package to a Socket
    /// patch while ANOTHER lock resolves the same version from the registry
    /// — a stale `yarn.lock` beside the hosted `package-lock.json`, a
    /// registry `uv.lock` (which `uv sync` installs) beside a hosted
    /// `requirements.txt`. Which lock the build uses depends on the package
    /// manager that runs, so the ref is contested: diagnosed, not emitted,
    /// and its uuid still recognized so a ledger claim for it is dead. Every
    /// pairing below, hosted and vendored alike.
    #[tokio::test]
    async fn a_ref_another_lock_resolves_elsewhere_is_contested() {
        const SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
        const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let npm_url = hosted_url("npm", "foo", "1.0.0", UUID_A, "foo-1.0.0.tgz");
        let npm_vendored = format!("file:.socket/vendor/npm/{UUID_B}/foo-1.0.0.tgz");
        let registry_tgz = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let package_lock = |resolved: &str| {
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/foo": {"version": "1.0.0", "resolved": resolved, "integrity": SRI},
                }
            })
            .to_string()
        };
        let yarn_registry = format!(
            "# yarn lockfile v1\n\n\nfoo@^1.0.0:\n  version \"1.0.0\"\n  resolved \"{registry_tgz}#{}\"\n  integrity {SRI}\n",
            "0".repeat(40)
        );
        let pnpm_hosted = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  foo@1.0.0:\n    resolution: {{integrity: {SRI}, tarball: {npm_url}}}\n"
        );
        let wheel = "vexdemo-1.2.3-py3-none-any.whl";
        let pypi_url = hosted_url("pypi", "vexdemo", "1.2.3", UUID_A, wheel);
        let uv_registry = format!(
            "version = 1\nrequires-python = \">=3.8\"\n\n[[package]]\nname = \"vexdemo\"\n\
             version = \"1.2.3\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n\
             wheels = [{{ url = \"https://files.pythonhosted.org/packages/{wheel}\", hash = \"sha256:{SHA}\" }}]\n"
        );
        type Files = Vec<(&'static str, String)>;
        let cases: Vec<(&str, Files, &str, &str)> = vec![
            (
                "npm hosted + yarn registry",
                vec![
                    ("package-lock.json", package_lock(&npm_url)),
                    ("yarn.lock", yarn_registry.clone()),
                ],
                "pkg:npm/foo@1.0.0",
                UUID_A,
            ),
            (
                "npm vendored + yarn registry",
                vec![
                    ("package-lock.json", package_lock(&npm_vendored)),
                    ("yarn.lock", yarn_registry.clone()),
                ],
                "pkg:npm/foo@1.0.0",
                UUID_B,
            ),
            (
                "pnpm hosted + npm registry",
                vec![
                    ("pnpm-lock.yaml", pnpm_hosted.clone()),
                    ("package-lock.json", package_lock(registry_tgz)),
                ],
                "pkg:npm/foo@1.0.0",
                UUID_A,
            ),
            (
                "requirements hosted + uv registry",
                vec![
                    (
                        "requirements.txt",
                        format!("vexdemo @ {pypi_url} --hash=sha256:{SHA}\n"),
                    ),
                    ("uv.lock", uv_registry.clone()),
                ],
                "pkg:pypi/vexdemo@1.2.3",
                UUID_A,
            ),
            (
                "requirements vendored + uv registry",
                vec![
                    (
                        "requirements.txt",
                        format!("./.socket/vendor/pypi/{UUID_B}/{wheel} --hash=sha256:{SHA}\n"),
                    ),
                    ("uv.lock", uv_registry.clone()),
                ],
                "pkg:pypi/vexdemo@1.2.3",
                UUID_B,
            ),
            (
                "uv hosted + requirements registry pin",
                vec![
                    (
                        "uv.lock",
                        format!(
                            "version = 1\n\n[[package]]\nname = \"vexdemo\"\nversion = \"1.2.3\"\n\
                             source = {{ url = \"{pypi_url}\" }}\n\
                             wheels = [{{ url = \"{pypi_url}\", hash = \"sha256:{SHA}\" }}]\n"
                        ),
                    ),
                    (
                        "requirements.txt",
                        format!("vexdemo==1.2.3 --hash=sha256:{SHA}\n"),
                    ),
                ],
                "pkg:pypi/vexdemo@1.2.3",
                UUID_A,
            ),
        ];
        for (name, files, purl, uuid) in cases {
            let p = Project::new();
            for (file, text) in &files {
                p.write(file, text);
            }
            let out = p.discover().await;
            assert!(out.refs.is_empty(), "{name}: {:#?}", out.refs);
            assert!(
                out.diagnostics
                    .iter()
                    .any(|d| d.code == DIAG_REF_UNATTRIBUTABLE
                        && d.detail.contains(uuid)
                        && d.detail.contains(files[1].0)),
                "{name}: {:#?}",
                out.diagnostics
            );
            let mode = if uuid == UUID_A {
                WiringMode::Hosted
            } else {
                WiringMode::Vendored
            };
            assert!(out.recognizes(uuid, mode), "{name}");
            if mode == WiringMode::Hosted {
                assert_eq!(out.hosted_claim(purl, uuid), Some(false), "{name}");
            }

            // Without the contesting lock the same wiring is a ref.
            let alone = Project::new();
            alone.write(files[0].0, &files[0].1);
            assert_eq!(alone.discover().await.refs.len(), 1, "{name} alone");
        }
    }

    /// What does NOT contest: a lock that never mentions the package, a lock
    /// that wires the same patch too, another version of the package, and a
    /// PEP 723 script lock (scoped to its script's own install).
    #[tokio::test]
    async fn only_a_registry_resolution_of_the_same_version_contests() {
        const SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
        let npm_url = hosted_url("npm", "foo", "1.0.0", UUID_A, "foo-1.0.0.tgz");
        let package_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/foo": {"version": "1.0.0", "resolved": npm_url, "integrity": SRI},
            }
        })
        .to_string();
        let yarn = |key: &str, version: &str, resolved: &str| {
            format!(
                "# yarn lockfile v1\n\n\n{key}:\n  version \"{version}\"\n  resolved \"{resolved}\"\n  integrity {SRI}\n"
            )
        };
        for (name, yarn_lock) in [
            (
                "unrelated package",
                yarn(
                    "bar@^1.0.0",
                    "1.0.0",
                    "https://registry.yarnpkg.com/bar/-/bar-1.0.0.tgz",
                ),
            ),
            ("same patch", yarn("foo@^1.0.0", "1.0.0", &npm_url)),
            (
                "another version",
                yarn(
                    "foo@^2.0.0",
                    "2.0.0",
                    "https://registry.yarnpkg.com/foo/-/foo-2.0.0.tgz",
                ),
            ),
        ] {
            let p = Project::new();
            p.write("package-lock.json", &package_lock);
            p.write("yarn.lock", &yarn_lock);
            let out = p.discover().await;
            assert!(
                out.refs
                    .iter()
                    .any(|r| r.source_file == Path::new("package-lock.json")),
                "{name}: {:#?} {:#?}",
                out.refs,
                out.diagnostics
            );
            assert!(
                !out.diagnostics
                    .iter()
                    .any(|d| d.code == DIAG_REF_UNATTRIBUTABLE),
                "{name}: {:#?}",
                out.diagnostics
            );
        }

        let sha = "a".repeat(64);
        let wheel = "vexdemo-1.2.3-py3-none-any.whl";
        let pypi_url = hosted_url("pypi", "vexdemo", "1.2.3", UUID_A, wheel);
        let p = Project::new();
        p.write(
            "requirements.txt",
            format!("vexdemo @ {pypi_url} --hash=sha256:{sha}\n"),
        );
        p.write(
            "tool.py",
            "# /// script\n# dependencies = [\"vexdemo\"]\n# ///\n",
        );
        p.write(
            "tool.py.lock",
            "version = 1\n\n[[package]]\nname = \"vexdemo\"\nversion = \"1.2.3\"\n\
             source = { registry = \"https://pypi.org/simple\" }\n",
        );
        let out = p.discover().await;
        assert_refs(
            &out,
            &[("pkg:pypi/vexdemo@1.2.3", UUID_A, WiringMode::Hosted)],
        );
    }

    /// The orchestrator runs every extractor; a project with no lockfiles at
    /// all (or only unrelated files) discovers nothing and diagnoses nothing.
    #[tokio::test]
    async fn empty_project_discovers_nothing() {
        let p = Project::new();
        p.write("README.md", "hello");
        let out = p.discover().await;
        assert!(out.refs.is_empty(), "{:?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }
}
