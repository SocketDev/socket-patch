//! pnpm LEGACY vendor backend: the pre-9 lock grammars — `lockfileVersion:
//! 5.4` (pnpm 7) and `'6.0'` (pnpm 8) — wired through the same
//! `package.json pnpm.overrides` + `pnpm-lock.yaml` pair surgery as the v9
//! backend ([`super::pnpm_lock`]), with the legacy serialization shapes.
//!
//! Every splice below is a faithful port of REAL captured pnpm output
//! (spike `matrix/vendor-legacy-spike/{p7,p8,t7,t8}`, pnpm 7.33.5 /
//! 8.15.9, 2026-08-18): a `file:` tarball override was added to
//! `package.json` and THAT pnpm's own `install` re-serialized the lock; the
//! unit-test fixtures quote those locks verbatim. Both majors were also
//! proven byte-stable across an install re-run of the captured shape.
//!
//! ## The legacy shapes (vs the v9 grammar)
//!
//! 1. `overrides:` — same `<name>@<version>: file:<rel-tgz>` entry, but the
//!    section sits after `lockfileVersion:`/`settings:` (pnpm's
//!    ROOT_KEYS_ORDER puts `overrides` at priority 4, before
//!    `specifiers:`/`dependencies:`/`packages:`).
//! 2. root dependency — v5.4 keeps flat top-level maps (`specifiers:` +
//!    `dependencies:`/`devDependencies:`/`optionalDependencies:` with bare
//!    values); v6.0 nests `specifier:`/`version:` under each dep. The
//!    resolved value moves to `file:<rel-tgz>` in both.
//! 3. the SPECIFIER is ABSOLUTE: pnpm <= 8 absolutizes `file:` override
//!    prefs against the project root before recording them (verified in the
//!    bundled `createVersionsOverrider`: `path.join(rootDir, pkgPath)`), so
//!    the captured locks carry `file:/abs/project/.socket/...`. This makes
//!    the frozen check path-bound: `pnpm install --frozen-lockfile` only
//!    passes in a checkout at that exact absolute path (spike probes A/B),
//!    while a `pnpm install --offline --no-frozen-lockfile` at any path installs the
//!    patched tarball and re-resolves only that specifier line (probe C).
//!    Vendoring writes the absolute spelling pnpm itself emits and surfaces
//!    the portability limit as `vendor_pnpm_legacy_absolute_specifier`.
//! 4. `packages:` — the registry entry (`/name/version` in v5.4,
//!    `/name@version` in v6.0) is REKEYED to the bare `file:<rel-tgz>` key
//!    (no `name@` prefix, unlike v9), its `resolution:` replaced with
//!    `{integrity: <ours>, tarball: file:<rel-tgz>}`, `name:`/`version:`
//!    lines inserted after it (legacy registry entries derive both from the
//!    key; file: entries spell them out), and `deprecated:` dropped —
//!    everything else (`dev: false`, engines, …) verbatim. The rekey MOVES
//!    the block to its byte-sorted position (pnpm sorts package keys with
//!    the default code-unit compare; `/`-keys sort before `file:`-keys).
//! 5. other packages' `dependencies:`/`optionalDependencies:` refs to the
//!    exact version become `name: file:<rel-tgz>`.
//!
//! No `pnpm-workspace.yaml` is written for legacy locks: pnpm <= 8 reads
//! overrides ONLY from package.json `pnpm.overrides` (proven by the spike —
//! the override applied with no workspace file present), and creating one
//! would flip the project into workspace mode. Legacy WORKSPACE locks
//! (an `importers:` section) are refused fail-closed: the flat-map surgery
//! has no captured fixtures for them.
//!
//! Same commit discipline as v9: package.json first, lock second, unwind on
//! a lock write failure; wiring fragments recorded for byte-identical
//! revert; peer-suffixed / aliased reference spellings refuse before any
//! write.

use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

use super::common::{already_patched_result, detect_indent, done, refused, serialize_json};
use super::npm_common::{
    done_failure, guard_coordinates, guard_revert_uuid_dir, stage_patch_pack, tgz_rel_leaf,
};
use super::path::parse_vendor_path;
use super::pnpm_lock::{
    apply_pkg_override, check_lock_override, classify_pkg_override, commit_surfaces, drifted,
    guard_unwired_revert, lines_value, next_block, overrides_record, parse_key_line,
    revert_overrides_line, revert_pkg_record, section_bounds, split_lines, value_lines,
    vendor_value_is_for, yaml_key, yaml_key_like, KIND_LOCK_OVERRIDES,
};
use super::state::{
    write_marker, PnpmMeta, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

const PACKAGE_JSON: &str = "package.json";
const PNPM_LOCK: &str = "pnpm-lock.yaml";

/// The [`VendorEntry::flavor`] string legacy wirings are stamped with.
/// Distinct from the v9 backend's `"pnpm"` so an older binary (which has no
/// legacy backend) fails CLOSED on revert instead of misreading the records.
pub(super) const FLAVOR: &str = "pnpm-legacy";

/// Wiring kinds. `pnpm_pkg_override`/`pnpm_lock_overrides` are shared with
/// the v9 backend (identical fragment shapes); the rest are legacy-only.
const KIND_LOCK_SPECIFIER: &str = "pnpm_lock_specifier";
const KIND_LOCK_ROOT_DEP: &str = "pnpm_lock_root_dep";
const KIND_LOCK_ROOT_DEP_PAIR: &str = "pnpm_lock_root_dep_pair";
const KIND_LOCK_PACKAGE: &str = "pnpm_lock_package";
const KIND_LOCK_PKG_DEP_REF: &str = "pnpm_lock_pkg_dep_ref";

/// SECURITY: same rule as the v9 backend — revert writes are restricted to
/// exactly the pair vendor edits (legacy never touches pnpm-workspace.yaml).
const REVERT_ALLOWLIST: [&str; 2] = [PNPM_LOCK, PACKAGE_JSON];

/// The flat root-dependency sections a v5.4/v6.0 single-package lock keys
/// its direct deps under.
const ROOT_DEP_SECTIONS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];

/// Top-level keys that sort BEFORE `overrides:` (pnpm's ROOT_KEYS_ORDER,
/// identical in the 7.33.5 and 8.15.9 bundles); the insert anchor is the
/// first section that is none of these.
const OVERRIDES_PRECEDING: [&str; 4] = [
    "lockfileVersion",
    "settings",
    "neverBuiltDependencies",
    "onlyBuiltDependencies",
];

/// Normalize a `std::fs::canonicalize`d project-root path for embedding in
/// the pnpm <= 8 absolute `file:` override specifier.
///
/// On Windows `canonicalize` returns a VERBATIM path — `\\?\C:\dir` (or
/// `\\?\UNC\server\share\dir` for network paths) with backslash separators
/// — a spelling pnpm itself never emits (its `path.join(rootDir, pkgPath)`
/// records `C:/dir`-shaped, forward-slashed specifiers). Embedding the
/// verbatim spelling makes the very next `pnpm install` re-serialize the
/// specifier line (lock churn) and `pnpm install --frozen-lockfile` fail
/// even in a checkout at the recorded path — contradicting the
/// `vendor_pnpm_legacy_absolute_specifier` warning. So: strip the verbatim
/// prefix (`\\?\` → drive path, `\\?\UNC\` → `\\`-rooted UNC path) and
/// forward-slash the separators of Windows-shaped inputs.
///
/// Unix paths pass through BYTE-UNCHANGED — including any literal `\` in a
/// unix file name, which is only a separator on Windows-shaped inputs.
/// Pure string-level so the transformation is unit-testable on any host;
/// a real Windows CI leg should confirm pnpm 7/8's own emission spelling.
fn normalize_canonical_root(path: &str) -> String {
    /// Drive-letter (`C:\...` / `C:/...`) or UNC (`\\server\...`) shape.
    fn is_windows_shaped(path: &str) -> bool {
        let b = path.as_bytes();
        let drive_letter = b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/');
        drive_letter || path.starts_with(r"\\")
    }

    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        // Verbatim UNC: `\\?\UNC\server\share\dir` → `//server/share/dir`.
        format!("//{}", rest.replace('\\', "/"))
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        // Verbatim drive: `\\?\C:\dir` → `C:/dir`.
        rest.replace('\\', "/")
    } else if is_windows_shaped(path) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

// ───────────────────────────── grammar sniff ──────────────────────────────

/// Which pnpm lock grammar a `pnpm-lock.yaml` head declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PnpmLockGrammar {
    /// `lockfileVersion: '9.0'` — the [`super::pnpm_lock`] backend.
    V9,
    /// `lockfileVersion: 5.4` (pnpm 7, bare float spelling).
    V54,
    /// `lockfileVersion: '6.0'` (pnpm 8).
    V60,
}

/// The full vendor allowlist sniff (5.4 / 6.0 / 9.0) the flavor router
/// uses; anything else refuses with a version-aware remedy: pre-allowlist
/// versions (pnpm <= 6's 5.x line) are fixed by upgrading pnpm, but a
/// FUTURE version means the user's pnpm already outgrew this build —
/// looping them back to "re-lock with pnpm >= 9" would hand them the lock
/// they have.
pub(crate) fn sniff_lock_grammar(text: &str) -> Result<PnpmLockGrammar, String> {
    let version = text
        .lines()
        .take(5)
        .find_map(|line| line.strip_prefix("lockfileVersion:"))
        .map(|rest| rest.trim().trim_matches(['\'', '"']).to_string());
    match version.as_deref() {
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

impl PnpmLockGrammar {
    /// Human name for diagnostics (`pnpm 7 (lockfileVersion 5.4)`).
    fn describe(self) -> &'static str {
        match self {
            PnpmLockGrammar::V9 => "pnpm >= 9 (lockfileVersion 9.0)",
            PnpmLockGrammar::V54 => "pnpm 7 (lockfileVersion 5.4)",
            PnpmLockGrammar::V60 => "pnpm 8 (lockfileVersion 6.0)",
        }
    }
}

// ───────────────────────────── edit context ──────────────────────────────

struct Ctx<'a> {
    grammar: PnpmLockGrammar,
    name: &'a str,
    version: &'a str,
    /// `.socket/vendor/npm/<uuid>/<leaf>` (forward slashes, root-relative).
    rel_tgz: &'a str,
    /// `file:<rel_tgz>` — override values, root-dep values, packages key.
    spec: &'a str,
    /// `file:<abs-project-root>/<rel_tgz>` — the SPECIFIER spelling pnpm
    /// <= 8 itself emits (module doc §3).
    abs_spec: &'a str,
    /// `sha512-<base64>` of the packed tarball.
    integrity: &'a str,
    /// The override key both surfaces edit (canonical `name@version`, or a
    /// taken-over user key).
    override_key: &'a str,
}

impl Ctx<'_> {
    /// The registry packages key this grammar spells for `name@version`.
    fn reg_key(&self) -> String {
        match self.grammar {
            PnpmLockGrammar::V54 => format!("/{}/{}", self.name, self.version),
            _ => format!("/{}@{}", self.name, self.version),
        }
    }

    /// Our rekeyed packages key (`file:<rel-tgz>` — bare, no `name@`).
    fn new_key(&self) -> String {
        format!("file:{}", self.rel_tgz)
    }

    /// Does `value` point at OUR vendored tarball for THIS name@version
    /// (any uuid, relative or the machine-absolute specifier spelling —
    /// `parse_vendor_path` anchors on `.socket/vendor/` anywhere in the
    /// string)?
    fn is_ours(&self, value: &str) -> bool {
        vendor_value_is_for(value, self.name, self.version)
    }

    /// The peer-suffix marker this grammar appends to a version/key
    /// (`1.3.0_peer@1.0.0` in v5.4, `1.3.0(peer@1.0.0)` in v6.0).
    fn peer_sep(&self) -> char {
        match self.grammar {
            PnpmLockGrammar::V54 => '_',
            _ => '(',
        }
    }
}

// ─────────────────────────────── vendor ───────────────────────────────────

/// Vendor one installed npm package into a pnpm 7/8 project. Same contract
/// as [`super::pnpm_lock::vendor_pnpm`]: refuse-early / wire-last, `entry`
/// present iff success and not a dry run, in-sync re-runs synthesize
/// AlreadyPatched.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_pnpm_legacy(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    let mut warnings: Vec<VendorWarning> = Vec::new();

    // ── 1. Coordinates ────────────────────────────────────────────────────
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name.as_str(), coords.version.as_str());
    let rel_tgz = format!("{}/{}", coords.uuid_dir_rel, tgz_rel_leaf(name, version));
    let spec = format!("file:{rel_tgz}");
    let override_key = format!("{name}@{version}");

    // ── 2. Read the pair (refuse before any write) ───────────────────────
    let pkg_bytes = match tokio::fs::read(project_root.join(PACKAGE_JSON)).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!(
                    "cannot read {PACKAGE_JSON}: {e} — the pnpm wiring edits the \
                     package.json + pnpm-lock.yaml PAIR (a lock-only edit silently \
                     unpatches on the next plain `pnpm install`)"
                ),
            );
        }
    };
    let mut pkg: Value = match serde_json::from_slice(&pkg_bytes) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(_) | Err(_) => {
            return refused(
                "vendor_pkg_json_unsupported",
                format!("{PACKAGE_JSON} is not a JSON object; cannot add pnpm.overrides"),
            );
        }
    };
    let lock_text = match tokio::fs::read_to_string(project_root.join(PNPM_LOCK)).await {
        Ok(text) => text,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("cannot read {PNPM_LOCK}: {e} — run `pnpm install` first"),
            );
        }
    };
    let grammar = match sniff_lock_grammar(&lock_text) {
        Ok(PnpmLockGrammar::V9) => {
            // Router bug guard: v9 locks belong to the v9 backend.
            return refused(
                "vendor_lockfile_version_unsupported",
                format!("{PNPM_LOCK} is a lockfileVersion 9.0 lock; not a legacy grammar"),
            );
        }
        Ok(g) => g,
        Err(detail) => return refused("vendor_lockfile_version_unsupported", detail),
    };
    // CRLF fails closed exactly like the v9 backend: every structural probe
    // below is byte-exact on LF lines.
    if lock_text.contains('\r') {
        return refused(
            "vendor_lockfile_crlf_unsupported",
            format!(
                "{PNPM_LOCK} has CRLF line endings, which this rewriter cannot edit \
                 byte-faithfully — normalize the file to LF (re-run `pnpm install`, \
                 or add `pnpm-lock.yaml text eol=lf` to .gitattributes and re-checkout) \
                 and retry"
            ),
        );
    }
    let mut lines = split_lines(&lock_text);

    // Legacy WORKSPACE locks nest everything under `importers:` — a shape
    // with no captured fixtures. Fail closed with the upgrade path.
    if section_bounds(&lines, "importers").is_some() {
        return refused(
            "vendor_lock_entry_unsupported",
            format!(
                "{PNPM_LOCK} is a {} WORKSPACE lock (importers: section); the legacy \
                 pair surgery only supports single-package locks — upgrade to pnpm >= 9 \
                 (its lockfileVersion 9.0 workspace grammar is supported) and re-lock",
                grammar.describe()
            ),
        );
    }

    // pnpm <= 8 absolutizes file: override prefs against the project root
    // (module doc §3), so the specifier splice needs the canonical absolute
    // path — the same one pnpm's own process.cwd() yields. On Windows,
    // `canonicalize` returns a VERBATIM path (`\\?\C:\...`) that pnpm never
    // emits; `normalize_canonical_root` rewrites it to the pnpm spelling so
    // the embedded specifier doesn't churn the lock on the next install
    // (which would fail `--frozen-lockfile`, contradicting the
    // `vendor_pnpm_legacy_absolute_specifier` warning below).
    let abs_root = match std::fs::canonicalize(project_root) {
        Ok(p) => p,
        Err(e) => {
            return refused(
                "vendor_lock_entry_unsupported",
                format!(
                    "cannot canonicalize the project root ({e}) — the pnpm <= 8 lock \
                     records the override specifier as an absolute path"
                ),
            );
        }
    };
    let abs_root = normalize_canonical_root(&abs_root.display().to_string());
    let abs_spec = format!("file:{abs_root}/{rel_tgz}");

    // ── 3. Pre-flight refusals ────────────────────────────────────────────
    let disposition = match classify_pkg_override(&pkg, name, version, &override_key) {
        Ok(d) => d,
        Err(detail) => return refused("vendor_override_conflict", detail),
    };
    let effective_key = disposition.effective_key(&override_key).to_string();
    if let Err(detail) = check_lock_override(&lines, name, version, &effective_key) {
        return refused("vendor_override_conflict", detail);
    }
    let ctx = Ctx {
        grammar,
        name,
        version,
        rel_tgz: &rel_tgz,
        spec: &spec,
        abs_spec: &abs_spec,
        integrity: "", // filled after packing; pre-flight never reads it
        override_key: &effective_key,
    };
    // Refs guard FIRST: a peer-suffixed packages key is also not the plain
    // registry key, and "entry not found" would misdiagnose that shape.
    if let Err(detail) = check_rewritable_refs(&lines, &ctx) {
        return refused("vendor_lock_entry_unsupported", detail);
    }
    if !lock_has_target_package(&lines, &ctx) {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{PNPM_LOCK} has no packages entry for {name}@{version} — make sure the \
                 package is installed and locked (`pnpm install`) before vendoring"
            ),
        );
    }

    // ── 4. Stage → patch → pack ───────────────────────────────────────────
    let (staged, result) = match stage_patch_pack(
        purl,
        installed_dir,
        project_root,
        record,
        sources,
        dry_run,
        force,
        &mut warnings,
        service,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return *outcome,
    };
    let Some(staged) = staged else {
        return done(result, None, warnings);
    };
    debug_assert_eq!(staged.rel_tgz, rel_tgz);
    let packed = staged.packed;
    if staged.staged_pkg_json.is_some() {
        // Legacy locks mirror the package's dependency maps inside its
        // packages entry, preserved verbatim here — same caveat as v9.
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; pnpm-lock.yaml's \
                 dependency mirrors were preserved verbatim — if the patch changed \
                 dependency ranges, run `pnpm install` to re-resolve them"
            ),
        ));
    }

    // ── 5. Compute both edits in memory ──────────────────────────────────
    let ctx = Ctx {
        integrity: &packed.integrity,
        ..ctx
    };
    let mut wiring: Vec<WiringRecord> = Vec::new();

    let (pkg_changed, created_pnpm_table, created_overrides_table) =
        match apply_pkg_override(&mut pkg, &effective_key, &spec, &mut wiring) {
            Ok(out) => out,
            Err(e) => return done_failure(purl, e),
        };

    let mut lock_changed = false;
    match edit_overrides(&mut lines, &ctx, &mut wiring) {
        Ok(changed) => lock_changed |= changed,
        Err(e) => return done_failure(purl, format!("{PNPM_LOCK} surgery failed: {e}")),
    }
    let root_edit = match grammar {
        PnpmLockGrammar::V54 => edit_root_deps_v54(&mut lines, &ctx, &mut wiring),
        _ => edit_root_deps_v60(&mut lines, &ctx, &mut wiring),
    };
    let root_dep_hit = match root_edit {
        Ok((changed, hit)) => {
            lock_changed |= changed;
            hit
        }
        Err(e) => return done_failure(purl, format!("{PNPM_LOCK} surgery failed: {e}")),
    };
    if grammar == PnpmLockGrammar::V54 && root_dep_hit {
        match edit_specifier_v54(&mut lines, &ctx, &mut wiring) {
            Ok(changed) => lock_changed |= changed,
            Err(e) => return done_failure(purl, format!("{PNPM_LOCK} surgery failed: {e}")),
        }
    }
    for edit in [edit_packages, edit_pkg_dep_refs] {
        match edit(&mut lines, &ctx, &mut wiring) {
            Ok(changed) => lock_changed |= changed,
            Err(e) => return done_failure(purl, format!("{PNPM_LOCK} surgery failed: {e}")),
        }
    }

    if !pkg_changed && !lock_changed {
        return done(
            already_patched_result(purl, &project_root.join(&rel_tgz), &record.files),
            None,
            warnings,
        );
    }

    if root_dep_hit {
        // The committable-artifact caveat this grammar cannot avoid
        // (module doc §3) — surfaced every wiring run, not just the first.
        warnings.push(VendorWarning::new(
            "vendor_pnpm_legacy_absolute_specifier",
            format!(
                "{} records the override specifier as an absolute path \
                 (pnpm <= 8 absolutizes file: overrides itself), so `pnpm install \
                 --frozen-lockfile` only passes in a checkout at exactly \
                 {} — checkouts at other paths must run `pnpm install --offline \
                 --no-frozen-lockfile` once (the flag matters on CI, where pnpm \
                 defaults --frozen-lockfile on), which installs the vendored \
                 tarball and re-resolves only that specifier line",
                grammar.describe(),
                abs_root
            ),
        ));
    }

    // ── 6. Commit: package.json first, lock second, unwind on failure ────
    let pkg_indent = detect_indent(&String::from_utf8_lossy(&pkg_bytes));
    let new_pkg_bytes = match serialize_json(&pkg, &pkg_indent) {
        Ok(bytes) => bytes,
        Err(e) => return done_failure(purl, format!("cannot serialize {PACKAGE_JSON}: {e}")),
    };
    let lock_out = lines.join("\n");
    if let Err(e) = commit_surfaces(
        project_root,
        pkg_changed.then_some(new_pkg_bytes.as_slice()),
        &pkg_bytes,
        None,
        None,
        false,
        lock_changed.then_some(lock_out.as_bytes()),
    )
    .await
    {
        return done_failure(purl, e);
    }

    // ── 7. Marker + ledger entry ──────────────────────────────────────────
    let marker = VendorMarker::new("npm", &coords.base_purl, record, vendored_at);
    if let Err(e) = write_marker(&project_root.join(&coords.uuid_dir_rel), &marker).await {
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write the informational vendor marker: {e}"),
        ));
    }

    let entry = VendorEntry {
        ecosystem: "npm".to_string(),
        base_purl: coords.base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: rel_tgz,
            sha256: packed.sha256_hex,
            size: Some(packed.size),
            platform_locked: None,
            file_inventory: None,
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: Some(FLAVOR.to_string()),
        uv: None,
        pnpm: Some(PnpmMeta {
            created_overrides_table,
            created_pnpm_table,
            // Legacy never touches pnpm-workspace.yaml (module doc).
            created_workspace_file: false,
            created_workspace_overrides: false,
        }),
        poetry: None,
        pdm: None,
        pipenv: None,
    };
    done(result, Some(entry), warnings)
}

/// Is this legacy-vendored entry still consumed by the lock? `Some(true)`
/// when a `packages:` block is keyed by the entry's artifact path;
/// `Some(false)` when the lock parses as a legacy grammar and carries none
/// (the `overrides:` declaration alone never counts); `None` when
/// undeterminable — callers keep the entry, fail-safe.
pub async fn pnpm_legacy_entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    let text = tokio::fs::read_to_string(project_root.join(PNPM_LOCK))
        .await
        .ok()?;
    match sniff_lock_grammar(&text) {
        Ok(PnpmLockGrammar::V54 | PnpmLockGrammar::V60) => {}
        _ => return None,
    }
    let lines = split_lines(&text);
    let Some((start, end)) = section_bounds(&lines, "packages") else {
        return Some(false);
    };
    let mut i = start + 1;
    while let Some(block) = next_block(&lines, i, end) {
        let ours =
            parse_vendor_path(&block.key).is_some_and(|p| p.eco == "npm" && p.uuid == entry.uuid);
        if ours {
            return Some(true);
        }
        i = block.end;
    }
    Some(false)
}

// ─────────────────────────── pre-flight checks ───────────────────────────

/// Does the lock have a packages entry vendoring can target — the grammar's
/// registry key, or our rekeyed `file:` key (the in-sync / stale-uuid
/// re-run)?
fn lock_has_target_package(lines: &[String], ctx: &Ctx<'_>) -> bool {
    let Some((start, end)) = section_bounds(lines, "packages") else {
        return false;
    };
    let reg_key = ctx.reg_key();
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        if block.key == reg_key || ctx.is_ours(&block.key) {
            return true;
        }
        i = block.end;
    }
    false
}

/// Fail-closed guard against legacy reference forms the surgery does not
/// rewrite: PEER-SUFFIXED dep paths (`/name/version_peer…` in v5.4,
/// `/name@version(peer…)` in v6.0) and ALIASED references (a dep whose
/// recorded value IS the registry dep path). Both would survive the rekey
/// verbatim and dangle — pnpm then hard-rejects the lock — and neither has
/// a pnpm-blessed fixture. Scans the root dep maps and every packages
/// block's dep maps.
fn check_rewritable_refs(lines: &[String], ctx: &Ctx<'_>) -> Result<(), String> {
    let reg_key = ctx.reg_key();
    let key_peer_prefix = format!("{reg_key}{}", ctx.peer_sep());
    let val_peer_prefix = format!("{}{}", ctx.version, ctx.peer_sep());
    let refuse = |what: &str, spelling: &str| {
        Err(format!(
            "{PNPM_LOCK} references {}@{} through {what} (`{spelling}`) that the \
             pair surgery cannot rewrite — vendoring would leave a dangling reference \
             pnpm rejects; this lock shape is not supported yet",
            ctx.name, ctx.version
        ))
    };
    // Root dep maps (v5.4 bare values; v6.0 version: fields).
    for section in ROOT_DEP_SECTIONS {
        let Some((start, end)) = section_bounds(lines, section) else {
            continue;
        };
        let mut k = start + 1;
        while k < end {
            let Some((dep, _repr, rest)) = parse_key_line(&lines[k], 2) else {
                k += 1;
                continue;
            };
            let value = if rest.is_empty() {
                // v6.0 nested shape: read the version: field.
                let (_, ver, f) = dep_field_lines(lines, k + 1, end, 4);
                k = f;
                match ver {
                    Some((_, v)) => v,
                    None => continue,
                }
            } else {
                k += 1;
                rest
            };
            if value == reg_key || value.starts_with(&key_peer_prefix) {
                return refuse("an aliased root dependency", &value);
            }
            if dep == ctx.name && value.starts_with(&val_peer_prefix) {
                return refuse("a peer-suffixed root dependency", &value);
            }
        }
    }
    // packages blocks: peer-suffixed keys + aliased/peer-suffixed dep refs.
    if let Some((start, end)) = section_bounds(lines, "packages") {
        let mut i = start + 1;
        while let Some(block) = next_block(lines, i, end) {
            if block.key.starts_with(&key_peer_prefix) {
                return refuse("a peer-suffixed packages key", &block.key);
            }
            for line in &lines[block.header + 1..block.end] {
                let Some((dep, _repr, rest)) = parse_key_line(line, 6) else {
                    continue;
                };
                if rest == reg_key || rest.starts_with(&key_peer_prefix) {
                    return refuse("an aliased dependency reference", &rest);
                }
                if dep == ctx.name && rest.starts_with(&val_peer_prefix) {
                    return refuse("a peer-suffixed dependency reference", &rest);
                }
            }
            i = block.end;
        }
    }
    Ok(())
}

// ───────────────────────────── lock edits ─────────────────────────────────

/// Locate a dep entry's `specifier:`/`version:` field lines at `indent`
/// starting at `f` (v6.0 root deps use 4; the v9 backend's importers use 8).
#[allow(clippy::type_complexity)]
fn dep_field_lines(
    lines: &[String],
    mut f: usize,
    end: usize,
    indent: usize,
) -> (Option<(usize, String)>, Option<(usize, String)>, usize) {
    let mut spec = None;
    let mut ver = None;
    while f < end {
        let Some((field, _repr, fval)) = parse_key_line(&lines[f], indent) else {
            break;
        };
        match field.as_str() {
            "specifier" => spec = Some((f, fval)),
            "version" => ver = Some((f, fval)),
            _ => {}
        }
        f += 1;
    }
    (spec, ver, f)
}

/// Edit 1: the `overrides:` section — splice our entry into an existing one,
/// or insert the section at pnpm's ROOT_KEYS_ORDER slot (after
/// `lockfileVersion:`/`settings:`, before everything else — byte-identical
/// to the p7/p8 captures).
fn edit_overrides(
    lines: &mut Vec<String>,
    ctx: &Ctx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let our_key = ctx.override_key.to_string();
    let entry_line = format!("  {}: {}", yaml_key(&our_key), ctx.spec);
    if let Some((start, end)) = section_bounds(lines, "overrides") {
        let mut ours = None;
        let mut last_entry = start;
        for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            if let Some((key, repr, rest)) = parse_key_line(line, 2) {
                last_entry = i;
                if key == our_key {
                    ours = Some((i, repr, rest));
                    break;
                }
            }
        }
        if let Some((i, repr, rest)) = ours {
            if rest == ctx.spec {
                return Ok(false); // in sync
            }
            // Ours with a stale uuid (no original), or the user's pinned
            // value being TAKEN OVER (recorded as original).
            let original = (!super::pnpm_lock::is_vendor_value(&rest)).then(|| rest.clone());
            lines[i] = format!("  {}: {}", yaml_key_like(&our_key, &repr), ctx.spec);
            wiring.push(overrides_record(
                &our_key,
                ctx.spec,
                WiringAction::Rewritten,
                original,
            ));
            return Ok(true);
        }
        lines.insert(last_entry + 1, entry_line);
        wiring.push(overrides_record(
            &our_key,
            ctx.spec,
            WiringAction::Added,
            None,
        ));
        return Ok(true);
    }
    // No overrides section: insert at the first top-level key that sorts
    // after it (the captures show it between `lockfileVersion:`/`settings:`
    // and `specifiers:`/`dependencies:`).
    let anchor = lines
        .iter()
        .position(|l| {
            !l.is_empty()
                && !l.starts_with(' ')
                && !OVERRIDES_PRECEDING.contains(&l.split(':').next().unwrap_or(""))
        })
        .unwrap_or(lines.len());
    lines.splice(
        anchor..anchor,
        ["overrides:".to_string(), entry_line, String::new()],
    );
    wiring.push(overrides_record(
        &our_key,
        ctx.spec,
        WiringAction::Added,
        None,
    ));
    Ok(true)
}

/// Edit 2a (v5.4): the flat root dep maps — `name: <version>` moves to
/// `name: file:<rel-tgz>`. Returns `(changed, root_dep_hit)`; `root_dep_hit`
/// is true when the root depends on the package directly (in-sync re-runs
/// included), which is what gates the specifier edit.
fn edit_root_deps_v54(
    lines: &mut [String],
    ctx: &Ctx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<(bool, bool), String> {
    let mut changed = false;
    let mut hit = false;
    for section in ROOT_DEP_SECTIONS {
        let Some((start, end)) = section_bounds(lines, section) else {
            continue;
        };
        for line in lines.iter_mut().take(end).skip(start + 1) {
            let Some((dep, repr, rest)) = parse_key_line(line, 2) else {
                continue;
            };
            if dep != ctx.name {
                continue;
            }
            if rest == ctx.spec {
                hit = true; // in sync
                continue;
            }
            let target = rest == ctx.version || ctx.is_ours(&rest);
            if !target {
                continue;
            }
            hit = true;
            let was_ours = ctx.is_ours(&rest);
            let original = (!was_ours).then(|| Value::String(rest.clone()));
            *line = format!("  {}: {}", yaml_key_like(&dep, &repr), ctx.spec);
            wiring.push(WiringRecord {
                file: PNPM_LOCK.to_string(),
                kind: KIND_LOCK_ROOT_DEP.to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{section}|{dep}")),
                original,
                new: Some(Value::String(ctx.spec.to_string())),
            });
            changed = true;
        }
    }
    Ok((changed, hit))
}

/// Edit 2b (v5.4): the `specifiers:` entry — whatever range the user wrote
/// moves to the machine-absolute `file:` spelling pnpm itself records
/// (module doc §3). Only runs when the root depends on the package.
fn edit_specifier_v54(
    lines: &mut [String],
    ctx: &Ctx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let Some((start, end)) = section_bounds(lines, "specifiers") else {
        return Ok(false);
    };
    for line in lines.iter_mut().take(end).skip(start + 1) {
        let Some((key, repr, rest)) = parse_key_line(line, 2) else {
            continue;
        };
        if key != ctx.name {
            continue;
        }
        if rest == ctx.abs_spec {
            return Ok(false); // in sync
        }
        // Ours at a stale root/uuid (a moved checkout being re-vendored) has
        // no original; anything else is the user's range, recorded.
        let original = (!ctx.is_ours(&rest)).then(|| Value::String(rest.clone()));
        *line = format!("  {}: {}", yaml_key_like(&key, &repr), ctx.abs_spec);
        wiring.push(WiringRecord {
            file: PNPM_LOCK.to_string(),
            kind: KIND_LOCK_SPECIFIER.to_string(),
            action: WiringAction::Rewritten,
            key: Some(key),
            original,
            new: Some(Value::String(ctx.abs_spec.to_string())),
        });
        return Ok(true);
    }
    Ok(false)
}

/// Edit 2 (v6.0): the nested root dep entries — `specifier:` moves to the
/// machine-absolute spelling, `version:` to the relative `file:` spec (both
/// captured verbatim from pnpm 8.15.9). Returns `(changed, root_dep_hit)`.
fn edit_root_deps_v60(
    lines: &mut [String],
    ctx: &Ctx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<(bool, bool), String> {
    let mut changed = false;
    let mut hit = false;
    for section in ROOT_DEP_SECTIONS {
        let Some((start, end)) = section_bounds(lines, section) else {
            continue;
        };
        let mut k = start + 1;
        while k < end {
            let Some((dep, _repr, rest)) = parse_key_line(&lines[k], 2) else {
                k += 1;
                continue;
            };
            if dep != ctx.name || !rest.is_empty() {
                k += 1;
                continue;
            }
            let (spec_f, ver_f, f) = dep_field_lines(lines, k + 1, end, 4);
            if let (Some((si, old_spec)), Some((vi, old_ver))) = (spec_f, ver_f) {
                let target = old_ver == ctx.version || ctx.is_ours(&old_ver);
                if target {
                    hit = true;
                    if old_ver == ctx.spec && old_spec == ctx.abs_spec {
                        k = f;
                        continue; // in sync
                    }
                    let was_ours = ctx.is_ours(&old_ver);
                    lines[si] = format!("    specifier: {}", ctx.abs_spec);
                    lines[vi] = format!("    version: {}", ctx.spec);
                    wiring.push(WiringRecord {
                        file: PNPM_LOCK.to_string(),
                        kind: KIND_LOCK_ROOT_DEP_PAIR.to_string(),
                        action: WiringAction::Rewritten,
                        key: Some(format!("{section}|{dep}")),
                        original: if was_ours {
                            None
                        } else {
                            Some(serde_json::json!({
                                "specifier": old_spec,
                                "version": old_ver,
                            }))
                        },
                        new: Some(serde_json::json!({
                            "specifier": ctx.abs_spec,
                            "version": ctx.spec,
                        })),
                    });
                    changed = true;
                }
            }
            k = f;
        }
    }
    Ok((changed, hit))
}

/// Edit 3: rekey the `packages:` entry to the bare `file:<rel-tgz>` key at
/// its byte-sorted position — resolution replaced with our integrity +
/// tarball, `name:`/`version:` inserted after it, `deprecated:` dropped,
/// everything else verbatim (module doc §4).
fn edit_packages(
    lines: &mut Vec<String>,
    ctx: &Ctx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let (start, end) = section_bounds(lines, "packages").ok_or("no packages: section")?;
    let reg_key = ctx.reg_key();
    let new_key = ctx.new_key();

    // Fail closed on a half-drifted lock carrying BOTH spellings.
    let mut has_registry = false;
    let mut has_ours = false;
    let mut j = start + 1;
    while let Some(block) = next_block(lines, j, end) {
        if block.key == reg_key {
            has_registry = true;
        } else if ctx.is_ours(&block.key) {
            has_ours = true;
        }
        j = block.end;
    }
    if has_registry && has_ours {
        return Err(format!(
            "packages section carries BOTH `{reg_key}` and a `file:…` entry (a \
             half-edited lock); run `pnpm install` to re-resolve it, then re-vendor"
        ));
    }

    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        let is_registry = block.key == reg_key;
        let is_ours_key = ctx.is_ours(&block.key);
        if !is_registry && !is_ours_key {
            i = block.end;
            continue;
        }
        let original_lines: Vec<String> = lines[block.header..block.end].to_vec();
        let expected_resolution = format!(
            "    resolution: {{integrity: {}, tarball: {}}}",
            ctx.integrity, ctx.spec
        );
        if block.key == new_key && original_lines.iter().any(|l| l == &expected_resolution) {
            return Ok(false); // in sync
        }
        let mut new_lines = Vec::with_capacity(original_lines.len() + 2);
        // file: keys are emitted bare by pnpm (never quoted) — captured.
        new_lines.push(format!("  {new_key}:"));
        let mut replaced_resolution = false;
        for line in &original_lines[1..] {
            if let Some((field, _repr, _rest)) = parse_key_line(line, 4) {
                match field.as_str() {
                    "resolution" => {
                        new_lines.push(expected_resolution.clone());
                        new_lines.push(format!("    name: {}", ctx.name));
                        new_lines.push(format!("    version: {}", ctx.version));
                        replaced_resolution = true;
                        continue;
                    }
                    // Re-emitted canonically after resolution / dropped
                    // (pnpm drops `deprecated:` for file: entries — captured).
                    "name" | "version" | "deprecated" => continue,
                    _ => {}
                }
            }
            new_lines.push(line.clone());
        }
        if !replaced_resolution {
            return Err(format!(
                "packages entry `{}` has no resolution line",
                block.key
            ));
        }
        let old_key = block.key.clone();
        swap_block_sorted(lines, "packages", &old_key, &new_key, &new_lines)?;
        wiring.push(WiringRecord {
            file: PNPM_LOCK.to_string(),
            kind: KIND_LOCK_PACKAGE.to_string(),
            action: WiringAction::Rewritten,
            key: Some(old_key),
            original: if is_ours_key {
                None
            } else {
                Some(lines_value(&original_lines))
            },
            new: Some(lines_value(&new_lines)),
        });
        return Ok(true);
    }
    Err(format!("packages entry for {reg_key} vanished mid-rewrite"))
}

/// Edit 4: every OTHER packages block's `dependencies:` /
/// `optionalDependencies:` reference to the exact version — `name:
/// <version>` → `name: file:<rel-tgz>` (captured: the `file:consumer`
/// directory dep's map). `peerDependencies` values are RANGES, never
/// resolutions, so only the two resolution maps are touched.
// &mut Vec keeps both edit functions' signatures unifiable into the one fn
// array `vendor_pnpm_legacy` iterates (edit_packages needs the Vec).
#[allow(clippy::ptr_arg)]
fn edit_pkg_dep_refs(
    lines: &mut Vec<String>,
    ctx: &Ctx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let Some((start, end)) = section_bounds(lines, "packages") else {
        return Ok(false);
    };
    let mut changed = false;
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        let mut in_dep_map = false;
        for line in lines[block.header + 1..block.end].iter_mut() {
            if let Some((field, _repr, rest)) = parse_key_line(line, 4) {
                in_dep_map = rest.is_empty()
                    && matches!(field.as_str(), "dependencies" | "optionalDependencies");
                continue;
            }
            if !in_dep_map {
                continue;
            }
            let Some((dep, _repr, rest)) = parse_key_line(line, 6) else {
                continue;
            };
            if dep != ctx.name {
                continue;
            }
            let target = rest == ctx.version || (rest != ctx.spec && ctx.is_ours(&rest));
            if !target {
                continue;
            }
            let was_ours = ctx.is_ours(&rest);
            *line = format!("      {}: {}", yaml_key(&dep), ctx.spec);
            wiring.push(WiringRecord {
                file: PNPM_LOCK.to_string(),
                kind: KIND_LOCK_PKG_DEP_REF.to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{}|{dep}", block.key)),
                original: if was_ours {
                    None
                } else {
                    Some(Value::String(rest.clone()))
                },
                new: Some(Value::String(ctx.spec.to_string())),
            });
            changed = true;
        }
        i = block.end;
    }
    Ok(changed)
}

/// Replace `old_key`'s block with `new_block` at `new_block`'s byte-sorted
/// position inside a top-level section, preserving the blank-line-separated
/// shape pnpm emits (a rekey can MOVE across the sort boundary — `/`-keys
/// sort before `file:`-keys). pnpm sorts package keys with the `sort-keys`
/// default compare (JS code-unit order), which plain Rust `str` ordering
/// matches for these ASCII keys.
fn swap_block_sorted(
    lines: &mut Vec<String>,
    section: &str,
    old_key: &str,
    new_key: &str,
    new_block: &[String],
) -> Result<(), String> {
    let (start, end) = section_bounds(lines, section).ok_or("section vanished mid-rewrite")?;
    // Collect the section's blocks in order.
    let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
    let mut last_block_end = start + 1;
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        blocks.push((block.key.clone(), lines[block.header..block.end].to_vec()));
        last_block_end = block.end;
        i = block.end;
    }
    // Whatever trails the final block (the file's trailing blank when the
    // section is last) is preserved verbatim.
    let trailer: Vec<String> = lines[last_block_end..end].to_vec();

    let pos = blocks
        .iter()
        .position(|(k, _)| k == old_key)
        .ok_or_else(|| format!("{section} entry `{old_key}` vanished mid-rewrite"))?;
    blocks.remove(pos);
    let insert_at = blocks
        .iter()
        .position(|(k, _)| k.as_str() > new_key)
        .unwrap_or(blocks.len());
    blocks.insert(insert_at, (new_key.to_string(), new_block.to_vec()));

    let mut rebuilt: Vec<String> = Vec::with_capacity(end - start);
    for (_, block_lines) in &blocks {
        rebuilt.push(String::new());
        rebuilt.extend(block_lines.iter().cloned());
    }
    rebuilt.extend(trailer);
    lines.splice(start + 1..end, rebuilt);
    Ok(())
}

// ─────────────────────────────── revert ───────────────────────────────────

/// Undo one legacy-vendored package: restore the recorded pair fragments
/// and remove the artifact dir. Reverse application order; per-record
/// ownership re-checked against the live fragment (drift ⇒ warning, left
/// alone) — same discipline as [`super::pnpm_lock::revert_pnpm`].
pub async fn revert_pnpm_legacy(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    let uuid_dir_rel = match guard_revert_uuid_dir(&entry.uuid) {
        Ok(d) => d,
        Err(outcome) => return outcome,
    };
    // Nothing to replay (a `repair`-reconstructed entry): refuse the
    // artifact removal while the legacy lock still resolves through it —
    // fail-closed, before the dry-run return, exactly like the v9 backend
    // (see [`super::pnpm_lock::guard_unwired_revert`]).
    if entry.wiring.is_empty() {
        let in_use = pnpm_legacy_entry_in_use(entry, project_root).await;
        if let Some(blocked) = guard_unwired_revert(project_root, in_use, &uuid_dir_rel).await {
            return blocked;
        }
    }
    if dry_run {
        return RevertOutcome::ok();
    }
    let mut outcome = RevertOutcome::ok();

    let mut touches_pkg = false;
    let mut touches_lock = false;
    for rec in &entry.wiring {
        if !REVERT_ALLOWLIST.contains(&rec.file.as_str()) {
            outcome.warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for non-allowlisted file `{}`",
                    rec.file
                ),
            ));
            continue;
        }
        if rec.file == PACKAGE_JSON {
            touches_pkg = true;
        } else {
            touches_lock = true;
        }
    }

    let mut lock_lines: Option<Vec<String>> = None;
    if touches_lock {
        match tokio::fs::read_to_string(project_root.join(PNPM_LOCK)).await {
            Ok(text) => lock_lines = Some(split_lines(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{PNPM_LOCK} is missing; lock fragments cannot be restored"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {PNPM_LOCK}: {e}")),
        }
    }
    let mut pkg_state: Option<(Value, String)> = None;
    if touches_pkg {
        match tokio::fs::read(project_root.join(PACKAGE_JSON)).await {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(doc) if doc.is_object() => {
                    let indent = detect_indent(&String::from_utf8_lossy(&bytes));
                    pkg_state = Some((doc, indent));
                }
                _ => {
                    return RevertOutcome::failed(format!(
                        "{PACKAGE_JSON} is not a JSON object; fix it and re-run revert"
                    ))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{PACKAGE_JSON} is missing; the pnpm override cannot be removed"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {PACKAGE_JSON}: {e}")),
        }
    }

    let mut lock_dirty = false;
    let mut pkg_dirty = false;
    for rec in entry.wiring.iter().rev() {
        match rec.file.as_str() {
            PNPM_LOCK => {
                if let Some(lines) = lock_lines.as_mut() {
                    revert_lock_record(
                        lines,
                        rec,
                        &entry.uuid,
                        &mut lock_dirty,
                        &mut outcome.warnings,
                    );
                }
            }
            PACKAGE_JSON => {
                if let Some((doc, _)) = pkg_state.as_mut() {
                    revert_pkg_record(doc, rec, &entry.uuid, &mut pkg_dirty, &mut outcome.warnings);
                }
            }
            _ => {} // warned above
        }
    }

    // Remove the now-empty tables iff vendor created them.
    if let Some((doc, _)) = pkg_state.as_mut() {
        let (created_overrides, created_pnpm) = match &entry.pnpm {
            Some(meta) => (meta.created_overrides_table, meta.created_pnpm_table),
            None => (false, false),
        };
        if let Some(obj) = doc.as_object_mut() {
            if let Some(pnpm_tbl) = obj.get_mut("pnpm").and_then(Value::as_object_mut) {
                if created_overrides
                    && pnpm_tbl
                        .get("overrides")
                        .and_then(Value::as_object)
                        .is_some_and(serde_json::Map::is_empty)
                {
                    pnpm_tbl.shift_remove("overrides");
                    pkg_dirty = true;
                }
            }
            if created_pnpm
                && obj
                    .get("pnpm")
                    .and_then(Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
            {
                obj.shift_remove("pnpm");
                pkg_dirty = true;
            }
        }
    }

    // Reverse write order: lock first, package.json second.
    if lock_dirty {
        if let Some(lines) = &lock_lines {
            if let Err(e) = atomic_write_bytes_preserving_mode(
                &project_root.join(PNPM_LOCK),
                lines.join("\n").as_bytes(),
            )
            .await
            {
                return RevertOutcome::failed(format!("cannot write {PNPM_LOCK}: {e}"));
            }
        }
    }
    if pkg_dirty {
        if let Some((doc, indent)) = &pkg_state {
            let bytes = match serialize_json(doc, indent) {
                Ok(b) => b,
                Err(e) => {
                    return RevertOutcome::failed(format!("cannot serialize {PACKAGE_JSON}: {e}"))
                }
            };
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&project_root.join(PACKAGE_JSON), &bytes).await
            {
                return RevertOutcome::failed(format!("cannot write {PACKAGE_JSON}: {e}"));
            }
        }
    }

    if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
    }
    outcome
}

fn revert_lock_record(
    lines: &mut Vec<String>,
    rec: &WiringRecord,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some(key) = rec.key.as_deref() else {
        warnings.push(drifted(format!(
            "wiring record in {PNPM_LOCK} has no key; left alone"
        )));
        return;
    };
    match rec.kind.as_str() {
        KIND_LOCK_OVERRIDES => revert_overrides_line(lines, rec, key, entry_uuid, dirty, warnings),
        KIND_LOCK_SPECIFIER => {
            revert_value_line(lines, rec, "specifiers", key, entry_uuid, dirty, warnings)
        }
        KIND_LOCK_ROOT_DEP => match key.rsplit_once('|') {
            Some((section, dep)) => {
                revert_value_line(lines, rec, section, dep, entry_uuid, dirty, warnings)
            }
            None => warnings.push(drifted(format!(
                "malformed root-dep key `{key}`; left alone"
            ))),
        },
        KIND_LOCK_ROOT_DEP_PAIR => {
            revert_root_dep_pair(lines, rec, key, entry_uuid, dirty, warnings)
        }
        KIND_LOCK_PACKAGE => revert_package_block(lines, rec, key, entry_uuid, dirty, warnings),
        KIND_LOCK_PKG_DEP_REF => revert_pkg_dep_ref(lines, rec, key, entry_uuid, dirty, warnings),
        other => warnings.push(drifted(format!(
            "unknown wiring kind `{other}` for `{key}`; left alone"
        ))),
    }
}

/// Restore one flat `key: value` line (v5.4 specifiers / root dep maps) to
/// its recorded original. Fail-closed on drift.
fn revert_value_line(
    lines: &mut [String],
    rec: &WiringRecord,
    section: &str,
    dep: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some((start, end)) = section_bounds(lines, section) else {
        warnings.push(drifted(format!(
            "{section} section is gone; `{dep}` not restored"
        )));
        return;
    };
    for line in lines.iter_mut().take(end).skip(start + 1) {
        let Some((k, repr, rest)) = parse_key_line(line, 2) else {
            continue;
        };
        if k != dep {
            continue;
        }
        let ours = Some(rest.as_str()) == rec.new.as_ref().and_then(Value::as_str)
            || parse_vendor_path(&rest).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !ours {
            warnings.push(drifted(format!(
                "{section} entry `{dep}` was changed since vendoring ({rest}); left alone"
            )));
            return;
        }
        let Some(orig) = rec.original.as_ref().and_then(Value::as_str) else {
            warnings.push(drifted(format!(
                "{section} entry `{dep}` has no recorded pre-vendor original; left as-is \
                 (re-run `pnpm install` to re-resolve it)"
            )));
            return;
        };
        *line = format!("  {}: {orig}", yaml_key_like(dep, &repr));
        *dirty = true;
        return;
    }
    warnings.push(drifted(format!(
        "{section} entry `{dep}` no longer exists; nothing to restore"
    )));
}

/// Restore a v6.0 root dep's `specifier:`/`version:` pair.
fn revert_root_dep_pair(
    lines: &mut [String],
    rec: &WiringRecord,
    key: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some((section, dep)) = key.rsplit_once('|') else {
        warnings.push(drifted(format!(
            "malformed root-dep key `{key}`; left alone"
        )));
        return;
    };
    let Some((start, end)) = section_bounds(lines, section) else {
        warnings.push(drifted(format!(
            "{section} section is gone; `{dep}` not restored"
        )));
        return;
    };
    let mut k = start + 1;
    while k < end {
        let Some((d, _repr, rest)) = parse_key_line(&lines[k], 2) else {
            k += 1;
            continue;
        };
        if d != dep || !rest.is_empty() {
            k += 1;
            continue;
        }
        let (spec_f, ver_f, _) = dep_field_lines(lines, k + 1, end, 4);
        let (Some((si, _)), Some((vi, live_ver))) = (spec_f, ver_f) else {
            break;
        };
        let new_ver = rec
            .new
            .as_ref()
            .and_then(|n| n.get("version"))
            .and_then(Value::as_str);
        let ours = Some(live_ver.as_str()) == new_ver
            || parse_vendor_path(&live_ver).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !ours {
            warnings.push(drifted(format!(
                "root dep `{key}` was re-resolved since vendoring ({live_ver}); left alone"
            )));
            return;
        }
        let Some(original) = rec.original.as_ref() else {
            warnings.push(drifted(format!(
                "root dep `{key}` has no recorded pre-vendor original; left as-is \
                 (re-run `pnpm install` to re-resolve it)"
            )));
            return;
        };
        let (Some(orig_spec), Some(orig_ver)) = (
            original.get("specifier").and_then(Value::as_str),
            original.get("version").and_then(Value::as_str),
        ) else {
            warnings.push(drifted(format!("root dep `{key}` original is malformed")));
            return;
        };
        lines[si] = format!("    specifier: {orig_spec}");
        lines[vi] = format!("    version: {orig_ver}");
        *dirty = true;
        return;
    }
    warnings.push(drifted(format!(
        "root dep `{key}` no longer exists; nothing to restore"
    )));
}

/// Restore the rekeyed packages block: locate it by the NEW `file:` key,
/// verify ownership, then reinsert the ORIGINAL block at its byte-sorted
/// position (the rekey moved it across the `/` vs `file:` sort boundary, so
/// an in-place splice would restore it out of order and break byte-identity
/// with the pre-vendor lock).
fn revert_package_block(
    lines: &mut Vec<String>,
    rec: &WiringRecord,
    key: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some(new_lines) = rec.new.as_ref().and_then(value_lines) else {
        warnings.push(drifted(format!(
            "record for `{key}` has no `new` fragment; left alone"
        )));
        return;
    };
    let Some((new_key, _repr, _rest)) = new_lines.first().and_then(|l| parse_key_line(l, 2)) else {
        warnings.push(drifted(format!(
            "record for `{key}` has a malformed fragment"
        )));
        return;
    };
    let Some((start, end)) = section_bounds(lines, "packages") else {
        warnings.push(drifted(format!(
            "packages section is gone; `{key}` not restored"
        )));
        return;
    };
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        if block.key != new_key {
            i = block.end;
            continue;
        }
        let live: Vec<String> = lines[block.header..block.end].to_vec();
        let key_is_ours =
            parse_vendor_path(&new_key).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if live != new_lines && !key_is_ours {
            warnings.push(drifted(format!(
                "packages entry `{new_key}` was changed since vendoring; left alone"
            )));
            return;
        }
        let Some(original) = rec.original.as_ref().and_then(value_lines) else {
            warnings.push(drifted(format!(
                "packages entry `{key}` has no recorded pre-vendor original; left as-is \
                 (re-run `pnpm install` to re-resolve it)"
            )));
            return;
        };
        let Some((orig_key, _r, _v)) = original.first().and_then(|l| parse_key_line(l, 2)) else {
            warnings.push(drifted(format!(
                "packages entry `{key}` original is malformed"
            )));
            return;
        };
        if swap_block_sorted(lines, "packages", &new_key, &orig_key, &original).is_err() {
            warnings.push(drifted(format!(
                "packages entry `{new_key}` vanished mid-restore; left alone"
            )));
            return;
        }
        *dirty = true;
        return;
    }
    warnings.push(drifted(format!(
        "packages entry `{new_key}` no longer exists; nothing to restore"
    )));
}

fn revert_pkg_dep_ref(
    lines: &mut [String],
    rec: &WiringRecord,
    key: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some((pkg_key, dep)) = key.rsplit_once('|') else {
        warnings.push(drifted(format!(
            "malformed dep-ref key `{key}`; left alone"
        )));
        return;
    };
    let Some((start, end)) = section_bounds(lines, "packages") else {
        warnings.push(drifted(
            "packages section is gone; nothing to restore".to_string(),
        ));
        return;
    };
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        if block.key != pkg_key {
            i = block.end;
            continue;
        }
        let mut in_dep_map = false;
        for line in lines[block.header + 1..block.end].iter_mut() {
            if let Some((field, _repr, rest)) = parse_key_line(line, 4) {
                in_dep_map = rest.is_empty()
                    && matches!(field.as_str(), "dependencies" | "optionalDependencies");
                continue;
            }
            if !in_dep_map {
                continue;
            }
            let Some((d, _repr, rest)) = parse_key_line(line, 6) else {
                continue;
            };
            if d != dep {
                continue;
            }
            let ours = Some(rest.as_str()) == rec.new.as_ref().and_then(Value::as_str)
                || parse_vendor_path(&rest).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
            if !ours {
                warnings.push(drifted(format!(
                    "dep ref `{key}` was re-resolved since vendoring ({rest}); left alone"
                )));
                return;
            }
            let Some(original) = rec.original.as_ref().and_then(Value::as_str) else {
                warnings.push(drifted(format!(
                    "dep ref `{key}` has no recorded pre-vendor original; left as-is"
                )));
                return;
            };
            *line = format!("      {}: {original}", yaml_key(dep));
            *dirty = true;
            return;
        }
        break;
    }
    warnings.push(drifted(format!(
        "dep ref `{key}` no longer exists; nothing to restore"
    )));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    use std::collections::HashMap;
    use std::path::PathBuf;

    // ── normalize_canonical_root (pure string level; no Windows host) ─────
    // The synthetic inputs mirror what `std::fs::canonicalize` returns on
    // Windows (verbatim paths); a real Windows CI leg should confirm pnpm
    // 7/8's own emission spelling (tracked residual).

    #[test]
    fn normalize_strips_windows_verbatim_drive_prefix_and_forward_slashes() {
        assert_eq!(
            normalize_canonical_root(r"\\?\C:\Users\dev\proj"),
            "C:/Users/dev/proj"
        );
        // The full specifier shape the lock embeds — never `\\?\`-prefixed,
        // never backslashed.
        let spec = format!(
            "file:{}/{}",
            normalize_canonical_root(r"\\?\C:\proj"),
            ".socket/vendor/npm/uuid/left-pad-1.3.0.tgz"
        );
        assert_eq!(
            spec,
            "file:C:/proj/.socket/vendor/npm/uuid/left-pad-1.3.0.tgz"
        );
    }

    #[test]
    fn normalize_strips_windows_verbatim_unc_prefix() {
        assert_eq!(
            normalize_canonical_root(r"\\?\UNC\srv\share\proj"),
            "//srv/share/proj"
        );
    }

    #[test]
    fn normalize_forward_slashes_plain_windows_shapes() {
        // Non-verbatim spellings (defensive: canonicalize is verbatim on
        // Windows today, but the splice must never emit a backslash).
        assert_eq!(normalize_canonical_root(r"C:\proj"), "C:/proj");
        assert_eq!(
            normalize_canonical_root(r"\\srv\share\proj"),
            "//srv/share/proj"
        );
    }

    #[test]
    fn normalize_leaves_unix_paths_byte_unchanged() {
        assert_eq!(normalize_canonical_root("/home/dev/proj"), "/home/dev/proj");
        // A literal backslash inside a unix file name is NOT a separator
        // and must survive untouched.
        assert_eq!(
            normalize_canonical_root(r"/home/we\ird/proj"),
            r"/home/we\ird/proj"
        );
    }

    /// The uuid the 2026-08-18 legacy spike vendored under (the captured
    /// locks quote it verbatim).
    const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    /// The spike tarball's integrity as the captured after-locks record it.
    /// Our pack pipeline produces a DIFFERENT (deterministic) tarball, so
    /// fixture comparisons substitute the actual integrity for this token —
    /// everything else must be byte-identical.
    const SPIKE_INTEGRITY: &str =
        "sha512-pceaN98Av+E8ugNGKlqbfzvbJWVAdWx3RKI7kc7jPThP6QHZg7c2xbZhCqV8N42Jf9hKWdLW4ZNDnFHQinZ0Hw==";

    /// The absolute project root the captured locks embedded (pnpm <= 8
    /// absolutizes the override specifier). Fixtures carry this token; the
    /// tests substitute the tempdir's canonical path.
    const ROOT_TOKEN: &str = "__PROJECT_ROOT__";

    // ── tool-generated byte-exact oracles ─────────────────────────────────
    // Provenance: matrix/vendor-legacy-spike/{t7,t8} — a `file:` tarball
    // pnpm.overrides entry added to the fixture below, then serialized by
    // REAL `corepack pnpm@7.33.5` / `pnpm@8.15.9` installs (2026-08-18) and
    // proven byte-stable across an install re-run. Only the machine path
    // and the tarball integrity are tokenized.
    const T_BEFORE_PKG: &str = r#"{
  "name": "legacy-spike2",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "consumer": "file:./consumer",
    "left-pad": "1.3.0",
    "left-pad-old": "npm:left-pad@1.2.0"
  }
}
"#;
    const T_AFTER_PKG: &str = r#"{
  "name": "legacy-spike2",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "consumer": "file:./consumer",
    "left-pad": "1.3.0",
    "left-pad-old": "npm:left-pad@1.2.0"
  },
  "pnpm": {
    "overrides": {
      "left-pad@1.3.0": "file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz"
    }
  }
}
"#;
    const T7_BEFORE_LOCK: &str = "lockfileVersion: 5.4

specifiers:
  consumer: file:./consumer
  left-pad: 1.3.0
  left-pad-old: npm:left-pad@1.2.0

dependencies:
  consumer: file:consumer
  left-pad: 1.3.0
  left-pad-old: /left-pad/1.2.0

packages:

  /left-pad/1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()
    dev: false

  /left-pad/1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()
    dev: false

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    version: 1.0.0
    dependencies:
      left-pad: 1.3.0
    dev: false
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
    const T8_BEFORE_LOCK: &str = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  consumer:
    specifier: file:./consumer
    version: file:consumer
  left-pad:
    specifier: 1.3.0
    version: 1.3.0
  left-pad-old:
    specifier: npm:left-pad@1.2.0
    version: /left-pad@1.2.0

packages:

  /left-pad@1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()
    dev: false

  /left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()
    dev: false

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    dependencies:
      left-pad: 1.3.0
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

    // Provenance: matrix/vendor-legacy-spike/x7 — the transitive-ONLY shape
    // (root depends on `consumer` only): pnpm rekeys the packages entry and
    // the consumer's dep ref but touches NO root section — no absolute path
    // appears anywhere.
    const X7_BEFORE_PKG: &str = r#"{
  "name": "legacy-spike3",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "consumer": "file:./consumer"
  }
}
"#;
    const X7_BEFORE_LOCK: &str = "lockfileVersion: 5.4

specifiers:
  consumer: file:./consumer

dependencies:
  consumer: file:consumer

packages:

  /left-pad/1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()
    dev: false

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    version: 1.0.0
    dependencies:
      left-pad: 1.3.0
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

    struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }

        /// The canonical root — what the backend embeds in the absolute
        /// specifier (macOS tempdirs are symlinks; pnpm's process.cwd() and
        /// our canonicalize agree on the physical path).
        fn canon_root(&self) -> PathBuf {
            std::fs::canonicalize(self.root()).unwrap()
        }

        fn installed(&self) -> PathBuf {
            self.root().join("node_modules/left-pad")
        }

        fn rel_tgz(&self) -> String {
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
        }

        async fn read(&self, name: &str) -> String {
            tokio::fs::read_to_string(self.root().join(name))
                .await
                .unwrap()
        }

        /// The actual SRI of the tarball our pack produced.
        async fn actual_integrity(&self) -> String {
            let tgz = tokio::fs::read(self.root().join(self.rel_tgz()))
                .await
                .unwrap();
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tgz))
            )
        }

        /// Instantiate a captured after-lock for THIS tempdir: the spike's
        /// integrity and absolute-root tokens swapped for the live values.
        async fn expected_lock(&self, fixture: &str) -> String {
            fixture
                .replace(SPIKE_INTEGRITY, &self.actual_integrity().await)
                .replace(ROOT_TOKEN, &self.canon_root().display().to_string())
        }

        async fn vendor(&self, dry_run: bool) -> VendorOutcome {
            let blobs = self.root().join(".socket/blobs");
            let sources = PatchSources::blobs_only(&blobs);
            vendor_pnpm_legacy(
                "pkg:npm/left-pad@1.3.0",
                &self.installed(),
                self.root(),
                &self.record,
                &sources,
                "2026-08-18T00:00:00Z",
                dry_run,
                false,
                None,
            )
            .await
        }
    }

    async fn fixture_with(pkg_json: &str, lock: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let installed = root.join("node_modules/left-pad");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(
            installed.join("package.json"),
            br#"{"name":"left-pad","version":"1.3.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(installed.join("index.js"), ORIG_INDEX)
            .await
            .unwrap();

        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
        tokio::fs::write(blobs.join(&after_hash), PATCHED_INDEX)
            .await
            .unwrap();

        tokio::fs::write(root.join(PACKAGE_JSON), pkg_json)
            .await
            .unwrap();
        tokio::fs::write(root.join(PNPM_LOCK), lock).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG_INDEX),
                after_hash,
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-08-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: "test patch".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        };
        Fixture { tmp, record }
    }

    fn expect_done(
        outcome: VendorOutcome,
    ) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match outcome {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => {
                panic!("expected Done, got Refused {code}: {detail}")
            }
        }
    }

    fn expect_refused(outcome: VendorOutcome, want_code: &str) -> String {
        match outcome {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, want_code, "wrong refusal code ({detail})");
                detail
            }
            VendorOutcome::Done { result, .. } => {
                panic!(
                    "expected Refused {want_code}, got Done (success={})",
                    result.success
                )
            }
        }
    }

    // ── oracle transforms ─────────────────────────────────────────────────

    /// pnpm 7 (5.4): the whole captured transform — overrides inserted at
    /// the ROOT_KEYS_ORDER slot, specifier absolutized, root dep + the
    /// consumer's dep ref moved to the relative file: spec, the packages
    /// entry rekeyed ACROSS the `/` vs `file:` sort boundary — byte-identical
    /// to what pnpm 7.33.5 itself serialized.
    #[tokio::test]
    async fn v54_oracle_transform_is_byte_identical_for_both_files() {
        let fx = fixture_with(T_BEFORE_PKG, T7_BEFORE_LOCK).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("success carries a ledger entry");

        assert_eq!(fx.read(PACKAGE_JSON).await, T_AFTER_PKG);
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            fx.expected_lock(T7_AFTER_LOCK).await
        );

        // Ledger facts: flavor + meta (NO workspace surface for legacy).
        assert_eq!(entry.flavor.as_deref(), Some("pnpm-legacy"));
        assert_eq!(
            entry.pnpm,
            Some(PnpmMeta {
                created_overrides_table: true,
                created_pnpm_table: true,
                created_workspace_file: false,
                created_workspace_overrides: false,
            })
        );
        assert_eq!(entry.artifact.path, fx.rel_tgz());
        let kinds: Vec<&str> = entry.wiring.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "pnpm_pkg_override",
                KIND_LOCK_OVERRIDES,
                KIND_LOCK_ROOT_DEP,
                KIND_LOCK_SPECIFIER,
                KIND_LOCK_PACKAGE,
                KIND_LOCK_PKG_DEP_REF,
            ],
            "{:?}",
            entry.wiring
        );
        // The consumer's dep ref is keyed pkg|dep with the bare-version
        // original recorded for revert.
        let dep_ref = entry
            .wiring
            .iter()
            .find(|r| r.kind == KIND_LOCK_PKG_DEP_REF)
            .unwrap();
        assert_eq!(dep_ref.key.as_deref(), Some("file:consumer|left-pad"));
        assert_eq!(dep_ref.original, Some(Value::String("1.3.0".into())));

        // The absolute-specifier portability caveat is surfaced.
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_pnpm_legacy_absolute_specifier"),
            "{warnings:?}"
        );
        // …and no workspace file appeared.
        assert!(!fx.root().join("pnpm-workspace.yaml").exists());
    }

    /// pnpm 8 (6.0): same transform through the nested specifier/version
    /// grammar — byte-identical to what pnpm 8.15.9 itself serialized.
    #[tokio::test]
    async fn v60_oracle_transform_is_byte_identical_for_both_files() {
        let fx = fixture_with(T_BEFORE_PKG, T8_BEFORE_LOCK).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("success carries a ledger entry");

        assert_eq!(fx.read(PACKAGE_JSON).await, T_AFTER_PKG);
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            fx.expected_lock(T8_AFTER_LOCK).await
        );

        assert_eq!(entry.flavor.as_deref(), Some("pnpm-legacy"));
        let kinds: Vec<&str> = entry.wiring.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "pnpm_pkg_override",
                KIND_LOCK_OVERRIDES,
                KIND_LOCK_ROOT_DEP_PAIR,
                KIND_LOCK_PACKAGE,
                KIND_LOCK_PKG_DEP_REF,
            ],
            "{:?}",
            entry.wiring
        );
        let pair = entry
            .wiring
            .iter()
            .find(|r| r.kind == KIND_LOCK_ROOT_DEP_PAIR)
            .unwrap();
        assert_eq!(pair.key.as_deref(), Some("dependencies|left-pad"));
        assert_eq!(
            pair.original,
            Some(serde_json::json!({"specifier": "1.3.0", "version": "1.3.0"}))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_pnpm_legacy_absolute_specifier"),
            "{warnings:?}"
        );
        assert!(!fx.root().join("pnpm-workspace.yaml").exists());
    }

    /// The transitive-ONLY capture (x7): no root section mentions the
    /// package, so nothing absolute is written and no portability warning
    /// fires — overrides + rekeyed packages entry + the consumer's dep ref
    /// only, byte-identical to pnpm 7.33.5's own serialization.
    #[tokio::test]
    async fn v54_transitive_only_writes_no_absolute_specifier() {
        let fx = fixture_with(X7_BEFORE_PKG, X7_BEFORE_LOCK).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry");

        let lock_after = fx.read(PNPM_LOCK).await;
        assert_eq!(lock_after, fx.expected_lock(X7_AFTER_LOCK).await);
        assert!(
            !lock_after.contains(&fx.canon_root().display().to_string()),
            "no machine path may leak into a transitive-only wiring:\n{lock_after}"
        );
        assert!(
            !warnings
                .iter()
                .any(|w| w.code == "vendor_pnpm_legacy_absolute_specifier"),
            "{warnings:?}"
        );
        let kinds: Vec<&str> = entry.wiring.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "pnpm_pkg_override",
                KIND_LOCK_OVERRIDES,
                KIND_LOCK_PACKAGE,
                KIND_LOCK_PKG_DEP_REF,
            ],
            "{:?}",
            entry.wiring
        );
    }

    // ── idempotency + revert ──────────────────────────────────────────────

    /// A second vendor over an in-sync legacy wiring is AlreadyPatched: no
    /// new ledger entry, every byte stable — for BOTH grammars.
    #[tokio::test]
    async fn rerun_is_already_patched_and_byte_stable() {
        for (before_lock, tag) in [(T7_BEFORE_LOCK, "5.4"), (T8_BEFORE_LOCK, "6.0")] {
            let fx = fixture_with(T_BEFORE_PKG, before_lock).await;
            let (result, entry, _) = expect_done(fx.vendor(false).await);
            assert!(result.success, "{tag}: {:?}", result.error);
            assert!(entry.is_some(), "{tag}");
            let pkg_after = fx.read(PACKAGE_JSON).await;
            let lock_after = fx.read(PNPM_LOCK).await;

            let (result, entry, _) = expect_done(fx.vendor(false).await);
            assert!(result.success, "{tag}: {:?}", result.error);
            assert!(entry.is_none(), "{tag}: in-sync rerun records nothing");
            assert!(
                result
                    .files_verified
                    .iter()
                    .all(|v| v.status == VerifyStatus::AlreadyPatched),
                "{tag}"
            );
            assert_eq!(
                fx.read(PACKAGE_JSON).await,
                pkg_after,
                "{tag}: bytes stable"
            );
            assert_eq!(fx.read(PNPM_LOCK).await, lock_after, "{tag}: bytes stable");
        }
    }

    /// Revert restores BOTH files byte-identical (the packages block moves
    /// back across the sort boundary to its original slot) and removes the
    /// artifact dir — for BOTH grammars.
    #[tokio::test]
    async fn revert_round_trips_both_files_and_removes_the_artifact() {
        for (before_lock, tag) in [(T7_BEFORE_LOCK, "5.4"), (T8_BEFORE_LOCK, "6.0")] {
            let fx = fixture_with(T_BEFORE_PKG, before_lock).await;
            let (_, entry, _) = expect_done(fx.vendor(false).await);
            let entry = entry.unwrap();
            let tgz_path = fx.root().join(fx.rel_tgz());
            assert!(tgz_path.exists(), "{tag}");

            // Dry-run revert touches nothing.
            let outcome = revert_pnpm_legacy(&entry, fx.root(), true).await;
            assert!(outcome.success, "{tag}");
            assert!(tgz_path.exists(), "{tag}");
            assert_ne!(fx.read(PNPM_LOCK).await, before_lock, "{tag}");

            let outcome = revert_pnpm_legacy(&entry, fx.root(), false).await;
            assert!(outcome.success, "{tag}: {:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{tag}: {:?}", outcome.warnings);
            assert_eq!(
                fx.read(PACKAGE_JSON).await,
                T_BEFORE_PKG,
                "{tag}: package.json byte-restored"
            );
            assert_eq!(
                fx.read(PNPM_LOCK).await,
                before_lock,
                "{tag}: lock byte-restored"
            );
            assert!(!tgz_path.exists(), "{tag}");
            assert!(
                !fx.root()
                    .join(format!(".socket/vendor/npm/{UUID}"))
                    .exists(),
                "{tag}"
            );
        }
    }

    // ── empty-wiring (reconstructed) revert guard ─────────────────────────

    /// Same P1 regression guard as the v9 backend: a `repair`-reconstructed
    /// entry (empty wiring — the legacy fragments are just as
    /// offline-unrecoverable) must not have its artifact deleted while the
    /// legacy lock still resolves through it; a provably orphaned artifact
    /// still gets removed. Both grammars.
    #[tokio::test]
    async fn empty_wiring_revert_refuses_then_removes_orphan_both_grammars() {
        for (before_lock, tag) in [(T7_BEFORE_LOCK, "5.4"), (T8_BEFORE_LOCK, "6.0")] {
            let fx = fixture_with(T_BEFORE_PKG, before_lock).await;
            let (_, entry, _) = expect_done(fx.vendor(false).await);
            let mut entry = entry.unwrap();
            entry.wiring.clear();
            entry.pnpm = None;
            let tgz_path = fx.root().join(fx.rel_tgz());
            let lock_wired = fx.read(PNPM_LOCK).await;

            // Wired lock (dry and wet): refuse, artifact + lock untouched.
            for dry_run in [true, false] {
                let outcome = revert_pnpm_legacy(&entry, fx.root(), dry_run).await;
                assert!(!outcome.success, "{tag} dry_run={dry_run}: must refuse");
                assert!(
                    outcome
                        .warnings
                        .iter()
                        .any(|w| w.code == "vendor_wiring_unknown_revert_blocked"),
                    "{tag}: {:?}",
                    outcome.warnings
                );
                assert!(tgz_path.exists(), "{tag}: artifact survives the refusal");
                assert_eq!(
                    fx.read(PNPM_LOCK).await,
                    lock_wired,
                    "{tag}: lock untouched"
                );
            }

            // Undeterminable grammar (a v9 re-lock): still fail-closed.
            tokio::fs::write(fx.root().join(PNPM_LOCK), "lockfileVersion: '9.0'\n")
                .await
                .unwrap();
            let outcome = revert_pnpm_legacy(&entry, fx.root(), false).await;
            assert!(!outcome.success, "{tag}: unparseable grammar must refuse");
            assert!(tgz_path.exists(), "{tag}");

            // Pre-vendor lock restored: provably orphaned → removal proceeds.
            tokio::fs::write(fx.root().join(PNPM_LOCK), before_lock)
                .await
                .unwrap();
            let outcome = revert_pnpm_legacy(&entry, fx.root(), false).await;
            assert!(outcome.success, "{tag}: {:?}", outcome.error);
            assert!(
                !fx.root()
                    .join(format!(".socket/vendor/npm/{UUID}"))
                    .exists(),
                "{tag}: orphaned artifact dir removed"
            );
            assert_eq!(
                fx.read(PNPM_LOCK).await,
                before_lock,
                "{tag}: empty wiring replays nothing"
            );
        }
    }

    // ── takeover / conflict ───────────────────────────────────────────────

    /// A user-authored exact-version pin is TAKEN OVER on both surfaces and
    /// restored verbatim on revert (v6.0 grammar; the package.json handling
    /// is grammar-independent and shared with the v9 backend).
    #[tokio::test]
    async fn exact_pin_takeover_round_trips() {
        let pkg_before = r#"{
  "name": "legacy-spike2",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "consumer": "file:./consumer",
    "left-pad": "1.3.0",
    "left-pad-old": "npm:left-pad@1.2.0"
  },
  "pnpm": {
    "overrides": {
      "left-pad": "1.3.0"
    }
  }
}
"#;
        let fx = fixture_with(pkg_before, T8_BEFORE_LOCK).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        // The USER's key carries our spec now (never a second key).
        let pkg: Value = serde_json::from_str(&fx.read(PACKAGE_JSON).await).unwrap();
        assert_eq!(
            pkg["pnpm"]["overrides"]["left-pad"].as_str(),
            Some(format!("file:{}", fx.rel_tgz()).as_str())
        );
        assert!(pkg["pnpm"]["overrides"]
            .as_object()
            .unwrap()
            .get("left-pad@1.3.0")
            .is_none());
        // The lock's overrides section mirrors the taken-over key.
        let lock = fx.read(PNPM_LOCK).await;
        assert!(
            lock.contains(&format!("\n  left-pad: file:{}\n", fx.rel_tgz())),
            "{lock}"
        );

        let outcome = revert_pnpm_legacy(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(fx.read(PACKAGE_JSON).await, pkg_before, "pin restored");
        assert_eq!(fx.read(PNPM_LOCK).await, T8_BEFORE_LOCK);
    }

    /// A same-name override that is NOT an ownable pin refuses fail-closed.
    #[tokio::test]
    async fn conflicting_override_refuses() {
        let pkg = r#"{
  "name": "x",
  "dependencies": { "left-pad": "1.3.0" },
  "pnpm": { "overrides": { "left-pad": "^1.0.0" } }
}
"#;
        let fx = fixture_with(pkg, T8_BEFORE_LOCK).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("left-pad"), "{detail}");
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            T8_BEFORE_LOCK,
            "refusal writes nothing"
        );
    }

    // ── fail-closed refusals ──────────────────────────────────────────────

    /// Both grammars' PEER-SUFFIXED packages keys and ALIASED references
    /// refuse before any write (the rekey cannot follow those spellings —
    /// they would dangle).
    #[tokio::test]
    async fn peer_suffixed_and_aliased_spellings_refuse() {
        // v5.4 peer-suffixed key (`_peer` spelling).
        let lock = T7_BEFORE_LOCK.replace("/left-pad/1.3.0:", "/left-pad/1.3.0_react@18.2.0:");
        let fx = fixture_with(T_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("_react@18.2.0"), "{detail}");
        assert_eq!(fx.read(PNPM_LOCK).await, lock, "refusal writes nothing");

        // v6.0 peer-suffixed key (`(peer)` spelling).
        let lock = T8_BEFORE_LOCK.replace("/left-pad@1.3.0:", "/left-pad@1.3.0(react@18.2.0):");
        let fx = fixture_with(T_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("(react@18.2.0)"), "{detail}");

        // v5.4 aliased root dep resolving to the SAME version (`npm:` spec
        // records the registry dep path as its value).
        let lock = T7_BEFORE_LOCK.replace(
            "  left-pad-old: /left-pad/1.2.0",
            "  left-pad-old: /left-pad/1.3.0",
        );
        let fx = fixture_with(T_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("aliased"), "{detail}");

        // v6.0 aliased root dep, nested grammar.
        let lock = T8_BEFORE_LOCK.replace(
            "    version: /left-pad@1.2.0",
            "    version: /left-pad@1.3.0",
        );
        let fx = fixture_with(T_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("aliased"), "{detail}");
    }

    /// Legacy WORKSPACE locks (importers:) have no captured fixtures —
    /// refuse with the pnpm >= 9 upgrade path.
    #[tokio::test]
    async fn legacy_workspace_lock_refuses() {
        let lock = "lockfileVersion: 5.4

importers:

  .:
    specifiers:
      left-pad: 1.3.0
    dependencies:
      left-pad: 1.3.0

packages:

  /left-pad/1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    dev: false
";
        let fx = fixture_with(T_BEFORE_PKG, lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("WORKSPACE"), "{detail}");
        assert!(detail.contains("pnpm >= 9"), "{detail}");
        assert_eq!(fx.read(PNPM_LOCK).await, lock, "refusal writes nothing");
    }

    /// CRLF and non-allowlisted lock versions refuse with the same codes
    /// and byte-untouched files as the v9 backend.
    #[tokio::test]
    async fn crlf_and_foreign_versions_refuse() {
        let crlf = T7_BEFORE_LOCK.replace('\n', "\r\n");
        let fx = fixture_with(T_BEFORE_PKG, &crlf).await;
        expect_refused(fx.vendor(false).await, "vendor_lockfile_crlf_unsupported");
        assert_eq!(fx.read(PNPM_LOCK).await, crlf, "refusal writes nothing");

        // pnpm 6's 5.3 is NOT allowlisted.
        let old = T7_BEFORE_LOCK.replace("lockfileVersion: 5.4", "lockfileVersion: 5.3");
        let fx = fixture_with(T_BEFORE_PKG, &old).await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );
        assert!(detail.contains("5.3"), "{detail}");

        // A 9.0 lock reaching the legacy backend directly is a router bug —
        // still refused, never mis-spliced.
        let fx = fixture_with(
            T_BEFORE_PKG,
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n",
        )
        .await;
        expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );
    }

    /// No packages entry for the target → the not-found refusal, nothing
    /// written.
    #[tokio::test]
    async fn missing_lock_entry_refuses() {
        let lock = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  ms:
    specifier: 2.1.3
    version: 2.1.3

packages:

  /ms@2.1.3:
    resolution: {integrity: sha512-abc==}
    dev: false
";
        let fx = fixture_with(T_BEFORE_PKG, lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(detail.contains("left-pad@1.3.0"), "{detail}");
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusals write nothing"
        );
    }

    // ── moved checkout / stale absolute specifier ─────────────────────────

    /// Re-vendoring a project whose lock still carries ANOTHER machine's
    /// absolute specifier (a moved checkout) heals just that line to the
    /// current root — the stale path parses as ours through the
    /// `.socket/vendor/` anchor.
    #[tokio::test]
    async fn moved_checkout_revendor_heals_the_absolute_specifier() {
        let fx = fixture_with(T_BEFORE_PKG, T7_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());

        // Simulate the moved checkout: swap the live absolute root for a
        // foreign machine's path.
        let here = fx.canon_root().display().to_string();
        let lock = fx.read(PNPM_LOCK).await;
        let foreign = lock.replace(&here, "/home/other/checkout");
        assert_ne!(lock, foreign, "fixture must embed the absolute root");
        tokio::fs::write(fx.root().join(PNPM_LOCK), &foreign)
            .await
            .unwrap();

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "the heal is a real rewrite, recorded");
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            lock,
            "only the specifier line moves back to this machine's root"
        );
    }

    // ── in-use probe ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn entry_in_use_probe_reads_the_packages_keys() {
        let fx = fixture_with(T_BEFORE_PKG, T7_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        assert_eq!(
            pnpm_legacy_entry_in_use(&entry, fx.root()).await,
            Some(true)
        );

        // Dep removed + re-locked: unused (the overrides declaration alone
        // never counts).
        let relocked = "lockfileVersion: 5.4

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/left-pad-1.3.0.tgz

specifiers:
  consumer: file:./consumer

dependencies:
  consumer: file:consumer

packages:

  file:consumer:
    resolution: {directory: consumer, type: directory}
    name: consumer
    version: 1.0.0
    dev: false
";
        tokio::fs::write(fx.root().join(PNPM_LOCK), relocked)
            .await
            .unwrap();
        assert_eq!(
            pnpm_legacy_entry_in_use(&entry, fx.root()).await,
            Some(false)
        );

        // Unsupported grammar / missing lock: undeterminable, fail-safe.
        tokio::fs::write(fx.root().join(PNPM_LOCK), "lockfileVersion: '9.0'\n")
            .await
            .unwrap();
        assert_eq!(pnpm_legacy_entry_in_use(&entry, fx.root()).await, None);
        tokio::fs::remove_file(fx.root().join(PNPM_LOCK))
            .await
            .unwrap();
        assert_eq!(pnpm_legacy_entry_in_use(&entry, fx.root()).await, None);
    }
}
