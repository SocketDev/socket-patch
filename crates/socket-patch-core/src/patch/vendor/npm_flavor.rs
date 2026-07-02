//! Vendor-side npm lockfile flavor probe + router.
//!
//! `vendor` rewires whichever lockfile actually drives the project's
//! installs, so the probe sniffs lockfile CONTENT (not just file presence):
//! a `pnpm-lock.yaml` only routes to the pnpm backend when its
//! `lockfileVersion` is one we have fixtures for, and a `yarn.lock` is only
//! "yarn classic" when it carries the v1 header (a berry lock — top-level
//! `__metadata:` — checksums installs against its cache zips even under the
//! node-modules linker, so vendoring is structurally impossible there).
//!
//! The router fans `vendor`/`revert` out per detected flavor. Today only the
//! package-lock backend ([`super::npm_lock`]) exists; the yarn-classic /
//! pnpm / bun arms refuse with the same stable code the CLI's old layout
//! gate used (`vendor_pkg_manager_unsupported`) and will be replaced by real
//! backends. Reverts fail CLOSED on a flavor this build has no backend for —
//! never guess at another flavor's wiring records.

use std::path::Path;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;

use super::npm_lock;
use super::state::VendorEntry;
use super::{RevertOutcome, VendorOutcome, VendorWarning};

/// Which lockfile flavor drives this project's npm installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmLockFlavor {
    /// `package-lock.json` / `npm-shrinkwrap.json` (npm).
    PackageLock,
    /// `yarn.lock` with the `# yarn lockfile v1` header (yarn classic).
    YarnClassic,
    /// `yarn.lock` with a `__metadata:` key (yarn berry, node-modules linker).
    YarnBerry,
    /// `pnpm-lock.yaml`, lockfileVersion 9.0 (pnpm >= 9).
    Pnpm,
    /// `bun.lock` (bun's text lockfile).
    Bun,
}

impl NpmLockFlavor {
    /// The stable string recorded as [`VendorEntry::flavor`].
    pub fn as_str(self) -> &'static str {
        match self {
            NpmLockFlavor::PackageLock => "package-lock",
            NpmLockFlavor::YarnClassic => "yarn-classic",
            NpmLockFlavor::YarnBerry => "yarn-berry",
            NpmLockFlavor::Pnpm => "pnpm",
            NpmLockFlavor::Bun => "bun",
        }
    }
}

/// Yarn berry Plug'n'Play loaders: packages live inside `.yarn/cache/` zips,
/// so there is nothing on disk to stage and no lockfile entry to rewire.
const PNP_MARKERS: [&str; 3] = [".pnp.cjs", ".pnp.js", ".pnp.loader.mjs"];

/// The pnpm lockfile version the (future) pnpm backend is built against.
const PNPM_SUPPORTED_LOCK_VERSION: &str = "9.0";

/// How many head lines the content sniffs read. The markers sit at the very
/// top of their files (pnpm's `lockfileVersion` is line 1; yarn's v1 header
/// is in the leading comment block; berry's `__metadata:` is the first
/// top-level key after it).
const SNIFF_HEAD_LINES: usize = 5;
const YARN_SNIFF_HEAD_LINES: usize = 30;

/// Every lockfile name the probe knows, grouped into wiring families: the
/// flavor that owns a family wires (or supersedes) every file in it, so only
/// files OUTSIDE the detected family get the multiple-lockfiles warning.
const LOCKFILE_FAMILIES: [(NpmLockFlavor, &[&str]); 4] = [
    // npm itself ignores package-lock.json when npm-shrinkwrap.json exists,
    // so the npm family never warns about its own sibling.
    (
        NpmLockFlavor::PackageLock,
        &["npm-shrinkwrap.json", "package-lock.json"],
    ),
    (NpmLockFlavor::YarnClassic, &["yarn.lock"]),
    (NpmLockFlavor::Pnpm, &["pnpm-lock.yaml"]),
    // bun reads bun.lock when both exist (lockb is the migrated-away binary).
    (NpmLockFlavor::Bun, &["bun.lock", "bun.lockb"]),
];

/// Probe the project root for the lockfile flavor that drives npm installs.
///
/// Decision table, first match wins:
/// 1. a PnP loader file → Err `vendor_yarn_berry_unsupported`;
/// 2. `bun.lock` → Bun; else `bun.lockb` → Err `vendor_bun_lockb_unsupported`;
/// 3. `pnpm-lock.yaml` → head-sniff `lockfileVersion` (only `'9.0'`) → Pnpm,
///    else Err `vendor_lockfile_version_unsupported`;
/// 4. `yarn.lock` → head-sniff: column-0 `__metadata:` → Err
///    `vendor_yarn_berry_unsupported`; `# yarn lockfile v1` → YarnClassic;
///    neither → Err `vendor_lockfile_version_unsupported`;
/// 5. `npm-shrinkwrap.json` | `package-lock.json` → PackageLock;
/// 6. nothing recognized, but `rush.json` present → Err
///    `vendor_rush_unsupported` (Rush's generated-workspace install model
///    can't carry vendor's relative `file:` specs — hosted mode edits the
///    lock in place instead);
/// 7. nothing → Err `vendor_lockfile_missing`.
///
/// `Ok` carries one `vendor_multiple_lockfiles` warning per OTHER known
/// lockfile present (outside the detected flavor's family): installs driven
/// by an unwired lockfile would still install the unpatched registry bytes.
pub async fn detect_npm_lock_flavor(
    project_root: &Path,
) -> Result<(NpmLockFlavor, Vec<VendorWarning>), (&'static str, String)> {
    let exists = |name: &str| {
        let p = project_root.join(name);
        async move { tokio::fs::metadata(&p).await.is_ok() }
    };

    // 1. Yarn berry PnP — checked first because it means packages are not on
    //    disk at all, whatever lockfiles are also lying around.
    for marker in PNP_MARKERS {
        if exists(marker).await {
            return Err((
                "vendor_yarn_berry_unsupported",
                format!(
                    "found `{marker}`: this is a yarn berry Plug'n'Play project — packages \
                     live inside .yarn/cache/ zips, not node_modules/, so there is nothing \
                     vendor could stage or rewire; use `yarn patch <pkg>` instead"
                ),
            ));
        }
    }

    let detected = 'flavor: {
        // 2. bun: the text lockfile is wirable; the legacy binary one is not.
        if exists("bun.lock").await {
            break 'flavor NpmLockFlavor::Bun;
        }
        if exists("bun.lockb").await {
            return Err((
                "vendor_bun_lockb_unsupported",
                "bun.lockb is bun's legacy binary lockfile, which vendor cannot rewrite; \
                 run `bun install --save-text-lockfile`, commit the resulting bun.lock, \
                 and re-run vendor"
                    .to_string(),
            ));
        }

        // 3. pnpm: only lockfileVersion 9.0 has a wiring backend.
        if exists("pnpm-lock.yaml").await {
            sniff_pnpm_lock(project_root).await?;
            break 'flavor NpmLockFlavor::Pnpm;
        }

        // 4. yarn: classic v1 vs berry (node-modules linker), decided by content.
        if exists("yarn.lock").await {
            break 'flavor sniff_yarn_lock(project_root).await?;
        }

        // 5. npm (npm_lock itself prefers the shrinkwrap when both exist).
        if exists("npm-shrinkwrap.json").await || exists("package-lock.json").await {
            break 'flavor NpmLockFlavor::PackageLock;
        }

        // 6. nothing recognizable at the root. A Rush monorepo keeps its
        //    single source-of-truth lock under common/config/rush/ (no root
        //    package.json/lock pair), and its overrides live in
        //    common/config/rush/pnpm-config.json rather than the lockfile —
        //    so vendor's file:-relative rewiring cannot survive Rush's
        //    generated-workspace install (installs run from common/temp).
        //    Point the user at hosted mode, which edits the lock in place.
        if exists("rush.json").await {
            return Err((
                "vendor_rush_unsupported",
                "found rush.json: this is a Rush monorepo — its single pnpm lockfile lives at \
                 common/config/rush/pnpm-lock.yaml, overrides are declared in \
                 common/config/rush/pnpm-config.json (globalOverrides), and `rush install` \
                 copies the lock into common/temp and runs pnpm there, so vendor's relative \
                 file: specs cannot survive the copy; use `socket-patch scan --mode hosted`, \
                 which edits common/config/rush/pnpm-lock.yaml in place"
                    .to_string(),
            ));
        }

        // Nothing recognizable.
        return Err((
            "vendor_lockfile_missing",
            format!(
                "no package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, or \
                 bun.lock at {} — vendoring rewires the lockfile, so one must exist (run \
                 your package manager's install first)",
                project_root.display()
            ),
        ));
    };

    // Multiple lockfiles: warn about every present file the detected
    // flavor's wiring does not cover.
    let mut warnings = Vec::new();
    for (flavor, family) in LOCKFILE_FAMILIES {
        if flavor == detected {
            continue;
        }
        for file in family {
            if exists(file).await {
                warnings.push(VendorWarning::new(
                    "vendor_multiple_lockfiles",
                    format!(
                        "multiple lockfiles present: `{file}` is not wired by the {} vendor \
                         backend — installs driven by `{file}` will still install the \
                         UNPATCHED registry bytes",
                        detected.as_str()
                    ),
                ));
            }
        }
    }
    Ok((detected, warnings))
}

/// `pnpm-lock.yaml` head sniff: the first lines carry
/// `lockfileVersion: '9.0'` (pnpm quotes it; accept double-quoted and bare
/// spellings too). Anything else has no wiring backend.
async fn sniff_pnpm_lock(project_root: &Path) -> Result<(), (&'static str, String)> {
    let text = tokio::fs::read_to_string(project_root.join("pnpm-lock.yaml"))
        .await
        .map_err(|e| {
            (
                "vendor_lockfile_missing",
                format!("cannot read pnpm-lock.yaml: {e}"),
            )
        })?;
    let version = text
        .lines()
        .take(SNIFF_HEAD_LINES)
        .find_map(|line| line.strip_prefix("lockfileVersion:"))
        .map(|rest| rest.trim().trim_matches(['\'', '"']).to_string());
    match version {
        Some(v) if v == PNPM_SUPPORTED_LOCK_VERSION => Ok(()),
        Some(v) => Err((
            "vendor_lockfile_version_unsupported",
            format!(
                "pnpm-lock.yaml has lockfileVersion {v}; only {PNPM_SUPPORTED_LOCK_VERSION} \
                 is supported — re-lock with pnpm >= 9"
            ),
        )),
        None => Err((
            "vendor_lockfile_version_unsupported",
            format!(
                "pnpm-lock.yaml has no lockfileVersion in its first {SNIFF_HEAD_LINES} \
                 lines; only {PNPM_SUPPORTED_LOCK_VERSION} is supported — re-lock with \
                 pnpm >= 9"
            ),
        )),
    }
}

/// `yarn.lock` head sniff: berry locks carry a top-level (column-0)
/// `__metadata:` key; classic v1 locks carry the `# yarn lockfile v1`
/// comment header. Berry wins the check — a berry lock must never be
/// mistaken for classic.
async fn sniff_yarn_lock(project_root: &Path) -> Result<NpmLockFlavor, (&'static str, String)> {
    let text = tokio::fs::read_to_string(project_root.join("yarn.lock"))
        .await
        .map_err(|e| {
            (
                "vendor_lockfile_missing",
                format!("cannot read yarn.lock: {e}"),
            )
        })?;
    let head: Vec<&str> = text.lines().take(YARN_SNIFF_HEAD_LINES).collect();
    // Berry wins the check (it must never be mistaken for classic). The
    // node-modules linker keeps packages on disk for staging, and berry's
    // cache-zip checksum is reproducible from our tarball (berry_zip), so the
    // backend can wire it; PnP (caught earlier by the `.pnp.*` markers) is the
    // only berry layout vendor refuses.
    if head.iter().any(|l| l.starts_with("__metadata:")) {
        return Ok(NpmLockFlavor::YarnBerry);
    }
    if head.iter().any(|l| l.trim() == "# yarn lockfile v1") {
        return Ok(NpmLockFlavor::YarnClassic);
    }
    Err((
        "vendor_lockfile_version_unsupported",
        "yarn.lock carries neither the `# yarn lockfile v1` header nor a berry \
         `__metadata:` key; cannot identify the lockfile version"
            .to_string(),
    ))
}

/// Vendor one npm package through whichever lockfile-flavor backend serves
/// this project (package-lock / yarn classic / yarn berry node-modules /
/// pnpm / bun). Probe refusals (PnP, bun.lockb, unsupported lock versions)
/// surface verbatim; the detected flavor is stamped onto the ledger entry so
/// `revert_npm_any` routes back to the same backend.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_npm_any(
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
    let (flavor, probe_warnings) = match detect_npm_lock_flavor(project_root).await {
        Ok(found) => found,
        Err((code, detail)) => return VendorOutcome::Refused { code, detail },
    };
    let mut outcome = match flavor {
        NpmLockFlavor::PackageLock => {
            npm_lock::vendor_npm(
                purl,
                installed_dir,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        }
        NpmLockFlavor::YarnClassic => {
            super::yarn_classic_lock::vendor_yarn_classic(
                purl,
                installed_dir,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        }
        NpmLockFlavor::YarnBerry => {
            super::yarn_berry_lock::vendor_yarn_berry(
                purl,
                installed_dir,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        }
        NpmLockFlavor::Pnpm => {
            super::pnpm_lock::vendor_pnpm(
                purl,
                installed_dir,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        }
        NpmLockFlavor::Bun => {
            super::bun_lock::vendor_bun(
                purl,
                installed_dir,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        }
    };
    // Probe warnings (e.g. a sibling lockfile that will install UNPATCHED
    // bytes) precede the backend's own; the ledger records which flavor wired
    // the entry so revert routes — and fails closed on a build lacking the
    // backend. Each backend already self-stamps `flavor`; we re-assert it from
    // the probe for belt-and-braces (the values are identical).
    if let VendorOutcome::Done {
        entry, warnings, ..
    } = &mut outcome
    {
        if !probe_warnings.is_empty() {
            let mut merged = probe_warnings;
            merged.append(warnings);
            *warnings = merged;
        }
        if let Some(entry) = entry {
            entry.flavor = Some(flavor.as_str().to_string());
        }
    }
    outcome
}

/// Is this npm-vendored entry still consumed by its lockfile's dependency
/// graph?
///
/// `Some(true)`: the lockfile still resolves something to the entry's
/// artifact. `Some(false)`: the lockfile is present and parses but no
/// resolution references `.socket/vendor/npm/<uuid>/` — the dependency
/// was removed and re-locked, so the vendoring is unused (an override/
/// resolutions DECLARATION alone does not count: pnpm's mirrored
/// `overrides:` section is excluded by the flavor probe, and the other
/// flavors carry no declaration inside the lock at all). `None`: cannot
/// determine (missing lock, unknown flavor) — callers keep the entry,
/// fail-safe. Detached entries are lockfile-invisible BY DESIGN and must
/// never be routed here (the probe would always call them unused).
pub async fn vendored_entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    match entry.flavor.as_deref() {
        Some("pnpm") => super::pnpm_lock::pnpm_entry_in_use(entry, project_root).await,
        // The remaining flavors wire resolutions into the lock itself
        // (resolved URLs / file: ranges / package tuples), so a textual
        // probe for the uuid dir is exact: the path appears iff some
        // resolution still points at the artifact. shrinkwrap wins over
        // package-lock, mirroring the vendor/revert lockfile selection.
        None | Some("package-lock") => {
            lock_text_mentions_uuid(
                project_root,
                &["npm-shrinkwrap.json", "package-lock.json"],
                &entry.uuid,
            )
            .await
        }
        Some("yarn-classic") | Some("yarn-berry") => {
            lock_text_mentions_uuid(project_root, &["yarn.lock"], &entry.uuid).await
        }
        Some("bun") => lock_text_mentions_uuid(project_root, &["bun.lock"], &entry.uuid).await,
        Some(_) => None, // unknown flavor: cannot determine
    }
}

/// First readable lockfile from `names`, probed for the uuid artifact dir.
async fn lock_text_mentions_uuid(project_root: &Path, names: &[&str], uuid: &str) -> Option<bool> {
    let needle = format!(".socket/vendor/npm/{uuid}/");
    for name in names {
        if let Ok(text) = tokio::fs::read_to_string(project_root.join(name)).await {
            return Some(text.contains(&needle));
        }
    }
    None
}

/// Revert one recorded npm vendor entry through the flavor that wired it.
/// Entries from before the flavor field existed (`None`) are package-lock
/// wirings; an unknown flavor fails CLOSED (an older binary must not guess
/// at a newer backend's wiring records).
pub async fn revert_npm_any(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    match entry.flavor.as_deref() {
        None | Some("package-lock") => npm_lock::revert_npm(entry, project_root, dry_run).await,
        Some("yarn-classic") => {
            super::yarn_classic_lock::revert_yarn_classic(entry, project_root, dry_run).await
        }
        Some("yarn-berry") => {
            super::yarn_berry_lock::revert_yarn_berry(entry, project_root, dry_run).await
        }
        Some("pnpm") => super::pnpm_lock::revert_pnpm(entry, project_root, dry_run).await,
        Some("bun") => super::bun_lock::revert_bun(entry, project_root, dry_run).await,
        Some(other) => RevertOutcome::failed(format!(
            "this socket-patch build cannot revert npm vendor flavor `{other}` — upgrade \
             socket-patch and re-run"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::vendor::state::VendorArtifact;
    use std::collections::HashMap;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    async fn touch(root: &Path, name: &str, content: &str) {
        tokio::fs::write(root.join(name), content).await.unwrap();
    }

    async fn detect(
        root: &Path,
    ) -> Result<(NpmLockFlavor, Vec<VendorWarning>), (&'static str, String)> {
        detect_npm_lock_flavor(root).await
    }

    const YARN_V1: &str = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
                           # yarn lockfile v1\n\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n";
    const YARN_BERRY: &str =
        "# This file is generated by running \"yarn install\" inside your project.\n\
                              # Manifest files (package.json) are also used.\n\n\
                              __metadata:\n  version: 8\n  cacheKey: 10\n";
    const PNPM_9: &str = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n";

    #[test]
    fn flavor_strings_are_stable() {
        assert_eq!(NpmLockFlavor::PackageLock.as_str(), "package-lock");
        assert_eq!(NpmLockFlavor::YarnClassic.as_str(), "yarn-classic");
        assert_eq!(NpmLockFlavor::Pnpm.as_str(), "pnpm");
        assert_eq!(NpmLockFlavor::Bun.as_str(), "bun");
    }

    #[tokio::test]
    async fn pnp_loaders_refuse_before_any_lockfile() {
        for marker in PNP_MARKERS {
            let tmp = tempfile::tempdir().unwrap();
            touch(tmp.path(), marker, "/* pnp */").await;
            // Even with a perfectly good package-lock present.
            touch(tmp.path(), "package-lock.json", "{}").await;
            let (code, detail) = detect(tmp.path()).await.unwrap_err();
            assert_eq!(code, "vendor_yarn_berry_unsupported", "{marker}");
            assert!(detail.contains(marker), "{detail}");
            assert!(detail.contains("yarn patch"), "{detail}");
        }
    }

    #[tokio::test]
    async fn bun_lock_routes_and_lockb_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "bun.lock", "{\n  \"lockfileVersion\": 1\n}\n").await;
        let (flavor, warnings) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Bun);
        assert!(warnings.is_empty());

        // bun.lock wins over a stray bun.lockb (no warning for the sibling).
        touch(tmp.path(), "bun.lockb", "binary").await;
        let (flavor, warnings) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Bun);
        assert!(warnings.is_empty(), "{warnings:?}");

        // lockb alone: actionable migration pointer.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "bun.lockb", "binary").await;
        let (code, detail) = detect(tmp.path()).await.unwrap_err();
        assert_eq!(code, "vendor_bun_lockb_unsupported");
        assert!(
            detail.contains("bun install --save-text-lockfile"),
            "{detail}"
        );
    }

    #[tokio::test]
    async fn pnpm_version_sniff() {
        // Quoted (pnpm's own spelling), double-quoted, and bare all accept.
        for head in [
            "lockfileVersion: '9.0'",
            "lockfileVersion: \"9.0\"",
            "lockfileVersion: 9.0",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            touch(
                tmp.path(),
                "pnpm-lock.yaml",
                &format!("{head}\n\nsettings: {{}}\n"),
            )
            .await;
            let (flavor, _) = detect(tmp.path()).await.unwrap();
            assert_eq!(flavor, NpmLockFlavor::Pnpm, "{head}");
        }

        // Older version: named in the error.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '6.0'\n").await;
        let (code, detail) = detect(tmp.path()).await.unwrap_err();
        assert_eq!(code, "vendor_lockfile_version_unsupported");
        assert!(detail.contains("6.0"), "{detail}");
        assert!(detail.contains("pnpm >= 9"), "{detail}");

        // No version line in the head at all.
        let tmp = tempfile::tempdir().unwrap();
        touch(
            tmp.path(),
            "pnpm-lock.yaml",
            "settings:\n  autoInstallPeers: true\n",
        )
        .await;
        let (code, _) = detect(tmp.path()).await.unwrap_err();
        assert_eq!(code, "vendor_lockfile_version_unsupported");
    }

    #[tokio::test]
    async fn yarn_sniff_separates_classic_berry_and_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "yarn.lock", YARN_V1).await;
        let (flavor, _) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::YarnClassic);

        // A berry (node-modules) lock now routes to the YarnBerry backend
        // (cache-zip checksum is reproducible from our tarball — berry_zip).
        // Only PnP (`.pnp.*` markers, caught earlier) stays refused.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "yarn.lock", YARN_BERRY).await;
        let (flavor, _) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::YarnBerry);

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "yarn.lock", "garbage: true\n").await;
        let (code, _) = detect(tmp.path()).await.unwrap_err();
        assert_eq!(code, "vendor_lockfile_version_unsupported");
    }

    #[tokio::test]
    async fn npm_locks_route_to_package_lock_and_nothing_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "package-lock.json", "{}").await;
        assert_eq!(
            detect(tmp.path()).await.unwrap().0,
            NpmLockFlavor::PackageLock
        );

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "npm-shrinkwrap.json", "{}").await;
        let (flavor, warnings) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::PackageLock);
        assert!(warnings.is_empty());

        // Shrinkwrap + package-lock are the same family: no self-warning.
        touch(tmp.path(), "package-lock.json", "{}").await;
        let (_, warnings) = detect(tmp.path()).await.unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");

        let tmp = tempfile::tempdir().unwrap();
        let (code, _) = detect(tmp.path()).await.unwrap_err();
        assert_eq!(code, "vendor_lockfile_missing");
    }

    #[tokio::test]
    async fn rush_json_without_root_lock_refuses_pointing_at_hosted_mode() {
        // A Rush monorepo has no root package.json/lock pair — only
        // rush.json and its generated-workspace lock under common/config.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
        let (code, detail) = detect(tmp.path()).await.unwrap_err();
        assert_eq!(code, "vendor_rush_unsupported");
        // Names the install model and routes to hosted mode.
        assert!(detail.contains("pnpm-config.json"), "{detail}");
        assert!(detail.contains("common/temp"), "{detail}");
        assert!(detail.contains("scan --mode hosted"), "{detail}");
        assert!(
            detail.contains("common/config/rush/pnpm-lock.yaml"),
            "{detail}"
        );
    }

    #[tokio::test]
    async fn rush_check_fires_only_when_nothing_else_matched() {
        // A repo with rush.json AND a recognized root lock is a normal npm
        // project (some tools scaffold a stray rush.json); the flavor probe
        // matches the root lock first — the rush arm only guards the
        // otherwise-missing case.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
        touch(tmp.path(), "package-lock.json", "{}").await;
        let (flavor, _) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::PackageLock);
    }

    #[tokio::test]
    async fn precedence_and_multiple_lockfile_warnings() {
        // bun.lock beats pnpm beats yarn beats package-lock; every unwired
        // lockfile gets its own loud warning.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "bun.lock", "{}").await;
        touch(tmp.path(), "pnpm-lock.yaml", PNPM_9).await;
        touch(tmp.path(), "yarn.lock", YARN_V1).await;
        touch(tmp.path(), "package-lock.json", "{}").await;
        let (flavor, warnings) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Bun);
        let named: Vec<&str> = warnings.iter().map(|w| w.detail.as_str()).collect();
        assert_eq!(warnings.len(), 3, "{named:?}");
        assert!(warnings
            .iter()
            .all(|w| w.code == "vendor_multiple_lockfiles"));
        for file in ["pnpm-lock.yaml", "yarn.lock", "package-lock.json"] {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.detail.contains(file) && w.detail.contains("UNPATCHED")),
                "missing loud warning for {file}: {named:?}"
            );
        }

        // yarn.lock outranks package-lock.json (yarn classic projects often
        // carry an npm-generated stray): yarn classic wins, npm lock warned.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "package-lock.json", "{}").await;
        touch(tmp.path(), "yarn.lock", YARN_V1).await;
        let (flavor, warnings) = detect(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::YarnClassic);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].detail.contains("package-lock.json"),
            "{warnings:?}"
        );
    }

    /// Build a vendorable npm project (installed package, v3 package-lock,
    /// patched blob + record) and return `(tempdir, record)`.
    async fn npm_project() -> (tempfile::TempDir, crate::manifest::schema::PatchRecord) {
        const ORIG: &[u8] = b"module.exports = () => 'orig';\n";
        const PATCHED: &[u8] = b"module.exports = () => 'patched';\n";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pkg = root.join("node_modules/left-pad");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        touch(
            &pkg,
            "package.json",
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        )
        .await;
        tokio::fs::write(pkg.join("index.js"), ORIG).await.unwrap();
        touch(
            root,
            "package-lock.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "fixture", "version": "1.0.0" },
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity": "sha512-orig=="
                    }
                }
            }))
            .unwrap(),
        )
        .await;
        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let after_hash = compute_git_sha256_from_bytes(PATCHED);
        tokio::fs::write(blobs.join(&after_hash), PATCHED)
            .await
            .unwrap();
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG),
                after_hash,
            },
        );
        let record = crate::manifest::schema::PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (tmp, record)
    }

    async fn vendor_any(
        root: &Path,
        record: &crate::manifest::schema::PatchRecord,
    ) -> VendorOutcome {
        let blobs = root.join(".socket/blobs");
        let sources = crate::patch::apply::PatchSources::blobs_only(&blobs);
        vendor_npm_any(
            "pkg:npm/left-pad@1.3.0",
            &root.join("node_modules/left-pad"),
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await
    }

    /// The PackageLock arm: the router runs the npm_lock backend and stamps
    /// the ledger entry's flavor. (Every OTHER known lockfile outranks
    /// package-lock in the decision table, so the PackageLock arm can never
    /// carry probe warnings today — the merge matters once the yarn/pnpm/bun
    /// arms become real backends.)
    #[tokio::test]
    async fn package_lock_arm_stamps_flavor_on_the_ledger_entry() {
        let (tmp, record) = npm_project().await;

        let outcome = vendor_any(tmp.path(), &record).await;
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(warnings.is_empty(), "{warnings:?}");
        let entry = entry.expect("success carries a ledger entry");
        assert_eq!(entry.flavor.as_deref(), Some("package-lock"));
        // The lock really was wired (the backend ran).
        let lock = tokio::fs::read_to_string(tmp.path().join("package-lock.json"))
            .await
            .unwrap();
        assert!(lock.contains(&format!(
            "file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"
        )));
    }

    /// A yarn.lock now ROUTES to the yarn-classic backend (no longer the old
    /// `vendor_pkg_manager_unsupported` gate). With a header-only lock that
    /// has no matching block, the backend's own `vendor_lock_entry_not_found`
    /// proves the dispatch reached it — and nothing is written.
    #[tokio::test]
    async fn yarn_lock_routes_to_the_backend_not_the_old_gate() {
        let (tmp, record) = npm_project().await;
        tokio::fs::remove_file(tmp.path().join("package-lock.json"))
            .await
            .unwrap();
        touch(tmp.path(), "yarn.lock", YARN_V1).await;

        let outcome = vendor_any(tmp.path(), &record).await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("expected the backend's Refused, got {outcome:?}");
        };
        assert_eq!(
            code, "vendor_lock_entry_not_found",
            "yarn.lock must reach the yarn-classic backend, not the removed gate"
        );
        assert_ne!(code, "vendor_pkg_manager_unsupported");
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "refusal writes nothing"
        );
    }

    #[tokio::test]
    async fn revert_routes_by_flavor_and_fails_closed_on_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let mut entry = VendorEntry {
            ecosystem: "npm".into(),
            base_purl: "pkg:npm/left-pad@1.3.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("future-pm".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        };

        // A flavor this build has no backend for: fail closed, name it.
        let outcome = revert_npm_any(&entry, tmp.path(), false).await;
        assert!(!outcome.success);
        assert!(outcome.error.as_deref().unwrap().contains("future-pm"));

        // Every known flavor routes to its backend; with no wiring records and
        // nothing on disk each reverts trivially (None = a pre-flavor ledger).
        for flavor in [
            None,
            Some("package-lock".to_string()),
            Some("yarn-classic".to_string()),
            Some("yarn-berry".to_string()),
            Some("pnpm".to_string()),
            Some("bun".to_string()),
        ] {
            entry.flavor = flavor.clone();
            let outcome = revert_npm_any(&entry, tmp.path(), false).await;
            assert!(outcome.success, "flavor {flavor:?}: {:?}", outcome.error);
        }
    }

    /// One minimal entry per flavor for the in-use probe.
    fn probe_entry(flavor: Option<&str>) -> VendorEntry {
        VendorEntry {
            ecosystem: "npm".into(),
            base_purl: "pkg:npm/left-pad@1.3.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: flavor.map(str::to_string),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    /// The textual flavors: a resolution pointing at the uuid dir means in
    /// use; a clean lock means unused; a missing lock or unknown flavor
    /// cannot be determined (keep, fail-safe).
    #[tokio::test]
    async fn vendored_entry_in_use_textual_flavors() {
        let entry = probe_entry(Some("package-lock"));

        // Missing lock: undeterminable.
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, None);

        // Lock resolves to our artifact: in use.
        touch(
            tmp.path(),
            "package-lock.json",
            &format!(
                "{{\"packages\":{{\"node_modules/left-pad\":{{\"resolved\":\"file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz\"}}}}}}"
            ),
        )
        .await;
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, Some(true));

        // Dep removed + re-locked (no reference left): unused.
        touch(tmp.path(), "package-lock.json", "{\"packages\":{}}").await;
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, Some(false));

        // shrinkwrap wins over package-lock (same precedence as vendoring).
        touch(
            tmp.path(),
            "npm-shrinkwrap.json",
            &format!(
                "{{\"packages\":{{\"node_modules/left-pad\":{{\"resolved\":\"file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz\"}}}}}}"
            ),
        )
        .await;
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, Some(true));

        // yarn flavors probe yarn.lock.
        let entry = probe_entry(Some("yarn-classic"));
        let tmp = tempfile::tempdir().unwrap();
        touch(
            tmp.path(),
            "yarn.lock",
            &format!("left-pad@1.3.0:\n  resolved \"file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz#abc\"\n"),
        )
        .await;
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, Some(true));
        touch(tmp.path(), "yarn.lock", "# yarn lockfile v1\n").await;
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, Some(false));

        // Unknown flavor: undeterminable, fail-safe keep.
        let entry = probe_entry(Some("future-pm"));
        assert_eq!(vendored_entry_in_use(&entry, tmp.path()).await, None);
    }
}
