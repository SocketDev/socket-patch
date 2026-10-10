pub(crate) mod agent_download;
pub mod apply;
pub(crate) mod bun_preflight;
pub(crate) mod composer_hints;
pub(crate) mod context;
pub(crate) mod fetch_stage;
pub mod get;
pub mod hosted_bundle;
pub(crate) mod hosted_unwind;
pub mod list;
pub(crate) mod lock_cli;
pub mod remove;
pub mod repair;
pub mod rollback;
pub mod scan;
pub mod update;
pub mod vendor;
pub(crate) mod vendored_backend;
pub mod vex;
pub(crate) mod vex_consumed;
pub(crate) mod vex_sources;
pub(crate) mod vlt_heal;
pub(crate) mod vlt_preflight;

use std::path::Path;

/// The documented name of hosted mode (lockfile pins to Socket-hosted
/// patched packages; no ledger). Shared by scan's `redirectState` envelope
/// block and list's hosted event labels so the two surfaces can never
/// drift.
pub(crate) const HOSTED_MODE_LABEL: &str = "hosted";

/// The documented name of the mode whose ledger is
/// `.socket/vendor/state.json` — `list`'s label for a vendored patch
/// record. Vendored mode is manifest-free: every `scan`/`get --mode
/// vendored` entry is written `detached: true` with its embedded patch
/// `record`, so the ledger is the only place those records live.
pub(crate) const VENDORED_MODE_LABEL: &str = "vendored";

/// Whether the run's target includes the `--cwd` project's own
/// lockfile-backed state: its hosted pins and its vendor ledger. Global
/// scope (`--global` / `--global-prefix`) targets globally installed
/// packages, which have no project lockfile (CLI_CONTRACT.md, Mode
/// resolution). The project a global run happens to start in is not its
/// target, so that project's hosted and vendored state is never rewired,
/// unwound, or consulted for ownership of a global copy.
pub(crate) fn project_state_in_scope(common: &crate::args::GlobalArgs) -> bool {
    !common.is_global()
}

/// The mode a `scan`/`get` run with no `--mode` uses for the project
/// (CLI_CONTRACT.md, Mode resolution): the mode the project's own patch
/// state already records, so a bare run never converts the project to
/// another mode. Hosted is the default for a project with no state.
///
/// * a non-empty vendor ledger (`.socket/vendor/state.json`) → vendored;
/// * a manifest (`.socket/manifest.json`) holding patches → agent;
/// * neither → hosted (hosted mode keeps no ledger of its own);
/// * both → `Err(usage message)`: the run cannot tell which mode to keep,
///   so it asks for an explicit `--mode` rather than guess.
///
/// Both stores are read from [`GlobalArgs::project_root`], so a
/// `--manifest-path` into another project consults that project's ledger,
/// never a ledger left in `--cwd`.
///
/// A manifest record the ledger already covers (same key or base purl) is
/// vendored state, not agent evidence: the documented `get --save-only`
/// then `vendor` flow leaves the record in the manifest beside its ledger
/// entry, and that project is vendored.
///
/// An unreadable or malformed vendor ledger counts as vendored, so the
/// vendored flow reports the corruption instead of a hosted takeover
/// running over it; with no readable ledger no manifest record counts as
/// covered. Likewise an unreadable or malformed manifest counts as agent
/// state, so the agent flow reports it rather than a bare run converting
/// the project to hosted mode (#1088). A missing manifest is no evidence.
/// Only called in project scope.
///
/// [`GlobalArgs::project_root`]: crate::args::GlobalArgs::project_root
pub(crate) async fn mode_from_project_state(
    common: &crate::args::GlobalArgs,
) -> Result<scan::ScanMode, String> {
    let manifest_path = common.resolved_manifest_path();
    let project_root = common.project_root();
    let (manifest, vendor) = tokio::join!(
        socket_patch_core::manifest::operations::read_manifest(&manifest_path),
        socket_patch_core::vendor::load_state(&project_root),
    );
    let vendored_keys = match &vendor {
        Ok(state) => state.purl_keys(),
        Err(_) => Default::default(),
    };
    let vendored = !matches!(&vendor, Ok(state) if state.entries.is_empty());
    let agent = match &manifest {
        Ok(Some(m)) => m
            .patches
            .keys()
            .any(|purl| !socket_patch_core::vendor::state::purl_keys_cover(&vendored_keys, purl)),
        Ok(None) => false,
        Err(_) => true,
    };
    match (vendored, agent) {
        (true, true) => Err(format!(
            "{} holds both agent-mode patches ({}) and vendored patches \
             (.socket/vendor/state.json): pass --mode agent, --mode vendored or \
             --mode hosted to choose the mode this run uses",
            project_root.display(),
            manifest_path.display(),
        )),
        (true, false) => Ok(scan::ScanMode::Vendored),
        (false, true) => Ok(scan::ScanMode::Agent),
        (false, false) => Ok(scan::ScanMode::Hosted),
    }
}

/// The stderr note a human-mode `scan`/`get` prints when it kept a
/// non-default mode from the project's state.
pub(crate) fn kept_mode_note(mode: scan::ScanMode) -> Option<String> {
    let store = match mode {
        scan::ScanMode::Hosted => return None,
        scan::ScanMode::Vendored => ".socket/vendor/state.json",
        scan::ScanMode::Agent => "the manifest",
    };
    Some(format!(
        "Note: using --mode {} because {store} already holds {} patches; pass \
         --mode explicitly to switch modes",
        mode.cli_name(),
        mode.cli_name(),
    ))
}

/// The usage error for a mode that rewires the project (`hosted`,
/// `vendored`) under global scope, or `None` when `mode` is allowed.
/// Shared by `scan` and `get` so both refuse the same combinations with
/// the same wording.
pub(crate) fn global_mode_conflict(
    common: &crate::args::GlobalArgs,
    mode: scan::ScanMode,
) -> Option<String> {
    if project_state_in_scope(common) {
        return None;
    }
    let why = match mode {
        scan::ScanMode::Agent => return None,
        scan::ScanMode::Hosted => "redirect",
        scan::ScanMode::Vendored => "wire vendored artifacts into",
    };
    Some(format!(
        "{} cannot be used with --mode {}: global installs have no project lockfile to {why}",
        global_scope_flag(common),
        mode.cli_name(),
    ))
}

/// The usage-error code of [`foreign_manifest_conflict`].
pub(crate) const FOREIGN_MANIFEST_PROJECT: &str = "manifest_path_foreign_project";

/// The usage error for a form that writes `--cwd`'s lockfiles and vendor
/// ledger (`scan`/`get --mode hosted|vendored`, `vendor` other than
/// `--check`) when `--manifest-path` resolves into another project, or
/// `None`. Every store a run reads or writes belongs to ONE project — the
/// manifest's ([`crate::args::GlobalArgs::project_root`]; #745) — and these
/// forms rewire the lockfiles of `--cwd`, so there is no single project to
/// write. `what` names the refused form (`--mode vendored`, `vendor`).
pub(crate) fn foreign_manifest_conflict(
    common: &crate::args::GlobalArgs,
    what: &str,
) -> Option<String> {
    if !common.manifest_project_is_foreign() {
        return None;
    }
    let root = common.project_root();
    Some(format!(
        "{what} cannot be used with a --manifest-path in another project: it rewires the \
         lockfiles and vendor ledger of --cwd ({}), but the manifest belongs to {}. Run it \
         from the manifest's project (--cwd {}) or drop --manifest-path",
        common.cwd.display(),
        root.display(),
        root.display(),
    ))
}

/// The flag that put a run in global scope, as usage errors name it
/// (`SOCKET_GLOBAL` / `SOCKET_GLOBAL_PREFIX` set the same fields).
pub(crate) fn global_scope_flag(common: &crate::args::GlobalArgs) -> &'static str {
    if common.global {
        "--global"
    } else {
        "--global-prefix"
    }
}

/// Lockfile discovery of `root` (core `vex::discover`): the hosted and
/// vendored patch references its lockfiles and configs wire, with hosted
/// references counted on Socket's public patch server plus the operator's
/// `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. The one input to
/// every ledger-liveness verdict ([`Discovery::redirect_record_live`] /
/// [`Discovery::vendor_entry_live`]): `vex`'s attestation gates and `scan`'s
/// cross-mode takeover and hosted-wiring advisories read the lockfiles the
/// same way.
///
/// [`Discovery::redirect_record_live`]: socket_patch_core::vex::discover::Discovery::redirect_record_live
/// [`Discovery::vendor_entry_live`]: socket_patch_core::vex::discover::Discovery::vendor_entry_live
pub(crate) async fn discover_wiring(
    common: &crate::args::GlobalArgs,
    root: &Path,
) -> socket_patch_core::vex::discover::Discovery {
    #[cfg(test)]
    DISCOVERIES.with(|n| n.set(n.get() + 1));
    socket_patch_core::vex::discover_patched_refs_with(root, &discover_options(common)).await
}

#[cfg(test)]
thread_local! {
    /// How many times this thread ran [`discover_wiring`]: discovery walks
    /// every lockfile, so tests pin the paths that must not repeat it.
    pub(crate) static DISCOVERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// [`discover_wiring`] of the snapshot's root, reading through `snapshot`.
pub(crate) async fn discover_wiring_in(
    common: &crate::args::GlobalArgs,
    snapshot: &socket_patch_core::vendor::lock_inventory::DiskSnapshot<'_>,
) -> socket_patch_core::vex::discover::Discovery {
    socket_patch_core::vex::discover_patched_refs_in(snapshot, &discover_options(common)).await
}

fn discover_options(common: &crate::args::GlobalArgs) -> socket_patch_core::vex::DiscoverOptions {
    socket_patch_core::vex::DiscoverOptions {
        patch_server_origins: hosted_unwind::patch_server_origins(common),
    }
}

/// The project's hosted wiring as raw inventory (core
/// [`HostedInventory`]): the attributable pins management commands act on,
/// and the contested wiring they must refuse around. VEX eligibility is a
/// separate judgment over the same discovery.
///
/// [`HostedInventory`]: socket_patch_core::patch::redirect::upstream::HostedInventory
pub(crate) async fn hosted_inventory(
    common: &crate::args::GlobalArgs,
    root: &Path,
) -> socket_patch_core::patch::redirect::upstream::HostedInventory {
    socket_patch_core::patch::redirect::upstream::HostedInventory::of(
        &discover_wiring(common, root).await,
    )
}

/// [`hosted_state_from_pins`] over a fresh [`discover_wiring`] of `root`
/// (the unit tests' load-then-derive entry point).
#[cfg(test)]
pub(crate) async fn hosted_state_from_lockfiles(
    common: &crate::args::GlobalArgs,
    root: &Path,
) -> socket_patch_core::patch::redirect::RedirectState {
    hosted_state_from_pins(
        &socket_patch_core::patch::redirect::upstream::HostedPin::all(
            &discover_wiring(common, root).await,
        ),
    )
}

/// The project's hosted state, v5-style: v5 hosted mode keeps no ledger,
/// so the hosted pins [`discover_wiring`] finds in the lockfiles are the
/// whole record. Shaped as a [`RedirectState`] for the readers that classify
/// hosted against vendored state (one uuid-only record per pinned purl, no
/// edits) — it is never persisted. A purl pinned to several uuids
/// (different lockfiles) keeps the first.
///
/// [`RedirectState`]: socket_patch_core::patch::redirect::RedirectState
pub(crate) fn hosted_state_from_pins(
    pins: &[socket_patch_core::patch::redirect::upstream::HostedPin],
) -> socket_patch_core::patch::redirect::RedirectState {
    let mut state = socket_patch_core::patch::redirect::RedirectState::new();
    for pin in pins {
        state.records.entry(pin.purl.clone()).or_insert_with(|| {
            socket_patch_core::manifest::schema::PatchRecord {
                uuid: pin.uuid.clone(),
                exported_at: String::new(),
                files: Default::default(),
                vulnerabilities: Default::default(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            }
        });
    }
    state
}

/// Read-only lenient view of a loaded vendor ledger (`.socket/vendor/state.json`):
/// missing → an empty ledger; malformed/unreadable → `None` with the
/// problem surfaced on stderr unless `silent`. A read-only
/// consumer (`list`) degrades a broken ledger to nothing-to-consult but
/// must say so, while every path that writes or attests from it fails
/// closed instead.
pub(crate) fn vendor_state_lenient(
    loaded: &std::io::Result<socket_patch_core::vendor::state::VendorState>,
    silent: bool,
) -> Option<&socket_patch_core::vendor::state::VendorState> {
    match loaded {
        Ok(state) => Some(state),
        Err(e) => {
            if !silent {
                eprintln!(
                    "Warning: unreadable vendor ledger ({e}); its vendored patches are not listed"
                );
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const LEDGER_PURL: &str = "pkg:npm/left-pad@1.3.0";
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    /// A one-entry vendor ledger at `root` for `LEDGER_PURL`, checked to
    /// load, so a test never passes on the malformed-ledger branch.
    async fn write_ledger(root: &Path) {
        let path = root.join(socket_patch_core::vendor::VENDOR_STATE_REL);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let ledger = serde_json::json!({
            "version": 1,
            "entries": {
                LEDGER_PURL: {
                    "ecosystem": "npm",
                    "basePurl": LEDGER_PURL,
                    "uuid": UUID,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                        "sha256": "ab".repeat(32),
                    },
                    "wiring": [],
                }
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&ledger).unwrap()).unwrap();
        let loaded = socket_patch_core::vendor::load_state(root)
            .await
            .expect("the fixture ledger must load");
        assert_eq!(loaded.entries.len(), 1);
    }

    /// An agent manifest at `<root>/.socket/manifest.json` holding `purls`.
    fn write_manifest(root: &Path, purls: &[&str]) {
        let dir = root.join(".socket");
        std::fs::create_dir_all(&dir).unwrap();
        let patches: serde_json::Map<String, serde_json::Value> = purls
            .iter()
            .map(|purl| {
                (
                    purl.to_string(),
                    serde_json::json!({
                        "uuid": UUID,
                        "exportedAt": "2026-01-01T00:00:00Z",
                        "files": {},
                        "vulnerabilities": {},
                        "description": "fixture",
                        "license": "MIT",
                        "tier": "free",
                    }),
                )
            })
            .collect();
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
        )
        .unwrap();
    }

    fn args(cwd: &Path, manifest_path: &str) -> crate::args::GlobalArgs {
        crate::args::GlobalArgs {
            cwd: PathBuf::from(cwd),
            manifest_path: manifest_path.to_string(),
            ..crate::args::GlobalArgs::default()
        }
    }

    /// `get --save-only` then `vendor` leaves the vendored record in the
    /// manifest beside its ledger entry: that project is vendored, not
    /// ambiguous.
    #[tokio::test]
    async fn manifest_records_the_ledger_covers_are_vendored_state() {
        let tmp = tempfile::tempdir().unwrap();
        write_ledger(tmp.path()).await;
        write_manifest(tmp.path(), &[LEDGER_PURL]);
        let mode = mode_from_project_state(&args(tmp.path(), ".socket/manifest.json")).await;
        assert_eq!(mode, Ok(scan::ScanMode::Vendored));
    }

    /// A manifest record the ledger does not cover is agent state, so a
    /// project holding it beside a ledger is still ambiguous.
    #[tokio::test]
    async fn an_uncovered_manifest_record_beside_a_ledger_is_ambiguous() {
        let tmp = tempfile::tempdir().unwrap();
        write_ledger(tmp.path()).await;
        write_manifest(tmp.path(), &[LEDGER_PURL, "pkg:npm/is-odd@3.0.1"]);
        let mode = mode_from_project_state(&args(tmp.path(), ".socket/manifest.json")).await;
        let err = mode.expect_err("agent and vendored state together");
        assert!(err.contains("--mode"), "{err}");
    }

    /// A malformed manifest is agent state: a bare run must not take the
    /// project over in hosted mode, so the agent flow reports the error.
    #[tokio::test]
    async fn a_malformed_manifest_is_not_a_hosted_project() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
        std::fs::write(tmp.path().join(".socket/manifest.json"), b"{ not json").unwrap();
        let common = args(tmp.path(), ".socket/manifest.json");
        assert_eq!(
            mode_from_project_state(&common).await,
            Ok(scan::ScanMode::Agent)
        );

        // Beside a vendor ledger it is ambiguous, not silently vendored.
        write_ledger(tmp.path()).await;
        assert!(mode_from_project_state(&common).await.is_err());
    }

    /// With `--manifest-path` into another project, the ledger is read
    /// from that project, not from `--cwd`: a ledger left in `--cwd` is
    /// not consulted, and the other project's ledger is.
    #[tokio::test]
    async fn the_ledger_is_read_from_the_manifest_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("cwd");
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let manifest_path = other.join(".socket/manifest.json");
        let manifest_path = manifest_path.to_str().unwrap();

        // A ledger in --cwd only: the manifest's project is agent.
        write_ledger(&cwd).await;
        write_manifest(&other, &["pkg:npm/is-odd@3.0.1"]);
        let mode = mode_from_project_state(&args(&cwd, manifest_path)).await;
        assert_eq!(mode, Ok(scan::ScanMode::Agent));

        // The manifest's project vendored the record: vendored.
        write_ledger(&other).await;
        write_manifest(&other, &[LEDGER_PURL]);
        let mode = mode_from_project_state(&args(&cwd, manifest_path)).await;
        assert_eq!(mode, Ok(scan::ScanMode::Vendored));
    }
}
