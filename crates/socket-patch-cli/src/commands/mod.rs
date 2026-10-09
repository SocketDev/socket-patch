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
pub(crate) mod pypi_reinstall;
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
