//! The hosted unwind leg: restore in-scope hosted pins to their default
//! upstream registry entries. A helper module, not a command: `rollback`,
//! `remove` and `vendor` (a pre-v5 vendored-over-hosted revert) all run it
//! without importing each other.

use socket_patch_core::patch::redirect::upstream::HostedPin;

use crate::args::GlobalArgs;

/// What the hosted leg did.
#[derive(Default)]
pub(crate) struct HostedLegOutcome {
    pub(crate) reverted: Vec<String>,
    pub(crate) failed: Vec<(String, String)>,
    /// Scoped targets whose ecosystem has no per-purl hosted revert.
    pub(crate) unsupported: Vec<String>,
    pub(crate) warnings: Vec<(String, String)>,
    pub(crate) edited_files: std::collections::BTreeSet<String>,
}

/// The patch-server origins that count as hosted, besides Socket's own:
/// the operator's `--patch-server-url` (discovery's allowlist).
pub(crate) fn patch_server_origins(common: &GlobalArgs) -> Vec<String> {
    patch_server_origins_of(common.patch_server_url.as_deref())
}

/// [`patch_server_origins`] from the `--patch-server-url` value itself, for
/// callers that carry it outside a [`GlobalArgs`].
pub(crate) fn patch_server_origins_of(patch_server_url: Option<&str>) -> Vec<String> {
    patch_server_url
        .into_iter()
        .filter(|url| !url.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Restore the in-scope hosted pins to their default upstream registry
/// entries (core `patch::redirect::upstream`): v5 hosted mode keeps no
/// ledger, so each pin's lock entry is re-resolved from the registry, and a
/// pin that cannot be is refused with the `git checkout` remedy.
pub(crate) async fn run_hosted_leg(common: &GlobalArgs, pins: &[HostedPin]) -> HostedLegOutcome {
    use socket_patch_core::patch::redirect::upstream::{
        restore_upstream, PinStatus, RestoreOptions,
    };
    // The pins are the manifest's project's (#745): restore them there.
    let rooted = common.at_project_root();
    let common: &GlobalArgs = &rooted;

    let mut out = HostedLegOutcome::default();
    if pins.is_empty() {
        return out;
    }
    // The vlt nodes the restored pins pin, read before the restore rewrites
    // them: the heal below invalidates the patched installed copies once the
    // registry pins are back.
    let vlt_lock = socket_patch_core::utils::fs::read_regular_to_string(
        &common
            .cwd
            .join(socket_patch_core::constants::npm_family::VLT_LOCK),
    )
    .await
    .ok();
    let origins = patch_server_origins(common);
    let purls: Vec<String> = pins.iter().map(|p| p.purl.clone()).collect();
    let vlt_targets = vlt_lock
        .as_deref()
        .map(|lock| {
            socket_patch_core::patch::redirect::vlt_heal::lock_targets(lock, &origins, &purls)
        })
        .unwrap_or_default();
    let opts = RestoreOptions {
        dry_run: common.dry_run,
        offline: common.offline,
        patch_server_origins: origins,
        // A binary bun.lockb pin refuses with the checkout remedy: its
        // rebuilt registry record is not byte-exact for every lock.
        bun_lockb: false,
    };
    let outcome = restore_upstream(&common.cwd, pins, &opts).await;
    for pin in &outcome.pins {
        match &pin.status {
            PinStatus::Restored => {
                if !common.json && !common.silent {
                    if common.dry_run {
                        println!("Would restore {} to its upstream registry entry", pin.purl);
                    } else {
                        println!("Restored {} to its upstream registry entry", pin.purl);
                    }
                }
                out.reverted.push(pin.purl.clone());
            }
            PinStatus::Refused(why) => {
                // Errors print even under --silent: this drives exit 1.
                if !common.json {
                    eprintln!("Error: {}", crate::ui::sentence_case(why));
                }
                out.failed.push((pin.purl.clone(), why.clone()));
            }
        }
    }
    if let Some(e) = &outcome.flush_error {
        let why = format!("writing the restored lockfiles failed: {e}");
        if !common.json {
            eprintln!("Error: {}", crate::ui::sentence_case(&why));
        }
        out.failed.push(("files".to_string(), why));
    }
    out.warnings.extend(
        outcome
            .warnings
            .iter()
            .map(|(code, detail)| (code.to_string(), detail.clone())),
    );
    out.edited_files
        .extend(outcome.reverted_files.iter().cloned());
    // Bun's hoisted linker keeps the patched copies of the pins it no
    // longer pins (#764): say so, with the install that does reinstall.
    // A dry run says it too, so the preview's reinstall note names
    // `bun install --force` like the real run's.
    if outcome.flush_error.is_none() {
        use socket_patch_core::constants::npm_family::{BUN_LOCK, BUN_LOCKB};
        use socket_patch_core::vendor::bun_lock;
        let bun_purls = outcome
            .restored()
            .filter(|pin| pin.files.iter().any(|f| f == BUN_LOCK || f == BUN_LOCKB));
        let stale =
            bun_lock::stale_hoisted_copies(&common.cwd, bun_purls.map(|p| p.purl.as_str())).await;
        if !stale.is_empty() {
            out.warnings.push((
                "redirect_bun_reinstall_required".to_string(),
                bun_lock::reinstall_advisory(&stale),
            ));
        }
    }
    // PDM, uv and Pipenv keep a same-version install through a plain sync
    // (#477): name the reinstall that restores the upstream bytes.
    if outcome.flush_error.is_none() {
        use crate::commands::pypi_reinstall::{advisory, Tool, HOSTED_CODE};
        let unwound: Vec<(String, Tool)> = outcome
            .restored()
            .filter(|pin| pin.purl.starts_with("pkg:pypi/"))
            .filter_map(|pin| {
                let tool = pin.files.iter().find_map(|f| Tool::of_file(f))?;
                Some((pin.purl.clone(), tool))
            })
            .collect();
        if let Some(detail) = advisory(&common.cwd, &unwound).await {
            out.warnings.push((HOSTED_CODE.to_string(), detail));
        }
    }
    let unwound: Vec<_> = vlt_targets
        .into_iter()
        .filter(|t| out.reverted.iter().any(|p| p == &t.purl))
        .collect();
    out.warnings
        .extend(crate::commands::vlt_heal::rollback_heal(common, &unwound).await);
    out
}
