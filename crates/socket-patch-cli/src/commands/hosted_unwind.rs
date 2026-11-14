//! The hosted unwind leg: restore in-scope hosted pins to their default
//! upstream registry entries. A helper module, not a command: `rollback`,
//! `remove`, scan's withdrawn-patch restore and `vendor` (a pre-v5
//! vendored-over-hosted revert) all run it without importing each other.

use socket_patch_core::patch::redirect::upstream::HostedPin;

use crate::args::GlobalArgs;

/// What the hosted leg did.
#[derive(Default)]
pub(crate) struct HostedLegOutcome {
    /// The pins restored (on a dry run: that would be). None when writing
    /// the restored files failed: that restore is all or nothing.
    pub(crate) reverted: Vec<String>,
    /// `(purl, why)` per refused pin, and `(WRITE_FAILURE_KEY, why)` when
    /// writing the restored files failed.
    pub(crate) failed: Vec<(String, String)>,
    pub(crate) warnings: Vec<(String, String)>,
    /// The files the leg changed (on a dry run: would change). After a
    /// write failure, only the ones it could not put back.
    pub(crate) edited_files: std::collections::BTreeSet<String>,
    /// The restored gems whose installed copies the leg brought back to the
    /// upstream gem (on a dry run: would), with none left on the patched
    /// build: they need no reinstall.
    pub(crate) refreshed_installs: std::collections::BTreeSet<String>,
}

/// The [`HostedLegOutcome::failed`] key of a failure that is not one pin's:
/// writing the restored files failed (rollback's artifact-level
/// `hosted_write_failed` event).
pub(crate) const WRITE_FAILURE_KEY: &str = "files";

impl HostedLegOutcome {
    /// Why the project is left half restored, if it is: writing the
    /// restored files failed part-way and not every file already written
    /// could be put back. The reason names each such file and its state.
    pub(crate) fn half_applied(&self) -> Option<&str> {
        if self.edited_files.is_empty() {
            return None;
        }
        self.failed
            .iter()
            .find(|(key, _)| key == WRITE_FAILURE_KEY)
            .map(|(_, why)| why.as_str())
    }
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

/// The gem leg of the unwind's installed-tree care (the "Gem stale-install
/// guard" section of CLI_CONTRACT.md, in the upstream direction): refresh
/// what [`crate::commands::gem_refresh::after_restore`] may, then report.
/// A human run prints what was refreshed as progress lines and gets ONE
/// warning for the gems still on their patched build; `--json` carries a
/// note per refreshed materialization and a warning per stale one. An
/// archive in Bundler's cache dir the refresh replaced no longer needs the
/// restore's own `upstream_gem_stale_cache` advisory.
///
/// Only this leg refreshes, because only its callers leave the gem on its
/// upstream entry. A hosted → vendored takeover restores the pins itself
/// (`restore_upstream`, on its way to the `path:` source) and must stay
/// off this path: Bundler loads the vendored copy from then on, so the
/// installed one is an unused leftover that a refresh would only make
/// unpatched, at the cost of a registry download vendored mode never needs.
async fn refresh_restored_gems(
    common: &GlobalArgs,
    outcome: &socket_patch_core::patch::redirect::upstream::RestoreOutcome,
    out: &mut HostedLegOutcome,
) {
    use crate::commands::gem_refresh::{after_restore, Direction};
    use socket_patch_core::patch::redirect::upstream::GEM_STALE_CACHE;

    let restored: Vec<String> = outcome
        .restored()
        .filter(|pin| pin.purl.starts_with("pkg:gem/"))
        .map(|pin| pin.purl.clone())
        .collect();
    if restored.is_empty() {
        return;
    }
    let refresh = after_restore(common, &restored, &outcome.staged_text).await;
    out.warnings.retain(|(code, detail)| {
        code != GEM_STALE_CACHE
            || !refresh
                .replaced_archives
                .iter()
                .any(|path| detail.contains(&path.display().to_string()))
    });
    out.refreshed_installs = refresh.refreshed_installs;
    let report = refresh.report;
    if common.json {
        out.warnings.extend(
            report
                .warnings
                .into_iter()
                .map(|(code, detail)| (code.to_string(), detail)),
        );
        return;
    }
    if !common.silent {
        for line in &report.progress {
            println!("{line}");
        }
    }
    if let Some(summary) = &report.summary {
        out.warnings.push((
            Direction::Upstream.stale_code().to_string(),
            summary.paragraph(),
        ));
    }
}

/// Restore the in-scope hosted pins to their default upstream registry
/// entries (core `patch::redirect::upstream`): v5 hosted mode keeps no
/// ledger, so each pin's lock entry is re-resolved from the registry, and a
/// pin that cannot be is refused with the `git checkout` remedy.
///
/// `lanes` is the lane table the rows of a Bazel root's owned index are
/// undone through: `bazel_gate::commands::PRODUCTION` from a command.
pub(crate) async fn run_hosted_leg(
    common: &GlobalArgs,
    pins: &[HostedPin],
    lanes: &socket_patch_core::bazel::model::LaneTable,
) -> HostedLegOutcome {
    use socket_patch_core::patch::redirect::upstream::{PinStatus, RestoreOptions};
    // The pins are the manifest's project's: restore them there.
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
    let live_before = if common.dry_run {
        Default::default()
    } else {
        socket_patch_core::vendor::bun_lock::live_user_patch_keys(&common.cwd).await
    };
    // Under a Bazel root the pins are restored together with what the
    // root's owned index records for them (a lock only Bazel reads, a
    // value derived from a lock), and the run names the command that
    // refreshes what Bazel derived. Elsewhere this is `restore_upstream`.
    let outcome = crate::bazel_gate::commands::restore(common, pins, &opts, lanes).await;
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
            // Not restored: the one write failure below covers them all.
            PinStatus::Unwritten => {}
        }
    }
    if let Some(e) = &outcome.flush_error {
        let why = if common.dry_run {
            format!("writing the restored lockfiles would fail: {e}")
        } else {
            format!("writing the restored lockfiles failed: {e}")
        };
        if !common.json {
            eprintln!("Error: {}", crate::ui::sentence_case(&why));
        }
        out.failed.push((WRITE_FAILURE_KEY.to_string(), why));
        // Only what the failed flush could not put back was edited.
        out.edited_files
            .extend(outcome.half_applied.iter().cloned());
    } else {
        out.edited_files
            .extend(outcome.reverted_files.iter().cloned());
    }
    out.warnings.extend(
        outcome
            .warnings
            .iter()
            .map(|(code, detail)| (code.to_string(), detail.clone())),
    );
    // Bun's hoisted linker keeps the patched copies of the pins it no
    // longer pins: say so, with the install that does reinstall.
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
        // A `bun patch` keyed by a hosted URL the restore took out of the
        // lock stops applying.
        if !common.dry_run {
            let live_after = bun_lock::live_user_patch_keys(&common.cwd).await;
            for key in live_before.difference(&live_after) {
                out.warnings.push((
                    "redirect_bun_patched_dependency_dropped".to_string(),
                    bun_lock::dropped_patch_detail(key),
                ));
            }
        }
        // pip, PDM, uv and Pipenv keep a same-version install through a
        // plain install or sync: name the reinstall that restores the
        // upstream bytes.
        use crate::commands::pypi_reinstall::{advisory, Tool, Unwound, HOSTED_CODE};
        let unwound: Vec<Unwound> = outcome
            .restored()
            .filter(|pin| pin.purl.starts_with("pkg:pypi/"))
            .filter_map(|pin| {
                let tool = Tool::of_files(&pin.files)?;
                Some(Unwound::new(&pin.purl, tool, &pin.files))
            })
            .collect();
        if let Some(detail) = advisory(&common.cwd, &unwound).await {
            out.warnings.push((HOSTED_CODE.to_string(), detail));
        }
        // Bundler keeps a gem it already holds whatever source the lock
        // names: bring the project's installed copies and cached archives
        // of the restored gems back to the upstream gem, and say what is
        // still the patched build.
        refresh_restored_gems(common, &outcome, &mut out).await;
    }
    let unwound: Vec<_> = vlt_targets
        .into_iter()
        .filter(|t| out.reverted.iter().any(|p| p == &t.purl))
        .collect();
    out.warnings
        .extend(crate::commands::vlt_heal::rollback_heal(common, &unwound).await);
    out
}
