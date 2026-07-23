//! `socket-patch --update` — self-update from GitHub Releases.
//!
//! The public surface is the root `--update` flag; a first-class-looking
//! but hidden `self-update` subcommand is the parse target the argv
//! rewrite in `lib.rs` forwards to (same mechanism as the bare-UUID→`get`
//! shortcut). Policy lives here — offline gate, managed-channel refusal,
//! confirmation, envelope, exit codes — while the download/verify/swap
//! machinery lives in `socket_patch_core::update`.

use clap::Args;
use socket_patch_core::update::{
    self as core_update, asset_name_for_target, channel_label, current_version, detect_channel,
    fetch_latest_version, is_newer, upgrade_hint, ChannelEnv, InstallChannel, UpdateEndpoints,
    UpdateError, UpdateRequest, UpdateTimeouts,
};

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::lock_cli::error_envelope;
use crate::json_envelope::{Command, Envelope, PatchAction, PatchEvent};
use crate::output;

/// The target triple this binary was compiled for, embedded by `build.rs`.
/// Passed into core as a parameter so core stays testable with arbitrary
/// triples.
pub const UPDATE_TARGET: &str = env!("SOCKET_PATCH_TARGET");

#[derive(Args)]
pub struct UpdateArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Exact version to install instead of the latest release (e.g.
    /// `socket-patch --update 3.4.0`). An explicit pin installs that
    /// version even if it is older than the current one. Also settable via
    /// SOCKET_PATCH_VERSION — the same pin install.sh and the gem/composer
    /// launchers honor.
    ///
    /// Not named `version`: under `propagate_version` clap already owns a
    /// `--version` arg id on every subcommand, and the collision panics at
    /// parser construction.
    #[arg(
        value_name = "VERSION",
        env = "SOCKET_PATCH_VERSION",
        value_parser = parse_version_pin,
    )]
    pub pin_version: Option<String>,

    /// Proceed even when this install looks package-manager-managed
    /// (npm/pip/cargo/Homebrew/launcher), and reinstall even when already
    /// on the requested version.
    #[arg(
        long,
        env = "SOCKET_FORCE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub force: bool,
}

/// Validate a version pin at parse time (typos become clap usage errors,
/// exit 2). Tolerates a leading `v` like install.sh; stores the bare form.
fn parse_version_pin(raw: &str) -> Result<String, String> {
    let bare = raw.trim().trim_start_matches('v');
    semver::Version::parse(bare)
        .map(|v| v.to_string())
        .map_err(|e| format!("not a valid version: {e}"))
}

/// Emit an error in the mode-appropriate shape and return the exit code.
fn fail(args: &UpdateArgs, code: &str, message: &str) -> i32 {
    if args.common.json {
        let env = error_envelope(Command::Update, args.common.dry_run, code, message);
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
    }
    1
}

pub async fn run(args: UpdateArgs) -> i32 {
    apply_env_toggles(&args.common);
    let quiet = args.common.json || args.common.silent;

    // 1. Offline gate first — strict airgap refuses before any client
    //    exists, and --force does not bypass it (matching scan/get).
    if args.common.offline {
        return fail(
            &args,
            "offline",
            "update requires network access to check releases and cannot run with \
             --offline/SOCKET_OFFLINE (strict airgap)",
        );
    }

    // 2. Where is this binary, and who manages it? Zero network so far.
    let install_path = match core_update::resolve_install_path() {
        Ok(p) => p,
        Err(e) => return fail(&args, e.error_code(), &e.to_string()),
    };
    let channel = detect_channel(&install_path, &ChannelEnv::from_env());
    if channel != InstallChannel::Standalone {
        if args.force {
            if !quiet {
                eprintln!(
                    "Warning: this install is managed by {} — its next upgrade will overwrite \
                     the updated binary.",
                    channel_label(channel)
                );
            }
        } else {
            return fail(
                &args,
                "managed_install",
                &format!(
                    "this socket-patch binary ({}) is managed by {}; update it with `{}` \
                     instead, or pass --force to replace it in place",
                    install_path.display(),
                    channel_label(channel),
                    upgrade_hint(channel)
                ),
            );
        }
    }

    // 3. Resolve what to install.
    let endpoints = UpdateEndpoints::from_env();
    let timeouts = UpdateTimeouts::from_env();
    let current = current_version();
    let (target_version, pinned) = match &args.pin_version {
        Some(pin) => match semver::Version::parse(pin) {
            Ok(v) => (v, true),
            // Unreachable via clap (value_parser validates), but the env
            // path deserves a real error over a panic.
            Err(e) => return fail(&args, "check_failed", &format!("invalid version pin: {e}")),
        },
        None => match fetch_latest_version(&endpoints, &timeouts).await {
            Ok(v) => (v, false),
            Err(e) => return fail(&args, e.error_code(), &e.to_string()),
        },
    };

    // Whatever we just learned, remember it for the passive notifier
    // (best-effort; an explicit check refreshes the once-a-day cache).
    if !pinned {
        let mut state = core_update::load_state();
        state.last_check_at = Some(core_update::unix_now());
        state.latest_seen = Some(target_version.to_string());
        let _ = core_update::save_state(&state).await;
    }

    let asset = asset_name_for_target(UPDATE_TARGET);

    let update_available = if pinned {
        target_version != current
    } else {
        is_newer(&target_version, &current)
    };

    // 4. --dry-run is check-only, and it reports FIRST — whether or not an
    //    update is available, the probe's contract is one metadata request,
    //    zero downloads, zero mutation, exit 0, with `updateAvailable` in
    //    the details (scripts branch on it).
    if args.common.dry_run {
        let msg = if update_available {
            format!("Update available: socket-patch {current} → {target_version} (dry run; not installed)")
        } else if args.force {
            format!("Would reinstall socket-patch {target_version} (dry run; --force)")
        } else {
            format!("socket-patch {current} is already the latest version.")
        };
        if args.common.json {
            let mut env = Envelope::new(Command::Update);
            env.dry_run = true;
            env.record(
                PatchEvent::artifact(PatchAction::Verified)
                    .with_reason("update_check", &msg)
                    .with_details(serde_json::json!({
                        "current": current.to_string(),
                        "latest": target_version.to_string(),
                        "updateAvailable": update_available,
                        "target": UPDATE_TARGET,
                        "asset": asset,
                        "path": install_path.display().to_string(),
                    })),
            );
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("{msg}");
        }
        return 0;
    }

    // 5. Already there? (An explicit pin may go up OR down; `latest` never
    //    downgrades — a dev build newer than the newest release is left
    //    alone.) --force reinstalls regardless.
    if !update_available && !args.force {
        let msg = if pinned {
            format!("socket-patch is already version {current}.")
        } else {
            format!("socket-patch {current} is already the latest version.")
        };
        if args.common.json {
            let mut env = Envelope::new(Command::Update);
            env.dry_run = args.common.dry_run;
            env.record(
                PatchEvent::artifact(PatchAction::Skipped)
                    .with_reason("already_latest", &msg)
                    .with_details(serde_json::json!({
                        "current": current.to_string(),
                        "latest": target_version.to_string(),
                    })),
            );
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("{msg}");
        }
        return 0;
    }

    // 6. Confirm (auto-proceeds under --yes/--json; declines default-yes
    //    only on an explicit "n").
    let prompt = format!("Update socket-patch {current} → {target_version}?");
    if !output::confirm(&prompt, true, args.common.yes, args.common.json) {
        if !quiet {
            eprintln!("Update cancelled.");
        }
        return 1;
    }

    // 7. Lock → download → verify → stage → sanity → swap (core).
    let outcome = match core_update::perform_update(UpdateRequest {
        target_triple: UPDATE_TARGET,
        version: &target_version,
        install_path: &install_path,
        endpoints: &endpoints,
        timeouts: &timeouts,
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            let mut message = e.to_string();
            if let UpdateError::PermissionDenied { .. } = e {
                message.push_str(
                    "; re-run with elevated privileges (e.g. `sudo socket-patch --update`) \
                     or re-run the installer",
                );
            }
            return fail(&args, e.error_code(), &message);
        }
    };

    if !quiet {
        for warning in &outcome.warnings {
            eprintln!("Warning: {warning}");
        }
    }

    if args.common.json {
        let mut env = Envelope::new(Command::Update);
        env.record(
            PatchEvent::artifact(PatchAction::Downloaded).with_details(serde_json::json!({
                "asset": outcome.asset,
                "bytes": outcome.archive_bytes,
                "sha256": outcome.archive_sha256,
            })),
        );
        env.record(
            PatchEvent::artifact(PatchAction::Updated).with_details(serde_json::json!({
                "from": current.to_string(),
                "to": target_version.to_string(),
                "path": outcome.installed_path.display().to_string(),
                "target": UPDATE_TARGET,
            })),
        );
        println!("{}", env.to_pretty_json());
    } else if !args.common.silent {
        println!(
            "Updated socket-patch {current} → {target_version} ({})",
            outcome.installed_path.display()
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_pin_parses_and_normalizes() {
        assert_eq!(parse_version_pin("3.4.0").unwrap(), "3.4.0");
        assert_eq!(parse_version_pin("v3.4.0").unwrap(), "3.4.0");
        assert_eq!(parse_version_pin(" v3.4.0 ").unwrap(), "3.4.0");
        assert!(parse_version_pin("latest").is_err());
        assert!(parse_version_pin("3.4").is_err());
        assert!(parse_version_pin("").is_err());
    }

    // The 3 CI platforms plus the common dev hosts must map onto real
    // release assets; an exotic self-built target legitimately won't, so
    // the pin is gated to the platforms release.yml actually builds.
    #[cfg(any(
        target_os = "macos",
        target_os = "windows",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn compiled_target_is_a_release_triple() {
        const RELEASE_TRIPLES: &[&str] = &[
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
            "x86_64-pc-windows-msvc",
            "i686-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "aarch64-linux-android",
            "arm-unknown-linux-gnueabihf",
            "arm-unknown-linux-musleabihf",
            "i686-unknown-linux-gnu",
            "i686-unknown-linux-musl",
        ];
        assert!(
            RELEASE_TRIPLES.contains(&UPDATE_TARGET),
            "compiled target {UPDATE_TARGET} has no release asset — update \
             release.yml (and this list) or the asset mapping"
        );
    }
}
