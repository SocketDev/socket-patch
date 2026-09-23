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
    fetch_latest_version, is_newer, upgrade_hint_for, ChannelEnv, InstallChannel, UpdateEndpoints,
    UpdateError, UpdateRequest, UpdateTimeouts,
};

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::lock_cli::error_envelope;
use crate::json_envelope::{Command, Envelope, PatchAction, PatchEvent, RunWarning};

/// The target triple this binary was compiled for, embedded by `build.rs`.
/// Passed into core as a parameter so core stays testable with arbitrary
/// triples.
pub const UPDATE_TARGET: &str = env!("SOCKET_PATCH_TARGET");

// `socket-patch --update --help` must describe the public `--update`
// flag, not the hidden `self-update` subcommand it is rewritten to. The
// variant's doc comment in lib.rs (developer notes) becomes the
// subcommand's `about` and is applied after these attributes, so the help
// text is fixed through a template that never renders `{about}`.
// (The usage line still reads `socket-patch self-update ...`: lib.rs's
// `update_help_shows_self_update_help` pins that; overriding it to
// `socket-patch --update [VERSION] [OPTIONS]` belongs with that test.)
#[derive(Args)]
#[command(
    help_template = "Update socket-patch itself to the latest release (or to VERSION).\n\n\
                     {usage-heading} {usage}\n\n{all-args}{after-help}"
)]
pub struct UpdateArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Exact version to install instead of the latest release (e.g.
    /// `socket-patch --update 3.4.0`). An explicit pin installs that
    /// version even if it is older than the current one. Also settable via
    /// SOCKET_PATCH_VERSION — the same pin install.sh and the gem launcher
    /// honor.
    //
    // Not named `version`: under `propagate_version` clap already owns a
    // `--version` arg id on every subcommand, and the collision panics at
    // parser construction.
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
/// The envelope keeps the message verbatim; the human line capitalizes it
/// (`Error: Could not check for updates: ...`).
fn fail(args: &UpdateArgs, code: &str, message: &str) -> i32 {
    if args.common.json {
        let env = error_envelope(Command::Update, args.common.dry_run, code, message);
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {}", capitalize_first(message));
    }
    1
}

/// `"could not ..."` → `"Could not ..."` (char-safe; empty stays empty).
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The no-op message when there is nothing to install: a pin already
/// satisfied, the latest release already running, or a build newer than
/// the latest release (`latest` never downgrades).
fn already_message(current: &semver::Version, target: &semver::Version, pinned: bool) -> String {
    if pinned {
        format!("socket-patch is already version {current}.")
    } else if target < current {
        format!("socket-patch {current} is newer than the latest release ({target}).")
    } else {
        format!("socket-patch {current} is already the latest version.")
    }
}

/// The `--dry-run` report. `change` is whether a real run would install
/// `target` (a pin may point below `current`: that is a downgrade, not an
/// "update available").
fn dry_run_message(
    current: &semver::Version,
    target: &semver::Version,
    pinned: bool,
    force: bool,
    change: bool,
) -> String {
    if change && target < current {
        format!("Would downgrade socket-patch {current} \u{2192} {target} (dry run; not installed)")
    } else if change {
        format!(
            "Update available: socket-patch {current} \u{2192} {target} (dry run; not installed)"
        )
    } else if force {
        format!("Would reinstall socket-patch {target} (dry run; --force)")
    } else {
        already_message(current, target, pinned)
    }
}

/// The confirmation question before installing.
fn confirm_prompt(current: &semver::Version, target: &semver::Version) -> String {
    if target < current {
        format!("Downgrade socket-patch {current} \u{2192} {target}?")
    } else if target == current {
        format!("Reinstall socket-patch {target}?")
    } else {
        format!("Update socket-patch {current} \u{2192} {target}?")
    }
}

/// The line after a declined [`confirm_prompt`], naming the same action.
fn cancelled_message(current: &semver::Version, target: &semver::Version) -> &'static str {
    if target < current {
        "Downgrade cancelled."
    } else if target == current {
        "Reinstall cancelled."
    } else {
        "Update cancelled."
    }
}

/// The result line after a successful install, naming the same action as
/// [`confirm_prompt`].
fn installed_message(current: &semver::Version, target: &semver::Version, path: &std::path::Path) -> String {
    let path = path.display();
    if target < current {
        format!("Downgraded socket-patch {current} \u{2192} {target} ({path})")
    } else if target == current {
        format!("Reinstalled socket-patch {target} ({path})")
    } else {
        format!("Updated socket-patch {current} \u{2192} {target} ({path})")
    }
}

/// The status line shown while the release downloads and installs.
fn download_status(target: &semver::Version, asset: &str) -> String {
    format!("Downloading socket-patch {target} ({asset})...")
}

/// Record a non-fatal advisory: stderr for humans, `warnings[]` on the
/// envelope for machines. `--json` suppresses the stderr line (stdout is
/// the machine channel and stderr must stay clean), so a warning that only
/// ever went to stderr would vanish entirely for JSON consumers — the
/// managed-install override in particular is the "your package manager
/// will silently revert this" signal, and a silent override is the bug
/// class the channel suite exists to catch. Same stderr-or-envelope
/// split `vendor`/`remove` use for their run-level advisories (the
/// rendered stderr line keeps update's own `Warning: <detail>` wording).
fn note_warning(warnings: &mut Vec<RunWarning>, quiet: bool, code: &str, detail: String) {
    if !quiet {
        eprintln!("Warning: {}", capitalize_first(&detail));
    }
    warnings.push(RunWarning {
        code: code.to_string(),
        detail,
    });
}

pub async fn run(args: UpdateArgs) -> i32 {
    apply_env_toggles(&args.common);
    let quiet = args.common.json || args.common.silent;
    // Advisories collected as the run proceeds; attached to whichever
    // envelope is emitted (the managed-install one lands long before the
    // envelope exists).
    let mut warnings: Vec<RunWarning> = Vec::new();

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
    let hint = upgrade_hint_for(channel, &install_path);
    if channel != InstallChannel::Standalone {
        if args.force {
            note_warning(
                &mut warnings,
                quiet,
                "managed_install_override",
                format!(
                    "this install is managed by {} — its next upgrade will overwrite \
                     the updated binary.",
                    channel_label(channel)
                ),
            );
        } else {
            return fail(
                &args,
                "managed_install",
                &format!(
                    "this socket-patch binary ({}) is managed by {}; update it with `{}` \
                     instead, or pass --force to replace it in place",
                    install_path.display(),
                    channel_label(channel),
                    hint
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
        let msg = dry_run_message(
            &current,
            &target_version,
            pinned,
            args.force,
            update_available,
        );
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
            env.warnings = warnings;
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
        let msg = already_message(&current, &target_version, pinned);
        if args.common.json {
            // `--dry-run` returned above, so this envelope's `dryRun` is
            // always `Envelope::new`'s `false`.
            let mut env = Envelope::new(Command::Update);
            env.record(
                PatchEvent::artifact(PatchAction::Skipped)
                    .with_reason("already_latest", &msg)
                    .with_details(serde_json::json!({
                        "current": current.to_string(),
                        "latest": target_version.to_string(),
                    })),
            );
            env.warnings = warnings;
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("{msg}");
        }
        return 0;
    }

    // 6. Confirm (auto-proceeds under --yes/--json; an empty answer takes
    //    the default yes, while "n" or Ctrl-D/EOF declines).
    let prompt = confirm_prompt(&current, &target_version);
    if !crate::ui::confirm(&prompt, true, &args.common) {
        if !quiet {
            eprintln!("{}", cancelled_message(&current, &target_version));
        }
        return 1;
    }

    // 7. Lock → download → verify → stage → sanity → swap (core). The
    //    download can take a while (300 s budget), so a terminal gets a
    //    status line instead of a silent pause after the prompt.
    let mut status = crate::ui::StatusLine::stderr(args.common.json, args.common.silent);
    status.set(download_status(&target_version, &asset));
    let result = core_update::perform_update(UpdateRequest {
        target_triple: UPDATE_TARGET,
        version: &target_version,
        install_path: &install_path,
        endpoints: &endpoints,
        timeouts: &timeouts,
    })
    .await;
    status.finish();
    let outcome = match result {
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

    for warning in &outcome.warnings {
        note_warning(&mut warnings, quiet, "update_warning", warning.clone());
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
        env.warnings = warnings;
        println!("{}", env.to_pretty_json());
    } else if !args.common.silent {
        println!(
            "{}",
            installed_message(&current, &target_version, &outcome.installed_path)
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn already_message_covers_pin_latest_and_newer_than_latest() {
        assert_eq!(
            already_message(&v("4.0.0"), &v("4.0.0"), true),
            "socket-patch is already version 4.0.0."
        );
        assert_eq!(
            already_message(&v("4.0.0"), &v("4.0.0"), false),
            "socket-patch 4.0.0 is already the latest version."
        );
        assert_eq!(
            already_message(&v("4.0.0"), &v("3.0.0"), false),
            "socket-patch 4.0.0 is newer than the latest release (3.0.0)."
        );
    }

    #[test]
    fn dry_run_message_matches_the_real_run() {
        // Pinned to the running version: same wording as the wet no-op.
        assert_eq!(
            dry_run_message(&v("4.0.0"), &v("4.0.0"), true, false, false),
            "socket-patch is already version 4.0.0."
        );
        // A pin below the running version is a downgrade.
        assert_eq!(
            dry_run_message(&v("4.0.0"), &v("3.0.0"), true, false, true),
            "Would downgrade socket-patch 4.0.0 \u{2192} 3.0.0 (dry run; not installed)"
        );
        assert_eq!(
            dry_run_message(&v("4.0.0"), &v("9.9.9"), false, false, true),
            "Update available: socket-patch 4.0.0 \u{2192} 9.9.9 (dry run; not installed)"
        );
        assert_eq!(
            dry_run_message(&v("4.0.0"), &v("4.0.0"), false, true, false),
            "Would reinstall socket-patch 4.0.0 (dry run; --force)"
        );
        // Running a build newer than the latest release.
        assert_eq!(
            dry_run_message(&v("4.0.0"), &v("3.0.0"), false, false, false),
            "socket-patch 4.0.0 is newer than the latest release (3.0.0)."
        );
    }

    #[test]
    fn confirm_prompt_names_the_direction() {
        assert_eq!(
            confirm_prompt(&v("4.0.0"), &v("9.9.9")),
            "Update socket-patch 4.0.0 \u{2192} 9.9.9?"
        );
        assert_eq!(
            confirm_prompt(&v("4.0.0"), &v("3.0.0")),
            "Downgrade socket-patch 4.0.0 \u{2192} 3.0.0?"
        );
        assert_eq!(
            confirm_prompt(&v("4.0.0"), &v("4.0.0")),
            "Reinstall socket-patch 4.0.0?"
        );
    }

    #[test]
    fn cancel_and_result_lines_match_the_prompt() {
        assert_eq!(cancelled_message(&v("4.0.0"), &v("9.9.9")), "Update cancelled.");
        assert_eq!(cancelled_message(&v("4.0.0"), &v("3.0.0")), "Downgrade cancelled.");
        assert_eq!(cancelled_message(&v("4.0.0"), &v("4.0.0")), "Reinstall cancelled.");
        let p = std::path::Path::new("/opt/sp/socket-patch");
        assert_eq!(
            installed_message(&v("4.0.0"), &v("9.9.9"), p),
            "Updated socket-patch 4.0.0 \u{2192} 9.9.9 (/opt/sp/socket-patch)"
        );
        assert_eq!(
            installed_message(&v("4.0.0"), &v("3.0.0"), p),
            "Downgraded socket-patch 4.0.0 \u{2192} 3.0.0 (/opt/sp/socket-patch)"
        );
        assert_eq!(
            installed_message(&v("4.0.0"), &v("4.0.0"), p),
            "Reinstalled socket-patch 4.0.0 (/opt/sp/socket-patch)"
        );
    }

    #[test]
    fn download_status_and_error_capitalization() {
        assert_eq!(
            download_status(&v("9.9.9"), "socket-patch-x.tar.gz"),
            "Downloading socket-patch 9.9.9 (socket-patch-x.tar.gz)..."
        );
        assert_eq!(
            capitalize_first("could not check for updates: x"),
            "Could not check for updates: x"
        );
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("éclair"), "Éclair");
        assert_eq!(capitalize_first("Already"), "Already");
    }

    #[test]
    fn help_describes_the_update_flag_not_the_internal_subcommand() {
        use clap::CommandFactory;
        let mut cmd = crate::Cli::command();
        let sub = cmd
            .find_subcommand_mut("self-update")
            .expect("self-update subcommand");
        let help = sub.render_long_help().to_string();
        assert!(
            help.starts_with("Update socket-patch itself to the latest release (or to VERSION)."),
            "{help}"
        );
        for internal in [
            "Internal parse target",
            "propagate_version",
            "parse_argv_with_shortcuts",
        ] {
            assert!(!help.contains(internal), "leaked {internal:?}: {help}");
        }
    }

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
