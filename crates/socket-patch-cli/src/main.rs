use std::ffi::OsString;

use socket_patch_cli::{commands, hot_patch, parse_argv_with_shortcuts, Commands};
use socket_patch_core::utils::env_compat::promote_peer_env_vars;
use socket_patch_core::utils::socket_cli_config;

/// The way out of `main`: exit with `code`, or, for `hot-patch`, become
/// the command. That command starts whatever the patching did, so every
/// early exit below goes through here too.
fn leave(hot_patch_command: &Option<hot_patch::Start>, code: i32) -> ! {
    match hot_patch_command {
        Some(start) => hot_patch::exec(start),
        None => std::process::exit(code),
    }
}

fn main() {
    // A hot-patch run's command starts with the environment this process
    // was given, not the one `run` leaves behind.
    let given_env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    // `hot-patch ... -- <command>` is cut in two first: the command is not
    // ours to parse, and may hold any bytes.
    let (own_args, command) = hot_patch::split_command(std::env::args_os().collect());
    let command = command.map(|argv| hot_patch::Start {
        argv,
        env: given_env,
    });
    let Some(start) = command.clone() else {
        return run(own_args, command);
    };
    // `run` prints, parses and patches, and none of it may keep that
    // command from starting, not even by panicking: on this thread, or on
    // a worker whose panic is raised again here. (`run` itself ends in the
    // command; it only comes back by unwinding.)
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(own_args, command)));
    hot_patch::say("the patch check failed with an internal error");
    hot_patch::exec(&start);
}

#[tokio::main]
async fn run(own_args: Vec<OsString>, hot_patch_command: Option<hot_patch::Start>) {
    // Must precede any output: clap help writes to a possibly-already-closed
    // pipe, which from here on stops the printing rather than the run.
    // Ctrl-C / SIGTERM / SIGHUP remove a held `.socket/apply.lock` before
    // the signal ends the process (see `interrupt`).
    socket_patch_cli::interrupt::install();

    // Accept the JS socket-cli's SOCKET_CLI_* peer names (silently —
    // they are aliases, not deprecations) so `socket login` / socket-cli
    // env setups work for socket-patch unchanged. Canonical names win.
    promote_peer_env_vars();

    // SOCKET_NO_API_TOKEN (or its SOCKET_CLI_ alias, promoted above)
    // suppresses ambient tokens: scrub the env var before clap parses so
    // only an explicit `--api-token` flag can authenticate. Core applies
    // the same veto to its own env/config fallback layers.
    if socket_cli_config::no_api_token_veto() {
        std::env::remove_var("SOCKET_API_TOKEN");
    }

    // Then drop exported-but-empty SOCKET_* flag vars — global and
    // subcommand-local (`SOCKET_CWD=` means "unset", not "crash the
    // parse").
    socket_patch_cli::args::scrub_empty_env_vars();

    // The parser surface is `String`-typed, but argv is raw bytes on Unix —
    // `std::env::args()` would *panic* on a non-Unicode argument. Collect
    // `args_os` instead and turn a bad argument into the contract's clap
    // usage error (stderr + exit 2) rather than a crash.
    let argv: Vec<String> = match own_args
        .into_iter()
        .map(OsString::into_string)
        .collect::<Result<_, _>>()
    {
        Ok(argv) => argv,
        Err(bad_arg) => {
            eprintln!("Error: Invalid UTF-8 was detected in one or more arguments: {bad_arg:?}");
            leave(&hot_patch_command, 2);
        }
    };
    let mut cli = match parse_argv_with_shortcuts(argv) {
        Ok(cli) => cli,
        // A hot-patch run's command starts even when its own flags (or the
        // environment variables behind them) do not parse. `--help` and
        // `--version` are requests, not errors: they print and exit.
        Err(err) if hot_patch_command.is_some() && err.use_stderr() => {
            let _ = err.print();
            leave(&hot_patch_command, 2);
        }
        Err(err) => err.exit(),
    };

    // `hot-patch` with no command after a `--`: there is nothing to start,
    // so nothing is patched either. `exec` says where the command goes.
    if let Commands::HotPatch(_) = &cli.command {
        let none = hot_patch::Start {
            argv: Vec::new(),
            env: Vec::new(),
        };
        match &hot_patch_command {
            Some(start) if !start.argv.is_empty() => {}
            _ => hot_patch::exec(&none),
        }
    }

    // A successful parse with `update == true` means a subcommand was also
    // given (`socket-patch --update scan`) — bare `--update` is rewritten
    // to the hidden `self-update` subcommand before it can parse Ok. The
    // combination is contradictory; refuse with the contract's usage exit.
    if cli.update {
        eprintln!(
            "Error: --update cannot be combined with a subcommand; run `socket-patch --update` on its own"
        );
        leave(&hot_patch_command, 2);
    }

    // `hot-patch`: agent mode, one line of output, and state in a directory
    // that is gone before the command starts.
    if let Commands::HotPatch(args) = &mut cli.command {
        if let Err(message) = hot_patch::prepare(args) {
            hot_patch::say(&format!("patching skipped: {message}"));
            leave(&hot_patch_command, 2);
        }
    }

    // A `--cwd`, `--global-prefix` or `--manifest-path` that names nothing
    // is a usage error, checked once here before any command runs: read as
    // an empty project it made every verifier pass vacuously.
    if let Err(message) = cli.command.validate_paths() {
        eprintln!("Error: {message}");
        leave(&hot_patch_command, 2);
    }

    // Human-output policy (core advisories and prompt notes go quiet under
    // --silent/--json) is fixed once, before any command code runs.
    socket_patch_cli::ui::init(cli.command.global_args());

    // Passive update notifier: guards + (maybe) a background check kicked
    // off before dispatch, joined with a short grace budget after it.
    // Structurally skipped for `--update` itself — an explicit update IS
    // the check, and it refreshes the notifier's cache on its own.
    // A hot-patch run skips it as well: an update notice is no part of a
    // container's start, and neither is the wait for it.
    let notifier = if matches!(cli.command, Commands::SelfUpdate(_)) || hot_patch_command.is_some()
    {
        None
    } else {
        socket_patch_cli::update_notifier::spawn_if_due(cli.command.global_args())
    };

    let exit_code = match cli.command {
        Commands::Scan(args) => commands::scan::run(args).await,
        Commands::Apply(args) => commands::apply::run(args).await,
        Commands::Vex(args) => commands::vex::run(args).await,
        Commands::Vendor(args) => commands::vendor::run(args).await,
        Commands::Rollback(args) => commands::rollback::run(args).await,
        Commands::Get(args) => commands::get::run(args).await,
        Commands::List(args) => commands::list::run(args).await,
        Commands::Remove(args) => commands::remove::run(args).await,
        Commands::Repair(args) => commands::repair::run(args).await,
        Commands::SelfUpdate(args) => commands::update::run(args).await,
        Commands::HostedBundle(args) => commands::hosted_bundle::run(args).await,
        // The project and the global packages under one time limit, and
        // no exit code, since what follows is the command.
        Commands::HotPatch(args) => {
            hot_patch::run(args).await;
            0
        }
    };

    // The tail of the run, after all command output. Telemetry sent beside
    // the command gets a short grace to finish (`telemetry::EXIT_GRACE`),
    // then is dropped. The notifier never delays exit beyond its 500 ms
    // grace budget and prints (at most) its notice to stderr. Neither
    // changes the exit code, and joined they cost the longer of the two
    // waits, not the sum.
    tokio::join!(
        socket_patch_core::telemetry::flush(telemetry_grace()),
        socket_patch_cli::update_notifier::finish(notifier),
    );

    leave(&hot_patch_command, exit_code);
}

/// How long the exit waits for telemetry still in flight: the production
/// grace, or `SOCKET_TELEMETRY_GRACE_MS` — a test hook, so a suite that
/// counts the events a loopback mock received is not racing a loaded
/// runner (a send's own 5 s request timeout still ends the wait).
fn telemetry_grace() -> std::time::Duration {
    std::env::var("SOCKET_TELEMETRY_GRACE_MS")
        .ok()
        .and_then(|ms| ms.parse().ok())
        .map_or(
            socket_patch_core::telemetry::EXIT_GRACE,
            std::time::Duration::from_millis,
        )
}
