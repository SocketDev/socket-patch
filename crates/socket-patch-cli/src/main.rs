use socket_patch_cli::{commands, parse_with_uuid_fallback, Commands};
use socket_patch_core::utils::env_compat::promote_legacy_env_vars;

#[tokio::main]
async fn main() {
    // Migrate legacy SOCKET_PATCH_* env vars into the new SOCKET_* names
    // before clap parses, so downstream code only needs to know the new
    // names. A one-shot deprecation warning fires per legacy name set.
    promote_legacy_env_vars();

    // Then drop exported-but-empty SOCKET_* globals (`SOCKET_CWD=` means
    // "unset", not "crash the parse"). Must run after the promotion so a
    // blanked legacy name is scrubbed too.
    socket_patch_cli::args::scrub_empty_global_env_vars();

    // The parser surface is `String`-typed, but argv is raw bytes on Unix —
    // `std::env::args()` would *panic* on a non-Unicode argument. Collect
    // `args_os` instead and turn a bad argument into the contract's clap
    // usage error (stderr + exit 2) rather than a crash.
    let argv: Vec<String> = match std::env::args_os()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<_, _>>()
    {
        Ok(argv) => argv,
        Err(bad_arg) => {
            eprintln!("error: invalid UTF-8 was detected in one or more arguments: {bad_arg:?}");
            std::process::exit(2);
        }
    };
    let cli = match parse_with_uuid_fallback(argv) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };

    let exit_code = match cli.command {
        Commands::Apply(args) => commands::apply::run(args).await,
        Commands::Rollback(args) => commands::rollback::run(args).await,
        Commands::Get(args) => commands::get::run(args).await,
        Commands::Scan(args) => commands::scan::run(args).await,
        Commands::List(args) => commands::list::run(args).await,
        Commands::Remove(args) => commands::remove::run(args).await,
        Commands::Setup(args) => commands::setup::run(args).await,
        Commands::Repair(args) => commands::repair::run(args).await,
        Commands::Unlock(args) => commands::unlock::run(args).await,
        Commands::Vendor(args) => commands::vendor::run(args).await,
        Commands::Vex(args) => commands::vex::run(args).await,
    };

    std::process::exit(exit_code);
}
