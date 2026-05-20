use socket_patch_cli::{commands, parse_with_uuid_fallback, Commands};

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
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
    };

    std::process::exit(exit_code);
}
