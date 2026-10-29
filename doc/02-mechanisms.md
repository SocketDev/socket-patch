## Part 2

_Last checked against main @ c07af61 on 2026-10-29 by audit-cli-tests._

 Common mechanisms:For each cross-cutting concern: the **canonical mechanism** (the one way the code should do it, with a permalink to its home), the **deviations** found (file, what it does instead, its register token), and a count. Concerns: error types and context; error codes and exit codes; swallowed errors and panics in non-test code; stdout/stderr and the `ui` layer; the JSON envelope; human text, color and progress; logging; env and config reading; paths and containment; file I/O (atomic writes, BOM/CRLF); HTTP clients, timeouts and retries; process spawning and deadlines; concurrency.

### Findings
- **Env and config reading** (proposed canonical: one `utils/env.rs` with `flag`, `non_empty` and `positive` readers). Today there are three vocabularies: `env_compat` (exact `1`/`true`), `socket_cli_config::env_truthy` (yes/on/y/t) and `concurrent` (trim plus debug log). {{A09}}
- **Home directory** (proposed canonical: `utils::fs::home_dir`, which requires a usable absolute home). `crawlers/hatch_env.rs` and `repo_root::home` use their own rules. {{A10}}
- **spawn_blocking join handling** (canonical: `fs::run_blocking`). `fs::asyncify` converts panics and cancellations into `io::Error`, which is a second policy. This is a local note on `utils/fs.rs`.
- **Line endings** (canonical: `utils::line_endings`). Four sites re-derive CRLF detection or the terminator, plus three `eol_eq` copies. {{A04}}
- **Durable directory sync**: `group_commit::sync_dir` duplicates the fsync in `fs.rs`. {{A12}}
- **Env-var registry** (proposed canonical: derive every scrub/hermetic list from clap's `Arg::get_env()` over `cli_command()`). Today `args.rs` keeps hand lists that already miss `SOCKET_NO_SOCKET_YML`. {{T03}}
- **Lock acquisition in the CLI** (proposed canonical: one `lock_cli` helper taking `GlobalArgs`). The acquire/timeout/`lock_failure` sequence is open-coded ~8× and the timeout conversion 14×. {{T09}}
- **`--json` writes** (canonical: `ui::print_json`). `apply.rs` alone writes 8 envelopes with `println!("{}", env.to_pretty_json())` and builds `RunWarning` literals 12× instead of `RunWarning::new`. Local notes on `apply.rs`.
