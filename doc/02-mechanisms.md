## Part 2

_Last checked against main @ 5ca5623 on 2026-10-30 by audit-core._

 Common mechanisms:For each cross-cutting concern: the **canonical mechanism** (the one way the code should do it, with a permalink to its home), the **deviations** found (file, what it does instead, its register token), and a count. Concerns: error types and context; error codes and exit codes; swallowed errors and panics in non-test code; stdout/stderr and the `ui` layer; the JSON envelope; human text, color and progress; logging; env and config reading; paths and containment; file I/O (atomic writes, BOM/CRLF); HTTP clients, timeouts and retries; process spawning and deadlines; concurrency.

### Findings
- **Env and config reading** (proposed canonical: one `utils/env.rs` with `flag`, `non_empty` and `positive` readers). Today there are three vocabularies: `env_compat` (exact `1`/`true`), `socket_cli_config::env_truthy` (yes/on/y/t) and `concurrent` (trim plus debug log). {{A09}}
- **Home directory** (proposed canonical: `utils::fs::home_dir`, which requires a usable absolute home). `crawlers/hatch_env.rs`, `repo_root::home`, `process::neutral_probe_dir_with` and `socket_cli_config` use their own rules. {{A10}}
- **spawn_blocking join handling** (canonical: `fs::run_blocking`). `fs::asyncify` converts panics and cancellations into `io::Error`, which is a second policy. This is a local note on `utils/fs.rs`.
- **Line endings** (canonical: `utils::line_endings`). Four sites re-derive CRLF detection or the terminator, plus three `eol_eq` copies. {{A04}}
- **Durable directory sync**: `group_commit::sync_dir` duplicates the fsync in `fs.rs`. {{A12}}
- **Env-var registry** (proposed canonical: derive every scrub/hermetic list from clap's `Arg::get_env()` over `cli_command()`). Today `args.rs` keeps hand lists that already miss `SOCKET_NO_SOCKET_YML`. {{T03}}
- **Lock acquisition in the CLI** (proposed canonical: one `lock_cli` helper taking `GlobalArgs`). The acquire/timeout/`lock_failure` sequence is open-coded 9× beside the 5 `acquire_or_emit` callers and the timeout conversion 14×; `lock_held` has 3 human renderings and scan/hosted prints it under `--json`. {{T09}}
- **`--json` writes** (canonical: `ui::print_json`). `apply.rs` alone writes 8 envelopes with `println!("{}", env.to_pretty_json())` and builds `RunWarning` literals 12× instead of `RunWarning::new`. Local notes on `apply.rs`.
- **URL credential stripping** (proposed canonical: `utils::redact`). The live copy is `vex::product::strip_url_userinfo`; redact's own `strip_url_credentials` is dead. {{A20}}
- **Lexical path normalization** (canonical: `utils::relpath::normalize_lexically_keeping_escapes`). Four private `PathBuf::pop` copies. {{A19}}
- **Repository root walk** (canonical: `utils::repo_root`). Three hand walks ignore `GIT_CEILING_DIRECTORIES`. {{A21}}
- **Committed JSON ledgers** (proposed canonical: `socket_dir::write_json_ledger`). The manifest writer and two state markers serialize on their own. {{A16}}
- **Error emit** (proposed canonical: one `json_envelope::emit_error(Command, json, dry_run, EnvelopeError)`). remove, rollback, repair (3×), list and scan each hand-write "envelope under `--json`, else stderr". {{T20}}
- **Run warnings** (proposed canonical: `RunWarning::new` plus one `ui` sink with an explicit print-under-`--silent` rule). The sink is hand-rolled in list ×3, user_patches and scan/withdrawn, which disagree on `--silent`; 40 `RunWarning {` literals vs 17 `::new`. {{T21}}
- **Terminal-safe text** (proposed canonical: core `policy::strip_unsafe`, keeping `\n`/`\t`). `list::sanitize` and `StatusPrinter::println` keep bidi and zero-width characters. {{T23}}
- **Shell-quoted remedies** (canonical: `ui::shell_word`). `scan/discovery.rs` keeps a POSIX-only copy. {{T18}}
- **Telemetry auth**: repair copies core's token chain (`api_token_available`) to avoid building a client, while remove builds one eagerly (an org lookup and a proxy notice before any local work). Local notes; related to C10/#793.
- **HTTP retries** (proposed canonical: one retry helper in `api/retry.rs` driven by one policy). `api/client.rs` runs two policies that disagree on statuses, counts, jitter and an over-cap `Retry-After` (executed: JSON gives up, vendor retries after 4 s), through four hand-written loops; blob GETs and the upstream registry client (#1650) retry nothing. {{A27}}
- **Debug output** (canonical: `api::client::debug_log` → `[socket-patch debug]` on stderr, deferrable per task). `vendor/pypi.rs` reuses its deferral; other modules print through `env_compat::debug_message` directly. Not yet surveyed beyond `api/`.
