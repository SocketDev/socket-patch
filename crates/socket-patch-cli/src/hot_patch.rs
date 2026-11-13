//! `socket-patch hot-patch -- <command>`: hot patch mode (experimental).
//!
//! ```text
//! ENTRYPOINT ["socket-patch", "hot-patch", "--"]
//! CMD ["node", "server.js"]
//! ```
//!
//! Hot patch mode patches everything installed on the machine in place,
//! saves nothing, and then replaces itself with the command, which keeps
//! the PID, the signals, the environment and the exit status it would have
//! had. As a container's entrypoint it makes a restart the way a patch is
//! deployed. Everything after `--` is the command.
//!
//! - **The command always starts.** A flag that does not parse, an
//!   unreachable API, packages that cannot be written, a panic: each is
//!   reported on stderr and the command starts anyway. Only a stop signal
//!   that arrives first ends the run without it (see `interrupt`).
//! - **Two agent-mode scans:** the project under the working directory,
//!   then the system's globally installed packages, each the scan it would
//!   be on its own (`--global` runs only the second), with two
//!   differences. The project pass leaves Go to the global one (see
//!   [`passes`]), and the global pass reads the working directory's
//!   socket.yml too: a package the repository excludes stays unpatched
//!   wherever it is installed.
//! - **Nothing is saved.** Patches are written straight into the installed
//!   packages. The manifests and patch data the agent engine works from
//!   live in a temporary directory that is removed before the command
//!   starts, and the flags that write elsewhere are refused.
//! - **Every patch scan would select is applied.** `--min-severity`,
//!   `SOCKET_MIN_SEVERITY` and socket.yml narrow that as they do for scan.
//! - **A time limit** (`--timeout`, 10 s by default) covers everything up to
//!   a pass's first write to an installed package. A pass that has not got
//!   that far by then is dropped: it touched nothing, and the command
//!   starts without it. Once writing has begun a pass runs to its end, so
//!   no package is left half written.
//! - **One line of output,** on stderr, in place of scan's own.
//!
//! `SOCKET_OFFLINE=1` (or `--offline`) is the off switch: the command starts
//! and nothing is patched.
//!
//! Experimental: the subcommand is hidden, and its flags and stderr text
//! carry no stability guarantee.

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use clap::Args;
use serde_json::Value;
use socket_patch_core::crawlers::Ecosystem;

use crate::commands::scan::{ScanArgs, ScanMode};

/// The subcommand's name on the command line.
pub const NAME: &str = "hot-patch";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// The two passes of a run, as the stderr line names them.
const PROJECT: &str = "project";
const GLOBAL: &str = "global";

/// `hot-patch` takes scan's options: it is two scans. The command is not
/// in the parser: `main` cuts it off the command line before clap sees it
/// ([`split_command`]), so a command's own flags are never read as these.
#[derive(Args, Clone)]
pub struct HotPatchArgs {
    #[command(flatten)]
    pub scan: ScanArgs,

    /// The longest a pass may take before it starts writing patches, in
    /// seconds from the start of the run (0: no limit)
    #[arg(long = "timeout", value_name = "SECONDS", value_parser = parse_seconds)]
    pub timeout: Option<Duration>,
}

fn parse_seconds(text: &str) -> Result<Duration, String> {
    let seconds = text
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|seconds| seconds.is_finite() && (0.0..=86_400.0).contains(seconds))
        .ok_or_else(|| format!("`{text}` is not a number of seconds"))?;
    let limit = Duration::from_secs_f64(seconds);
    // Only a literal zero means "no limit": a positive number too small to
    // hold in a `Duration` is the shortest limit, not none.
    Ok(if seconds > 0.0 && limit.is_zero() {
        Duration::from_nanos(1)
    } else {
        limit
    })
}

/// Cut `hot-patch ... -- <command>...` in two: hot-patch's own arguments
/// and the command. The command is `None` when this is not a hot-patch
/// command line, and empty when there is no `--`: there is then no command
/// to become ([`exec`] says so).
pub fn split_command(mut argv: Vec<OsString>) -> (Vec<OsString>, Option<Vec<OsString>>) {
    if argv.get(1).is_none_or(|subcommand| subcommand != NAME) {
        return (argv, None);
    }
    let command = match argv.iter().position(|arg| arg == "--") {
        Some(at) => {
            let command = argv.split_off(at + 1);
            argv.pop();
            command
        }
        None => Vec::new(),
    };
    (argv, Some(command))
}

/// The command a hot-patch run ends in, and the environment it starts
/// with: the one this process was given, before socket-patch's own edits
/// (alias promotion, the scrub of empty values, the toggles flags set).
#[derive(Clone, Debug)]
pub struct Start {
    pub argv: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
}

/// Set once a hot-patch run is under way: scan's JSON documents are then
/// kept for the one stderr line instead of printed ([`report`]).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Set when the agent engine is about to write to installed packages: from
/// then on the pass is no longer dropped at the time limit.
static APPLY_STARTED: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<Instant> = OnceLock::new();
/// The document each finished pass reported.
static DOCUMENTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
/// The run's temporary state. [`exec`] removes it before the command starts.
static STATE: Mutex<Option<tempfile::TempDir>> = Mutex::new(None);

pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// The agent engine calls this right before its apply step.
pub(crate) fn mark_apply_started() {
    APPLY_STARTED.store(true, Ordering::SeqCst);
}

/// Hot patch mode's stand-in for printing the JSON document of a scan.
pub(crate) fn report(document: &Value) {
    if let Ok(mut documents) = DOCUMENTS.lock() {
        documents.push(document.clone());
    }
}

/// What hot patch mode makes of scan's options: agent mode, the quiet
/// engine, and state that does not outlive the run. `Err` is why nothing
/// will be patched.
pub fn prepare(args: &mut HotPatchArgs) -> Result<(), String> {
    let _ = STARTED.set(Instant::now());
    ACTIVE.store(true, Ordering::Relaxed);
    let args = &mut args.scan;
    // The off switch: a scan cannot run offline, so say so in a word
    // instead of running into its refusal.
    if args.common.offline {
        return Err("offline (--offline or SOCKET_OFFLINE is set)".to_string());
    }
    match args.mode {
        None => args.mode = Some(ScanMode::Agent),
        Some(ScanMode::Agent) => {}
        Some(other) => {
            return Err(format!(
                "hot-patch patches installed packages in place, so it cannot be used with --mode {}",
                other.cli_name()
            ));
        }
    }
    // The flags that keep or manage saved patches have nothing to work on
    // here, and their writes are not ones the time limit knows to wait for.
    let keeps = [
        (args.prune || args.sync, "--prune or --sync"),
        (
            args.common.manifest_path != socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH,
            "--manifest-path (or SOCKET_MANIFEST_PATH)",
        ),
        (args.vex.vex.is_some(), "--vex (or SOCKET_VEX)"),
    ];
    if let Some((_, flag)) = keeps.iter().find(|(given, _)| *given) {
        return Err(format!(
            "hot-patch saves nothing, so it cannot be used with {flag}"
        ));
    }
    // A rollout cap paces patches across runs by what the manifest already
    // records, and this mode's manifest starts empty every time: the same
    // few patches would be admitted on every start and the rest never.
    if args
        .rollout
        .max_new_patches
        .is_some_and(|cap| cap.0.is_some())
    {
        return Err(
            "hot-patch keeps no record between runs, so it cannot be used with --max-new-patches"
                .to_string(),
        );
    }
    // (This also lifts a cap from SOCKET_MAX_NEW_PATCHES or socket.yml.)
    args.rollout.max_new_patches = Some(crate::commands::scan::rollout_args::MaxNewPatches(None));
    // Each pass reports into one document, which `report` keeps, and the
    // warnings a scan prints beside it would be lines of their own.
    args.common.json = true;
    args.common.silent = true;
    let state = tempfile::Builder::new()
        .prefix("socket-patch-")
        .tempdir()
        .map_err(|error| format!("cannot create a temporary directory: {error}"))?;
    if let Ok(mut slot) = STATE.lock() {
        *slot = Some(state);
    }
    Ok(())
}

/// The scans one run makes, in order, each with a manifest of its own
/// under `state`: the project at `--cwd`, then the global installs.
/// `--global` (or `--global-prefix`) runs only the second.
///
/// The project pass leaves Go to the global one. A project run does not
/// patch a Go module where it is installed: it redirects the module through
/// the project's `go.mod` to a copy under `.socket/`, and drops the
/// redirects its manifest does not list. This mode writes nothing but
/// installed packages, and its manifest starts empty.
fn passes(args: &ScanArgs, state: &Path) -> Vec<(&'static str, ScanArgs)> {
    let with_manifest = |mut pass: ScanArgs, scope: &'static str| {
        pass.common.manifest_path = state
            .join(scope)
            .join("manifest.json")
            .to_string_lossy()
            .into_owned();
        (scope, pass)
    };
    let mut global = args.clone();
    let mut passes = Vec::new();
    if !args.common.is_global() {
        let golang = Ecosystem::Golang.cli_name();
        let ecosystems: Vec<String> = match &args.common.ecosystems {
            Some(named) if !named.is_empty() => named.clone(),
            _ => Ecosystem::all()
                .iter()
                .map(|eco| eco.cli_name().to_string())
                .collect(),
        }
        .into_iter()
        .filter(|name| name != golang)
        .collect();
        // An empty list would mean every ecosystem: with nothing but Go
        // asked for, there is no project pass.
        if !ecosystems.is_empty() {
            let mut project = args.clone();
            project.common.ecosystems = Some(ecosystems);
            passes.push(with_manifest(project, PROJECT));
        }
        // The positional paths scope the project's packages only.
        global.common.global = true;
        global.paths = Vec::new();
    }
    passes.push(with_manifest(global, GLOBAL));
    passes
}

/// Run one pass up to `deadline`; `false` when it was dropped there. The
/// deadline drops the pass only while it has not started writing patches:
/// a drop before that leaves every installed package as it was, and one
/// after could leave a package half written, so from then on the pass is
/// awaited.
async fn run_pass(args: ScanArgs, deadline: Option<tokio::time::Instant>) -> bool {
    APPLY_STARTED.store(false, Ordering::SeqCst);
    let mut scan = Box::pin(crate::commands::scan::run(args));
    let Some(deadline) = deadline else {
        scan.await;
        return true;
    };
    tokio::select! {
        _exit_code = scan.as_mut() => return true,
        () = tokio::time::sleep_until(deadline) => {}
    }
    if APPLY_STARTED.load(Ordering::SeqCst) {
        scan.await;
        return true;
    }
    false
}

/// Run the passes under the time limit and print the one line. There is no
/// exit code: what follows is the command.
pub async fn run(args: HotPatchArgs) {
    let limit = args.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let args = args.scan;
    let deadline = (!limit.is_zero()).then(|| tokio::time::Instant::now() + limit);
    let state = STATE
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|dir| dir.path().to_path_buf()));
    let mut reports: Vec<(&'static str, Value)> = Vec::new();
    let mut timed_out = false;
    // `prepare` made the directory; without it there is nothing to run in.
    for (scope, pass) in state.iter().flat_map(|state| passes(&args, state)) {
        let finished = run_pass(pass, deadline).await;
        let documents = DOCUMENTS
            .lock()
            .map(|mut documents| std::mem::take(&mut *documents))
            .unwrap_or_default();
        reports.extend(documents.into_iter().map(|document| (scope, document)));
        if !finished {
            timed_out = true;
            break;
        }
    }
    say(&summary_line(&reports, timed_out, limit, &elapsed()));
}

fn elapsed() -> String {
    let seconds = STARTED
        .get()
        .map_or(0.0, |start| start.elapsed().as_secs_f64());
    format!("{seconds:.1}s")
}

/// Print one `socket-patch: ...` line on stderr. A stderr that cannot be
/// written to loses the line, not the start of the command.
pub fn say(message: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "socket-patch: {message}");
}

fn events<'a>(
    reports: &'a [(&'static str, Value)],
    action: &'a str,
) -> impl Iterator<Item = &'a Value> {
    reports
        .iter()
        .filter_map(|(_, document)| document.get("events").and_then(Value::as_array))
        .flatten()
        .filter(move |event| event.get("action").and_then(Value::as_str) == Some(action))
}

/// One line for the documents the passes reported: what was patched, what
/// was not and why. `timed_out`: the last pass was dropped at the limit and
/// did not report.
fn summary_line(
    reports: &[(&'static str, Value)],
    timed_out: bool,
    limit: Duration,
    elapsed: &str,
) -> String {
    let plural = |count: usize| if count == 1 { "patch" } else { "patches" };
    let text =
        |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
    let applied: Vec<Option<String>> = events(reports, "applied")
        .map(|event| text(event, "purl"))
        .collect();
    // The passes can reach the same package (a Python image's system
    // site-packages is the project's and the global one): what the first
    // patched, the second finds in place, and that is not news.
    let in_place = events(reports, "skipped")
        .filter(|event| text(event, "errorCode").as_deref() == Some("already_patched"))
        .filter(|event| !applied.contains(&text(event, "purl")))
        .count();
    // The same goes for a package neither pass could patch, or both would.
    let distinct = |events: &mut dyn Iterator<Item = &Value>| {
        let mut purls: Vec<Option<String>> = events.map(|event| text(event, "purl")).collect();
        purls.sort();
        purls.dedup();
        purls.len()
    };
    let failed = distinct(&mut events(reports, "failed"));
    // `--dry-run` writes nothing: each patch it would apply is `verified`.
    let previewed = distinct(
        &mut reports
            .iter()
            .filter(|(_, document)| document.get("dryRun").and_then(Value::as_bool) == Some(true))
            .flat_map(|report| events(std::slice::from_ref(report), "verified")),
    );
    let mut parts: Vec<String> = Vec::new();
    if previewed > 0 {
        parts.push(format!(
            "dry run: {previewed} {} would be applied",
            plural(previewed)
        ));
    }
    if !applied.is_empty() {
        let applied = applied.len();
        parts.push(format!("applied {applied} {}", plural(applied)));
    }
    if in_place > 0 {
        parts.push(format!("{in_place} {} already in place", plural(in_place)));
    }
    if failed > 0 {
        let errors: Vec<String> = events(reports, "failed")
            .map(|event| {
                let error = text(event, "error").unwrap_or_else(|| "unknown error".to_string());
                match text(event, "purl") {
                    Some(purl) => format!("{purl}: {error}"),
                    None => error,
                }
            })
            .collect();
        let first = errors.first().cloned().unwrap_or_default();
        // The two failures a locked-down container always hits, in words:
        // the io error alone does not say whose files.
        let any = |needle: &str| errors.iter().any(|error| error.contains(needle));
        let why = if any("Read-only file system") {
            ": the installed packages are on a read-only file system"
        } else if any("Permission denied") {
            ": the installed packages are not writable by this user"
        } else {
            ""
        };
        parts.push(format!(
            "{failed} {} not applied{why} ({first})",
            plural(failed)
        ));
    }
    let mut errors: Vec<&str> = reports
        .iter()
        .filter_map(|(_, document)| document.pointer("/error/message").and_then(Value::as_str))
        .collect();
    errors.dedup();
    for message in errors {
        parts.push(format!("the patch check failed ({message})"));
    }
    if timed_out && reports.is_empty() {
        parts.push(format!(
            "the patch check did not finish in {:.1}s, so nothing was patched",
            limit.as_secs_f64()
        ));
    } else if timed_out {
        parts.push(format!(
            "the global packages were not checked within {:.1}s",
            limit.as_secs_f64()
        ));
    }
    if parts.is_empty() {
        parts.push("no patches to apply".to_string());
    }
    // Per pass, not summed: packages both passes reach are counted by each.
    let checked: Vec<String> = reports
        .iter()
        .filter_map(|(scope, document)| {
            let count = document.get("scannedPackages").and_then(Value::as_u64)?;
            Some(format!("{count} {scope}"))
        })
        .collect();
    let checked = if checked.is_empty() {
        String::new()
    } else {
        format!("{} packages checked, ", checked.join(" + "))
    };
    format!("{} [{checked}{elapsed}]", parts.join("; "))
}

/// Replace this process with the command. Returns only when that failed.
#[cfg(unix)]
fn replace_process(start: &Start) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    // std resets the signal mask and SIGPIPE before the exec, and an exec
    // drops this process's handlers, so the command starts with every
    // signal at its default: what a container's command starts with. (A
    // SIGPIPE this process inherited as ignored is not passed on: Rust's
    // start-up has replaced that setting before any of this code runs.)
    std::process::Command::new(&start.argv[0])
        .args(&start.argv[1..])
        .env_clear()
        .envs(start.env.iter().map(|(name, value)| (name, value)))
        .exec()
}

/// No exec on this platform: run the command as a child and end with its
/// exit status.
#[cfg(not(unix))]
fn replace_process(start: &Start) -> std::io::Error {
    match std::process::Command::new(&start.argv[0])
        .args(&start.argv[1..])
        .env_clear()
        .envs(start.env.iter().map(|(name, value)| (name, value)))
        .status()
    {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => error,
    }
}

/// Become the command, after removing the run's temporary state. When the
/// command cannot be started, exit the way a shell reports it: 127 for a
/// command that is not found, 126 for one that cannot be run, and 2 when
/// there is no command at all.
pub fn exec(start: &Start) -> ! {
    // Every way out of a hot-patch run comes through here, so this is
    // where the state goes: a function that never returns drops nothing.
    // (`try_lock`: a panic may have come from under the lock.)
    if let Ok(mut state) = STATE.try_lock() {
        drop(state.take());
    }
    if start.argv.is_empty() {
        say("hot-patch needs a command to start after `--`, for example: socket-patch hot-patch -- node server.js");
        std::process::exit(2);
    }
    let error = replace_process(start);
    say(&format!(
        "cannot run {}: {error}",
        start.argv[0].to_string_lossy()
    ));
    std::process::exit(if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The limit the summary lines below were dropped at.
    const LIMIT: Duration = Duration::from_secs(5);

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_command_is_everything_after_the_separator() {
        let (head, command) = split_command(os(&[
            "socket-patch",
            "hot-patch",
            "--timeout",
            "2",
            "--",
            "node",
            "--timeout",
            "--",
            "server.js",
        ]));
        assert_eq!(head, os(&["socket-patch", "hot-patch", "--timeout", "2"]));
        assert_eq!(command, Some(os(&["node", "--timeout", "--", "server.js"])));
    }

    #[test]
    fn without_a_separator_there_is_no_command() {
        for argv in [
            os(&["socket-patch", "hot-patch"]),
            os(&["socket-patch", "hot-patch", "node", "server.js"]),
        ] {
            let (head, command) = split_command(argv.clone());
            assert_eq!(head, argv);
            assert_eq!(command, Some(Vec::new()));
        }
        let (head, command) = split_command(os(&["socket-patch", "hot-patch", "--"]));
        assert_eq!(head, os(&["socket-patch", "hot-patch"]));
        assert_eq!(command, Some(Vec::new()));
    }

    /// Every other subcommand keeps its `--`: scan's is the start of its
    /// positional paths.
    #[test]
    fn only_hot_patch_takes_a_command() {
        for argv in [
            os(&["socket-patch", "scan", "--", "packages/a"]),
            os(&["socket-patch", "apply", "--", "hot-patch"]),
            os(&["socket-patch"]),
        ] {
            let (head, command) = split_command(argv.clone());
            assert_eq!(head, argv);
            assert_eq!(command, None);
        }
    }

    #[test]
    fn seconds_parse_and_reject() {
        assert_eq!(parse_seconds("5"), Ok(Duration::from_secs(5)));
        assert_eq!(parse_seconds("0"), Ok(Duration::ZERO));
        assert_eq!(parse_seconds("1.5"), Ok(Duration::from_millis(1500)));
        // Too small to hold, but not zero: a limit, not "no limit".
        assert_eq!(parse_seconds("1e-12"), Ok(Duration::from_nanos(1)));
        for bad in ["", "-1", "soon", "inf", "nan", "1e99"] {
            assert!(parse_seconds(bad).is_err(), "{bad:?}");
        }
    }

    fn hot_patch_args(extra: &[&str]) -> HotPatchArgs {
        use clap::Parser;
        let argv = ["socket-patch", NAME].iter().chain(extra);
        match crate::Cli::try_parse_from(argv).unwrap().command {
            crate::Commands::HotPatch(args) => args,
            _ => unreachable!("parsed a hot-patch"),
        }
    }

    fn scan_args(extra: &[&str]) -> ScanArgs {
        hot_patch_args(extra).scan
    }

    #[test]
    fn hot_patch_takes_scans_options_and_a_time_limit() {
        let args = hot_patch_args(&["--timeout", "2.5", "--min-severity", "high", "-g"]);
        assert_eq!(args.timeout, Some(Duration::from_millis(2500)));
        assert_eq!(args.scan.socket_yml.min_severity.as_deref(), Some("high"));
        assert!(args.scan.common.global);
        assert_eq!(hot_patch_args(&[]).timeout, None);
    }

    fn ecosystems(pass: &ScanArgs) -> Vec<&str> {
        let named = pass.common.ecosystems.as_deref().unwrap_or_default();
        named.iter().map(String::as_str).collect()
    }

    #[test]
    fn a_start_is_a_project_pass_then_a_global_pass() {
        let state = Path::new("/state");
        let passes = passes(&scan_args(&["packages/*"]), state);
        let [(PROJECT, project), (GLOBAL, global)] = passes.as_slice() else {
            panic!("a project pass and a global pass, got {}", passes.len());
        };
        assert!(!project.common.global);
        assert_eq!(project.paths, ["packages/*"]);
        assert_eq!(project.common.manifest_path, "/state/project/manifest.json");
        // Go is the global pass's: a project run would rewrite `go.mod`.
        assert!(!ecosystems(project).contains(&"golang"));
        assert!(ecosystems(project).contains(&"npm"));
        assert!(global.common.global);
        assert!(global.paths.is_empty());
        assert_eq!(global.common.ecosystems, None);
        assert_eq!(global.common.manifest_path, "/state/global/manifest.json");
    }

    #[test]
    fn global_and_go_only_runs_have_one_pass() {
        let state = Path::new("/state");
        let only_global = passes(&scan_args(&["--global"]), state);
        assert_eq!(only_global.len(), 1);
        assert_eq!(only_global[0].0, GLOBAL);
        assert!(only_global[0].1.common.global);

        let only_go = passes(&scan_args(&["--ecosystems", "golang"]), state);
        assert_eq!(only_go.len(), 1);
        assert!(only_go[0].1.common.global);
        assert_eq!(ecosystems(&only_go[0].1), ["golang"]);

        let two = passes(&scan_args(&["--ecosystems", "npm,golang"]), state);
        assert_eq!(two.len(), 2);
        assert_eq!(ecosystems(&two[0].1), ["npm"]);
        assert_eq!(ecosystems(&two[1].1), ["npm", "golang"]);
    }

    #[test]
    fn the_line_says_what_was_patched() {
        let project = json!({ "status": "success", "scannedPackages": 106, "events": [
            { "action": "downloaded", "purl": "pkg:npm/a@1" },
            { "action": "applied", "purl": "pkg:npm/a@1" },
            { "action": "applied", "purl": "pkg:npm/b@1" },
            { "action": "skipped", "purl": "pkg:npm/c@1", "errorCode": "already_patched" },
        ]});
        let global = json!({ "status": "success", "scannedPackages": 186, "events": [
            { "action": "applied", "purl": "pkg:npm/d@1" },
        ]});
        assert_eq!(
            summary_line(
                &[(PROJECT, project), (GLOBAL, global)],
                false,
                LIMIT,
                "1.2s"
            ),
            "applied 3 patches; 1 patch already in place \
             [106 project + 186 global packages checked, 1.2s]"
        );
        let nothing = json!({ "status": "success", "scannedPackages": 37, "events": [] });
        assert_eq!(
            summary_line(&[(GLOBAL, nothing)], false, LIMIT, "0.9s"),
            "no patches to apply [37 global packages checked, 0.9s]"
        );
    }

    /// A package both passes reach is patched by the first and found in
    /// place by the second: one patch, said once.
    #[test]
    fn a_patch_both_passes_reach_is_said_once() {
        let project = json!({ "status": "success", "scannedPackages": 37, "events": [
            { "action": "applied", "purl": "pkg:pypi/flask@2.0.0" },
        ]});
        let global = json!({ "status": "success", "scannedPackages": 37, "events": [
            { "action": "skipped", "purl": "pkg:pypi/flask@2.0.0", "errorCode": "already_patched" },
            { "action": "skipped", "purl": "pkg:pypi/older@1.0.0", "errorCode": "already_patched" },
        ]});
        assert_eq!(
            summary_line(
                &[(PROJECT, project), (GLOBAL, global)],
                false,
                LIMIT,
                "1.0s"
            ),
            "applied 1 patch; 1 patch already in place \
             [37 project + 37 global packages checked, 1.0s]"
        );
    }

    #[test]
    fn the_line_says_why_nothing_was_patched() {
        let read_only = json!({ "status": "partialFailure", "scannedPackages": 106, "events": [
            { "action": "failed", "purl": "pkg:npm/a@1",
              "error": "Cannot apply patch: index.js - Permission denied (os error 13)" },
            { "action": "failed", "purl": "pkg:npm/b@1", "error": "x" },
        ]});
        assert_eq!(
            summary_line(&[(PROJECT, read_only)], false, LIMIT, "1.0s"),
            "2 patches not applied: the installed packages are not writable by this user \
             (pkg:npm/a@1: Cannot apply patch: index.js - Permission denied (os error 13)) \
             [106 project packages checked, 1.0s]"
        );
        // Both passes failing the same way is said once.
        let api_down = json!({ "status": "error", "scannedPackages": 106, "events": [],
            "error": { "code": "api_batch_failed", "message": "Network error: connection refused" } });
        assert_eq!(
            summary_line(
                &[(PROJECT, api_down.clone()), (GLOBAL, api_down)],
                false,
                LIMIT,
                "0.1s"
            ),
            "the patch check failed (Network error: connection refused) \
             [106 project + 106 global packages checked, 0.1s]"
        );
    }

    #[test]
    fn the_line_says_what_the_time_limit_cut_off() {
        assert_eq!(
            summary_line(&[], true, LIMIT, "5.0s"),
            "the patch check did not finish in 5.0s, so nothing was patched [5.0s]"
        );
        let project = json!({ "status": "success", "scannedPackages": 106, "events": [
            { "action": "applied", "purl": "pkg:npm/a@1" },
        ]});
        assert_eq!(
            summary_line(&[(PROJECT, project)], true, LIMIT, "5.0s"),
            "applied 1 patch; the global packages were not checked within 5.0s \
             [106 project packages checked, 5.0s]"
        );
    }

    /// A package both passes fail on is one patch not applied, not two.
    #[test]
    fn a_failure_both_passes_reach_is_said_once() {
        let failing = json!({ "status": "partialFailure", "scannedPackages": 37, "events": [
            { "action": "failed", "purl": "pkg:pypi/flask@2.0.0",
              "error": "Cannot apply patch: app.py - Read-only file system (os error 30)" },
        ]});
        assert_eq!(
            summary_line(
                &[(PROJECT, failing.clone()), (GLOBAL, failing)],
                false,
                LIMIT,
                "1.0s"
            ),
            "1 patch not applied: the installed packages are on a read-only file system \
             (pkg:pypi/flask@2.0.0: Cannot apply patch: app.py - Read-only file system \
             (os error 30)) [37 project + 37 global packages checked, 1.0s]"
        );
    }

    /// A dry run writes nothing, and the line must not read as "nothing to
    /// patch": it says what a real start would apply.
    #[test]
    fn the_line_says_what_a_dry_run_would_apply() {
        let project = json!({ "status": "success", "dryRun": true, "scannedPackages": 106,
        "events": [
            { "action": "verified", "purl": "pkg:npm/a@1" },
            { "action": "verified", "purl": "pkg:npm/b@1" },
        ]});
        let global = json!({ "status": "success", "dryRun": true, "scannedPackages": 186,
            "events": [] });
        assert_eq!(
            summary_line(
                &[(PROJECT, project), (GLOBAL, global)],
                false,
                LIMIT,
                "1.0s"
            ),
            "dry run: 2 patches would be applied \
             [106 project + 186 global packages checked, 1.0s]"
        );
    }
}
