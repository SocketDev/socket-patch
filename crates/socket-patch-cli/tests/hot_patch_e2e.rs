//! `socket-patch hot-patch -- <command>` (experimental): hot patch mode,
//! as a container's entrypoint runs it. It patches everything installed in
//! place, saves nothing, and becomes the command, which starts no matter
//! what the patching did.
//!
//! Each test spawns the real binary against a mock public patch proxy. The
//! project has one npm package installed locally and the machine one
//! "globally": `npm` on the test's `PATH` is a stub whose `npm root -g`
//! names a directory of the test's own, so the global sweep is hermetic.
//! The command each run wraps is a `sh` one-liner that prints the package
//! files, so its stdout shows what the command saw.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;
use common::git_sha256;

/// A package of the fixture: where it is installed, the patch for it and
/// the severity of the advisory that patch fixes.
struct Package {
    name: &'static str,
    purl: &'static str,
    uuid: &'static str,
    severity: &'static str,
}

const LOCAL: Package = Package {
    name: "hot-local",
    purl: "pkg:npm/hot-local@1.0.0",
    uuid: "4c4f4341-4c4f-4341-8c4f-43414c4f4341",
    severity: "critical",
};
const GLOBAL: Package = Package {
    name: "hot-global",
    purl: "pkg:npm/hot-global@1.0.0",
    uuid: "474c4f42-474c-4f42-8c47-4c4f42474c4f",
    severity: "low",
};
const ORIGINAL: &str = "module.exports = 'original';\n";
const PATCHED: &str = "module.exports = 'patched';\n";

/// A project directory, a global `node_modules`, a stub `npm`, an empty
/// home and a temp dir, all removed with `guard`.
struct Fixture {
    _guard: tempfile::TempDir,
    project: PathBuf,
    global: PathBuf,
    bin: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
}

fn install(node_modules: &Path, package: &Package) {
    let dir = node_modules.join(package.name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{ "name": "{}", "version": "1.0.0" }}"#, package.name),
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), ORIGINAL).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let guard = tempfile::tempdir().unwrap();
        let outer = guard.path().canonicalize().unwrap();
        let fixture = Self {
            project: outer.join("project"),
            global: outer.join("global").join("node_modules"),
            bin: outer.join("bin"),
            home: outer.join("home"),
            tmp: outer.join("tmp"),
            _guard: guard,
        };
        for dir in [&fixture.project, &fixture.bin, &fixture.home, &fixture.tmp] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(
            fixture.project.join("package.json"),
            r#"{ "name": "hot-test", "version": "0.0.0" }"#,
        )
        .unwrap();
        // `npm root -g` answers with the fixture's global directory.
        let npm = fixture.bin.join("npm");
        std::fs::write(
            &npm,
            format!("#!/bin/sh\necho '{}'\n", fixture.global.display()),
        )
        .unwrap();
        std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).unwrap();
        fixture.reinstall();
        fixture
    }

    /// Lay the packages down again, pristine: a fresh container.
    fn reinstall(&self) {
        install(&self.project.join("node_modules"), &LOCAL);
        install(&self.global, &GLOBAL);
    }

    fn local_file(&self) -> PathBuf {
        self.project
            .join("node_modules")
            .join(LOCAL.name)
            .join("index.js")
    }

    fn global_file(&self) -> PathBuf {
        self.global.join(GLOBAL.name).join("index.js")
    }

    /// The command the runs wrap: print both package files, exit 7.
    fn show(&self) -> String {
        format!(
            "cat '{}' '{}'; exit 7",
            self.local_file().display(),
            self.global_file().display()
        )
    }

    /// `socket-patch hot-patch <scan_args> -- <command>` in the project.
    fn command(&self, proxy: &str, scan_args: &[&str], command: &[&str]) -> std::process::Command {
        let mut cmd = common::hermetic::binary_command();
        common::hermetic::scrub_crawler_inputs(&mut cmd);
        cmd.current_dir(&self.project)
            .arg("hot-patch")
            // One ecosystem keeps the global pass to the stub `npm`.
            .args(["--ecosystems", "npm"]);
        // Only the tests of the time limit run under a short one: a loaded
        // machine must not turn the others into a timeout.
        if !scan_args.contains(&"--timeout") {
            cmd.args(["--timeout", "60"]);
        }
        cmd.args(scan_args)
            .arg("--")
            .args(command)
            .env("PATH", format!("{}:/bin:/usr/bin", self.bin.display()))
            // No version manager's global installs under the real home.
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmp)
            .env("SOCKET_PROXY_URL", proxy)
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, proxy: &str, scan_args: &[&str]) -> Output {
        self.command(proxy, scan_args, &["sh", "-c", &self.show()])
            .output()
            .unwrap()
    }

    /// Nothing is saved: no `.socket` in the project, an empty temp dir.
    fn assert_nothing_saved(&self) {
        assert_eq!(entries(&self.project), ["node_modules", "package.json"]);
        assert_eq!(entries(&self.tmp), Vec::<String>::new());
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The mock proxy: one patch for each fixture package while
/// `offered` is set, none once it is cleared. `delay` slows the batch
/// answer of the project pass, `global_delay` that of the global pass (the
/// query that names the global package).
async fn mock_api(offered: Arc<AtomicBool>, delay: Duration, global_delay: Duration) -> MockServer {
    use base64::Engine;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let asked: Vec<&str> = body["components"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|component| component["purl"].as_str())
                .collect();
            let packages: Vec<Value> = [&LOCAL, &GLOBAL]
                .into_iter()
                .filter(|package| offered.load(Ordering::SeqCst) && asked.contains(&package.purl))
                .map(|package| {
                    json!({ "purl": package.purl, "patches": [{
                        "uuid": package.uuid, "purl": package.purl, "tier": "free",
                        "cveIds": [], "ghsaIds": ["GHSA-hott-hott-hott"],
                        "severity": package.severity, "title": "fixture"
                    }]})
                })
                .collect();
            ResponseTemplate::new(200)
                .set_delay(if asked.contains(&GLOBAL.purl) {
                    global_delay
                } else {
                    delay
                })
                .set_body_json(json!({ "packages": packages, "canAccessPaidPatches": false }))
        })
        .mount(&server)
        .await;
    for package in [&LOCAL, &GLOBAL] {
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/patch/by-package/.*{}.*$",
                package.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [{
                    "uuid": package.uuid, "purl": package.purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": { "GHSA-hott-hott-hott": {
                        "cves": [], "summary": "s", "severity": package.severity, "description": "d"
                    }}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/patch/view/{}", package.uuid)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": package.uuid, "purl": package.purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": git_sha256(ORIGINAL.as_bytes()),
                    "afterHash": git_sha256(PATCHED.as_bytes()),
                    "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
                }},
                "vulnerabilities": {}, "description": "x", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
    }
    server
}

async fn offering_api() -> MockServer {
    mock_api(
        Arc::new(AtomicBool::new(true)),
        Duration::ZERO,
        Duration::ZERO,
    )
    .await
}

/// The whole point: the project's and the global packages are patched in
/// one run, whatever the severity of what a patch fixes, the command then
/// runs with its own exit status, and nothing is left behind.
#[tokio::test(flavor = "multi_thread")]
async fn patches_local_and_global_packages_then_becomes_the_command() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let output = fixture.run(&server.uri(), &[]);
    assert_eq!(
        stdout(&output),
        format!("{PATCHED}{PATCHED}"),
        "{}",
        stderr(&output)
    );
    assert_eq!(output.status.code(), Some(7), "the command's own status");
    let stderr = stderr(&output);
    assert!(
        stderr.contains("socket-patch: applied 2 patches"),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "one line of output:\n{stderr}");
    fixture.assert_nothing_saved();
    // Each pass fetched its own patch, once. (The batch count is the
    // machine's: on macOS the global pass also reads the host's own global
    // `node_modules`, for which the mock offers nothing.)
    let requests = server.received_requests().await.unwrap_or_default();
    let views = requests
        .iter()
        .filter(|r| r.url.path().starts_with("/patch/view/"));
    assert_eq!(views.count(), 2);
}

/// `--global` leaves the project pass out, as it does for any other scan.
#[tokio::test(flavor = "multi_thread")]
async fn global_runs_the_global_pass_alone() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let output = fixture.run(&server.uri(), &["--global"]);
    assert_eq!(
        stdout(&output),
        format!("{ORIGINAL}{PATCHED}"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("applied 1 patch"),
        "{}",
        stderr(&output)
    );
}

/// The command replaces the scan process: same PID, so a container's
/// signals and exit status are the command's, with nothing in between.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_runs_in_the_same_process() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let child = fixture
        .command(&server.uri(), &[], &["sh", "-c", "echo $$"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        stdout(&output).trim(),
        pid.to_string(),
        "{}",
        stderr(&output)
    );
}

/// Everything after the first `--` is the command, flags included.
#[tokio::test(flavor = "multi_thread")]
async fn the_commands_own_flags_are_not_scans() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let output = fixture
        .command(
            &server.uri(),
            &[],
            &[
                "sh",
                "-c",
                "echo \"$@\"",
                "sh",
                "--json",
                "--timeout",
                "--",
                "--help",
            ],
        )
        .output()
        .unwrap();
    assert_eq!(
        stdout(&output),
        "--json --timeout -- --help\n",
        "{}",
        stderr(&output)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_api_does_not_stop_the_command() {
    let fixture = Fixture::new();

    // Nothing listens on port 9 of the loopback: the connect is refused.
    let output = fixture.run("http://127.0.0.1:9", &[]);
    assert_eq!(stdout(&output), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(output.status.code(), Some(7));
    assert!(
        stderr(&output).contains("the patch check failed"),
        "{}",
        stderr(&output)
    );
    fixture.assert_nothing_saved();
}

/// The time limit drops a run that is still waiting on the API: nothing
/// was written, and the command starts unpatched.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_api_is_cut_off_at_the_time_limit() {
    let slow = Duration::from_secs(60);
    let server = mock_api(Arc::new(AtomicBool::new(true)), slow, slow).await;
    let fixture = Fixture::new();

    let started = Instant::now();
    let output = fixture.run(&server.uri(), &["--timeout", "0.5"]);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the command waited {:?} on a 60 s API",
        started.elapsed()
    );
    assert_eq!(stdout(&output), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(output.status.code(), Some(7));
    assert!(
        stderr(&output).contains("did not finish in 0.5s, so nothing was patched"),
        "{}",
        stderr(&output)
    );
    fixture.assert_nothing_saved();
}

/// The limit is the run's, not each pass's: a global pass that is still
/// waiting when it is reached is dropped, and what the project pass
/// patched stays patched.
#[tokio::test(flavor = "multi_thread")]
async fn the_time_limit_can_cut_off_the_global_pass_alone() {
    let server = mock_api(
        Arc::new(AtomicBool::new(true)),
        Duration::ZERO,
        Duration::from_secs(120),
    )
    .await;
    let fixture = Fixture::new();

    let output = fixture.run(&server.uri(), &["--timeout", "12"]);
    assert_eq!(
        stdout(&output),
        format!("{PATCHED}{ORIGINAL}"),
        "{}",
        stderr(&output)
    );
    assert_eq!(output.status.code(), Some(7));
    assert!(
        stderr(&output)
            .contains("applied 1 patch; the global packages were not checked within 12.0s"),
        "{}",
        stderr(&output)
    );
    fixture.assert_nothing_saved();
}

/// Nothing is recorded, so the API's answer at each start is the whole
/// patch set: a patch it stops offering is not applied to a fresh tree.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_patch_is_not_applied_to_a_fresh_tree() {
    let offered = Arc::new(AtomicBool::new(true));
    let server = mock_api(offered.clone(), Duration::ZERO, Duration::ZERO).await;
    let fixture = Fixture::new();
    let first = fixture.run(&server.uri(), &[]);
    assert_eq!(
        stdout(&first),
        format!("{PATCHED}{PATCHED}"),
        "{}",
        stderr(&first)
    );

    offered.store(false, Ordering::SeqCst);
    fixture.reinstall();
    let second = fixture.run(&server.uri(), &[]);
    assert_eq!(
        stdout(&second),
        format!("{ORIGINAL}{ORIGINAL}"),
        "{}",
        stderr(&second)
    );
    assert!(
        stderr(&second).contains("no patches to apply"),
        "{}",
        stderr(&second)
    );
}

/// The same container started again: the files are already patched and
/// are left alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_finds_its_patches_in_place() {
    let server = offering_api().await;
    let fixture = Fixture::new();
    let first = fixture.run(&server.uri(), &[]);
    assert_eq!(
        stdout(&first),
        format!("{PATCHED}{PATCHED}"),
        "{}",
        stderr(&first)
    );

    let second = fixture.run(&server.uri(), &[]);
    assert_eq!(stdout(&second), format!("{PATCHED}{PATCHED}"));
    assert!(
        stderr(&second).contains("2 patches already in place"),
        "{}",
        stderr(&second)
    );
}

/// A flag or an environment value scan cannot parse is reported, and the
/// command starts anyway.
#[tokio::test(flavor = "multi_thread")]
async fn a_usage_error_does_not_stop_the_command() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let bad_flag = fixture.run(&server.uri(), &["--no-such-option"]);
    assert_eq!(stdout(&bad_flag), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(bad_flag.status.code(), Some(7));
    assert!(
        stderr(&bad_flag).contains("--no-such-option"),
        "{}",
        stderr(&bad_flag)
    );

    let bad_env = fixture
        .command(&server.uri(), &[], &["sh", "-c", &fixture.show()])
        .env("SOCKET_BATCH_SIZE", "many")
        .output()
        .unwrap();
    assert_eq!(stdout(&bad_env), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(bad_env.status.code(), Some(7), "{}", stderr(&bad_env));

    // In-place patching is agent mode's: another mode is refused, not run.
    let hosted = fixture.run(&server.uri(), &["--mode", "hosted"]);
    assert_eq!(stdout(&hosted), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(hosted.status.code(), Some(7));
    assert!(
        stderr(&hosted).contains("cannot be used with --mode hosted"),
        "{}",
        stderr(&hosted)
    );

    // So are the flags that keep or manage saved patches: this mode
    // saves none.
    let kept = fixture.tmp.join("kept.json");
    let vex = fixture.tmp.join("vex.json");
    for (flags, named) in [
        (
            vec!["--manifest-path", kept.to_str().unwrap()],
            "--manifest-path",
        ),
        (vec!["--prune"], "--prune or --sync"),
        (vec!["--sync"], "--prune or --sync"),
        (vec!["--vex", vex.to_str().unwrap()], "--vex"),
    ] {
        let refused = fixture.run(&server.uri(), &flags);
        assert_eq!(stdout(&refused), format!("{ORIGINAL}{ORIGINAL}"));
        assert_eq!(refused.status.code(), Some(7));
        let stderr = stderr(&refused);
        assert!(
            stderr.contains("patching skipped: hot-patch saves nothing") && stderr.contains(named),
            "{stderr}"
        );
    }

    // And a rollout cap: it paces patches by what earlier runs recorded,
    // and this mode records nothing.
    let capped = fixture.run(&server.uri(), &["--max-new-patches", "1"]);
    assert_eq!(stdout(&capped), format!("{ORIGINAL}{ORIGINAL}"));
    assert!(
        stderr(&capped).contains("cannot be used with --max-new-patches"),
        "{}",
        stderr(&capped)
    );
    fixture.assert_nothing_saved();
}

/// Not even a panic keeps the command from starting. A stderr that cannot
/// be written to (a full log volume) makes the report of a usage error
/// panic, where the process used to end with status 101.
#[tokio::test(flavor = "multi_thread")]
async fn a_panic_does_not_stop_the_command() {
    // A device every write to fails with ENOSPC: Linux only.
    let Ok(full) = std::fs::OpenOptions::new().write(true).open("/dev/full") else {
        return;
    };
    let server = offering_api().await;
    let fixture = Fixture::new();

    let output = fixture
        .command(&server.uri(), &[], &["sh", "-c", &fixture.show()])
        .env("SOCKET_CWD", fixture.tmp.join("no-such-directory"))
        .stderr(full)
        .output()
        .unwrap();
    assert_eq!(stdout(&output), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(output.status.code(), Some(7));
}

/// `SOCKET_OFFLINE=1` is the off switch: no request, no patch, the command.
#[tokio::test(flavor = "multi_thread")]
async fn offline_starts_the_command_without_patching() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let output = fixture
        .command(&server.uri(), &[], &["sh", "-c", &fixture.show()])
        .env("SOCKET_OFFLINE", "1")
        .output()
        .unwrap();
    assert_eq!(stdout(&output), format!("{ORIGINAL}{ORIGINAL}"));
    assert_eq!(output.status.code(), Some(7));
    assert!(
        stderr(&output).contains("socket-patch: patching skipped: offline"),
        "{}",
        stderr(&output)
    );
    assert!(server
        .received_requests()
        .await
        .unwrap_or_default()
        .is_empty());
}

/// A command that cannot be started exits the way a shell would report it.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_command_exits_127_and_no_command_exits_2() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let missing = fixture
        .command(
            &server.uri(),
            &[],
            &["no-such-command-socket-patch-hot-patch"],
        )
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(127), "{}", stderr(&missing));

    // With no command to start, nothing is checked or patched: the run
    // says where the command goes and exits 2.
    let requests_before = server.received_requests().await.unwrap_or_default().len();
    let none = fixture.command(&server.uri(), &[], &[]).output().unwrap();
    assert_eq!(none.status.code(), Some(2), "{}", stderr(&none));
    assert!(
        stderr(&none).contains("needs a command to start after `--`"),
        "{}",
        stderr(&none)
    );

    // The same without the `--` itself, whatever scan makes of the words
    // that were meant as the command.
    let mut unseparated = common::hermetic::binary_command();
    let unseparated = unseparated
        .current_dir(&fixture.project)
        .args(["hot-patch", "sh", "-c", "exit 7"])
        .env("SOCKET_PROXY_URL", server.uri())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(unseparated.status.code(), Some(2));
    assert!(
        stderr(&unseparated).contains("needs a command to start after `--`"),
        "{}",
        stderr(&unseparated)
    );
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        requests_before
    );
}

/// Every patch is applied unless the run is told otherwise:
/// `--min-severity` and `SOCKET_MIN_SEVERITY` narrow both passes, as they
/// narrow a scan.
#[tokio::test(flavor = "multi_thread")]
async fn a_severity_floor_narrows_both_passes() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    // The global package's patch fixes a low-severity advisory.
    let by_flag = fixture.run(&server.uri(), &["--min-severity", "critical"]);
    assert_eq!(
        stdout(&by_flag),
        format!("{PATCHED}{ORIGINAL}"),
        "{}",
        stderr(&by_flag)
    );

    fixture.reinstall();
    let by_env = fixture
        .command(&server.uri(), &[], &["sh", "-c", &fixture.show()])
        .env("SOCKET_MIN_SEVERITY", "critical")
        .output()
        .unwrap();
    assert_eq!(
        stdout(&by_env),
        format!("{PATCHED}{ORIGINAL}"),
        "{}",
        stderr(&by_env)
    );
}

/// A rollout cap in socket.yml (or the environment) does not hold patches
/// back: with no record of earlier runs it would hold the same ones back
/// on every start.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_cap_from_the_project_does_not_hold_patches_back() {
    let server = offering_api().await;
    let fixture = Fixture::new();
    std::fs::write(
        fixture.project.join("socket.yml"),
        "version: 2\npatches:\n  maxNewPatches: 0\n",
    )
    .unwrap();

    let output = fixture
        .command(&server.uri(), &[], &["sh", "-c", &fixture.show()])
        .env("SOCKET_MAX_NEW_PATCHES", "0")
        .output()
        .unwrap();
    assert_eq!(
        stdout(&output),
        format!("{PATCHED}{PATCHED}"),
        "{}",
        stderr(&output)
    );
}

/// `--dry-run` writes nothing, and says what a real start would apply
/// instead of "no patches to apply".
#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_patches_nothing_and_says_what_it_would() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let output = fixture.run(&server.uri(), &["--dry-run"]);
    assert_eq!(
        stdout(&output),
        format!("{ORIGINAL}{ORIGINAL}"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("socket-patch: dry run: 2 patches would be applied"),
        "{}",
        stderr(&output)
    );
    fixture.assert_nothing_saved();
}

/// The working directory's socket.yml governs both passes: a package the
/// repository excludes is left alone in the global installs too, where a
/// plain `--global` scan would read no policy file.
#[tokio::test(flavor = "multi_thread")]
async fn the_projects_socket_yml_covers_the_global_pass() {
    let server = offering_api().await;
    let fixture = Fixture::new();
    std::fs::write(
        fixture.project.join("socket.yml"),
        format!(
            "version: 2\npatches:\n  ignorePackages: [{}]\n",
            GLOBAL.name
        ),
    )
    .unwrap();

    let output = fixture.run(&server.uri(), &[]);
    assert_eq!(
        stdout(&output),
        format!("{PATCHED}{ORIGINAL}"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("socket-patch: applied 1 patch"),
        "{}",
        stderr(&output)
    );
}

/// The command starts with the environment the run was given, not the one
/// socket-patch works in: a variable its own start-up removes (a vetoed
/// token, an empty value) or sets (`--debug`) reaches the command as given.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_starts_with_the_environment_it_was_given() {
    let server = offering_api().await;
    let fixture = Fixture::new();

    let show = r#"echo "token=${SOCKET_API_TOKEN-unset} org=${SOCKET_ORG_SLUG-unset} debug=${SOCKET_DEBUG-unset}""#;
    let output = fixture
        .command(&server.uri(), &["--debug"], &["sh", "-c", show])
        .env("SOCKET_NO_API_TOKEN", "1")
        .env("SOCKET_API_TOKEN", "given-token")
        .env("SOCKET_ORG_SLUG", "")
        .env_remove("SOCKET_DEBUG")
        .output()
        .unwrap();
    assert_eq!(
        stdout(&output),
        "token=given-token org= debug=unset\n",
        "{}",
        stderr(&output)
    );
}

/// A run told to stop while it is still patching stops, and the command is
/// never started.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_signal_during_the_check_ends_the_run_without_the_command() {
    let server = mock_api(
        Arc::new(AtomicBool::new(true)),
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .await;
    let fixture = Fixture::new();
    let marker = fixture.tmp.join("command-ran");

    let child = fixture
        .command(
            &server.uri(),
            &["--timeout", "45"],
            &["touch", marker.to_str().unwrap()],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait until the run is asking the API, then stop it.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let requests = server.received_requests().await.unwrap_or_default();
        if requests.iter().any(|r| r.url.path() == "/patch/batch") {
            break;
        }
        assert!(Instant::now() < deadline, "the run never reached the API");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // SAFETY: signalling a child this test spawned and has not reaped.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let started = Instant::now();
    let output = child.wait_with_output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGTERM),
        "{}",
        stderr(&output)
    );
    assert!(!marker.exists(), "the command must not start after a stop");
}
