//! Coverage-gap tests for the interactive TTY branches of `src/ui/prompt.rs`
//! (2026-09 coverage audit):
//!
//! * `confirm()`'s bare-Enter -> `default_yes` return. Every production
//!   caller passes `default_yes = true`, so this IS the "Enter proceeds
//!   with the destructive action" contract — the sibling pty suite drives
//!   `y`, `n`, and non-UTF-8 answers through `ui::confirm` but never a
//!   bare Enter (its bare-Enter test hits `setup`'s default-no
//!   `confirm_or_proceed`).
//! * `select_one()`'s `dialoguer::Select` branch, whose
//!   sole production caller is `get`'s free-user multi-patch selection:
//!   the Enter-accepts-first-ranked-option happy path and the
//!   quit -> `interact_opt` `Ok(None)` -> `SelectError::Cancelled` exit path.
//!
//! PTY support: macOS + Linux. Skipped on Windows.

#![cfg(unix)]

#[path = "common/pty_io.rs"]
mod pty_io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Pulled in for `git_sha256` (the patch-view blob fixture below must clear
// PR #158's "patch has no applicable files" guardrail with a real blob
// hash). Read-only reuse of the shared helper module.
#[path = "common/mod.rs"]
mod common;

const ORG_SLUG: &str = "test-org";
const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Spawn the socket-patch binary inside a PTY, send `input`, and collect
/// all output until the child exits. Returns `(exit_code, output)`.
///
/// Same choreography as the sibling `interactive_prompts_e2e.rs` harness
/// (reader thread on the master, detached SIGKILL watchdog, input written
/// once a prompt is on screen via `pty_io::send_when_prompted` — `confirm`
/// discards earlier typeahead — then EOF on the writer) — plus a
/// pinned `TERM` because the `dialoguer`/`console` menu these tests drive
/// derives key handling and rendering from the terminal type, which the
/// ambient environment (some CI shells) may not set at all.
fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
    let (code, _signal, output) = run_in_pty_raw(Sigint::Default, args, cwd, input, timeout);
    (code, output)
}

/// [`run_in_pty`] with a second answer: `then` is written once the y/n
/// confirm (`[Y/n] `) is on screen, after `input` answered the first
/// prompt (the dialoguer menu).
fn run_in_pty_then(
    args: &[&str],
    cwd: &Path,
    input: &str,
    then: &str,
    timeout: Duration,
) -> (i32, String) {
    let (code, _signal, output) =
        run_in_pty_inner(Sigint::Default, args, cwd, input, Some(then), timeout);
    (code, output)
}

/// The SIGINT disposition the binary starts with under [`run_in_pty_raw`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sigint {
    /// Inherited default: Ctrl-C kills the process.
    Default,
    /// Ignored (as `nohup` and some launchers do), via
    /// `sh -c 'trap "" INT; exec ...'`.
    Ignored,
}

/// [`run_in_pty`], also returning the name of the signal that ended the
/// child (`None` for a normal exit), with the binary started under the
/// given [`Sigint`] disposition.
fn run_in_pty_raw(
    sigint: Sigint,
    args: &[&str],
    cwd: &Path,
    input: &str,
    timeout: Duration,
) -> (i32, Option<String>, String) {
    run_in_pty_inner(sigint, args, cwd, input, None, timeout)
}

fn run_in_pty_inner(
    sigint: Sigint,
    args: &[&str],
    cwd: &Path,
    input: &str,
    then: Option<&str>,
    timeout: Duration,
) -> (i32, Option<String>, String) {
    let input = input.as_bytes();
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = if sigint == Sigint::Ignored {
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.arg("-c");
        cmd.arg("trap '' INT; exec \"$0\" \"$@\"");
        cmd.arg(binary());
        cmd
    } else {
        CommandBuilder::new(binary())
    };
    for a in args {
        cmd.arg(a);
    }
    cmd.cwd(cwd);
    // The binary binds a wide `SOCKET_*` env surface. An ambient value
    // silently reroutes what these tests exercise — SOCKET_YES=true skips
    // the very confirm prompt the bare-Enter test exists to drive, and
    // SOCKET_JSON=true flips select_one onto its JsonModeNeedsExplicit
    // branch before the dialoguer menu ever renders. The highest-risk vars
    // are seeded with hostile values and then scrubbed — `env_remove`
    // clears the seed too, so the child never sees it, but if a scrub line
    // is ever dropped the seed (rather than a developer's ambient shell,
    // which this suite can't rely on) turns the tests red immediately.
    cmd.env("SOCKET_YES", "true");
    cmd.env("SOCKET_JSON", "true");
    cmd.env("SOCKET_DRY_RUN", "true");
    cmd.env("SOCKET_SILENT", "true");
    cmd.env_remove("SOCKET_YES");
    cmd.env_remove("SOCKET_JSON");
    cmd.env_remove("SOCKET_DRY_RUN");
    cmd.env_remove("SOCKET_SILENT");
    // Prefix-scrub whatever else the ambient shell carries (SOCKET_CWD,
    // SOCKET_MANIFEST_PATH, SOCKET_API_TOKEN, SOCKET_PROXY_URL — the get
    // tests pin their API endpoint by flag and must not be rerouted).
    // Telemetry opt-outs are deliberately kept so an opted-out dev stays
    // opted out.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_")
            && !name.contains("TELEMETRY")
            && name != "SOCKET_NO_CONFIG"
            && name != "SOCKET_NO_UPDATE_CHECK"
        {
            cmd.env_remove(&key);
        }
    }
    // A developer's real `socket login` (the socket-cli config.json token
    // fallback) must never authenticate a test child.
    cmd.env("SOCKET_NO_CONFIG", "1");
    // This suite hands children a REAL terminal, so the update notifier's
    // stderr-TTY guard does not protect it. Force the kill-switch so no PTY
    // child ever fetches release metadata mid-prompt.
    cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
    // `dialoguer`/`console` key handling needs a terminal type; pin one so
    // an unset ambient TERM (bare CI shells) can't skew rendering.
    cmd.env("TERM", "xterm-256color");

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("spawn socket-patch in PTY");
    drop(pair.slave);

    let reader_handle = crate::pty_io::PtyOutput::spawn(
        pair.master.try_clone_reader().expect("clone reader"),
    );

    // Watchdog: detached kill after `timeout`; a no-op if the child exits
    // naturally first.
    let mut killer = child.clone_killer();
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        let _ = killer.kill();
    });

    let mut writer = pair.master.take_writer().expect("take writer");
    crate::pty_io::send_when_prompted(&reader_handle, &mut writer, input);
    if let Some(then) = then {
        use std::io::Write;
        reader_handle.wait_for_count("[Y/n] ", 1, Duration::from_secs(10));
        let _ = writer.write_all(then.as_bytes());
        let _ = writer.flush();
    }
    drop(writer);

    let status = child.wait().expect("child.wait");
    drop(pair.master);

    let output = reader_handle.finish();
    let code = status.exit_code() as i32;
    (
        code,
        status.signal().map(str::to_string),
        String::from_utf8_lossy(&output).to_string(),
    )
}

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

/// The menu hid the cursor at least once, and the last hide was followed
/// by a show: the user's terminal is left with a visible cursor.
fn assert_cursor_restored(output: &str) {
    let hidden = output
        .rfind(HIDE_CURSOR)
        .unwrap_or_else(|| panic!("the menu must have hidden the cursor; got: {output:?}"));
    assert!(
        output[hidden..].contains(SHOW_CURSOR),
        "the cursor must be shown again after the menu; got: {output:?}"
    );
}

// ---------------------------------------------------------------------------
// ui::confirm — bare Enter takes the printed [Y/n] default
// ---------------------------------------------------------------------------

const REMOVE_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__covgap_output_remove__@1.0.0": {
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "covgap output bare-enter test",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn write_remove_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), REMOVE_MANIFEST).unwrap();
}

#[test]
fn remove_interactive_bare_enter_proceeds_with_default_yes() {
    // `ui::confirm`'s empty-answer arm returns `default_yes`, and every
    // production caller passes `default_yes = true` — so a bare Enter at
    // remove's "[Y/n]" prompt must PROCEED with the removal, matching the
    // hint the prompt printed. The sibling pty suite covers `y`, `n`, and
    // non-UTF-8 answers through this same prompt but never bare Enter.
    let tmp = tempfile::tempdir().unwrap();
    write_remove_manifest(tmp.path());

    let (code, output) = run_in_pty(
        &[
            "remove",
            "pkg:npm/__covgap_output_remove__@1.0.0",
            "--skip-rollback",
        ],
        tmp.path(),
        "\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0, "remove with bare Enter must succeed; got: {output}");
    // The interactive confirm MUST have run — otherwise this test passes
    // vacuously against a regression that drops the TTY gate and
    // auto-proceeds. Match the distinctive prompt verbatim (the loose
    // "Remove"/"patch(es)" pair is also satisfied by the success line).
    assert!(
        output.contains("Remove 1 patch from the manifest without rolling back its files?"),
        "remove must have shown the interactive confirm prompt verbatim; got: {output}"
    );
    // Pin the printed default: the hint must advertise YES-by-default —
    // that is the contract the bare Enter is honoring.
    assert!(
        output.contains("[Y/n]"),
        "remove's confirm must advertise the yes default; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Removed"),
        "bare Enter must take the YES default and remove; got: {output}"
    );
    // Proceeded for real: the manifest's `patches` object must exist and be
    // empty (not merely "missing", which a corrupt rewrite could produce).
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = manifest["patches"]
        .as_object()
        .unwrap_or_else(|| panic!("manifest must keep a 'patches' object; got: {body}"));
    assert!(
        patches.is_empty(),
        "bare-Enter remove must drop the entry; got: {body}"
    );
}

// ---------------------------------------------------------------------------
// ui::select_one — the dialoguer::Select interactive branch (ui/prompt.rs)
// ---------------------------------------------------------------------------

/// Collect the paths of every request the mock actually received. Used to
/// prove which code path the binary really took (vs. fabricating the right
/// output without touching the network it claims to touch).
async fn received_paths(mock: &MockServer) -> Vec<String> {
    mock.received_requests()
        .await
        .expect("wiremock must record received requests")
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

/// A single-file patch-view `files` map that survives PR #158's "patch has
/// no applicable files" guardrail: one net-new file with an all-zero
/// `beforeHash`, a real git-blob `afterHash`, and matching base64
/// `blobContent`. These tests pass `--save-only`, which records without
/// verifying content on disk, so one recordable file clears the guard.
fn single_file_view() -> serde_json::Value {
    // base64 "cGF0Y2hlZAo=" decodes to exactly these bytes.
    let blob_bytes = b"patched\n";
    serde_json::json!({
        "package/index.js": {
            "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
            "afterHash":  common::git_sha256(blob_bytes),
            "blobContent": "cGF0Y2hlZAo=",
        }
    })
}

/// Mount the free-user multi-patch fixture: a by-package listing with TWO
/// free patches for one PURL (forcing `get` through `select_one`'s
/// interactive branch — a free user with a single patch auto-selects), plus
/// view endpoints for BOTH uuids so a wrong selection would *succeed* and
/// be caught by the request log rather than dying on a confusing 404.
///
/// Both patches carry the same `publishedAt` and no vulnerabilities, so
/// `cmp_search_results` falls through severity/coverage/recency to its
/// uuid-ascending backstop: UUID_A ranks first, deterministically, without
/// depending on how the date string parses.
async fn mount_two_free_patches(mock: &MockServer, purl: &str, encoded: &str) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID_A, "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "first", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                },
                {
                    "uuid": UUID_B, "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "second", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    for (uuid, desc) in [(UUID_A, "first"), (UUID_B, "second")] {
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": single_file_view(),
                "vulnerabilities": {},
                "description": desc,
                "license": "MIT",
                "tier": "free",
            })))
            .mount(mock)
            .await;
    }
}

#[test]
fn get_interactive_dialoguer_enter_accepts_first_ranked_option() {
    // Free user + two free patches for one PURL → `select_one` reaches its
    // `dialoguer::Select` branch (ui/prompt.rs). Enter must accept the
    // menu's `.default(0)` — the FIRST-ranked patch (UUID_A by the uuid
    // tiebreak) — and `get` must then fetch exactly that patch's view.
    //
    // The pty runs a sync child while wiremock needs a live async runtime,
    // so the runtime is built manually and kept alive across the pty run.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let purl = "pkg:npm/covgap-multi@1.0.0";
    let encoded = "pkg%3Anpm%2Fcovgap-multi%401.0.0";
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        mount_two_free_patches(&mock, purl, encoded).await;
        mock
    });
    let uri = mock.uri();

    let tmp = tempfile::tempdir().unwrap();
    // No `--yes`: it answers the menu with its default without showing it.
    // "\r" (Enter at a raw-mode terminal) accepts the menu's default, then
    // "\n" answers the "Download 1 patch?" confirm that follows.
    let (code, output) = run_in_pty_then(
        &[
            "get",
            purl,
            "--save-only",
            "--api-url",
            &uri,
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ],
        tmp.path(),
        "\r",
        "\n",
        Duration::from_secs(20),
    );
    assert_eq!(
        code, 0,
        "interactive selection + save-only must succeed; got: {output}"
    );
    // The dialoguer menu MUST have rendered — the prompt text plus BOTH
    // option rows. The non-TTY auto-select branch prints none of these
    // (it never lists the candidates), so their presence pins the
    // interactive branch, not a lookalike outcome.
    assert!(
        output.contains(&format!("Multiple patches available for {purl}")),
        "the dialoguer select prompt must have rendered; got: {output}"
    );
    assert!(
        output.contains(UUID_A) && output.contains(UUID_B),
        "both candidate rows must have rendered in the menu; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode: auto-selecting"),
        "get must NOT have taken the non-TTY auto-select branch in a PTY; got: {output}"
    );
    // Enter accepted the first-ranked option and get proceeded to save it.
    assert!(
        output.contains("Added: 1"),
        "get must have saved the selected patch; got: {output}"
    );
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json"))
        .expect("get --save-only must write .socket/manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        manifest["patches"][purl]["uuid"], UUID_A,
        "Enter must select the FIRST-ranked patch (uuid tiebreak → UUID_A); got: {body}"
    );
    // Prove the route: view/{UUID_A} fetched, view/{UUID_B} never touched —
    // both views are mounted, so a wrong selection would have succeeded and
    // only this request log catches it.
    let paths = rt.block_on(received_paths(&mock));
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with(&format!("/patches/view/{UUID_A}"))),
        "accepting the default must fetch the first-ranked patch's view; recorded paths={paths:?}"
    );
    assert!(
        !paths
            .iter()
            .any(|p| p.ends_with(&format!("/patches/view/{UUID_B}"))),
        "the non-selected patch must not be fetched; recorded paths={paths:?}"
    );
}

#[test]
fn get_yes_answers_the_menu_with_its_default_without_showing_it() {
    // `--yes` skips interactive prompts, the patch menu included: it takes
    // the menu's default (the top-ranked patch) — even at a terminal.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let purl = "pkg:npm/covgap-multi-yes@1.0.0";
    let encoded = "pkg%3Anpm%2Fcovgap-multi-yes%401.0.0";
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        mount_two_free_patches(&mock, purl, encoded).await;
        mock
    });
    let uri = mock.uri();

    let tmp = tempfile::tempdir().unwrap();
    let (code, output) = run_in_pty(
        &[
            "get",
            purl,
            "--save-only",
            "--yes",
            "--api-url",
            &uri,
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ],
        tmp.path(),
        "",
        Duration::from_secs(20),
    );
    assert_eq!(code, 0, "{output}");
    assert!(
        !output.contains("Multiple patches available"),
        "--yes must not open the menu; got: {output}"
    );
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json"))
        .expect("get --save-only must write .socket/manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(manifest["patches"][purl]["uuid"], UUID_A, "{body}");
    // The listing showed two patches; the pick is named before saving.
    let screen = crate::pty_io::render(output.as_bytes()).join("\n");
    assert!(
        screen.contains("Selected:\n  pkg:npm/covgap-multi-yes@1.0.0 [FREE] 11111111"),
        "{screen}"
    );
}

#[test]
fn get_interactive_dialoguer_quit_cancels_with_exit_zero() {
    // Cancelling the dialoguer menu → `interact_opt()` returns `Ok(None)` →
    // `select_one` maps it to `SelectError::Cancelled` (ui/prompt.rs) →
    // get prints "Selection cancelled." and exits 0 without downloading
    // anything (get.rs:660-663).
    //
    // The keystroke is `q`, not ESC: dialoguer 0.11's Select treats
    // `Key::Escape | Key::Char('q')` identically (both return `None` from
    // `interact_opt`), but a lone ESC byte at a pty whose writer then
    // closes strands `console`'s escape-SEQUENCE disambiguation at EOF —
    // it re-renders on Unknown keys forever (verified empirically: the
    // child hung until the watchdog killed it). `q` is a plain character,
    // so it reaches the same cancel arm without the escape-parse race.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let purl = "pkg:npm/covgap-multi-esc@1.0.0";
    let encoded = "pkg%3Anpm%2Fcovgap-multi-esc%401.0.0";
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        mount_two_free_patches(&mock, purl, encoded).await;
        mock
    });
    let uri = mock.uri();

    let tmp = tempfile::tempdir().unwrap();
    let (code, output) = run_in_pty(
        &[
            "get",
            purl,
            "--save-only",
            "--api-url",
            &uri,
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ],
        tmp.path(),
        "q",
        Duration::from_secs(20),
    );
    // Vacuity guard first: the menu MUST have rendered — otherwise an early
    // failure (bad fixture, dead mock) would satisfy the negative
    // assertions below without ever reaching the cancel path.
    assert!(
        output.contains(&format!("Multiple patches available for {purl}")),
        "the dialoguer select prompt must have rendered; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode: auto-selecting"),
        "get must NOT have taken the non-TTY auto-select branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Selection cancelled."),
        "Esc must surface the Cancelled message; got: {output}"
    );
    // dialoguer shows the cursor again itself on a clean q/Esc cancel, so
    // this passes even without CursorGuard; the Ctrl-C test below
    // (`..._ctrl_c_restores_cursor_and_dies_by_sigint`) is the real guard.
    assert_cursor_restored(&output);
    assert_eq!(
        code, 0,
        "a user-cancelled selection is a clean exit, not an error; got: {output}"
    );
    // Cancelled means NOTHING was downloaded or recorded.
    assert!(
        !output.contains("Patches saved"),
        "cancelled selection must not save anything; got: {output}"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "cancelled selection must not write a manifest"
    );
    let paths = rt.block_on(received_paths(&mock));
    assert!(
        !paths.iter().any(|p| p.contains("/patches/view/")),
        "cancelled selection must not fetch any patch view; recorded paths={paths:?}"
    );
    // ... but the by-package listing WAS consulted (the menu had real
    // candidates), so the cancel happened at the selection step, not before.
    assert!(
        paths.iter().any(|p| p.contains("/by-package/")),
        "the by-package listing must have been queried before the menu; recorded paths={paths:?}"
    );
}

#[test]
fn get_interactive_dialoguer_ctrl_c_restores_cursor_and_dies_by_sigint() {
    // Ctrl-C at the menu: console reads the raw ^C byte and raises SIGINT.
    // `select_one`'s guard must show the cursor again before the default
    // SIGINT action kills the process — dialoguer leaves it hidden.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let purl = "pkg:npm/covgap-multi-ctrlc@1.0.0";
    let encoded = "pkg%3Anpm%2Fcovgap-multi-ctrlc%401.0.0";
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        mount_two_free_patches(&mock, purl, encoded).await;
        mock
    });
    let uri = mock.uri();

    let tmp = tempfile::tempdir().unwrap();
    let (code, signal, output) = run_in_pty_raw(
        Sigint::Default,
        &[
            "get",
            purl,
            "--save-only",
            "--api-url",
            &uri,
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ],
        tmp.path(),
        "\x03",
        Duration::from_secs(20),
    );
    assert!(
        output.contains(&format!("Multiple patches available for {purl}")),
        "the dialoguer select prompt must have rendered; got: {output}"
    );
    // Died of the re-raised SIGINT, not the watchdog's SIGKILL and not a
    // normal exit.
    let signal = signal.unwrap_or_else(|| {
        panic!("Ctrl-C must end the process by SIGINT; exited with {code}; got: {output:?}")
    });
    assert!(
        signal.contains("Interrupt"),
        "expected SIGINT, got signal {signal:?}; output: {output:?}"
    );
    assert_cursor_restored(&output);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "an interrupted selection must not write a manifest"
    );
}

#[test]
fn get_interactive_dialoguer_ctrl_c_with_sigint_ignored_cancels_cleanly() {
    // Started with SIGINT ignored, the raised SIGINT must stay ignored:
    // the cursor guard may not swap in a handler that re-raises into the
    // default (fatal) action. The menu then just returns Cancelled.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let purl = "pkg:npm/covgap-multi-sigign@1.0.0";
    let encoded = "pkg%3Anpm%2Fcovgap-multi-sigign%401.0.0";
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        mount_two_free_patches(&mock, purl, encoded).await;
        mock
    });
    let uri = mock.uri();

    let tmp = tempfile::tempdir().unwrap();
    let (code, signal, output) = run_in_pty_raw(
        Sigint::Ignored,
        &[
            "get",
            purl,
            "--save-only",
            "--api-url",
            &uri,
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ],
        tmp.path(),
        "\x03",
        Duration::from_secs(20),
    );
    assert!(
        output.contains(&format!("Multiple patches available for {purl}")),
        "the dialoguer select prompt must have rendered; got: {output}"
    );
    assert_eq!(
        signal, None,
        "an ignored SIGINT must not kill the process; got: {output:?}"
    );
    assert!(
        output.contains("Selection cancelled."),
        "Ctrl-C with SIGINT ignored must cancel the menu; got: {output}"
    );
    assert_eq!(code, 0, "{output}");
    assert_cursor_restored(&output);
}
