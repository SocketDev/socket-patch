//! `list` on a terminal: the full-screen table of the project's patches
//! (`src/ui/browser.rs`), driven in a PTY that changes size while the
//! table is up.
//!
//! The table draws on the alternate screen, redraws to fit whenever the
//! terminal's size changes, fills its rows in from the patch service as
//! the answers arrive, and opens a patch as a page. PTY support: macOS +
//! Linux. Skipped on Windows, where `list` uses the inline menu.

#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common;
use crate::pty_io::PtyOutput;

const ENTER_SCREEN: &str = "\x1b[?1049h";
const LEAVE_SCREEN: &str = "\x1b[?1049l";
const SHOW_CURSOR: &str = "\x1b[?25h";
/// What every frame starts with: cursor home.
const HOME: &str = "\x1b[H";
const ORG_SLUG: &str = "test-org";

fn uuid(i: usize) -> String {
    format!("{i:08x}-1111-4111-8111-111111111111")
}

/// A manifest of `n` agent-mode patches, enough to scroll.
fn write_manifest(root: &Path, n: usize) {
    let patches: serde_json::Map<String, serde_json::Value> = (0..n)
        .map(|i| {
            (
                format!("pkg:npm/list-tty-package-{i:02}@1.0.{i}"),
                serde_json::json!({
                    "uuid": uuid(i),
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": { "package/index.js": {
                        "beforeHash": "b".repeat(64),
                        "afterHash": "a".repeat(64),
                    }},
                    "vulnerabilities": { format!("GHSA-aaaa-bbbb-{i:04}"): {
                        "cves": [format!("CVE-2026-{:05}", 1000 + i)],
                        "summary": "A summary",
                        "severity": if i % 3 == 0 { "critical" } else { "high" },
                        "description": "A description",
                    }},
                    "description": "A patch",
                    "license": "MIT",
                    "tier": "free",
                }),
            )
        })
        .collect();
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}

/// A command running on a PTY whose size the test controls.
struct Terminal {
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    output: PtyOutput,
}

fn size(cols: u16, rows: u16) -> portable_pty::PtySize {
    portable_pty::PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

impl Terminal {
    fn list(cwd: &Path, args: &[&str], cols: u16, rows: u16) -> Terminal {
        Terminal::run("list", cwd, args, cols, rows)
    }

    fn run(command: &str, cwd: &Path, args: &[&str], cols: u16, rows: u16) -> Terminal {
        let pair = portable_pty::native_pty_system()
            .openpty(size(cols, rows))
            .expect("openpty");
        let mut cmd = common::hermetic::pty_binary_command();
        cmd.arg(command);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.cwd(cwd);
        cmd.env("TERM", "xterm-256color");
        // No color, so a frame's lines are its text; glyphs go with color.
        cmd.env("NO_COLOR", "1");
        let child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
        drop(pair.slave);
        let output = PtyOutput::spawn(pair.master.try_clone_reader().expect("clone reader"));
        let writer = pair.master.take_writer().expect("take writer");
        Terminal {
            master: pair.master,
            writer,
            child,
            output,
        }
    }

    fn press(&mut self, keys: &[u8]) {
        self.writer.write_all(keys).unwrap();
        self.writer.flush().unwrap();
    }

    fn resize(&self, cols: u16, rows: u16) {
        self.master.resize(size(cols, rows)).expect("resize");
    }

    /// Wait until `needle` has been drawn `n` times.
    fn wait_for(&self, needle: &str, n: usize) {
        self.output
            .wait_for_count(needle, n, Duration::from_secs(20));
    }

    /// Wait for the child to exit; its code and everything it printed.
    fn finish(mut self) -> (i32, String) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => break status,
                None if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    break self.child.wait().expect("wait");
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        drop(self.writer);
        drop(self.master);
        let output = String::from_utf8_lossy(&self.output.finish()).into_owned();
        (status.exit_code() as i32, output)
    }
}

/// The frames drawn in `output`: each one's lines, escape sequences
/// removed.
fn frames(output: &str) -> Vec<Vec<String>> {
    let escape = regex::Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap();
    output
        .split(HOME)
        .skip(1)
        .map(|frame| {
            // A frame ends where the browser leaves the screen.
            let frame = frame.split(LEAVE_SCREEN).next().unwrap_or(frame);
            frame
                .split('\n')
                // The browser ends its lines with a return and a newline,
                // and the terminal adds a return of its own to the newline.
                .map(|line| {
                    escape
                        .replace_all(line.trim_end_matches('\r'), "")
                        .into_owned()
                })
                .collect()
        })
        .collect()
}

/// The last frame that shows `position` on its key line.
fn frame_at<'a>(frames: &'a [Vec<String>], position: &str) -> &'a Vec<String> {
    frames
        .iter()
        .rev()
        .find(|frame| frame.last().is_some_and(|line| line.ends_with(position)))
        .unwrap_or_else(|| panic!("no frame at {position}: {frames:#?}"))
}

/// What the run printed once it left the browser.
fn after_leaving(output: &str) -> String {
    let escape = regex::Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap();
    let tail = output.rsplit(LEAVE_SCREEN).next().unwrap();
    escape.replace_all(tail, "").replace('\r', "")
}

/// The reported need: the table must handle the terminal being resized.
/// Shrunk, it redraws within the new size with the selected row still in
/// view and nothing wrapped (the columns that give way are left out);
/// grown, it fills the new size again. Leaving it restores the screen and
/// the cursor, and prints the rows as the listing that stays.
#[test]
fn list_redraws_to_fit_when_the_terminal_is_resized() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), 30);
    // `--offline`: the rows are what the project records.
    let mut term = Terminal::list(tmp.path(), &["--offline"], 100, 12);

    term.wait_for(ENTER_SCREEN, 1);
    term.wait_for("1/30", 1);
    term.press(b"\x1b[B");
    term.wait_for("2/30", 1);
    term.press(b"j");
    term.wait_for("3/30", 1);

    // Narrower and shorter than what is drawn.
    term.resize(40, 6);
    term.wait_for("3/30", 2);
    // Move in the small terminal, then grow it past the first size.
    term.press(b"\x1b[B");
    term.wait_for("4/30", 1);
    term.resize(120, 40);
    term.wait_for("4/30", 2);
    // The end of the table, then out.
    term.press(b"G");
    term.wait_for("30/30", 1);
    term.press(b"q");
    let (code, output) = term.finish();
    assert_eq!(code, 0, "{output}");

    // Nothing but the status line went out before the browser opened.
    let before = output.split(ENTER_SCREEN).next().unwrap();
    assert!(!before.contains("Found 30 patches"), "{before}");
    assert!(!before.contains("Package: pkg:npm/"), "{before}");

    let frames = frames(&output);
    // At 100x12: the title, the column titles, nine rows, the key line.
    let first = frame_at(&frames, "1/30");
    assert_eq!(first.len(), 12, "{first:#?}");
    assert_eq!(first[0], "30 patches in this project");
    assert_eq!(
        first[1],
        "  SEVERITY  PACKAGE                     FIXES           MODE"
    );
    assert_eq!(
        first[2],
        "> CRITICAL  list-tty-package-00@1.0.0   CVE-2026-01000  agent"
    );
    assert!(
        first[11].starts_with("Up/Down move   PgUp/PgDn page   Enter open   q quit"),
        "{first:#?}"
    );

    // At 40x6 the frame is drawn again to fit: six lines, none reaching
    // the last column, the columns that give way left out, and the
    // selected row among the three in view.
    let small = frames
        .iter()
        .rev()
        .find(|frame| frame.len() == 6 && frame.last().is_some_and(|l| l.ends_with("3/30")))
        .unwrap_or_else(|| panic!("no frame for the 40x6 terminal: {frames:#?}"));
    for line in small {
        assert!(line.chars().count() < 40, "{line:?} wraps at 40 columns");
    }
    assert_eq!(small[1], "  SEVERITY  PACKAGE", "{small:#?}");
    assert_eq!(
        small.iter().filter(|line| line.starts_with("> ")).count(),
        1,
        "{small:#?}"
    );
    assert!(
        small
            .iter()
            .any(|line| line == "> HIGH      list-tty-package-02@1.0.2"),
        "{small:#?}"
    );
    assert_eq!(small[5], "3/30", "the keys give way, the position stays");

    // At 120x40 every row is on screen again, under the titles.
    let large = frames
        .iter()
        .rev()
        .find(|frame| frame.len() == 40 && frame.last().is_some_and(|l| l.ends_with("4/30")))
        .unwrap_or_else(|| panic!("no frame for the 120x40 terminal: {frames:#?}"));
    assert!(large[2].contains("list-tty-package-00"), "{large:#?}");
    assert!(large[31].contains("list-tty-package-29"), "{large:#?}");
    assert!(large[5].starts_with("> "), "{large:#?}");

    // `G` went to the last row.
    let last = frame_at(&frames, "30/30");
    assert!(
        last.iter()
            .any(|line| line.starts_with("> ") && line.contains("list-tty-package-29")),
        "{last:#?}"
    );

    // Out: the main screen and the cursor are back, and the rows are the
    // listing that stays on the terminal.
    assert!(output.contains(LEAVE_SCREEN), "{output}");
    assert!(
        output.rfind(SHOW_CURSOR) > output.rfind("\x1b[?25l"),
        "the cursor is shown again"
    );
    let after = after_leaving(&output);
    assert!(
        after.starts_with(
            "Found 30 patches:\n  SEVERITY  PACKAGE                     FIXES           MODE\n  \
             CRITICAL  list-tty-package-00@1.0.0   CVE-2026-01000  agent\n"
        ),
        "{after:?}"
    );
    assert_eq!(after.lines().count(), 32, "{after:?}");
}

/// Enter opens the selected patch as a page that takes the screen, and
/// `q` comes back to the table on the same row. With `--offline` the page
/// is what the project records about the patch.
#[test]
fn list_opens_a_patch_as_a_page_and_comes_back() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), 3);
    let mut term = Terminal::list(tmp.path(), &["--offline"], 100, 16);
    term.wait_for("1/3", 1);
    term.press(b"\x1b[B");
    term.wait_for("2/3", 1);
    term.press(b"\r");
    term.wait_for("Package: pkg:npm/list-tty-package-01@1.0.1", 1);
    // Back to the table, where it was left; then out.
    term.press(b"q");
    term.wait_for("2/3", 2);
    term.press(b"q");
    let (code, output) = term.finish();
    assert_eq!(code, 0, "{output}");

    let frames = frames(&output);
    let page = frames
        .iter()
        .find(|frame| frame[0] == "pkg:npm/list-tty-package-01@1.0.1")
        .unwrap_or_else(|| panic!("no page: {frames:#?}"));
    assert_eq!(page.len(), 16, "{page:#?}");
    assert_eq!(page[1], "Package: pkg:npm/list-tty-package-01@1.0.1");
    assert_eq!(page[2], format!("  UUID: {}", uuid(1)));
    assert!(
        page.iter()
            .any(|line| line == "    - GHSA-aaaa-bbbb-0001 (CVE-2026-01001)"),
        "{page:#?}"
    );
    assert!(
        page[15].starts_with("Up/Down scroll   PgUp/PgDn page   q back"),
        "{page:#?}"
    );
    // The table came back on the row that was opened.
    let back = frames.last().unwrap();
    assert_eq!(back[0], "3 patches in this project");
    assert!(
        back[3].starts_with("> HIGH      list-tty-package-01"),
        "{back:#?}"
    );
    // One screen throughout: the page did not leave it.
    assert_eq!(output.matches(ENTER_SCREEN).count(), 1, "{output:?}");
    assert!(after_leaving(&output).starts_with("Found 3 patches:\n"));
}

/// Keys that arrive together are each acted on, in order: a held arrow,
/// a paste and a slow link all deliver several presses in one read. Two
/// arrows and Enter written at once open the third row's page; read as
/// one key they would be a sequence the browser does not know, and
/// nothing would happen. Esc by itself is still the Esc key: it comes
/// back from the page, and then leaves the table.
#[test]
fn list_acts_on_every_key_that_arrives_at_once() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), 3);
    let mut term = Terminal::list(tmp.path(), &["--offline"], 100, 16);
    term.wait_for("1/3", 1);
    term.press(b"\x1b[B\x1b[B\r");
    term.wait_for("Package: pkg:npm/list-tty-package-02@1.0.2", 1);
    term.press(b"\x1b");
    term.wait_for("> HIGH      list-tty-package-02", 1);
    term.press(b"\x1b");
    let (code, output) = term.finish();
    assert_eq!(code, 0, "{output}");

    let frames = frames(&output);
    assert!(
        frames
            .iter()
            .any(|frame| frame[0] == "pkg:npm/list-tty-package-02@1.0.2"),
        "no page: {frames:#?}"
    );
    // The table came back on the row the keys reached.
    let back = frames.last().unwrap();
    assert_eq!(back[0], "3 patches in this project");
    assert!(
        back[4].starts_with("> HIGH      list-tty-package-02"),
        "{back:#?}"
    );
    assert!(back[15].ends_with("3/3"), "{back:#?}");
    assert!(after_leaving(&output).starts_with("Found 3 patches:\n"));
}

/// The table goes up with what the project records, and the patch
/// service's account of each patch fills its row in as it arrives: what
/// was measured about it, the size and cost of the change, and when it
/// was published. The listing left on the terminal has them too.
#[test]
fn list_fills_its_rows_in_from_the_patch_service() {
    // The pty runs a sync child while wiremock needs a live async runtime,
    // so the runtime is built manually and kept alive across the pty run.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                r"^/v0/orgs/{ORG_SLUG}/patches/view/[0-9a-f-]+$"
            )))
            .respond_with(|request: &wiremock::Request| {
                let uuid = request.url.path().rsplit('/').next().unwrap().to_string();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid,
                    "purl": "pkg:npm/list-tty-package-00@1.0.0",
                    "publishedAt": "Sat, 14 Nov 2026 07:13:44 GMT",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "A patch",
                    "license": "MIT",
                    "tier": "free",
                    "statistics": {
                        "diff": { "linesAdded": 26, "linesRemoved": 22, "filesChanged": 2 },
                        "tests": { "after": { "count": 34, "total": 35 } },
                        "pocs": { "blockedAfter": { "count": 2, "total": 2 } },
                        "performance": { "hotWallChange": 0.008 },
                    },
                }))
            })
            .mount(&mock)
            .await;
        mock
    });
    let uri = mock.uri();

    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), 2);
    let mut term = Terminal::list(
        tmp.path(),
        &[
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
        140,
        10,
    );
    // Both rows filled in.
    term.wait_for("34/35", 2);
    term.press(b"q");
    let (code, output) = term.finish();
    assert_eq!(code, 0, "{output}");

    let frames = frames(&output);
    // The table was up before the patch service had answered.
    let first = &frames[0];
    assert_eq!(
        first[0].split("   ").next(),
        Some("2 patches in this project")
    );
    assert_eq!(
        first[2], "> CRITICAL  list-tty-package-00@1.0.0  CVE-2026-01000  agent",
        "{first:#?}"
    );
    let filled = frames.last().unwrap();
    assert_eq!(
        filled[..4],
        [
            "2 patches in this project",
            "  SEVERITY  PACKAGE                    FIXES           EXPLOITS  TESTS  CHANGE   PERF   \
             PUBLISHED    MODE",
            "> CRITICAL  list-tty-package-00@1.0.0  CVE-2026-01000  2/2       34/35  +26 -22  +0.8%  \
             14 Nov 2026  agent",
            "  HIGH      list-tty-package-01@1.0.1  CVE-2026-01001  2/2       34/35  +26 -22  +0.8%  \
             14 Nov 2026  agent",
        ],
        "{filled:#?}"
    );
    let after = after_leaving(&output);
    assert!(
        after.contains(
            "  HIGH      list-tty-package-01@1.0.1  CVE-2026-01001  2/2       34/35  +26 -22  \
             +0.8%  14 Nov 2026  agent\n"
        ),
        "{after:?}"
    );
    // One request per patch, for the view without its file contents.
    let requests = rt.block_on(mock.received_requests()).unwrap_or_default();
    assert_eq!(requests.len(), 2, "{requests:#?}");
    assert!(
        requests
            .iter()
            .all(|r| r.url.query() == Some("include_blobs=false")),
        "{requests:#?}"
    );
}

/// A row of `list` and `show` open one and the same page: the patch is
/// read the same way and shown on the same screen, so Enter on a row and
/// `show <its uuid>` draw the same lines, down to the key line. There is
/// no second way to read a patch on a terminal.
#[test]
fn a_list_row_opens_the_page_show_opens() {
    use base64::Engine as _;
    let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
    let (before, after, added) = (
        b64("one\ntwo\nthree\n"),
        b64("one\nTWO\nthree\n"),
        b64("new\n"),
    );
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                r"^/v0/orgs/{ORG_SLUG}/patches/view/[0-9a-f-]+$"
            )))
            .respond_with(move |request: &wiremock::Request| {
                let uuid = request.url.path().rsplit('/').next().unwrap().to_string();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid,
                    "purl": "pkg:npm/list-tty-package-00@1.0.0",
                    "publishedAt": "Sat, 14 Nov 2026 07:13:44 GMT",
                    "description": "A patch",
                    "license": "MIT",
                    "tier": "free",
                    "files": {
                        "package/index.js": {
                            "beforeHash": "b".repeat(64),
                            "afterHash": "a".repeat(64),
                            "beforeBlobContent": before,
                            "blobContent": after,
                        },
                        "package/new.js": { "afterHash": "c".repeat(64), "blobContent": added },
                    },
                    "vulnerabilities": { "GHSA-aaaa-bbbb-0000": {
                        "cves": ["CVE-2026-01000"],
                        "summary": "A summary",
                        "severity": "critical",
                        "description": "A description",
                    }},
                    "statistics": {
                        "diff": { "linesAdded": 2, "linesRemoved": 1, "filesChanged": 2 },
                        "tests": { "after": { "count": 34, "total": 35 } },
                        "pocs": { "blockedAfter": { "count": 2, "total": 2 } },
                        "performance": { "hotWallChange": 0.008 },
                    },
                }))
            })
            .mount(&mock)
            .await;
        mock
    });
    let uri = mock.uri();
    let service = [
        "--api-url",
        uri.as_str(),
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ];
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), 1);
    const LAST_DIFF: &str = "+++ b/package/new.js";

    // From the table: Enter on the row, then back and out.
    let mut term = Terminal::list(tmp.path(), &service, 100, 40);
    term.wait_for("1/1", 1);
    term.press(b"\r");
    term.wait_for(LAST_DIFF, 1);
    term.press(b"qq");
    let (code, from_list) = term.finish();
    assert_eq!(code, 0, "{from_list}");

    // By its uuid: `show`.
    let patch = uuid(0);
    let mut args = vec![patch.as_str()];
    args.extend(service);
    let mut term = Terminal::run("show", tmp.path(), &args, 100, 40);
    term.wait_for(LAST_DIFF, 1);
    term.press(b"q");
    let (code, from_show) = term.finish();
    assert_eq!(code, 0, "{from_show}");

    let page = |output: &str| {
        frames(output)
            .into_iter()
            .rev()
            .find(|frame| frame.iter().any(|line| line == LAST_DIFF))
            .unwrap_or_else(|| panic!("no page: {output:?}"))
    };
    let (opened, shown) = (page(&from_list), page(&from_show));
    assert_eq!(opened, shown);
    // And it is the patch: its title, what it fixes, what was measured,
    // each file's diff, the keys.
    assert_eq!(shown.len(), 40, "{shown:#?}");
    assert_eq!(
        shown[0],
        "pkg:npm/list-tty-package-00@1.0.0  CRITICAL  [FREE]"
    );
    for line in [
        "Fixes:",
        "  CRITICAL  CVE-2026-01000  A summary",
        "Measured by Socket:",
        "2 files changed: +2 -1",
        "--- a/package/index.js",
        "-two",
        "+TWO",
        "--- /dev/null",
        "+new",
    ] {
        assert!(shown.iter().any(|l| l == line), "{line:?} in {shown:#?}");
    }
    assert!(
        shown[39].starts_with("Up/Down scroll   PgUp/PgDn page   n/p file   q back"),
        "{shown:#?}"
    );
    // `show` leaves the summary on the terminal; `list` its rows.
    assert!(after_leaving(&from_show).contains("Measured by Socket:"));
    assert!(after_leaving(&from_list).starts_with("Found 1 patch:\n"));
}

/// `show --yes` on a terminal opens nothing: the summary and every diff
/// print at once, as a pipe gets them, and the run ends by itself. There
/// is no menu of files and no pager to wait on.
#[test]
fn show_yes_prints_the_patch_at_once_and_opens_nothing() {
    use base64::Engine as _;
    let content = base64::engine::general_purpose::STANDARD.encode("new\n");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mock = rt.block_on(async {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                r"^/v0/orgs/{ORG_SLUG}/patches/view/[0-9a-f-]+$"
            )))
            .respond_with(move |request: &wiremock::Request| {
                let uuid = request.url.path().rsplit('/').next().unwrap().to_string();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid,
                    "purl": "pkg:npm/list-tty-package-00@1.0.0",
                    "publishedAt": "Sat, 14 Nov 2026 07:13:44 GMT",
                    "description": "A patch",
                    "license": "MIT",
                    "tier": "free",
                    "files": {
                        "package/a.js": { "afterHash": "a".repeat(64), "blobContent": content },
                        "package/b.js": { "afterHash": "c".repeat(64), "blobContent": content },
                    },
                    "vulnerabilities": {},
                }))
            })
            .mount(&mock)
            .await;
        mock
    });
    let uri = mock.uri();
    let patch = uuid(0);
    let tmp = tempfile::tempdir().unwrap();
    let term = Terminal::run(
        "show",
        tmp.path(),
        &[
            patch.as_str(),
            "--yes",
            "--api-url",
            uri.as_str(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
        100,
        20,
    );
    let (code, output) = term.finish();
    assert_eq!(code, 0, "{output}");
    assert!(!output.contains(ENTER_SCREEN), "{output:?}");
    for line in [
        "pkg:npm/list-tty-package-00@1.0.0  [FREE]",
        "2 files changed: +2 -0",
        "+++ b/package/a.js",
        "+++ b/package/b.js",
    ] {
        assert!(output.contains(line), "{line:?} in {output:?}");
    }
    assert!(!output.contains("Open a file"), "{output:?}");
}

/// `--yes`, like a pipe, keeps the full entries and opens no browser: the
/// run ends by itself, and asks the patch service nothing.
#[test]
fn list_yes_prints_the_full_entries_and_opens_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), 3);
    let pair = portable_pty::native_pty_system()
        .openpty(size(100, 30))
        .expect("openpty");
    let mut cmd = common::hermetic::pty_binary_command();
    cmd.arg("list");
    cmd.arg("--yes");
    cmd.cwd(tmp.path());
    cmd.env("TERM", "xterm-256color");
    let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
    drop(pair.slave);
    let output = PtyOutput::spawn(pair.master.try_clone_reader().expect("clone reader"));
    let status = child.wait().expect("wait");
    drop(pair.master);
    let output = String::from_utf8_lossy(&output.finish()).into_owned();
    assert_eq!(status.exit_code(), 0, "{output}");
    assert!(output.contains("Found 3 patches:"), "{output}");
    assert!(
        output.contains("Package: pkg:npm/list-tty-package-00@1.0.0"),
        "{output}"
    );
    assert!(!output.contains(ENTER_SCREEN), "{output:?}");
}
