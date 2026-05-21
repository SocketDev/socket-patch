//! End-to-end tests that drive interactive `dialoguer` prompts via a
//! pseudo-terminal. These exercise the `stdin_is_tty()`-gated
//! confirmation paths in `setup`, `remove`, and `get` that
//! subprocess-with-piped-stdin tests can't reach.
//!
//! PTY support: macOS + Linux. Skipped on Windows.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Spawn the socket-patch binary inside a PTY, send `input` after a
/// short delay, then collect output for up to `timeout`. Returns
/// `(exit_code, output)`.
fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = CommandBuilder::new(binary());
    for a in args {
        cmd.arg(a);
    }
    cmd.cwd(cwd);
    cmd.env_remove("SOCKET_API_TOKEN");

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("spawn socket-patch in PTY");
    // Drop the slave so it doesn't keep the file descriptor open after
    // the child exits — without this the reader on the master side
    // blocks forever waiting for EOF.
    drop(pair.slave);

    // Reader thread: drain the master output continuously until EOF.
    let mut reader = pair.master.try_clone_reader().expect("clone reader");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let reader_handle = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Writer: send the input after a short pause to give the binary
    // time to render the prompt.
    let mut writer = pair.master.take_writer().expect("take writer");
    std::thread::sleep(Duration::from_millis(300));
    let _ = writer.write_all(input.as_bytes());
    let _ = writer.flush();
    drop(writer);

    // Wait for child to exit, bounded by `timeout`.
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            break child.wait().expect("wait after kill");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(pair.master);
    let _ = reader_handle.join();

    let mut output = Vec::new();
    while let Ok(chunk) = rx.try_recv() {
        output.extend(chunk);
    }
    let code = status.exit_code() as i32;
    (code, String::from_utf8_lossy(&output).to_string())
}

// ---------------------------------------------------------------------------
// `setup` interactive confirmation
// ---------------------------------------------------------------------------

#[test]
fn setup_interactive_y_proceeds_with_update() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "p", "version": "1.0.0" }"#,
    )
    .unwrap();

    // Without --yes, setup prompts "Proceed with these changes? (y/N): ".
    // Sending "y\n" should make it proceed with the update.
    let (code, _output) = run_in_pty(
        &["setup"],
        tmp.path(),
        "y\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0, "setup with 'y' must succeed");

    // package.json should have been updated.
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert!(
        pkg.contains("socket-patch"),
        "setup must have written postinstall script; got: {pkg}"
    );
}

#[test]
fn setup_interactive_n_aborts_without_update() {
    let tmp = tempfile::tempdir().unwrap();
    let original = r#"{ "name": "p", "version": "1.0.0" }
"#;
    std::fs::write(tmp.path().join("package.json"), original).unwrap();

    let (code, output) = run_in_pty(
        &["setup"],
        tmp.path(),
        "n\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0, "setup with 'n' must exit cleanly");
    assert!(
        output.contains("Aborted") || output.contains("aborted"),
        "setup must print abort message; got: {output}"
    );

    // package.json must be unchanged.
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(pkg, original, "setup 'n' must not modify package.json");
}

#[test]
fn setup_interactive_default_no_aborts() {
    // Pressing just Enter at the prompt defaults to N (abort).
    let tmp = tempfile::tempdir().unwrap();
    let original = r#"{ "name": "p", "version": "1.0.0" }
"#;
    std::fs::write(tmp.path().join("package.json"), original).unwrap();

    let (code, _output) = run_in_pty(
        &["setup"],
        tmp.path(),
        "\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0);
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(pkg, original, "default-N must not modify package.json");
}

// ---------------------------------------------------------------------------
// `remove` interactive confirmation
// ---------------------------------------------------------------------------

const REMOVE_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__interactive_remove__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "interactive remove test",
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
fn remove_interactive_y_proceeds() {
    let tmp = tempfile::tempdir().unwrap();
    write_remove_manifest(tmp.path());

    let (code, _output) = run_in_pty(
        &["remove", "pkg:npm/__interactive_remove__@1.0.0", "--skip-rollback"],
        tmp.path(),
        "y\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0);
    // Manifest should be empty now.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        manifest["patches"]
            .as_object()
            .map(|p| p.is_empty())
            .unwrap_or(false),
        "remove 'y' must drop the entry; got: {body}"
    );
}

#[test]
fn remove_interactive_n_cancels() {
    let tmp = tempfile::tempdir().unwrap();
    write_remove_manifest(tmp.path());

    let (code, _output) = run_in_pty(
        &["remove", "pkg:npm/__interactive_remove__@1.0.0", "--skip-rollback"],
        tmp.path(),
        "n\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0, "remove 'n' must exit cleanly");
    // Manifest must still have the entry.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        manifest["patches"]
            .as_object()
            .map(|p| !p.is_empty())
            .unwrap_or(true),
        "remove 'n' must leave manifest intact"
    );
}

// ---------------------------------------------------------------------------
// Apply non-JSON without --yes also exercises confirm() flow,
// even though apply auto-proceeds in non-interactive contexts.
// ---------------------------------------------------------------------------

#[test]
fn apply_in_pty_with_no_manifest_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, output) = run_in_pty(
        &["apply"],
        tmp.path(),
        "",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0);
    assert!(
        output.contains("No .socket folder") || output.contains("skipping"),
        "PTY apply no-manifest must print friendly message; got: {output}"
    );
}
