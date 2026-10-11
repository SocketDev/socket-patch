//! #931: one manifest-load error mapping on every command. A
//! `.socket/manifest.json` that exists but cannot be parsed is
//! `manifest_invalid`; one that cannot be read (here: a directory at that
//! path) is `manifest_unreadable` — under `--json`, on every command that
//! loads the manifest, with the command's own exit code (1; `vex` keeps its
//! hard-error exit 2). Before v5.0 the same corrupt file surfaced as five
//! different codes (`apply_failed`, `repair_failed`, `invalid_manifest`,
//! `manifest_unreadable`, `manifest_invalid`). Nothing here reaches the
//! network.

use std::path::Path;

use socket_patch_cli::args::{GLOBAL_ARG_ENV_VARS, LOCAL_ARG_ENV_VARS};

#[path = "common/hermetic.rs"]
mod hermetic;

fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic::binary_command();
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    cmd.args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS.iter().chain(LOCAL_ARG_ENV_VARS.iter()) {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    // Unroutable: a case that reached the network would fail differently.
    cmd.env("SOCKET_API_URL", "http://127.0.0.1:1");
    cmd.env("SOCKET_PATCH_SERVER_URL", "http://127.0.0.1:1");
    cmd.env("SOCKET_API_TOKEN", "fake-token-for-test");
    cmd.env("SOCKET_ORG_SLUG", "test-org");
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// `(argv, envelope command, exit code)` — every command that loads the
/// manifest and prints the envelope.
const MATRIX: &[(&[&str], &str, i32)] = &[
    (&["list", "--json"], "list", 1),
    (
        &["remove", "pkg:npm/x@1.0.0", "--json", "--yes"],
        "remove",
        1,
    ),
    (&["apply", "--json", "--offline"], "apply", 1),
    (&["apply", "--check", "--json"], "apply", 1),
    (&["repair", "--json", "--offline"], "repair", 1),
    (&["vendor", "--json", "--offline"], "vendor", 1),
    (&["vendor", "--check", "--json"], "vendor", 1),
    (&["vex", "--json", "--output", "out.json"], "vex", 2),
];

/// A project holding `package.json` plus whatever `seed` puts at
/// `.socket/manifest.json`.
fn project(seed: impl Fn(&Path)) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"proj","version":"1.0.0"}"#,
    )
    .unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    seed(&socket.join("manifest.json"));
    tmp
}

fn assert_matrix(seed: impl Fn(&Path), code: &str) {
    for (argv, command, exit) in MATRIX {
        // A fresh project per command: nothing one run leaves behind (an
        // apply.lock, a VEX file) can steer the next.
        let tmp = project(&seed);
        let (got_exit, stdout, stderr) = run(tmp.path(), argv);
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{argv:?}: stdout must be one JSON envelope ({e}): {stdout:?}\nstderr={stderr}")
        });
        assert_eq!(v["error"]["code"], code, "{argv:?}: {v}");
        assert_eq!(got_exit, *exit, "{argv:?}: {v}\nstderr={stderr}");
        // A full envelope, not a bare `{status, error}`.
        assert_eq!(v["command"], *command, "{argv:?}: {v}");
        assert_eq!(v["status"], "error", "{argv:?}: {v}");
        assert!(v["dryRun"].is_boolean(), "{argv:?}: {v}");
        assert!(v["summary"].is_object(), "{argv:?}: {v}");
        assert_eq!(v["events"], serde_json::json!([]), "{argv:?}: {v}");
        assert!(
            v["error"]["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "{argv:?}: {v}"
        );
        assert!(v.get("errorCode").is_none(), "{argv:?}: {v}");
    }
}

#[test]
fn unparseable_manifest_is_manifest_invalid_on_every_command() {
    assert_matrix(
        |path| std::fs::write(path, r#"{"patches": {"#).unwrap(),
        "manifest_invalid",
    );
}

#[test]
fn unreadable_manifest_is_manifest_unreadable_on_every_command() {
    // A directory where the file belongs: it exists, so no command takes
    // its missing-manifest path, and reading it is an I/O error.
    assert_matrix(
        |path| std::fs::create_dir_all(path).unwrap(),
        "manifest_unreadable",
    );
}
