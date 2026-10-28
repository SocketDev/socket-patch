//! #931: one manifest-load error mapping on every command. A
//! `.socket/manifest.json` that exists but cannot be parsed is
//! `manifest_invalid`; one that cannot be read (here: a directory at that
//! path) is `manifest_unreadable` — under `--json`, on every command that
//! loads the manifest, with the command's own exit code (1; `vex` keeps its
//! hard-error exit 2). Before v5.0 the same corrupt file surfaced as five
//! different codes (`apply_failed`, `repair_failed`, `invalid_manifest`,
//! `manifest_unreadable`, `manifest_invalid`). Nothing here reaches the
//! network.
//!
//! #998: the commands that probe for a manifest before loading it must
//! read a stat error (`.socket` as a plain file, a symlink loop) as
//! unreadable, not as "no manifest". #1123: the verdict must not depend on
//! how the manifest path is spelled.

use std::path::Path;

use socket_patch_cli::args::{GLOBAL_ARG_ENV_VARS, LOCAL_ARG_ENV_VARS};

#[path = "common/hermetic.rs"]
mod hermetic;

fn run(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = hermetic::binary_command();
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    cmd.args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS.iter().chain(LOCAL_ARG_ENV_VARS.iter()) {
        cmd.env_remove(var);
    }
    cmd.envs(env.iter().copied());
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
    (&["rollback", "--json", "--offline"], "rollback", 1),
    (&["vendor", "--json", "--offline"], "vendor", 1),
    (&["vendor", "--check", "--json"], "vendor", 1),
    (&["vex", "--json", "--output", "out.json"], "vex", 2),
];

/// A project holding `package.json` plus whatever `seed` puts at
/// `.socket/manifest.json`.
fn project(seed: &dyn Fn(&Path)) -> tempfile::TempDir {
    project_root(&|root| {
        let socket = root.join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        seed(&socket.join("manifest.json"));
    })
}

/// A project holding `package.json` plus whatever `seed` puts in its root.
fn project_root(seed: &dyn Fn(&Path)) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"proj","version":"1.0.0"}"#,
    )
    .unwrap();
    seed(tmp.path());
    tmp
}

/// How a run names the manifest (#1123): the default, or spelled out
/// through the flag (relative or absolute) or the environment.
#[derive(Clone, Copy, Debug)]
enum Spelling {
    Default,
    FlagRelative,
    FlagAbsolute,
    Env,
}

fn assert_matrix(seed: impl Fn(&Path), code: &str) {
    assert_matrix_in(project, &seed, &[code], Spelling::Default);
}

fn assert_matrix_in(
    make: fn(&dyn Fn(&Path)) -> tempfile::TempDir,
    seed: &dyn Fn(&Path),
    codes: &[&str],
    spelling: Spelling,
) {
    for (argv, command, exit) in MATRIX {
        // A fresh project per command: nothing one run leaves behind (an
        // apply.lock, a VEX file) can steer the next.
        let tmp = make(seed);
        let absolute = tmp.path().join(".socket").join("manifest.json");
        let absolute = absolute.to_str().unwrap();
        let mut args: Vec<&str> = argv.to_vec();
        let mut env: Vec<(&str, &str)> = Vec::new();
        match spelling {
            Spelling::Default => {}
            Spelling::FlagRelative => args.extend(["--manifest-path", "./.socket/manifest.json"]),
            Spelling::FlagAbsolute => args.extend(["--manifest-path", absolute]),
            Spelling::Env => env.push(("SOCKET_MANIFEST_PATH", "./.socket/manifest.json")),
        }
        let argv = (&args, spelling);
        let (got_exit, stdout, stderr) = run(tmp.path(), &args, &env);
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{argv:?}: stdout must be one JSON envelope ({e}): {stdout:?}\nstderr={stderr}")
        });
        assert!(
            codes.iter().any(|c| v["error"]["code"] == *c),
            "{argv:?}: expected one of {codes:?}: {v}"
        );
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

/// #998: `.socket` is a plain file, so stating the manifest fails with
/// ENOTDIR. That is unreadable, not missing: `apply` and `vendor` used to
/// report `noManifest` and exit 0, the others `manifest_not_found`. Runs
/// as root, unlike a `chmod 000` fixture.
#[test]
fn socket_dir_as_file_is_manifest_unreadable_on_every_command() {
    assert_matrix_in(
        project_root,
        &|root| std::fs::write(root.join(".socket"), "not a directory").unwrap(),
        // `vendor --check` reads the vendor ledger under the same `.socket`
        // first, and refuses that store just as closed.
        &["manifest_unreadable", "vendor_state_unreadable"],
        Spelling::Default,
    );
}

/// #998: a manifest symlinked to itself fails stat with ELOOP.
#[cfg(unix)]
#[test]
fn manifest_symlink_loop_is_manifest_unreadable_on_every_command() {
    assert_matrix(
        |path| std::os::unix::fs::symlink("manifest.json", path).unwrap(),
        "manifest_unreadable",
    );
}

/// #1123: a directory at the manifest path gets the same verdict however
/// the path is spelled. A spelled-out path used to exit 2 from argument
/// validation with no `--json` document.
#[test]
fn directory_manifest_verdict_does_not_depend_on_spelling() {
    for spelling in [
        Spelling::FlagRelative,
        Spelling::FlagAbsolute,
        Spelling::Env,
    ] {
        assert_matrix_in(
            project,
            &|path| std::fs::create_dir_all(path).unwrap(),
            &["manifest_unreadable"],
            spelling,
        );
    }
}
