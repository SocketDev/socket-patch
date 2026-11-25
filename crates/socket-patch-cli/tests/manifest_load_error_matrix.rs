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
/// as root, unlike a `chmod 000` fixture. Unix only: Windows reports a
/// path under a file as not found, so there it is no manifest.
#[cfg(unix)]
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

// ── a target the unreadable vendor ledger may hold ──────────────────────

/// A vendor ledger a merge left conflict markers in: both branches
/// vendored a package, and git could not join the two entries.
const CONFLICTED_LEDGER: &str = r#"{
  "version": 2,
  "entries": {
<<<<<<< HEAD
    "pkg:npm/x@1.0.0": {
=======
    "pkg:npm/y@2.0.0": {
>>>>>>> vendor-y
      "ecosystem": "npm"
    }
  }
}
"#;

/// A readable ledger holding one entry, of another package.
const OTHER_LEDGER: &str = r#"{
  "version": 1,
  "entries": {
    "pkg:npm/other@2.0.0": {
      "ecosystem": "npm",
      "basePurl": "pkg:npm/other@2.0.0",
      "uuid": "22222222-2222-4222-8222-222222222222",
      "artifact": { "path": ".socket/vendor/npm/22222222-2222-4222-8222-222222222222/package.tgz" },
      "detached": true,
      "wiring": []
    }
  }
}
"#;

/// A manifest holding one patch, of another package.
const OTHER_MANIFEST: &str = r#"{"patches":{"pkg:npm/other@2.0.0":{
  "uuid":"22222222-2222-4222-8222-222222222222","exportedAt":"2026-01-01T00:00:00Z",
  "files":{},"vulnerabilities":{},"description":"d","license":"MIT","tier":"free"}}}"#;

/// `(argv, envelope command, the code of a target no store holds)`: every
/// command that takes a target and looks it up in the project's stores.
const TARGETED: &[(&[&str], &str, &str)] = &[
    (
        &["remove", "pkg:npm/x@1.0.0", "--json", "--yes"],
        "remove",
        "not_found",
    ),
    (
        &["remove", "x", "--json", "--yes", "--dry-run"],
        "remove",
        "not_found",
    ),
    (
        &[
            "remove",
            "11111111-1111-4111-8111-111111111111",
            "--json",
            "--yes",
        ],
        "remove",
        "not_found",
    ),
    (
        &["rollback", "pkg:npm/x@1.0.0", "--json", "--offline"],
        "rollback",
        "patch_not_found",
    ),
    (
        &["rollback", "x", "--json", "--offline", "--dry-run"],
        "rollback",
        "patch_not_found",
    ),
    (
        &[
            "rollback",
            "11111111-1111-4111-8111-111111111111",
            "--json",
            "--offline",
        ],
        "rollback",
        "patch_not_found",
    ),
    (
        &["rollback", "./node_modules/x", "--json", "--offline"],
        "rollback",
        "path_glob_no_match",
    ),
    (
        &["report", "pkg:npm/x@1.0.0", "--json", "--dry-run"],
        "report",
        "patch_not_found",
    ),
    (
        &["report", "x", "--json", "--dry-run"],
        "report",
        "patch_not_found",
    ),
];

/// A project whose vendor ledger is whatever `seed` puts at
/// `.socket/vendor/state.json` and, when given, `manifest` as its manifest.
fn ledger_project(seed: &dyn Fn(&Path), manifest: Option<&str>) -> tempfile::TempDir {
    project_root(&|root| {
        let vendor = root.join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        seed(&vendor.join("state.json"));
        if let Some(manifest) = manifest {
            std::fs::write(root.join(".socket/manifest.json"), manifest).unwrap();
        }
    })
}

fn run_targeted(tmp: &tempfile::TempDir, argv: &[&str]) -> (i32, serde_json::Value) {
    let (exit, stdout, stderr) = run(tmp.path(), argv, &[]);
    let v = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{argv:?}: stdout must be one JSON document ({e}): {stdout:?}\nstderr={stderr}")
    });
    (exit, v)
}

/// Every [`TARGETED`] command over a ledger `seed` makes unreadable, with
/// no manifest, an empty one and one holding another package's patch
/// beside it: each must fail with the ledger's error.
fn assert_ledger_error_on_every_targeted_command(seed: &dyn Fn(&Path)) {
    let mut wrong: Vec<String> = Vec::new();
    for manifest in [None, Some(r#"{"patches":{}}"#), Some(OTHER_MANIFEST)] {
        for (argv, command, _) in TARGETED {
            let tmp = ledger_project(seed, manifest);
            let ledger = tmp.path().join(".socket/vendor/state.json");
            let before = std::fs::read_link(&ledger)
                .map(|to| to.into_os_string().into_encoded_bytes())
                .or_else(|_| std::fs::read(&ledger))
                .unwrap();
            let (exit, v) = run_targeted(&tmp, argv);
            assert_eq!(exit, 1, "{argv:?}: {v}");
            assert_eq!(v["command"], *command, "{argv:?}: {v}");
            let code = v["error"]["code"].as_str().unwrap_or_default();
            let message = v["error"]["message"].as_str().unwrap_or_default();
            if code != "vendor_state_unreadable" {
                wrong.push(format!(
                    "{} (manifest: {}): {code}: {message}",
                    argv.join(" "),
                    match manifest {
                        None => "none",
                        Some(m) if m.contains("other") => "another package's patch",
                        Some(_) => "empty",
                    },
                ));
                continue;
            }
            assert_eq!(v["status"], "error", "{argv:?}: {v}");
            // `remove` and `rollback` name the file and the target that
            // was not looked up in it (`report` has its own wording).
            if *command != "report" {
                assert!(
                    message.contains(".socket/vendor/state.json") && message.contains(argv[1]),
                    "{argv:?}: {message}"
                );
            }
            let after = std::fs::read_link(&ledger)
                .map(|to| to.into_os_string().into_encoded_bytes())
                .or_else(|_| std::fs::read(&ledger))
                .unwrap();
            assert_eq!(after, before, "{argv:?}: the ledger is left as it was");
        }
    }
    assert!(
        wrong.is_empty(),
        "the vendor ledger could not be read, so these targets were never looked up in it:\n  {}",
        wrong.join("\n  ")
    );
}

/// "No patch matches" is a statement about every store. A vendor ledger
/// that cannot be read may hold the target (vendored mode keeps no
/// manifest, so the ledger is a vendored project's only record of its
/// patches), so a target that matches nothing in the stores that could be
/// read fails with the ledger's error on every command that takes one,
/// and never as "not found". With or without a manifest beside the ledger.
#[test]
fn a_target_is_never_not_found_while_the_vendor_ledger_is_unreadable() {
    assert_ledger_error_on_every_targeted_command(&|ledger| {
        std::fs::write(ledger, CONFLICTED_LEDGER).unwrap()
    });
}

/// The same for a ledger that cannot even be stat'd (a symlink to itself
/// fails with ELOOP): that is unreadable, not "no ledger", as #998 settled
/// for the manifest. With no manifest beside it, `remove` and `rollback`
/// used to probe for the ledger, take the error for absence and report a
/// project with no patches.
#[cfg(unix)]
#[test]
fn a_target_is_never_not_found_while_the_vendor_ledger_cannot_be_stat() {
    assert_ledger_error_on_every_targeted_command(&|ledger| {
        std::os::unix::fs::symlink("state.json", ledger).unwrap()
    });
}

/// The control: with every store readable, a target none of them holds
/// keeps each command's own "not found" code.
#[test]
fn a_target_no_readable_store_holds_keeps_its_not_found_code() {
    for manifest in [None, Some(OTHER_MANIFEST)] {
        for (argv, command, not_found) in TARGETED {
            let tmp = ledger_project(
                &|ledger| std::fs::write(ledger, OTHER_LEDGER).unwrap(),
                manifest,
            );
            let (exit, v) = run_targeted(&tmp, argv);
            assert_eq!(exit, 1, "{argv:?}: {v}");
            assert_eq!(v["command"], *command, "{argv:?}: {v}");
            assert_eq!(v["error"]["code"], *not_found, "{argv:?}: {v}");
        }
    }
}
