//! Integration tests for `setup`'s Python `.pth`-hook branch. Like the npm
//! `setup_invariants`, these operate entirely on disk (manifest detection +
//! editing + audit record) and need no network.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn run_setup(cwd: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut args = vec!["setup", "--json", "--yes"];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}):\n{stdout}"));
    (out.status.code().unwrap_or(-1), v)
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read file")
}

#[test]
fn pip_requirements_gets_hook_dep() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("requirements.txt"), "requests==2.31.0\n");

    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0, "setup should succeed; payload={v}");
    assert_eq!(v["status"], "success");
    assert_eq!(v["updated"], 1);
    assert_eq!(v["pythonPackageManager"], "pip");
    let entry = &v["files"].as_array().unwrap()[0];
    assert_eq!(entry["kind"], "pth");

    let req = read(&tmp.path().join("requirements.txt"));
    assert!(req.contains("socket-patch[hook]"), "got:\n{req}");
    assert!(req.contains("requests==2.31.0"), "must preserve existing deps");

    // The committed dependency is the source of truth — no separate marker file.
    assert!(
        !tmp.path().join(".socket/hook.json").exists(),
        "setup must not write a separate marker/audit file"
    );
}

#[test]
fn uv_pyproject_array_edited_and_format_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let original = "[project]\nname = \"x\"\nversion = \"0.0.0\"\ndependencies = [\n    \"requests\",\n]\n\n[tool.uv]\n";
    write(&tmp.path().join("pyproject.toml"), original);
    write(&tmp.path().join("uv.lock"), ""); // detected as uv

    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0, "payload={v}");
    assert_eq!(v["pythonPackageManager"], "uv");

    let py = read(&tmp.path().join("pyproject.toml"));
    assert!(py.contains("socket-patch[hook]"));
    assert!(py.contains("[tool.uv]"), "unrelated tables preserved");
    assert!(py.contains("name = \"x\""));
}

#[test]
fn idempotent_second_run_reports_already_configured() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("requirements.txt"), "requests\n");

    let (_, _) = run_setup(tmp.path(), &[]);
    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "already_configured");
    let req = read(&tmp.path().join("requirements.txt"));
    assert_eq!(
        req.matches("socket-patch[hook]").count(),
        1,
        "must not duplicate the hook dependency"
    );
}

#[test]
fn dry_run_does_not_modify_or_create_files() {
    let tmp = tempfile::tempdir().unwrap();
    let original = "requests\n";
    write(&tmp.path().join("requirements.txt"), original);

    let (code, v) = run_setup(tmp.path(), &["--dry-run"]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "dry_run");
    assert_eq!(v["dryRun"], true);
    assert_eq!(v["wouldUpdate"], 1);

    assert_eq!(read(&tmp.path().join("requirements.txt")), original);
}

#[test]
fn remove_reverses_dep() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("requirements.txt"), "requests\n");
    // Configure first.
    let (_, v) = run_setup(tmp.path(), &[]);
    assert_eq!(v["status"], "success");

    let (code, v) = run_setup(tmp.path(), &["--remove"]);
    assert_eq!(code, 0, "payload={v}");
    let req = read(&tmp.path().join("requirements.txt"));
    assert!(!req.contains("socket-patch[hook]"), "got:\n{req}");
    assert!(req.contains("requests"));
}

#[test]
fn polyglot_configures_both_npm_and_python() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("package.json"),
        "{ \"name\": \"x\", \"version\": \"0.0.0\" }\n",
    );
    write(
        &tmp.path().join("pyproject.toml"),
        "[project]\nname = \"x\"\nversion = \"0.0.0\"\ndependencies = []\n",
    );

    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0, "payload={v}");
    assert_eq!(v["updated"], 2);
    let kinds: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"package_json"));
    assert!(kinds.contains(&"pth"));

    assert!(read(&tmp.path().join("package.json")).contains("socket-patch"));
    assert!(read(&tmp.path().join("pyproject.toml")).contains("socket-patch[hook]"));
}

#[test]
fn pure_python_with_no_manifest_files_is_no_op() {
    // `setup.py`-only project (no pyproject/requirements): pip path would
    // create requirements.txt. But an EMPTY dir with neither markers nor
    // package.json must report no_files.
    let tmp = tempfile::tempdir().unwrap();
    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "no_files");
}
