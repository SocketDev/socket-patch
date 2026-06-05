//! Integration tests for `setup`'s Python `.pth`-hook branch. Like the npm
//! `setup_invariants`, these operate entirely on disk (manifest detection +
//! editing + audit record) and need no network.

use std::collections::BTreeSet;
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

/// The set of directory-entry names directly under `dir` (non-recursive).
fn dir_entries(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect()
}

/// Return the single `files[]` entry whose `kind == kind`, panicking if there
/// is not exactly one. Stops a regression from hiding a wrong/extra entry
/// behind a positional `files[0]`.
fn file_entry<'a>(v: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    let arr = v["files"].as_array().unwrap_or_else(|| panic!("files must be an array: {v}"));
    let matches: Vec<&serde_json::Value> =
        arr.iter().filter(|f| f["kind"] == kind).collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{kind}` file entry, got {}: {v}",
        matches.len()
    );
    matches[0]
}

/// Extract the literal text inside the first top-level `dependencies = [ ... ]`
/// array in a pyproject.toml, so we can assert membership *within the array*
/// rather than merely "the string appears somewhere in the file". Deliberately
/// independent of the production toml_edit code path.
fn dependencies_array_body(toml: &str) -> String {
    let start = toml
        .find("dependencies = [")
        .unwrap_or_else(|| panic!("no `dependencies = [` in:\n{toml}"));
    // Scan from just inside the opening `[` (depth 1) and find the matching
    // close, accounting for nested brackets like the `[hook]` extra in
    // `socket-patch[hook]` — a naive `.find(']')` would stop there.
    let after = &toml[start + "dependencies = [".len()..];
    let mut depth = 1usize;
    let mut end = None;
    for (i, c) in after.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.unwrap_or_else(|| panic!("unterminated dependencies array in:\n{toml}"));
    after[..end].to_string()
}

#[test]
fn pip_requirements_gets_hook_dep() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("requirements.txt"), "requests==2.31.0\n");

    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0, "setup should succeed; payload={v}");
    assert_eq!(v["status"], "success");
    assert_eq!(v["updated"], 1);
    assert_eq!(v["alreadyConfigured"], 0, "fresh file is not already-configured");
    assert_eq!(v["errors"], 0);
    assert_eq!(v["pythonPackageManager"], "pip");

    let entry = file_entry(&v, "pth");
    assert_eq!(entry["status"], "updated");
    assert!(
        entry["path"].as_str().unwrap().ends_with("requirements.txt"),
        "pth entry must point at requirements.txt: {entry}"
    );
    assert!(entry["error"].is_null(), "no error expected: {entry}");

    // Exact on-disk result: the hook dep is appended on its own trailing line,
    // the existing pinned dep is preserved verbatim, nothing else is rewritten.
    let req = read(&tmp.path().join("requirements.txt"));
    assert_eq!(
        req, "requests==2.31.0\nsocket-patch[hook]\n",
        "requirements.txt must gain exactly the hook line; got:\n{req}"
    );

    // The committed dependency is the source of truth — no separate marker file
    // and no other files conjured into the project dir.
    assert_eq!(
        dir_entries(tmp.path()),
        BTreeSet::from(["requirements.txt".to_string()]),
        "setup must touch only requirements.txt"
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
    assert_eq!(v["status"], "success", "payload={v}");
    assert_eq!(v["updated"], 1);
    assert_eq!(v["errors"], 0);
    assert_eq!(v["pythonPackageManager"], "uv");

    let entry = file_entry(&v, "pth");
    assert_eq!(entry["status"], "updated");
    assert!(entry["path"].as_str().unwrap().ends_with("pyproject.toml"));

    let py = read(&tmp.path().join("pyproject.toml"));

    // The hook dep must land *inside* the PEP 621 dependencies array, alongside
    // the pre-existing `requests` — not appended as a stray top-level line.
    let body = dependencies_array_body(&py);
    assert!(
        body.contains("socket-patch[hook]"),
        "hook dep must be inside the dependencies array; array body:\n{body}\nfull:\n{py}"
    );
    assert!(
        body.contains("\"requests\""),
        "existing dep must remain in the array; array body:\n{body}"
    );
    // Exactly one occurrence in the whole file (no duplication / stray copy).
    assert_eq!(
        py.matches("socket-patch[hook]").count(),
        1,
        "hook dep must appear exactly once; got:\n{py}"
    );

    // Format / unrelated content preserved: the [tool.uv] table survives, the
    // user's 4-space array indentation is kept, and the file is still parseable
    // by the same edit path (idempotent re-run reports already-configured, which
    // proves the array is well-formed enough to be re-detected).
    assert!(py.contains("[tool.uv]"), "unrelated tables preserved:\n{py}");
    assert!(py.contains("name = \"x\""), "scalar keys preserved:\n{py}");
    assert!(
        py.contains("    \"requests\""),
        "original 4-space array indentation must be preserved:\n{py}"
    );

    let (code2, v2) = run_setup(tmp.path(), &[]);
    assert_eq!(code2, 0);
    assert_eq!(
        v2["status"], "already_configured",
        "re-run must detect the array entry it just wrote: {v2}"
    );
}

#[test]
fn idempotent_second_run_reports_already_configured() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("requirements.txt"), "requests\n");

    let (code1, v1) = run_setup(tmp.path(), &[]);
    assert_eq!(code1, 0, "first run must succeed: {v1}");
    assert_eq!(v1["status"], "success", "first run must configure: {v1}");
    assert_eq!(v1["updated"], 1, "first run updates exactly one manifest: {v1}");

    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "already_configured");
    assert_eq!(v["updated"], 0, "second run must not re-edit: {v}");
    assert_eq!(v["alreadyConfigured"], 1, "second run sees it configured: {v}");
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
    let before = dir_entries(tmp.path());

    let (code, v) = run_setup(tmp.path(), &["--dry-run"]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "dry_run");
    assert_eq!(v["dryRun"], true);
    assert_eq!(v["wouldUpdate"], 1);
    assert_eq!(v["errors"], 0);

    // No write: byte-identical content AND no new files created anywhere in the
    // project dir (the failure mode the test name warns about).
    assert_eq!(read(&tmp.path().join("requirements.txt")), original);
    assert_eq!(
        dir_entries(tmp.path()),
        before,
        "dry-run must not create or remove any files"
    );
}

#[test]
fn remove_reverses_dep() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("requirements.txt"), "requests\n");
    // Configure first.
    let (_, v) = run_setup(tmp.path(), &[]);
    assert_eq!(v["status"], "success");
    assert_eq!(
        read(&tmp.path().join("requirements.txt")),
        "requests\nsocket-patch[hook]\n",
        "precondition: setup added the hook line"
    );

    let (code, v) = run_setup(tmp.path(), &["--remove"]);
    assert_eq!(code, 0, "payload={v}");
    assert_eq!(v["status"], "success", "remove must report success: {v}");
    assert_eq!(v["removed"], 1, "exactly one manifest reverted: {v}");
    assert_eq!(v["errors"], 0);
    let entry = file_entry(&v, "pth");
    assert_eq!(entry["status"], "removed");

    // Exact restoration to the pre-setup content — not merely "hook absent".
    let req = read(&tmp.path().join("requirements.txt"));
    assert_eq!(
        req, "requests\n",
        "remove must restore the original file byte-for-byte; got:\n{req}"
    );
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
    assert_eq!(v["status"], "success", "payload={v}");
    assert_eq!(v["updated"], 2);
    assert_eq!(v["alreadyConfigured"], 0, "both manifests start unconfigured: {v}");
    assert_eq!(v["errors"], 0);

    let files = v["files"].as_array().unwrap();
    // Exactly the two expected kinds, each updated.
    let pj = file_entry(&v, "package_json");
    assert_eq!(pj["status"], "updated");
    let pth = file_entry(&v, "pth");
    assert_eq!(pth["status"], "updated");
    assert_eq!(files.len(), 2, "no spurious extra file entries: {v}");

    // The npm side injects the postinstall hook into package.json.
    let pkg = read(&tmp.path().join("package.json"));
    assert!(pkg.contains("socket-patch"), "package.json must gain the hook:\n{pkg}");
    assert!(pkg.contains("postinstall"), "npm hook is a postinstall script:\n{pkg}");

    // The python side adds the dep inside the dependencies array.
    let py = read(&tmp.path().join("pyproject.toml"));
    assert!(
        dependencies_array_body(&py).contains("socket-patch[hook]"),
        "hook dep must be inside the pyproject dependencies array:\n{py}"
    );
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
    assert_eq!(v["updated"], 0, "no_files must touch nothing: {v}");
    assert_eq!(v["errors"], 0);
    assert!(
        v["files"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "no_files must report an empty files list: {v}"
    );

    // Crucially: setup must NOT conjure a requirements.txt (or any file) into an
    // empty, non-python directory.
    assert!(
        dir_entries(tmp.path()).is_empty(),
        "no files may be created on a no_files run; found: {:?}",
        dir_entries(tmp.path())
    );
}
