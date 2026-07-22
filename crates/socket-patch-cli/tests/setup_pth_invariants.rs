//! Integration tests for `setup`'s Python `.pth`-hook branch. Like the npm
//! `setup_invariants`, these operate entirely on disk (manifest detection +
//! editing + audit record) and need no network.

use std::collections::BTreeSet;
use std::path::Path;

#[path = "common/mod.rs"]
mod common;

/// Run `setup --json --yes [extra]` in `cwd` through the shared hermetic
/// runner. The binary binds a wide `SOCKET_*` env surface (SOCKET_DRY_RUN,
/// SOCKET_ECOSYSTEMS, SOCKET_CWD, SOCKET_SETUP_EXCLUDE, ...); an ambient
/// value silently flips what every test here exercises (SOCKET_DRY_RUN=true
/// turns each real run into a dry run, SOCKET_ECOSYSTEMS=npm hides the
/// Python branch entirely), so `common::run_with_env`'s seed-then-scrub is
/// load-bearing, not hygiene.
fn run_setup(cwd: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut args = vec!["setup", "--json", "--yes"];
    args.extend_from_slice(extra);
    let (code, stdout, _stderr) =
        common::run_with_env(cwd, &args, &[("SOCKET_TELEMETRY_DISABLED", "1")]);
    let v = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}):\n{stdout}"));
    (code, v)
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

/// Every regular-file path under `dir`, relative to `dir` (recursive). Proves
/// `setup` writes nothing outside the repo (property 5) and snapshots a
/// "clone" (property 6).
fn files_under(dir: &Path) -> BTreeSet<String> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    out.insert(p.strip_prefix(base).unwrap().to_string_lossy().to_string());
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

/// Copy every file under `src` into `dst`. Simulates a fresh checkout of the
/// committed tree on another host.
fn copy_tree(src: &Path, dst: &Path) {
    for rel in files_under(src) {
        let to = dst.join(&rel);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::copy(src.join(&rel), &to).expect("copy file");
    }
}

/// Return the single `files[]` entry whose `kind == kind`, panicking if there
/// is not exactly one. Stops a regression from hiding a wrong/extra entry
/// behind a positional `files[0]`.
fn file_entry<'a>(v: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    let arr = v["files"]
        .as_array()
        .unwrap_or_else(|| panic!("files must be an array: {v}"));
    let matches: Vec<&serde_json::Value> = arr.iter().filter(|f| f["kind"] == kind).collect();
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
    assert_eq!(
        v["alreadyConfigured"], 0,
        "fresh file is not already-configured"
    );
    assert_eq!(v["errors"], 0);
    assert_eq!(v["pythonPackageManager"], "pip");

    let entry = file_entry(&v, "pth");
    assert_eq!(entry["status"], "updated");
    assert!(
        entry["path"]
            .as_str()
            .unwrap()
            .ends_with("requirements.txt"),
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
    assert!(
        py.contains("[tool.uv]"),
        "unrelated tables preserved:\n{py}"
    );
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
    assert_eq!(
        v1["updated"], 1,
        "first run updates exactly one manifest: {v1}"
    );

    let (code, v) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "already_configured");
    assert_eq!(v["updated"], 0, "second run must not re-edit: {v}");
    assert_eq!(
        v["alreadyConfigured"], 1,
        "second run sees it configured: {v}"
    );
    let req = read(&tmp.path().join("requirements.txt"));
    assert_eq!(
        req.matches("socket-patch[hook]").count(),
        1,
        "must not duplicate the hook dependency"
    );
}

#[test]
fn pep503_equivalent_hook_spellings_are_already_configured() {
    // pip installs the hook from `socket_patch[hook]` exactly as from the
    // canonical spelling (PEP 503: `-`/`_`/`.` are interchangeable in names)
    // and from a combined-extras spec like `socket-patch[cli,hook]` (PEP 508).
    // Setup must recognize both as configured: appending a second spelling of
    // the same requirement is non-idempotent, `--check` would fail a CI gate
    // on a correctly configured repo, and `--remove` would report nothing to
    // remove while the hook stays wired.
    for spec in ["socket_patch[hook]\n", "socket-patch[cli,hook]>=1.0\n"] {
        let tmp = tempfile::tempdir().unwrap();
        write(&tmp.path().join("requirements.txt"), spec);

        let (code, v) = run_setup(tmp.path(), &[]);
        assert_eq!(code, 0, "spec {spec:?}: payload={v}");
        assert_eq!(
            v["status"], "already_configured",
            "spec {spec:?} already declares the hook; setup must not re-add it: {v}"
        );
        assert_eq!(
            read(&tmp.path().join("requirements.txt")),
            spec,
            "spec {spec:?}: requirements.txt must be untouched"
        );

        let (code, v) = run_setup(tmp.path(), &["--check"]);
        assert_eq!(
            code, 0,
            "spec {spec:?}: --check must pass on a configured project: {v}"
        );
        assert_eq!(v["status"], "configured", "spec {spec:?}: {v}");
    }
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
    assert_eq!(
        v["alreadyConfigured"], 0,
        "both manifests start unconfigured: {v}"
    );
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
    assert!(
        pkg.contains("socket-patch"),
        "package.json must gain the hook:\n{pkg}"
    );
    assert!(
        pkg.contains("postinstall"),
        "npm hook is a postinstall script:\n{pkg}"
    );

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

// ---------------------------------------------------------------------------
// Property 5 — the Python branch writes only inside the repo. The `.pth` wheel
// is installed later by the user's package manager into site-packages; `setup`
// itself only edits the committed requirements.txt / pyproject.toml and must
// never write to `$HOME` or global site-packages.
// (CLI_CONTRACT.md → "Setup command contract", property 5.)
// ---------------------------------------------------------------------------

#[test]
fn setup_python_writes_only_inside_repo() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write(&proj.path().join("requirements.txt"), "requests\n");
    assert!(
        files_under(home.path()).is_empty(),
        "sentinel HOME must start empty"
    );

    let (code, _stdout, stderr) = common::run_with_env(
        proj.path(),
        &["setup", "--json", "--yes"],
        &[
            ("HOME", home.path().to_str().unwrap()),
            ("SOCKET_TELEMETRY_DISABLED", "1"),
        ],
    );
    assert_eq!(code, 0, "setup should succeed; stderr=\n{stderr}");

    assert!(
        files_under(home.path()).is_empty(),
        "Python setup must not write outside --cwd; HOME gained: {:?}",
        files_under(home.path())
    );
    // Only the committed manifest was touched — no site-packages, no .pth, no
    // marker file beside it.
    assert_eq!(
        files_under(proj.path()),
        BTreeSet::from(["requirements.txt".to_string()]),
        "setup must touch only the in-repo requirements.txt"
    );
    assert_eq!(
        read(&proj.path().join("requirements.txt")),
        "requests\nsocket-patch[hook]\n",
        "the in-repo manifest must have gained exactly the hook line"
    );
}

// ---------------------------------------------------------------------------
// Property 6 — Python setup state is clone-portable: the committed dependency
// line is the whole story, so `--check` passes on a copied tree.
// (CLI_CONTRACT.md → "Setup command contract", property 6.)
// ---------------------------------------------------------------------------

#[test]
fn setup_python_state_is_clone_portable() {
    let a = tempfile::tempdir().unwrap();
    write(&a.path().join("requirements.txt"), "requests\n");
    let (c, v) = run_setup(a.path(), &[]);
    assert_eq!(c, 0, "initial setup must succeed: {v}");
    assert_eq!(v["status"], "success");

    let b = tempfile::tempdir().unwrap();
    copy_tree(a.path(), b.path());

    let before = read(&b.path().join("requirements.txt"));
    let (code, v) = run_setup(b.path(), &["--check"]);
    assert_eq!(code, 0, "clone must already be configured: {v}");
    assert_eq!(v["status"], "configured");
    assert_eq!(
        read(&b.path().join("requirements.txt")),
        before,
        "--check must not modify the clone"
    );
}

// ---------------------------------------------------------------------------
// Property 7 — the post-edit lockfile refresh must not rewrite the user's
// pinned dependency set. Poetry 1.x's bare `poetry lock` re-resolves EVERY
// dependency to the newest compatible version (the pin-preserving spelling is
// `lock --no-update`); Poetry 2.x makes pin-preserving the default and
// REMOVES `--no-update`, so setup must try the 1.x spelling first and fall
// back to the bare form when the flag is unknown. Same shape for PDM
// (`--update-reuse`). A fake package manager on PATH records the argv setup
// actually invokes.
// ---------------------------------------------------------------------------

/// Lay a fake `name` executable into `bin_dir` that appends its argv to `log`
/// and exits 0 — unless the argv contains `reject_arg`, in which case it prints
/// an unknown-option error and exits 1 without logging (a tool that does not
/// know the flag, e.g. Poetry 2.x and `--no-update`).
#[cfg(unix)]
fn write_pm_shim(bin_dir: &Path, name: &str, log: &Path, reject_arg: Option<&str>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(bin_dir).expect("create shim dir");
    let reject = match reject_arg {
        Some(flag) => format!(
            "case \"$*\" in *{flag}*) echo 'The \"{flag}\" option does not exist.' >&2; exit 1;; esac\n"
        ),
        None => String::new(),
    };
    let body = format!(
        "#!/bin/sh\n{reject}printf '%s\\n' \"$*\" >> '{}'\nexit 0\n",
        log.display()
    );
    let p = bin_dir.join(name);
    std::fs::write(&p, body).expect("write shim");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

/// `run_setup` with the shim dir prepended to PATH so the spawned lockfile
/// refresh resolves to the fake package manager.
#[cfg(unix)]
fn run_setup_with_shims(cwd: &Path, bin_dir: &Path) -> (i32, serde_json::Value) {
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let (code, stdout, _stderr) = common::run_with_env(
        cwd,
        &["setup", "--json", "--yes"],
        &[("SOCKET_TELEMETRY_DISABLED", "1"), ("PATH", &path_env)],
    );
    let v = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}):\n{stdout}"));
    (code, v)
}

const POETRY_PYPROJECT: &str = "[tool.poetry]\nname = \"x\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = []\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";

#[cfg(unix)]
#[test]
fn poetry_lock_refresh_asks_for_pin_preserving_lock_first() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("pyproject.toml"), POETRY_PYPROJECT);
    write(&tmp.path().join("poetry.lock"), "# stub lock\n");
    let log = tmp.path().join("poetry-argv.log");
    // Poetry 1.x: knows both `lock` and `lock --no-update`.
    write_pm_shim(&tmp.path().join("bin"), "poetry", &log, None);

    let (code, v) = run_setup_with_shims(tmp.path(), &tmp.path().join("bin"));
    assert_eq!(code, 0, "setup must succeed: {v}");
    let argvs = read(&log);
    let first = argvs.lines().next().unwrap_or_default();
    assert_eq!(
        first, "lock --no-update",
        "on a tool that accepts it, the FIRST lock invocation must be the \
         pin-preserving `poetry lock --no-update` — the bare `poetry lock` \
         re-resolves the user's entire pinned set on Poetry 1.x; got argv log:\n{argvs}"
    );
    assert!(
        v.get("warnings").is_none(),
        "successful pin-preserving refresh must not warn: {v}"
    );
}

#[cfg(unix)]
#[test]
fn poetry_2x_without_no_update_falls_back_to_bare_lock() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("pyproject.toml"), POETRY_PYPROJECT);
    write(&tmp.path().join("poetry.lock"), "# stub lock\n");
    let log = tmp.path().join("poetry-argv.log");
    // Poetry 2.x: `--no-update` was removed (pin-preserving became the
    // default), so that spelling exits non-zero.
    write_pm_shim(&tmp.path().join("bin"), "poetry", &log, Some("--no-update"));

    let (code, v) = run_setup_with_shims(tmp.path(), &tmp.path().join("bin"));
    assert_eq!(code, 0, "setup must succeed: {v}");
    let argvs = read(&log);
    assert_eq!(
        argvs.lines().last().unwrap_or_default(),
        "lock",
        "when `--no-update` is unknown the bare `poetry lock` must still run \
         (it is pin-preserving on 2.x); got argv log:\n{argvs}"
    );
    assert!(
        v.get("warnings").is_none(),
        "a successful fallback is not a failure — no lockfile warning: {v}"
    );
}

#[cfg(unix)]
#[test]
fn pdm_lock_refresh_asks_for_pin_preserving_lock_first() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("pyproject.toml"),
        "[project]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n\n[tool.pdm]\n",
    );
    write(&tmp.path().join("pdm.lock"), "# stub lock\n");
    let log = tmp.path().join("pdm-argv.log");
    write_pm_shim(&tmp.path().join("bin"), "pdm", &log, None);

    let (code, v) = run_setup_with_shims(tmp.path(), &tmp.path().join("bin"));
    assert_eq!(code, 0, "setup must succeed: {v}");
    let argvs = read(&log);
    assert_eq!(
        argvs.lines().next().unwrap_or_default(),
        "lock --update-reuse",
        "the first PDM lock invocation must reuse the user's pins; got argv log:\n{argvs}"
    );
}
