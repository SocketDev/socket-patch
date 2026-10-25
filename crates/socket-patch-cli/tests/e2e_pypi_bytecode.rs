//! Agent-mode PyPI apply and rollback against real CPython bytecode (#819).
//!
//! pip byte-compiles every installed module into `__pycache__/*.pyc`.
//! Without `SOURCE_DATE_EPOCH` those files are timestamp-validated: CPython
//! reuses the bytecode while the source's mtime (whole seconds) and size
//! match the `.pyc` header. A same-size patch written in the same second as
//! the install therefore kept the unpatched bytecode running while `apply`
//! reported success, and a rollback in the same second as the apply kept
//! the patched bytecode running.
//!
//! The race is made deterministic by putting the source's mtime back on
//! the second the bytecode was compiled against after each write: exactly
//! what an apply or rollback inside that second leaves on disk.
//!
//! A real venv and interpreter, a hand-installed `dupkit 1.0.0`, a staged
//! manifest + blobs and `--offline`. Skipped when no Python 3 is on PATH.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::json;

const PURL: &str = "pkg:pypi/dupkit@1.0.0";
const UUID: &str = "81981981-9819-4819-8819-819819819819";
const FILE: &str = "dupkit/__init__.py";
// Same length, so a timestamp `.pyc` cannot tell them apart by size.
const ORIGINAL: &[u8] = b"VERSION = 'original'\n";
const PATCHED: &[u8] = b"VERSION = 'patchedX'\n";

/// Env vars that change where or whether CPython reads and writes
/// bytecode, or which interpreter / site dirs are used.
const PYTHON_VARS: &[&str] = &[
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONPYCACHEPREFIX",
    "SOURCE_DATE_EPOCH",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONUSERBASE",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "WORKON_HOME",
    "PIPENV_ACTIVE",
];

fn python_on_path() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|py| {
        Command::new(py)
            .args(["-c", "import sys; assert sys.version_info >= (3, 7)"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

fn python(py: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new(py);
    cmd.args(args);
    for name in PYTHON_VARS {
        cmd.env_remove(name);
    }
    let out = cmd.output().expect("run python");
    assert!(
        out.status.success(),
        "python {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn socket_patch(cwd: &Path, args: &[&str]) {
    let mut cmd = common::hermetic::command(&common::binary());
    cmd.args(args).current_dir(cwd);
    for name in PYTHON_VARS {
        cmd.env_remove(name);
    }
    let out = cmd.output().expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "socket-patch {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn set_mtime(path: &Path, mtime: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
}

/// Whole-second mtime: the precision a timestamp `.pyc` records.
fn second_of(path: &Path) -> SystemTime {
    let secs = std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// What `import dupkit` runs, through the venv's interpreter.
fn imported_version(py: &Path) -> String {
    python(py, &["-c", "import dupkit; print(dupkit.VERSION)"])
}

fn stage_patch(project: &Path) {
    let socket = project.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = json!({
        "patches": {
            PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { FILE: {
                    "beforeHash": common::git_sha256(ORIGINAL),
                    "afterHash": common::git_sha256(PATCHED),
                }},
                "vulnerabilities": {},
                "description": "synthetic same-size bytecode test patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    common::write_blob(&socket, &common::git_sha256(ORIGINAL), ORIGINAL);
    common::write_blob(&socket, &common::git_sha256(PATCHED), PATCHED);
}

/// #819: a same-size apply (and rollback) in the same second as the
/// bytecode was compiled must still change what `import` runs.
#[test]
fn same_second_same_size_apply_and_rollback_change_imported_code() {
    let Some(system_py) = python_on_path() else {
        eprintln!("SKIP: no python3 on PATH");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("requirements.txt"), "dupkit==1.0.0\n").unwrap();
    let venv = project.join(".venv");
    python(
        Path::new(system_py),
        &["-m", "venv", "--without-pip", venv.to_str().unwrap()],
    );
    let py: PathBuf = if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    };
    let site = PathBuf::from(python(
        &py,
        &["-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
    ));

    // Install dupkit 1.0.0 the way pip leaves it: dist-info, module, and
    // timestamp bytecode compiled from the module.
    let dist = site.join("dupkit-1.0.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: dupkit\nVersion: 1.0.0\n",
    )
    .unwrap();
    let module = site.join(FILE);
    std::fs::create_dir_all(module.parent().unwrap()).unwrap();
    std::fs::write(&module, ORIGINAL).unwrap();
    python(
        &py,
        &["-m", "compileall", "-q", module.parent().unwrap().to_str().unwrap()],
    );
    assert_eq!(imported_version(&py), "original");
    stage_patch(&project);

    // Apply in the same second the install compiled against.
    let installed_second = second_of(&module);
    socket_patch(&project, &["apply", "--offline"]);
    assert_eq!(std::fs::read(&module).unwrap(), PATCHED);
    set_mtime(&module, installed_second);
    assert_eq!(
        imported_version(&py),
        "patchedX",
        "apply reported the module patched, but Python still runs the \
         install's bytecode"
    );

    // The import above compiled bytecode for the patched source. Roll back
    // in that same second.
    let patched_second = second_of(&module);
    socket_patch(&project, &["rollback", "--offline", "--yes"]);
    assert_eq!(std::fs::read(&module).unwrap(), ORIGINAL);
    set_mtime(&module, patched_second);
    assert_eq!(
        imported_version(&py),
        "original",
        "rollback restored the source, but Python still runs the patched \
         bytecode"
    );
}
