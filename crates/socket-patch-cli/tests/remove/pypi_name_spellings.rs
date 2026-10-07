//! #1024: `remove` and `rollback` select a PyPI patch by any PEP 503
//! spelling of its name. Patch keys are canonical
//! (`pkg:pypi/typing-extensions@4.7.1`), but users type the name the way
//! the project declares it (`typing_extensions`, `Typing-Extensions`), the
//! same identifier `get` accepts.
//!
//! Agent mode, offline, against a hand-built venv: the identifier must
//! select the patch, restore the installed file and (for `remove`) drop the
//! manifest entry.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::common;

const KEY: &str = "pkg:pypi/typing-extensions@4.7.1";
const UUID: &str = "10241024-1024-4024-8024-102410241024";
const BEFORE: &[u8] = b"VERSION = 'original'\n";
const AFTER: &[u8] = b"VERSION = 'patched'\n";

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    venv: PathBuf,
    module: PathBuf,
}

/// An installed, patched `typing_extensions` 4.7.1 in `.venv`, its manifest
/// entry under the canonical key, and the before-blob staged for an
/// offline rollback.
fn patched_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let venv = root.join(".venv");
    #[cfg(windows)]
    let site_packages = venv.join("Lib").join("site-packages");
    #[cfg(not(windows))]
    let site_packages = venv.join("lib").join("python3.12").join("site-packages");
    let dist_info = site_packages.join("typing_extensions-4.7.1.dist-info");
    std::fs::create_dir_all(&dist_info).expect("create dist-info");
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: typing_extensions\nVersion: 4.7.1\n",
    )
    .expect("write METADATA");
    let module = site_packages.join("typing_extensions.py");
    std::fs::write(&module, AFTER).expect("write module");

    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).expect("create .socket/blobs");
    let manifest = json!({
        "patches": {
            KEY: {
                "uuid": UUID,
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "typing_extensions.py": {
                        "beforeHash": common::git_sha256(BEFORE),
                        "afterHash": common::git_sha256(AFTER),
                    }
                },
                "vulnerabilities": {},
                "description": "synthetic #1024 patch",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    std::fs::write(
        socket.join("blobs").join(common::git_sha256(BEFORE)),
        BEFORE,
    )
    .expect("stage before-blob");
    Fixture {
        _tmp: tmp,
        root,
        venv,
        module,
    }
}

fn run(fx: &Fixture, args: &[&str]) -> (i32, String, String) {
    common::run_with_env(
        &fx.root,
        args,
        &[("VIRTUAL_ENV", fx.venv.to_str().expect("utf8 venv path"))],
    )
}

fn manifest(root: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(root.join(".socket").join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON")
}

const SPELLINGS: &[&str] = &[
    "pkg:pypi/typing_extensions@4.7.1",
    "pkg:pypi/Typing-Extensions@4.7.1",
    "pkg:pypi/typing.extensions@4.7.1",
];

#[test]
fn remove_selects_pypi_patch_by_any_pep503_spelling() {
    for spelling in SPELLINGS {
        let fx = patched_fixture();
        let (code, stdout, stderr) =
            run(&fx, &["remove", spelling, "--json", "--yes", "--offline"]);
        assert_eq!(
            code, 0,
            "remove {spelling} must select {KEY}; stdout=\n{stdout}\nstderr=\n{stderr}"
        );
        assert_eq!(
            std::fs::read(&fx.module).expect("read module"),
            BEFORE,
            "remove {spelling} must restore the original file"
        );
        assert!(
            manifest(&fx.root)["patches"].get(KEY).is_none(),
            "remove {spelling} must drop the manifest entry; stdout=\n{stdout}"
        );
    }
}

#[test]
fn rollback_selects_pypi_patch_by_any_pep503_spelling() {
    for spelling in SPELLINGS {
        let fx = patched_fixture();
        let (code, stdout, stderr) =
            run(&fx, &["rollback", spelling, "--json", "--yes", "--offline"]);
        assert_eq!(
            code, 0,
            "rollback {spelling} must select {KEY}; stdout=\n{stdout}\nstderr=\n{stderr}"
        );
        assert_eq!(
            std::fs::read(&fx.module).expect("read module"),
            BEFORE,
            "rollback {spelling} must restore the original file; stdout=\n{stdout}"
        );
    }
}

#[test]
fn remove_still_refuses_another_pypi_version() {
    let fx = patched_fixture();
    let (code, stdout, _) = run(
        &fx,
        &[
            "remove",
            "pkg:pypi/typing_extensions@4.7.2",
            "--json",
            "--yes",
            "--offline",
        ],
    );
    assert_eq!(code, 1, "another version must not match; stdout=\n{stdout}");
    assert_eq!(
        std::fs::read(&fx.module).expect("read module"),
        AFTER,
        "a non-matching identifier must leave the patch applied"
    );
    assert!(manifest(&fx.root)["patches"].get(KEY).is_some());
}
