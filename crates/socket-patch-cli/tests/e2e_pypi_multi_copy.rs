//! Agent-mode PyPI apply over SEVERAL installed copies of one release.
//!
//! The Python crawler can resolve one `name@version` in more than one
//! candidate site-packages dir: a Pipenv project with both a WORKON_HOME
//! venv and an auto-detected `./.venv` (#529), or the user site beside a
//! system `dist-packages` in global scope (#501). Which copy the
//! interpreter imports is not knowable without running the project's tool,
//! so `apply` must patch EVERY copy (as it does for npm and gem, and as
//! `rollback` already restores every copy). Patching only the first one
//! left the imported copy vulnerable while `vex` attested `not_affected`.
//!
//! Hand-built site-packages layouts, a staged manifest + blobs, `--offline`:
//! no Python, network or package manager needed for #529; #501 swaps in a
//! stub `python3` whose `site` answer lists a system dir and the user site.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

const PURL: &str = "pkg:pypi/dupkit@1.0.0";
const UUID: &str = "52952952-9529-4529-8529-529529529529";
const FILE: &str = "dupkit/__init__.py";
const ORIGINAL: &[u8] = b"VERSION = 'original'\n";
const PATCHED: &[u8] = b"VERSION = 'patched'\n";

/// Env vars that redirect Python/Pipenv discovery; removed from every
/// child so an activated shell or CI image cannot change which dirs the
/// crawler probes.
const DISCOVERY_VARS: &[&str] = &[
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "WORKON_HOME",
    "PIPENV_ACTIVE",
    "PIPENV_IGNORE_VIRTUALENVS",
    "PIPENV_NO_IGNORE_VIRTUALENVS",
    "PIPENV_VENV_IN_PROJECT",
    "PIPENV_NO_VENV_IN_PROJECT",
    "PIPENV_CUSTOM_VENV_NAME",
    "PIPENV_PIPFILE",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONUSERBASE",
];

/// Run the binary in `cwd` with the `SOCKET_*` and discovery env scrubbed
/// and exactly `env` added.
fn run(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(common::binary());
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") {
            cmd.env_remove(&key);
        }
    }
    for name in DISCOVERY_VARS {
        cmd.env_remove(name);
    }
    cmd.env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `<venv>/lib/python3.12/site-packages` (`Lib\site-packages` on Windows),
/// the layout `find_site_packages_under` probes.
fn venv_site_packages(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Lib").join("site-packages")
    } else {
        venv.join("lib").join("python3.12").join("site-packages")
    }
}

/// Install a pristine `dupkit 1.0.0` (dist-info + module) into `site`.
/// Returns the module file the patch rewrites.
fn install_dupkit(site: &Path) -> PathBuf {
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
    module
}

/// Stage the agent patch for `dupkit 1.0.0` (with one vulnerability so
/// `vex` has a statement to emit) and its before/after blobs.
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
                "vulnerabilities": { "GHSA-dupk-dupk-dupk": {
                    "cves": ["CVE-2026-0529"],
                    "summary": "dupkit test vulnerability",
                    "severity": "high",
                    "description": "synthetic",
                }},
                "description": "synthetic multi-copy test patch",
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

fn envelope(stdout: &str, stderr: &str) -> Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("not a JSON envelope ({e}):\n{stdout}\nstderr:\n{stderr}"))
}

/// Apply, check every copy is patched, `vex` attests, then rollback
/// restores every copy.
fn assert_every_copy_patched(
    cwd: &Path,
    global: bool,
    env: &[(&str, &str)],
    copies: &[(&str, &Path)],
) {
    let g: &[&str] = if global { &["-g"] } else { &[] };
    let with = |base: &[&'static str]| -> Vec<&str> { base.iter().chain(g).copied().collect() };

    let (code, stdout, stderr) = run(cwd, &with(&["apply", "--offline", "--json"]), env);
    assert_eq!(
        code, 0,
        "apply failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env_json = envelope(&stdout, &stderr);
    for (label, module) in copies {
        assert_eq!(
            std::fs::read(module).unwrap(),
            PATCHED,
            "the {label} copy must be patched: apply has to patch EVERY \
             installed copy, the interpreter may import any of them\n\
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    let applied = env_json["events"]
        .as_array()
        .expect("envelope events array")
        .iter()
        .filter(|e| e["purl"] == json!(PURL) && e["action"] == json!("applied"))
        .count();
    assert_eq!(
        applied,
        copies.len(),
        "one `applied` event per patched copy\nstdout:\n{stdout}"
    );

    // A re-run sees every copy already patched: nothing fails.
    let (code, stdout, stderr) = run(cwd, &with(&["apply", "--offline", "--json"]), env);
    assert_eq!(code, 0, "re-apply\nstdout:\n{stdout}\nstderr:\n{stderr}");

    let (code, stdout, stderr) = run(
        cwd,
        &with(&["vex", "--offline", "--product", "pkg:pypi/app@1.0.0"]),
        env,
    );
    assert_eq!(code, 0, "vex\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc = envelope(&stdout, &stderr);
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "vex doc:\n{stdout}");
    assert_eq!(
        stmts[0]["status"],
        json!("not_affected"),
        "vex doc:\n{stdout}"
    );

    let (code, stdout, stderr) = run(
        cwd,
        &with(&["rollback", "--offline", "--json", "--yes"]),
        env,
    );
    assert_eq!(code, 0, "rollback\nstdout:\n{stdout}\nstderr:\n{stderr}");
    for (label, module) in copies {
        assert_eq!(
            std::fs::read(module).unwrap(),
            ORIGINAL,
            "rollback must restore the {label} copy\nstdout:\n{stdout}"
        );
    }
}

/// #529: a Pipenv project with a WORKON_HOME venv AND an auto-detected
/// `./.venv` (nothing explicit about which Pipenv uses). Pipenv up to
/// 2026.1 runs `./.venv`, 2026.2+ the WORKON_HOME one; the crawler returns
/// both, WORKON_HOME first. Apply used to patch only the WORKON_HOME copy,
/// leaving the `./.venv` copy older Pipenv imports unpatched.
#[test]
fn pipenv_workon_home_and_dot_venv_copies_are_all_patched() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("Pipfile"),
        "[packages]\ndupkit = \"==1.0.0\"\n",
    )
    .unwrap();
    let workon = tmp.path().join("wh");
    let workon_copy = install_dupkit(&venv_site_packages(&workon.join("proj-env")));
    let in_tree_copy = install_dupkit(&venv_site_packages(&project.join(".venv")));
    stage_patch(&project);

    let workon_str = workon.to_str().unwrap();
    assert_every_copy_patched(
        &project,
        false,
        &[
            ("WORKON_HOME", workon_str),
            ("PIPENV_CUSTOM_VENV_NAME", "proj-env"),
            ("HOME", tmp.path().to_str().unwrap()),
        ],
        &[
            ("WORKON_HOME venv", workon_copy.as_path()),
            ("./.venv", in_tree_copy.as_path()),
        ],
    );
}

/// #501: the same release in a system site dir and in the user site. The
/// interpreter's `site` answer lists the system dirs first and the user
/// site last, while `sys.path` imports the user site first. Apply used to
/// patch only the first (shadowed, system) copy, so the imported user-site
/// copy stayed vulnerable while `vex -g` attested it.
#[cfg(unix)]
#[test]
fn global_system_and_user_site_copies_are_all_patched() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home");
    let system_site = root.join("usr/lib/python3/dist-packages");
    let user_site = home.join(".local/lib/python3.12/site-packages");
    let system_copy = install_dupkit(&system_site);
    let user_copy = install_dupkit(&user_site);

    // Stub interpreter: `python3 --version` succeeds, and the `site` query
    // prints `getsitepackages()` then `getusersitepackages()`, exactly the
    // order the real query prints.
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stub = bin.join("python3");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'Python 3.12.0'; exit 0; fi\n\
             printf '%s\\n%s\\n' '{}' '{}'\n",
            system_site.display(),
            user_site.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

    let project = root.join("work");
    std::fs::create_dir_all(&project).unwrap();
    stage_patch(&project);

    let path = format!("{}:/usr/bin:/bin", bin.display());
    assert_every_copy_patched(
        &project,
        true,
        &[("PATH", path.as_str()), ("HOME", home.to_str().unwrap())],
        &[
            ("system dist-packages", system_copy.as_path()),
            ("user site", user_copy.as_path()),
        ],
    );
}
