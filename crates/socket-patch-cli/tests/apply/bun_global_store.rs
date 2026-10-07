//! Agent-mode `apply` / `rollback` on a project installed with Bun's global
//! store (`[install] globalStore = true`, Bun >= 1.3.14, #635).
//!
//! Each `node_modules/.bun/<entry>` is then a link into
//! `<cache>/links/<entry>-<hash>`, and every project on the machine links
//! to the same dir. Writing through it patched (and a rollback unpatched)
//! every other project using the store, with `success`. And because the
//! `.bun` walk kept only real dirs, a transitive dependency was reported
//! `package_not_installed` and left unpatched.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::common;

use common::{git_sha256, parse_json_envelope, run_with_env};

const BEFORE: &[u8] = b"module.exports = 'pristine';\n";
const AFTER: &[u8] = b"module.exports = 'patched';\n";

fn link_dir(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        let link: PathBuf = link.components().collect();
        let target: PathBuf = target.components().collect();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
    }
}

/// The layout Bun 1.3.14 writes with `linker = "isolated"` and
/// `globalStore = true`: `proj/node_modules/{left-pad,is-odd}` link to
/// `.bun/<entry>/node_modules/<name>`, each `.bun/<entry>` links to
/// `<cache>/links/<entry>-<hash>`, and is-odd's entry links `is-number` to
/// its sibling entry. Returns the project dir and the store's `left-pad`
/// and `is-number` dirs.
fn stage(tmp: &Path, bytes: &[u8]) -> (PathBuf, PathBuf, PathBuf) {
    let links = tmp.join("bun-cache").join("links");
    let proj = tmp.join("proj");
    let nm = proj.join("node_modules");
    let bun = nm.join(".bun");
    std::fs::create_dir_all(&bun).unwrap();
    let entry = |name: &str, version: &str, hash: &str| {
        let shared = links.join(format!("{name}@{version}-{hash}"));
        let pkg = shared.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), bytes).unwrap();
        link_dir(&shared, &bun.join(format!("{name}@{version}")));
        pkg
    };
    let left_pad = entry("left-pad", "1.3.0", "6a490709ba3c5c8f");
    let odd = entry("is-odd", "3.0.1", "630ebdaa4b425d00");
    let number = entry("is-number", "6.0.0", "fe514fa0667977a7");
    link_dir(&number, &odd.parent().unwrap().join("is-number"));
    for name in ["left-pad", "is-odd"] {
        let version = if name == "left-pad" { "1.3.0" } else { "3.0.1" };
        link_dir(
            &bun.join(format!("{name}@{version}"))
                .join("node_modules")
                .join(name),
            &nm.join(name),
        );
    }
    std::fs::write(
        proj.join("package.json"),
        r#"{ "name": "p", "version": "1.0.0", "dependencies": { "left-pad": "1.3.0", "is-odd": "3.0.1" } }"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("bunfig.toml"),
        "[install]\nlinker = \"isolated\"\nglobalStore = true\n",
    )
    .unwrap();
    (proj, left_pad, number)
}

fn write_manifest(root: &Path, purls: &[&str]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    for bytes in [BEFORE, AFTER] {
        std::fs::write(socket.join("blobs").join(git_sha256(bytes)), bytes).unwrap();
    }
    let patches: serde_json::Map<String, Value> = purls
        .iter()
        .enumerate()
        .map(|(i, purl)| {
            let patch = json!({
                "uuid": format!("63563563-0000-4000-8000-00000000000{i}"),
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": git_sha256(BEFORE),
                    "afterHash": git_sha256(AFTER),
                }},
                "vulnerabilities": {},
                "description": "bun global store fixture",
                "license": "MIT",
                "tier": "free"
            });
            (purl.to_string(), patch)
        })
        .collect();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}

/// `purl`'s entry in an apply envelope's `events` or a rollback
/// envelope's `results`.
fn event<'a>(v: &'a Value, purl: &str) -> &'a Value {
    v["events"]
        .as_array()
        .or_else(|| v["results"].as_array())
        .expect("events or results array")
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("no event for {purl}: {v}"))
}

fn run(proj: &Path, command: &str) -> Value {
    let (code, stdout, stderr) = run_with_env(
        proj,
        &[command, "--offline", "--json"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    let v = parse_json_envelope(&stdout);
    assert_ne!(
        code, 0,
        "a shared-store refusal fails the {command}; {v}\n{stderr}"
    );
    v
}

fn assert_refused(v: &Value, purl: &str) {
    let ev = event(v, purl);
    assert_ne!(ev["errorCode"], "package_not_installed", "{ev}");
    let text = ev.to_string();
    assert!(
        text.contains("shared by other projects") && text.contains("globalStore = false"),
        "the refusal names the shared store and its remedy; {ev}"
    );
}

/// #635: the direct `left-pad` and the transitive `is-number` (reachable
/// only through `.bun`) are both refused as shared, and the store keeps
/// its bytes for the other projects linked to it.
#[test]
fn apply_refuses_bun_global_store_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let (proj, left_pad, number) = stage(tmp.path(), BEFORE);
    write_manifest(
        &proj,
        &["pkg:npm/left-pad@1.3.0", "pkg:npm/is-number@6.0.0"],
    );

    let v = run(&proj, "apply");
    assert_eq!(v["status"], "partialFailure", "{v}");
    assert_refused(&v, "pkg:npm/left-pad@1.3.0");
    assert_refused(&v, "pkg:npm/is-number@6.0.0");
    assert_eq!(std::fs::read(left_pad.join("index.js")).unwrap(), BEFORE);
    assert_eq!(std::fs::read(number.join("index.js")).unwrap(), BEFORE);
}

/// #635: a rollback in one project must not restore the original bytes
/// into the shared store, which would unpatch every other project
/// relying on them.
#[test]
fn rollback_refuses_bun_global_store_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let (proj, left_pad, number) = stage(tmp.path(), AFTER);
    write_manifest(
        &proj,
        &["pkg:npm/left-pad@1.3.0", "pkg:npm/is-number@6.0.0"],
    );

    let v = run(&proj, "rollback");
    assert_eq!(v["status"], "partial_failure", "{v}");
    assert_refused(&v, "pkg:npm/left-pad@1.3.0");
    assert_refused(&v, "pkg:npm/is-number@6.0.0");
    assert_eq!(std::fs::read(left_pad.join("index.js")).unwrap(), AFTER);
    assert_eq!(std::fs::read(number.join("index.js")).unwrap(), AFTER);
}
