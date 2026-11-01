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

use serde_json::Value;

use super::apply_fixture::{index_js_patches, link_dir, stage_blob, write_manifest};
use crate::common::envelope::event_for;
use crate::common::{git_sha256, parse_json_envelope, run_with_env};

const BEFORE: &[u8] = b"module.exports = 'pristine';\n";
const AFTER: &[u8] = b"module.exports = 'patched';\n";

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

fn write_patches(root: &Path, purls: &[&str]) {
    write_manifest(root, index_js_patches(purls, "63563563", BEFORE, AFTER));
    for bytes in [BEFORE, AFTER] {
        stage_blob(root, &git_sha256(bytes), bytes);
    }
}

fn run(proj: &Path, command: &str) -> Value {
    let (code, stdout, stderr) = run_with_env(proj, &[command, "--offline", "--json"], &[]);
    let v = parse_json_envelope(&stdout);
    assert_ne!(
        code, 0,
        "a shared-store refusal fails the {command}; {v}\n{stderr}"
    );
    v
}

fn assert_refused(v: &Value, purl: &str) {
    let ev = event_for(v, purl);
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
    write_patches(
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
    write_patches(
        &proj,
        &["pkg:npm/left-pad@1.3.0", "pkg:npm/is-number@6.0.0"],
    );

    let v = run(&proj, "rollback");
    // Both refused and nothing rolled back: the run failed as a whole.
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["error"]["code"], "rollback_failed", "{v}");
    assert_eq!(v["summary"]["failed"], 2, "{v}");
    assert_refused(&v, "pkg:npm/left-pad@1.3.0");
    assert_refused(&v, "pkg:npm/is-number@6.0.0");
    assert_eq!(std::fs::read(left_pad.join("index.js")).unwrap(), AFTER);
    assert_eq!(std::fs::read(number.join("index.js")).unwrap(), AFTER);
}

/// #635: the human-mode Bun note must not promise that copy-on-write
/// keeps the install cache untouched when the installed packages ARE the
/// cache's shared `links` dirs; it says they are refused and how to fix.
#[test]
fn apply_note_names_the_bun_global_store() {
    let tmp = tempfile::tempdir().unwrap();
    let (proj, left_pad, _) = stage(tmp.path(), BEFORE);
    std::fs::write(proj.join("bun.lock"), "{}\n").unwrap();
    write_patches(&proj, &["pkg:npm/left-pad@1.3.0"]);

    let (code, _stdout, stderr) = run_with_env(&proj, &["apply", "--offline"], &[]);
    assert_ne!(
        code, 0,
        "the shared-store refusal fails the apply; {stderr}"
    );
    assert!(
        stderr.contains("Note: bun global store detected")
            && stderr.contains("globalStore = false"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("will keep ~/.bun/install/cache/ untouched"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(left_pad.join("index.js")).unwrap(), BEFORE);
}
