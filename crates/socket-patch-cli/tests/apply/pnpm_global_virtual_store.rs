//! `apply` on a transitive dependency that lives only in pnpm's global
//! virtual store (`enableGlobalVirtualStore`, #362).
//!
//! The store (`<store>/v<N>/links`) is shared by every project on the
//! machine, so agent mode must refuse to patch it, as it already does for
//! a direct dependency linked into it (#486). A transitive dependency has
//! no importer link, so the crawler never found it. Because the project
//! lock resolves it, the miss was then taken for a calm lockfile-only
//! skip: `apply` exited 0 with `success` while Node kept loading the
//! unpatched copy.

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

fn write_pkg(dir: &Path, name: &str, version: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), BEFORE).unwrap();
}

/// The layout pnpm 10.12+ writes with `enableGlobalVirtualStore: true`:
/// `proj/node_modules/is-odd` links to the store entry of `is-odd`, whose
/// own `node_modules` links `is-number` to a sibling entry. Another
/// project's `left-pad` sits in the same store. Returns the project dir,
/// the store's `is-number` and `left-pad` dirs.
fn stage(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let v10 = tmp.join("store").join("v10");
    std::fs::create_dir_all(v10.join("files")).unwrap();
    let links = v10.join("links").join("@");
    let odd_nm = links.join("is-odd/3.0.1/aaa111/node_modules");
    write_pkg(&odd_nm.join("is-odd"), "is-odd", "3.0.1");
    let number = links.join("is-number/6.0.0/bbb222/node_modules/is-number");
    write_pkg(&number, "is-number", "6.0.0");
    link_dir(&number, &odd_nm.join("is-number"));
    let left_pad = links.join("left-pad/1.3.0/ccc333/node_modules/left-pad");
    write_pkg(&left_pad, "left-pad", "1.3.0");

    let proj = tmp.join("proj");
    let nm = proj.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{ "name": "p", "version": "0.0.0", "private": true, "dependencies": { "is-odd": "3.0.1" } }"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      is-odd:\n        \
         specifier: 3.0.1\n        version: 3.0.1\n\npackages:\n\n  is-number@6.0.0:\n    \
         resolution: {integrity: sha512-AAAA}\n\n  is-odd@3.0.1:\n    resolution: {integrity: \
         sha512-BBBB}\n\nsnapshots:\n\n  is-number@6.0.0: {}\n\n  is-odd@3.0.1:\n    \
         dependencies:\n      is-number: 6.0.0\n",
    )
    .unwrap();
    std::fs::write(
        nm.join(".modules.yaml"),
        "layoutVersion: 5\nnodeLinker: isolated\nvirtualStoreDir: ../../store/v10/links\n",
    )
    .unwrap();
    link_dir(&odd_nm.join("is-odd"), &nm.join("is-odd"));
    (proj, number, left_pad)
}

fn write_manifest(root: &Path, purl: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": { purl: {
            "uuid": "36236236-0000-4000-8000-000000000001",
            "exportedAt": "2024-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(BEFORE),
                "afterHash": git_sha256(AFTER),
            }},
            "vulnerabilities": {},
            "description": "pnpm global virtual store fixture",
            "license": "MIT",
            "tier": "free"
        }}}))
        .unwrap(),
    )
    .unwrap();
}

fn event<'a>(v: &'a Value, purl: &str) -> &'a Value {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("no event for {purl}: {v}"))
}

/// #362: the transitive `is-number` is refused as shared, like a direct
/// dependency would be, and the shared copy stays untouched. It is not
/// reported as a lockfile-only skip.
#[test]
fn transitive_global_virtual_store_dep_is_refused_not_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let (proj, number, _) = stage(tmp.path());
    write_manifest(&proj, "pkg:npm/is-number@6.0.0");

    let (code, stdout, stderr) = run_with_env(
        &proj,
        &["apply", "--offline", "--json"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    let v = parse_json_envelope(&stdout);
    assert_ne!(
        code, 0,
        "a shared-store refusal fails the run; {v}\n{stderr}"
    );
    assert_eq!(v["status"], "partialFailure", "{v}");
    let ev = event(&v, "pkg:npm/is-number@6.0.0");
    assert_ne!(ev["errorCode"], "package_not_installed", "{ev}");
    assert!(
        ev.to_string().contains("shared by other projects")
            && ev.to_string().contains("enableGlobalVirtualStore"),
        "the refusal names the shared store and its remedy; {ev}"
    );
    assert_eq!(std::fs::read(number.join("index.js")).unwrap(), BEFORE);
}

/// The walk covers only what this project reaches: a package another
/// project installed into the same store is still "not installed" here.
#[test]
fn other_projects_global_virtual_store_entries_stay_invisible() {
    let tmp = tempfile::tempdir().unwrap();
    let (proj, _, left_pad) = stage(tmp.path());
    write_manifest(&proj, "pkg:npm/left-pad@1.3.0");

    let (code, stdout, stderr) = run_with_env(
        &proj,
        &["apply", "--offline", "--json"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    let v = parse_json_envelope(&stdout);
    assert_ne!(code, 0, "{v}\n{stderr}");
    let ev = event(&v, "pkg:npm/left-pad@1.3.0");
    assert_eq!(ev["errorCode"], "package_not_installed", "{ev}");
    assert_eq!(std::fs::read(left_pad.join("index.js")).unwrap(), BEFORE);
}

/// A pnpm workspace (#362, review on #829): pnpm writes `.modules.yaml`
/// only at the workspace root, and a member's `node_modules` holds just
/// its own links into the store. The member's transitive `is-number` is
/// refused as shared too, not reported as a lockfile-only skip.
#[test]
fn workspace_member_transitive_global_virtual_store_dep_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (proj, number, _) = stage(tmp.path());
    // Move the direct link from the root to member `packages/a`.
    let root_nm = proj.join("node_modules");
    let odd = std::fs::canonicalize(root_nm.join("is-odd")).unwrap();
    #[cfg(unix)]
    std::fs::remove_file(root_nm.join("is-odd")).unwrap();
    #[cfg(windows)]
    std::fs::remove_dir(root_nm.join("is-odd")).unwrap();
    std::fs::create_dir_all(root_nm.join(".pnpm").join("node_modules")).unwrap();
    std::fs::write(
        proj.join("pnpm-workspace.yaml"),
        "packages:\n  - packages/*\n",
    )
    .unwrap();
    let member = proj.join("packages").join("a");
    let member_nm = member.join("node_modules");
    std::fs::create_dir_all(&member_nm).unwrap();
    std::fs::write(
        member.join("package.json"),
        r#"{ "name": "a", "version": "0.0.0", "dependencies": { "is-odd": "3.0.1" } }"#,
    )
    .unwrap();
    link_dir(&odd, &member_nm.join("is-odd"));
    write_manifest(&proj, "pkg:npm/is-number@6.0.0");

    let (code, stdout, stderr) = run_with_env(
        &proj,
        &["apply", "--offline", "--json"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    let v = parse_json_envelope(&stdout);
    assert_ne!(code, 0, "{v}\n{stderr}");
    let ev = event(&v, "pkg:npm/is-number@6.0.0");
    assert_ne!(ev["errorCode"], "package_not_installed", "{ev}");
    assert!(ev.to_string().contains("enableGlobalVirtualStore"), "{ev}");
    assert_eq!(std::fs::read(number.join("index.js")).unwrap(), BEFORE);
}
