//! Consent is checked at package level, even when the Socket fix touches
//! a different file and beforeHash verification would succeed.
mod common;

use common::{git_sha256, run_with_env, write_blob, write_minimal_manifest, PatchEntry};
use std::path::Path;

const PURL: &str = "pkg:npm/example@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const BEFORE: &[u8] = b"original\n";
const AFTER: &[u8] = b"Socket fix\n";

fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "package.json", "{}");
    write(
        tmp.path(),
        "node_modules/example/package.json",
        r#"{"name":"example","version":"1.0.0"}"#,
    );
    write(tmp.path(), "node_modules/example/index.js", BEFORE);
    write(tmp.path(), "node_modules/example/user.js", b"user fix\n");
    let socket = tmp.path().join(".socket");
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "index.js",
            before_hash: &git_sha256(BEFORE),
            after_hash: &git_sha256(AFTER),
        }],
    );
    write_blob(&socket, &git_sha256(AFTER), AFTER);
    tmp
}

#[test]
fn apply_and_vendor_refuse_declared_patches_despite_matching_hashes_or_general_confirmation() {
    for (file, contents) in [
        (
            "package.json",
            r#"{"pnpm":{"patchedDependencies":{"example@1.0.0":"patches/fix.patch"}}}"#,
        ),
        (
            "pnpm-workspace.yaml",
            "patchedDependencies:\n  example@1.0.0: missing.patch\n",
        ),
        (
            "package.json",
            r#"{"resolutions":{"example":"patch:example@npm%3A1.0.0#./fix.patch"}}"#,
        ),
        ("patches/example+1.0.0.patch", "diff for a different file"),
        (
            "package.json",
            r#"{"patchedDependencies":{"example@1.0.0":"patches/fix.patch"}}"#,
        ),
    ] {
        for args in [
            vec!["apply", "--json", "--offline", "--yes"],
            vec!["apply", "--json", "--offline", "--force"],
            vec!["apply", "--json", "--offline", "--dry-run"],
            vec!["vendor", "--json", "--offline", "--force"],
        ] {
            let tmp = fixture();
            write(tmp.path(), file, contents);
            let original = std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap();
            let (code, stdout, stderr) = run_with_env(tmp.path(), &args, &[]);
            let value: serde_json::Value = serde_json::from_str(&stdout).expect(&stdout);
            assert_eq!(code, 1, "{args:?} {file}: {stdout} {stderr}");
            assert_eq!(value["error"]["code"], "user_patch_conflict", "{value}");
            assert!(value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--allow-user-patches"));
            assert_eq!(
                std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
                BEFORE
            );
            assert_eq!(
                std::fs::read(tmp.path().join(file)).unwrap(),
                contents.as_bytes()
            );
            assert_eq!(
                std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
                original
            );
            assert!(!tmp.path().join(".socket/vendor/state.json").exists());
            assert!(!tmp.path().join(".socket/apply.lock").exists());
        }
    }
}

#[test]
fn consent_allows_agent_application_and_does_not_modify_the_user_patch() {
    let tmp = fixture();
    write(tmp.path(), "patches/example+1.0.0.patch", b"user diff\n");
    let (code, stdout, stderr) = run_with_env(
        tmp.path(),
        &["apply", "--json", "--offline", "--allow-user-patches"],
        &[],
    );
    assert_eq!(code, 0, "{stdout} {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w["code"] == "user_patch_override"));
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
        AFTER
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/user.js")).unwrap(),
        b"user fix\n"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("patches/example+1.0.0.patch")).unwrap(),
        b"user diff\n"
    );
}

#[test]
fn unknown_local_edits_fail_closed_by_default_including_yes_silent_and_dry_run() {
    for extra in [
        vec![],
        vec!["--yes"],
        vec!["--silent"],
        vec!["--dry-run"],
        vec!["--allow-user-patches", "--strict"],
    ] {
        let tmp = fixture();
        write(tmp.path(), "node_modules/example/index.js", b"local edit\n");
        let mut args = vec!["apply", "--json", "--offline"];
        args.extend(extra);
        let (code, stdout, stderr) = run_with_env(tmp.path(), &args, &[]);
        assert_eq!(code, 1, "{args:?}: {stdout} {stderr}");
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
            b"local edit\n"
        );
    }
}

#[test]
fn unrelated_versions_and_ecosystems_are_not_blocked() {
    let tmp = fixture();
    write(
        tmp.path(),
        "patches/example+2.0.0.patch",
        b"different release\n",
    );
    write(
        tmp.path(),
        "composer.json",
        r#"{"extra":{"patches":{"a/b":{"fix":"fix.patch"}}}}"#,
    );
    let (code, stdout, stderr) = run_with_env(
        tmp.path(),
        &["apply", "--json", "--offline", "--ecosystems", "npm"],
        &[],
    );
    assert_eq!(code, 0, "{stdout} {stderr}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
        AFTER
    );
}

#[test]
fn environment_and_read_only_checks_do_not_grant_or_require_consent() {
    let tmp = fixture();
    write(tmp.path(), "patches/example+1.0.0.patch", b"user diff\n");
    let (code, stdout, _) = run_with_env(
        tmp.path(),
        &["apply", "--json", "--offline"],
        &[("SOCKET_ALLOW_USER_PATCHES", "1")],
    );
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("user_patch_conflict"));
    let (_, stdout, _) = run_with_env(
        tmp.path(),
        &["apply", "--json", "--offline", "--check"],
        &[],
    );
    assert!(!stdout.contains("user_patch_conflict"), "{stdout}");
}
