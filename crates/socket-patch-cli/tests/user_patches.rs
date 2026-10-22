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
fn apply_skips_and_vendor_refuses_declared_patches_despite_matching_hashes_or_general_confirmation()
{
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
            // apply leaves the package out with a warning and succeeds (a
            // postinstall apply must not fail every install); vendor, an
            // explicit vendoring of the whole manifest, refuses.
            let message = if args[0] == "apply" {
                assert_eq!(code, 0, "{args:?} {file}: {stdout} {stderr}");
                let skip = value["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|event| event["action"] == "skipped" && event["purl"] == PURL)
                    .unwrap_or_else(|| panic!("missing skipped event: {value}"));
                assert_eq!(skip["errorCode"], "user_patch_conflict");
                assert_eq!(skip["uuid"], UUID);
                assert!(skip["reason"].as_str().unwrap().contains(file));
                assert_eq!(value["summary"]["applied"], 0);
                assert_eq!(value["summary"]["skipped"], 1);
                let warning = value["warnings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|w| w["code"] == "user_patch_conflict")
                    .unwrap_or_else(|| panic!("{args:?} {file}: {value}"));
                warning["detail"].as_str().unwrap().to_string()
            } else {
                assert_eq!(code, 1, "{args:?} {file}: {stdout} {stderr}");
                assert_eq!(value["error"]["code"], "user_patch_conflict", "{value}");
                value["error"]["message"].as_str().unwrap().to_string()
            };
            assert!(message.contains("--allow-patch-conflicts"), "{message}");
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
        &["apply", "--json", "--offline", "--allow-patch-conflicts"],
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
        vec!["--allow-patch-conflicts", "--strict"],
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
        &[("SOCKET_ALLOW_PATCH_CONFLICTS", "1")],
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("user_patch_conflict"));
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
        BEFORE,
        "the environment grants no consent"
    );
    let (_, stdout, _) = run_with_env(
        tmp.path(),
        &["apply", "--json", "--offline", "--check"],
        &[],
    );
    assert!(!stdout.contains("user_patch_conflict"), "{stdout}");
    // The drift names the project patch, and the remedy names the consent
    // that clears it: a plain `apply` leaves the package untouched.
    assert!(stdout.contains("patches/example+1.0.0.patch"), "{stdout}");
    let (code, _, stderr) = run_with_env(tmp.path(), &["apply", "--offline", "--check"], &[]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("--allow-patch-conflicts"), "{stderr}");
}

#[test]
fn apply_skips_only_the_protected_package() {
    let tmp = fixture();
    write(tmp.path(), "patches/example+1.0.0.patch", b"user diff\n");
    write(
        tmp.path(),
        "node_modules/other/package.json",
        r#"{"name":"other","version":"2.0.0"}"#,
    );
    write(tmp.path(), "node_modules/other/index.js", BEFORE);
    let manifest_path = tmp.path().join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let mut other = manifest["patches"][PURL].clone();
    other["uuid"] = "22222222-2222-4222-8222-222222222222".into();
    manifest["patches"]["pkg:npm/other@2.0.0"] = other;
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    let original = std::fs::read(&manifest_path).unwrap();

    let (code, stdout, stderr) = run_with_env(tmp.path(), &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "{stdout} {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let conflicts: Vec<_> = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["code"] == "user_patch_conflict")
        .collect();
    assert_eq!(conflicts.len(), 1, "{value}");
    assert!(conflicts[0]["detail"].as_str().unwrap().contains(PURL));
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
        BEFORE
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/other/index.js")).unwrap(),
        AFTER
    );
    assert_eq!(std::fs::read(&manifest_path).unwrap(), original);
}

#[test]
fn default_apply_replaces_an_earlier_socket_patch_but_not_a_local_edit() {
    // After an update to a newer patch for the same release, the file holds
    // the old patch's output, whose blob Socket stored: not a local change.
    let previous: &[u8] = b"older Socket fix\n";
    let tmp = fixture();
    write_blob(&tmp.path().join(".socket"), &git_sha256(previous), previous);
    write(tmp.path(), "node_modules/example/index.js", previous);
    let (code, stdout, stderr) = run_with_env(tmp.path(), &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "{stdout} {stderr}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
        AFTER
    );

    // --strict still refuses it.
    write(tmp.path(), "node_modules/example/index.js", previous);
    let (code, stdout, stderr) = run_with_env(
        tmp.path(),
        &["apply", "--json", "--offline", "--strict"],
        &[],
    );
    assert_eq!(code, 1, "{stdout} {stderr}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
        previous
    );
}
