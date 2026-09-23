//! Regression suite for the npm 12 `allow-remote` hazard of hosted mode.
//!
//! npm 12 changed the `allow-remote` default to `none`: `npm ci` / `npm
//! install` refuse (EALLOWREMOTE) every tarball whose `resolved` origin is
//! not the configured registry — which is exactly what `scan --mode hosted`
//! writes into package-lock.json / npm-shrinkwrap.json. Verified against the
//! real npm 12.0.0 / 12.1.0 (`e2e_redirect_npm_build`'s pinned matrix): the
//! redirected lock fails to install until the project `.npmrc` carries
//! `allow-remote=all`.
//!
//! The hosted run therefore AUTO-CONFIGURES it (the npm twin of the pnpm
//! `trustLockfile` auto-config): it ensures `allow-remote=all` in the project
//! `.npmrc` (created, or one line appended with every other byte kept),
//! records the edit in the redirect ledger (`redirect_npmrc_allow_remote`)
//! so `rollback` removes exactly what it added, respects an explicit other
//! user value, honors `--no-npm-allow-remote-config` /
//! `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG` and `--dry-run`, and ALWAYS warns
//! (`redirect_npm_allow_remote`) with the whole-tree tradeoff — while a
//! project whose npm-family redirect is not in an npm lock stays quiet.
//!
//! Hermetic: wiremock API, the built binary, no npm needed.

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const NAME: &str = "allow-remote-dep";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/allow-remote-dep@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstream==";
const CODE: &str = "redirect_npm_allow_remote";

fn hosted_url() -> String {
    format!(
        "http://patch.test/patch/npm/{NAME}/{VERSION}/22222222-2222-4222-8222-222222222222/{UUID}/{NAME}-{VERSION}.tgz"
    )
}

async fn mock_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "allow-remote fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: {
                "status": "granted",
                "url": hosted_url(),
                "purl": PURL,
                "artifacts": [{
                    "kind": "tarball",
                    "url": hosted_url(),
                    "integrity": { "sha512": PATCHED_SHA512 }
                }],
                "registryOverride": null
            }}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID, "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64),
            }},
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// package.json + an installed copy + a registry-resolved lock under
/// `lock_name` (package-lock.json or npm-shrinkwrap.json).
fn write_npm_project(root: &Path, lock_name: &str) {
    std::fs::write(
        root.join("package.json"),
        format!(r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    let lock = json!({
        "name": "consumer", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": { "name": "consumer", "version": "0.0.0", "dependencies": { NAME: VERSION } },
            format!("node_modules/{NAME}"): {
                "version": VERSION,
                "resolved": format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"),
                "integrity": UPSTREAM_SHA512,
            }
        }
    });
    std::fs::write(
        root.join(lock_name),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
}

/// Isolate the child from the developer's / runner's npm config layers:
/// the hosted run respects an explicit `allow-remote` in the env and in the
/// user / global / builtin npm config, so an ambient value would flip what
/// these tests exercise. Empty env values are ignored (by npm and by the
/// resolver); the file layers point at paths that do not exist. Both
/// spellings are pinned because npm matches the prefix case-insensitively.
/// `npm_config_prefix` is pinned too: it outranks `PREFIX`, and the GitHub
/// Windows runner sets it machine-wide (`C:\npm\prefix`). The builtin
/// layer (npm's own `npmrc`, beside the `node` on PATH) has no env
/// relocation in npm, so it stays the machine's; the pinned user / global
/// paths make any `userconfig` / `globalconfig` / `prefix` it sets inert.
fn npm_isolation(root: &Path) -> Vec<(String, String)> {
    let absent = |name: &str| root.join(name).to_str().unwrap().to_string();
    vec![
        ("NPM_CONFIG_USERCONFIG".into(), absent(".absent-user-npmrc")),
        ("npm_config_userconfig".into(), absent(".absent-user-npmrc")),
        (
            "NPM_CONFIG_GLOBALCONFIG".into(),
            absent(".absent-global-npmrc"),
        ),
        (
            "npm_config_globalconfig".into(),
            absent(".absent-global-npmrc"),
        ),
        ("NPM_CONFIG_PREFIX".into(), absent(".absent-prefix")),
        ("npm_config_prefix".into(), absent(".absent-prefix")),
        ("PREFIX".into(), absent(".absent-prefix")),
        ("NPM_CONFIG_ALLOW_REMOTE".into(), String::new()),
        ("npm_config_allow_remote".into(), String::new()),
    ]
}

/// Run the binary with [`npm_isolation`] plus `env` (which lands last).
fn run_isolated(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut all = npm_isolation(cwd);
    all.extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let refs: Vec<(&str, &str)> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    common::run_with_env(cwd, args, &refs)
}

fn scan_hosted(cwd: &Path, api: &str, extra: &[&str]) -> (i32, Value, String) {
    scan_hosted_env(cwd, api, extra, &[])
}

fn scan_hosted_env(
    cwd: &Path,
    api: &str,
    extra: &[&str],
    env: &[(&str, &str)],
) -> (i32, Value, String) {
    let cwd_s = cwd.to_str().unwrap().to_string();
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        &cwd_s,
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_isolated(cwd, &args, env);
    let doc = if args.contains(&"--json") {
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"))
    } else {
        Value::Null
    };
    (code, doc, stderr)
}

fn allow_remote_warning(doc: &Value) -> Option<&str> {
    doc["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == CODE)
        .and_then(|w| w["detail"].as_str())
}

/// The recorded `.npmrc` ledger edits (`(action, key, new)`).
fn npmrc_edits(root: &Path) -> Vec<(String, String, String)> {
    let Ok(text) = std::fs::read_to_string(root.join(".socket/vendor/redirect-state.json")) else {
        return Vec::new();
    };
    let ledger: Value = serde_json::from_str(&text).unwrap();
    ledger["edits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["kind"] == "redirect_npmrc_allow_remote")
        .map(|e| {
            assert_eq!(e["path"], ".npmrc", "{e}");
            (
                e["action"].as_str().unwrap().to_string(),
                e["key"].as_str().unwrap().to_string(),
                e["new"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn rollback(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let cwd_s = cwd.to_str().unwrap().to_string();
    let mut args = vec!["rollback", "--json", "--cwd", &cwd_s];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_isolated(cwd, &args, &[]);
    let doc = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
    (code, doc)
}

/// A package-lock.json redirect CREATES `.npmrc` with exactly
/// `allow-remote=all`, records a `created` ledger edit, and warns (JSON +
/// human) with the npm 12 failure, the whole-tree tradeoff and the opt-out;
/// the idempotent re-run records nothing new and still warns (the
/// already-set variant); `rollback` deletes the file it created and
/// restores the lock.
#[tokio::test]
async fn package_lock_redirect_writes_npmrc_warns_and_rollback_removes_it() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let pristine = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
    for needle in [
        "patch.test",
        "npm >=12",
        "EALLOWREMOTE",
        "`allow-remote=all` was written to a new project .npmrc",
        "lets npm install ANY url-resolved",
        "sha512 integrity pins are still enforced",
        "--no-npm-allow-remote-config",
    ] {
        assert!(detail.contains(needle), "{needle:?} missing: {detail}");
    }
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        "allow-remote=all\n"
    );
    assert_eq!(
        npmrc_edits(tmp.path()),
        vec![("created".into(), "allow-remote".into(), "all".into())]
    );
    // The `.npmrc` write rides the hosted run's lock window: the lock is
    // released (unlinked) when the run ends.
    assert!(
        !tmp.path().join(".socket/apply.lock").exists(),
        "the apply lock never outlives the hosted run"
    );

    // Re-run: nothing to splice, nothing new recorded — still warns.
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("re-run: {doc:#}"));
    assert!(
        detail.contains("already sets `allow-remote=all`"),
        "{detail}"
    );
    assert_eq!(npmrc_edits(tmp.path()).len(), 1, "no duplicate ledger edit");

    // Human output: the `Warning (<code>): …` line on stderr; --silent mutes it.
    let (code, _, stderr) = scan_hosted(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(&format!("Warning ({CODE}): ")) && stderr.contains("EALLOWREMOTE"),
        "human stderr: {stderr}"
    );
    let (code, _, stderr) = scan_hosted(tmp.path(), &server.uri(), &["--silent"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains(CODE), "--silent is errors only: {stderr}");

    // Rollback: the created .npmrc is deleted with the lock redirect.
    let (code, doc) = rollback(tmp.path(), &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert!(!tmp.path().join(".npmrc").exists(), "{doc:#}");
    // (The npm writer normalizes the trailing newline; compare the JSON.)
    let json = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
    assert_eq!(
        json(&std::fs::read(tmp.path().join("package-lock.json")).unwrap()),
        json(&pristine)
    );
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
    assert!(
        !tmp.path().join(".socket").exists(),
        "a fully unwound hosted project keeps no .socket/ residue: {doc:#}"
    );
}

/// An existing `.npmrc` (BOM + CRLF, no allow-remote) gets exactly one
/// appended line in its own line ending; a user edit made AFTER the scan
/// survives rollback, which removes only the appended line. The shrinkwrap
/// flavor is configured the same way.
#[tokio::test]
async fn existing_npmrc_gets_one_line_and_rollback_keeps_user_edits() {
    let server = MockServer::start().await;
    mock_api(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "npm-shrinkwrap.json");
    let user = "\u{feff}registry=https://r.example/\r\n; team config\r\n";
    std::fs::write(tmp.path().join(".npmrc"), user).unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
    assert!(
        detail.contains("was appended to the existing project .npmrc"),
        "{detail}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        format!("{user}allow-remote=all\r\n")
    );
    assert_eq!(
        npmrc_edits(tmp.path()),
        vec![("added".into(), "allow-remote".into(), "all".into())]
    );

    // The user keeps editing the file after the scan.
    let mut live = std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap();
    live.push_str("fund=false\r\n");
    std::fs::write(tmp.path().join(".npmrc"), &live).unwrap();

    let (code, doc) = rollback(tmp.path(), &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        format!("{user}fund=false\r\n"),
        "only the appended line is removed"
    );
    // The reversal prunes the emptied `.socket/` — never the user's
    // `.npmrc`, which lives outside it and keeps their settings.
    assert!(
        !tmp.path().join(".socket").exists(),
        "a fully unwound hosted project keeps no .socket/ residue: {doc:#}"
    );
}

/// An explicit other value (`none` / `root`) is RESPECTED — never rewritten,
/// no ledger edit — and named with the manual remedy; an `allow_remote`
/// spelling npm does not honor in `.npmrc` is left alone and the real key
/// appended; an existing `allow-remote=all` is kept (already-set warning).
#[tokio::test]
async fn explicit_values_are_respected_and_unhonored_spellings_are_not_trusted() {
    let server = MockServer::start().await;
    mock_api(&server).await;

    for value in ["root", "none"] {
        let tmp = tempfile::tempdir().unwrap();
        write_npm_project(tmp.path(), "package-lock.json");
        let npmrc = format!("allow-remote=all\nallow-remote={value}\n");
        std::fs::write(tmp.path().join(".npmrc"), &npmrc).unwrap();
        let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
        assert_eq!(code, 0, "{doc:#}");
        let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
        assert!(
            detail.contains(&format!("explicitly sets `allow-remote={value}`"))
                && detail.contains("npm ci --allow-remote=all"),
            "{detail}"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
            npmrc,
            "an explicit user setting is never rewritten"
        );
        assert!(npmrc_edits(tmp.path()).is_empty());
    }

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    std::fs::write(tmp.path().join(".npmrc"), "allow_remote=all\n").unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        "allow_remote=all\nallow-remote=all\n",
        "npm 12 ignores `allow_remote` in .npmrc: the real key is appended"
    );

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    std::fs::write(tmp.path().join(".npmrc"), "allow-remote = \"all\"\n").unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    assert!(
        allow_remote_warning(&doc).is_some_and(|d| d.contains("already sets `allow-remote=all`"))
    );
    assert!(npmrc_edits(tmp.path()).is_empty());
    // A user-owned setting survives rollback untouched.
    let (code, doc) = rollback(tmp.path(), &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        "allow-remote = \"all\"\n"
    );
}

/// `--no-npm-allow-remote-config` (and its env var) writes nothing and
/// warns with both manual recoveries; `--dry-run` writes nothing but says
/// what it WOULD write; a project with no npm lock stays quiet.
#[tokio::test]
async fn opt_out_dry_run_and_unredirected_projects() {
    let server = MockServer::start().await;
    mock_api(&server).await;

    for (flags, env) in [
        (vec!["--json", "--no-npm-allow-remote-config"], vec![]),
        (
            vec!["--json"],
            vec![("SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG", "1")],
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_npm_project(tmp.path(), "package-lock.json");
        let cwd_s = tmp.path().to_str().unwrap().to_string();
        let uri = server.uri();
        let mut args = vec![
            "scan",
            "--mode",
            "hosted",
            "--yes",
            "--cwd",
            &cwd_s,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ];
        args.extend(flags.iter().copied());
        let (code, stdout, stderr) = run_isolated(tmp.path(), &args, &env);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        let doc: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
        let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
        assert!(
            detail.contains("Commit `allow-remote=all` in the project .npmrc")
                && detail.contains("npm ci --allow-remote=all"),
            "{detail}"
        );
        assert!(
            !tmp.path().join(".npmrc").exists(),
            "opt-out writes nothing"
        );
        assert!(npmrc_edits(tmp.path()).is_empty());
    }

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json", "--dry-run"]);
    assert_eq!(code, 0, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("dry run: {doc:#}"));
    assert!(
        detail.contains("would be written to a new project .npmrc")
            && !detail.contains("(--dry-run)"),
        "{detail}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        before,
        "dry run leaves the lock untouched"
    );
    assert!(
        !tmp.path().join(".npmrc").exists(),
        "dry run writes no .npmrc"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a dry run never locks, so it creates no .socket/ either"
    );

    let nolock = tempfile::tempdir().unwrap();
    write_npm_project(nolock.path(), "package-lock.json");
    std::fs::remove_file(nolock.path().join("package-lock.json")).unwrap();
    let (_, doc, _) = scan_hosted(nolock.path(), &server.uri(), &["--json"]);
    assert_eq!(allow_remote_warning(&doc), None, "{doc:#}");
    assert!(!nolock.path().join(".npmrc").exists());
}

/// A symlinked `.npmrc` is never written through (nor does it trip the
/// whole-run symlink guard): the redirect lands, the link is untouched, and
/// the warning names the manual remedy.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_npmrc_is_left_alone() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    std::fs::write(tmp.path().join("shared.npmrc"), "fund=false\n").unwrap();
    std::os::unix::fs::symlink("shared.npmrc", tmp.path().join(".npmrc")).unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
    assert!(detail.contains("symbolic link") && detail.contains("npm ci --allow-remote=all"));
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("shared.npmrc")).unwrap(),
        "fund=false\n"
    );
    assert!(npmrc_edits(tmp.path()).is_empty());
}

/// Review findings, end to end:
/// - a CR-only `.npmrc` with an explicit `allow-remote=none` (npm splits on
///   a bare `\r`) is respected, never flipped by an appended line;
/// - an indented `[sec]` is NOT a section header to npm, so the `none`
///   below it is respected (writing above it would not have taken effect);
/// - a CR-only file without the key is never spliced (manual remedy);
/// - a section-scoped `allow-remote=all` (inert to npm) gets our top-level
///   line, and rollback removes exactly ours instead of refusing the two
///   copies as ambiguous.
#[tokio::test]
async fn npm_ini_line_and_section_rules_are_honored() {
    let server = MockServer::start().await;
    mock_api(&server).await;

    for npmrc in [
        "registry=https://r.example/\rallow-remote=none\r",
        "  [sec]\nallow-remote=none\n",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_npm_project(tmp.path(), "package-lock.json");
        std::fs::write(tmp.path().join(".npmrc"), npmrc).unwrap();
        let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
        assert_eq!(code, 0, "{doc:#}");
        let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
        assert!(
            detail.contains("explicitly sets `allow-remote=none`"),
            "{npmrc:?}: {detail}"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
            npmrc,
            "an explicit value is never flipped"
        );
        assert!(npmrc_edits(tmp.path()).is_empty());
    }

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let cr_only = "registry=https://r.example/\rfund=false\r";
    std::fs::write(tmp.path().join(".npmrc"), cr_only).unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
    assert!(
        detail.contains("bare carriage-return") && detail.contains("npm ci --allow-remote=all"),
        "{detail}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        cr_only
    );
    assert!(npmrc_edits(tmp.path()).is_empty());

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let sectioned = "[sec]\nallow-remote=all\n";
    std::fs::write(tmp.path().join(".npmrc"), sectioned).unwrap();
    let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        format!("allow-remote=all\n{sectioned}")
    );
    let (code, doc) = rollback(tmp.path(), &[]);
    assert_eq!(
        code, 0,
        "the section copy must not make the unwind ambiguous: {doc:#}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        sectioned
    );
}

/// Review finding: only the project `.npmrc` was consulted. An explicit
/// `allow-remote` in the env (which beats the project file) or in the
/// user / global npm config (a machine / org policy a committed project
/// line would silently override) is now respected — nothing written, no
/// ledger edit — and the warning names the source and the remedy.
#[tokio::test]
async fn outer_npm_config_layers_are_respected() {
    let server = MockServer::start().await;
    mock_api(&server).await;

    // user config (relocated the way npm allows: NPM_CONFIG_USERCONFIG).
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let user = cfg.path().join("user.npmrc");
    std::fs::write(&user, "allow-remote=none\n").unwrap();
    let user_s = user.to_str().unwrap();
    let (code, doc, _) = scan_hosted_env(
        tmp.path(),
        &server.uri(),
        &["--json"],
        &[
            ("NPM_CONFIG_USERCONFIG", user_s),
            ("npm_config_userconfig", user_s),
        ],
    );
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
    assert!(
        detail.contains("The user npm config")
            && detail.contains(user_s)
            && detail.contains("explicitly sets `allow-remote=none`")
            && detail.contains("npm ci --allow-remote=all"),
        "{detail}"
    );
    assert!(
        !tmp.path().join(".npmrc").exists(),
        "no project override written"
    );
    assert!(npmrc_edits(tmp.path()).is_empty());

    // global config under <prefix>/etc/npmrc, the prefix relocated the
    // way npm allows from the env (`npm_config_prefix` — it outranks the
    // builtin config's `prefix`, e.g. the Windows installer's
    // `${APPDATA}\npm`, and `PREFIX`, the default-only fallback the core
    // unit tests pin).
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let prefix = cfg.path().join("prefix");
    std::fs::create_dir_all(prefix.join("etc")).unwrap();
    std::fs::write(prefix.join("etc").join("npmrc"), "allow-remote=root\n").unwrap();
    let prefix_s = prefix.to_str().unwrap();
    let (code, doc, _) = scan_hosted_env(
        tmp.path(),
        &server.uri(),
        &["--json"],
        &[
            ("NPM_CONFIG_PREFIX", prefix_s),
            ("npm_config_prefix", prefix_s),
            ("NPM_CONFIG_GLOBALCONFIG", ""),
            ("npm_config_globalconfig", ""),
        ],
    );
    assert_eq!(code, 0, "{doc:#}");
    let detail = allow_remote_warning(&doc).unwrap_or_else(|| panic!("no {CODE}: {doc:#}"));
    assert!(
        detail.contains("The global npm config") && detail.contains("allow-remote=root"),
        "{detail}"
    );
    assert!(!tmp.path().join(".npmrc").exists());

    // env beats every file — even an already-configured project.
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    let (code, _, stderr) = scan_hosted_env(
        tmp.path(),
        &server.uri(),
        &[],
        &[("npm_config_allow_remote", "none")],
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(&format!("Warning ({CODE}): "))
            && stderr.contains("npm_config_allow_remote=none")
            && stderr.contains("would not take effect"),
        "{stderr}"
    );
    assert!(!tmp.path().join(".npmrc").exists());

    // An outer `all` never blocks the write.
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), "package-lock.json");
    std::fs::write(&user, "allow-remote=all\n").unwrap();
    let (code, doc, _) = scan_hosted_env(
        tmp.path(),
        &server.uri(),
        &["--json"],
        &[
            ("NPM_CONFIG_USERCONFIG", user_s),
            ("npm_config_userconfig", user_s),
        ],
    );
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
        "allow-remote=all\n"
    );
}

/// Review finding: `remove` dropped the hosted leg's warnings, so a
/// redirect-created `.npmrc` the user had since added to was rewritten
/// with no `redirect_npmrc_allow_remote_modified` (CLI_CONTRACT promises
/// it in rollback/remove `warnings[]`). Human stderr and JSON both carry it.
#[tokio::test]
async fn remove_surfaces_the_npmrc_modified_warning() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    for json in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        write_npm_project(tmp.path(), "package-lock.json");
        let (code, doc, _) = scan_hosted(tmp.path(), &server.uri(), &["--json"]);
        assert_eq!(code, 0, "{doc:#}");
        std::fs::write(tmp.path().join(".npmrc"), "allow-remote=all\nfund=false\n").unwrap();

        let cwd_s = tmp.path().to_str().unwrap().to_string();
        let mut args = vec!["remove", PURL, "--yes", "--cwd", &cwd_s];
        if json {
            args.push("--json");
        }
        let (code, stdout, stderr) = run_isolated(tmp.path(), &args, &[]);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        if json {
            let doc: Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\n{stderr}"));
            assert!(
                doc["warnings"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|w| w["code"] == "redirect_npmrc_allow_remote_modified"),
                "{doc:#}"
            );
            assert!(
                !stderr.contains("Warning ("),
                "--json keeps stderr quiet: {stderr}"
            );
        } else {
            assert!(
                stderr.contains("Warning (redirect_npmrc_allow_remote_modified): "),
                "{stderr}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".npmrc")).unwrap(),
            "fund=false\n"
        );
    }
}
