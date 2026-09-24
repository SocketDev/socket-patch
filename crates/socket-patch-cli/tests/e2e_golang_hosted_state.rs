#![cfg(unix)]
//! Hosted golang redirects must claim (and attest) exactly what the
//! committed go.mod/go.sum enforce, and a vendored→hosted mode switch must
//! leave the project fully hosted.
//!
//! Drives the real binary (`get <uuid> --mode hosted`) against a wiremock
//! patch API. No go toolchain is needed: every assertion is on the files
//! the CLI writes and on its JSON envelope.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UPURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const UUID_H: &str = "55555555-5555-4555-8555-555555555555";
const UUID_V: &str = "3c4d5e6f-7081-4a1b-8c2d-0123456789ab";
const SVER: &str = "v1.0.0-socketpatch.1";
const ZIP_H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
const GOMOD_H1: &str = "h1:XgagPTRZSCprrzR+3Ro36/XJpibdovhAbsKThYI8bxg=";
const UPSTREAM_SUM: &str = "example.com/upstream v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
                            example.com/upstream v1.0.0/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";
/// The goproxy override's `indexUrl` is the bare patch-server origin.
const INDEX_URL: &str = "https://patch.socket.dev";

fn smod() -> String {
    format!("patch.socket.dev/gopatch/{UUID_H}")
}

async fn mount_hosted_grant(server: &MockServer) {
    let artifact_url = format!("{INDEX_URL}/{}/@v/{SVER}.zip", smod());
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID_H}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_H,
            "purl": UPURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "lib.go": {
                "beforeHash": compute_git_sha256_from_bytes(PRISTINE_LIB.as_bytes()),
                "afterHash": compute_git_sha256_from_bytes(PATCHED_LIB.as_bytes()),
            }},
            "vulnerabilities": { "GHSA-gogo-host-stat": {
                "cves": ["CVE-2026-4243"], "summary": "s", "severity": "high", "description": "d",
            }},
            "description": "golang hosted state fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID_H: {
                "status": "granted",
                "url": &artifact_url,
                "purl": UPURL,
                "artifacts": [{ "kind": "tarball", "url": &artifact_url, "integrity": {} }],
                "registryOverride": {
                    "kind": "goproxy",
                    "indexUrl": INDEX_URL,
                    "identifiers": {
                        "name": UMOD,
                        "version": UVER,
                        "goModulePath": smod(),
                        "goModuleVersion": SVER,
                        "goZipDirhashH1": ZIP_H1,
                        "goModH1": GOMOD_H1,
                    }
                }
            }}
        })))
        .mount(server)
        .await;
}

fn get_hosted(consumer: &Path, server: &MockServer, modcache: &Path) -> serde_json::Value {
    let (code, stdout, stderr) = common::run_with_env(
        consumer,
        &[
            "get",
            UUID_H,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            consumer.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "get --mode hosted failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}"))
}

fn write_consumer(consumer: &Path, go_mod_tail: &str, go_sum: &str) {
    std::fs::create_dir_all(consumer).unwrap();
    std::fs::write(
        consumer.join("go.mod"),
        format!("module example.com/consumer\n\ngo 1.21\n\n{go_mod_tail}"),
    )
    .unwrap();
    std::fs::write(consumer.join("go.sum"), go_sum).unwrap();
}

/// A polyglot repo whose npm lock is already hosted-redirected contains the
/// bare patch-server origin. A golang dep whose go.mod rewrite was REFUSED
/// must not be confirmed by that unrelated text: nothing redirects it, so it
/// must not be counted, recorded in the redirect ledger, or attested by VEX.
#[tokio::test(flavor = "multi_thread")]
async fn refused_go_rewrite_is_not_confirmed_by_another_lockfile() {
    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    write_consumer(
        &consumer,
        &format!("require {UMOD} {UVER}\n\nreplace {UMOD} {UVER} => ../my-fork\n"),
        UPSTREAM_SUM,
    );
    std::fs::write(
        consumer.join("package-lock.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "consumer",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "consumer", "dependencies": { "left-pad": "1.3.0" } },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": format!("{INDEX_URL}/patch-registry/npm/left-pad/-/left-pad-1.3.0.tgz"),
                    "integrity": "sha512-AAAA",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let server = MockServer::start().await;
    mount_hosted_grant(&server).await;

    let env = get_hosted(&consumer, &server, &tmp.path().join("modcache"));
    assert_eq!(env["redirect"]["redirected"], 0, "envelope: {env}");
    assert!(
        env["redirect"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "redirect_golang_replace_conflict"),
        "the refusal is reported: {env}"
    );
    let ledger = std::fs::read_to_string(consumer.join(".socket/vendor/redirect-state.json"))
        .unwrap_or_default();
    assert!(
        !ledger.contains(UPURL),
        "no redirect record for the refused module: {ledger}"
    );
}

/// go.sum lines for the socket module outlive a hand-removed replace. When
/// the rewrite is refused (the graph moved to another version), those
/// leftover lines pin nothing and must not confirm the dep.
#[tokio::test(flavor = "multi_thread")]
async fn leftover_go_sum_lines_do_not_confirm_a_refused_rewrite() {
    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    write_consumer(
        &consumer,
        &format!("require {UMOD} v1.1.0\n"),
        &format!(
            "{UMOD} v1.1.0 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n\
             {UMOD} v1.1.0/go.mod h1:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\n\
             {} {SVER} {ZIP_H1}\n{} {SVER}/go.mod {GOMOD_H1}\n",
            smod(),
            smod()
        ),
    );
    let server = MockServer::start().await;
    mount_hosted_grant(&server).await;

    let env = get_hosted(&consumer, &server, &tmp.path().join("modcache"));
    assert_eq!(env["redirect"]["redirected"], 0, "envelope: {env}");
    assert!(
        env["redirect"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "redirect_golang_version_mismatch"),
        "{env}"
    );
    let ledger = std::fs::read_to_string(consumer.join(".socket/vendor/redirect-state.json"))
        .unwrap_or_default();
    assert!(!ledger.contains(UPURL), "{ledger}");
}

/// vendored → hosted takeover: the hosted run must revert the vendored
/// state (ledger entry, committed copy, marker) before redirecting, so the
/// project is fully hosted — never a hosted go.mod beside a vendor ledger
/// that still claims the module.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_takeover_of_vendored_module_removes_vendored_state() {
    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    write_consumer(&consumer, &format!("require {UMOD} {UVER}\n"), UPSTREAM_SUM);
    let modcache = tmp.path().join("modcache");
    let module_dir = modcache.join(format!("{UMOD}@{UVER}"));
    std::fs::create_dir_all(&module_dir).unwrap();
    std::fs::write(
        module_dir.join("go.mod"),
        format!("module {UMOD}\n\ngo 1.21\n"),
    )
    .unwrap();
    std::fs::write(module_dir.join("lib.go"), PRISTINE_LIB).unwrap();

    let socket = consumer.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let after = compute_git_sha256_from_bytes(PATCHED_LIB.as_bytes());
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "patches": { UPURL: {
                "uuid": UUID_V,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "lib.go": {
                    "beforeHash": compute_git_sha256_from_bytes(PRISTINE_LIB.as_bytes()),
                    "afterHash": &after,
                }},
                "vulnerabilities": {},
                "description": "vendored first",
                "license": "MIT",
                "tier": "free",
            }}
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED_LIB).unwrap();

    let (code, stdout, stderr) = common::run_with_env(
        &consumer,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            consumer.to_str().unwrap(),
        ],
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "vendor failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let vendor_dir = consumer.join(format!(".socket/vendor/golang/{UUID_V}"));
    assert!(vendor_dir.is_dir(), "precondition: module vendored");
    let state_path = consumer.join(".socket/vendor/state.json");
    assert!(
        std::fs::read_to_string(&state_path)
            .unwrap()
            .contains(UPURL),
        "precondition: vendor ledger records the module"
    );

    let server = MockServer::start().await;
    mount_hosted_grant(&server).await;
    let env = get_hosted(&consumer, &server, &modcache);
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");

    let go_mod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    assert_eq!(
        go_mod.matches(&format!("{UMOD} {UVER} =>")).count(),
        1,
        "{go_mod}"
    );
    assert!(go_mod.contains(&format!("replace {UMOD} {UVER} => {} {SVER}", smod())));
    assert!(!vendor_dir.exists(), "the vendored copy is removed");
    let state = std::fs::read_to_string(&state_path).unwrap_or_default();
    assert!(
        !state.contains(UPURL),
        "the vendor ledger no longer claims the module: {state}"
    );
}

const TEXT_SUM: &str = "golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\n\
                        golang.org/x/text v0.14.0/go.mod h1:18ZOQIKpY8NJVqYksKHtTdi31H5itFRjB5/qKTNYzSU=\n";

fn pristine_module(modcache: &Path) {
    let module_dir = modcache.join(format!("{UMOD}@{UVER}"));
    std::fs::create_dir_all(&module_dir).unwrap();
    std::fs::write(
        module_dir.join("go.mod"),
        format!("module {UMOD}\n\ngo 1.21\n"),
    )
    .unwrap();
    std::fs::write(module_dir.join("lib.go"), PRISTINE_LIB).unwrap();
}

/// Hosted `rollback` puts the pruned upstream go.sum pair back where go
/// sorts it, so go.mod and go.sum return byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_rollback_restores_go_sum_byte_for_byte() {
    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    let go_sum = format!("{UPSTREAM_SUM}{TEXT_SUM}");
    write_consumer(&consumer, &format!("require {UMOD} {UVER}\n"), &go_sum);
    let go_mod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    let modcache = tmp.path().join("modcache");
    let server = MockServer::start().await;
    mount_hosted_grant(&server).await;
    let env = get_hosted(&consumer, &server, &modcache);
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");

    let (code, stdout, stderr) = common::run_with_env(
        &consumer,
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            consumer.to_str().unwrap(),
        ],
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "rollback failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.mod")).unwrap(),
        go_mod
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.sum")).unwrap(),
        go_sum
    );
}

/// hosted → vendored takeover: vendoring must first unwind the hosted
/// redirect (replace, socket go.sum lines, pruned upstream pair, ledger
/// record), so the project is fully vendored — never a vendored go.mod
/// beside a redirect ledger that still claims the module.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_takeover_of_hosted_module_unwinds_the_redirect() {
    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    let go_sum = format!("{UPSTREAM_SUM}{TEXT_SUM}");
    write_consumer(&consumer, &format!("require {UMOD} {UVER}\n"), &go_sum);
    let modcache = tmp.path().join("modcache");
    pristine_module(&modcache);
    let server = MockServer::start().await;
    mount_hosted_grant(&server).await;
    let env = get_hosted(&consumer, &server, &modcache);
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    let ledger_path = consumer.join(".socket/vendor/redirect-state.json");
    assert!(
        std::fs::read_to_string(&ledger_path)
            .unwrap()
            .contains(UPURL),
        "precondition: the module is hosted-redirected"
    );

    let socket = consumer.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let after = compute_git_sha256_from_bytes(PATCHED_LIB.as_bytes());
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "patches": { UPURL: {
                "uuid": UUID_V,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "lib.go": {
                    "beforeHash": compute_git_sha256_from_bytes(PRISTINE_LIB.as_bytes()),
                    "afterHash": &after,
                }},
                "vulnerabilities": {},
                "description": "vendored over hosted",
                "license": "MIT",
                "tier": "free",
            }}
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED_LIB).unwrap();

    let (code, stdout, stderr) = common::run_with_env(
        &consumer,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            consumer.to_str().unwrap(),
        ],
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "vendor failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("vendor_takeover_reverted_redirect"),
        "the takeover is reported: {stdout}"
    );
    let go_mod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    assert!(
        go_mod.contains(&format!(
            "replace {UMOD} {UVER} => ./.socket/vendor/golang/{UUID_V}/{UMOD}@{UVER}"
        )),
        "{go_mod}"
    );
    assert!(!go_mod.contains("gopatch"), "{go_mod}");
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.sum")).unwrap(),
        go_sum,
        "go.sum is back to its pre-redirect bytes"
    );
    let ledger = std::fs::read_to_string(&ledger_path).unwrap_or_default();
    assert!(
        !ledger.contains(UPURL),
        "the redirect ledger no longer claims the module: {ledger}"
    );
}
