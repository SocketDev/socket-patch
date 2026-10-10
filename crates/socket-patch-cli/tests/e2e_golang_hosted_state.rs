#![cfg(unix)]
//! Hosted golang redirects must claim (and attest) exactly what the
//! committed go.mod/go.sum enforce, and a vendored→hosted mode switch must
//! leave the project fully hosted.
//!
//! Drives the real binary (`get <uuid> --mode hosted`) against a wiremock
//! patch API. No go toolchain is needed: every assertion is on the files
//! the CLI writes and on its JSON envelope.

#[path = "common/rollback_json.rs"]
mod rollback_json;

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

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

/// Serve Go's checksum database lookup for the upstream module (the
/// `SOCKET_GOSUMDB_URL` override the hosted -> upstream restore reads): the
/// two go.sum lines of `UPSTREAM_SUM`, so the restore re-derives exactly
/// the pair the hosted rewrite pruned.
async fn mount_sumdb(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/lookup/{UMOD}@{UVER}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "12345\n{UPSTREAM_SUM}\ngo.sum database tree\n12345\nAAAA\n"
        )))
        .mount(server)
        .await;
}

fn get_hosted(consumer: &Path, server: &MockServer, modcache: &Path) -> serde_json::Value {
    get_hosted_with(consumer, server, modcache, &[])
}

fn get_hosted_with(
    consumer: &Path,
    server: &MockServer,
    modcache: &Path,
    extra: &[&str],
) -> serde_json::Value {
    let uri = server.uri();
    let mut args = vec![
        "get",
        UUID_H,
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        consumer.to_str().unwrap(),
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_with_prebuilt(
        consumer,
        &args,
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "get --mode hosted failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}"))
}

/// Every file under `root`, `.socket/` included (relative path → bytes).
fn tree_snapshot(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if std::fs::symlink_metadata(&p).unwrap().is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
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
    assert_eq!(hosted_pinned(&env), 0, "envelope: {env}");
    assert!(
        env["warnings"]
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
    assert_eq!(hosted_pinned(&env), 0, "envelope: {env}");
    assert!(
        env["warnings"]
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

    let (code, stdout, stderr) = run_with_prebuilt(
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
    // The dry run stages the same revert in memory and drops it: every
    // byte of the project, `.socket/` included, stays as it was.
    let before = tree_snapshot(&consumer);
    let preview = get_hosted_with(&consumer, &server, &modcache, &["--dry-run"]);
    assert!(
        preview
            .to_string()
            .contains("redirect_would_revert_vendored"),
        "the takeover is previewed: {preview}"
    );
    assert_eq!(
        tree_snapshot(&consumer),
        before,
        "a dry-run takeover changes nothing: {preview}"
    );

    let env = get_hosted(&consumer, &server, &modcache);
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");

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

/// Hosted `rollback` drops the hosted `replace` and puts the pruned upstream
/// go.sum pair back where go sorts it -- re-derived from the (mocked)
/// checksum database, no ledger involved -- so go.mod and go.sum return
/// byte for byte. Offline, the pin is refused and nothing is written.
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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    assert!(
        !consumer.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode keeps no ledger: go.mod/go.sum are the record"
    );
    let wired_mod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    let wired_sum = std::fs::read_to_string(consumer.join("go.sum")).unwrap();
    assert_ne!(wired_mod, go_mod, "precondition: go.mod is hosted-wired");

    let rollback = |extra: &[&str], env: &[(&str, &str)]| {
        let mut args = vec![
            "rollback",
            "--json",
            "--yes",
            "--cwd",
            consumer.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let mut env_full = vec![("GOMODCACHE", modcache.to_str().unwrap())];
        env_full.extend_from_slice(env);
        run_with_prebuilt(&consumer, &args, &env_full)
    };

    let (code, stdout, stderr) = rollback(&["--offline"], &[]);
    assert_eq!(
        code, 1,
        "offline must refuse\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        rollback_json::hosted_failed(&doc)[0]["purl"],
        UPURL,
        "{doc}"
    );
    assert!(
        rollback_json::hosted_failed(&doc)[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("this run is offline") && e.contains("go.mod")),
        "{doc}"
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.mod")).unwrap(),
        wired_mod
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.sum")).unwrap(),
        wired_sum
    );

    mount_sumdb(&server).await;
    let sumdb = server.uri();
    let (code, stdout, stderr) = rollback(&[], &[("SOCKET_GOSUMDB_URL", sumdb.as_str())]);
    assert_eq!(
        code, 0,
        "rollback failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        rollback_json::hosted_reverted(&doc),
        serde_json::json!([UPURL]),
        "{doc}"
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

/// hosted → vendored takeover: vendoring must first restore the hosted pin
/// to its upstream entry (drop the hosted replace and the socket go.sum
/// lines, re-derive the pruned upstream pair from the checksum database),
/// so the project is fully vendored — never a vendored go.mod beside a
/// hosted pin. No ledger is involved at any point.
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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    let ledger_path = consumer.join(".socket/vendor/redirect-state.json");
    assert!(
        std::fs::read_to_string(consumer.join("go.mod"))
            .unwrap()
            .contains("gopatch"),
        "precondition: the module is hosted-redirected"
    );
    assert!(!ledger_path.exists(), "hosted mode keeps no ledger");
    mount_sumdb(&server).await;
    let sumdb = server.uri();

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

    // Online: the takeover's upstream restore consults the (mocked)
    // checksum database; the patch itself comes from the local manifest.
    let (code, stdout, stderr) = run_with_prebuilt(
        &consumer,
        &["vendor", "--json", "--cwd", consumer.to_str().unwrap()],
        &[
            ("GOMODCACHE", modcache.to_str().unwrap()),
            ("SOCKET_GOSUMDB_URL", sumdb.as_str()),
        ],
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
    assert!(!ledger_path.exists(), "no hosted ledger is ever written");
}

fn run_with_prebuilt(
    cwd: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let fixture = (args.first() == Some(&"vendor") && !args.contains(&"--revert"))
        .then(|| prebuilt_common::Server::project_with_env(cwd, env));
    let args: Vec<_> = args
        .iter()
        .copied()
        .filter(|a| fixture.is_none() || *a != "--offline")
        .collect();
    let mut env = env.to_vec();
    if let Some(fixture) = &fixture {
        env.push(("SOCKET_VENDOR_URL", &fixture.uri));
    }
    common::run_with_env(cwd, &args, &env)
}

/// How many hosted pins the run wrote (v5.0: the `applied` / `verified`
/// events with `details.mode: "hosted"`, formerly `redirect.redirected`).
fn hosted_pinned(env: &serde_json::Value) -> u64 {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            e["details"]["mode"] == "hosted"
                && (e["action"] == "applied" || e["action"] == "verified")
        })
        .count() as u64
}
