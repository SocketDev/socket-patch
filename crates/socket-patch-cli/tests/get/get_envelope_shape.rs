//! v5.0: `get --json` prints one shared envelope (`command: "get"`) on
//! every path — statuses from the `Status` enum (camelCase), per-patch
//! outcomes as events, `summary` equal to the event counts, and every
//! failure (usage errors included) as a full envelope.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common;
use crate::common::envelope::{assert_envelope_invariants, event_triples};

const ORG: &str = "test-org";
const UUID_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const UUID_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn get(cwd: &std::path::Path, server: &str, args: &[&str]) -> (i32, serde_json::Value) {
    let mut argv = vec!["get"];
    argv.extend_from_slice(args);
    argv.extend([
        "--json",
        "--api-url",
        server,
        "--api-token",
        "fake",
        "--org",
        ORG,
    ]);
    let (code, stdout, stderr) =
        common::run_with_env(cwd, &argv, &[("SOCKET_TELEMETRY_DISABLED", "1")]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be ONE JSON document ({e}):\n{stdout}\nstderr:\n{stderr}")
    });
    assert_envelope_invariants(&v, "get");
    (code, v)
}

fn patch(uuid: &str, purl: &str, published: &str) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid, "purl": purl, "publishedAt": published,
        "description": "fixture", "license": "MIT", "tier": "free",
        "vulnerabilities": {}
    })
}

/// Usage and `--offline` errors print the full envelope (exit 2 / 1).
#[test]
fn get_early_errors_print_full_envelopes() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, v) = get(tmp.path(), "http://127.0.0.1:9", &["x", "--id", "--cve"]);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "invalid_args", "{v:#}");
    assert_eq!(v["events"], serde_json::json!([]));
    let (code, v) = get(tmp.path(), "http://127.0.0.1:9", &["lodash", "--offline"]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "offline_unsupported", "{v:#}");
}

/// A uuid nobody publishes is `notFound`, exit 0, no events.
#[tokio::test]
async fn get_unknown_uuid_is_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID_A}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let (code, v) = get(tmp.path(), &server.uri(), &[UUID_A]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "notFound", "{v:#}");
    assert_eq!(v["events"], serde_json::json!([]));
}

/// Several free patches for one package in agent mode: `selectionRequired`
/// (exit 1) with its coded `error`, the package and the camelCase options.
#[tokio::test]
async fn get_selection_required_is_a_status_with_options() {
    let purl = "pkg:npm/multi@1.0.0";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/pkg%3Anpm%2Fmulti%401.0.0"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                patch(UUID_A, purl, "Mon, 01 Jan 2024 00:00:00 GMT"),
                patch(UUID_B, purl, "Thu, 01 Feb 2024 00:00:00 GMT"),
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let (code, v) = get(tmp.path(), &server.uri(), &[purl, "--mode", "agent"]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(v["status"], "selectionRequired");
    assert_eq!(v["error"]["code"], "selection_required");
    assert_eq!(v["purl"], purl);
    let options = v["options"].as_array().unwrap();
    assert_eq!(options.len(), 2, "{v:#}");
    for o in options {
        assert!(o["publishedAt"].is_string(), "camelCase publishedAt: {o}");
        assert!(o.get("published_at").is_none(), "{o}");
    }
}

/// Agent-mode `--dry-run`: one `verified` event per patch a wet run would
/// record, top-level `dryRun`, nothing written.
#[tokio::test]
async fn get_agent_dry_run_previews_verified_events() {
    let purl = "pkg:npm/one@1.0.0";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/pkg%3Anpm%2Fone%401.0.0"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [patch(UUID_A, purl, "Mon, 01 Jan 2024 00:00:00 GMT")],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let (code, v) = get(
        tmp.path(),
        &server.uri(),
        &[purl, "--mode", "agent", "--dry-run"],
    );
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["dryRun"], true);
    assert_eq!(
        event_triples(&v),
        vec![(purl.to_string(), "verified".to_string(), String::new())]
    );
    assert_eq!(v["summary"]["verified"], 1);
    assert!(
        !tmp.path().join(".socket").exists(),
        "a dry run writes nothing"
    );
}
