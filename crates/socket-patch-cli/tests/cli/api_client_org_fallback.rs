//! A token whose org can't be resolved: the whole run falls back to the
//! public proxy, and every output mode reports it.
//!
//! The core inline tests (`org_auto_resolution_401_with_hash_shaped_token_hint_arm`)
//! pin the resulting client *state*. Here `--json` runs assert the
//! `api_auth_fallback` warning code and the request log; the human run pins
//! the stderr text once per message family (the org fallback, the
//! "you configured the sha512- storage hash, not the token" hint and the
//! token-shape warning), which only a spawned process can observe.

use crate::common::envelope::{output_envelope, warning_codes};
use crate::common::{binary, hermetic_command};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UUID: &str = "11111111-1111-4111-8111-111111111111";

/// `warnings[]` carries the startup downgrade to the public proxy, and its
/// detail still names the `--org` remedy agents act on.
fn assert_api_auth_fallback(v: &serde_json::Value, context: &str) {
    assert!(
        warning_codes(v).iter().any(|c| c == "api_auth_fallback"),
        "[{context}] api_auth_fallback missing from warnings[]: {v}"
    );
    let detail = v["warnings"]
        .as_array()
        .and_then(|w| w.iter().find(|w| w["code"] == "api_auth_fallback"))
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default();
    assert!(
        detail.contains("--org"),
        "[{context}] the api_auth_fallback detail names the remedy: {v}"
    );
}

/// The org fallback warning reaches stderr exactly once, in any output
/// mode that doesn't mute warnings.
fn assert_org_warning_once(stderr: &str, mode: &str) {
    assert_eq!(
        stderr
            .matches("Could not determine your organization")
            .count(),
        1,
        "[{mode}] the failed resolution warns once; stderr={stderr}"
    );
}

/// Run `get <UUID> --save-only --yes` plus `extra` flags with a hash-shaped
/// `--api-token` (the dashboard's stored `sha512-...` value) and no `--org`,
/// against a fresh mock that 401s org auto-resolution exactly once and
/// 404s the public proxy's view route exactly once (the failed resolution
/// puts the whole run on the proxy; no `/v0/orgs/` route is ever hit).
async fn run_get_with_hash_shaped_token(extra: &[&str]) -> std::process::Output {
    let mock = MockServer::start().await;
    // Org auto-resolution: exactly one 401. `.expect(1)` proves the
    // resolution round-trip actually fired (no ambient slug short-circuit).
    Mock::given(method("GET"))
        .and(path("/v0/organizations"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock)
        .await;
    // After failed resolution the run is on the public proxy (here the same
    // mock, via --proxy-url): a 404 on its view route is a graceful
    // not-found. No org-scoped route may be queried.
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(wiremock::matchers::path_regex("^/v0/orgs/"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = mock.uri();
    let mut args = vec!["get", UUID];
    args.extend_from_slice(extra);
    args.extend_from_slice(&[
        "--save-only",
        "--yes",
        "--api-url",
        &uri,
        "--proxy-url",
        &uri,
        "--api-token",
        "sha512-deadbeefdeadbeef",
    ]);
    // `mock` is dropped (and its `.expect(1)`s verified) on return.
    // Hermetic env: ambient state must not short-circuit auto-resolution
    // (no env slug, no offline gate, no socket-cli config).
    hermetic_command(&binary())
        .args(&args)
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch get")
}

/// The human render of the 401, one check per message family: the org
/// fallback warning (printed once, with its remedy), the stored-hash hint
/// naming the `sha512-` prefix and the flag the token came from, and the
/// pre-flight token-shape warning.
fn assert_hash_token_render(stderr: &str) {
    assert_org_warning_once(stderr, "human");
    assert!(
        stderr.contains("Warning: Could not determine your organization"),
        "the fallback is printed as a warning; stderr={stderr}"
    );
    assert!(
        stderr.contains(
            "using the public patch API proxy (free patches only). \
                         Pass --org or set SOCKET_ORG_SLUG."
        ),
        "the warning says what the run does and how to fix it; stderr={stderr}"
    );
    assert!(
        stderr.contains("Hint: --api-token starts with `sha512-`")
            && stderr.contains("Set it to the raw `sktsec_..._api` value instead."),
        "the 401 + hash-shaped token prints the stored-hash hint and its \
         remedy; stderr={stderr}"
    );
    assert!(
        stderr.contains("Warning: --api-token does not look like a Socket API token")
            && stderr.contains("looks like an SRI-format hash"),
        "the shape warning names the flag, not SOCKET_API_TOKEN, and says \
         why; stderr={stderr}"
    );
}

/// Human mode: the 401 produces the stored-hash hint on stderr, and the
/// command degrades gracefully (proxy fetch → 404 → not found, exit 0)
/// instead of crashing.
#[tokio::test]
async fn get_with_hash_shaped_token_prints_stored_hash_hint_on_401() {
    let out = run_get_with_hash_shaped_token(&[]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_hash_token_render(&stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "graceful not-found must exit 0; stderr={stderr}"
    );
}

/// `--json` keeps stdout machine-readable but does not mute warnings: the
/// hint and token-shape warning still reach stderr (their text is pinned by
/// the human test above), and stdout is a `notFound` envelope whose
/// `warnings[]` reports the downgrade.
#[tokio::test]
async fn get_with_hash_shaped_token_under_json_keeps_warnings_and_envelope() {
    let out = run_get_with_hash_shaped_token(&["--json"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_org_warning_once(&stderr, "json");
    assert!(
        stderr.contains("Hint: --api-token") && stderr.contains("Warning: --api-token"),
        "--json must not mute the stderr warnings; stderr={stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "graceful not-found must exit 0; stderr={stderr}"
    );
    let v = output_envelope(&out);
    assert_eq!(
        v["status"], "notFound",
        "404 after failed org resolution maps to not_found, got: {v}"
    );
    assert_eq!(
        v["events"],
        serde_json::json!([]),
        "notFound reports no events: {v}"
    );
    // The UUID path reports the startup downgrade in `warnings[]` too.
    assert_api_auth_fallback(&v, "get --json");
}

/// `--silent` is "errors only": the same misconfiguration prints neither
/// the token-shape warning nor the org auto-detect warning, and the
/// command still degrades to exit 0.
#[tokio::test]
async fn get_with_hash_shaped_token_under_silent_prints_no_warnings() {
    let out = run_get_with_hash_shaped_token(&["--json", "--silent"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Could not determine")
            && !stderr.contains("SRI-format")
            && !stderr.contains("Hint:"),
        "--silent must mute the org and token-shape warnings; stderr={stderr}"
    );
    assert_eq!(out.status.code(), Some(0), "stderr={stderr}");
    assert_eq!(output_envelope(&out)["status"], "notFound");
}

/// #648: the uuid path's agent `--dry-run` preview must report the
/// startup downgrade in `warnings[]` like its wet run does. The org
/// resolve 500s, the proxy serves the patch, and `get <uuid> --json
/// --dry-run --mode agent` previews it without writing anything.
#[tokio::test]
async fn unresolved_org_reaches_get_uuid_dry_run_json_warnings() {
    const PATCH: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/organizations"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(wiremock::matchers::path_regex("^/v0/orgs/"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{PATCH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": PATCH,
            "purl": "pkg:npm/left-pad@1.3.0",
            "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
            "files": { "package/index.js": {
                "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64)
            } },
            "vulnerabilities": {},
            "description": "agent patch",
            "license": "MIT",
            "tier": "free",
        })))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/telemetry"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let uri = mock.uri();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    let mut cmd = hermetic_command(&binary());
    let out = cmd
        .args([
            "get",
            PATCH,
            "--json",
            "--dry-run",
            "--mode",
            "agent",
            "--yes",
            "--cwd",
            cwd.to_str().unwrap(),
            "--api-url",
            &uri,
            "--proxy-url",
            &uri,
            "--api-token",
            &token,
        ])
        .current_dir(cwd)
        .output()
        .expect("run socket-patch get");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v = output_envelope(&out);
    assert_eq!(
        v["dryRun"], true,
        "the agent dry-run envelope: {v}; stderr={stderr}"
    );
    assert!(
        !cwd.join(".socket").exists(),
        "a dry run writes nothing; stderr={stderr}"
    );
    assert_api_auth_fallback(&v, "get --dry-run --json");
}

/// #648: a token whose org cannot be resolved (here `/v0/organizations`
/// answers 500) puts the WHOLE run on the public proxy, decided once.
/// `scan --json --vex` on a lockfile-only checkout with a hosted pin runs
/// the batch search, the embedded VEX record fetch and telemetry: every
/// request goes to `/patch/*`, none to `/v0/orgs/`, the org is resolved
/// exactly once (the embedded VEX reuses scan's client instead of building
/// another), and `--json` reports the downgrade in `warnings[]`.
#[tokio::test]
async fn unresolved_org_routes_the_whole_scan_vex_run_to_the_proxy_once() {
    const PATCH: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/organizations"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(wiremock::matchers::path_regex("^/v0/orgs/"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{PATCH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": PATCH,
            "purl": "pkg:npm/left-pad@1.3.0",
            "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
            "files": { "package/index.js": {
                "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64)
            } },
            "vulnerabilities": { "GHSA-org-once": {
                "cves": ["CVE-2026-41"], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "hosted patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/telemetry"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&mock)
        .await;

    // Lockfile-only checkout pinned to a hosted patch: the embedded VEX
    // must fetch this record from the patch API.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    std::fs::write(
        cwd.join("package-lock.json"),
        serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": format!(
                        "https://patch.socket.dev/patch/npm/left-pad/1.3.0/\
                         11111111-2222-4333-8444-555555555555/{PATCH}/left-pad-1.3.0.tgz"
                    ),
                    "integrity": "sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==",
                },
            },
        })
        .to_string(),
    )
    .unwrap();
    let vex_path = cwd.join("out.vex.json");
    let uri = mock.uri();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    let mut cmd = hermetic_command(&binary());
    let out = cmd
        .args([
            "scan",
            "--json",
            "--cwd",
            cwd.to_str().unwrap(),
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:generic/app@1.0.0",
            "--api-url",
            &uri,
            "--proxy-url",
            &uri,
            "--api-token",
            &token,
        ])
        .current_dir(cwd)
        .output()
        .expect("run socket-patch scan");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v = output_envelope(&out);
    assert_api_auth_fallback(&v, "scan --vex --json");

    let requests = mock.received_requests().await.unwrap();
    let paths: Vec<String> = requests.iter().map(|r| r.url.path().to_string()).collect();
    assert_eq!(
        paths.iter().filter(|p| *p == "/v0/organizations").count(),
        1,
        "the org is resolved once per run: {paths:?}"
    );
    assert!(
        paths
            .iter()
            .all(|p| p == "/v0/organizations" || p.starts_with("/patch/")),
        "every other call goes to the proxy: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p == "/patch/batch"),
        "the scan searched on the proxy: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| *p == format!("/patch/view/{PATCH}")),
        "the embedded VEX fetched its record on the proxy: {paths:?}; v={v}; stderr={stderr}"
    );
    assert!(
        requests
            .iter()
            .filter(|r| r.url.path().starts_with("/patch/"))
            .all(|r| !r.headers.contains_key("authorization")),
        "no proxy request carries the bearer"
    );
}

/// #648: `apply` and `vendor` seed their embedded `--vex` with the run's
/// client, which suppresses the VEX plan's own `api_auth_fallback` note on
/// the promise that the host reports it. So, like `scan` / `get`, their
/// `--json` envelopes must carry the downgrade in `warnings[]` (here on a
/// project whose manifest lists no patches: the host path still builds the
/// client, resolves the org once and prints its envelope).
#[tokio::test]
async fn unresolved_org_reaches_apply_and_vendor_json_warnings() {
    for command in ["apply", "vendor"] {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/organizations"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .expect(1)
            .mount(&mock)
            .await;
        Mock::given(wiremock::matchers::path_regex("^/v0/orgs/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/patch/telemetry"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&mock)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        std::fs::write(
            cwd.join("package.json"),
            r#"{"name":"app","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::create_dir_all(cwd.join(".socket")).unwrap();
        std::fs::write(cwd.join(".socket/manifest.json"), r#"{"patches":{}}"#).unwrap();
        let uri = mock.uri();
        let token = format!("sktsec_{}_api", "x".repeat(44));
        let mut cmd = hermetic_command(&binary());
        let out = cmd
            .args([
                command,
                "--json",
                "--cwd",
                cwd.to_str().unwrap(),
                "--api-url",
                &uri,
                "--proxy-url",
                &uri,
                "--api-token",
                &token,
            ])
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|e| panic!("run socket-patch {command}: {e}"));
        let v = output_envelope(&out);
        assert_eq!(v["command"], command, "{v}");
        assert_api_auth_fallback(&v, command);
    }
}
