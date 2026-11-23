//! `socket-patch report` end to end, against a mock of the endpoint the
//! report is sent to.
//!
//! Covers a report by UUID from a directory that holds no patch, a report
//! by package name resolved against the project's manifest, `--dry-run`,
//! the human lines, and the failures: a name the project does not hold,
//! an endpoint that refuses, and an offline run. Every run points the
//! proxy at the mock: a report is sent even with telemetry switched off
//! (the hermetic default), so no run may be left on the real endpoint.

#[path = "common/mod.rs"]
mod common;
use common::{binary, hermetic_command, write_minimal_manifest, PatchEntry};

use std::path::Path;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UUID: &str = "8be53d06-7bd4-40cc-ab8f-36dc6248985a";
const OTHER: &str = "1d90158a-fffb-47ee-a84f-b210a3f7ae65";
const PURL: &str = "pkg:npm/lodash@4.17.20";
const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A mock that answers the anonymous report route with `status`.
async fn endpoint(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/telemetry"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

/// Run `socket-patch report <args>` in `cwd` with the proxy at `server`.
fn report(cwd: &Path, server: &MockServer, args: &[&str]) -> std::process::Output {
    hermetic_command(&binary())
        .arg("report")
        .args(args)
        .current_dir(cwd)
        .env("SOCKET_PROXY_URL", server.uri())
        .output()
        .expect("run socket-patch")
}

/// The bodies the mock received, in arrival order.
async fn bodies(server: &MockServer) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .expect("recording enabled")
        .iter()
        .map(|request| serde_json::from_slice(&request.body).expect("a JSON body"))
        .collect()
}

fn stdout_json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// A project whose manifest holds one agent-mode patch of lodash.
fn project_with_lodash() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_minimal_manifest(
        &tmp.path().join(".socket"),
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/index.js",
            before_hash: HASH,
            after_hash: HASH,
        }],
    );
    tmp
}

/// A UUID is reported from anywhere: the directory holds no patch (the
/// patch was rolled back, say). The report goes out although the run's
/// telemetry is switched off, names the patch by UUID alone, and carries
/// the reason and the message on one line.
#[tokio::test]
async fn a_uuid_is_reported_from_a_directory_that_holds_no_patch() {
    let server = endpoint(201).await;
    let tmp = tempfile::tempdir().expect("tempdir");

    let out = report(
        tmp.path(),
        &server,
        &[
            &UUID.to_uppercase(),
            "--reason",
            "tests",
            "--message",
            "jest fails:\n  TypeError",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        stdout_json(&out),
        serde_json::json!({
            "command": "report",
            "status": "success",
            "dryRun": false,
            "reason": "tests",
            "message": "jest fails: TypeError",
            "patches": [{ "uuid": UUID, "ecosystem": "", "mode": "unknown" }],
        })
    );

    let sent = bodies(&server).await;
    assert_eq!(sent.len(), 1, "one report, and no telemetry beside it");
    assert_eq!(sent[0]["event_type"], "patch_reported");
    assert_eq!(sent[0]["context"]["command"], "report");
    assert_eq!(
        sent[0]["metadata"],
        serde_json::json!({
            "reason": "breaks_tests",
            "message": "jest fails: TypeError",
            "patches": [
                { "uuid": UUID, "ecosystem": "", "mode": "unknown", "outcome": "reported" }
            ],
            "outcomes": { "reported": 1 },
            "ecosystems": [],
            "modes": ["unknown"],
        })
    );
}

/// A package name is resolved against the project: the report names the
/// patch the manifest holds for it, with its ecosystem and mode, and the
/// package name itself is not sent. With no `--reason` the reason is
/// `other`.
#[tokio::test]
async fn a_package_name_reports_the_patch_the_project_holds() {
    let server = endpoint(201).await;
    let tmp = project_with_lodash();

    let out = report(tmp.path(), &server, &["lodash"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("Reported 1 patch to Socket as broken:\n  {PURL} ({UUID}, agent mode)\n")
    );

    let sent = bodies(&server).await;
    assert_eq!(sent.len(), 1);
    let metadata = &sent[0]["metadata"];
    assert_eq!(metadata["reason"], "other");
    assert!(metadata.get("message").is_none());
    assert_eq!(
        metadata["patches"],
        serde_json::json!([
            { "uuid": UUID, "ecosystem": "npm", "mode": "agent", "outcome": "reported" }
        ])
    );
    assert!(
        !sent[0].to_string().contains("lodash"),
        "the package name is not sent: {}",
        sent[0]
    );
}

/// `--dry-run` resolves the patches and shows the whole report (each
/// patch with its mode, and the message as it would be sent, redacted),
/// and sends nothing. `--silent` prints nothing for a report that was
/// sent.
#[tokio::test]
async fn a_dry_run_sends_nothing_and_silent_prints_nothing() {
    let server = endpoint(201).await;
    let tmp = project_with_lodash();

    let out = report(
        tmp.path(),
        &server,
        &[
            PURL,
            "--reason",
            "build",
            "--message",
            "see\nhttps://user:hunter2@example.com/log",
            "--dry-run",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines[..2],
        [
            "Would report 1 patch to Socket as breaking the build:".to_string(),
            format!("  {PURL} ({UUID}, agent mode)"),
        ]
    );
    assert_eq!(lines.len(), 3, "{stdout}");
    assert!(
        lines[2].starts_with("  Message: see https://") && !lines[2].contains("hunter2"),
        "the message as sent, on one line and redacted: {stdout}"
    );
    assert!(bodies(&server).await.is_empty(), "a dry run sends nothing");

    let out = report(tmp.path(), &server, &[UUID, "--silent"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
    assert_eq!(bodies(&server).await.len(), 1);
}

/// A name the project holds no patch for is an error that says how to
/// report by UUID, and nothing is sent, not even for the targets that
/// did match.
#[tokio::test]
async fn a_name_the_project_does_not_hold_is_refused() {
    let server = endpoint(201).await;
    let tmp = project_with_lodash();

    let out = report(tmp.path(), &server, &["lodash", "left-pad", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let doc = stdout_json(&out);
    assert_eq!(doc["command"], "report");
    assert_eq!(doc["status"], "error");
    assert_eq!(doc["error"]["code"], "patch_not_found");
    let message = doc["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("left-pad") && message.contains("UUID"),
        "{message}"
    );
    assert!(bodies(&server).await.is_empty());
}

/// A report the endpoint refuses is a failed run that says the report
/// was not sent; so is an offline run, which makes no request at all.
#[tokio::test]
async fn a_report_that_cannot_be_sent_fails_the_run() {
    let refusing = endpoint(500).await;
    let tmp = tempfile::tempdir().expect("tempdir");

    let out = report(tmp.path(), &refusing, &[UUID, OTHER]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Error: The report was not sent: the request returned status 500 Internal Server \
         Error\n"
    );
    assert_eq!(bodies(&refusing).await.len(), 1);

    let server = endpoint(201).await;
    let out = report(tmp.path(), &server, &[UUID, "--offline", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let doc = stdout_json(&out);
    assert_eq!(doc["error"]["code"], "offline_unsupported");
    assert_eq!(
        doc["error"]["message"],
        "The report was not sent: the run is offline"
    );
    assert!(
        bodies(&server).await.is_empty(),
        "an offline run sends nothing"
    );
}

/// A saved login the org endpoint refuses does not cost the report: it
/// goes out again on the public route, without the token.
#[tokio::test]
async fn a_refused_login_still_delivers_the_report() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v0/orgs/acme/telemetry"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/telemetry"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().expect("tempdir");

    let out = hermetic_command(&binary())
        .args(["report", UUID, "--json"])
        .current_dir(tmp.path())
        .env("SOCKET_API_URL", server.uri())
        .env("SOCKET_PROXY_URL", server.uri())
        .env("SOCKET_ORG_SLUG", "acme")
        .env(
            "SOCKET_API_TOKEN",
            "sktsec_00000000000000000000000000000000000000000000_api",
        )
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(stdout_json(&out)["status"], "success");

    let requests = server.received_requests().await.expect("recording enabled");
    let seen: Vec<(&str, bool)> = requests
        .iter()
        .map(|r| (r.url.path(), r.headers.contains_key("authorization")))
        .collect();
    assert_eq!(
        seen,
        [
            ("/v0/orgs/acme/telemetry", true),
            ("/patch/telemetry", false)
        ]
    );
}

/// A manifest that cannot be read may hold the patch a name meant: the
/// run says the manifest is the problem, not that no patch matches, and
/// a report by UUID still goes out.
#[tokio::test]
async fn an_unreadable_manifest_is_named_and_a_uuid_still_reports() {
    let server = endpoint(201).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), "{ not json").unwrap();

    let out = report(tmp.path(), &server, &["lodash", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let doc = stdout_json(&out);
    assert_eq!(doc["error"]["code"], "manifest_invalid");
    let message = doc["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("manifest.json") && message.contains("UUID"),
        "{message}"
    );
    assert!(bodies(&server).await.is_empty());

    let out = report(tmp.path(), &server, &[UUID]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(bodies(&server).await.len(), 1);
}

/// A vendor ledger that cannot be read may hold the vendored copy the
/// build consumes: a name is refused with the ledger's error rather than
/// resolved to the manifest's record of the same package, which could be
/// a patch the vendored artifact has replaced.
#[tokio::test]
async fn an_unreadable_vendor_ledger_refuses_a_name_the_manifest_still_holds() {
    let server = endpoint(201).await;
    let tmp = project_with_lodash();
    std::fs::create_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::write(tmp.path().join(".socket/vendor/state.json"), "{ not json").unwrap();

    let out = report(tmp.path(), &server, &["lodash", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let doc = stdout_json(&out);
    assert_eq!(doc["error"]["code"], "vendor_state_unreadable");
    assert!(
        doc["error"]["message"].as_str().unwrap().contains("UUID"),
        "{doc}"
    );
    assert!(bodies(&server).await.is_empty());

    let out = report(tmp.path(), &server, &[UUID]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(bodies(&server).await.len(), 1);
}

/// One report names at most 50 patches. More is refused, even on a dry
/// run, rather than sent with some left out.
#[tokio::test]
async fn more_patches_than_one_report_names_is_refused() {
    let server = endpoint(201).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let uuids: Vec<String> = (0..51)
        .map(|n| format!("{n:08x}-7bd4-40cc-ab8f-36dc6248985a"))
        .collect();
    let all: Vec<&str> = uuids.iter().map(String::as_str).collect();

    let mut args = all.clone();
    args.push("--dry-run");
    let out = report(tmp.path(), &server, &args);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Error: The report was not sent: one report names at most 50 patches; send the rest \
         in another\n"
    );

    let mut args = all.clone();
    args.push("--json");
    let out = report(tmp.path(), &server, &args);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(stdout_json(&out)["error"]["code"], "too_many_patches");
    assert!(bodies(&server).await.is_empty());

    // Exactly 50 go out, all named.
    let out = report(tmp.path(), &server, &all[..50]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let sent = bodies(&server).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["metadata"]["patches"].as_array().unwrap().len(), 50);
    assert!(sent[0]["metadata"].get("patches_truncated").is_none());
}
