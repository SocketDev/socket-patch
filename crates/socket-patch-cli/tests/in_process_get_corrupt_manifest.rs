//! In-process regression test for `get <uuid>`'s save step
//! (`save_and_apply_patch`): a manifest that EXISTS but cannot be parsed
//! must be a hard error. Historically the read error was swallowed into
//! an EMPTY manifest which the save step then unconditionally rewrote
//! with just the one fetched patch — silently destroying every
//! previously tracked record. The download flow's identical guard lives
//! in `in_process_get_update_count.rs`.

use serial_test::serial;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::get::{run, GetArgs};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "33333333-3333-4333-8333-333333333333";
const PURL: &str = "pkg:npm/corrupt-manifest-pkg@1.0.0";

#[tokio::test]
#[serial]
async fn uuid_get_with_corrupt_manifest_fails_without_clobbering() {
    let server = MockServer::start().await;
    // The patch fetch itself succeeds: the failure must come from the
    // manifest read in the save step, and must not rewrite the file.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-06-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                    "blobContent": "cGF0Y2hlZAo=",
                    "beforeBlobContent": "b3JpZ2luYWwK",
                }
            },
            "vulnerabilities": {},
            "description": "corrupt manifest test patch", "license": "MIT", "tier": "free",
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    // E.g. a git merge left conflict markers in a committed manifest.
    let corrupt = "<<<<<<< HEAD\n{ \"patches\": {} }\n";
    std::fs::write(socket.join("manifest.json"), corrupt).unwrap();

    let args = GetArgs {
        identifier: UUID.to_string(),
        common: GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            api_url: server.uri(),
            api_token: Some("fake-token".to_string()),
            org: Some(ORG.to_string()),
            proxy_url: server.uri(),
            json: true,
            no_telemetry: true,
            ..GlobalArgs::default()
        },
        id: true,
        cve: false,
        ghsa: false,
        package: false,
        // save_only isolates the save path from the apply step.
        save_only: true,
        one_off: false,
        all_releases: false,
    };

    let code = run(args).await;
    assert_eq!(
        code, 1,
        "an unreadable manifest must fail the run, not be treated as empty"
    );

    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    assert_eq!(
        body, corrupt,
        "a corrupt manifest must be left untouched, never overwritten"
    );
}
