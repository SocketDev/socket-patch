#[path = "common/mod.rs"]
mod common;
#[path = "get/get_fixture.rs"]
#[allow(dead_code)]
mod get_fixture;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use get_fixture::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CVE: &str = "CVE-2024-4248";
const NOTE: &str = "Enable safe mode explicitly before using the patch.";

#[derive(Clone, Copy)]
enum CommandKind {
    Get,
    Scan,
    Apply,
    List,
}

#[derive(Clone, Copy)]
enum Mode {
    Agent,
    Hosted,
    Vendored,
}

#[derive(Clone, Copy)]
enum Action {
    Real,
    DryRun,
    SaveOnly,
}

impl CommandKind {
    fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Scan => "scan",
            Self::Apply => "apply",
            Self::List => "list",
        }
    }
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Hosted => "hosted",
            Self::Vendored => "vendored",
        }
    }
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::DryRun => "dry-run",
            Self::SaveOnly => "save-only",
        }
    }
}

async fn mount_api(server: &MockServer) {
    let mut view = view_json(
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": git_hash(BEFORE_BYTES),
                "afterHash": git_hash(AFTER_BYTES),
                "blobContent": b64(AFTER_BYTES),
            }
        }),
    );
    view["requiresOptIn"] = serde_json::json!(true);
    view["optInNote"] = serde_json::json!(NOTE);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view.clone()))
        .mount(server)
        .await;
    crate::prebuilt_common::mount_view(server, &view, None).await;

    let records = serde_json::json!([{
        "uuid": UUID,
        "purl": PURL,
        "publishedAt": "2024-01-01T00:00:00Z",
        "description": "Activation metadata matrix",
        "license": "MIT",
        "tier": "free",
        "vulnerabilities": {},
        "requiresOptIn": true,
        "optInNote": NOTE,
    }]);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{CVE}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": records.clone(),
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{}",
            encode_purl(PURL)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": records,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "Activation metadata matrix",
                    "requiresOptIn": true, "optInNote": NOTE,
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

fn encode_purl(purl: &str) -> String {
    purl.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}

fn api_args(server: &MockServer) -> Vec<String> {
    vec![
        "--api-url".into(),
        server.uri(),
        "--api-token".into(),
        "fake-token-for-test".into(),
        "--org".into(),
        ORG.into(),
    ]
}

fn run_argv(root: &std::path::Path, args: Vec<String>) -> (i32, String, String) {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    common::run_with_env(root, &args, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

fn get_args(server: &MockServer, mode: Mode, action: Action) -> Vec<String> {
    let mut args = vec!["get".into(), CVE.into()];
    args.extend(api_args(server));
    args.extend(["--mode".into(), mode.name().into(), "--yes".into()]);
    match action {
        Action::Real => {}
        Action::DryRun => args.push("--dry-run".into()),
        Action::SaveOnly => args.push("--save-only".into()),
    }
    args
}

async fn stage_state(
    root: &std::path::Path,
    server: &MockServer,
    mode: Mode,
    command: CommandKind,
) {
    let (code, _, stderr) = run_argv(root, get_args(server, mode, Action::Real));
    assert_eq!(code, 0, "staging {}: {stderr}", mode.name());
    if matches!(command, CommandKind::Apply | CommandKind::List) && matches!(mode, Mode::Hosted) {
        seed_manifest_with(root, PURL, UUID);
        let path = root.join(".socket/manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let record = &mut manifest["patches"][PURL];
        record["requiresOptIn"] = serde_json::json!(true);
        record["optInNote"] = serde_json::json!(NOTE);
        record["files"] = view_json(
            UUID,
            PURL,
            serde_json::json!({
                "package/index.js": {
                    "beforeHash": git_hash(BEFORE_BYTES),
                    "afterHash": git_hash(AFTER_BYTES),
                    "blobContent": b64(AFTER_BYTES),
                }
            }),
        )["files"]
            .clone();
        record["exportedAt"] = serde_json::json!("2024-01-01T00:00:00Z");
        std::fs::write(path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        let socket = root.join(".socket");
        std::fs::create_dir_all(socket.join("blobs")).unwrap();
        std::fs::write(
            socket.join("blobs").join(git_hash(AFTER_BYTES)),
            AFTER_BYTES,
        )
        .unwrap();
    }
}

#[test]
fn opt_in_output_matrix() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for command in [
        CommandKind::Get,
        CommandKind::Scan,
        CommandKind::Apply,
        CommandKind::List,
    ] {
        for mode in [Mode::Agent, Mode::Hosted, Mode::Vendored] {
            for action in [Action::Real, Action::DryRun, Action::SaveOnly] {
                runtime.block_on(run_case(command, mode, action));
            }
        }
    }
}

async fn run_case(command: CommandKind, mode: Mode, action: Action) {
    let valid = !matches!(action, Action::SaveOnly)
        || matches!((command, mode), (CommandKind::Get, Mode::Agent));
    let label = format!("{}:{}:{}", command.name(), mode.name(), action.name());
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let mut args = match command {
        CommandKind::Get => get_args(&server, mode, action),
        CommandKind::Scan => {
            let mut args = vec!["scan".into()];
            args.extend(api_args(&server));
            args.extend(["--mode".into(), mode.name().into()]);
            args
        }
        CommandKind::Apply => vec!["apply".into()],
        CommandKind::List => vec!["list".into()],
    };
    if !matches!(command, CommandKind::Get) {
        if matches!(action, Action::DryRun) {
            args.push("--dry-run".into());
        } else if matches!(action, Action::SaveOnly) {
            args.push("--save-only".into());
        }
    }

    let (code, stdout, stderr) = if matches!(command, CommandKind::Apply | CommandKind::List) {
        stage_state(tmp.path(), &server, mode, command).await;
        server.reset().await;
        mount_api(&server).await;
        run_argv(tmp.path(), args)
    } else {
        run_argv(tmp.path(), args)
    };
    if valid {
        assert_eq!(code, 0, "{label}: stdout={stdout}\nstderr={stderr}");
        assert_eq!(stdout.matches(NOTE).count(), 1, "{label}: {stdout}");
        assert_eq!(stderr.matches(NOTE).count(), 0, "{label}: {stderr}");
    } else {
        assert_ne!(code, 0, "{label}");
        assert!(!stdout.contains(NOTE) && !stderr.contains(NOTE), "{label}");
        assert!(
            received_paths(&server).await.is_empty(),
            "{label} must not fetch patch metadata"
        );
    }
}
