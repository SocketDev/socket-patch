//! `scan --max-new-patches` end to end (staged rollout, work item B): a
//! project with nine patchable packages and a cap of three rolls forward
//! three packages per run, most severe first, in hosted, agent and vendored
//! mode; a fourth run changes nothing. Mock API, the built binary.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const HOST: &str = "http://patch.test";

/// `(name, severities)`: one advisory per severity; none = unknown.
const PACKAGES: [(&str, &[&str]); 9] = [
    ("roll-a", &["low"]),
    ("roll-b", &["critical"]),
    ("roll-c", &["high"]),
    ("roll-d", &["medium"]),
    ("roll-e", &["critical", "high"]),
    ("roll-f", &[]),
    ("roll-g", &["high", "low", "low"]),
    ("roll-h", &["medium"]),
    ("roll-i", &["low"]),
];

/// The rollout order: severity, then advisory count, then name.
const ORDER: [&str; 9] = [
    "roll-e", "roll-b", "roll-g", "roll-c", "roll-d", "roll-h", "roll-a", "roll-i", "roll-f",
];

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn uuid(name: &str) -> String {
    let n = PACKAGES.iter().position(|(p, _)| *p == name).unwrap() + 1;
    format!("{n:08x}-1111-4111-8111-{n:012x}")
}

fn purl(name: &str) -> String {
    format!("pkg:npm/{name}@1.0.0")
}

fn hosted_url(name: &str) -> String {
    format!(
        "{HOST}/patch/npm/{name}/1.0.0/{TOKEN}/{}/{name}-1.0.0.tgz",
        uuid(name)
    )
}

fn before(name: &str) -> Vec<u8> {
    format!("module.exports = '{name} before';\n").into_bytes()
}

fn after(name: &str) -> Vec<u8> {
    format!("module.exports = '{name} after';\n").into_bytes()
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn vulns(name: &str, severities: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for (i, sev) in severities.iter().enumerate() {
        map.insert(
            format!("GHSA-{name}-{i}"),
            json!({ "cves": [], "summary": "s", "severity": sev, "description": "d" }),
        );
    }
    Value::Object(map)
}

/// A v3 npm project in `dir` with `names` installed and locked.
fn write_project(dir: &Path, names: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    let deps: serde_json::Map<String, Value> = names
        .iter()
        .map(|n| (n.to_string(), json!("1.0.0")))
        .collect();
    std::fs::write(
        dir.join("package.json"),
        serde_json::to_vec_pretty(&json!({
            "name": "rollout-consumer", "version": "0.0.0", "dependencies": deps
        }))
        .unwrap(),
    )
    .unwrap();
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        json!({ "name": "rollout-consumer", "version": "0.0.0", "dependencies": deps }),
    );
    for name in names {
        packages.insert(
            format!("node_modules/{name}"),
            json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                "integrity": "sha512-UPSTREAMupstream==",
                "license": "MIT"
            }),
        );
        let pkg = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), before(name)).unwrap();
    }
    let mut lock = serde_json::to_vec_pretty(&json!({
        "name": "rollout-consumer",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": packages,
    }))
    .unwrap();
    lock.push(b'\n');
    std::fs::write(dir.join("package-lock.json"), lock).unwrap();
}

/// How the mock answers one package's reference grant.
#[derive(Clone, Copy, PartialEq)]
enum Grant {
    Granted,
    Withdrawn,
    BadPurl,
}

/// Batch, by-package, view and reference mocks for every package.
async fn mount_api(mock: &MockServer, grant: impl Fn(&str) -> Grant) {
    let batch: Vec<Value> = PACKAGES
        .iter()
        .map(|(name, sevs)| {
            json!({
                "purl": purl(name),
                "patches": [{
                    "uuid": uuid(name), "purl": purl(name), "tier": "free",
                    "cveIds": [],
                    "ghsaIds": (0..sevs.len()).map(|i| format!("GHSA-{name}-{i}")).collect::<Vec<_>>(),
                    "severity": sevs.first().copied(),
                    "title": name,
                }]
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "packages": batch, "canAccessPaidPatches": false })),
        )
        .mount(mock)
        .await;
    let mut results = serde_json::Map::new();
    for (name, sevs) in PACKAGES {
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{name}(%40|@)1\\.0\\.0$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [{
                    "uuid": uuid(name), "purl": purl(name),
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "description": name, "license": "MIT", "tier": "free",
                    "vulnerabilities": vulns(name, sevs),
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(mock)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{}", uuid(name))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": uuid(name), "purl": purl(name),
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": git_sha256(&before(name)),
                    "afterHash": git_sha256(&after(name)),
                    "blobContent": b64(&after(name)),
                }},
                "vulnerabilities": vulns(name, sevs),
                "description": name, "license": "MIT", "tier": "free",
            })))
            .mount(mock)
            .await;
        let entry = match grant(name) {
            Grant::Granted => json!({
                "status": "granted",
                "url": hosted_url(name),
                "purl": purl(name),
                "artifacts": [{
                    "kind": "tarball", "url": hosted_url(name),
                    "integrity": { "sha512": format!("sha512-PATCHED{name}==") }
                }],
                "registryOverride": null
            }),
            Grant::Withdrawn => json!({ "status": "withdrawn" }),
            Grant::BadPurl => json!({
                "status": "granted", "url": hosted_url(name), "purl": "garbage",
                "artifacts": [], "registryOverride": null
            }),
        };
        results.insert(uuid(name), entry);
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
        .mount(mock)
        .await;
}

fn run(root: &Path, mock: &MockServer, args: &[&str]) -> (i32, String, String) {
    let uri = mock.uri();
    let mut argv = vec![
        "scan",
        "--yes",
        "--api-url",
        uri.as_str(),
        "--api-token",
        "fake-token",
        "--org",
        ORG,
    ];
    argv.extend_from_slice(args);
    let mut cmd = Command::new(binary());
    cmd.args(&argv).current_dir(root);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_json(root: &Path, mock: &MockServer, args: &[&str]) -> Value {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    let (code, stdout, stderr) = run(root, mock, &all);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

/// How many times the mock served `view/{uuid}`.
async fn view_fetches(mock: &MockServer, uuid: &str) -> usize {
    mock.received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with(&format!("/patches/view/{uuid}")))
        .count()
}

/// The packages whose hosted artifact the lockfile pins.
fn pinned(root: &Path) -> Vec<String> {
    let lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    ORDER
        .iter()
        .filter(|n| lock.contains(&hosted_url(n)))
        .map(|n| n.to_string())
        .collect()
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn deferred_names(v: &Value) -> Vec<String> {
    v["rollout"]["deferred"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            d["purl"]
                .as_str()
                .unwrap()
                .trim_start_matches("pkg:npm/")
                .trim_end_matches("@1.0.0")
                .to_string()
        })
        .collect()
}

fn counts(v: &Value) -> (u64, u64, u64, u64) {
    let c = &v["rollout"]["counts"];
    (
        c["new"].as_u64().unwrap(),
        c["deferred"].as_u64().unwrap(),
        c["upgrade"].as_u64().unwrap(),
        c["already"].as_u64().unwrap(),
    )
}

#[tokio::test]
async fn hosted_cap_rolls_nine_packages_forward_three_per_run() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let args = [
        "--mode",
        "hosted",
        "--max-new-patches",
        "3",
        "--patch-server-url",
        HOST,
    ];

    // The dry run predicts exactly what the wet run does.
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let mut dry_args = args.to_vec();
    dry_args.push("--dry-run");
    let dry = run_json(tmp.path(), &mock, &dry_args);
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "a dry run writes nothing"
    );

    let mut previous_lock = lock_before;
    let mut dry = dry;
    for run_no in 0..3 {
        let v = run_json(tmp.path(), &mock, &args);
        // The dry run before each wet run predicts it exactly.
        // (Warning details switch tense: "would be written" / "was written".)
        let decisions = |block: &Value| -> Value {
            let mut block = block.clone();
            let obj = block.as_object_mut().unwrap();
            obj.remove("dryRun");
            // `patches[]` rows switch tense too: `would_pin` / `pinned`.
            for row in obj["patches"].as_array_mut().unwrap() {
                if row["action"] == "would_pin" {
                    row["action"] = json!("pinned");
                }
            }
            let codes: Vec<Value> = obj["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w["code"].clone())
                .collect();
            obj.insert("warnings".into(), Value::Array(codes));
            block
        };
        let (predicted, actual) = (decisions(&dry["redirect"]), decisions(&v["redirect"]));
        assert_eq!(
            dry["rollout"],
            v["rollout"],
            "run {}: dry run == wet run",
            run_no + 1
        );
        assert_eq!(predicted, actual, "run {}: dry run == wet run", run_no + 1);
        if run_no == 0 {
            assert_eq!(
                v["rollout"]["deferred"][0],
                json!({
                    "purl": "pkg:npm/roll-c@1.0.0",
                    "uuids": [uuid("roll-c")],
                    "severity": "high",
                    "advisoryCount": 1,
                    "projects": [""],
                    "rank": 4,
                })
            );
        }
        assert_eq!(
            v["rollout"]["maxNewPatches"],
            json!({ "value": 3, "source": "flag" })
        );
        let done = 3 * run_no as u64;
        assert_eq!(
            counts(&v),
            (3, 6 - done, 0, done),
            "run {}: {v}",
            run_no + 1
        );
        assert_eq!(
            pinned(tmp.path()),
            names(&ORDER[..3 * (run_no + 1)]),
            "run {} pins the next three, most severe first",
            run_no + 1
        );
        assert_eq!(deferred_names(&v), names(&ORDER[3 * (run_no + 1)..]));
        let ranks: Vec<u64> = v["rollout"]["deferred"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["rank"].as_u64().unwrap())
            .collect();
        assert_eq!(ranks, (4..4 + ranks.len() as u64).collect::<Vec<_>>());
        let skipped: Vec<&str> = v["redirect"]["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["reason"].as_str().unwrap())
            .collect();
        assert!(skipped.iter().all(|r| *r == "rollout_deferred"));
        assert_eq!(skipped.len() as u64, 6 - done);
        assert_eq!(v["redirect"]["redirected"], 3 * (run_no as u64 + 1));
        previous_lock = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
        let mut next_dry = args.to_vec();
        next_dry.push("--dry-run");
        dry = run_json(tmp.path(), &mock, &next_dry);
    }

    let v = run_json(tmp.path(), &mock, &args);
    assert_eq!(counts(&v), (0, 0, 0, 9), "a fourth run adds nothing: {v}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        previous_lock,
        "a converged run is byte-stable"
    );
}

#[tokio::test]
async fn hosted_converges_even_when_the_patch_server_is_not_configured() {
    // Without --patch-server-url discovery does not recognize the test
    // host's pins; the rollout still treats a lockfile that names the
    // selected patch as recorded, so it never re-spends a slot on it.
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    for run_no in 1..=3 {
        run_json(
            tmp.path(),
            &mock,
            &["--mode", "hosted", "--max-new-patches", "3"],
        );
        assert_eq!(pinned(tmp.path()), names(&ORDER[..3 * run_no]));
    }
    let v = run_json(
        tmp.path(),
        &mock,
        &["--mode", "hosted", "--max-new-patches", "3"],
    );
    assert_eq!(counts(&v), (0, 0, 0, 9));
}

#[tokio::test]
async fn hosted_ineligible_top_ranked_patches_hold_no_slot() {
    let mock = MockServer::start().await;
    mount_api(&mock, |name| match name {
        "roll-e" => Grant::Withdrawn,
        "roll-b" => Grant::BadPurl,
        _ => Grant::Granted,
    })
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let v = run_json(
        tmp.path(),
        &mock,
        &[
            "--mode",
            "hosted",
            "--max-new-patches",
            "2",
            "--patch-server-url",
            HOST,
        ],
    );
    assert_eq!(pinned(tmp.path()), names(&["roll-g", "roll-c"]), "{v}");
    assert_eq!(counts(&v), (2, 5, 0, 0));
    assert_eq!(
        deferred_names(&v),
        names(&["roll-d", "roll-h", "roll-a", "roll-i", "roll-f"])
    );
    assert_eq!(
        v["rollout"]["deferred"][0]["rank"], 3,
        "ranks count eligible rows only"
    );
    let reasons: Vec<(&str, &str)> = v["redirect"]["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["purl"].as_str().unwrap(), s["reason"].as_str().unwrap()))
        .collect();
    assert!(
        reasons.contains(&("pkg:npm/roll-e@1.0.0", "withdrawn")),
        "{reasons:?}"
    );
    assert!(reasons.contains(&("garbage", "bad_purl")), "{reasons:?}");
}

#[tokio::test]
async fn a_failed_detail_lookup_admits_nothing_new_under_a_cap() {
    let mock = MockServer::start().await;
    // Mounted first, so it wins over the per-package mock below.
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*roll-i(%40|@)1\\.0\\.0$"
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let v = run_json(
        tmp.path(),
        &mock,
        &[
            "--mode",
            "hosted",
            "--max-new-patches",
            "3",
            "--patch-server-url",
            HOST,
        ],
    );
    assert_eq!(counts(&v), (0, 8, 0, 0), "{v}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before
    );
    let codes: Vec<&str> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"rollout_incomplete_lookup"), "{codes:?}");
    assert!(codes.contains(&"patch_details_failed"), "{codes:?}");
}

#[tokio::test]
async fn agent_cap_rolls_forward_and_upgrades_ignore_the_cap() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let recorded = |root: &Path| -> Vec<String> {
        let m: Value = serde_json::from_slice(
            &std::fs::read(root.join(".socket/manifest.json")).unwrap_or_else(|_| b"{}".to_vec()),
        )
        .unwrap();
        ORDER
            .iter()
            .filter(|n| m["patches"].get(purl(n)).is_some())
            .map(|n| n.to_string())
            .collect()
    };
    let args = ["--mode", "agent", "--max-new-patches", "3"];
    let dry = {
        let mut a = args.to_vec();
        a.push("--dry-run");
        run_json(tmp.path(), &mock, &a)
    };
    for run_no in 1..=3 {
        let v = run_json(tmp.path(), &mock, &args);
        if run_no == 1 {
            assert_eq!(dry["rollout"], v["rollout"], "dry run == wet run");
            let added: Vec<&str> = dry["apply"]["patches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["purl"].as_str().unwrap())
                .collect();
            assert_eq!(added.len(), 3, "{dry}");
        }
        assert_eq!(recorded(tmp.path()), names(&ORDER[..3 * run_no]), "{v}");
        for name in &ORDER[..3 * run_no] {
            assert_eq!(
                std::fs::read(tmp.path().join("node_modules").join(name).join("index.js")).unwrap(),
                after(name)
            );
        }
        for name in &ORDER[3 * run_no..] {
            assert_eq!(
                std::fs::read(tmp.path().join("node_modules").join(name).join("index.js")).unwrap(),
                before(name),
                "a deferred package is not touched"
            );
            assert_eq!(
                view_fetches(&mock, &uuid(name)).await,
                0,
                "a deferred patch is never downloaded: {name}"
            );
        }
    }
    let manifest = std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap();
    let v = run_json(tmp.path(), &mock, &args);
    assert_eq!(counts(&v), (0, 0, 0, 9));
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        manifest,
        "a converged run is byte-stable"
    );

    // A newer patch for an applied package is an UPGRADE: it lands even
    // with `--max-new-patches 0`, and is reported in `updates[]`.
    mock.reset().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let newer = "0000000a-1111-4111-8111-00000000000a";
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*roll-a(%40|@)1\\.0\\.0$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [
                { "uuid": newer, "purl": purl("roll-a"), "publishedAt": "2026-06-01T00:00:00Z",
                  "description": "newer", "license": "MIT", "tier": "free",
                  "vulnerabilities": vulns("roll-a", &["low"]) },
                { "uuid": uuid("roll-a"), "purl": purl("roll-a"), "publishedAt": "2026-01-01T00:00:00Z",
                  "description": "roll-a", "license": "MIT", "tier": "free",
                  "vulnerabilities": vulns("roll-a", &["low"]) }
            ],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{newer}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": newer, "purl": purl("roll-a"), "publishedAt": "2026-06-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(&before("roll-a")),
                "afterHash": git_sha256(&after("roll-a")),
                "blobContent": b64(&after("roll-a")),
            }},
            "vulnerabilities": vulns("roll-a", &["low"]),
            "description": "newer", "license": "MIT", "tier": "free",
        })))
        .mount(&mock)
        .await;
    let v = run_json(
        tmp.path(),
        &mock,
        &["--mode", "agent", "--max-new-patches", "0"],
    );
    assert_eq!(counts(&v), (0, 0, 1, 8), "{v}");
    assert_eq!(
        v["updates"],
        json!([{ "purl": purl("roll-a"), "oldUuid": uuid("roll-a"), "newUuid": newer }])
    );
    let m: Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(m["patches"][purl("roll-a")]["uuid"], newer);
}

#[tokio::test]
async fn vendored_cap_rolls_forward_three_per_run() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    for (name, severities) in PACKAGES {
        let view = json!({
            "uuid": uuid(name), "purl": purl(name), "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": { "beforeHash": git_sha256(&before(name)), "afterHash": git_sha256(&after(name)), "blobContent": b64(&after(name)) } },
            "vulnerabilities": vulns(name, severities), "description": name, "license": "MIT", "tier": "free"
        });
        prebuilt_common::mount_view(&mock, &view, None).await;
    }
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let vendored = |root: &Path| -> Vec<String> {
        let state: Value = std::fs::read(root.join(".socket/vendor/state.json"))
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
            .unwrap_or(json!({}));
        ORDER
            .iter()
            .filter(|n| state["entries"].get(purl(n)).is_some())
            .map(|n| n.to_string())
            .collect()
    };
    let args = ["--mode", "vendored", "--max-new-patches", "3"];
    let dry = {
        let mut a = args.to_vec();
        a.push("--dry-run");
        run_json(tmp.path(), &mock, &a)
    };
    assert!(
        !tmp.path().join(".socket").exists(),
        "a dry run writes nothing"
    );
    for run_no in 1..=3 {
        let v = run_json(tmp.path(), &mock, &args);
        if run_no == 1 {
            assert_eq!(dry["rollout"], v["rollout"], "dry run == wet run");
            assert_eq!(dry["vendor"]["patches"].as_array().unwrap().len(), 3);
        }
        assert_eq!(vendored(tmp.path()), names(&ORDER[..3 * run_no]), "{v}");
    }
    let lock = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let v = run_json(tmp.path(), &mock, &args);
    assert_eq!(counts(&v), (0, 0, 0, 9));
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock
    );
}

#[tokio::test]
async fn project_directories_share_one_budget_in_sorted_order() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    // `a/` sorts first and spends two slots; `b/` gets the one left, and
    // its copy of roll-b rides free (already admitted in `a/`).
    write_project(&tmp.path().join("a"), &["roll-a", "roll-b"]);
    write_project(
        &tmp.path().join("b"),
        &["roll-b", "roll-c", "roll-e", "roll-h"],
    );
    let (code, stdout, stderr) = run(
        tmp.path(),
        &mock,
        &[
            "--mode",
            "hosted",
            "--max-new-patches",
            "3",
            "--patch-server-url",
            HOST,
            // Given out of order: the directories are still visited sorted.
            "b",
            "a",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(pinned(&tmp.path().join("a")), names(&["roll-b", "roll-a"]));
    assert_eq!(pinned(&tmp.path().join("b")), names(&["roll-e", "roll-b"]));
    assert!(
        stdout.contains(
            "Rollout: 2 of 2 new patches applied (maxNewPatches=3 from --max-new-patches, \
             shared by this run's directories, 1 left)"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "Rollout: 2 of 4 new patches applied (maxNewPatches=3 from --max-new-patches, \
             shared by this run's directories, 0 left)"
        ),
        "b/ admits roll-b free and roll-e with the last slot: {stdout}"
    );
    assert!(
        stdout.contains("Next up: roll-c@1.0.0 (high), roll-h@1.0.0 (medium)"),
        "{stdout}"
    );
}

#[tokio::test]
async fn a_malformed_env_cap_is_a_usage_error_unless_the_flag_overrides_it() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &["roll-a", "roll-b"]);
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--json", "--api-url"])
        .arg(mock.uri())
        .args(["--api-token", "t", "--org", ORG])
        .current_dir(tmp.path());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_MAX_NEW_PATCHES", "lots");
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("SOCKET_MAX_NEW_PATCHES"));

    // A flag overrides the env value without reading it.
    let mut with_flag = Command::new(binary());
    with_flag
        .args([
            "scan",
            "--json",
            "--dry-run",
            "--max-new-patches",
            "1",
            "--api-url",
        ])
        .arg(mock.uri())
        .args(["--api-token", "t", "--org", ORG])
        .current_dir(tmp.path());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            with_flag.env_remove(&key);
        }
    }
    with_flag
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_MAX_NEW_PATCHES", "lots");
    let out = with_flag.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["rollout"]["maxNewPatches"],
        json!({ "value": 1, "source": "flag" })
    );

    cmd.env("SOCKET_MAX_NEW_PATCHES", "1");
    let out = cmd.output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["rollout"]["maxNewPatches"],
        json!({ "value": 1, "source": "env" })
    );
    assert_eq!(v["rollout"]["counts"]["new"], 1);

    cmd.args(["--max-new-patches", "none"]);
    let out = cmd.output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["rollout"]["maxNewPatches"],
        json!({ "value": null, "source": "flag" })
    );
    assert_eq!(
        v["rollout"]["counts"]["new"], 1,
        "roll-b landed on the capped run; roll-a now"
    );
}

/// Mount, ahead of `mount_api`'s answers, a newer superseding patch for
/// `name`: offered first by-package, granted, and viewable.
async fn mount_newer(mock: &MockServer, name: &str, newer: &str) {
    let sevs = PACKAGES.iter().find(|(n, _)| *n == name).unwrap().1;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*{name}(%40|@)1\\.0\\.0$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [
                { "uuid": newer, "purl": purl(name), "publishedAt": "2026-06-01T00:00:00Z",
                  "description": "newer", "license": "MIT", "tier": "free",
                  "vulnerabilities": vulns(name, sevs) },
                { "uuid": uuid(name), "purl": purl(name), "publishedAt": "2026-01-01T00:00:00Z",
                  "description": name, "license": "MIT", "tier": "free",
                  "vulnerabilities": vulns(name, sevs) }
            ],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(mock)
        .await;
    let mut results = serde_json::Map::new();
    for (n, _) in PACKAGES {
        results.insert(
            uuid(n),
            json!({ "status": "granted", "url": hosted_url(n), "purl": purl(n),
                "artifacts": [{ "kind": "tarball", "url": hosted_url(n),
                    "integrity": { "sha512": format!("sha512-PATCHED{n}==") } }],
                "registryOverride": null }),
        );
    }
    let newer_url = hosted_url(name).replace(&uuid(name), newer);
    results.insert(
        newer.to_string(),
        json!({ "status": "granted", "url": newer_url, "purl": purl(name),
            "artifacts": [{ "kind": "tarball", "url": newer_url,
                "integrity": { "sha512": "sha512-NEWER==" } }],
            "registryOverride": null }),
    );
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
        .with_priority(1)
        .mount(mock)
        .await;
}

#[tokio::test]
async fn hosted_upgrades_land_with_a_cap_of_zero() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let args = [
        "--mode",
        "hosted",
        "--max-new-patches",
        "3",
        "--patch-server-url",
        HOST,
    ];
    run_json(tmp.path(), &mock, &args);
    assert_eq!(pinned(tmp.path()), names(&ORDER[..3]));

    // roll-e (applied) gains a newer patch; six packages still wait.
    let newer = "0000000e-1111-4111-8111-00000000000e";
    mount_newer(&mock, "roll-e", newer).await;
    let v = run_json(
        tmp.path(),
        &mock,
        &[
            "--mode",
            "hosted",
            "--max-new-patches",
            "0",
            "--patch-server-url",
            HOST,
        ],
    );
    assert_eq!(counts(&v), (0, 6, 1, 2), "{v}");
    assert_eq!(
        v["updates"],
        json!([{ "purl": purl("roll-e"), "oldUuid": uuid("roll-e"), "newUuid": newer }])
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(newer), "the upgrade landed: {lock}");
    assert_eq!(
        pinned(tmp.path()),
        names(&["roll-b", "roll-g"]),
        "nothing new was added"
    );
}

#[tokio::test]
async fn a_failed_reference_lookup_defers_new_rows_instead_of_failing() {
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let args = [
        "--mode",
        "hosted",
        "--max-new-patches",
        "3",
        "--patch-server-url",
        HOST,
    ];

    let failing = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&failing)
        .await;
    mount_api(&failing, |_| Grant::Granted).await;

    // Every row is NEW: the failure only affects rows the incomplete lookup
    // defers anyway, so the capped run succeeds and writes nothing.
    let v = run_json(tmp.path(), &failing, &args);
    assert_eq!(counts(&v), (0, 9, 0, 0), "{v}");
    let codes: Vec<&str> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"rollout_reference_failed"), "{codes:?}");
    assert!(codes.contains(&"rollout_incomplete_lookup"), "{codes:?}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before
    );
    assert!(!tmp.path().join(".socket").exists(), "no lock, no state");

    // Without a cap the failure is the run's, as before.
    let (code, stdout, _) = run(tmp.path(), &failing, &["--json", "--mode", "hosted"]);
    assert_eq!(code, 1, "{stdout}");
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["status"], "error");
    assert!(
        v.get("rollout").is_none(),
        "no rollout block on an error envelope"
    );

    // With applied rows the failure affects them too: the run fails.
    let ok = MockServer::start().await;
    mount_api(&ok, |_| Grant::Granted).await;
    run_json(tmp.path(), &ok, &args);
    let mut failing_args = vec!["--json"];
    failing_args.extend_from_slice(&args);
    let (code, stdout, _) = run(tmp.path(), &failing, &failing_args);
    assert_eq!(code, 1, "{stdout}");
}

#[tokio::test]
async fn a_failed_detail_lookup_for_an_applied_package_does_not_freeze_new_rows() {
    let mock = MockServer::start().await;
    mount_api(&mock, |_| Grant::Granted).await;
    let tmp = tempfile::tempdir().unwrap();
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    write_project(tmp.path(), &names9);
    let args = [
        "--mode",
        "hosted",
        "--max-new-patches",
        "3",
        "--patch-server-url",
        HOST,
    ];
    run_json(tmp.path(), &mock, &args);
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*roll-e(%40|@)1\\.0\\.0$"
        )))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&mock)
        .await;
    let v = run_json(tmp.path(), &mock, &args);
    assert_eq!(
        counts(&v).0,
        3,
        "roll-e is recorded, so the next three land: {v}"
    );
    let codes: Vec<&str> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(!codes.contains(&"rollout_incomplete_lookup"), "{codes:?}");
    assert!(
        pinned(tmp.path()).contains(&"roll-e".to_string()),
        "the pin stays"
    );
}

/// #954: a vendored package gains a superseding patch whose prebuilt
/// artifact the service has not built (`pending_build`) or cannot serve
/// (`not_found`). `scan --mode vendored` keeps the vendored patch and
/// reports the upgrade as a skip, exit 0, the way hosted mode keeps its pin:
/// before the fix every re-run failed (`partial_failure`, exit 1) until the
/// server built the artifact.
#[tokio::test]
async fn vendored_upgrade_without_a_served_artifact_keeps_the_vendored_patch() {
    let newer = "0000000e-2222-4222-8222-00000000000e";
    let names9: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    for (status, code) in [
        ("pending_build", "vendor_prebuilt_pending"),
        ("not_found", "vendor_prebuilt_unavailable"),
    ] {
        let first = MockServer::start().await;
        mount_api(&first, |_| Grant::Granted).await;
        for (name, severities) in PACKAGES {
            let view = json!({
                "uuid": uuid(name), "purl": purl(name), "publishedAt": "2026-01-01T00:00:00Z",
                "files": { "package/index.js": { "beforeHash": git_sha256(&before(name)), "afterHash": git_sha256(&after(name)), "blobContent": b64(&after(name)) } },
                "vulnerabilities": vulns(name, severities), "description": name, "license": "MIT", "tier": "free"
            });
            prebuilt_common::mount_view(&first, &view, None).await;
        }
        let tmp = tempfile::tempdir().unwrap();
        write_project(tmp.path(), &names9);
        run_json(tmp.path(), &first, &["--mode", "vendored"]);
        let state_path = tmp.path().join(".socket/vendor/state.json");
        let state_before = std::fs::read(&state_path).unwrap();
        let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

        // A fresh API: roll-e's newer patch is offered and viewable, but
        // the service has no artifact for it.
        let second = MockServer::start().await;
        mount_api(&second, |_| Grant::Granted).await;
        let sevs = PACKAGES.iter().find(|(n, _)| *n == "roll-e").unwrap().1;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*roll-e(%40|@)1\\.0\\.0$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [
                    { "uuid": newer, "purl": purl("roll-e"), "publishedAt": "2026-06-01T00:00:00Z",
                      "description": "newer", "license": "MIT", "tier": "free",
                      "vulnerabilities": vulns("roll-e", sevs) },
                    { "uuid": uuid("roll-e"), "purl": purl("roll-e"), "publishedAt": "2026-01-01T00:00:00Z",
                      "description": "roll-e", "license": "MIT", "tier": "free",
                      "vulnerabilities": vulns("roll-e", sevs) }
                ],
                "canAccessPaidPatches": false,
            })))
            .with_priority(1)
            .mount(&second)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{newer}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": newer, "purl": purl("roll-e"),
                "publishedAt": "2026-06-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": git_sha256(&before("roll-e")),
                    "afterHash": git_sha256(&after("roll-e")),
                    "blobContent": b64(&after("roll-e")),
                }},
                "vulnerabilities": vulns("roll-e", sevs),
                "description": "newer", "license": "MIT", "tier": "free",
            })))
            .mount(&second)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/package")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "results": { newer: { "status": status } } })),
            )
            .with_priority(1)
            .mount(&second)
            .await;

        for _ in 0..2 {
            let (exit, stdout, stderr) =
                run(tmp.path(), &second, &["--json", "--mode", "vendored"]);
            assert_eq!(exit, 0, "{status}: stdout={stdout}\nstderr={stderr}");
            let v: Value = serde_json::from_str(stdout.trim()).unwrap();
            assert_eq!(v["status"], "success", "{status}: {v:#}");
            assert_eq!(v["vendor"]["summary"]["failed"], 0, "{status}: {v:#}");
            let vendor = v["vendor"].to_string();
            assert!(
                vendor.contains(code) && vendor.contains(newer),
                "{status}: the upgrade is a `{code}` skip: {v:#}"
            );
            assert_eq!(
                std::fs::read(&state_path).unwrap(),
                state_before,
                "{status}"
            );
            assert_eq!(
                std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
                lock_before,
                "{status}: the vendored wiring stays"
            );
        }

        // Human mode: no "Failed to vendor", exit 0.
        let (exit, stdout, stderr) = run(tmp.path(), &second, &["--mode", "vendored"]);
        assert_eq!(exit, 0, "{status}: stdout={stdout}\nstderr={stderr}");
        assert!(
            !stderr.contains("Failed to vendor") && !stdout.contains("failed"),
            "{status}: stdout={stdout}\nstderr={stderr}"
        );
    }
}
