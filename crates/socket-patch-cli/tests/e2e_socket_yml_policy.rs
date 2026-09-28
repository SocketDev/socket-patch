//! End-to-end tests for the socket.yml patch policy on disk scans: a
//! monorepo with several npm roots (plus a gem, for the ecosystem filter)
//! scanned through the real binary in hosted, agent and vendored mode
//! against a mock patch API that serves a small catalog.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use serial_test::serial;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ORG: &str = "test-org";
const TOKEN_SEGMENT: &str = "55555555-5555-4555-8555-555555555555";

#[derive(Clone)]
struct Patch {
    uuid: &'static str,
    name: &'static str,
    version: &'static str,
    eco: &'static str,
    severities: &'static [&'static str],
    published: &'static str,
}

impl Patch {
    fn purl(&self) -> String {
        format!("pkg:{}/{}@{}", self.eco, self.name, self.version)
    }

    fn hosted_url(&self) -> String {
        format!(
            "http://patch.test/patch/npm/{n}/{v}/{TOKEN_SEGMENT}/{u}/{n}-{v}.tgz",
            n = self.name,
            v = self.version,
            u = self.uuid
        )
    }

    fn vulnerabilities(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (i, severity) in self.severities.iter().enumerate() {
            map.insert(
                format!("GHSA-{}-{i:04}", &self.uuid[..4]),
                json!({"cves": [], "summary": "s", "severity": severity, "description": "d"}),
            );
        }
        Value::Object(map)
    }

    fn batch_severity(&self) -> &'static str {
        let rank = |s: &str| match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        self.severities.iter().copied().min_by_key(|s| rank(s)).unwrap_or("unknown")
    }
}

const P_ALPHA: Patch = Patch {
    uuid: "a1a1a1a1-0000-4000-8000-000000000001",
    name: "alpha",
    version: "1.0.0",
    eco: "npm",
    severities: &["critical"],
    published: "2024-01-01T00:00:00Z",
};
const P_BETA: Patch = Patch {
    uuid: "b1b1b1b1-0000-4000-8000-000000000001",
    name: "beta",
    version: "1.0.0",
    eco: "npm",
    severities: &["low"],
    published: "2024-01-01T00:00:00Z",
};
const P_LEFTPAD: Patch = Patch {
    uuid: "c1c1c1c1-0000-4000-8000-000000000001",
    name: "left-pad",
    version: "1.0.0",
    eco: "npm",
    severities: &["high"],
    published: "2024-01-01T00:00:00Z",
};
const P_GAMMA: Patch = Patch {
    uuid: "d1d1d1d1-0000-4000-8000-000000000001",
    name: "gamma",
    version: "1.0.0",
    eco: "npm",
    severities: &["high"],
    published: "2024-01-01T00:00:00Z",
};
const P_DELTA: Patch = Patch {
    uuid: "e1e1e1e1-0000-4000-8000-000000000001",
    name: "delta",
    version: "1.0.0",
    eco: "npm",
    severities: &["high"],
    published: "2024-01-01T00:00:00Z",
};
const P_RACK: Patch = Patch {
    uuid: "f1f1f1f1-0000-4000-8000-000000000001",
    name: "rack",
    version: "1.0.0",
    eco: "gem",
    severities: &["high"],
    published: "2024-01-01T00:00:00Z",
};
/// A merged (two-advisory) low patch for alpha: ranks first while no floor
/// applies.
const P_ALPHA_MERGED_LOW: Patch = Patch {
    uuid: "a2a2a2a2-0000-4000-8000-000000000002",
    name: "alpha",
    version: "1.0.0",
    eco: "npm",
    severities: &["low", "low"],
    published: "2024-02-01T00:00:00Z",
};
/// A newer merged patch for alpha (supersedes P_ALPHA).
const P_ALPHA_MERGED_NEW: Patch = Patch {
    uuid: "a3a3a3a3-0000-4000-8000-000000000003",
    name: "alpha",
    version: "1.0.0",
    eco: "npm",
    severities: &["critical", "high"],
    published: "2024-03-01T00:00:00Z",
};

fn catalog() -> Vec<Patch> {
    vec![P_ALPHA, P_BETA, P_LEFTPAD, P_GAMMA, P_DELTA, P_RACK]
}

fn orig_index(name: &str) -> String {
    format!("module.exports = () => '{name} orig';\n")
}

fn patched_index(name: &str) -> String {
    format!("module.exports = () => '{name} patched';\n")
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

/// Serve `patches` from every patches route scan uses.
async fn mount_api(server: &MockServer, patches: Vec<Patch>) {
    let by_purl = {
        let mut m: BTreeMap<String, Vec<Patch>> = BTreeMap::new();
        for p in &patches {
            m.entry(p.purl()).or_default().push(p.clone());
        }
        m
    };
    let batch_map = by_purl.clone();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let mut packages = Vec::new();
            for c in body["components"].as_array().unwrap() {
                let purl = c["purl"].as_str().unwrap();
                if let Some(list) = batch_map.get(purl) {
                    let infos: Vec<Value> = list
                        .iter()
                        .map(|p| {
                            json!({
                                "uuid": p.uuid, "purl": purl, "tier": "free", "cveIds": [],
                                "ghsaIds": p.vulnerabilities().as_object().unwrap().keys().collect::<Vec<_>>(),
                                "severity": p.batch_severity(), "title": "fixture"
                            })
                        })
                        .collect();
                    packages.push(json!({"purl": purl, "patches": infos}));
                }
            }
            ResponseTemplate::new(200).set_body_json(json!({"packages": packages, "canAccessPaidPatches": false}))
        })
        .mount(server)
        .await;
    let detail_map = by_purl.clone();
    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
        .respond_with(move |req: &Request| {
            let raw = req.url.path().rsplit('/').next().unwrap();
            let purl = percent_decode(raw);
            let list: Vec<Value> = detail_map
                .get(&purl)
                .into_iter()
                .flatten()
                .map(|p| {
                    json!({
                        "uuid": p.uuid, "purl": purl, "publishedAt": p.published,
                        "description": "x", "license": "MIT", "tier": "free",
                        "vulnerabilities": p.vulnerabilities()
                    })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({"patches": list, "canAccessPaidPatches": false}))
        })
        .mount(server)
        .await;
    let by_uuid: BTreeMap<String, Patch> = patches.iter().map(|p| (p.uuid.to_string(), p.clone())).collect();
    let refs = by_uuid.clone();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let mut results = serde_json::Map::new();
            for uuid in body["uuids"].as_array().unwrap() {
                let uuid = uuid.as_str().unwrap();
                if let Some(p) = refs.get(uuid) {
                    results.insert(
                        uuid.to_string(),
                        json!({
                            "status": "granted", "url": p.hosted_url(), "purl": p.purl(),
                            "artifacts": [{"kind": "tarball", "url": p.hosted_url(),
                                           "integrity": {"sha512": format!("sha512-PATCHED{}==", &p.uuid[..8])}}],
                            "registryOverride": null
                        }),
                    );
                }
            }
            ResponseTemplate::new(200).set_body_json(json!({"results": results}))
        })
        .mount(server)
        .await;
    let views = by_uuid;
    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/view/.+$")))
        .respond_with(move |req: &Request| {
            use base64::Engine as _;
            let uuid = req.url.path().rsplit('/').next().unwrap();
            let Some(p) = views.get(uuid) else {
                return ResponseTemplate::new(404);
            };
            let before = compute_git_sha256_from_bytes(orig_index(p.name).as_bytes());
            let after_bytes = patched_index(p.name);
            let after = compute_git_sha256_from_bytes(after_bytes.as_bytes());
            ResponseTemplate::new(200).set_body_json(json!({
                "uuid": p.uuid, "purl": p.purl(), "publishedAt": p.published,
                "files": {"package/index.js": {
                    "beforeHash": before, "afterHash": after,
                    "blobContent": base64::engine::general_purpose::STANDARD.encode(after_bytes.as_bytes())
                }},
                "vulnerabilities": p.vulnerabilities(),
                "description": "x", "license": "MIT", "tier": "free"
            }))
        })
        .mount(server)
        .await;
}

/// An npm project root: package.json, installed copies, a v3 lockfile.
fn write_npm_root(dir: &Path, deps: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    let dep_map: BTreeMap<&str, &str> = deps.iter().map(|d| (*d, "1.0.0")).collect();
    std::fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&json!({"name": "consumer", "version": "0.0.0", "dependencies": dep_map}))
            .unwrap(),
    )
    .unwrap();
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        json!({"name": "consumer", "version": "0.0.0", "dependencies": dep_map}),
    );
    for name in deps {
        let pkg = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("package.json"), format!(r#"{{ "name": "{name}", "version": "1.0.0" }}"#)).unwrap();
        std::fs::write(pkg.join("index.js"), orig_index(name)).unwrap();
        packages.insert(
            format!("node_modules/{name}"),
            json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                "integrity": "sha512-UPSTREAMupstream=="
            }),
        );
    }
    let lock = json!({
        "name": "consumer", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
        "packages": packages
    });
    std::fs::write(dir.join("package-lock.json"), serde_json::to_string_pretty(&lock).unwrap() + "\n").unwrap();
}

fn write_gem(dir: &Path, name: &str, version: &str) {
    std::fs::create_dir_all(dir.join("vendor/bundle/ruby/3.0.0/gems").join(format!("{name}-{version}")).join("lib"))
        .unwrap();
}

/// The monorepo: `services/web` (alpha, beta, left-pad + a gem),
/// `services/legacy` (gamma), `services/test` (delta).
struct Repo {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Repo {
    fn new(socket_yml: Option<&str>) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap().join("repo");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write_npm_root(&root.join("services/web"), &["alpha", "beta", "left-pad"]);
        write_gem(&root.join("services/web"), "rack", "1.0.0");
        write_npm_root(&root.join("services/legacy"), &["gamma"]);
        write_npm_root(&root.join("services/test"), &["delta"]);
        if let Some(text) = socket_yml {
            std::fs::write(root.join("socket.yml"), text).unwrap();
        }
        Self { _tmp: tmp, root }
    }

    fn dir(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn lock(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir(rel).join("package-lock.json")).unwrap()
    }

    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    walk(&path, root, out);
                } else {
                    let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                    out.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }
}

/// Run the binary with ambient `SOCKET_*` scrubbed; `(code, stdout, stderr)`.
fn run_cli(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env_remove("GIT_CEILING_DIRECTORIES").env_remove("VIRTUAL_ENV");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    // The fixture's hosted pins name this origin; it makes them recorded.
    cmd.env("SOCKET_PATCH_SERVER_URL", "http://patch.test");
    let absent = cwd.join(".absent-npm-config");
    for var in [
        "NPM_CONFIG_USERCONFIG",
        "npm_config_userconfig",
        "NPM_CONFIG_GLOBALCONFIG",
        "npm_config_globalconfig",
        "PREFIX",
    ] {
        cmd.env(var, &absent);
    }
    cmd.env("NPM_CONFIG_ALLOW_REMOTE", "").env("npm_config_allow_remote", "");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scan(cwd: &Path, api: &str, extra: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut args = vec![
        "scan",
        "--yes",
        "--cwd",
        cwd.to_str().unwrap(),
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--batch-size",
        "100",
    ];
    args.extend_from_slice(extra);
    run_cli(cwd, &args, env)
}

fn scan_json(cwd: &Path, api: &str, extra: &[&str], env: &[(&str, &str)]) -> (i32, Value) {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = scan(cwd, api, &args, env);
    let doc: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e})\nstdout=\n{stdout}\nstderr=\n{stderr}"));
    (code, doc)
}

fn filtered(doc: &Value) -> Vec<(Option<String>, String)> {
    doc["policy"]["filtered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["purl"].as_str().map(str::to_string), f["reason"].as_str().unwrap().to_string()))
        .collect()
}

fn filtered_reason<'a>(doc: &'a Value, purl: &str) -> &'a Value {
    doc["policy"]["filtered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["purl"] == purl)
        .unwrap_or_else(|| panic!("{purl} not in policy.filtered: {:#}", doc["policy"]))
}

fn warning_codes(doc: &Value) -> Vec<String> {
    doc["warnings"]
        .as_array()
        .map(|w| w.iter().filter_map(|e| e["code"].as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Hosted
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hosted_filters_by_ecosystem_package_and_severity() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some(
        "version: 2\npatches:\n  ecosystems: [npm]\n  ignorePackages: [\"pkg:npm/left-pad\"]\n  minSeverity: high\n",
    ));
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");

    let lock = repo.lock("services/web");
    assert!(lock.contains(&P_ALPHA.hosted_url()), "alpha is patched:\n{lock}");
    assert!(!lock.contains(P_BETA.uuid), "beta is below the floor:\n{lock}");
    assert!(!lock.contains(P_LEFTPAD.uuid), "left-pad is ignored:\n{lock}");

    let policy = &doc["policy"];
    assert_eq!(policy["source"], "file");
    assert_eq!(policy["path"], "socket.yml");
    assert_eq!(policy["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(policy["enabled"], true);
    assert_eq!(policy["minSeverity"], json!({"value": "high", "source": "file"}));
    let beta = filtered_reason(&doc, "pkg:npm/beta@1.0.0");
    assert_eq!(beta["reason"], "policy_severity");
    assert_eq!(beta["detail"], "low < high");
    assert_eq!(beta["uuid"], P_BETA.uuid);
    assert_eq!(beta["project"], "services/web");
    let left_pad = filtered_reason(&doc, "pkg:npm/left-pad@1.0.0");
    assert_eq!(left_pad["reason"], "policy_package_ignored");
    assert_eq!(left_pad["uuid"], Value::Null, "filtered before any patch lookup");
    assert_eq!(left_pad["detail"], "pkg:npm/left-pad (patches.ignorePackages)");
    let rack = filtered_reason(&doc, "pkg:gem/rack@1.0.0");
    assert_eq!(rack["reason"], "policy_ecosystem");
    assert_eq!(policy["counts"]["filtered"], 3);
    assert_eq!(policy["counts"]["retained"], 0);
    // Packages filtered before lookup are never queried.
    let reqs = server.received_requests().await.unwrap();
    for r in &reqs {
        if r.url.path().ends_with("/patches/batch") {
            let body = String::from_utf8_lossy(&r.body);
            assert!(!body.contains("left-pad") && !body.contains("rack"), "{body}");
        }
    }
    assert_eq!(doc["redirect"]["redirected"], 1, "{:#}", doc["redirect"]);
}

#[tokio::test]
#[serial]
async fn hosted_dry_run_makes_the_same_decisions_and_writes_nothing() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  minSeverity: high\n  ecosystems: [npm]\n"));
    let before = repo.snapshot();
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.snapshot(), before, "a dry run changes no bytes");
    assert_eq!(doc["redirect"]["redirected"], 2, "alpha and left-pad: {:#}", doc["redirect"]);
    assert_eq!(filtered_reason(&doc, "pkg:npm/beta@1.0.0")["reason"], "policy_severity");
}

#[tokio::test]
#[serial]
async fn path_globs_apply_default_ignores_and_ignore_paths_human() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  ignorePaths: [\"/services/legacy/\"]\n"));
    let legacy = repo.lock("services/legacy");
    let test_lock = repo.lock("services/test");
    let (code, stdout, stderr) = scan(&repo.root, &server.uri(), &["services/*"], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(repo.lock("services/web").contains(&P_ALPHA.hosted_url()));
    assert_eq!(repo.lock("services/legacy"), legacy, "ignored by patches.ignorePaths");
    assert_eq!(repo.lock("services/test"), test_lock, "a discovered test/ root is a built-in ignore");
    assert!(stdout.contains("Policy (socket.yml)"), "{stdout}");

    // Named literally, the test/ root is explicit: defaults do not apply.
    let (code, stdout, stderr) = scan(&repo.root, &server.uri(), &["services/test"], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(repo.lock("services/test").contains(&P_DELTA.hosted_url()));
}

#[tokio::test]
#[serial]
async fn include_paths_limit_roots() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  includePaths: [\"/services/legacy/\"]\n"));
    let web = repo.lock("services/web");
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.lock("services/web"), web);
    assert_eq!(
        filtered(&doc),
        vec![(None, "policy_path_not_included".to_string())],
        "a root filtered as a whole is one entry with purl null"
    );
    let (code, doc) = scan_json(&repo.dir("services/legacy"), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert!(repo.lock("services/legacy").contains(&P_GAMMA.hosted_url()));
    assert_eq!(doc["policy"]["counts"]["filtered"], 0);
}

#[tokio::test]
#[serial]
async fn invalid_file_fails_closed_before_any_request_or_write() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  minSeverty: high\n"));
    let before = repo.snapshot();
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &[], &[]);
    assert_eq!(code, 1);
    assert_eq!(doc["status"], "error");
    assert_eq!(doc["errorCode"], "socket_yml_invalid");
    let message = doc["error"].as_str().unwrap();
    assert!(message.contains("patches.minSeverty"), "{message}");
    assert!(message.contains("did you mean `minSeverity`"), "{message}");
    assert!(message.contains("--no-socket-yml"), "{message}");
    assert!(doc.get("policy").is_none());
    assert_eq!(repo.snapshot(), before);
    assert!(server.received_requests().await.unwrap().is_empty(), "no request before the policy loads");

    // Human output names the code on stderr, same exit code.
    let (code, _, stderr) = scan(&repo.dir("services/web"), &server.uri(), &[], &[]);
    assert_eq!(code, 1);
    assert!(stderr.contains("socket_yml_invalid"), "{stderr}");

    // --no-socket-yml (and its env var) skips the file.
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &["--no-socket-yml", "--dry-run"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["policy"]["source"], "bypassed");
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &["--dry-run"], &[("SOCKET_NO_SOCKET_YML", "1")]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["policy"]["source"], "bypassed");
}

#[tokio::test]
#[serial]
async fn both_files_disagreeing_is_ambiguous() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  maxNewPatches: 1\n"));
    std::fs::write(repo.root.join("socket.yaml"), "version: 2\npatches:\n  maxNewPatches: 2\n").unwrap();
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &[], &[]);
    assert_eq!(code, 1);
    assert_eq!(doc["errorCode"], "socket_yml_ambiguous");
}

#[tokio::test]
#[serial]
async fn severity_flag_and_env_override_the_file() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  minSeverity: high\n"));
    let web = repo.dir("services/web");
    let (code, doc) = scan_json(&web, &server.uri(), &["--dry-run", "--min-severity", "none"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["policy"]["minSeverity"], json!({"value": null, "source": "flag"}));
    assert_eq!(doc["redirect"]["redirected"], 3, "beta too once the floor is lifted");

    let (code, doc) = scan_json(&web, &server.uri(), &["--dry-run"], &[("SOCKET_MIN_SEVERITY", "critical")]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(doc["policy"]["minSeverity"], json!({"value": "critical", "source": "env"}));
    assert_eq!(doc["redirect"]["redirected"], 1);

    // The flag beats the env; an empty env value is unset.
    let (_, doc) = scan_json(&web, &server.uri(), &["--dry-run", "--min-severity", "moderate"], &[("SOCKET_MIN_SEVERITY", "critical")]);
    assert_eq!(doc["policy"]["minSeverity"], json!({"value": "medium", "source": "flag"}));
    let (_, doc) = scan_json(&web, &server.uri(), &["--dry-run"], &[("SOCKET_MIN_SEVERITY", "")]);
    assert_eq!(doc["policy"]["minSeverity"], json!({"value": "high", "source": "file"}));

    // Malformed values are usage errors.
    let (code, _, stderr) = scan(&web, &server.uri(), &["--min-severity", "severe"], &[]);
    assert_eq!(code, 2, "{stderr}");
    let (code, _, stderr) = scan(&web, &server.uri(), &[], &[("SOCKET_MIN_SEVERITY", "severe")]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("SOCKET_MIN_SEVERITY"), "{stderr}");
}

#[tokio::test]
#[serial]
async fn narrowing_after_a_hosted_patch_leaves_the_pin_byte_identical() {
    let server = MockServer::start().await;
    mount_api(&server, vec![P_ALPHA]).await;
    let repo = Repo::new(None);
    let web = repo.dir("services/web");
    let (code, doc) = scan_json(&web, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let pinned = repo.lock("services/web");
    assert!(pinned.contains(&P_ALPHA.hosted_url()));

    // A newer merged patch appears, and the repo now ignores alpha.
    std::fs::write(repo.root.join("socket.yml"), "version: 2\npatches:\n  ignorePackages: [alpha]\n").unwrap();
    server.reset().await;
    mount_api(&server, vec![P_ALPHA, P_ALPHA_MERGED_NEW]).await;
    let (code, doc) = scan_json(&web, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.lock("services/web"), pinned, "retained: not upgraded, not removed");
    let retained = &doc["policy"]["retained"][0];
    assert_eq!(retained["purl"], "pkg:npm/alpha@1.0.0");
    assert_eq!(retained["recordedUuid"], P_ALPHA.uuid);
    assert_eq!(retained["reason"], "policy_package_ignored");
    assert_eq!(retained["upgradeAvailable"], true);
    assert_eq!(retained["project"], "services/web");
    assert_eq!(doc["policy"]["counts"]["retained"], 1);

    // Same with the whole root excluded, and with enabled: false.
    for yml in [
        "version: 2\npatches:\n  ignorePaths: [\"services/\"]\n",
        "version: 2\npatches:\n  enabled: false\n",
    ] {
        std::fs::write(repo.root.join("socket.yml"), yml).unwrap();
        let (code, doc) = scan_json(&web, &server.uri(), &[], &[]);
        assert_eq!(code, 0, "{doc:#}");
        assert_eq!(repo.lock("services/web"), pinned, "{yml}");
        assert_eq!(doc["policy"]["retained"][0]["purl"], "pkg:npm/alpha@1.0.0", "{yml}: {:#}", doc["policy"]);
    }
}

#[tokio::test]
#[serial]
async fn enabled_false_reports_and_writes_nothing() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  enabled: false\n"));
    let before = repo.snapshot();
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.snapshot(), before);
    assert_eq!(doc["policy"]["enabled"], false);
    assert!(warning_codes(&doc).contains(&"patches_disabled".to_string()), "{doc:#}");
    let reasons: Vec<String> = filtered(&doc).into_iter().map(|(_, r)| r).collect();
    assert!(!reasons.is_empty() && reasons.iter().all(|r| r == "policy_disabled"), "{reasons:?}");
    assert_eq!(doc["redirect"]["redirected"], 0);
}

#[tokio::test]
#[serial]
async fn recorded_merged_patch_below_a_new_floor_is_kept() {
    let server = MockServer::start().await;
    mount_api(&server, vec![P_ALPHA_MERGED_LOW, P_ALPHA]).await;
    let repo = Repo::new(None);
    let web = repo.dir("services/web");
    let (code, doc) = scan_json(&web, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let pinned = repo.lock("services/web");
    assert!(pinned.contains(&P_ALPHA_MERGED_LOW.hosted_url()), "merged ranks first:\n{pinned}");

    std::fs::write(repo.root.join("socket.yml"), "version: 2\npatches:\n  minSeverity: high\n").unwrap();
    let (code, doc) = scan_json(&web, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.lock("services/web"), pinned, "the floor never replaces the recorded merged patch");
}

#[tokio::test]
#[serial]
async fn path_outside_the_repo_is_a_usage_error() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(None);
    let outside = repo.root.parent().unwrap().join("elsewhere");
    write_npm_root(&outside, &["alpha"]);
    let (code, _, stderr) = scan(&repo.dir("services"), &server.uri(), &["web", "../../elsewhere"], &[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("outside the repository root"), "{stderr}");
}

#[tokio::test]
#[serial]
async fn project_ignore_paths_is_honored_without_a_patches_block() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\nprojectIgnorePaths:\n  - \"services/legacy/**\"\n"));
    let legacy = repo.lock("services/legacy");
    let (code, doc) = scan_json(&repo.dir("services/legacy"), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.lock("services/legacy"), legacy);
    let entry = &doc["policy"]["filtered"][0];
    assert_eq!(entry["reason"], "policy_path_excluded");
    assert_eq!(entry["detail"], "services/legacy/** (projectIgnorePaths)");

    // A malformed projectIgnorePaths without a patches block only warns.
    std::fs::write(repo.root.join("socket.yml"), "version: 2\nprojectIgnorePaths: {a: 1}\n").unwrap();
    let (code, doc) = scan_json(&repo.dir("services/legacy"), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert!(warning_codes(&doc).contains(&"socket_yml_ignored_value".to_string()), "{doc:#}");
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn agent_mode_applies_only_admitted_patches() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some(
        "version: 2\npatches:\n  minSeverity: high\n  ecosystems: [npm]\n  ignorePackages: [\"pkg:npm/left-pad\"]\n",
    ));
    let web = repo.dir("services/web");
    let (code, doc) = scan_json(&web, &server.uri(), &["--mode", "agent", "--dry-run"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let planned: Vec<&str> = doc["apply"]["patches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["purl"].as_str().unwrap())
        .collect();
    assert_eq!(planned, ["pkg:npm/alpha@1.0.0"], "{doc:#}");

    let (code, doc) = scan_json(&web, &server.uri(), &["--mode", "agent"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(web.join(".socket/manifest.json")).unwrap()).unwrap();
    let keys: Vec<&String> = manifest["patches"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["pkg:npm/alpha@1.0.0"]);
    assert_eq!(
        std::fs::read_to_string(web.join("node_modules/alpha/index.js")).unwrap(),
        patched_index("alpha")
    );
    assert_eq!(std::fs::read_to_string(web.join("node_modules/beta/index.js")).unwrap(), orig_index("beta"));
}

#[tokio::test]
#[serial]
async fn agent_mode_retains_a_recorded_patch_the_policy_now_excludes() {
    let server = MockServer::start().await;
    mount_api(&server, vec![P_ALPHA]).await;
    let repo = Repo::new(None);
    let web = repo.dir("services/web");
    let (code, doc) = scan_json(&web, &server.uri(), &["--mode", "agent"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let manifest_before = std::fs::read(web.join(".socket/manifest.json")).unwrap();
    let installed_before = std::fs::read(web.join("node_modules/alpha/index.js")).unwrap();

    std::fs::write(repo.root.join("socket.yml"), "version: 2\npatches:\n  ecosystems: [pypi]\n").unwrap();
    server.reset().await;
    mount_api(&server, vec![P_ALPHA, P_ALPHA_MERGED_NEW]).await;
    let (code, doc) = scan_json(&web, &server.uri(), &["--mode", "agent"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(std::fs::read(web.join(".socket/manifest.json")).unwrap(), manifest_before);
    assert_eq!(std::fs::read(web.join("node_modules/alpha/index.js")).unwrap(), installed_before);
    assert_eq!(doc["policy"]["retained"][0]["reason"], "policy_ecosystem");
    assert_eq!(doc["policy"]["retained"][0]["upgradeAvailable"], true);
}

// ---------------------------------------------------------------------------
// Vendored
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn vendored_dry_run_previews_only_admitted_patches() {
    let server = MockServer::start().await;
    mount_api(&server, catalog()).await;
    let repo = Repo::new(Some("version: 2\npatches:\n  packages: [\"pkg:npm/beta\", \"pkg:npm/left-pad\"]\n  minSeverity: medium\n"));
    let before = repo.snapshot();
    let (code, doc) = scan_json(&repo.dir("services/web"), &server.uri(), &["--mode", "vendored", "--dry-run"], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(repo.snapshot(), before);
    let previewed: Vec<&str> = doc["vendor"]["patches"]
        .as_array()
        .unwrap_or_else(|| panic!("{doc:#}"))
        .iter()
        .filter_map(|p| p["purl"].as_str())
        .collect();
    assert_eq!(previewed, ["pkg:npm/left-pad@1.0.0"], "{doc:#}");
    assert_eq!(filtered_reason(&doc, "pkg:npm/alpha@1.0.0")["reason"], "policy_package_not_listed");
    assert_eq!(filtered_reason(&doc, "pkg:npm/beta@1.0.0")["reason"], "policy_severity");
}
