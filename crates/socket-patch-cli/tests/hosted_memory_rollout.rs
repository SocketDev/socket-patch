//! The staged rollout (`maxNewPatches`) in the in-memory hosted engine,
//! held to the disk `scan --mode hosted --json --max-new-patches` run: one
//! root admits and defers the same rows run after run until converged; two
//! roots show memory's run-wide budget next to disk's per-directory one
//! (they differ by design, §5.2); a committed manifest, vendor ledger or
//! lockfile pin counts as recorded, never NEW.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use socket_patch_cli::hosted_memory::{HostedScanOptions, HostedScanOutput, MaxNewPatchesOption};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[path = "hosted_memory_common/mod.rs"]
mod common;

use common::{build_input, run_disk_args, run_disk_with, run_engine, ORG};

const TOKEN: &str = "22222222-2222-4222-8222-222222222222";

/// `(name, severities)`: one advisory per severity.
const PACKAGES: [(&str, &[&str]); 5] = [
    ("mem-a", &["low"]),
    ("mem-b", &["critical"]),
    ("mem-c", &["high"]),
    ("mem-d", &["medium"]),
    ("mem-e", &["critical", "high"]),
];

/// Most severe first: severity, then advisory count, then name.
const ORDER: [&str; 5] = ["mem-e", "mem-b", "mem-c", "mem-d", "mem-a"];

fn uuid(name: &str) -> String {
    let n = PACKAGES.iter().position(|(p, _)| *p == name).unwrap() + 1;
    format!("{n:08x}-3333-4333-8333-{n:012x}")
}

fn purl(name: &str) -> String {
    format!("pkg:npm/{name}@1.0.0")
}

fn url(name: &str) -> String {
    format!(
        "https://patch.socket.dev/patch/npm/{name}/1.0.0/{TOKEN}/{}/{name}-1.0.0.tgz",
        uuid(name)
    )
}

fn name_of(purl: &str) -> Option<&'static str> {
    PACKAGES
        .iter()
        .map(|(n, _)| *n)
        .find(|n| purl.contains(&format!("{n}@")) || purl.contains(&format!("{n}%40")))
}

fn vulns(name: &str) -> Value {
    let sevs = PACKAGES.iter().find(|(n, _)| *n == name).unwrap().1;
    let mut map = serde_json::Map::new();
    for (i, sev) in sevs.iter().enumerate() {
        map.insert(
            format!("GHSA-{name}-{i}"),
            json!({ "cves": [], "summary": "s", "severity": sev, "description": "d" }),
        );
    }
    Value::Object(map)
}

struct Batch;
impl Respond for Batch {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let packages: Vec<Value> = body["components"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| {
                let p = c["purl"].as_str()?;
                let name = name_of(p)?;
                Some(json!({ "purl": p, "patches": [{
                    "uuid": uuid(name), "purl": p, "tier": "free", "cveIds": [],
                    "ghsaIds": [format!("GHSA-{name}-0")], "severity": "high", "title": name
                }]}))
            })
            .collect();
        ResponseTemplate::new(200)
            .set_body_json(json!({ "packages": packages, "canAccessPaidPatches": false }))
    }
}

struct ByPackage;
impl Respond for ByPackage {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let patches: Vec<Value> = name_of(request.url.path())
            .map(|name| {
                vec![json!({
                    "uuid": uuid(name), "purl": purl(name),
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": name, "license": "MIT", "tier": "free",
                    "vulnerabilities": vulns(name),
                })]
            })
            .unwrap_or_default();
        ResponseTemplate::new(200)
            .set_body_json(json!({ "patches": patches, "canAccessPaidPatches": false }))
    }
}

struct References;
impl Respond for References {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let mut results = serde_json::Map::new();
        for requested in body["uuids"].as_array().into_iter().flatten() {
            let Some(requested) = requested.as_str() else {
                continue;
            };
            if let Some((name, _)) = PACKAGES.iter().find(|(n, _)| uuid(n) == requested) {
                results.insert(
                    requested.to_string(),
                    json!({
                        "status": "granted", "url": url(name), "purl": null,
                        "artifacts": [{ "kind": "tarball", "url": url(name),
                            "integrity": { "sha512": format!("sha512-PATCHED{name}==") } }],
                        "registryOverride": null
                    }),
                );
            }
        }
        ResponseTemplate::new(200).set_body_json(json!({ "results": results }))
    }
}

struct View;
impl Respond for View {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let requested = request.url.path().rsplit('/').next().unwrap_or("");
        match PACKAGES.iter().find(|(n, _)| uuid(n) == requested) {
            Some((name, _)) => ResponseTemplate::new(200).set_body_json(json!({
                "uuid": uuid(name), "purl": purl(name), "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": { "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64) } },
                "vulnerabilities": vulns(name),
                "description": name, "license": "MIT", "tier": "free"
            })),
            None => ResponseTemplate::new(404),
        }
    }
}

async fn mount(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(Batch)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ByPackage)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(References)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/view/.+$")))
        .respond_with(View)
        .mount(server)
        .await;
}

/// A v3 package-lock at `dir` locking `names` (no install needed: both
/// engines read the lock).
fn lock(files: &mut BTreeMap<String, Vec<u8>>, dir: &str, names: &[&str]) {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let deps: serde_json::Map<String, Value> = names
        .iter()
        .map(|n| (n.to_string(), json!("1.0.0")))
        .collect();
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        json!({ "name": "c", "version": "0.0.0", "dependencies": deps }),
    );
    for n in names {
        packages.insert(
            format!("node_modules/{n}"),
            json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/{n}/-/{n}-1.0.0.tgz"),
                "integrity": "sha512-UPSTREAM=="
            }),
        );
    }
    let mut text = serde_json::to_vec_pretty(&json!({
        "name": "c", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
        "packages": packages
    }))
    .unwrap();
    text.push(b'\n');
    files.insert(format!("{prefix}package-lock.json"), text);
    files.insert(
        format!("{prefix}package.json"),
        serde_json::to_vec(&json!({ "name": "c", "version": "0.0.0", "dependencies": deps }))
            .unwrap(),
    );
}

fn options(cap: Option<u32>) -> HostedScanOptions {
    HostedScanOptions {
        org_slug: ORG.to_string(),
        max_new_patches: cap.map(|n| MaxNewPatchesOption(Some(n))),
        ..HostedScanOptions::default()
    }
}

async fn memory(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
    o: HostedScanOptions,
) -> HostedScanOutput {
    run_engine(server, build_input(files, &[], o)).await
}

/// [`memory`] through two-phase path selection, as a host with a root
/// socket.yml runs it: select with the policy text, fetch what selection
/// asks for, then pass its `policyPaths` / `policySha256` to the session.
async fn memory_selected(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
    mut o: HostedScanOptions,
) -> HostedScanOutput {
    use socket_patch_cli::hosted_memory::{
        select_paths, PolicyFileInput, SelectOptions, TreeEntryInput,
    };
    let entries: Vec<TreeEntryInput> = files
        .iter()
        .map(|(p, bytes)| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(bytes.len() as u64),
        })
        .collect();
    let policy_files: Vec<PolicyFileInput> = ["socket.yml", "socket.yaml"]
        .iter()
        .filter_map(|name| {
            files.get(*name).map(|bytes| PolicyFileInput {
                path: name.to_string(),
                text: Some(String::from_utf8(bytes.clone()).unwrap()),
                missing: None,
            })
        })
        .collect();
    let selection = select_paths(
        &entries,
        &SelectOptions {
            policy_files: Some(policy_files),
            no_socket_yml: o.no_socket_yml,
            ..SelectOptions::default()
        },
    );
    assert!(
        selection.policy_error.is_none(),
        "{:?}",
        selection.policy_error
    );
    let fetched: BTreeMap<String, Vec<u8>> = selection
        .fetch_text
        .iter()
        .chain(selection.fetch_binary.iter())
        .map(|p| (p.clone(), files[p].clone()))
        .collect();
    let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
    o.policy_paths = Some(selection.policy_paths.clone());
    o.policy_sha256 = selection.policy_sha256.clone();
    run_engine(server, build_input(&fetched, &present, o)).await
}

/// `files` with the engine's changed files applied: the next run's input.
fn apply(files: &BTreeMap<String, Vec<u8>>, out: &HostedScanOutput) -> BTreeMap<String, Vec<u8>> {
    let mut next = files.clone();
    for f in &out.changed_files {
        next.insert(f.path.clone(), f.content.clone().into_bytes());
    }
    next
}

fn pinned(files: &BTreeMap<String, Vec<u8>>, lock_path: &str) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(&files[lock_path]).into_owned();
    ORDER
        .iter()
        .copied()
        .filter(|n| text.contains(&uuid(n)))
        .collect()
}

#[tokio::test]
async fn one_root_disk_and_memory_admit_and_defer_the_same_rows_until_converged() {
    let server = MockServer::start().await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    let names: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    lock(&mut files, "", &names);

    for (run, expected) in [&ORDER[..2], &ORDER[..4], &ORDER[..5], &ORDER[..5]]
        .iter()
        .enumerate()
    {
        let disk = run_disk_with(&server, &files, false, &["--max-new-patches", "2"]);
        let mem = memory(&server, &files, options(Some(2))).await;
        let project = &mem.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        assert_eq!(
            mem.rollout,
            disk.envelope["rollout"],
            "run {}: the rollout blocks agree\nstderr: {}",
            run + 1,
            disk.stderr
        );
        assert_eq!(
            project.redirect,
            disk.envelope["redirect"],
            "run {}: the redirect blocks agree",
            run + 1
        );
        let next = apply(&files, &mem);
        let memory_changed: Vec<&String> = mem.changed_files.iter().map(|f| &f.path).collect();
        assert_eq!(
            memory_changed,
            disk.changed.keys().collect::<Vec<_>>(),
            "run {}: the same files change",
            run + 1
        );
        for (rel, bytes) in &disk.changed {
            assert_eq!(
                String::from_utf8_lossy(&next[rel]),
                String::from_utf8_lossy(bytes),
                "run {}: {rel}",
                run + 1
            );
        }
        assert_eq!(pinned(&next, "package-lock.json"), expected.to_vec());
        let deferred: Vec<&str> = project.deferred.iter().map(|d| d.purl.as_str()).collect();
        let want: Vec<String> = ORDER[expected.len()..].iter().map(|n| purl(n)).collect();
        assert_eq!(
            deferred,
            want.iter().map(String::as_str).collect::<Vec<_>>()
        );
        let skipped: Vec<&str> = project
            .skipped
            .iter()
            .filter(|s| s.reason == "rollout_deferred")
            .map(|s| s.purl.as_str())
            .collect();
        assert_eq!(skipped, deferred, "deferred rows are mirrored in skipped[]");
        files = next;
    }
    assert_eq!(
        memory(&server, &files, options(Some(2))).await.rollout["counts"],
        json!({ "new": 0, "deferred": 0, "upgrade": 0, "already": 5 })
    );
}

/// A patch uuid a file merely MENTIONS — here a stale hosted URL left in
/// a `package.json` field no installer reads — is not a pin: the row stays
/// NEW and costs its slot, on disk and in memory alike. Both engines used
/// to count any mention as ALREADY, which let the row ride past the cap.
#[tokio::test]
async fn a_uuid_mentioned_outside_a_pin_is_new_not_already() {
    let server = MockServer::start().await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    let names: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    lock(&mut files, "", &names);
    let mut manifest: Value = serde_json::from_slice(&files["package.json"]).unwrap();
    manifest["description"] = json!(format!("was pinned to {}", url("mem-e")));
    files.insert(
        "package.json".to_string(),
        serde_json::to_vec(&manifest).unwrap(),
    );

    let want = json!({ "new": 1, "deferred": 4, "upgrade": 0, "already": 0 });
    let mem = memory(&server, &files, options(Some(1))).await;
    assert!(
        mem.projects[0].error.is_none(),
        "{:?}",
        mem.projects[0].error
    );
    assert_eq!(mem.rollout["counts"], want);
    assert_eq!(pinned(&apply(&files, &mem), "package-lock.json"), ["mem-e"]);

    let disk = run_disk_with(&server, &files, false, &["--max-new-patches", "1"]);
    assert_eq!(disk.envelope["rollout"]["counts"], want, "{}", disk.stderr);
    let mut disk_files = files.clone();
    disk_files.extend(disk.changed);
    assert_eq!(pinned(&disk_files, "package-lock.json"), ["mem-e"]);
}

#[tokio::test]
async fn two_roots_spend_one_budget_in_memory_and_one_per_directory_on_disk() {
    let server = MockServer::start().await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    lock(&mut files, "a", &["mem-a", "mem-b"]);
    lock(&mut files, "b", &["mem-c", "mem-d", "mem-e"]);

    // Memory: one run-wide queue, e (b/), b (a/) first.
    let mem = memory(&server, &files, options(Some(2))).await;
    assert_eq!(
        mem.rollout["counts"],
        json!({ "new": 2, "deferred": 3, "upgrade": 0, "already": 0 })
    );
    let next = apply(&files, &mem);
    assert_eq!(pinned(&next, "a/package-lock.json"), ["mem-b"]);
    assert_eq!(pinned(&next, "b/package-lock.json"), ["mem-e"]);
    let mut ranks: Vec<(String, u32)> = mem
        .projects
        .iter()
        .flat_map(|p| p.deferred.iter().map(|d| (d.purl.clone(), d.rank)))
        .collect();
    ranks.sort();
    assert_eq!(
        ranks,
        [(purl("mem-a"), 5), (purl("mem-c"), 3), (purl("mem-d"), 4)],
        "ranks are run-wide"
    );

    // Disk: the directories spend the budget in sorted order, so `a/`
    // takes both slots before `b/` is visited.
    let (code, stdout, changed) =
        run_disk_args(&server, &files, &["--max-new-patches", "2", "a", "b"]);
    assert_eq!(code, 0, "{stdout}");
    let mut disk_files = files.clone();
    disk_files.extend(changed);
    assert_eq!(
        pinned(&disk_files, "a/package-lock.json"),
        ["mem-b", "mem-a"]
    );
    assert!(
        pinned(&disk_files, "b/package-lock.json").is_empty(),
        "{stdout}"
    );
}

/// The socket.yml policy and the cap together (§9.3): `includePaths`
/// keeps `legacy/` out, `minSeverity: high` leaves only e, b and c
/// eligible, and `maxNewPatches: 2` paces them; both engines converge in
/// two runs. `--no-socket-yml` then drops the file's floor, paths and cap
/// but keeps a flag cap, and each engine spends it in its own scope.
#[tokio::test]
async fn socket_yml_policy_and_cap_converge_on_disk_and_in_memory() {
    let server = MockServer::start().await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    files.insert(
        "socket.yml".to_string(),
        b"version: 2\npatches:\n  includePaths: [\"/apps/\"]\n  minSeverity: high\n  maxNewPatches: 2\n"
            .to_vec(),
    );
    lock(
        &mut files,
        "apps/one",
        &["mem-a", "mem-b", "mem-c", "mem-d", "mem-e"],
    );
    lock(&mut files, "apps/two", &["mem-b", "mem-c", "mem-d"]);
    lock(&mut files, "legacy", &["mem-b", "mem-e"]);
    let dirs = ["apps/one", "apps/two", "legacy"];
    let pins = |f: &BTreeMap<String, Vec<u8>>| -> Vec<Vec<&'static str>> {
        dirs.iter()
            .map(|d| pinned(f, &format!("{d}/package-lock.json")))
            .collect()
    };
    let expected: [Vec<Vec<&str>>; 3] = [
        vec![vec!["mem-e", "mem-b"], vec!["mem-b"], vec![]],
        vec![
            vec!["mem-e", "mem-b", "mem-c"],
            vec!["mem-b", "mem-c"],
            vec![],
        ],
        vec![
            vec!["mem-e", "mem-b", "mem-c"],
            vec!["mem-b", "mem-c"],
            vec![],
        ],
    ];

    let mut mem_files = files.clone();
    let mut disk_files = files.clone();
    for (run, want) in expected.iter().enumerate() {
        let mem = memory_selected(&server, &mem_files, options(None)).await;
        assert_eq!(
            mem.rollout["maxNewPatches"],
            json!({ "value": 2, "source": "file" }),
            "run {}",
            run + 1
        );
        assert_eq!(
            mem.policy.as_ref().map(|p| p["source"].clone()),
            Some(json!("file"))
        );
        mem_files = apply(&mem_files, &mem);
        assert_eq!(&pins(&mem_files), want, "memory run {}", run + 1);

        let (code, stdout, changed) = run_disk_args(&server, &disk_files, &dirs);
        assert_eq!(code, 0, "{stdout}");
        assert!(
            stdout.contains("maxNewPatches=2 from socket.yml"),
            "disk run {}: {stdout}",
            run + 1
        );
        disk_files.extend(changed);
        assert_eq!(&pins(&disk_files), want, "disk run {}: {stdout}", run + 1);
    }

    // Disk visits the directories in sorted order: `apps/one` spends the
    // one slot on d, `apps/two` gets d free, and `legacy` defers e and b.
    let (code, stdout, changed) = run_disk_args(
        &server,
        &disk_files,
        &[
            "--no-socket-yml",
            "--max-new-patches",
            "1",
            "apps/one",
            "apps/two",
            "legacy",
        ],
    );
    assert_eq!(code, 0, "{stdout}");
    disk_files.extend(changed);
    assert_eq!(
        pins(&disk_files),
        [
            vec!["mem-e", "mem-b", "mem-c", "mem-d"],
            vec!["mem-b", "mem-c", "mem-d"],
            vec![],
        ],
        "{stdout}"
    );

    // Memory ranks every root in one queue: legacy's critical e goes first.
    let mut o = options(Some(1));
    o.no_socket_yml = Some(true);
    let mem = memory_selected(&server, &mem_files, o).await;
    assert_eq!(
        mem.rollout["maxNewPatches"],
        json!({ "value": 1, "source": "flag" })
    );
    mem_files = apply(&mem_files, &mem);
    assert_eq!(
        pins(&mem_files),
        [
            vec!["mem-e", "mem-b", "mem-c"],
            vec!["mem-b", "mem-c"],
            vec!["mem-e"],
        ]
    );
}

#[tokio::test]
async fn memory_counts_a_committed_manifest_vendor_entry_or_pin_as_recorded() {
    let server = MockServer::start().await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    let names: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    lock(&mut files, "", &names);
    // mem-e is recorded by the agent manifest, mem-b by the vendor ledger.
    files.insert(
        ".socket/manifest.json".into(),
        serde_json::to_vec(&json!({ "patches": { purl("mem-e"): {
            "uuid": uuid("mem-e"), "exportedAt": "", "files": {}, "vulnerabilities": {},
            "description": "", "license": "", "tier": "free"
        }}}))
        .unwrap(),
    );
    files.insert(
        ".socket/vendor/state.json".into(),
        serde_json::to_vec(&json!({
            "version": 1,
            "entries": { purl("mem-b"): {
                "ecosystem": "npm", "uuid": uuid("mem-b"), "basePurl": purl("mem-b"),
                "artifact": { "path": format!(".socket/vendor/npm/{}/mem-b-1.0.0.tgz", uuid("mem-b")) },
                "wiring": []
            }}
        }))
        .unwrap(),
    );
    let mem = memory(&server, &files, options(Some(1))).await;
    assert_eq!(
        mem.rollout["counts"],
        json!({ "new": 1, "deferred": 2, "upgrade": 0, "already": 2 }),
        "{:#}",
        mem.rollout
    );
    let deferred: Vec<&str> = mem.projects[0]
        .deferred
        .iter()
        .map(|d| d.purl.as_str())
        .collect();
    assert_eq!(deferred, [purl("mem-d"), purl("mem-a")]);
    // mem-e (manifest) re-confirms its pin; mem-b (vendored) is refused as a
    // takeover; mem-c is the one NEW patch admitted.
    let next = apply(&files, &mem);
    assert_eq!(pinned(&next, "package-lock.json"), ["mem-e", "mem-c"]);
    // The rerun lands the next one.
    let again = memory(&server, &next, options(Some(1))).await;
    assert_eq!(
        again.rollout["counts"],
        json!({ "new": 1, "deferred": 1, "upgrade": 0, "already": 3 })
    );
    assert_eq!(
        pinned(&apply(&next, &again), "package-lock.json"),
        ["mem-e", "mem-c", "mem-d"]
    );
}

#[tokio::test]
async fn memory_defers_new_rows_when_the_reference_lookup_fails_under_a_cap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&server)
        .await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    let names: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    lock(&mut files, "", &names);
    let mem = memory(&server, &files, options(Some(2))).await;
    let project = &mem.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(project.deferred.len(), 5);
    assert!(mem.changed_files.is_empty());
    let codes: Vec<&str> = mem.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"rollout_reference_failed"), "{codes:?}");
    // Uncapped, the failure is the root's.
    let mem = memory(&server, &files, options(None)).await;
    assert_eq!(
        mem.projects[0].error.as_ref().map(|e| e.code.as_str()),
        Some("reference_lookup_failed")
    );
}

#[tokio::test]
async fn memory_in_flight_patches_go_first_and_the_server_cap_tightens() {
    let server = MockServer::start().await;
    mount(&server).await;
    let mut files = BTreeMap::new();
    let names: Vec<&str> = PACKAGES.iter().map(|(n, _)| *n).collect();
    lock(&mut files, "", &names);
    let mem = memory(
        &server,
        &files,
        HostedScanOptions {
            max_new_patches: Some(MaxNewPatchesOption(None)),
            max_new_patches_cap: Some(1),
            in_flight_patches: Some(vec![purl("mem-a")]),
            ..options(None)
        },
    )
    .await;
    assert_eq!(
        mem.rollout["maxNewPatches"],
        json!({ "value": 1, "source": "cap" })
    );
    assert_eq!(
        pinned(&apply(&files, &mem), "package-lock.json"),
        ["mem-a"],
        "the in-flight patch keeps its slot"
    );
}

#[test]
fn the_max_new_patches_option_takes_a_count_or_none() {
    let parse = |v: Value| {
        serde_json::from_value::<HostedScanOptions>(json!({ "orgSlug": "o", "maxNewPatches": v }))
    };
    assert_eq!(
        parse(json!(3)).unwrap().max_new_patches,
        Some(MaxNewPatchesOption(Some(3)))
    );
    assert_eq!(
        parse(json!("none")).unwrap().max_new_patches,
        Some(MaxNewPatchesOption(None))
    );
    for bad in [json!(-1), json!(1.5), json!("all"), json!(4294967296u64)] {
        assert!(parse(bad.clone()).is_err(), "{bad}");
    }
    assert_eq!(
        serde_json::to_value(MaxNewPatchesOption(None)).unwrap(),
        json!("none")
    );
}
