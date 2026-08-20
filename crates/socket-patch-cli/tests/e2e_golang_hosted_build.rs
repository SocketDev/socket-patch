#![cfg(unix)]
//! Full go-toolchain capstone for the HOSTED golang redirect: proves that the
//! rewriter's committed `go.mod` + `go.sum` alone make a **fresh day-2
//! machine** (empty caches, default `-mod=readonly`, NO machine-local
//! configuration) build the PATCHED module — and that go's own integrity
//! machinery still has teeth against a tampered pin.
//!
//! The three properties this pins (each validated empirically before the
//! feature was built — see `docs/design/golang-hosted.md`):
//!
//! 1. **No sumdb consultation**: `GOSUMDB` is set to a bogus database name
//!    for every day-2 command. go parses `GOSUMDB` lazily and consults it only
//!    for modules ABSENT from `go.sum` — if any command here asked the
//!    checksum database, it would fail loudly (`malformed verifier id`), so
//!    green tests prove committed go.sum lines are sufficient day-2 state.
//! 2. **Fork-style replace with a zero-rewrite artifact**: the served module
//!    zip keeps the ORIGINAL module path in its internal `go.mod` and the
//!    original import-path spellings in its sources; only the zip's entry
//!    prefix and the proxy directory use the socket module path.
//! 3. **go.sum verification stays load-bearing**: flipping one character of
//!    the committed zip `h1:` fails the build with a checksum SECURITY ERROR
//!    on a fresh cache — a wrong CLI-written hash can never be silently built.
//!
//! Hermetic + offline: both the upstream and the socket-patched module are
//! served from a `file://` GOPROXY into per-"machine" temp caches. Skips when
//! `go`/`zip` aren't installed.
//!
//! Two entry points into the SAME committed shape (both stage through
//! [`stage_hosted_project`]): the rewriter capstone drives the pure
//! `rewrite_registry_redirect` engine in-process, and the `get`-driven twin
//! drives the full CLI (`get <uuid> --mode hosted`) against a wiremock API,
//! proving the advisory-selector path lands the identical go.mod/go.sum.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "common/mod.rs"]
mod common;

use common::{cache_env, has_command};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::patch::redirect::{
    rewrite_registry_redirect, DepOverride, Integrity, RegistryOverride,
    RegistryOverrideIdentifiers,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const GHSA: &str = "GHSA-gogo-host-get1";
const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UUID: &str = "55555555-5555-5555-5555-555555555555";
const SVER: &str = "v1.0.0-socketpatch.1";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";

fn socket_module() -> String {
    format!("patch.socket.dev/gopatch/{UUID}")
}

/// One "machine": its own GOMODCACHE + GOCACHE, nothing shared.
struct Machine {
    modcache: PathBuf,
    gocache: PathBuf,
}

impl Machine {
    fn new(tmp: &Path, name: &str) -> Self {
        let m = Machine {
            modcache: tmp.join(name).join("modcache"),
            gocache: tmp.join(name).join("gocache"),
        };
        std::fs::create_dir_all(&m.modcache).unwrap();
        std::fs::create_dir_all(&m.gocache).unwrap();
        m
    }
}

/// Run `go` sandboxed (cache_env), then this machine's caches + the given env
/// on top (explicit values win over both the sandbox and hostile ambient).
fn go(dir: &Path, machine: &Machine, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    cache_env::isolate(&mut cmd);
    cmd.env("GOMODCACHE", &machine.modcache);
    cmd.env("GOCACHE", &machine.gocache);
    cmd.env("GOTOOLCHAIN", "local");
    // Empty env-var pins do NOT defeat `go env -w` config — go treats an
    // empty variable as unset and falls back to the env FILE. GOENV=off is
    // the only switch that ignores it entirely.
    cmd.env("GOENV", "off");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run go")
}

/// The day-2 environment: default mod mode (`-mod=readonly`), sumdb pointed at
/// a BOGUS database that fails loudly if ever consulted, and every sanctioned
/// escape hatch (`GOPRIVATE`/`GONOSUMDB`/`GONOPROXY`) explicitly empty — the
/// committed go.mod+go.sum must carry the redirect entirely on their own.
fn day2_env(proxy_url: &str) -> Vec<(&'static str, String)> {
    vec![
        ("GOPROXY", proxy_url.to_string()),
        ("GOSUMDB", "sum.invalid.example".to_string()),
        ("GOFLAGS", String::new()),
        ("GOPRIVATE", String::new()),
        ("GONOSUMDB", String::new()),
        ("GONOPROXY", String::new()),
    ]
}

fn as_pairs<'a>(env: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    env.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

/// Go writes extracted modules into GOMODCACHE with read-only dirs, which
/// makes `TempDir::drop`'s remove fail silently — and a panicking assertion
/// would skip any trailing chmod. Restore write bits on EVERY exit path.
struct ChmodGuard(PathBuf);
impl Drop for ChmodGuard {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&self.0)
            .status();
    }
}

/// Stage a module dir and zip it into the file-proxy under `mod_path@ver/`.
fn publish(tmp: &Path, mod_path: &str, ver: &str, gomod: &str, lib: &str) {
    let stage_root = tmp.join("stage").join(mod_path.replace('/', "_"));
    let stage = stage_root.join(format!("{mod_path}@{ver}"));
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("go.mod"), gomod).unwrap();
    std::fs::write(stage.join("lib.go"), lib).unwrap();

    let pxv = tmp.join("proxy").join(mod_path).join("@v");
    std::fs::create_dir_all(&pxv).unwrap();
    std::fs::write(
        pxv.join(format!("{ver}.info")),
        format!("{{\"Version\":\"{ver}\"}}"),
    )
    .unwrap();
    // The served `.mod` must byte-match the zip's internal go.mod — go hashes
    // the SERVED bytes into the `/go.mod h1:` line without cross-checking the
    // zip, so the server contract freezes them together.
    std::fs::write(pxv.join(format!("{ver}.mod")), gomod).unwrap();
    let zip_out = pxv.join(format!("{ver}.zip"));
    let status = Command::new("zip")
        .args([
            "-q",
            "-r",
            zip_out.to_str().unwrap(),
            &format!("{mod_path}@{ver}"),
        ])
        .current_dir(&stage_root)
        .status()
        .expect("run zip");
    assert!(status.success(), "zip failed for {mod_path}@{ver}");
}

/// Harvest the two go.sum hashes for `mod_path@ver` the way the patch server
/// would publish them: `go mod download -json` in a throwaway module (sums
/// off — this is the trusted build side, not the consumer side).
fn harvest_sums(tmp: &Path, proxy_url: &str, mod_path: &str, ver: &str) -> (String, String) {
    let dir = tmp.join("harvest").join(mod_path.replace('/', "_"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/harvest\n\ngo 1.21\n",
    )
    .unwrap();
    let machine = Machine::new(tmp, &format!("harvest-{}", mod_path.replace('/', "_")));
    let out = go(
        &dir,
        &machine,
        &["mod", "download", "-json", &format!("{mod_path}@{ver}")],
        &[
            ("GOPROXY", proxy_url),
            ("GOSUMDB", "off"),
            ("GOFLAGS", "-mod=mod"),
        ],
    );
    assert!(
        out.status.success(),
        "hash harvest failed for {mod_path}@{ver}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("download -json");
    (
        v["Sum"].as_str().expect("Sum").to_string(),
        v["GoModSum"].as_str().expect("GoModSum").to_string(),
    )
}

/// Everything both capstones share once [`stage_hosted_project`] returns.
struct HostedGoProject {
    consumer: PathBuf,
    proxy_url: String,
    /// The socket module path (`patch.socket.dev/gopatch/<uuid>`).
    smod: String,
    /// The socket module's go.sum pair: zip dirhash + served-`.mod` hash.
    zip_h1: String,
    gomod_h1: String,
}

/// Shared fixture for the rewriter capstone and the `get`-driven twin — the
/// patch server's side plus the user's pre-redirect project:
///
/// * Upstream module (vulnerable), and the patched artifact published under
///   the socket module path. ZERO-REWRITE converter shape: the internal
///   go.mod still declares the ORIGINAL module path and sources keep original
///   import spellings; only the zip prefix + proxy dir carry the socket path.
/// * The consumer project (go.mod + upstream go.sum pair + main.go).
/// * Anti-vacuity baseline: an untouched project on a fresh machine links
///   PRISTINE (so a later PATCHED link can only come from the redirect).
///
/// Each caller then performs the redirect its own way (in-process rewriter
/// vs the CLI's `get <uuid> --mode hosted`) and proves the same day-2 build.
fn stage_hosted_project(tmp: &Path) -> HostedGoProject {
    let proxy_url = format!("file://{}", tmp.join("proxy").display());
    let smod = socket_module();

    let upstream_gomod = format!("module {UMOD}\n\ngo 1.21\n");
    publish(tmp, UMOD, UVER, &upstream_gomod, PRISTINE_LIB);
    publish(tmp, &smod, SVER, &upstream_gomod, PATCHED_LIB);
    let (zip_h1, gomod_h1) = harvest_sums(tmp, &proxy_url, &smod, SVER);
    let (u_zip_h1, u_gomod_h1) = harvest_sums(tmp, &proxy_url, UMOD, UVER);

    let consumer = tmp.join("consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("go.mod"),
        format!("module example.com/consumer\n\ngo 1.21\n\nrequire {UMOD} {UVER}\n"),
    )
    .unwrap();
    std::fs::write(
        consumer.join("go.sum"),
        format!("{UMOD} {UVER} {u_zip_h1}\n{UMOD} {UVER}/go.mod {u_gomod_h1}\n"),
    )
    .unwrap();
    std::fs::write(
        consumer.join("main.go"),
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"OUT:\", upstream.Greeting()) }}\n"
        ),
    )
    .unwrap();

    let m0 = Machine::new(tmp, "machine0");
    let env = day2_env(&proxy_url);
    let base = go(&consumer, &m0, &["run", "."], &as_pairs(&env));
    assert!(
        base.status.success(),
        "baseline run failed: {}",
        String::from_utf8_lossy(&base.stderr)
    );
    assert!(String::from_utf8_lossy(&base.stdout).contains("OUT: PRISTINE"));

    HostedGoProject {
        consumer,
        proxy_url,
        smod,
        zip_h1,
        gomod_h1,
    }
}

#[test]
fn day2_machine_builds_patched_module_from_committed_files_alone() {
    if !has_command("go") || !has_command("zip") {
        eprintln!("skipping e2e_golang_hosted_build: `go`/`zip` not installed");
        return;
    }
    // RED guards: hostile ambient values every pinned env below must defeat.
    // `GOTOOLCHAIN` must lose to the `local` pin; `GOFLAGS=-mod=mod` must lose
    // to the explicit empty (day-2 must run readonly); `GONOSUMDB=*` must lose
    // to the explicit empty (it would mask the bogus-GOSUMDB tripwire).
    std::env::set_var("GOTOOLCHAIN", "go1.99.99");
    std::env::set_var("GOFLAGS", "-mod=mod");
    std::env::set_var("GONOSUMDB", "*");
    let tmp = tempfile::tempdir().unwrap();
    let _cleanup = ChmodGuard(tmp.path().to_path_buf());
    let fx = stage_hosted_project(tmp.path());
    let consumer = fx.consumer.clone();
    let proxy_url = fx.proxy_url.clone();
    let smod = fx.smod.clone();
    let (zip_h1, gomod_h1) = (fx.zip_h1.clone(), fx.gomod_h1.clone());
    let env = day2_env(&proxy_url);

    // ── `scan --mode hosted`'s rewrite (in-process, pure) ───────────────────
    let ovr = DepOverride {
        ecosystem: "golang".into(),
        name: UMOD.into(),
        namespace: None,
        version: UVER.into(),
        token: String::new(),
        patch_uuid: UUID.into(),
        artifact_url: format!("{proxy_url}/{smod}/@v/{SVER}.zip"),
        berry_zip_url: None,
        registry_override: Some(RegistryOverride {
            kind: "goproxy".into(),
            index_url: proxy_url.clone(),
            identifiers: RegistryOverrideIdentifiers {
                name: UMOD.into(),
                version: UVER.into(),
                go_module_path: Some(smod.clone()),
                go_module_version: Some(SVER.into()),
                ..Default::default()
            },
        }),
        integrity: Integrity {
            dirhash_h1: Some(zip_h1.clone()),
            go_mod_h1: Some(gomod_h1),
            ..Default::default()
        },
    };
    let mut files = std::collections::BTreeMap::new();
    for name in ["go.mod", "go.sum"] {
        files.insert(
            name.to_string(),
            std::fs::read_to_string(consumer.join(name)).unwrap(),
        );
    }
    let rewrite = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
    assert!(
        rewrite.warnings.is_empty(),
        "rewrite warnings: {:?}",
        rewrite.warnings
    );
    assert_eq!(
        rewrite.files.keys().collect::<Vec<_>>(),
        ["go.mod", "go.sum"],
        "exactly the two committed files change"
    );
    for (name, content) in &rewrite.files {
        std::fs::write(consumer.join(name), content).unwrap();
    }

    // ── day 2: a fresh machine, committed files only, zero local config ─────
    let m2 = Machine::new(tmp.path(), "machine2");
    let patched = go(&consumer, &m2, &["run", "."], &as_pairs(&env));
    assert!(
        patched.status.success(),
        "day-2 run failed: {}",
        String::from_utf8_lossy(&patched.stderr)
    );
    assert!(
        String::from_utf8_lossy(&patched.stdout).contains("OUT: PATCHED"),
        "day-2 build must link the PATCHED module: {}",
        String::from_utf8_lossy(&patched.stdout)
    );

    // `go mod tidy` on the same machine is a byte-level no-op: the redirect
    // survives the day-2 command most likely to churn go.mod/go.sum.
    let before_mod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    let before_sum = std::fs::read_to_string(consumer.join("go.sum")).unwrap();
    let tidy = go(&consumer, &m2, &["mod", "tidy"], &as_pairs(&env));
    assert!(
        tidy.status.success(),
        "go mod tidy failed: {}",
        String::from_utf8_lossy(&tidy.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.mod")).unwrap(),
        before_mod,
        "tidy must not churn go.mod"
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("go.sum")).unwrap(),
        before_sum,
        "tidy must not churn go.sum"
    );

    // ── tamper: go.sum verification must stay load-bearing ──────────────────
    // Flip one character of the committed zip h1 — a fresh machine must
    // refuse the download with a checksum SECURITY ERROR, never build it.
    let tampered = {
        let flip = |c: char| if c == 'A' { 'B' } else { 'A' };
        let mut lines: Vec<String> = before_sum.lines().map(str::to_string).collect();
        let idx = lines
            .iter()
            .position(|l| l.starts_with(&format!("{smod} {SVER} h1:")))
            .expect("socket zip h1 line present");
        let mut chars: Vec<char> = lines[idx].chars().collect();
        let at = lines[idx].find("h1:").unwrap() + 3;
        chars[at] = flip(chars[at]);
        lines[idx] = chars.into_iter().collect();
        lines.join("\n") + "\n"
    };
    std::fs::write(consumer.join("go.sum"), &tampered).unwrap();
    let m3 = Machine::new(tmp.path(), "machine3");
    let bad = go(&consumer, &m3, &["build", "./..."], &as_pairs(&env));
    let bad_err = String::from_utf8_lossy(&bad.stderr);
    assert!(
        !bad.status.success(),
        "tampered go.sum must fail the build, got: {}",
        String::from_utf8_lossy(&bad.stdout)
    );
    assert!(
        bad_err.contains("checksum mismatch") || bad_err.contains("SECURITY ERROR"),
        "failure must be go's checksum verification, got: {bad_err}"
    );
    std::fs::write(consumer.join("go.sum"), &before_sum).unwrap();

    // ── positive tripwire control ────────────────────────────────────────
    // Prove the bogus GOSUMDB actually fires when consulted: with the socket
    // zip h1 line REMOVED, resolving the module needs the checksum database,
    // and the bogus name must fail loudly — this is what makes every green
    // assertion above meaningful (the tripwire is demonstrably armed).
    let without_h1: String = before_sum
        .lines()
        .filter(|l| !l.starts_with(&format!("{smod} {SVER} h1:")))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(consumer.join("go.sum"), &without_h1).unwrap();
    let m4 = Machine::new(tmp.path(), "machine4");
    let dl = go(
        &consumer,
        &m4,
        &["mod", "download", &format!("{smod}@{SVER}")],
        &as_pairs(&env),
    );
    let dl_err = String::from_utf8_lossy(&dl.stderr);
    assert!(
        !dl.status.success(),
        "a missing go.sum line must force a checksum-DB lookup that fails, got: {}",
        String::from_utf8_lossy(&dl.stdout)
    );
    assert!(
        dl_err.contains("GOSUMDB")
            || dl_err.contains("verifier")
            || dl_err.contains("sum.invalid.example"),
        "failure must come from the bogus checksum DB (tripwire armed), got: {dl_err}"
    );
    std::fs::write(consumer.join("go.sum"), &before_sum).unwrap();
}

/// `get <uuid> --mode hosted` twin of the capstone above: the CLI's
/// advisory-selector path routes through the SAME shared engine, so the
/// committed go.mod/go.sum must come out identical in shape — fork-replace
/// onto the gopatch module path, plus BOTH go.sum `h1:` lines (the goproxy
/// integrity pair is all-or-nothing; the grant carries it on the override's
/// identifiers) — and a fresh day-2 machine must build the PATCHED module
/// from the committed files alone. Hosted persistence is the redirect ledger
/// ONLY: no manifest, no blobs.
// multi_thread: the CLI subprocess blocks a worker thread while wiremock
// keeps serving the view + reference routes on the others.
#[tokio::test(flavor = "multi_thread")]
async fn golang_get_uuid_hosted_day2_machine_builds() {
    if !has_command("go") || !has_command("zip") {
        eprintln!("skipping e2e_golang_hosted_build: `go`/`zip` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _cleanup = ChmodGuard(tmp.path().to_path_buf());
    let fx = stage_hosted_project(tmp.path());
    let purl = format!("pkg:golang/{UMOD}@{UVER}");
    let artifact_url = format!("{}/{}/@v/{SVER}.zip", fx.proxy_url, fx.smod);

    // API mocks: `view/{uuid}` (the record the redirect ledger embeds for
    // VEX) + the reference grant whose goproxy override carries the module
    // path/version and the gopatch-flavor hash pair the rewriter pins.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": &purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "lib.go": {
                    "beforeHash": compute_git_sha256_from_bytes(PRISTINE_LIB.as_bytes()),
                    "afterHash": compute_git_sha256_from_bytes(PATCHED_LIB.as_bytes()),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-4242"],
                    "summary": "golang hosted get capstone vuln",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "golang hosted get capstone fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": &artifact_url,
                    "purl": &purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": &artifact_url,
                        "integrity": {}
                    }],
                    "registryOverride": {
                        "kind": "goproxy",
                        "indexUrl": &fx.proxy_url,
                        "identifiers": {
                            "name": UMOD,
                            "version": UVER,
                            "goModulePath": &fx.smod,
                            "goModuleVersion": SVER,
                            "goZipDirhashH1": &fx.zip_h1,
                            "goModH1": &fx.gomod_h1,
                        }
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    // The CLI run: `get <uuid> --mode hosted --json --yes`.
    let (code, stdout, stderr) = common::run_with_env(
        &fx.consumer,
        &[
            "get",
            UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            fx.consumer.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[],
    );
    assert_eq!(
        code, 0,
        "get --mode hosted failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("get --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(envelope["status"], "success", "envelope: {envelope}");
    assert_eq!(
        envelope["redirect"]["mode"], "hosted",
        "envelope: {envelope}"
    );
    assert_eq!(
        envelope["redirect"]["redirected"], 1,
        "exactly one dep redirected: {envelope}"
    );
    assert_eq!(
        envelope["redirect"]["rewrittenFiles"],
        serde_json::json!(["go.mod", "go.sum"]),
        "exactly the two committed files change: {envelope}"
    );
    assert_eq!(
        envelope["redirect"]["warnings"],
        serde_json::json!([]),
        "no rewriter warnings: {envelope}"
    );

    // Committed shape identical to the rewriter capstone: the fork-style
    // replace onto the gopatch module path…
    let gomod = std::fs::read_to_string(fx.consumer.join("go.mod")).unwrap();
    let expected_replace = format!("replace {UMOD} {UVER} => {} {SVER}", fx.smod);
    assert!(
        gomod.lines().any(|l| l.trim() == expected_replace),
        "go.mod must carry the fork-replace.\nwant: {expected_replace}\ngot:\n{gomod}"
    );
    // …plus BOTH go.sum lines (the all-or-nothing integrity pair).
    let gosum = std::fs::read_to_string(fx.consumer.join("go.sum")).unwrap();
    let want_zip = format!("{} {SVER} {}", fx.smod, fx.zip_h1);
    let want_mod = format!("{} {SVER}/go.mod {}", fx.smod, fx.gomod_h1);
    assert!(
        gosum.lines().any(|l| l.trim() == want_zip),
        "go.sum must pin the zip dirhash.\nwant: {want_zip}\ngot:\n{gosum}"
    );
    assert!(
        gosum.lines().any(|l| l.trim() == want_mod),
        "go.sum must pin the served-.mod hash.\nwant: {want_mod}\ngot:\n{gosum}"
    );

    // Hosted persistence contract: the ledger IS the persistence.
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fx.consumer.join(".socket/vendor/redirect-state.json"))
            .expect("redirect ledger must be written"),
    )
    .unwrap();
    assert_eq!(ledger["mode"], "hosted", "ledger: {ledger}");
    assert_eq!(
        ledger["records"][purl.as_str()]["uuid"],
        UUID,
        "the ledger must embed the patch record for VEX: {ledger}"
    );
    assert!(
        !fx.consumer.join(".socket/manifest.json").exists(),
        "hosted mode must NOT write the manifest (parity with scan --mode hosted)"
    );
    assert!(
        !fx.consumer.join(".socket/blobs").exists(),
        "hosted mode must NOT persist blobs"
    );

    // Reference-grant oracle: exactly one grant request, for THIS uuid.
    let reference_bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/package"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert_eq!(
        reference_bodies.len(),
        1,
        "exactly one reference request: {reference_bodies:?}"
    );
    assert!(
        reference_bodies[0].contains(UUID),
        "the grant request must carry the selected uuid: {}",
        reference_bodies[0]
    );

    // ── day 2: a fresh machine, committed files only, zero local config ─────
    // Same harness as the rewriter capstone: default `-mod=readonly`, bogus
    // GOSUMDB (never consulted thanks to the committed pair), every escape
    // hatch empty.
    let env = day2_env(&fx.proxy_url);
    let m2 = Machine::new(tmp.path(), "machine2");
    let patched = go(&fx.consumer, &m2, &["run", "."], &as_pairs(&env));
    assert!(
        patched.status.success(),
        "day-2 run failed: {}",
        String::from_utf8_lossy(&patched.stderr)
    );
    assert!(
        String::from_utf8_lossy(&patched.stdout).contains("OUT: PATCHED"),
        "day-2 build must link the PATCHED module: {}",
        String::from_utf8_lossy(&patched.stdout)
    );
}
