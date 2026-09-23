#![cfg(unix)]
//! Real-go e2e for Go WORKSPACES (`go.work`): hosted and vendored Socket
//! patches in a multi-module workspace, built by the real toolchain, and
//! attested by manifest-less `socket-patch vex`.
//!
//! Layout: the project root is both the workspace root (`go.work` with
//! `use ( . ./tools )`) and a module (`example.com/consumer`); the `tools`
//! member module imports the same upstream module. Our writers only edit the
//! ROOT `go.mod` / `go.sum`, and in workspace mode a workspace module's
//! `replace` applies to the whole build — so both members must link the
//! PATCHED module. Two wirings per mode:
//!
//! * **root go.mod** — exactly what `vendor` / `get --mode hosted` write;
//! * **go.work replace** — the user moved the Socket `replace` (and, for
//!   hosted, its go.sum pin lines into `go.work.sum`) into the workspace
//!   file, which is what a workspace with conflicting member replaces must
//!   do. Discovery reads `go.work` + `go.work.sum` too.
//!
//! Each state then runs the manifest-less VEX tail
//! ([`golang_e2e_matrix::manifestless_vex`]): fresh checkout, real install
//! on a fresh cache, attested with and without ledgers, `record_unavailable`
//! offline, omitted when tampered or reverted. Hermetic + offline (file
//! GOPROXY, per-"machine" caches, wiremock API). Needs Go 1.18+ (`go.work`);
//! the release is whatever `go` is on `PATH` (see `golang_e2e_matrix`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "golang_e2e_matrix/mod.rs"]
mod golang_e2e_matrix;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use golang_e2e_matrix::{manifestless_vex, ManifestlessGo};
use vex_e2e_common::{binary, git_sha256, patch_view, Marker, VexVia};

const ORG: &str = "test-org";
const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UPURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const HOSTED_UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
const VENDOR_UUID: &str = "6c7d8e9f-0a1b-4c2d-8e3f-4a5b6c7d8e9f";
const SVER: &str = "v1.0.0-socketpatch.1";
const GHSA: &str = "GHSA-gowk-spac-e001";
const CVE: &str = "CVE-2026-6161";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";
const VULNS: &[(&str, &[&str])] = &[(GHSA, &[CVE])];

// ── go harness ────────────────────────────────────────────────────────

/// One "machine": its own GOMODCACHE + GOCACHE.
struct Machine {
    modcache: PathBuf,
    gocache: PathBuf,
}

impl Machine {
    fn new(tmp: &Path, name: &str) -> Self {
        let m = Machine {
            modcache: tmp.join("machines").join(name).join("modcache"),
            gocache: tmp.join("machines").join(name).join("gocache"),
        };
        std::fs::create_dir_all(&m.modcache).unwrap();
        std::fs::create_dir_all(&m.gocache).unwrap();
        m
    }
}

/// `go` sandboxed (cache_env), on `machine`'s caches, workspace mode left
/// to auto-detection (`GOWORK` unset), `GOENV=off` (no `go env -w` config),
/// then `env` on top.
fn go(dir: &Path, machine: &Machine, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    cache_env::isolate(&mut cmd);
    cmd.env("GOMODCACHE", &machine.modcache)
        .env("GOCACHE", &machine.gocache)
        .env("GOTOOLCHAIN", "local")
        .env("GOENV", "off")
        .env("GOFLAGS", "")
        .env_remove("GOWORK");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run go")
}

/// Day-2 env: default readonly mod mode, a BOGUS sumdb that fails loudly if
/// consulted (committed sums must suffice), no escape hatches.
fn day2(proxy: &str) -> Vec<(&str, &str)> {
    vec![
        ("GOPROXY", proxy),
        ("GOSUMDB", "sum.invalid.example"),
        ("GOPRIVATE", ""),
        ("GONOSUMDB", ""),
        ("GONOPROXY", ""),
    ]
}

/// `go run` both workspace members; assert each prints `want`.
fn run_members(dir: &Path, machine: &Machine, env: &[(&str, &str)], want: &str, what: &str) {
    for (pkg, tag) in [(".", "OUT"), ("./tools", "TOOLS")] {
        let out = go(dir, machine, &["run", pkg], env);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("{tag}: {want}")),
            "{what}: `go run {pkg}` must link {want}.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Go extracts modules read-only; restore write bits so the tempdir drops.
struct ChmodGuard(PathBuf);
impl Drop for ChmodGuard {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&self.0)
            .status();
    }
}

/// Zip `mod_path@ver` (go.mod + lib.go) into the file proxy.
fn publish(tmp: &Path, mod_path: &str, ver: &str, lib: &str) {
    let gomod = format!("module {UMOD}\n\ngo 1.18\n");
    let stage_root = tmp.join("stage").join(mod_path.replace('/', "_"));
    let stage = stage_root.join(format!("{mod_path}@{ver}"));
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("go.mod"), &gomod).unwrap();
    std::fs::write(stage.join("lib.go"), lib).unwrap();
    let pxv = tmp.join("proxy").join(mod_path).join("@v");
    std::fs::create_dir_all(&pxv).unwrap();
    std::fs::write(
        pxv.join(format!("{ver}.info")),
        format!("{{\"Version\":\"{ver}\"}}"),
    )
    .unwrap();
    std::fs::write(pxv.join(format!("{ver}.mod")), &gomod).unwrap();
    let zip = pxv.join(format!("{ver}.zip"));
    let status = Command::new("zip")
        .args([
            "-q",
            "-r",
            zip.to_str().unwrap(),
            &format!("{mod_path}@{ver}"),
        ])
        .current_dir(&stage_root)
        .status()
        .expect("run zip");
    assert!(status.success(), "zip {mod_path}@{ver}");
}

/// The go.sum `(zip h1, go.mod h1)` of `mod_path@ver` (trusted build side).
fn harvest(tmp: &Path, proxy: &str, mod_path: &str, ver: &str) -> (String, String) {
    let dir = tmp.join("harvest").join(mod_path.replace('/', "_"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/harvest\n\ngo 1.18\n",
    )
    .unwrap();
    let m = Machine::new(tmp, &format!("harvest-{}", mod_path.replace('/', "_")));
    let out = go(
        &dir,
        &m,
        &["mod", "download", "-json", &format!("{mod_path}@{ver}")],
        &[
            ("GOPROXY", proxy),
            ("GOSUMDB", "off"),
            ("GOFLAGS", "-mod=mod"),
        ],
    );
    assert!(
        out.status.success(),
        "harvest {mod_path}@{ver}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    (
        v["Sum"].as_str().unwrap().to_string(),
        v["GoModSum"].as_str().unwrap().to_string(),
    )
}

const GO_WORK: &str = "go 1.18\n\nuse (\n\t.\n\t./tools\n)\n";

/// The pre-patch workspace. Returns `(root, proxy_url, pristine files)`.
struct Workspace {
    root: PathBuf,
    proxy: String,
    /// `(relative path, bytes)` of the pre-patch go.mod / go.sum / go.work.
    pristine: Vec<(&'static str, Vec<u8>)>,
}

fn stage_workspace(tmp: &Path, socket_module: Option<&str>) -> Workspace {
    let proxy = format!("file://{}", tmp.join("proxy").display());
    publish(tmp, UMOD, UVER, PRISTINE_LIB);
    if let Some(smod) = socket_module {
        publish(tmp, smod, SVER, PATCHED_LIB);
    }
    let (zip_h1, mod_h1) = harvest(tmp, &proxy, UMOD, UVER);
    let sums = format!("{UMOD} {UVER} {zip_h1}\n{UMOD} {UVER}/go.mod {mod_h1}\n");
    let root = tmp.join("ws");
    let main = |tag: &str| {
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"{tag}:\", upstream.Greeting()) }}\n"
        )
    };
    let files: [(&str, String); 7] = [
        ("go.work", GO_WORK.to_string()),
        (
            "go.mod",
            format!("module example.com/consumer\n\ngo 1.18\n\nrequire {UMOD} {UVER}\n"),
        ),
        ("go.sum", sums.clone()),
        ("main.go", main("OUT")),
        (
            "tools/go.mod",
            format!("module example.com/consumer/tools\n\ngo 1.18\n\nrequire {UMOD} {UVER}\n"),
        ),
        ("tools/go.sum", sums),
        ("tools/main.go", main("TOOLS")),
    ];
    for (rel, body) in &files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
    // Anti-vacuity: the untouched workspace links PRISTINE everywhere.
    let m0 = Machine::new(tmp, "baseline");
    run_members(&root, &m0, &day2(&proxy), "PRISTINE", "baseline");
    let pristine = ["go.work", "go.mod", "go.sum"]
        .into_iter()
        .map(|rel| (rel, std::fs::read(root.join(rel)).unwrap()))
        .collect();
    Workspace {
        root,
        proxy,
        pristine,
    }
}

/// Restore the pre-patch go.work/go.mod/go.sum (drop any go.work.sum);
/// `.socket/` is untouched.
fn restore(dir: &Path, ws: &Workspace) {
    for (rel, bytes) in &ws.pristine {
        std::fs::write(dir.join(rel), bytes).unwrap();
    }
    let _ = std::fs::remove_file(dir.join("go.work.sum"));
}

/// Move the Socket `replace` line for `UMOD` out of the root go.mod into
/// go.work (and, when `sums` names the pinned module, its go.sum lines
/// into go.work.sum). Returns the moved directive.
fn move_replace_to_go_work(root: &Path, sums_of: Option<&str>) -> String {
    let gomod = std::fs::read_to_string(root.join("go.mod")).unwrap();
    let prefix = format!("replace {UMOD} {UVER} => ");
    let line = gomod
        .lines()
        .find(|l| l.trim().starts_with(&prefix))
        .unwrap_or_else(|| panic!("no Socket replace in go.mod:\n{gomod}"))
        .trim()
        .to_string();
    let kept: String = gomod
        .lines()
        .filter(|l| l.trim() != line)
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(root.join("go.mod"), kept).unwrap();
    std::fs::write(root.join("go.work"), format!("{GO_WORK}\n{line}\n")).unwrap();
    if let Some(smod) = sums_of {
        let gosum = std::fs::read_to_string(root.join("go.sum")).unwrap();
        let (moved, kept): (Vec<&str>, Vec<&str>) = gosum
            .lines()
            .partition(|l| l.starts_with(&format!("{smod} ")));
        assert_eq!(
            moved.len(),
            2,
            "both go.sum pin lines of the Socket module:\n{gosum}"
        );
        std::fs::write(root.join("go.sum"), kept.join("\n") + "\n").unwrap();
        std::fs::write(root.join("go.work.sum"), moved.join("\n") + "\n").unwrap();
    }
    line
}

/// Run socket-patch (SOCKET_* scrubbed, hermetic config) in `cwd`.
fn socket(cwd: &Path, args: &[&str], modcache: &Path) -> (i32, serde_json::Value, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("GOMODCACHE", modcache)
        .env("GOFLAGS", "")
        .env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\n{stderr}"));
    (out.status.code().unwrap_or(-1), env, stderr)
}

// ── vex tail wiring ───────────────────────────────────────────────────

struct Tail<'a> {
    tmp: &'a Path,
    ws: &'a Workspace,
    label: &'a str,
    uuid: &'a str,
    marker: Marker,
    /// Install env for fresh checkouts: day-2 against the proxy (hosted) or
    /// fully offline (vendored).
    install_env: Vec<(&'a str, &'a str)>,
    /// Project-relative consumed file (vendored artifact member) or, for
    /// hosted, `None`: the patched module in the install's cache.
    tamper_rel: Option<String>,
    tamper_reason: &'a str,
    unwired_reason: &'a str,
    embedded: &'a [VexVia],
}

fn tail(t: &Tail<'_>) {
    let n = std::cell::Cell::new(0);
    let machine = |what: &str| {
        n.set(n.get() + 1);
        Machine::new(
            t.tmp,
            &format!("vex-{}-{what}-{}", t.label.replace('/', "-"), n.get()),
        )
    };
    let install = |dir: &Path| {
        let m = machine("install");
        run_members(dir, &m, &t.install_env, "PATCHED", t.label);
        m.modcache
    };
    let revert = |dir: &Path| {
        restore(dir, t.ws);
        let m = machine("revert");
        run_members(dir, &m, &day2(&t.ws.proxy), "PRISTINE", t.label);
        m.modcache
    };
    let smod = format!("patch.socket.dev/gopatch/{}", t.uuid);
    let tamper = |dir: &Path, modcache: &Path| {
        let file = match &t.tamper_rel {
            Some(rel) => dir.join(rel),
            None => modcache.join(format!("{smod}@{SVER}/lib.go")),
        };
        golang_e2e_matrix::overwrite(&file, b"package upstream // tampered\n");
    };
    manifestless_vex(&ManifestlessGo {
        label: t.label,
        committed: &t.ws.root,
        scratch: t.tmp,
        purl: UPURL,
        uuid: t.uuid,
        marker: t.marker,
        vulns: VULNS,
        view: patch_view(
            t.uuid,
            UPURL,
            &[("lib.go", &git_sha256(PATCHED_LIB.as_bytes()))],
            VULNS,
        ),
        install: &install,
        revert: &revert,
        tamper: &tamper,
        tamper_reason: t.tamper_reason,
        unwired_reason: t.unwired_reason,
        embedded: t.embedded,
    });
}

// ── vendored ──────────────────────────────────────────────────────────

/// `vendor` in a workspace root: the root go.mod replace makes BOTH members
/// build the committed copy (fully offline on a fresh checkout); the replace
/// moved into go.work does the same. Each state attests manifest-less.
#[test]
fn go_work_vendored_members_build_patched_and_attest_without_manifest() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let ws = stage_workspace(tmp.path(), None);
    let root = &ws.root;

    // `vendor` builds from the installed module: download it first.
    let m1 = Machine::new(tmp.path(), "vendor");
    let dl = go(
        root,
        &m1,
        &["mod", "download", &format!("{UMOD}@{UVER}")],
        &day2(&ws.proxy),
    );
    assert!(
        dl.status.success(),
        "{}",
        String::from_utf8_lossy(&dl.stderr)
    );
    let socket_dir = root.join(".socket");
    std::fs::create_dir_all(socket_dir.join("blobs")).unwrap();
    let after = git_sha256(PATCHED_LIB.as_bytes());
    let manifest = serde_json::json!({ "patches": { UPURL: {
        "uuid": VENDOR_UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "lib.go": {
            "beforeHash": git_sha256(PRISTINE_LIB.as_bytes()),
            "afterHash": &after,
        }},
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "workspace vendor patch", "license": "MIT", "tier": "free",
    }}});
    std::fs::write(socket_dir.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(socket_dir.join("blobs").join(&after), PATCHED_LIB).unwrap();
    let (code, env, stderr) = socket(
        root,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            root.to_str().unwrap(),
        ],
        &m1.modcache,
    );
    assert_eq!(code, 0, "vendor in a go.work root: {env}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    let art = format!(".socket/vendor/golang/{VENDOR_UUID}/{UMOD}@{UVER}");
    let gomod = std::fs::read_to_string(root.join("go.mod")).unwrap();
    assert!(
        gomod
            .lines()
            .any(|l| l.trim() == format!("replace {UMOD} {UVER} => ./{art}")),
        "vendor wires the ROOT go.mod:\n{gomod}"
    );
    assert_eq!(
        std::fs::read(root.join("go.work")).unwrap(),
        GO_WORK.as_bytes(),
        "vendor never edits go.work"
    );
    let offline = vec![("GOPROXY", "off"), ("GOSUMDB", "off")];
    run_members(
        root,
        &Machine::new(tmp.path(), "vendored-root"),
        &offline,
        "PATCHED",
        "vendored, root go.mod replace",
    );

    let base = Tail {
        tmp: tmp.path(),
        ws: &ws,
        label: "vendored/go.work-root-go.mod",
        uuid: VENDOR_UUID,
        marker: Marker::Vendored,
        install_env: offline.clone(),
        tamper_rel: Some(format!("{art}/lib.go")),
        tamper_reason: "vendor_hash_mismatch",
        unwired_reason: "vendor_unwired",
        embedded: &[VexVia::Vendor, VexVia::Apply],
    };
    tail(&base);

    // The replace moved into go.work: still the committed copy for both
    // members, still attested (source go.work).
    move_replace_to_go_work(root, None);
    run_members(
        root,
        &Machine::new(tmp.path(), "vendored-work"),
        &offline,
        "PATCHED",
        "vendored, go.work replace",
    );
    tail(&Tail {
        label: "vendored/go.work-replace",
        ..base
    });
}

// ── hosted ────────────────────────────────────────────────────────────

/// The patch API for `get --mode hosted`: the record view + the reference
/// grant (goproxy override carrying the socket module path/version and its
/// go.sum pair). Owns its runtime so sync code can drive it.
struct GrantApi {
    server: wiremock::MockServer,
    _rt: tokio::runtime::Runtime,
}

impl GrantApi {
    fn start(proxy: &str, smod: &str, zip_h1: &str, mod_h1: &str) -> Self {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let artifact = format!("{proxy}/{smod}/@v/{SVER}.zip");
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            let mut view = patch_view(
                HOSTED_UUID,
                UPURL,
                &[("lib.go", &git_sha256(PATCHED_LIB.as_bytes()))],
                VULNS,
            );
            view["files"]["lib.go"]["beforeHash"] = git_sha256(PRISTINE_LIB.as_bytes()).into();
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{HOSTED_UUID}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(view))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { HOSTED_UUID: {
                        "status": "granted",
                        "url": &artifact,
                        "purl": UPURL,
                        "artifacts": [{ "kind": "tarball", "url": &artifact, "integrity": {} }],
                        "registryOverride": {
                            "kind": "goproxy",
                            "indexUrl": proxy,
                            "identifiers": {
                                "name": UMOD, "version": UVER,
                                "goModulePath": smod, "goModuleVersion": SVER,
                                "goZipDirhashH1": zip_h1, "goModH1": mod_h1,
                            }
                        }
                    }}
                })))
                .mount(&server)
                .await;
            server
        });
        GrantApi { server, _rt: rt }
    }
}

/// `get <uuid> --mode hosted` in a workspace root: the root go.mod/go.sum
/// fork-replace makes BOTH members build the patched module on a fresh
/// day-2 machine; moving the replace into go.work and its pin into
/// go.work.sum does the same. Each state attests manifest-less.
#[test]
fn go_work_hosted_members_build_patched_and_attest_without_manifest() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let smod = format!("patch.socket.dev/gopatch/{HOSTED_UUID}");
    let ws = stage_workspace(tmp.path(), Some(&smod));
    let root = &ws.root;
    let (zip_h1, mod_h1) = harvest(tmp.path(), &ws.proxy, &smod, SVER);
    let api = GrantApi::start(&ws.proxy, &smod, &zip_h1, &mod_h1);

    let m1 = Machine::new(tmp.path(), "get");
    let (code, env, stderr) = socket(
        root,
        &[
            "get",
            HOSTED_UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            root.to_str().unwrap(),
            "--api-url",
            &api.server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &m1.modcache,
    );
    assert_eq!(
        code, 0,
        "get --mode hosted in a go.work root: {env}\n{stderr}"
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env}");
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["go.mod", "go.sum"]),
        "only the ROOT module's files: {env}"
    );
    assert!(
        root.join(".socket/vendor/redirect-state.json").is_file(),
        "hosted persistence is the redirect ledger"
    );
    run_members(
        root,
        &Machine::new(tmp.path(), "hosted-root"),
        &day2(&ws.proxy),
        "PATCHED",
        "hosted, root go.mod replace",
    );

    let base = Tail {
        tmp: tmp.path(),
        ws: &ws,
        label: "hosted/go.work-root-go.mod",
        uuid: HOSTED_UUID,
        marker: Marker::Redirected,
        install_env: day2(&ws.proxy),
        tamper_rel: None,
        tamper_reason: "hash_mismatch",
        unwired_reason: "redirect_unwired",
        embedded: &[VexVia::Apply],
    };
    tail(&base);

    // The replace in go.work, its pin in go.work.sum: a fresh day-2 machine
    // (bogus sumdb) still builds PATCHED from the committed files alone.
    move_replace_to_go_work(root, Some(&smod));
    run_members(
        root,
        &Machine::new(tmp.path(), "hosted-work"),
        &day2(&ws.proxy),
        "PATCHED",
        "hosted, go.work replace + go.work.sum",
    );
    tail(&Tail {
        label: "hosted/go.work-replace",
        ..base
    });
}
