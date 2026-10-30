#![cfg(unix)]
//! Real-go e2e for Go WORKSPACES (`go.work`): hosted and vendored Socket
//! patches in a multi-module workspace, built by the real toolchain, and
//! attested by manifest-less `socket-patch vex`.
//!
//! Layout: the project root is both the workspace root (`go.work` with
//! `use ( . ./tools )`) and a module (`example.com/consumer`); the `tools`
//! member module imports the same upstream module. A module the workspace
//! shares is replaced once in `go.work` (and, hosted, pinned in
//! `go.work.sum`), which applies to the whole build — so both members must
//! link the PATCHED module; the members' go.mod and go.sum stay as they
//! were. Discovery reads `go.work` + `go.work.sum`.
//!
//! Each state then runs the manifest-less VEX tail
//! ([`golang_e2e_matrix::manifestless_vex`]): fresh checkout, real install
//! on a fresh cache, attested with and without ledgers (hosted mode writes
//! none since v5), `record_unavailable`
//! offline, omitted when tampered or reverted. Hermetic + offline (file
//! GOPROXY, per-"machine" caches, wiremock API). Needs Go 1.18+ (`go.work`);
//! the release is whatever `go` is on `PATH` (see `golang_e2e_matrix`).

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "common/envelope.rs"]
mod envelope;
#[path = "golang_e2e_matrix/mod.rs"]
mod golang_e2e_matrix;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use envelope::warning_codes;
use golang_e2e_matrix::{manifestless_vex, ManifestlessGo};
use vex_e2e_common::{binary, git_sha256, hermetic, patch_view, Marker, VexVia};

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
    publish_module(tmp, mod_path, ver, &gomod, lib);
}

/// Zip `mod_path@ver` with this `gomod` and `lib.go` into the file proxy.
fn publish_module(tmp: &Path, mod_path: &str, ver: &str, gomod: &str, lib: &str) {
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
    std::fs::write(pxv.join(format!("{ver}.mod")), gomod).unwrap();
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

/// `go mod download` each `(path, version)` into `machine`'s module cache
/// from a scratch module, as an earlier build would have: socket-patch
/// reads a workspace's module graph from the go.mod files there.
fn warm(tmp: &Path, machine: &Machine, proxy: &str, mods: &[(&str, &str)]) {
    let dir = tmp.join(format!("warm-{}", unique()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("go.mod"), "module example.com/warm\n\ngo 1.18\n").unwrap();
    let mut args = vec!["mod".to_string(), "download".to_string()];
    args.extend(mods.iter().map(|(m, v)| format!("{m}@{v}")));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = go(
        &dir,
        machine,
        &args,
        &[
            ("GOPROXY", proxy),
            ("GOSUMDB", "off"),
            ("GOFLAGS", "-mod=mod"),
            ("GOWORK", "off"),
        ],
    );
    assert!(
        out.status.success(),
        "warm {mods:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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

/// Run socket-patch (hermetic `SOCKET_*` environment) in `cwd`.
fn socket(cwd: &Path, args: &[&str], modcache: &Path) -> (i32, serde_json::Value, String) {
    socket_env(cwd, args, modcache, &[])
}

/// [`socket`] with `env` on top (`GOWORK` is unset unless `env` sets it).
fn socket_env(
    cwd: &Path,
    args: &[&str],
    modcache: &Path,
    env: &[(&str, &str)],
) -> (i32, serde_json::Value, String) {
    let mut cmd = hermetic::command(&binary());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    cmd.current_dir(cwd);
    cmd.env("GOMODCACHE", modcache)
        .env("GOFLAGS", "")
        .env("GOENV", "off")
        .env_remove("GOWORK");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        cwd,
        args,
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
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

/// `vendor` in a workspace root: the module both members require is
/// replaced once in go.work, and BOTH members build the committed copy
/// (fully offline on a fresh checkout); it attests manifest-less.
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
    assert_eq!(
        std::fs::read_to_string(root.join("go.work")).unwrap(),
        format!("{GO_WORK}\nreplace {UMOD} {UVER} => ./{art}\n"),
        "vendor wires the shared module in go.work"
    );
    for (rel, bytes) in &ws.pristine {
        if *rel == "go.mod" {
            // The root module, a `use` member, keeps the replace too.
            assert_eq!(
                std::fs::read_to_string(root.join(rel)).unwrap(),
                format!(
                    "{}\nreplace {UMOD} {UVER} => ./{art}\n",
                    String::from_utf8_lossy(bytes)
                ),
                "{rel}"
            );
        } else if *rel != "go.work" {
            assert_eq!(&std::fs::read(root.join(rel)).unwrap(), bytes, "{rel}");
        }
    }
    let offline = vec![("GOPROXY", "off"), ("GOSUMDB", "off")];
    run_members(
        root,
        &Machine::new(tmp.path(), "vendored-root"),
        &offline,
        "PATCHED",
        "vendored, go.work replace",
    );

    tail(&Tail {
        tmp: tmp.path(),
        ws: &ws,
        label: "vendored/go.work",
        uuid: VENDOR_UUID,
        marker: Marker::Vendored,
        install_env: offline.clone(),
        tamper_rel: Some(format!("{art}/lib.go")),
        tamper_reason: "vendor_hash_mismatch",
        unwired_reason: "vendor_unwired",
        embedded: &[VexVia::Vendor, VexVia::Apply],
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

    /// Serve Go's checksum database lookup of `UMOD@UVER` (what a hosted
    /// rollback reads through `SOCKET_GOSUMDB_URL`): the upstream pair.
    fn mount_sumdb(&self, zip_h1: &str, mod_h1: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let body = format!(
            "1\n{UMOD} {UVER} {zip_h1}\n{UMOD} {UVER}/go.mod {mod_h1}\n\ngo.sum database tree\n1\nAAAA\n"
        );
        self._rt.block_on(
            Mock::given(method("GET"))
                .and(path(format!("/lookup/{UMOD}@{UVER}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&self.server),
        );
    }

    /// `get HOSTED_UUID --mode hosted` in `cwd`, with `env` on top.
    fn get(
        &self,
        cwd: &Path,
        modcache: &Path,
        env: &[(&str, &str)],
    ) -> (i32, serde_json::Value, String) {
        self.get_with(cwd, modcache, env, &[])
    }

    /// [`GrantApi::get`] with `extra` arguments.
    fn get_with(
        &self,
        cwd: &Path,
        modcache: &Path,
        env: &[(&str, &str)],
        extra: &[&str],
    ) -> (i32, serde_json::Value, String) {
        let uri = self.server.uri();
        let cwd_arg = cwd.to_str().unwrap();
        let mut args = vec![
            "get",
            HOSTED_UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            cwd_arg,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ];
        args.extend_from_slice(extra);
        socket_env(cwd, &args, modcache, env)
    }
}

/// `get <uuid> --mode hosted` in a workspace root: the module both members
/// require is replaced in go.work and pinned in go.work.sum, and BOTH
/// members build the patched module on a fresh day-2 machine; it attests
/// manifest-less.
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
    warm(tmp.path(), &m1, &ws.proxy, &[(UMOD, UVER)]);
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
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["go.mod", "go.sum", "go.work", "go.work.sum"]),
        "the workspace files and the root module's own: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("go.work")).unwrap(),
        format!("{GO_WORK}\nreplace {UMOD} {UVER} => {smod} {SVER}\n")
    );
    assert_eq!(
        std::fs::read_to_string(root.join("go.work.sum")).unwrap(),
        format!("{smod} {SVER} {zip_h1}\n{smod} {SVER}/go.mod {mod_h1}\n")
    );
    // The root module, a `use` member, keeps the pin too, so a
    // `GOWORK=off` build of it stays patched.
    assert!(std::fs::read_to_string(root.join("go.mod"))
        .unwrap()
        .contains(&format!("replace {UMOD} {UVER} => {smod} {SVER}\n")));
    assert!(std::fs::read_to_string(root.join("go.sum"))
        .unwrap()
        .contains(&format!("{smod} {SVER} {zip_h1}\n")));
    for (rel, bytes) in &ws.pristine {
        if !["go.work", "go.mod", "go.sum"].contains(rel) {
            assert_eq!(&std::fs::read(root.join(rel)).unwrap(), bytes, "{rel}");
        }
    }
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted persistence is the go.mod/go.sum rewrite alone — no ledger"
    );
    run_members(
        root,
        &Machine::new(tmp.path(), "hosted-root"),
        &day2(&ws.proxy),
        "PATCHED",
        "hosted, go.work replace + go.work.sum",
    );

    tail(&Tail {
        tmp: tmp.path(),
        ws: &ws,
        label: "hosted/go.work",
        uuid: HOSTED_UUID,
        marker: Marker::Redirected,
        install_env: day2(&ws.proxy),
        tamper_rel: None,
        tamper_reason: "hash_mismatch",
        unwired_reason: "redirect_unwired",
        embedded: &[VexVia::Apply],
    });
}

// ── go.work model: members, selection, precedence, GOWORK ─────────────

/// A `go.work` workspace of two modules `a` and `b` (no root module unless
/// a test adds one), each importing `UMOD`, with the socket module and
/// `UMOD` `v1.0.0` / `v1.1.0` on the file proxy.
struct Members {
    root: PathBuf,
    proxy: String,
    smod: String,
    /// The socket module's go.sum pair.
    pin: (String, String),
    /// `UMOD` `v1.0.0`'s go.sum pair.
    upstream: (String, String),
    api: GrantApi,
}

const NEXT: &str = "v1.1.0";
const NEXT_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE-NEXT\" }\n";

fn stage_members(tmp: &Path, a_ver: &str, b_ver: &str) -> Members {
    let proxy = format!("file://{}", tmp.join("proxy").display());
    let smod = format!("patch.socket.dev/gopatch/{HOSTED_UUID}");
    publish(tmp, UMOD, UVER, PRISTINE_LIB);
    publish(tmp, UMOD, NEXT, NEXT_LIB);
    publish(tmp, &smod, SVER, PATCHED_LIB);
    let pin = harvest(tmp, &proxy, &smod, SVER);
    let upstream = harvest(tmp, &proxy, UMOD, UVER);
    let next = harvest(tmp, &proxy, UMOD, NEXT);
    let root = tmp.join("ws");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("go.work"), "go 1.18\n\nuse (\n\t./a\n\t./b\n)\n").unwrap();
    for (dir, ver) in [("a", a_ver), ("b", b_ver)] {
        let sums = if ver == UVER { &upstream } else { &next };
        let member = root.join(dir);
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("go.mod"),
            format!("module example.com/{dir}\n\ngo 1.18\n\nrequire {UMOD} {ver}\n"),
        )
        .unwrap();
        std::fs::write(
            member.join("go.sum"),
            format!("{UMOD} {ver} {}\n{UMOD} {ver}/go.mod {}\n", sums.0, sums.1),
        )
        .unwrap();
        std::fs::write(
            member.join("main.go"),
            format!(
                "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\n\
                 func main() {{ fmt.Println(\"{}:\", upstream.Greeting()) }}\n",
                dir.to_uppercase()
            ),
        )
        .unwrap();
    }
    let api = GrantApi::start(&proxy, &smod, &pin.0, &pin.1);
    Members {
        root,
        proxy,
        smod,
        pin,
        upstream,
        api,
    }
}

/// `go run ./<dir>` from `cwd` on a fresh machine; its stdout and stderr.
fn run_member(
    tmp: &Path,
    cwd: &Path,
    dir: &str,
    proxy: &str,
    extra: &[(&str, &str)],
) -> (String, String) {
    let m = Machine::new(tmp, &format!("run-{}", unique()));
    let mut env = day2(proxy);
    env.extend_from_slice(extra);
    let out = go(cwd, &m, &["run", &format!("./{dir}")], &env);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn unique() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The most common layout: a go.work root with no go.mod of its own.
/// `get --mode hosted` from the root replaces the module in go.work and
/// pins it in go.work.sum (the members' files untouched); both members
/// build the patched copy in workspace mode, and alone (`GOWORK=off`, which
/// ignores go.work) upstream; discovery from the root attests the go.work
/// pin; `rollback` from the root puts go.work back byte for byte, removes
/// the go.work.sum it created, and the members build upstream again.
#[test]
fn go_work_root_without_go_mod_hosted_pins_go_work_and_rolls_back() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let pristine: Vec<(String, String)> =
        ["go.work", "a/go.mod", "a/go.sum", "b/go.mod", "b/go.sum"]
            .iter()
            .map(|rel| (rel.to_string(), read(&w.root.join(rel))))
            .collect();
    let (out, _) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[]);
    assert!(out.contains("A: PRISTINE"), "baseline: {out}");

    let m = Machine::new(tmp.path(), "get");
    warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER)]);
    let (code, env, stderr) = w.api.get(&w.root, &m.modcache, &[]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["go.work", "go.work.sum"]),
        "{env}"
    );
    let replace = format!("replace {UMOD} {UVER} => {} {SVER}", w.smod);
    let work = read(&w.root.join("go.work"));
    assert!(work.lines().any(|l| l.trim() == replace), "{work}");
    assert!(
        read(&w.root.join("go.work.sum")).contains(&format!("{} {SVER} {}\n", w.smod, w.pin.0)),
        "go.work.sum"
    );
    for (rel, text) in pristine.iter().skip(1) {
        assert_eq!(&read(&w.root.join(rel)), text, "{rel} untouched");
    }
    assert!(!w.root.join("go.mod").exists(), "no root go.mod is created");
    for dir in ["a", "b"] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(
            out.contains(&format!("{}: PATCHED", dir.to_uppercase())),
            "{dir}: {out}\n{err}"
        );
        let (out, err) = run_member(
            tmp.path(),
            &w.root.join(dir),
            ".",
            &w.proxy,
            &[("GOWORK", "off")],
        );
        assert!(out.contains("PRISTINE"), "{dir} alone: {out}\n{err}");
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let discovery = rt.block_on(socket_patch_core::vex::discover::discover_patched_refs(
        &w.root,
    ));
    let sources: Vec<String> = discovery
        .refs
        .iter()
        .filter(|r| r.purl == UPURL && r.uuid == HOSTED_UUID && r.lockfile_basis_ok())
        .map(|r| r.source_file.to_string_lossy().into_owned())
        .collect();
    assert_eq!(sources, ["go.work"], "{:?}", discovery);

    w.api.mount_sumdb(&w.upstream.0, &w.upstream.1);
    let uri = w.api.server.uri();
    let (code, env, stderr) = socket_env(
        &w.root,
        &[
            "rollback",
            "--json",
            "--yes",
            "--cwd",
            w.root.to_str().unwrap(),
        ],
        &m.modcache,
        &[("SOCKET_GOSUMDB_URL", uri.as_str())],
    );
    assert_eq!(code, 0, "{env}\n{stderr}");
    for (rel, text) in &pristine {
        assert_eq!(&read(&w.root.join(rel)), text, "{rel} after rollback");
    }
    assert!(!w.root.join("go.work.sum").exists(), "{env}");
    let (out, err) = run_member(tmp.path(), &w.root, "b", &w.proxy, &[]);
    assert!(out.contains("B: PRISTINE"), "after rollback: {out}\n{err}");
}

/// A hosted pin moved into go.work, its sum lines in go.work.sum (where go
/// itself writes them in workspace mode): `rollback` drops the go.work
/// replace and the socket lines, puts the upstream pair back into
/// go.work.sum, and the workspace builds upstream on a fresh machine.
#[test]
fn go_work_pin_and_go_work_sum_roll_back() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    for dir in ["a", "b"] {
        let sum = w.root.join(dir).join("go.sum");
        std::fs::write(&sum, "").unwrap();
    }
    let work = read(&w.root.join("go.work"));
    std::fs::write(
        w.root.join("go.work"),
        format!("{work}\nreplace {UMOD} {UVER} => {} {SVER}\n", w.smod),
    )
    .unwrap();
    std::fs::write(
        w.root.join("go.work.sum"),
        format!(
            "{s} {SVER} {}\n{s} {SVER}/go.mod {}\n",
            w.pin.0,
            w.pin.1,
            s = w.smod
        ),
    )
    .unwrap();
    for dir in ["a", "b"] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(out.contains("PATCHED"), "{dir}: {out}\n{err}");
    }

    let m = Machine::new(tmp.path(), "rollback");
    w.api.mount_sumdb(&w.upstream.0, &w.upstream.1);
    let uri = w.api.server.uri();
    let (code, env, stderr) = socket_env(
        &w.root,
        &[
            "rollback",
            "--json",
            "--yes",
            "--cwd",
            w.root.to_str().unwrap(),
        ],
        &m.modcache,
        &[("SOCKET_GOSUMDB_URL", uri.as_str())],
    );
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(read(&w.root.join("go.work")), work);
    let work_sum = read(&w.root.join("go.work.sum"));
    assert!(!work_sum.contains("patch.socket.dev"), "{work_sum}");
    assert_eq!(
        work_sum,
        format!(
            "{UMOD} {UVER} {}\n{UMOD} {UVER}/go.mod {}\n",
            w.upstream.0, w.upstream.1
        )
    );
    for dir in ["a", "b"] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(out.contains("PRISTINE"), "{dir}: {out}\n{err}");
    }
}

/// Another member requiring a higher version raises the workspace build
/// above the patched one: hosted mode in `a` refuses (go builds v1.1.0)
/// whether `GOWORK` is unset or `auto`, refuses a relative `GOWORK` as go
/// does, and with `GOWORK=off` (module mode, where `a` builds v1.0.0)
/// pins it, and `a` alone builds the patched copy.
#[test]
fn cross_member_version_raise_and_gowork_modes() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, NEXT);
    let a = w.root.join("a");
    let m = Machine::new(tmp.path(), "list");
    let list = go(&a, &m, &["list", "-m", UMOD], &day2(&w.proxy));
    assert_eq!(
        String::from_utf8_lossy(&list.stdout).trim(),
        format!("{UMOD} {NEXT}"),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let go_mod = read(&a.join("go.mod"));

    for gowork in [None, Some("auto")] {
        let env: Vec<(&str, &str)> = gowork.map(|v| ("GOWORK", v)).into_iter().collect();
        let (code, out, stderr) = w.api.get(&a, &m.modcache, &env);
        assert_eq!(out["summary"]["applied"], 0, "{gowork:?}: {out}\n{stderr}");
        assert!(
            warning_codes(&out).contains(&"redirect_golang_version_mismatch".to_string()),
            "{gowork:?}: {out}"
        );
        assert_ne!(code, -1);
        assert_eq!(read(&a.join("go.mod")), go_mod, "{gowork:?}");
    }
    let (_, out, _) = w.api.get(&a, &m.modcache, &[("GOWORK", "go.work")]);
    assert_eq!(out["summary"]["applied"], 0, "{out}");
    assert!(
        warning_codes(&out).contains(&"redirect_golang_workspace_conflict".to_string()),
        "{out}"
    );
    assert_eq!(read(&a.join("go.mod")), go_mod);

    let (code, out, stderr) = w.api.get(&a, &m.modcache, &[("GOWORK", "off")]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 1, "{out}");
    let (stdout, err) = run_member(tmp.path(), &a, ".", &w.proxy, &[("GOWORK", "off")]);
    assert!(stdout.contains("A: PATCHED"), "{stdout}\n{err}");
    // The workspace still builds v1.1.0: the replace pinned to v1.0.0 is
    // inert there, and `vex` from `a` must not attest it.
    let (stdout, err) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[]);
    assert!(stdout.contains("PRISTINE-NEXT"), "{stdout}\n{err}");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sel = rt.block_on(socket_patch_core::vendor::go_build_list::project_selection(
        &a, UMOD, UVER,
    ));
    assert_eq!(
        sel,
        Some(socket_patch_core::vendor::go_build_list::Selection::Other(
            NEXT.to_string()
        ))
    );
}

/// The hosted writer consults the go.work in effect before writing: a
/// go.work replace of this module (or a member replacing the same version
/// elsewhere) keeps the pin from taking effect, so nothing is written and
/// the patch is not reported redirected; a go.work replace of ANOTHER
/// version leaves the member replace in force (Go 1.26 precedence), so
/// hosted pins it and the member builds patched.
#[test]
fn hosted_gate_follows_go_work_precedence() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let fork = w.root.join("fork");
    std::fs::create_dir_all(&fork).unwrap();
    std::fs::write(fork.join("go.mod"), format!("module {UMOD}\n\ngo 1.18\n")).unwrap();
    std::fs::write(
        fork.join("lib.go"),
        "package upstream\n\nfunc Greeting() string { return \"FORK\" }\n",
    )
    .unwrap();
    let b = w.root.join("b");
    let work = read(&w.root.join("go.work"));
    let a_mod = read(&w.root.join("a/go.mod"));
    let b_mod = read(&b.join("go.mod"));
    let m = Machine::new(tmp.path(), "gate");
    warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER)]);

    for (label, work_extra, a_extra) in [
        (
            "go.work replaces this version",
            format!("\nreplace {UMOD} {UVER} => ./fork\n"),
            "",
        ),
        (
            "go.work replaces every version",
            format!("\nreplace {UMOD} => ./fork\n"),
            "",
        ),
        (
            "member a replaces it elsewhere",
            String::new(),
            "\nreplace example.com/upstream v1.0.0 => ../fork\n",
        ),
        (
            "member a replaces every version elsewhere",
            String::new(),
            "\nreplace example.com/upstream => ../fork\n",
        ),
    ] {
        std::fs::write(w.root.join("go.work"), format!("{work}{work_extra}")).unwrap();
        std::fs::write(w.root.join("a/go.mod"), format!("{a_mod}{a_extra}")).unwrap();
        // The user's own replace is protected unless the conflict is
        // accepted; accepted, the go.work gate still refuses the pin.
        let (_, out, _) = w.api.get(&b, &m.modcache, &[]);
        assert_eq!(
            out["error"]["code"], "user_patch_conflict",
            "{label}: {out}"
        );
        let (_, out, stderr) = w
            .api
            .get_with(&b, &m.modcache, &[], &["--allow-patch-conflicts"]);
        assert_eq!(out["summary"]["applied"], 0, "{label}: {out}\n{stderr}");
        assert!(
            warning_codes(&out).contains(&"redirect_golang_workspace_conflict".to_string()),
            "{label}: {out}"
        );
        assert_eq!(read(&b.join("go.mod")), b_mod, "{label}: nothing written");
        let (stdout, err) = run_member(tmp.path(), &w.root, "b", &w.proxy, &[]);
        assert!(
            stdout.contains("B: FORK"),
            "{label}: workspace still builds: {stdout}\n{err}"
        );
    }

    // What the gate prevents: b's pin beside a's version-less replace never
    // builds the patched copy (go links the fork or refuses the workspace).
    std::fs::write(w.root.join("go.work"), &work).unwrap();
    std::fs::write(
        w.root.join("a/go.mod"),
        format!("{a_mod}\nreplace {UMOD} => ../fork\n"),
    )
    .unwrap();
    std::fs::write(
        b.join("go.mod"),
        format!("{b_mod}\nreplace {UMOD} {UVER} => {} {SVER}\n", w.smod),
    )
    .unwrap();
    let b_sum = read(&b.join("go.sum"));
    std::fs::write(
        b.join("go.sum"),
        format!(
            "{b_sum}{smod} {SVER} {}\n{smod} {SVER}/go.mod {}\n",
            w.pin.0,
            w.pin.1,
            smod = w.smod
        ),
    )
    .unwrap();
    for dir in ["a", "b"] {
        let (stdout, err) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(
            !stdout.contains("PATCHED"),
            "{dir}: a wildcard member replace beside the pin: {stdout}\n{err}"
        );
    }
    std::fs::write(b.join("go.mod"), &b_mod).unwrap();
    std::fs::write(b.join("go.sum"), &b_sum).unwrap();

    std::fs::write(w.root.join("a/go.mod"), &a_mod).unwrap();
    std::fs::write(
        w.root.join("go.work"),
        format!("{work}\nreplace {UMOD} v0.9.0 => ./fork\n"),
    )
    .unwrap();
    let (code, out, stderr) = w
        .api
        .get_with(&b, &m.modcache, &[], &["--allow-patch-conflicts"]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 1, "{out}");
    assert!(
        !warning_codes(&out).contains(&"go_workspace_replace_ineffective".to_string()),
        "{out}"
    );
    let (stdout, err) = run_member(tmp.path(), &w.root, "b", &w.proxy, &[]);
    assert!(stdout.contains("B: PATCHED"), "{stdout}\n{err}");
}

// ── one go.work replace for a module two members share ────────────────

/// Write a manifest + blob for `uuid` patching `UMOD@UVER` into `root`.
fn write_local_patch(root: &Path, uuid: &str) {
    let socket_dir = root.join(".socket");
    std::fs::create_dir_all(socket_dir.join("blobs")).unwrap();
    let after = git_sha256(PATCHED_LIB.as_bytes());
    let manifest = serde_json::json!({ "patches": { UPURL: {
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "lib.go": {
            "beforeHash": git_sha256(PRISTINE_LIB.as_bytes()),
            "afterHash": &after,
        }},
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "shared module patch", "license": "MIT", "tier": "free",
    }}});
    std::fs::write(socket_dir.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(socket_dir.join("blobs").join(&after), PATCHED_LIB).unwrap();
}

/// The workspace build with go's strictest everyday flags: both members
/// build with `-mod=readonly` from the committed files alone, and `go list
/// -m all` shows `UMOD` replaced by `want`.
fn assert_workspace_builds(tmp: &Path, root: &Path, env: &[(&str, &str)], want: &str) {
    let m = Machine::new(tmp, &format!("strict-{}", unique()));
    let build = go(root, &m, &["build", "-mod=readonly", "./a", "./b"], env);
    assert!(
        build.status.success(),
        "go build -mod=readonly: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let list = go(root, &m, &["list", "-m", "all"], env);
    let out = String::from_utf8_lossy(&list.stdout);
    assert!(
        list.status.success(),
        "go list -m all: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(
        out.lines()
            .any(|l| l.starts_with(&format!("{UMOD} {UVER} => ")) && l.contains(want)),
        "go list -m all must show the replacement {want}:\n{out}"
    );
}

/// The files a revert must give back byte for byte, and those it must
/// never touch.
fn snapshot(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    [
        "go.work",
        "go.work.sum",
        "a/go.mod",
        "a/go.sum",
        "b/go.mod",
        "b/go.sum",
    ]
    .iter()
    .map(|rel| (rel.to_string(), std::fs::read(root.join(rel)).ok()))
    .collect()
}

fn assert_snapshot(root: &Path, before: &[(String, Option<Vec<u8>>)], what: &str) {
    for (rel, bytes) in before {
        assert_eq!(
            &std::fs::read(root.join(rel)).ok(),
            bytes,
            "{what}: {rel} is not as it was"
        );
    }
}

/// Download `UMOD@UVER` into `m`'s cache (what `apply` and `vendor` copy).
fn download(root: &Path, m: &Machine, proxy: &str) {
    let dl = go(
        root,
        m,
        &["mod", "download", &format!("{UMOD}@{UVER}")],
        &day2(proxy),
    );
    assert!(
        dl.status.success(),
        "{}",
        String::from_utf8_lossy(&dl.stderr)
    );
}

/// `vendor` from a go.work root with no go.mod, two members requiring the
/// module: one replace in go.work (target relative to the root, where the
/// copy lives), the members' files untouched; both members build the
/// committed copy offline, `-mod=readonly`; a re-run changes nothing;
/// `vendor --check` is clean and discovery attests the go.work wiring;
/// `vendor --revert` gives go.work back byte for byte.
#[test]
fn shared_module_vendored_once_in_go_work() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let before = snapshot(&w.root);
    let m = Machine::new(tmp.path(), "vendor");
    download(&w.root, &m, &w.proxy);
    write_local_patch(&w.root, VENDOR_UUID);
    let cwd = w.root.to_str().unwrap();
    let vendor = |extra: &[&str]| {
        let mut args = vec!["vendor", "--json", "--offline", "--cwd", cwd];
        args.extend_from_slice(extra);
        socket(&w.root, &args, &m.modcache)
    };

    let (code, env, stderr) = vendor(&[]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    let art = format!(".socket/vendor/golang/{VENDOR_UUID}/{UMOD}@{UVER}");
    let work = read(&w.root.join("go.work"));
    assert_eq!(
        work,
        format!("go 1.18\n\nuse (\n\t./a\n\t./b\n)\n\nreplace {UMOD} {UVER} => ./{art}\n")
    );
    assert_snapshot(&w.root, &before[1..], "vendor");
    let offline = [("GOPROXY", "off"), ("GOSUMDB", "off")];
    for dir in ["a", "b"] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, "off", &offline);
        assert!(
            out.contains(&format!("{}: PATCHED", dir.to_uppercase())),
            "{dir}: {out}\n{err}"
        );
    }
    assert_workspace_builds(tmp.path(), &w.root, &offline, &format!("./{art}"));

    let (code, env, stderr) = vendor(&[]);
    assert_eq!(code, 0, "re-run: {env}\n{stderr}");
    assert_eq!(read(&w.root.join("go.work")), work, "re-run is byte-stable");
    let (code, env, stderr) = vendor(&["--check"]);
    assert_eq!(code, 0, "vendor --check: {env}\n{stderr}");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let discovery = rt.block_on(socket_patch_core::vex::discover::discover_patched_refs(
        &w.root,
    ));
    let sources: Vec<String> = discovery
        .refs
        .iter()
        .filter(|r| r.purl == UPURL && r.uuid == VENDOR_UUID)
        .map(|r| r.source_file.to_string_lossy().into_owned())
        .collect();
    assert_eq!(sources, ["go.work"], "{discovery:?}");

    let (code, env, stderr) = vendor(&["--revert"]);
    assert_eq!(code, 0, "vendor --revert: {env}\n{stderr}");
    assert_snapshot(&w.root, &before, "vendor --revert");
    assert!(!w.root.join(".socket/vendor/golang").exists());
    let (out, err) = run_member(tmp.path(), &w.root, "b", &w.proxy, &[]);
    assert!(out.contains("B: PRISTINE"), "after revert: {out}\n{err}");
}

/// `apply` from a go.work root with no go.mod: the module both members
/// require is copied once under `.socket/go-patches/` and replaced once in
/// go.work; both members build it, `-mod=readonly`; `apply --check` is
/// clean; a re-run changes nothing; `rollback` gives go.work back byte for
/// byte and removes the copy.
#[test]
fn shared_module_applied_once_in_go_work() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let before = snapshot(&w.root);
    let m = Machine::new(tmp.path(), "apply");
    download(&w.root, &m, &w.proxy);
    write_local_patch(&w.root, VENDOR_UUID);
    let cwd = w.root.to_str().unwrap();
    let run = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend_from_slice(&["--ecosystems", "golang", "--cwd", cwd]);
        socket_raw(&w.root, &all, &m.modcache)
    };

    let (code, out, err) = run(&["apply", "--offline", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let copy = format!(".socket/go-patches/{UMOD}@{UVER}");
    let work = read(&w.root.join("go.work"));
    assert_eq!(
        work,
        format!("go 1.18\n\nuse (\n\t./a\n\t./b\n)\n\nreplace {UMOD} {UVER} => ./{copy}\n")
    );
    assert_snapshot(&w.root, &before[1..], "apply");
    for dir in ["a", "b"] {
        let (stdout, stderr) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(
            stdout.contains(&format!("{}: PATCHED", dir.to_uppercase())),
            "{dir}: {stdout}\n{stderr}"
        );
    }
    assert_workspace_builds(tmp.path(), &w.root, &day2(&w.proxy), &format!("./{copy}"));
    let (code, out, err) = run(&["apply", "--check"]);
    assert_eq!(code, 0, "apply --check: {out}\n{err}");
    let (code, out, err) = run(&["apply", "--offline", "--json"]);
    assert_eq!(code, 0, "re-run: {out}\n{err}");
    assert_eq!(read(&w.root.join("go.work")), work, "re-run is byte-stable");

    let (code, out, err) = run(&["rollback", "--offline", "--json"]);
    assert_eq!(code, 0, "rollback: {out}\n{err}");
    assert_snapshot(&w.root, &before, "rollback");
    assert!(!w.root.join(".socket/go-patches").exists());
    let (stdout, stderr) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[]);
    assert!(stdout.contains("A: PRISTINE"), "{stdout}\n{stderr}");
}

/// `GOWORK` naming another file beside the root's go.work (#1810): `apply`
/// never writes the replace into the root's go.work, which go doesn't
/// read. A root with no module refuses and writes nothing, with or without
/// a root go.work; a root module the workspace uses takes the replace in
/// its go.mod, and both members build the patched copy through it.
#[test]
fn apply_never_writes_go_work_when_gowork_names_a_sibling_file() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    // go takes its working directory with symlinks resolved, so a GOWORK
    // under an unresolved temp path (macOS's /var -> /private/var) holds
    // no member go runs in. (Windows keeps the path: canonicalize would
    // give a \\?\ path go can't use.)
    let base = if cfg!(windows) {
        tmp.path().to_path_buf()
    } else {
        tmp.path().canonicalize().unwrap()
    };
    let w = stage_members(&base, UVER, UVER);
    let m = Machine::new(&base, "sibling");
    download(&w.root, &m, &w.proxy);
    write_local_patch(&w.root, VENDOR_UUID);
    let ci = w.root.join("ci.work");
    std::fs::write(&ci, "go 1.18\n\nuse (\n\t./a\n\t./b\n)\n").unwrap();
    std::fs::write(w.root.join("go.work"), "go 1.18\n\nuse ./a\n").unwrap();
    let gowork = [("GOWORK", ci.to_str().unwrap())];
    let cwd = w.root.to_str().unwrap();
    let apply = || {
        socket_env(
            &w.root,
            &[
                "apply",
                "--offline",
                "--json",
                "--ecosystems",
                "golang",
                "--cwd",
                cwd,
            ],
            &m.modcache,
            &gowork,
        )
    };
    let files = |root: &Path| {
        let mut all = snapshot(root);
        all.push(("ci.work".into(), std::fs::read(root.join("ci.work")).ok()));
        all
    };

    let before = files(&w.root);
    let (code, out, stderr) = apply();
    assert_ne!(code, 0, "{out}\n{stderr}");
    let text = out.to_string();
    assert!(text.contains("has nowhere to go"), "{out}");
    assert!(text.contains("GOWORK selects"), "{out}");
    assert_snapshot(&w.root, &before, "no root module, root go.work");

    std::fs::remove_file(w.root.join("go.work")).unwrap();
    let before = files(&w.root);
    let (code, out, stderr) = apply();
    assert_ne!(code, 0, "{out}\n{stderr}");
    let text = out.to_string();
    assert!(text.contains("has nowhere to go"), "{out}");
    assert!(!text.contains("No such file"), "{out}");
    assert_snapshot(&w.root, &before, "no root module, no root go.work");

    // A root module both workspace files use.
    let root_mod = format!("module example.com/root\n\ngo 1.18\n\nrequire {UMOD} {UVER}\n");
    std::fs::write(w.root.join("go.mod"), &root_mod).unwrap();
    std::fs::write(
        w.root.join("go.sum"),
        format!(
            "{UMOD} {UVER} {}\n{UMOD} {UVER}/go.mod {}\n",
            w.upstream.0, w.upstream.1
        ),
    )
    .unwrap();
    let work = "go 1.18\n\nuse (\n\t.\n\t./a\n\t./b\n)\n";
    std::fs::write(&ci, work).unwrap();
    std::fs::write(w.root.join("go.work"), work).unwrap();
    let (code, out, stderr) = apply();
    assert_eq!(code, 0, "{out}\n{stderr}");
    let copy = format!(".socket/go-patches/{UMOD}@{UVER}");
    assert_eq!(
        read(&w.root.join("go.mod")),
        format!("{root_mod}\nreplace {UMOD} {UVER} => ./{copy}\n")
    );
    assert_eq!(read(&w.root.join("go.work")), work, "go.work untouched");
    assert_eq!(read(&ci), work, "ci.work untouched");
    for dir in ["a", "b"] {
        let (stdout, stderr) = run_member(&base, &w.root, dir, &w.proxy, &gowork);
        assert!(
            stdout.contains(&format!("{}: PATCHED", dir.to_uppercase())),
            "{dir}: {stdout}\n{stderr}"
        );
    }
}

/// `get --mode hosted` from a go.work root, re-run: nothing changes, and
/// the workspace builds the Socket module `-mod=readonly` from the
/// committed go.work.sum on a fresh day-2 machine (bogus sumdb).
#[test]
fn shared_module_hosted_rerun_is_stable_and_builds_readonly() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let m = Machine::new(tmp.path(), "get");
    warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER)]);
    let (code, env, stderr) = w.api.get(&w.root, &m.modcache, &[]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    let after = snapshot(&w.root);
    let (code, env, stderr) = w.api.get(&w.root, &m.modcache, &[]);
    assert_eq!(code, 0, "re-run: {env}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    assert_snapshot(&w.root, &after, "hosted re-run");
    assert_workspace_builds(
        tmp.path(),
        &w.root,
        &day2(&w.proxy),
        &format!("{} {SVER}", w.smod),
    );
}

/// [`socket`] for a command whose stdout may not be one JSON document.
fn socket_raw(cwd: &Path, args: &[&str], modcache: &Path) -> (i32, String, String) {
    let mut cmd = hermetic::command(&binary());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    cmd.current_dir(cwd);
    cmd.env("GOMODCACHE", modcache)
        .env("GOFLAGS", "")
        .env("GOENV", "off")
        .env_remove("GOWORK");
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        cwd,
        args,
        &[("GOMODCACHE", modcache.to_str().unwrap())],
    );
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ── go work vendor, GOWORK elsewhere, member runs ─────────────────────

/// `go work vendor` (Go 1.22+) at `root`; its success.
fn work_vendor(tmp: &Path, root: &Path, proxy: &str) -> Output {
    let m = Machine::new(tmp, &format!("work-vendor-{}", unique()));
    go(root, &m, &["work", "vendor"], &day2(proxy))
}

/// A committed workspace `vendor/` directory: after vendor or hosted mode
/// replaces the shared module in go.work, the run warns that
/// `vendor/modules.txt` does not record it and the `-mod=vendor` build
/// fails as go says; `go work vendor` records it and the members build the
/// patched module from `vendor/` fully offline; `vendor --check` is clean
/// again.
#[test]
fn go_work_vendor_records_the_go_work_replace() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || golang_e2e_matrix::go_minor() < 22
    {
        return;
    }
    for mode in ["vendored", "hosted"] {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = ChmodGuard(tmp.path().to_path_buf());
        let w = stage_members(tmp.path(), UVER, UVER);
        let out = work_vendor(tmp.path(), &w.root, &w.proxy);
        assert!(
            out.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let offline_vendor = [
            ("GOPROXY", "off"),
            ("GOSUMDB", "off"),
            ("GOFLAGS", "-mod=vendor"),
        ];
        let (out, err) = run_member(tmp.path(), &w.root, "a", "off", &offline_vendor);
        assert!(out.contains("A: PRISTINE"), "{mode} baseline: {out}\n{err}");

        let m = Machine::new(tmp.path(), "run");
        let env = if mode == "vendored" {
            download(&w.root, &m, &w.proxy);
            write_local_patch(&w.root, VENDOR_UUID);
            let cwd = w.root.to_str().unwrap();
            let (code, env, stderr) = socket(
                &w.root,
                &["vendor", "--json", "--offline", "--cwd", cwd],
                &m.modcache,
            );
            assert_eq!(code, 0, "{env}\n{stderr}");
            env
        } else {
            warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER)]);
            let (code, env, stderr) = w.api.get(&w.root, &m.modcache, &[]);
            assert_eq!(code, 0, "{env}\n{stderr}");
            env
        };
        assert!(
            warning_codes(&env).contains(&"go_vendor_modules_txt_out_of_sync".to_string()),
            "{mode}: the run names `go work vendor`: {env}"
        );
        let (out, err) = run_member(tmp.path(), &w.root, "a", "off", &offline_vendor);
        assert!(
            !out.contains("PATCHED") && err.contains("inconsistent vendoring"),
            "{mode}: {out}\n{err}"
        );

        let out = work_vendor(tmp.path(), &w.root, &w.proxy);
        assert!(
            out.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let modules_txt = read(&w.root.join("vendor/modules.txt"));
        assert!(
            modules_txt
                .lines()
                .any(|l| l.starts_with(&format!("# {UMOD} {UVER} => "))),
            "{mode}: {modules_txt}"
        );
        for dir in ["a", "b"] {
            let (out, err) = run_member(tmp.path(), &w.root, dir, "off", &offline_vendor);
            assert!(
                out.contains(&format!("{}: PATCHED", dir.to_uppercase())),
                "{mode} {dir}: {out}\n{err}"
            );
        }
        if mode == "vendored" {
            let cwd = w.root.to_str().unwrap();
            let (code, env, stderr) = socket(
                &w.root,
                &["vendor", "--check", "--json", "--cwd", cwd],
                &m.modcache,
            );
            assert_eq!(code, 0, "vendor --check: {env}\n{stderr}");
        }
    }
}

/// Where the run happens decides where the replace goes. From a member
/// (go.work above it) `vendor` writes the member's go.mod, and a second
/// member is refused with the way out: run at the workspace root. From the
/// root the shared module is replaced once in go.work, over the member's
/// own Socket replace, and both members build it. `GOWORK` naming the same
/// file by absolute path is the same workspace; one naming a go.work
/// elsewhere leaves the root with no module and no go.work of its own, so
/// the run refuses and writes nothing.
#[test]
fn run_location_and_gowork_decide_the_replace_file() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let m = Machine::new(tmp.path(), "vendor");
    download(&w.root, &m, &w.proxy);
    let (a, b) = (w.root.join("a"), w.root.join("b"));
    write_local_patch(&a, VENDOR_UUID);
    write_local_patch(&b, VENDOR_UUID);
    write_local_patch(&w.root, VENDOR_UUID);
    let vendor = |cwd: &Path, env: &[(&str, &str)]| {
        socket_env(
            cwd,
            &[
                "vendor",
                "--json",
                "--offline",
                "--cwd",
                cwd.to_str().unwrap(),
            ],
            &m.modcache,
            env,
        )
    };

    let (code, env, stderr) = vendor(&a, &[]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    let art = format!(".socket/vendor/golang/{VENDOR_UUID}/{UMOD}@{UVER}");
    assert!(
        read(&a.join("go.mod")).contains(&format!("replace {UMOD} {UVER} => ./{art}")),
        "a member run writes its own go.mod"
    );
    let b_mod = read(&b.join("go.mod"));
    let (code, env, _) = vendor(&b, &[]);
    assert_ne!(code, 0, "{env}");
    let text = env.to_string();
    assert!(
        text.contains("conflicting replacements") && text.contains("run socket-patch in"),
        "{env}"
    );
    assert_eq!(read(&b.join("go.mod")), b_mod, "nothing written in b");

    let work_before = read(&w.root.join("go.work"));
    let elsewhere = tmp.path().join("other");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(
        elsewhere.join("go.work"),
        format!(
            "go 1.18\n\nuse (\n\t{}\n\t{}\n)\n",
            a.display(),
            b.display()
        ),
    )
    .unwrap();
    let gowork = elsewhere.join("go.work");
    let (code, env, _) = vendor(&w.root, &[("GOWORK", gowork.to_str().unwrap())]);
    assert_ne!(code, 0, "{env}");
    assert!(env.to_string().contains("has nowhere to go"), "{env}");
    assert_eq!(read(&w.root.join("go.work")), work_before);

    let own = w.root.join("go.work");
    let (code, env, stderr) = vendor(&w.root, &[("GOWORK", own.to_str().unwrap())]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(
        read(&w.root.join("go.work")),
        format!("{work_before}\nreplace {UMOD} {UVER} => ./{art}\n")
    );
    let offline = [("GOPROXY", "off"), ("GOSUMDB", "off")];
    for dir in ["a", "b"] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, "off", &offline);
        assert!(
            out.contains(&format!("{}: PATCHED", dir.to_uppercase())),
            "{dir}: {out}\n{err}"
        );
    }
}

/// go keeps no member's go.mod tidy in workspace mode: `b` requires `x`,
/// which requires `UMOD` v1.1.0, so the workspace builds v1.1.0 although
/// every member requires v1.0.0, and only x's go.mod shows it. Until the
/// module cache holds it nothing proves the selection and hosted pins
/// nothing; then hosted refuses, and a pin written in module mode is inert
/// in the workspace, with its zip line or (tidied) without.
#[test]
fn dependency_raise_makes_a_workspace_pin_inert() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    use socket_patch_core::vendor::go_build_list::Selection;
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let xmod = "example.com/x";
    publish_module(
        tmp.path(),
        xmod,
        UVER,
        &format!("module {xmod}\n\ngo 1.18\n\nrequire {UMOD} {NEXT}\n"),
        &format!(
            "package x\n\nimport \"{UMOD}\"\n\nfunc Greeting() string {{ return upstream.Greeting() }}\n"
        ),
    );
    let x = harvest(tmp.path(), &w.proxy, xmod, UVER);
    let next = harvest(tmp.path(), &w.proxy, UMOD, NEXT);
    let (a, b) = (w.root.join("a"), w.root.join("b"));
    let b_mod = read(&b.join("go.mod"));
    std::fs::write(
        b.join("go.mod"),
        format!("{b_mod}\nrequire {xmod} {UVER}\n"),
    )
    .unwrap();
    let b_sum = read(&b.join("go.sum"));
    std::fs::write(
        b.join("go.sum"),
        format!(
            "{b_sum}{xmod} {UVER} {}\n{xmod} {UVER}/go.mod {}\n{UMOD} {NEXT}/go.mod {}\n",
            x.0, x.1, next.1
        ),
    )
    .unwrap();

    // The module cache holds none of the graph yet: nothing proves which
    // version the workspace builds, so hosted pins nothing.
    let m = Machine::new(tmp.path(), "raise");
    let a_files = (read(&a.join("go.mod")), read(&a.join("go.sum")));
    let (code, out, stderr) = w.api.get(&a, &m.modcache, &[]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 0, "{out}");
    assert!(
        warning_codes(&out).contains(&"redirect_golang_not_in_module_graph".to_string()),
        "{out}"
    );
    assert_eq!((read(&a.join("go.mod")), read(&a.join("go.sum"))), a_files);

    // With x's go.mod in the cache (any earlier build puts it there) the
    // raise shows before go.work.sum records anything: hosted refuses.
    warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER), (xmod, UVER)]);
    let (code, out, stderr) = w.api.get(&a, &m.modcache, &[]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 0, "{out}");
    assert!(
        warning_codes(&out).contains(&"redirect_golang_version_mismatch".to_string()),
        "{out}"
    );
    assert!(!w.root.join("go.work.sum").exists());

    // A pin written in module mode (`GOWORK=off`, where `a` builds v1.0.0)
    // is inert in the workspace, which builds v1.1.0.
    let (code, out, stderr) = w.api.get(&a, &m.modcache, &[("GOWORK", "off")]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 1, "{out}");
    let (stdout, err) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[("GOSUMDB", "off")]);
    assert!(stdout.contains("A: PRISTINE-NEXT"), "{stdout}\n{err}");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let selection = || {
        use socket_patch_core::vendor::go_workspace::{load, Loaded};
        let Loaded::Workspace(mut ws) = rt.block_on(load(&a)) else {
            panic!("no workspace");
        };
        rt.block_on(ws.read_graph_from(Some(&m.modcache)));
        ws.selection(UMOD, UVER)
    };
    assert_eq!(selection(), Selection::Other(NEXT.to_string()), "zip pin");
    let zip_line = format!("{} {SVER} ", w.smod);
    let tidied: String = read(&a.join("go.sum"))
        .lines()
        .filter(|l| !l.starts_with(&zip_line))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(a.join("go.sum"), tidied).unwrap();
    assert_eq!(
        selection(),
        Selection::Other(NEXT.to_string()),
        "/go.mod-only pin"
    );
}

/// go only ever appends to `go.work.sum`: once `b` stops requiring `x`
/// (which raised `UMOD` to v1.1.0), the workspace builds v1.0.0 again but
/// the v1.1.0 zip line stays. That stale line is no evidence: hosted pins
/// `a`, which builds the patched copy.
#[test]
fn a_stale_go_work_sum_line_does_not_refuse_a_pin() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let xmod = "example.com/x";
    publish_module(
        tmp.path(),
        xmod,
        UVER,
        &format!("module {xmod}\n\ngo 1.18\n\nrequire {UMOD} {NEXT}\n"),
        &format!(
            "package x\n\nimport \"{UMOD}\"\n\nfunc Greeting() string {{ return upstream.Greeting() }}\n"
        ),
    );
    let x = harvest(tmp.path(), &w.proxy, xmod, UVER);
    let next = harvest(tmp.path(), &w.proxy, UMOD, NEXT);
    let (a, b) = (w.root.join("a"), w.root.join("b"));
    let (b_mod, b_sum) = (read(&b.join("go.mod")), read(&b.join("go.sum")));
    std::fs::write(
        b.join("go.mod"),
        format!("{b_mod}\nrequire {xmod} {UVER}\n"),
    )
    .unwrap();
    std::fs::write(
        b.join("go.sum"),
        format!(
            "{b_sum}{xmod} {UVER} {}\n{xmod} {UVER}/go.mod {}\n{UMOD} {NEXT}/go.mod {}\n",
            x.0, x.1, next.1
        ),
    )
    .unwrap();
    let (stdout, err) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[("GOSUMDB", "off")]);
    assert!(stdout.contains("A: PRISTINE-NEXT"), "{stdout}\n{err}");
    let stale = format!("{UMOD} {NEXT} {}", next.0);
    assert!(read(&w.root.join("go.work.sum")).contains(&stale));

    std::fs::write(b.join("go.mod"), &b_mod).unwrap();
    std::fs::write(b.join("go.sum"), &b_sum).unwrap();
    let m = Machine::new(tmp.path(), "stale");
    let list = go(&a, &m, &["list", "-m", UMOD], &day2(&w.proxy));
    assert_eq!(
        String::from_utf8_lossy(&list.stdout).trim(),
        format!("{UMOD} {UVER}"),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(read(&w.root.join("go.work.sum")).contains(&stale));

    warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER)]);
    let (code, out, stderr) = w.api.get(&a, &m.modcache, &[]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 1, "{out}");
    let (stdout, err) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[]);
    assert!(stdout.contains("A: PATCHED"), "{stdout}\n{err}");
}

/// A local checkout of the patched module that the workspace `use`s is a
/// main module: go builds it from that directory, at no version, and
/// ignores every replace of it. Hosted mode refuses to pin it, and the
/// selection never claims the patched version.
#[test]
fn a_workspace_module_is_never_replaced() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    use socket_patch_core::vendor::go_build_list::Selection;
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let a = w.root.join("a");
    let dep = w.root.join("dep");
    std::fs::create_dir_all(&dep).unwrap();
    std::fs::write(dep.join("go.mod"), format!("module {UMOD}\n\ngo 1.18\n")).unwrap();
    std::fs::write(
        dep.join("lib.go"),
        "package upstream\n\nfunc Greeting() string { return \"LOCAL\" }\n",
    )
    .unwrap();
    std::fs::write(
        w.root.join("go.work"),
        "go 1.18\n\nuse (\n\t./a\n\t./b\n\t./dep\n)\n",
    )
    .unwrap();
    let m = Machine::new(tmp.path(), "main");
    warm(tmp.path(), &m, &w.proxy, &[(UMOD, UVER)]);
    let a_mod = read(&a.join("go.mod"));
    let work = read(&w.root.join("go.work"));

    for cwd in [&a, &w.root] {
        let (code, out, stderr) = w.api.get(cwd, &m.modcache, &[]);
        assert_eq!(code, 0, "{out}\n{stderr}");
        assert_eq!(out["summary"]["applied"], 0, "{out}");
        assert!(
            warning_codes(&out).contains(&"redirect_golang_workspace_conflict".to_string()),
            "{out}"
        );
        assert_eq!(read(&a.join("go.mod")), a_mod);
        assert_eq!(read(&w.root.join("go.work")), work);
    }

    // A pin written in module mode does nothing in the workspace.
    let (code, out, stderr) = w.api.get(&a, &m.modcache, &[("GOWORK", "off")]);
    assert_eq!(code, 0, "{out}\n{stderr}");
    assert_eq!(out["summary"]["applied"], 1, "{out}");
    let (stdout, err) = run_member(tmp.path(), &w.root, "a", &w.proxy, &[]);
    assert!(stdout.contains("A: LOCAL"), "{stdout}\n{err}");
    let rt = tokio::runtime::Runtime::new().unwrap();
    use socket_patch_core::vendor::go_workspace::{load, Loaded};
    let Loaded::Workspace(mut ws) = rt.block_on(load(&a)) else {
        panic!("no workspace");
    };
    rt.block_on(ws.read_graph_from(Some(&m.modcache)));
    assert!(
        matches!(ws.selection(UMOD, UVER), Selection::Other(v) if v.contains("dep")),
        "{:?}",
        ws.selection(UMOD, UVER)
    );
    let ours = socket_patch_core::vendor::go_mod_edit::read_replace_entries(&a);
    let ours = rt.block_on(ours);
    let ours = ours.iter().find(|e| e.module == UMOD).unwrap();
    assert!(matches!(
        ws.conflict(&a, UMOD, UVER, ours),
        Some(socket_patch_core::vendor::go_workspace::WorkspaceConflict::MainModule { .. })
    ));
}

// ── a root go.mod replace once another member shares the module ───────

/// `apply` at a go.work root whose own module alone requires the module
/// writes the replace into go.mod; once member `a` (added to `use`) shares
/// it, `vendor` writes it into go.work too, repoints the go.mod replace at
/// the vendored copy and deletes the go-patches copy: the workspace and the
/// root alone (`GOWORK=off`) both build the vendored copy, a re-run keeps
/// both replaces, and `vendor --revert` leaves neither file replacing the
/// module.
#[test]
fn vendor_keeps_a_root_go_mod_redirect_beside_go_work() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let go_mod = format!("module example.com/root\n\ngo 1.18\n\nrequire {UMOD} {UVER}\n");
    std::fs::write(w.root.join("go.mod"), &go_mod).unwrap();
    std::fs::copy(w.root.join("a/go.sum"), w.root.join("go.sum")).unwrap();
    std::fs::write(
        w.root.join("main.go"),
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\n\
             func main() {{ fmt.Println(\"ROOT:\", upstream.Greeting()) }}\n"
        ),
    )
    .unwrap();
    std::fs::write(w.root.join("go.work"), "go 1.18\n\nuse .\n").unwrap();
    let m = Machine::new(tmp.path(), "apply-then-vendor");
    download(&w.root, &m, &w.proxy);
    write_local_patch(&w.root, VENDOR_UUID);
    let cwd = w.root.to_str().unwrap();

    let (code, out, err) = socket_raw(
        &w.root,
        &[
            "apply",
            "--offline",
            "--json",
            "--ecosystems",
            "golang",
            "--cwd",
            cwd,
        ],
        &m.modcache,
    );
    assert_eq!(code, 0, "apply: {out}\n{err}");
    let copy = format!(".socket/go-patches/{UMOD}@{UVER}");
    assert_eq!(
        read(&w.root.join("go.mod")),
        format!("{go_mod}\nreplace {UMOD} {UVER} => ./{copy}\n")
    );

    let work = "go 1.18\n\nuse (\n\t.\n\t./a\n)\n";
    std::fs::write(w.root.join("go.work"), work).unwrap();
    let vendor = |extra: &[&str]| {
        let mut args = vec!["vendor", "--json", "--offline", "--cwd", cwd];
        args.extend_from_slice(extra);
        socket(&w.root, &args, &m.modcache)
    };
    let (code, env, stderr) = vendor(&[]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    let art = format!(".socket/vendor/golang/{VENDOR_UUID}/{UMOD}@{UVER}");
    assert_eq!(
        read(&w.root.join("go.work")),
        format!("{work}\nreplace {UMOD} {UVER} => ./{art}\n")
    );
    // The root module keeps the replace beside go.work's.
    assert_eq!(
        read(&w.root.join("go.mod")),
        format!("{go_mod}\nreplace {UMOD} {UVER} => ./{art}\n")
    );
    assert!(!w.root.join(&copy).exists());
    for (dir, tag) in [(".", "ROOT"), ("a", "A")] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(
            out.contains(&format!("{tag}: PATCHED")),
            "{dir}: {out}\n{err}"
        );
    }
    let (out, err) = run_member(tmp.path(), &w.root, ".", &w.proxy, &[("GOWORK", "off")]);
    assert!(out.contains("ROOT: PATCHED"), "root alone: {out}\n{err}");
    // A re-run keeps both replaces.
    let (code, env, stderr) = vendor(&[]);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(
        read(&w.root.join("go.mod")),
        format!("{go_mod}\nreplace {UMOD} {UVER} => ./{art}\n")
    );
    assert_eq!(
        read(&w.root.join("go.work")),
        format!("{work}\nreplace {UMOD} {UVER} => ./{art}\n")
    );

    let (code, env, stderr) = vendor(&["--revert"]);
    assert_eq!(code, 0, "vendor --revert: {env}\n{stderr}");
    assert_eq!(read(&w.root.join("go.work")), work);
    assert_eq!(read(&w.root.join("go.mod")), go_mod);
    let (out, err) = run_member(tmp.path(), &w.root, ".", &w.proxy, &[("GOWORK", "off")]);
    assert!(out.contains("ROOT: PRISTINE"), "after revert: {out}\n{err}");
}

/// Hosted pins of one uuid in both members' go.mod (each pruned its go.sum
/// to the Socket pair) and in go.work (go.work.sum created for it), rolled
/// back together: every member's go.sum gets the upstream pair back, the
/// go.work.sum the pin created is removed, and each member builds upstream
/// on its own `-mod=readonly`.
#[test]
fn member_and_go_work_pins_of_one_uuid_roll_back_together() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_workspace_build")
        || !golang_e2e_matrix::supports_go_work()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ChmodGuard(tmp.path().to_path_buf());
    let w = stage_members(tmp.path(), UVER, UVER);
    let before = snapshot(&w.root);
    let replace = format!("replace {UMOD} {UVER} => {} {SVER}", w.smod);
    let socket_pair = format!(
        "{s} {SVER} {}\n{s} {SVER}/go.mod {}\n",
        w.pin.0,
        w.pin.1,
        s = w.smod
    );
    for rel in ["go.work", "a/go.mod", "b/go.mod"] {
        let text = read(&w.root.join(rel));
        std::fs::write(w.root.join(rel), format!("{text}\n{replace}\n")).unwrap();
    }
    for rel in ["go.work.sum", "a/go.sum", "b/go.sum"] {
        std::fs::write(w.root.join(rel), &socket_pair).unwrap();
    }
    for dir in ["a", "b"] {
        let (out, err) = run_member(tmp.path(), &w.root, dir, &w.proxy, &[]);
        assert!(out.contains("PATCHED"), "{dir}: {out}\n{err}");
    }

    let m = Machine::new(tmp.path(), "rollback-all");
    w.api.mount_sumdb(&w.upstream.0, &w.upstream.1);
    let uri = w.api.server.uri();
    let (code, env, stderr) = socket_env(
        &w.root,
        &[
            "rollback",
            "--json",
            "--yes",
            "--cwd",
            w.root.to_str().unwrap(),
        ],
        &m.modcache,
        &[("SOCKET_GOSUMDB_URL", uri.as_str())],
    );
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_snapshot(&w.root, &before, "rollback");
    assert!(!w.root.join("go.work.sum").exists(), "{env}");
    for dir in ["a", "b"] {
        let (out, err) = run_member(
            tmp.path(),
            &w.root.join(dir),
            ".",
            &w.proxy,
            &[("GOWORK", "off"), ("GOFLAGS", "-mod=readonly")],
        );
        assert!(out.contains("PRISTINE"), "{dir} alone: {out}\n{err}");
    }
}
