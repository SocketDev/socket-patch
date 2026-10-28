#![cfg(unix)]
//! Full go-toolchain capstone for the Go `replace`-redirect: proves the patched
//! bytes are actually LINKED by `go build`, and that the read-only
//! `apply --check` redirect auditor detects drift in the committed copy.
//!
//! Go is the one ecosystem that still uses the project-local `replace`-redirect
//! (the module cache is `go.sum`-verified, so in-place patching can't build).
//! There is no longer a build-time guard or `setup` step for Go — the committed
//! `go.mod` `replace` + `.socket/go-patches/` copy is the whole mechanism, and
//! `go build` links it with no extra wiring.
//!
//! Hermetic + offline: a tiny upstream module is served from a local file
//! GOPROXY into a temp GOMODCACHE, so no network and no pre-cached module are
//! needed. Skips when `go`/`zip` aren't installed (a failure under
//! `SOCKET_PATCH_GO_E2E_REQUIRED`; the Go release is whatever `go` is on
//! `PATH` — see `golang_e2e_matrix`).
//!
//! VEX tail: the committed go-patches redirect attests (manifest record) on
//! a fresh checkout built fully offline; with the manifest deleted it is NOT
//! attestable — `./.socket/go-patches/M@v` carries no patch uuid, so there
//! is no record to resolve (documented limitation of `apply`'s agent-mode
//! redirect; hosted/vendored wiring carries the uuid and is covered by
//! `e2e_golang_hosted_build` / `e2e_vendor_golang_build`).

use std::path::Path;
use std::process::Command;

#[path = "common/mod.rs"]
mod common;
#[path = "golang_e2e_matrix/mod.rs"]
mod golang_e2e_matrix;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use common::{binary, cache_env, git_sha256};
use vex_e2e_common::{
    assert_absent, assert_attested, run_vex, strip_manifest, Marker, VexRun, VexVia,
};

const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UPURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const UUID: &str = "4d5e6f70-8192-4a1b-8c2d-0123456789ab";
const GHSA: &str = "GHSA-gogo-patc-hes1";
const CVE: &str = "CVE-2026-5151";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";

/// Env for every `go` invocation: hermetic file-proxy + temp cache, sums off.
/// `GOTOOLCHAIN=local` keeps the installed toolchain from trying to download
/// a different one — an ambient `GOTOOLCHAIN` pin would otherwise send every
/// `go` command chasing a toolchain the file proxy can't serve.
fn go_env<'a>(modcache: &'a str, proxy_url: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("GOMODCACHE", modcache),
        ("GOPROXY", proxy_url),
        ("GOSUMDB", "off"),
        ("GOFLAGS", "-mod=mod"),
        ("GOTOOLCHAIN", "local"),
    ]
}

/// Run socket-patch through the shared hermetic runner with the fixture
/// GOMODCACHE (the go crawler resolves installed modules through it).
fn run_socket(cwd: &Path, args: &[&str], modcache: &Path) -> (i32, String, String) {
    common::run_with_env(cwd, args, &[("GOMODCACHE", modcache.to_str().unwrap())])
}

/// Run `go` with its caches sandboxed, then the fixture's own env on top.
///
/// `GOMODCACHE` alone is not isolation: `go build` keeps its compiled objects
/// in `GOCACHE`, a different directory that does not follow `GOPATH` either,
/// so without [`cache_env::isolate`] this test still filled the real home.
fn go(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    cache_env::isolate(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run go")
}

/// Build the upstream module into a file-proxy and `go mod download` it into a
/// temp GOMODCACHE. Returns (consumer_dir, modcache, proxy_url).
fn stage(tmp: &Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    // Staging dir holding `<mod>@<ver>/` for zipping.
    let stage = tmp.join("stage").join(format!("{UMOD}@{UVER}"));
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("go.mod"), format!("module {UMOD}\n\ngo 1.21\n")).unwrap();
    std::fs::write(stage.join("lib.go"), PRISTINE_LIB).unwrap();

    // File-proxy layout: proxy/<mod>/@v/<ver>.{info,mod,zip}.
    let pxv = tmp.join("proxy").join(UMOD).join("@v");
    std::fs::create_dir_all(&pxv).unwrap();
    std::fs::write(
        pxv.join(format!("{UVER}.info")),
        format!("{{\"Version\":\"{UVER}\"}}"),
    )
    .unwrap();
    std::fs::write(
        pxv.join(format!("{UVER}.mod")),
        format!("module {UMOD}\n\ngo 1.21\n"),
    )
    .unwrap();
    let zip_out = pxv.join(format!("{UVER}.zip"));
    let zip_status = Command::new("zip")
        .args([
            "-q",
            "-r",
            zip_out.to_str().unwrap(),
            &format!("{UMOD}@{UVER}"),
        ])
        .current_dir(tmp.join("stage"))
        .status()
        .expect("run zip");
    assert!(zip_status.success(), "zip failed");

    let modcache = tmp.join("modcache");
    std::fs::create_dir_all(&modcache).unwrap();
    let proxy_url = format!("file://{}", tmp.join("proxy").display());

    // Consumer module that calls the patched symbol.
    let consumer = tmp.join("consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("go.mod"),
        format!("module example.com/consumer\n\ngo 1.21\n\nrequire {UMOD} {UVER}\n"),
    )
    .unwrap();
    std::fs::write(
        consumer.join("main.go"),
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"OUT:\", upstream.Greeting()) }}\n"
        ),
    )
    .unwrap();

    let env = go_env(modcache.to_str().unwrap(), &proxy_url);
    let dl = go(
        &consumer,
        &["mod", "download", &format!("{UMOD}@{UVER}")],
        &env,
    );
    assert!(
        dl.status.success(),
        "go mod download failed: {}",
        String::from_utf8_lossy(&dl.stderr)
    );

    (consumer, modcache, proxy_url)
}

/// Hand-build the patch manifest + blob (apply will read these offline).
fn write_patch(consumer: &Path) {
    let socket = consumer.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let before = git_sha256(PRISTINE_LIB.as_bytes());
    let after = git_sha256(PATCHED_LIB.as_bytes());
    let manifest = format!(
        "{{\"patches\":{{\"{UPURL}\":{{\"uuid\":\"{UUID}\",\"exportedAt\":\"t\",\"files\":{{\"lib.go\":{{\"beforeHash\":\"{before}\",\"afterHash\":\"{after}\"}}}},\"vulnerabilities\":{{\"{GHSA}\":{{\"cves\":[\"{CVE}\"],\"summary\":\"s\",\"severity\":\"high\",\"description\":\"d\"}}}},\"description\":\"\",\"license\":\"\",\"tier\":\"\"}}}},\"setup\":{{\"manual\":[\"golang\"]}}}}"
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED_LIB).unwrap();
}

fn chmod_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for e in walkdir(dir) {
        let _ = std::fs::set_permissions(&e, std::fs::Permissions::from_mode(0o755));
    }
}
fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn go_build_links_patch_via_replace_redirect() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build") {
        return;
    }
    // RED guard for the toolchain pin: bake the hostile ambient value in so
    // this suite fails deterministically if the leak returns. `GOTOOLCHAIN`
    // must lose to go_env's `local` pin (or every `go` command chases a
    // nonexistent toolchain through the file proxy). `SOCKET_DRY_RUN` needs
    // no guard here: `hermetic::command` seeds and scrubs it itself.
    std::env::set_var("GOTOOLCHAIN", "go1.99.99");
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let cs = consumer.to_str().unwrap();
    let mc = modcache.to_str().unwrap();
    let goenv = go_env(mc, &proxy_url);

    // Baseline build links PRISTINE.
    let base = go(&consumer, &["run", "."], &goenv);
    assert!(
        base.status.success(),
        "baseline run failed: {}",
        String::from_utf8_lossy(&base.stderr)
    );
    assert!(String::from_utf8_lossy(&base.stdout).contains("OUT: PRISTINE"));

    // Patch + apply (socket-patch reads only the cache; no `go`). This writes the
    // project-local copy under `.socket/go-patches/` and the `go.mod` `replace`.
    write_patch(&consumer);
    let (code, so, se) = run_socket(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "apply failed.\n{so}\n{se}");

    // The patched bytes are now LINKED by `go build` via the `replace` redirect.
    let patched = go(&consumer, &["run", "."], &goenv);
    assert!(
        patched.status.success(),
        "patched run failed: {}",
        String::from_utf8_lossy(&patched.stderr)
    );
    assert!(
        String::from_utf8_lossy(&patched.stdout).contains("OUT: PATCHED"),
        "patched symbol not linked: {}",
        String::from_utf8_lossy(&patched.stdout)
    );

    // `apply --check` (read-only redirect auditor) reports the committed
    // redirect as in sync.
    let (code, _so, _se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "apply --check should be in sync after apply");

    // Corrupt the committed copy → `apply --check` must detect drift (exit !=0).
    let copy_file = consumer
        .join(".socket/go-patches/example.com")
        .join(format!("upstream@{UVER}"))
        .join("lib.go");
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&copy_file, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::write(
        &copy_file,
        "package upstream\n\nfunc Greeting() string { return \"DRIFT\" }\n",
    )
    .unwrap();
    let (code, _so, _se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_ne!(
        code, 0,
        "apply --check must detect drift in the committed copy"
    );

    // A fresh `apply` re-materialises the copy and `go build` links PATCHED again.
    let (code, _so, _se) = run_socket(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "re-apply should heal the drifted copy");
    let healed = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&healed.stdout).contains("OUT: PATCHED"),
        "re-apply should restore the patched bytes: {}",
        String::from_utf8_lossy(&healed.stdout)
    );

    // ── VEX over a fresh checkout of the committed redirect ─────────────
    let fresh = tmp.path().join("fresh");
    golang_e2e_matrix::checkout(&consumer, &fresh);
    let fresh_mc = tmp.path().join("fresh-modcache");
    std::fs::create_dir_all(&fresh_mc).unwrap();
    let offline = go_env(fresh_mc.to_str().unwrap(), "off");
    let run = go(&fresh, &["run", "."], &offline);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("OUT: PATCHED"),
        "fresh checkout (GOPROXY=off) must link the committed copy: {}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    // `vex` reads the committed copy only (empty cache); `apply` needs the
    // pristine module the redirect copies from, so it runs after the
    // checkout's `go mod download` (the stage's populated cache).
    let vex = |via: VexVia, offline: bool| {
        let cache = if via == VexVia::Apply {
            &modcache
        } else {
            &fresh_mc
        };
        let r = VexRun {
            offline,
            product: Some("pkg:golang/example.com/consumer@v0.0.1".into()),
            ..VexRun::default()
        }
        .via(via)
        .env("GOMODCACHE", cache)
        .env("GOFLAGS", "");
        run_vex(&vex_e2e_common::binary(), &fresh, &r)
    };
    // With the manifest (the record owner in agent mode): attested.
    let out = vex(VexVia::Vex, true);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), UPURL, UUID, Marker::Applied, &[(GHSA, &[CVE])]);
    let out = vex(VexVia::Apply, true);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), UPURL, UUID, Marker::Applied, &[(GHSA, &[CVE])]);
    // Manifest deleted: the go-patches path names no patch uuid, so there is
    // nothing to attest (not a false attestation: exit 2, no document), and
    // an embedded `apply --vex` keeps its calm no-manifest exit 0.
    strip_manifest(&fresh);
    let out = vex(VexVia::Vex, false);
    assert_eq!(out.code, Some(2), "{out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
    assert_absent(out.doc.as_ref(), UPURL);
    let out = vex(VexVia::Apply, false);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(out.envelope["status"], "noManifest", "{out}");
    assert!(out.doc.is_none(), "{out}");

    // Best-effort: relax perms so the temp cache cleans up.
    chmod_writable(tmp.path());
}

// ── consumer sync: vendor/modules.txt (#343) and requirements (#618) ──

/// Publish `module@version` (its files, `go.mod` included) into the file
/// proxy at `tmp/proxy`.
fn publish(tmp: &Path, module: &str, version: &str, files: &[(&str, &str)]) {
    let stage_root = tmp.join("stage-pub");
    let _ = std::fs::remove_dir_all(&stage_root);
    let dir = stage_root.join(format!("{module}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, body) in files {
        std::fs::write(dir.join(name), body).unwrap();
    }
    let pxv = tmp.join("proxy").join(module).join("@v");
    std::fs::create_dir_all(&pxv).unwrap();
    std::fs::write(
        pxv.join(format!("{version}.info")),
        format!("{{\"Version\":\"{version}\"}}"),
    )
    .unwrap();
    let go_mod = files.iter().find(|(n, _)| *n == "go.mod").unwrap().1;
    std::fs::write(pxv.join(format!("{version}.mod")), go_mod).unwrap();
    let status = Command::new("zip")
        .args([
            "-q",
            "-r",
            pxv.join(format!("{version}.zip")).to_str().unwrap(),
            &format!("{module}@{version}"),
        ])
        .current_dir(&stage_root)
        .status()
        .expect("run zip");
    assert!(status.success(), "zip failed");
    let mut list = std::fs::read_to_string(pxv.join("list")).unwrap_or_default();
    list.push_str(&format!("{version}\n"));
    std::fs::write(pxv.join("list"), list).unwrap();
}

/// The JSON `warnings[]` codes of a `--json` run's stdout.
fn warnings_of(stdout: &str) -> Vec<String> {
    common::envelope::codes_in(&common::envelope::parse_json_envelope(stdout)["warnings"])
}

/// #343: in a project with a committed `vendor/` (`go mod vendor`), the
/// redirect alone breaks every default build ("inconsistent vendoring").
/// apply names `go mod vendor`, `apply --check` reports the drift until it
/// is run, and the same holds the other way round after a rollback.
#[test]
fn committed_vendor_dir_needs_go_mod_vendor_after_apply_and_rollback() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(vendor-dir)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let cs = consumer.to_str().unwrap();
    let mc = modcache.to_str().unwrap();
    let mut goenv = go_env(mc, &proxy_url);
    let vendored = go(&consumer, &["mod", "vendor"], &goenv);
    assert!(
        vendored.status.success(),
        "go mod vendor: {}",
        String::from_utf8_lossy(&vendored.stderr)
    );
    // Default flags from here on: go builds from vendor/.
    goenv.retain(|(k, _)| *k != "GOFLAGS");
    goenv.push(("GOFLAGS", ""));
    let base = go(&consumer, &["build", "./..."], &goenv);
    assert!(
        base.status.success(),
        "{}",
        String::from_utf8_lossy(&base.stderr)
    );

    write_patch(&consumer);
    let (code, so, se) = run_socket(
        &consumer,
        &[
            "apply",
            "--offline",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            cs,
        ],
        &modcache,
    );
    assert_eq!(code, 0, "apply failed.\n{so}\n{se}");
    assert!(
        warnings_of(&so).contains(&"go_vendor_modules_txt_out_of_sync".to_string()),
        "apply must name the vendor/modules.txt regeneration:\n{so}"
    );
    let broken = go(&consumer, &["build", "./..."], &goenv);
    assert!(
        !broken.status.success()
            && String::from_utf8_lossy(&broken.stderr).contains("inconsistent vendoring"),
        "the fixture reproduces the broken build: {}",
        String::from_utf8_lossy(&broken.stderr)
    );
    let (code, _so, se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(
        code, 1,
        "apply --check must report the out-of-sync vendor/:\n{se}"
    );
    assert!(se.contains("go mod vendor"), "{se}");

    // The step the warning names fixes the build, and --check agrees.
    let revendor = go(&consumer, &["mod", "vendor"], &goenv);
    assert!(
        revendor.status.success(),
        "{}",
        String::from_utf8_lossy(&revendor.stderr)
    );
    let run = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("OUT: PATCHED"),
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let (code, so, se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "in sync after go mod vendor:\n{so}\n{se}");

    // Rollback drops the replace; modules.txt still records it.
    let (code, so, se) = run_socket(
        &consumer,
        &[
            "rollback",
            "--offline",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            cs,
        ],
        &modcache,
    );
    assert_eq!(code, 0, "rollback failed.\n{so}\n{se}");
    assert!(
        warnings_of(&so).contains(&"go_vendor_modules_txt_out_of_sync".to_string()),
        "rollback must name the vendor/modules.txt regeneration:\n{so}"
    );
    let (code, _so, se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 1, "stale vendor/modules.txt is drift:\n{se}");
    assert!(
        se.contains("no longer has") && se.contains("go mod vendor"),
        "{se}"
    );

    chmod_writable(tmp.path());
}

/// #1766: `go work vendor` records a non-root member's replace relative to
/// the workspace root (`./consumer/.socket/go-patches/…`). After rollback
/// or remove in that member every workspace build fails "inconsistent
/// vendoring", so both must warn and `apply --check` must report it.
#[test]
fn go_work_vendor_member_needs_go_work_vendor_after_rollback_and_remove() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(go-work-vendor)") {
        return;
    }
    if golang_e2e_matrix::go_minor() < 22 {
        eprintln!("SKIP: `go work vendor` needs Go 1.22+");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let ws = tmp.path();
    std::fs::write(ws.join("go.work"), "go 1.22\n\nuse ./consumer\n").unwrap();
    let cs = consumer.to_str().unwrap();
    let mc = modcache.to_str().unwrap();
    let mut goenv = go_env(mc, &proxy_url);
    goenv.retain(|(k, _)| *k != "GOFLAGS");
    goenv.push(("GOFLAGS", ""));
    let vendor = |what: &str| {
        let out = go(ws, &["work", "vendor"], &goenv);
        assert!(
            out.status.success(),
            "go work vendor ({what}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let warns = |args: &[&str], what: &str| {
        let (code, so, se) = run_socket(&consumer, args, &modcache);
        assert_eq!(code, 0, "{what} failed.\n{so}\n{se}");
        assert!(
            warnings_of(&so).contains(&"go_vendor_modules_txt_out_of_sync".to_string()),
            "{what} must name the vendor/modules.txt regeneration:\n{so}"
        );
    };
    let apply = ["apply", "--offline", "--json", "--cwd", cs];
    vendor("before apply");

    write_patch(&consumer);
    warns(&apply, "apply");
    vendor("after apply");
    let run = go(ws, &["run", "./consumer"], &goenv);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("OUT: PATCHED"),
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let modules_txt = std::fs::read_to_string(ws.join("vendor/modules.txt")).unwrap();
    assert!(
        modules_txt.contains("=> ./consumer/.socket/go-patches/"),
        "the fixture records the member replace relative to go.work:\n{modules_txt}"
    );

    for (what, args) in [
        (
            "rollback",
            vec!["rollback", "--offline", "--json", "--cwd", cs],
        ),
        (
            "remove",
            vec!["remove", UPURL, "--offline", "--json", "--cwd", cs],
        ),
    ] {
        warns(&args, what);
        let broken = go(ws, &["build", "./consumer"], &goenv);
        assert!(
            !broken.status.success()
                && String::from_utf8_lossy(&broken.stderr).contains("inconsistent vendoring"),
            "{what}: the fixture reproduces the broken build: {}",
            String::from_utf8_lossy(&broken.stderr)
        );
        let (code, _so, se) = run_socket(
            &consumer,
            &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
            &modcache,
        );
        assert_eq!(code, 1, "{what}: stale vendor/modules.txt is drift:\n{se}");
        assert!(
            se.contains("no longer has") && se.contains("go work vendor"),
            "{what}: {se}"
        );

        // The step the warning names fixes the build.
        vendor(what);
        let run = go(ws, &["run", "./consumer"], &goenv);
        assert!(
            String::from_utf8_lossy(&run.stdout).contains("OUT: PRISTINE"),
            "{what}: {}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        if what == "rollback" {
            // Re-apply and re-vendor so `remove` starts from a patched,
            // in-sync workspace (rollback dropped the manifest entry).
            write_patch(&consumer);
            warns(&apply, "re-apply");
            vendor("after re-apply");
        }
    }

    chmod_writable(tmp.path());
}

/// #618: a patch whose go.mod raises a requirement (the common security-fix
/// shape) leaves the default `-mod=readonly` build failing with "updates
/// to go.mod needed". apply names `go mod tidy`, `apply --check` reports
/// the drift until it is run, and after it the patched bytes build.
#[test]
fn patched_go_mod_requirement_bump_needs_go_mod_tidy() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(requirements)") {
        return;
    }
    let godir = golang_e2e_matrix::go_directive();
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    const DEP: &str = "example.com/dep";
    let dep_mod = format!("module {DEP}\n\ngo {godir}\n");
    let dep_src = |tag: &str| {
        format!("package dep\n\nfunc Safe(s string) string {{ return \"{tag}-\" + s }}\n")
    };
    publish(
        t,
        DEP,
        "v1.0.0",
        &[("go.mod", &dep_mod), ("dep.go", &dep_src("OLD"))],
    );
    publish(
        t,
        DEP,
        "v1.1.0",
        &[("go.mod", &dep_mod), ("dep.go", &dep_src("FIXED"))],
    );
    let up_mod = |v: &str| format!("module {UMOD}\n\ngo {godir}\n\nrequire {DEP} {v}\n");
    let up_lib = |tag: &str| {
        format!(
            "package upstream\n\nimport \"{DEP}\"\n\nfunc Greeting() string {{ return dep.Safe(\"{tag}\") }}\n"
        )
    };
    let (before_mod, after_mod) = (up_mod("v1.0.0"), up_mod("v1.1.0"));
    let (before_lib, after_lib) = (up_lib("PRISTINE"), up_lib("PATCHED"));
    publish(
        t,
        UMOD,
        UVER,
        &[("go.mod", &before_mod), ("lib.go", &before_lib)],
    );

    let modcache = t.join("modcache");
    std::fs::create_dir_all(&modcache).unwrap();
    let proxy_url = format!("file://{}", t.join("proxy").display());
    let consumer = t.join("consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("go.mod"),
        format!("module example.com/consumer\n\ngo {godir}\n\nrequire {UMOD} {UVER}\n"),
    )
    .unwrap();
    std::fs::write(
        consumer.join("main.go"),
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"OUT:\", upstream.Greeting()) }}\n"
        ),
    )
    .unwrap();
    let mc = modcache.to_str().unwrap();
    let mut goenv = go_env(mc, &proxy_url);
    let tidy = go(&consumer, &["mod", "tidy"], &goenv);
    assert!(
        tidy.status.success(),
        "{}",
        String::from_utf8_lossy(&tidy.stderr)
    );
    goenv.retain(|(k, _)| *k != "GOFLAGS");
    goenv.push(("GOFLAGS", ""));
    let base = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&base.stdout).contains("OUT: OLD-PRISTINE"),
        "{}",
        String::from_utf8_lossy(&base.stderr)
    );

    // The patch: lib.go and the go.mod requirement bump.
    let socket = consumer.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    for body in [&after_lib, &after_mod] {
        std::fs::write(socket.join("blobs").join(git_sha256(body.as_bytes())), body).unwrap();
    }
    let manifest = serde_json::json!({"patches": {UPURL: {
        "uuid": UUID, "exportedAt": "t",
        "files": {
            "lib.go": {"beforeHash": git_sha256(before_lib.as_bytes()),
                       "afterHash": git_sha256(after_lib.as_bytes())},
            "go.mod": {"beforeHash": git_sha256(before_mod.as_bytes()),
                       "afterHash": git_sha256(after_mod.as_bytes())},
        },
        "vulnerabilities": {GHSA: {"cves": [CVE], "summary": "s", "severity": "high",
                                   "description": "d"}},
        "description": "", "license": "", "tier": ""}}});
    std::fs::write(socket.join("manifest.json"), manifest.to_string()).unwrap();

    let cs = consumer.to_str().unwrap();
    let (code, so, se) = run_socket(
        &consumer,
        &[
            "apply",
            "--offline",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            cs,
        ],
        &modcache,
    );
    assert_eq!(code, 0, "apply failed.\n{so}\n{se}");
    assert!(
        warnings_of(&so).contains(&"go_requirements_out_of_sync".to_string()),
        "apply must name the go.mod/go.sum refresh:\n{so}"
    );
    let broken = go(&consumer, &["build", "./..."], &goenv);
    assert!(
        !broken.status.success(),
        "the fixture reproduces the readonly failure"
    );
    let (code, _so, se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(
        code, 1,
        "apply --check must report the requirement drift:\n{se}"
    );
    assert!(se.contains("go mod tidy"), "{se}");

    let mut tidy_env = goenv.clone();
    tidy_env.retain(|(k, _)| *k != "GOFLAGS");
    tidy_env.push(("GOFLAGS", "-mod=mod"));
    let tidy = go(&consumer, &["mod", "tidy"], &tidy_env);
    assert!(
        tidy.status.success(),
        "{}",
        String::from_utf8_lossy(&tidy.stderr)
    );
    let run = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("OUT: FIXED-PATCHED"),
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let (code, so, se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "in sync after go mod tidy:\n{so}\n{se}");

    chmod_writable(tmp.path());
}

// ── the go.work in effect (#393, #458, #531) ─────────────────────────

/// Workspace-mode go env: `-mod=mod` is rejected in workspace mode, so
/// `GOFLAGS` is cleared (the consumers carry a tidy go.sum instead).
fn workspace_env<'a>(modcache: &'a str, proxy_url: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut env = go_env(modcache, proxy_url);
    env.retain(|(k, _)| *k != "GOFLAGS");
    env.push(("GOFLAGS", ""));
    env
}

/// A module at `dir` that requires the upstream and prints its greeting,
/// with the go.sum `go mod tidy` writes (outside any workspace).
fn consumer_module(dir: &Path, module: &str, modcache: &str, proxy_url: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("go.mod"),
        format!("module {module}\n\ngo 1.21\n\nrequire {UMOD} {UVER}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("main.go"),
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"OUT:\", upstream.Greeting()) }}\n"
        ),
    )
    .unwrap();
    let mut env = go_env(modcache, proxy_url);
    env.push(("GOWORK", "off"));
    let tidy = go(dir, &["mod", "tidy"], &env);
    assert!(
        tidy.status.success(),
        "go mod tidy: {}",
        String::from_utf8_lossy(&tidy.stderr)
    );
}

fn go_out(dir: &Path, env: &[(&str, &str)]) -> String {
    let out = go(dir, &["run", "."], env);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn apply_json(dir: &Path, modcache: &Path) -> (i32, String, String) {
    run_socket(
        dir,
        &[
            "apply",
            "--offline",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            dir.to_str().unwrap(),
        ],
        modcache,
    )
}

/// [`apply_json`] with `--allow-patch-conflicts`, for guards behind that gate.
fn apply_json_consented(dir: &Path, modcache: &Path) -> (i32, String, String) {
    run_socket(
        dir,
        &[
            "apply",
            "--offline",
            "--allow-patch-conflicts",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            dir.to_str().unwrap(),
        ],
        modcache,
    )
}

fn check(dir: &Path, modcache: &Path) -> (i32, String, String) {
    run_socket(
        dir,
        &[
            "apply",
            "--check",
            "--ecosystems",
            "golang",
            "--cwd",
            dir.to_str().unwrap(),
        ],
        modcache,
    )
}

/// Standalone `vex --json` over `dir`: must not attest the upstream patch
/// and must say why (`go_workspace_override`).
fn assert_vex_omits(dir: &Path, modcache: &Path, product: &str) {
    let r = VexRun {
        offline: true,
        product: Some(product.into()),
        ..VexRun::default()
    }
    .env("GOMODCACHE", modcache)
    .env("GOFLAGS", "");
    let out = run_vex(&vex_e2e_common::binary(), dir, &r);
    assert_absent(out.doc.as_ref(), UPURL);
    vex_e2e_common::assert_not_attested(&out.envelope, UPURL, "go_workspace_override");
    assert!(
        warnings_of(&out.stdout).contains(&"go_workspace_replace_ineffective".to_string()),
        "{out}"
    );
}

fn replace_lines(go_mod: &Path) -> Vec<String> {
    std::fs::read_to_string(go_mod)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("replace "))
        .map(str::to_string)
        .collect()
}

/// #393: a user `replace` of the module in go.work overrides any member
/// replace. apply must refuse instead of reporting a patch the build
/// doesn't link; a replace written before the go.work appeared fails
/// `apply --check` and is left out of VEX.
#[test]
fn go_work_replace_overrides_the_socket_replace() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(go-work-replace)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let mc = modcache.to_str().unwrap();
    let mut tidy_env = go_env(mc, &proxy_url);
    tidy_env.push(("GOWORK", "off"));
    assert!(go(&consumer, &["mod", "tidy"], &tidy_env).status.success());
    let fork = tmp.path().join("fork");
    std::fs::create_dir_all(&fork).unwrap();
    std::fs::write(fork.join("go.mod"), format!("module {UMOD}\n\ngo 1.21\n")).unwrap();
    std::fs::write(
        fork.join("lib.go"),
        "package upstream\n\nfunc Greeting() string { return \"FORK\" }\n",
    )
    .unwrap();
    let go_work = format!("go 1.21\n\nuse .\n\nreplace {UMOD} {UVER} => ../fork\n");
    std::fs::write(consumer.join("go.work"), &go_work).unwrap();
    let env = workspace_env(mc, &proxy_url);
    assert!(go_out(&consumer, &env).contains("OUT: FORK"));

    write_patch(&consumer);
    // The go.work replace is also a user patch; consent past that gate so
    // the run reaches the go.work guard this test is about.
    // The dry run predicts the refusal.
    let (code, so, se) = run_socket(
        &consumer,
        &[
            "apply",
            "--offline",
            "--dry-run",
            "--allow-patch-conflicts",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            consumer.to_str().unwrap(),
        ],
        &modcache,
    );
    assert_ne!(
        code, 0,
        "apply --dry-run must predict the refusal:\n{so}\n{se}"
    );
    assert!(so.contains("go.work replaces"), "{so}");
    let (code, so, se) = apply_json_consented(&consumer, &modcache);
    assert_ne!(
        code, 0,
        "apply must refuse an overridden replace:\n{so}\n{se}"
    );
    assert!(so.contains("go.work replaces"), "{so}");
    assert!(replace_lines(&consumer.join("go.mod")).is_empty());
    assert!(
        !consumer.join(".socket/go-patches").exists(),
        "a refused apply leaves no copy behind"
    );
    assert!(go_out(&consumer, &env).contains("OUT: FORK"));

    // Applied before the go.work replace existed: the replace is inert.
    std::fs::remove_file(consumer.join("go.work")).unwrap();
    let (code, so, se) = apply_json_consented(&consumer, &modcache);
    assert_eq!(code, 0, "apply without go.work:\n{so}\n{se}");
    std::fs::write(consumer.join("go.work"), &go_work).unwrap();
    assert!(go_out(&consumer, &env).contains("OUT: FORK"));
    // A re-run doesn't call the inert replace in sync.
    let (code, so, se) = apply_json_consented(&consumer, &modcache);
    assert_ne!(code, 0, "re-run apply must refuse:\n{so}\n{se}");
    let (code, so, se) = check(&consumer, &modcache);
    assert_eq!(
        code, 1,
        "apply --check must flag the inert replace:\n{so}\n{se}"
    );
    assert!(
        se.contains("go_workspace_replace_ineffective") || se.contains("go.work replaces"),
        "{se}"
    );
    assert_vex_omits(
        &consumer,
        &modcache,
        "pkg:golang/example.com/consumer@v0.0.1",
    );

    chmod_writable(tmp.path());
}

/// #458: a go.work that doesn't `use` the project makes every workspace
/// build ignore the project's go.mod, replace included.
#[test]
fn go_work_without_the_project_ignores_its_replace() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(go-work-not-member)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let mc = modcache.to_str().unwrap();
    let mut tidy_env = go_env(mc, &proxy_url);
    tidy_env.push(("GOWORK", "off"));
    assert!(go(&consumer, &["mod", "tidy"], &tidy_env).status.success());
    let svc = consumer.join("svc");
    consumer_module(&svc, "example.com/svc", mc, &proxy_url);
    let go_work = "go 1.21\n\nuse ./svc\n";
    std::fs::write(consumer.join("go.work"), go_work).unwrap();
    let env = workspace_env(mc, &proxy_url);
    assert!(go_out(&svc, &env).contains("OUT: PRISTINE"));

    write_patch(&consumer);
    let (code, so, se) = apply_json(&consumer, &modcache);
    assert_ne!(code, 0, "apply must refuse an ignored replace:\n{so}\n{se}");
    assert!(so.contains("does not `use` this module"), "{so}");
    assert!(replace_lines(&consumer.join("go.mod")).is_empty());

    // Applied before the go.work existed.
    std::fs::remove_file(consumer.join("go.work")).unwrap();
    let (code, so, se) = apply_json(&consumer, &modcache);
    assert_eq!(code, 0, "apply without go.work:\n{so}\n{se}");
    std::fs::write(consumer.join("go.work"), go_work).unwrap();
    assert!(go_out(&svc, &env).contains("OUT: PRISTINE"));
    let (code, so, se) = check(&consumer, &modcache);
    assert_eq!(
        code, 1,
        "apply --check must flag the ignored replace:\n{so}\n{se}"
    );
    assert_vex_omits(
        &consumer,
        &modcache,
        "pkg:golang/example.com/consumer@v0.0.1",
    );

    // Positive control: once go.work uses the project, the same replace
    // works and nothing is flagged.
    std::fs::write(
        consumer.join("go.work"),
        "go 1.21\n\nuse (\n\t.\n\t./svc\n)\n",
    )
    .unwrap();
    assert!(go_out(&svc, &env).contains("OUT: PATCHED"));
    let (code, so, se) = check(&consumer, &modcache);
    assert_eq!(code, 0, "{so}\n{se}");

    chmod_writable(tmp.path());
}

/// #531: two members replacing the same module@version with different
/// directories break the whole workspace build ("conflicting
/// replacements"). The second apply must refuse (the first member's
/// replace already patches the whole workspace); two replaces written
/// before the go.work appeared fail `apply --check` and VEX.
#[test]
fn go_work_member_replaces_must_not_conflict() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(go-work-conflict)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (_consumer, modcache, proxy_url) = stage(tmp.path());
    let mc = modcache.to_str().unwrap();
    let ws = tmp.path().join("ws");
    let (a, b) = (ws.join("a"), ws.join("b"));
    consumer_module(&a, "example.com/a", mc, &proxy_url);
    consumer_module(&b, "example.com/b", mc, &proxy_url);
    write_patch(&a);
    write_patch(&b);
    let go_work = "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n";
    std::fs::write(ws.join("go.work"), go_work).unwrap();
    let env = workspace_env(mc, &proxy_url);

    let (code, so, se) = apply_json(&a, &modcache);
    assert_eq!(code, 0, "first member apply:\n{so}\n{se}");
    assert!(go_out(&b, &env).contains("OUT: PATCHED"));
    let (code, so, se) = apply_json(&b, &modcache);
    assert_ne!(code, 0, "second member apply must refuse:\n{so}\n{se}");
    assert!(so.contains("conflicting"), "{so}");
    assert!(replace_lines(&b.join("go.mod")).is_empty());
    let out = go_out(&b, &env);
    assert!(
        out.contains("OUT: PATCHED"),
        "the workspace still builds: {out}"
    );
    let (code, so, se) = check(&a, &modcache);
    assert_eq!(code, 0, "{so}\n{se}");

    // Both applied before the go.work existed: the workspace can't build.
    std::fs::remove_file(ws.join("go.work")).unwrap();
    let (code, so, se) = apply_json(&b, &modcache);
    assert_eq!(code, 0, "apply without go.work:\n{so}\n{se}");
    std::fs::write(ws.join("go.work"), go_work).unwrap();
    assert!(go_out(&b, &env).contains("conflicting replacements"));
    for member in [&a, &b] {
        let (code, so, se) = check(member, &modcache);
        assert_eq!(code, 1, "apply --check must flag the conflict:\n{so}\n{se}");
    }
    assert_vex_omits(&b, &modcache, "pkg:golang/example.com/b@v0.0.1");

    chmod_writable(tmp.path());
}

/// #1751: a go.work build list spans every `use` member's requirements, so
/// when member b requires a newer upstream than a, the workspace builds a
/// with b's version and a replace pinned to a's is inert. apply in a must
/// refuse, and a replace written before the go.work appeared fails
/// `apply --check` and is left out of VEX (`go_version_not_selected`).
#[test]
fn go_work_member_requiring_a_newer_version_makes_the_replace_inert() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(go-work-newer-member)") {
        return;
    }
    const NEWER: &str = "v1.1.0";
    let tmp = tempfile::tempdir().unwrap();
    let (_consumer, modcache, proxy_url) = stage(tmp.path());
    let mc = modcache.to_str().unwrap();
    publish(
        tmp.path(),
        UMOD,
        NEWER,
        &[
            ("go.mod", &format!("module {UMOD}\n\ngo 1.21\n")),
            (
                "lib.go",
                "package upstream\n\nfunc Greeting() string { return \"PRISTINE-v1.1.0\" }\n",
            ),
        ],
    );
    let ws = tmp.path().join("ws");
    let (a, b) = (ws.join("a"), ws.join("b"));
    consumer_module(&a, "example.com/a", mc, &proxy_url);
    consumer_module(&b, "example.com/b", mc, &proxy_url);
    let go_mod = std::fs::read_to_string(b.join("go.mod")).unwrap();
    std::fs::write(
        b.join("go.mod"),
        go_mod.replace(&format!("{UMOD} {UVER}"), &format!("{UMOD} {NEWER}")),
    )
    .unwrap();
    let mut tidy_env = go_env(mc, &proxy_url);
    tidy_env.push(("GOWORK", "off"));
    let tidy = go(&b, &["mod", "tidy"], &tidy_env);
    assert!(
        tidy.status.success(),
        "go mod tidy: {}",
        String::from_utf8_lossy(&tidy.stderr)
    );
    write_patch(&a);
    let go_work = "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n";
    std::fs::write(ws.join("go.work"), go_work).unwrap();
    let env = workspace_env(mc, &proxy_url);
    assert!(go_out(&a, &env).contains("OUT: PRISTINE-v1.1.0"));

    let (code, so, se) = apply_json(&a, &modcache);
    assert_ne!(code, 0, "apply must refuse an inert replace:\n{so}\n{se}");
    assert!(
        so.contains(&format!("the build selects {UMOD} {NEWER}")),
        "{so}"
    );
    assert!(replace_lines(&a.join("go.mod")).is_empty());
    assert!(go_out(&a, &env).contains("OUT: PRISTINE-v1.1.0"));

    // Applied before the go.work existed: the replace is inert.
    std::fs::remove_file(ws.join("go.work")).unwrap();
    let (code, so, se) = apply_json(&a, &modcache);
    assert_eq!(code, 0, "apply without go.work:\n{so}\n{se}");
    assert!(go_out(&a, &tidy_env).contains("OUT: PATCHED"));
    std::fs::write(ws.join("go.work"), go_work).unwrap();
    assert!(go_out(&a, &env).contains("OUT: PRISTINE-v1.1.0"));
    let (code, so, se) = check(&a, &modcache);
    assert_eq!(
        code, 1,
        "apply --check must flag the inert replace:\n{so}\n{se}"
    );
    let r = VexRun {
        offline: true,
        product: Some("pkg:golang/example.com/a@v0.0.1".into()),
        ..VexRun::default()
    }
    .env("GOMODCACHE", &modcache)
    .env("GOFLAGS", "");
    let out = run_vex(&vex_e2e_common::binary(), &a, &r);
    assert_absent(out.doc.as_ref(), UPURL);
    vex_e2e_common::assert_not_attested(&out.envelope, UPURL, "go_version_not_selected");

    // Positive control: once b is back on a's version, the replace patches
    // the whole workspace and nothing is flagged.
    std::fs::write(b.join("go.mod"), &go_mod).unwrap();
    let tidy = go(&b, &["mod", "tidy"], &tidy_env);
    assert!(tidy.status.success());
    assert!(go_out(&b, &env).contains("OUT: PATCHED"));
    let (code, so, se) = check(&a, &modcache);
    assert_eq!(code, 0, "{so}\n{se}");

    chmod_writable(tmp.path());
}

// ── global mode: tools already built with `go install` (#422) ──

const TOOL: &str = "example.com/tool";
const TOOL_PURL: &str = "pkg:golang/example.com/tool@v1.0.0";

/// Run the `go install`ed tool and return its trimmed output.
fn run_tool(gobin: &Path) -> String {
    let out = Command::new(gobin.join("tool")).output().expect("run tool");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `go install example.com/tool@v1.0.0` into `gobin`, from the file proxy.
fn install_tool(tmp: &Path, modcache: &str, proxy_url: &str, gobin: &Path) {
    let mut env = go_env(modcache, proxy_url);
    // `go install pkg@version` refuses `-mod=mod`.
    env.retain(|(k, _)| *k != "GOFLAGS");
    env.push(("GOBIN", gobin.to_str().unwrap()));
    let out = go(tmp, &["install", &format!("{TOOL}@{UVER}")], &env);
    assert!(
        out.status.success(),
        "go install: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `vex -g --json` over `dir` for the installed tool's product.
fn global_vex(dir: &Path, modcache: &Path, gobin: &Path) -> vex_e2e_common::VexOutcome {
    let r = VexRun {
        offline: true,
        product: Some(TOOL_PURL.into()),
        extra_args: vec!["--global".into()],
        ..VexRun::default()
    }
    .env("GOMODCACHE", modcache)
    .env("GOBIN", gobin)
    .env("GOFLAGS", "");
    run_vex(&vex_e2e_common::binary(), dir, &r)
}

/// #422: a global apply patches the module cache in place, which a tool
/// already built from it with `go install` never sees. apply names the
/// tool and its `go install` remedy, and `vex -g` refuses to attest until
/// the tool is rebuilt — after which it runs the patched code and attests.
#[test]
fn global_apply_flags_tools_built_from_the_unpatched_module() {
    if !golang_e2e_matrix::toolchain_ready("e2e_golang_build(global-go-install)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (_consumer, modcache, proxy_url) = stage(tmp.path());
    let mc = modcache.to_str().unwrap();
    publish(
        tmp.path(),
        TOOL,
        UVER,
        &[
            (
                "go.mod",
                &format!("module {TOOL}\n\ngo 1.21\n\nrequire {UMOD} {UVER}\n"),
            ),
            (
                "main.go",
                &format!(
                    "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"TOOL:\", upstream.Greeting()) }}\n"
                ),
            ),
        ],
    );
    let gobin = tmp.path().join("gobin");
    install_tool(tmp.path(), mc, &proxy_url, &gobin);
    assert_eq!(run_tool(&gobin), "TOOL: PRISTINE");

    // Outside any Go project: the manifest is the only project state.
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    write_patch(&outside);
    let apply_with = |extra: &[&str]| {
        let mut args = vec![
            "apply",
            "--global",
            "--offline",
            "--ecosystems",
            "golang",
            "--json",
            "--cwd",
            outside.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let (code, stdout, stderr) = common::run_with_env(
            &outside,
            &args,
            &[("GOMODCACHE", mc), ("GOBIN", gobin.to_str().unwrap())],
        );
        assert_eq!(code, 0, "apply -g: {stdout}\n{stderr}");
        let env = common::envelope::parse_json_envelope(&stdout);
        let stale: Vec<String> = env["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|w| w["code"] == "go_installed_tool_stale")
            .map(|w| w["detail"].as_str().unwrap().to_string())
            .collect();
        stale
    };
    let apply = || apply_with(&[]);
    // The preview names the tool the real run will leave stale.
    let preview = apply_with(&["--dry-run"]);
    let lib = modcache.join(format!("{UMOD}@{UVER}")).join("lib.go");
    assert_eq!(std::fs::read_to_string(&lib).unwrap(), PRISTINE_LIB);
    let stale = apply();
    assert_eq!(preview, stale);
    assert_eq!(std::fs::read_to_string(&lib).unwrap(), PATCHED_LIB);
    // The cache is patched; the installed binary is not.
    assert_eq!(run_tool(&gobin), "TOOL: PRISTINE");
    assert_eq!(stale.len(), 1, "{stale:?}");
    assert!(
        stale[0].contains(&format!("go install {TOOL}@{UVER}"))
            && stale[0].contains(&format!("{UMOD}@{UVER}")),
        "{stale:?}"
    );
    // A re-run over the already-patched cache still names the tool, a
    // dry run included (the check is read-only).
    assert_eq!(apply(), stale);
    assert_eq!(apply_with(&["--dry-run"]), stale);

    let out = global_vex(&outside, &modcache, &gobin);
    assert_absent(out.doc.as_ref(), UPURL);
    vex_e2e_common::assert_not_attested(&out.envelope, UPURL, "go_installed_tool_stale");
    assert!(
        warnings_of(&out.stdout).contains(&"go_installed_tool_stale".to_string()),
        "{out}"
    );

    // The remedy the warning names rebuilds the tool from the patched cache.
    install_tool(tmp.path(), mc, &proxy_url, &gobin);
    assert_eq!(run_tool(&gobin), "TOOL: PATCHED");
    let out = global_vex(&outside, &modcache, &gobin);
    assert!(
        !warnings_of(&out.stdout).contains(&"go_installed_tool_stale".to_string()),
        "{out}"
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), UPURL, UUID, Marker::Applied, &[(GHSA, &[CVE])]);

    chmod_writable(&modcache);
}
